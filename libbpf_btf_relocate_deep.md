# libbpf BTF 重定位机制深度分析

## 概述

`btf_relocate.c` (519 行) 实现了 **Split BTF 重定位**机制——将基于"蒸馏版"
(distilled) base BTF 编译的 split BTF，重定位到实际运行内核的完整 base BTF 上。

这是 Linux 6.x 引入的新特性，用于解决**内核模块 BTF 可移植性**问题：

```
问题背景：
  内核模块 (split BTF) 引用 vmlinux (base BTF) 中的类型 ID
  → 不同内核版本的 vmlinux BTF 类型 ID 不同
  → 模块 BTF 无法直接在其他内核上使用

解决方案：
  编译时：生成"蒸馏版" base BTF（仅保留模块引用的命名类型）
  加载时：btf_relocate() 将蒸馏版 ID 映射到实际 base BTF ID
```

### 设计亮点

1. **双重用途**：同一代码在用户空间 (libbpf) 和内核空间 (verifier) 都能编译运行
2. **名称+大小匹配**：通过类型名和大小而非 ID 进行匹配，实现跨版本兼容
3. **嵌入类型特殊处理**：结构体内嵌的 base 类型必须严格匹配大小

---

## 1. 核心数据结构

### 1.1 btf_relocate 上下文

```c
struct btf_relocate {
    struct btf *btf;                /* 待重定位的 split BTF */
    const struct btf *base_btf;     /* 目标 base BTF (实际内核 vmlinux) */
    const struct btf *dist_base_btf;/* 蒸馏版 base BTF (编译时记录) */
    unsigned int nr_base_types;     /* 实际 base BTF 类型数 */
    unsigned int nr_split_types;    /* split BTF 类型数 */
    unsigned int nr_dist_base_types;/* 蒸馏版 base BTF 类型数 */
    int dist_str_len;               /* 蒸馏版字符串表长度 */
    int base_str_len;               /* 实际 base 字符串表长度 */
    __u32 *id_map;                  /* 类型 ID 映射: dist_id → base_id */
    __u32 *str_map;                 /* 字符串偏移映射: dist_off → base_off */
};
```

**关键映射关系**：

```
蒸馏版 base BTF          实际 base BTF
┌──────────────┐         ┌──────────────────┐
│ id=1: "int"  │────────→│ id=5: "int"      │  id_map[1] = 5
│ id=2: "task" │────────→│ id=127: "task"   │  id_map[2] = 127
│ id=3: "sock" │────────→│ id=2043: "sock"  │  id_map[3] = 2043
└──────────────┘         └──────────────────┘
  (仅 3 个类型)             (数千个类型)
```

### 1.2 btf_name_info 排序/搜索辅助

```c
struct btf_name_info {
    const char *name;          /* 类型名 */
    bool needs_size: 1;        /* 是否需要匹配大小 */
    unsigned int size: 31;     /* 类型大小 */
    __u32 id;                  /* 类型 ID */
};
```

用于对蒸馏版 base BTF 类型建立按名称排序的索引，支持二分查找。

---

## 2. 算法流程

### 2.1 入口函数 btf_relocate()

```
btf_relocate(btf, base_btf, id_map)
│
├── 1. 初始化 btf_relocate 上下文
│       获取 dist_base_btf = btf__base_btf(btf)
│       计算各类型区间大小
│       分配 id_map[] 和 str_map[]
│
├── 2. btf_relocate_validate_distilled_base()
│       验证蒸馏版只含命名的 int/float/enum/struct/union/fwd
│
├── 3. 预填充 split BTF 的 id_map
│       id_map[split_id] = split_id + (nr_base - nr_dist_base)
│       (split 类型的 ID 需要整体偏移)
│
├── 4. btf_relocate_map_distilled_base()
│       核心：建立 dist_id → base_id 的映射
│
├── 5. btf_relocate_rewrite_type_id() × nr_split_types
│       遍历每个 split 类型，替换其引用的所有 type_id
│
├── 6. btf_relocate_rewrite_strs() × nr_split_types
│       遍历每个 split 类型，替换字符串偏移
│
└── 7. btf_set_base_btf(btf, base_btf)
        将 split BTF 的 base 指针切换到实际 base
```

### 2.2 核心映射算法：btf_relocate_map_distilled_base()

这是整个模块最复杂的函数（约 200 行），实现"按名称+大小"匹配：

**步骤 1：构建蒸馏版类型的排序索引**

```c
for (id = 0; id < nr_dist_base_types; id++) {
    info[id].name = btf__name_by_offset(dist_base_btf, dist_t->name_off);
    info[id].id = id;
    info[id].size = dist_t->size;
}
qsort(info, nr_dist_base_types, sizeof(*info), cmp_btf_name_size);
```

**步骤 2：标记嵌入类型**

遍历 split BTF 中的 struct/union 成员，如果成员类型引用了 dist_base
中的 struct/union（经过 const/volatile/typedef 后），标记为 `BTF_IS_EMBEDDED`。

嵌入类型必须严格匹配大小（因为会影响父结构的内存布局）。

**步骤 3：统计 base BTF 中同名类型数量**

```c
base_name_cnt = calloc(base_str_len, sizeof(*base_name_cnt));
for (id = 1; id < nr_base_types; id++) {
    if (composite && named)
        base_name_cnt[base_t->name_off]++;
}
```

如果存在多个同名 struct/union，则需要通过 size 区分。

**步骤 4：遍历 base BTF，查找匹配的蒸馏版类型**

```c
for (id = 1; id < nr_base_types; id++) {
    // 对 base 中每个命名类型，用二分查找在蒸馏版中寻找匹配
    dist_info = search_btf_name_size(&base_info, info, nr_dist_base_types);

    // 找到后验证类型兼容性 (FWD↔STRUCT/UNION, ENUM↔ENUM64 等)
    // 记录映射：
    r->id_map[dist_info->id] = id;         // ID 映射
    r->str_map[dist_t->name_off] = base_t->name_off;  // 字符串映射
}
```

**步骤 5：验证完整性**

确保所有蒸馏版类型都找到了映射目标。

### 2.3 自定义二分查找

```c
static struct btf_name_info *search_btf_name_size(key, vals, nelems)
```

**特殊之处**：查找**最左匹配**——当有多个同名类型时，总是返回排序后第一个匹配，
然后调用方向右迭代检查所有同名类型。这解决了同名不同大小的 struct 匹配问题。

### 2.4 类型兼容性验证规则

| 蒸馏版类型 | 可匹配的 base 类型 | 附加约束 |
|-----------|-------------------|---------|
| FWD | FWD, STRUCT, UNION | kflag 一致 |
| INT | INT | encoding 一致 |
| FLOAT | FLOAT | — |
| ENUM | ENUM, ENUM64 | 大小一致 |
| STRUCT/UNION | STRUCT/UNION | 嵌入时大小一致 |

---

## 3. 字符串重写机制

```c
static int btf_relocate_rewrite_strs(struct btf_relocate *r, __u32 i)
{
    while ((str_off = btf_field_iter_next(&it))) {
        if (*str_off >= r->dist_str_len)
            // split BTF 自己的字符串：调整偏移
            *str_off += r->base_str_len - r->dist_str_len;
        else
            // 引用蒸馏版 base 的字符串：使用 str_map 替换
            *str_off = r->str_map[*str_off];
    }
}
```

字符串表布局变化：

```
重定位前:
  [dist_base 字符串表][split 字符串表]
   ^                  ^
   0                  dist_str_len

重定位后:
  [base 字符串表][split 字符串表]
   ^             ^
   0             base_str_len

偏移调整: split_str_off += (base_str_len - dist_str_len)
```

---

## 4. 用户空间/内核空间双重编译

文件头部的宏定义使同一代码可在两种环境编译：

```c
#ifdef __KERNEL__
// 内核环境：使用内核 API
#define btf_type_by_id     (struct btf_type *)btf_type_by_id
#define btf__type_cnt      btf_nr_types
#define calloc(n, sz)      kvcalloc(n, sz, GFP_KERNEL | __GFP_NOWARN)
#define free(ptr)          kvfree(ptr)
#define qsort(...)         sort(...)
#else
// 用户空间 libbpf：使用标准 API
#include "btf.h"
#include "libbpf_internal.h"
#endif
```

**内核调用路径**：验证器加载含蒸馏版 base 的模块 BTF 时调用
**用户空间调用路径**：`btf__relocate()` API (btf.c:6221)

---

## 5. 调用关系

### 用户空间 API

```
btf__relocate(btf, base_btf)                          [btf.c:6221]
  └── btf_relocate(btf, base_btf, NULL)               [btf_relocate.c:444]
        ├── btf_relocate_validate_distilled_base()
        ├── btf_relocate_map_distilled_base()
        │     ├── btf_mark_embedded_composite_type_ids()
        │     └── search_btf_name_size() (二分查找)
        ├── btf_relocate_rewrite_type_id() × N
        ├── btf_relocate_rewrite_strs() × N
        └── btf_set_base_btf()                         [btf.c:6214]
```

### 内核调用路径

```
bpf_check_btf_info()                                   [kernel: verifier.c]
  └── btf_relocate(module_btf, vmlinux_btf, &id_map)  [btf_relocate.c]
```

---

## 6. 与 CO-RE 的关系

BTF 重定位与 CO-RE 重定位是**不同层面**的机制：

| 维度 | BTF Relocate | CO-RE Relocate |
|------|-------------|----------------|
| 对象 | BTF 类型数据本身 | BPF 指令中的字段偏移 |
| 时机 | BTF 加载时 | 程序加载时 |
| 目的 | 让 split BTF 适配新 base BTF | 让 BPF 程序适配不同内核布局 |
| 实现文件 | btf_relocate.c | relo_core.c |
| 输入 | 蒸馏版 base ↔ 实际 base | .BTF.ext 重定位记录 |

两者协作场景：
1. `btf_relocate()` 先将模块 BTF 的类型 ID 修正
2. 然后 CO-RE 重定位使用修正后的 BTF 信息做字段偏移重定位

---

## 7. 内核关联

### 内核侧实现

内核 `kernel/bpf/btf.c` 中包含了相同的 `btf_relocate.c`（通过 `#include`
方式共享代码）。当加载带有蒸馏版 base 的模块 BTF 时：

```c
// kernel/bpf/btf.c (简化)
static int btf_check_type_tags(...)
{
    if (btf_is_module(btf) && btf__base_btf(btf) != vmlinux_btf) {
        // 检测到 split BTF 的 base 不是当前 vmlinux
        err = btf_relocate(btf, vmlinux_btf, &id_map);
        // 使用 id_map 更新 BTF ID 引用
    }
}
```

### 蒸馏版 BTF 生成

由 `pahole --btf_features=distilled_base` 生成，只保留被模块引用的
base BTF 中的命名类型（INT/FLOAT/ENUM/STRUCT/UNION/FWD），去掉所有
PTR/ARRAY/FUNC 等匿名类型。

---

## 8. 错误处理

模块定义了精确的错误提示：

| 错误场景 | 错误信息 | 返回值 |
|---------|---------|--------|
| 蒸馏版含匿名类型 | "type [%d] is invalid for distilled base BTF; it is anonymous" | -EINVAL |
| 蒸馏版含非法 kind | "type [%d] has unexpected kind [%d]" | -EINVAL |
| 同名同大小多候选 | "has multiple candidates of the same size" | -EINVAL |
| 找不到映射 | "is not mapped to base BTF id" | -EINVAL |
| 字符串无映射 | "string '%s' is not mapped to base BTF" | -ENOENT |
| 内存分配失败 | — | -ENOMEM |

---

## 9. 设计评析

### 优点

1. **共享代码**：用户空间和内核使用完全相同的算法，避免行为差异
2. **名称匹配策略**：不依赖 ID 稳定性，天然支持跨版本
3. **嵌入类型保护**：对影响内存布局的嵌入类型强制大小匹配
4. **左偏二分查找**：处理同名类型时保证确定性
5. **增量设计**：str_map 使用蒸馏版字符串表长度作为数组大小（紧凑）

### 复杂度

- 时间：O(B log D) 其中 B = base 类型数，D = 蒸馏版类型数
- 空间：O(D + N) 其中 N = 总类型数（id_map + str_map + info 数组）

### 局限性

1. 同名同大小类型无法区分（极罕见，实际内核中几乎不存在）
2. 匿名类型不进入蒸馏版 → 模块不能直接引用 base 中的匿名结构体
3. 依赖 `btf_field_iter` 基础设施遍历类型内的 ID/字符串字段

---

## 10. 总结

`btf_relocate.c` 解决了 BPF 生态中的一个关键问题：**让编译好的 BPF
模块的类型信息能够在不同内核版本间迁移**。

它的核心思想是：
- 编译时记录"最小必要类型信息"（蒸馏版 base BTF）
- 加载时通过**名称匹配**将这些类型映射到实际内核的 BTF
- 然后改写 split BTF 中的所有类型引用

这与 CO-RE 的指令级重定位形成互补：BTF relocate 解决类型 ID 层面的
可移植性，CO-RE 解决字段偏移层面的可移植性。两者结合使 BPF 程序和
模块真正实现"一次编译，到处运行"。
