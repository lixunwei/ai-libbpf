# libbpf BTF 子系统与 CO-RE 重定位引擎深度分析

## 说明

本文基于以下源码版本进行静态分析，全部结论均直接对应源码实现：

- `include/uapi/linux/btf.h`
- `include/uapi/linux/bpf.h`
- `src/btf.c`
- `src/btf_dump.c`
- `src/relo_core.c`
- `src/btf_relocate.c`
- `src/btf_iter.c`

分析重点分三部分：

1. BTF 数据表示、解析、构建、去重、导出；
2. CO-RE（Compile Once – Run Everywhere）重定位引擎；
3. `btf_relocate.c` 的 split BTF 基础重定位机制，以及它与 CO-RE 的区别。

---

# Part 1：BTF 子系统（`btf.c`）

## 1.1 BTF 数据格式

### 1.1.1 BTF header 结构

BTF 的 on-disk/in-memory 头定义在 `include/uapi/linux/btf.h:21`：

```c
struct btf_header {
	__u16	magic;
	__u8	version;
	__u8	flags;
	__u32	hdr_len;
	__u32	type_off;
	__u32	type_len;
	__u32	str_off;
	__u32	str_len;
	__u32	layout_off;
	__u32	layout_len;
};
```

关键点：

- `magic=BTF_MAGIC(0xeB9F)`，用于识别格式；
- `hdr_len` 允许头部扩展；libbpf 会把已知字段复制到内部 `btf->hdr`；
- 所有 offset **都相对于 header 末尾**；
- 传统 BTF 只有 `type_off/type_len + str_off/str_len`；
- 新版 libbpf 还支持可选 `layout_off/layout_len`，用于描述未知 kind 的编码布局。

### 1.1.2 类型编码格式：`struct btf_type + 附加数据`

BTF 类型头定义在 `include/uapi/linux/btf.h:43`：

```c
struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
};
```

`info` 位域定义（`include/uapi/linux/btf.h:45-70`）：

- bits 0-15：`vlen`
- bits 24-28：`kind`
- bit 31：`kind_flag`

宏：

- `BTF_INFO_KIND(info)`
- `BTF_INFO_VLEN(info)`
- `BTF_INFO_KFLAG(info)`

**核心理解**：`btf_type` 只是公共头，真正的类型内容由 `kind` 决定；其后面可能跟 0 个、1 个或 `vlen` 个扩展元素：

- `INT`：后跟一个 `u32` 编码整数属性；
- `ARRAY`：后跟一个 `struct btf_array`；
- `STRUCT/UNION`：后跟 `vlen` 个 `struct btf_member`；
- `ENUM`：后跟 `vlen` 个 `struct btf_enum`；
- `ENUM64`：后跟 `vlen` 个 `struct btf_enum64`；
- `FUNC_PROTO`：后跟 `vlen` 个 `struct btf_param`；
- `VAR`：后跟一个 `struct btf_var`；
- `DATASEC`：后跟 `vlen` 个 `struct btf_var_secinfo`。

`src/btf.c:38-60` 中的 `layouts[]` 进一步把“每种 kind 后面跟多大附加数据”显式编码出来，这是 libbpf 对 BTF 编码布局的集中描述。

### 1.1.3 字符串表格式

字符串表是一个 NUL 结尾字符串拼接区，偏移由 `name_off` 等字段引用。

关键约束见 `src/btf.c:380-396`：

```c
if (!btf->hdr.str_len || btf->hdr.str_len - 1 > BTF_MAX_STR_OFFSET || end[-1])
	return -EINVAL;
if (!btf->base_btf && start[0])
	return -EINVAL;
```

含义：

- 非 split BTF 的字符串表必须以空字符串开头（offset 0）；
- 字符串区最后一个字节必须是 `\0`；
- split BTF 允许自己的 `str_len==0`，因为它共享 base BTF 的字符串空间前缀；
- 逻辑字符串偏移通过 `btf->start_str_off` 与 base BTF 拼接。

---

## 1.2 libbpf 内部存储结构

### 1.2.1 `struct btf`

libbpf 内部表示定义在 `src/btf.c:62-185`。这是理解整个子系统的关键。

核心成员：

- `raw_data/raw_size`：原始连续 BTF blob；
- `hdr`：复制出来的标准化 header；
- `types_data`：类型区；
- `type_offs[]`：type ID -> 在 `types_data` 中的偏移；
- `nr_types`：当前 BTF 实例持有的类型数；
- `base_btf/start_id`：split BTF 所依附的 base BTF 及其起始 ID；
- `start_str_off`：split BTF 的逻辑字符串偏移起点；
- `strs_data` / `strs_set`：只读模式下直接指向原始字符串区；可修改模式下改用 `strset`；
- `layout`：可选的 kind layout 数组；
- `ptr_sz`：目标架构指针大小。

源码注释 `src/btf.c:71-118` 很重要：

- **未修改前**：header/types/layout/strings 共享一个连续内存块；
- **一旦进入可修改模式**：数据被拆成独立区域，字符串改由 `strset` 管理；
- 之后如果用户请求 raw data，libbpf 再重新拼装一个连续 blob。

这解释了为什么很多 API 首先调用 `btf_ensure_modifiable()`：它负责把“只读连续表示”切换为“可编辑内部表示”。

---

## 1.3 BTF 解析流程

### 1.3.1 关键入口函数

| 函数 | 位置 | 签名 | 作用 |
|---|---|---|---|
| `btf__parse_elf` | `src/btf.c:1549` | `struct btf *btf__parse_elf(const char *path, struct btf_ext **btf_ext)` | 从 ELF 文件读取 `.BTF`/`.BTF.ext` |
| `btf__parse_raw` | `src/btf.c:1622` | `struct btf *btf__parse_raw(const char *path)` | 从原始 BTF blob 文件解析 |
| `btf__parse` | `src/btf.c:1680` | `struct btf *btf__parse(const char *path, struct btf_ext **btf_ext)` | 先尝试 raw，失败后退回 ELF |
| `btf__parse_split` | `src/btf.c:1685` | `struct btf *btf__parse_split(const char *path, struct btf *base_btf)` | 解析 split BTF |

### 1.3.2 `btf__parse_elf()` / `btf_parse_elf()` 实现

主逻辑在 `src/btf.c:1447-1547`：

```c
err = btf_find_elf_sections(elf, path, &secs);
...
if (secs.btf_base_data) {
	dist_base_btf = btf_new(secs.btf_base_data->d_buf, secs.btf_base_data->d_size,
				NULL, false);
}

btf = btf_new(secs.btf_data->d_buf, secs.btf_data->d_size,
	      dist_base_btf ?: base_btf, false);
if (dist_base_btf && base_btf) {
	err = btf__relocate(btf, base_btf);
```

流程可拆为 6 步：

1. `libelf` 打开 ELF；
2. `btf_find_elf_sections()` 定位 `.BTF`、`.BTF.ext`、可选 `.BTF.base`；
3. 若存在 `.BTF.base`，先构造“蒸馏的 base BTF（distilled base BTF）”；
4. 用 `.BTF` section 构造主 `struct btf`；
5. 若同时有 `dist_base_btf` 与用户提供的真实 `base_btf`，调用 `btf__relocate()` 完成 split BTF 的基础重定位；
6. 解析 `.BTF.ext`。

这说明：**ELF 解析不只是“把字节拷贝进来”，还会把 split BTF 与真实 base BTF 接起来。**

### 1.3.3 split BTF 的蒸馏 base 是如何生成的

与解析相对应，`src/btf.c` 末尾还有两组辅助函数：

| 函数 | 位置 | 作用 |
|---|---|---|
| `btf_add_distilled_type_ids` | `btf.c:5913` | 从 split BTF 递归找出它依赖的 base type 子集 |
| `btf_add_distilled_types` | `btf.c:5978` | 把这些 base type 以“蒸馏形式”写入 distilled base BTF |

其思想不是复制完整 base BTF，而是只保留 split BTF 真正用到的那部分基础类型轮廓：

- 命名 `struct/union` 在 distilled base 中只保留**同名、同大小、0-vlen 的壳**；
- 命名 `enum/enum64` 只保留**同名、同大小的 enum 壳**；
- `int/float/fwd` 保留名字与基本属性；
- `array/ptr/typedef/const/volatile/restrict/func_proto/type_tag` 留在 split 侧；
- 匿名 composite / 匿名 enum 作为 split 自身的一部分原样保留。

所以 distilled base 本质上是一份“**最小匹配索引**”，供后续 `btf_relocate.c` 把 split BTF 重新绑定到真实 base BTF 上。

### 1.3.4 `btf__parse_raw()` / `btf_parse_raw()` 实现

`src/btf.c:1559-1620`：

- 先读取前两个字节检查 `BTF_MAGIC`；
- 如果 magic 不对，返回 `-EPROTO`，让上层知道“这不是 raw BTF”；
- 否则把整个文件读入内存，交给 `btf_new()` 统一解析。

因此 `btf__parse()` 的策略是：

1. `btf_parse_raw()`；
2. 若成功，直接返回；
3. 若失败且错误不是 `-EPROTO`，直接报错；
4. 若是 `-EPROTO`，说明文件不是 raw BTF，再走 ELF 路径。

### 1.3.4 从 `.BTF` section 解析出类型信息

实际解析核心由以下函数串起来：

| 函数 | 位置 | 作用 |
|---|---|---|
| `btf_parse_hdr` | `src/btf.c:286` | 解析 header、校验布局、处理跨端序 |
| `btf_parse_str_sec` | `src/btf.c:380` | 校验字符串区 |
| `btf_parse_layout_sec` | `src/btf.c:398` | 解析可选 layout section |
| `btf_parse_type_sec` | `src/btf.c:578` | 顺序扫描类型区，建立 type offset 索引 |

`btf_parse_type_sec()` 的主体非常清楚：

```c
while (next_type + sizeof(struct btf_type) <= end_type) {
	if (btf->swapped_endian)
		btf_bswap_type_base(next_type);

	type_size = btf_type_size(btf, next_type);
	...
	if (btf->swapped_endian && btf_bswap_type_rest(next_type))
		return -EINVAL;

	err = btf_add_type_idx_entry(btf, next_type - btf->types_data);
	...
	next_type += type_size;
	btf->nr_types++;
}
```

关键点：

- 它不是按 type ID 随机访问，而是**顺序线性扫描 type section**；
- 每个类型大小由 `btf_type_size()` 根据 `kind/vlen/layout` 动态计算；
- 每成功解析一个类型，就在 `type_offs[]` 中记录偏移；
- 后续 `btf_type_by_id()` 就能 O(1) 按 ID 跳转。

### 1.3.5 split BTF 的原理

split BTF 是“模块 BTF / 对象 BTF 只保存自己新增类型，把公共基础类型放在 base BTF 里”的机制。

`src/btf.c:1235-1240` 的 `btf_new_empty()` 已体现这种设计：

```c
if (base_btf) {
	btf->base_btf = base_btf;
	btf->start_id = btf__type_cnt(base_btf);
	btf->start_str_off = base_btf->hdr.str_len + base_btf->start_str_off;
}
```

也就是说，split BTF：

- 类型 ID 空间接在 base BTF 之后；
- 字符串偏移空间逻辑上也接在 base BTF 之后；
- 自身只保存“增量部分”。

但 ELF 中携带的 `.BTF.base` 往往不是完整真实 base，而是一个**蒸馏版 base**（distilled base），只保留 split BTF 需要引用的那部分基础类型轮廓。解析时要靠 `btf_relocate.c` 把蒸馏 base 映射回真实 base。这个过程与 CO-RE 不同，后文单独讲。

---

## 1.4 BTF 构建 API

### 1.4.1 空 BTF 的创建

关键函数：

| 函数 | 位置 | 签名 |
|---|---|---|
| `btf_new_empty` | `src/btf.c:1216` | `static struct btf *btf_new_empty(struct btf_new_opts *opts)` |
| `btf__new_empty` | `src/btf.c:1278` | `struct btf *btf__new_empty(void)` |
| `btf__new_empty_split` | `src/btf.c:1283` | `struct btf *btf__new_empty_split(struct btf *base_btf)` |

其初始化逻辑：

```c
btf->nr_types = 0;
btf->start_id = 1;
btf->start_str_off = 0;
...
hdr->hdr_len = sizeof(struct btf_header);
hdr->magic = BTF_MAGIC;
hdr->version = BTF_VERSION;
...
hdr->str_len = base_btf ? 0 : 1; /* empty string at offset 0 */
```

普通 BTF：

- 从 type ID 1 开始；
- 字符串表预置 offset 0 的空串。

split BTF：

- `start_id`、`start_str_off` 继承并偏移到 `base_btf` 之后；
- 自己不重复保存 base 字符串。

### 1.4.2 `btf__add_*` 系列如何构建类型

构建 API 基本模式一致：

1. `btf_ensure_modifiable()` 进入可编辑模式；
2. `btf_add_type_mem()` 在 type 区末尾追加空间；
3. `btf__add_str()` 追加/复用字符串；
4. 填写 `struct btf_type` 和附加数据；
5. `btf_commit_type()` 更新 `type_offs[]`、`hdr.type_len`、`nr_types`。

例如 `btf__add_int()`（`src/btf.c:2378`）：

```c
name_off = btf__add_str(btf, name);
t->name_off = name_off;
t->info = btf_type_info(BTF_KIND_INT, 0, 0);
t->size = byte_sz;
*(__u32 *)(t + 1) = (encoding << 24) | (byte_sz * 8);
return btf_commit_type(btf, sz);
```

例如 `btf__add_struct()` + `btf__add_field()`（`src/btf.c:2602`、`2640`）：

```c
t->info = btf_type_info(kind, 0, 0);
t->size = bytes_sz;
...
m->name_off = name_off;
m->type = type_id;
m->offset = bit_offset | (bit_size << 24);
...
t->info = btf_type_info(btf_kind(t), btf_vlen(t) + 1,
			is_bitfield || btf_kflag(t));
```

这套 API 的特点是：

- 以“追加”方式构建，不支持随机插入；
- 允许 forward type ID 引用，只要数值合法；
- 复合类型（struct/union/enum/func proto/datasec）通常先创建壳，再逐个追加成员。

### 1.4.3 字符串与类型存储

`btf__add_str()`（`src/btf.c:2094`）说明了字符串策略：

```c
if (btf->base_btf) {
	off = btf__find_str(btf->base_btf, s);
	if (off != -ENOENT)
		return off;
}
...
off = strset__add_str(btf->strs_set, s);
...
return btf->start_str_off + off;
```

即：

- 先尝试复用 base BTF 的字符串；
- 否则插入本地 `strset`；
- 对外返回逻辑偏移（带 `start_str_off`）。

类型区则通过 `btf_add_type_mem()` / `btf_commit_type()` 管理。`btf_commit_type()`（`src/btf.c:2145`）负责：

- 为新类型记录偏移索引；
- 递增 `hdr.type_len`；
- 递增 `nr_types`；
- 返回新 type ID。

---

## 1.5 BTF Dedup 算法（`btf__dedup`）

### 1.5.1 目标和意义

`btf__dedup()` 位于 `src/btf.c:3891`。

其目标：

1. 删除重复字符串，压缩 string section；
2. 把语义等价的类型合并为一个 canonical type；
3. 重新编号 type ID；
4. 重写所有类型引用与 `.BTF.ext` 中的 type ID 引用。

意义：

- 降低 BTF 大小；
- 把不同编译单元里重复出现的类型统一起来；
- 为 CO-RE、BTF dump、内核加载提供稳定类型视图；
- 对 split BTF，还要兼容 base BTF 不可变这一约束。

### 1.5.2 顶层流程

`src/btf.c:3891-3945`：

```c
err = btf_dedup_prep(d);
err = btf_dedup_strings(d);
err = btf_dedup_prim_types(d);
err = btf_dedup_struct_types(d);
err = btf_dedup_resolve_fwds(d);
err = btf_dedup_ref_types(d);
err = btf_dedup_compact_types(d);
err = btf_dedup_remap_types(d);
```

可概括为：

> 预置 base BTF canonical → 字符串去重 → 原始/基础类型去重 → 结构体/联合体/typedef 图等价去重 → FWD 解析 → 引用类型去重 → 物理压缩 → ID 重写。

### 1.5.3 核心数据结构

`struct btf_dedup` 定义在 `src/btf.c:3958-3992`：

- `dedup_table`：hash -> 候选 canonical type 列表；
- `map[type_id]`：原始 type ID -> canonical type ID；
- `hypot_map`：图等价比较时的“假设映射”；
- `hypot_list/hypot_cnt`：记录 hypot_map 中本轮写入了哪些节点，便于回滚；
- `strs_set`：新的去重字符串集合；
- `opts`：是否处理 `btf_ext`、是否允许 FWD 解析等。

特别重要的是 `map` 与 `hypot_map` 的分工：

- `map`：最终正式映射；
- `hypot_map`：比较“两个 struct 图是否等价”时的临时推导结果。

### 1.5.4 步骤一：字符串去重

函数：`btf_dedup_strings()`，`src/btf.c:4198`。

其注释已经把算法讲得非常清楚：

```c
/* build index of all strings ... mark used ... dedup and compact ...
 * Then all the string references are iterated again and rewritten
 */
```

实现关键点：

- 遍历 `.BTF` 和可选 `.BTF.ext` 中所有字符串引用位置；
- 若 split BTF 有 `base_btf`，优先复用 base 字符串；
- 新字符串写入 `strset`；
- 再次遍历所有引用位置，把旧 offset 改成新 offset。

这一步不只是“去重”，还顺便做了**垃圾回收**：未被引用的字符串会消失。

### 1.5.5 步骤二：预置 base BTF 哈希表

函数：`btf_dedup_prep()`，`src/btf.c:4556`。

如果当前是 split BTF：

- base BTF 中所有类型天然视为 canonical；
- 它们会被直接写入 `map[type_id]=type_id`；
- 同时按 kind 计算 hash，塞进 `dedup_table`，作为后续 split 类型的候选代表。

这决定了 split BTF 的 dedup 不是“base 与 split 平等合并”，而是：

> base BTF 先天是不可变 canonical 集合，split BTF 只能向它靠拢。

### 1.5.6 步骤三：原始类型去重

函数：

- `btf_dedup_prim_type()`，`src/btf.c:4622`
- `btf_dedup_prim_types()`，`src/btf.c:4707`

此阶段处理：

- `INT`
- `ENUM/ENUM64`
- `FWD`
- `FLOAT`

做法：

1. 计算 type hash；
2. 在 `dedup_table` 中查候选；
3. 用 `btf_equal_*()` 或 `btf_compat_enum()` 精确判断；
4. 若匹配，则 `map[type_id]=cand_id`；
5. 若不匹配，则自己成为 canonical，加入 hash 表。

这一层不需要递归比较复杂图，因为这些类型不形成复杂引用图。

### 1.5.7 步骤四：结构体/联合体/typedef 图等价比较

核心函数：

| 函数 | 位置 | 作用 |
|---|---|---|
| `btf_dedup_is_equiv` | `src/btf.c:4972` | 判断 candidate graph 与 canonical graph 是否等价 |
| `btf_dedup_merge_hypot_map` | `src/btf.c:5160` | 把临时假设映射并入正式映射 |
| `btf_dedup_struct_type` | `src/btf.c:5262` | 对单个 struct/union/typedef 执行 dedup |
| `btf_dedup_struct_types` | `src/btf.c:5322` | 批量处理 |

这一阶段是整个 dedup 最复杂的部分。

#### (a) 为什么不能只按浅比较去重？

struct/union 的 `name/size/field names/order` 相同，不代表字段引用的子类型图也相同。

所以这里只做 shallow hash：

- 先用名字、大小、成员名字等算 hash；
- 仅把 hash 相同者作为候选；
- 再做 **图等价** 验证。

#### (b) 图等价算法要点

`btf_dedup_is_equiv()`（`src/btf.c:4972`）的核心思想：

- 同步 DFS 遍历 candidate graph 与 canonical graph；
- 当前节点若“除引用 type ID 外的结构信息一致”，就暂时记入 `hypot_map[canon_id]=cand_id`；
- 若后续递归无冲突，则两图等价；
- 若同一个 canonical 节点被映射到两个不同 candidate 节点，则出现矛盾，不等价。

源码中的关键逻辑：

```c
hypot_type_id = d->hypot_map[canon_id];
if (hypot_type_id <= BTF_MAX_NR_TYPES) {
	if (hypot_type_id == cand_id)
		return 1;
	if (btf_dedup_identical_types(d, hypot_type_id, cand_id, 16))
		return 1;
	return 0;
}
...
if (btf_dedup_hypot_map_add(d, canon_id, cand_id))
	return -ENOMEM;
```

#### (c) FWD 解析的特殊处理

源码 `src/btf.c:5019-5035` 专门支持 `FWD <-> STRUCT/UNION` 的兼容推导：

```c
if ((cand_kind == BTF_KIND_FWD || canon_kind == BTF_KIND_FWD)
    && cand_kind != canon_kind) {
	...
	return fwd_kind == real_kind;
}
```

也就是说：

- 若一个图里是前向声明，另一个图里是实体 struct/union；
- 且名字、种类匹配；
- dedup 可以把它们视为等价，并在后续合并映射时解析 FWD。

但 split BTF 时，若这种解析会“反向改动 base 的 canonical 关系”，`hypot_adjust_canon` 会阻止它真的被视为等价，这一点非常关键。

### 1.5.8 步骤五：FWD 统一解析

函数：`btf_dedup_resolve_fwds()`，`src/btf.c:5602`。

这一步处理那些**没有出现在复杂图比较路径中**、因此没机会自动解析的 FWD。

做法：

1. 遍历所有 canonical struct/union，建立“唯一名称 -> type ID”表；
2. 对每个仍未映射的 FWD：
   - 若能找到同名且唯一的 struct/union；
   - 且 struct/union 种类与 FWD kind 匹配；
   - 则直接 `map[fwd]=struct_or_union`。

源码注释 `src/btf.c:5570-5601` 给了一个典型例子：

- 一个编译单元只有 `struct foo; struct foo *p;`
- 另一个编译单元有 `struct foo { int u; };`

struct graph dedup 可能覆盖不到这个裸 FWD，因此需要这一遍收尾。

### 1.5.9 步骤六：引用类型去重

函数：

- `btf_dedup_ref_type()`，`src/btf.c:5358`
- `btf_dedup_ref_types()`，`src/btf.c:5483`

此时 primitive/composite/typedef 已经稳定，因此指针、const、array、func proto 等引用链也稳定了。

算法：

1. 递归先把被引用 type ID 解析到 canonical；
2. 直接把 `t->type` 或数组/函数原型中的引用改成 canonical ID；
3. 再计算完整 hash；
4. 查找已有 canonical 候选并比较；
5. 否则自己成为 canonical。

这一步结束后，所有类型的语义映射已经稳定。

### 1.5.10 步骤七：压缩与 remap

函数：

- `btf_dedup_compact_types()`，`src/btf.c:5637`
- `btf_dedup_remap_types()`，`src/btf.c:5718`

`btf_dedup_compact_types()` 的作用：

- 只把 canonical 类型重新顺序拷贝到 `types_data` 前部；
- 用 `hypot_map` 复用为“旧 ID -> 新 ID”的压缩映射；
- 更新 `nr_types`、`hdr.type_len`、`type_offs[]`、`str_off`/`layout_off`/`raw_size`。

之后 `btf_dedup_remap_types()` 再遍历所有类型引用：

```c
while ((type_id = btf_field_iter_next(&it))) {
	resolved_id = resolve_type_id(d, *type_id);
	new_id = d->hypot_map[resolved_id];
	*type_id = new_id;
}
```

若有 `btf_ext`，还会通过 `btf_ext_visit_type_ids()` 把 `.BTF.ext` 中的引用一并改掉。

---

## 1.6 BTF Dump（`btf_dump.c`）

### 1.6.1 核心入口

| 函数 | 位置 | 签名 |
|---|---|---|
| `btf_dump__dump_type` | `src/btf_dump.c:281` | `int btf_dump__dump_type(struct btf_dump *d, __u32 id)` |
| `btf_dump__emit_type_decl` | `src/btf_dump.c:1270` | `int btf_dump__emit_type_decl(struct btf_dump *d, __u32 id, const struct btf_dump_emit_type_decl_opts *opts)` |
| `btf_dump__dump_type_data` | `src/btf_dump.c:2581` | `int btf_dump__dump_type_data(struct btf_dump *d, __u32 id, const void *data, size_t data_sz, const struct btf_dump_type_data_opts *opts)` |

本文重点讨论“如何导出 C 类型定义”。

### 1.6.2 如何把 BTF 输出成 C 代码

`btf_dump__dump_type()`（`src/btf_dump.c:281`）先排序，再输出：

```c
err = btf_dump_order_type(d, id, false);
...
for (i = 0; i < d->emit_queue_cnt; i++)
	btf_dump_emit_type(d, d->emit_queue[i], 0);
```

#### (a) 拓扑排序：`btf_dump_order_type()`

位置：`src/btf_dump.c:473`。

这不是普通 DAG 拓扑排序，而是**考虑 C 语言“前置声明 vs 必须完整定义”语义的拓扑排序**。

源码注释 `src/btf_dump.c:399-472` 给出核心规则：

- 若依赖链中经过指针，且最终目标是命名类型，则通常可弱化为 forward declaration；
- 若是嵌入式成员（embedded member），则必须先看到完整定义，属于强依赖；
- 匿名 struct/union 即使在指针后面，也可能把依赖重新变成强依赖。

这套规则由 `through_ptr` 参数在 DFS 中传播。

#### (b) 发射器：`btf_dump_emit_type()`

位置：`src/btf_dump.c:689`。

它根据 `emit_state` 处理几类场景：

- 已经发射过：跳过；
- 正在发射又被递归引用：必要时补 forward declaration；
- 顶层 enum/struct/union/typedef：真正输出定义；
- 指针、数组、修饰符：递归确保底层类型已准备好。

典型逻辑：

```c
if (tstate->emit_state == EMITTING) {
	...
	btf_dump_emit_struct_fwd(d, id, t);
	btf_dump_printf(d, ";\n\n");
}
```

这就是“边 DFS 边补前置声明”。

#### (c) 结构体定义输出：`btf_dump_emit_struct_def()`

位置：`src/btf_dump.c:967`。

核心逻辑：

- 遍历成员；
- 计算成员 bit offset / bitfield size；
- 用 `btf_dump_emit_bit_padding()` 补匿名 padding；
- 再用 `btf_dump_emit_type_decl()` 输出成员声明；
- packed struct 追加 `__attribute__((packed))`。

```c
m_sz = btf_member_bitfield_size(t, i);
m_off = btf_member_bit_offset(t, i);
...
btf_dump_emit_bit_padding(d, off, m_off, m_align, in_bitfield, lvl + 1);
btf_dump_emit_type_decl(d, m->type, fname, lvl + 1);
if (m_sz)
	btf_dump_printf(d, ": %d", m_sz);
```

这说明 BTF dump 并不是“简单打印成员名”，它会尽量重建真实 C 布局，包括 bitfield 与 padding。

#### (d) 声明语法重建：`btf_dump_emit_type_decl()`

位置：`src/btf_dump.c:1291`。

这部分非常值得注意。因为 BTF 是图结构，而 C 声明语法是“中缀 + 前后缀混合”的线性文本，尤其数组/函数指针/const 修饰非常绕。

libbpf 的策略是：

1. 沿类型链不断压栈；
2. 直到命中 terminal type（int/enum/struct/typedef...）；
3. 再由 `btf_dump_emit_type_chain()` 逆向生成合法 C 声明。

源码注释 `src/btf_dump.c:1229-1269` 专门解释了这一点。

---

# Part 2：CO-RE 重定位引擎（`relo_core.c`）

## 2.1 重定位种类（`enum bpf_core_relo_kind`）

定义在 `include/uapi/linux/bpf.h:7586-7600`：

```c
enum bpf_core_relo_kind {
	BPF_CORE_FIELD_BYTE_OFFSET = 0,
	BPF_CORE_FIELD_BYTE_SIZE = 1,
	BPF_CORE_FIELD_EXISTS = 2,
	BPF_CORE_FIELD_SIGNED = 3,
	BPF_CORE_FIELD_LSHIFT_U64 = 4,
	BPF_CORE_FIELD_RSHIFT_U64 = 5,
	BPF_CORE_TYPE_ID_LOCAL = 6,
	BPF_CORE_TYPE_ID_TARGET = 7,
	BPF_CORE_TYPE_EXISTS = 8,
	BPF_CORE_TYPE_SIZE = 9,
	BPF_CORE_ENUMVAL_EXISTS = 10,
	BPF_CORE_ENUMVAL_VALUE = 11,
	BPF_CORE_TYPE_MATCHES = 12,
};
```

### 2.1.1 字段类 relocation

- `FIELD_BYTE_OFFSET`：字段字节偏移；
- `FIELD_BYTE_SIZE`：字段字节大小；
- `FIELD_EXISTS`：字段是否存在；
- `FIELD_SIGNED`：字段是否为有符号；
- `FIELD_LSHIFT_U64` / `FIELD_RSHIFT_U64`：bitfield 提取辅助位移。

### 2.1.2 类型类 relocation

- `TYPE_ID_LOCAL`：本地 BTF 中的 type ID；
- `TYPE_ID_TARGET`：目标 BTF 中的 type ID；
- `TYPE_EXISTS`：目标类型是否存在；
- `TYPE_SIZE`：目标类型大小；
- `TYPE_MATCHES`：本地类型是否与目标类型匹配。

### 2.1.3 枚举值类 relocation

- `ENUMVAL_EXISTS`：枚举成员是否存在；
- `ENUMVAL_VALUE`：枚举成员的数值。

---

## 2.2 CO-RE 访问路径表示

LLVM 通过 `struct bpf_core_relo` 把 relocation 记录传给 libbpf。`access_str_off` 指向的字符串编码访问路径，例如：

- `0:0`
- `0:1:0:5`

对应注释位于 `include/uapi/linux/bpf.h:7602-7648`。

### 2.2.1 `bpf_core_parse_spec()`

位置：`src/relo_core.c:262`

签名：

```c
int bpf_core_parse_spec(const char *prog_name, const struct btf *btf,
			const struct bpf_core_relo *relo,
			struct bpf_core_spec *spec)
```

作用：把 `"0:1:2:3"` 这样的访问字符串解析成两层表示：

- **raw_spec**：逐级原始索引；
- **spec[]**：只保留语义关键点（命名字段、数组下标）。

关键片段：

```c
while (*spec_str) {
	if (*spec_str == ':')
		++spec_str;
	if (sscanf(spec_str, "%d%n", &access_idx, &parsed_len) != 1)
		return -EINVAL;
	...
	spec->raw_spec[spec->raw_len++] = access_idx;
}
```

随后它会沿类型图前进：

- 遇到 composite，就按 field index 找成员并累计 bit offset；
- 遇到 array，就按 element index 累计步长；
- 遇到 enum relocation，只记录枚举成员名。

所以 `bpf_core_spec` 本质上是 **“从根类型到目标字段/枚举成员的规范化访问轨迹”**。

---

## 2.3 核心算法总入口：`bpf_core_calc_relo_insn()`

位置：`src/relo_core.c:1297`

签名：

```c
int bpf_core_calc_relo_insn(const char *prog_name,
			    const struct bpf_core_relo *relo,
			    int relo_idx,
			    const struct btf *local_btf,
			    struct bpf_core_cand_list *cands,
			    struct bpf_core_spec *specs_scratch,
			    struct bpf_core_relo_res *targ_res)
```

这是 CO-RE 计算“某条指令该怎么补丁”的总入口。

### 2.3.1 主流程

源码注释 `src/relo_core.c:1247-1296` 已经总结得很好，可归纳为：

1. 解析本地 relocation 规格；
2. 在目标 BTF 候选类型集合里逐个尝试匹配；
3. 对每个匹配候选计算 relocation 结果；
4. 检查所有候选结果是否一致；
5. 若无候选，则根据 relocation kind 决定返回 0 / exists=0 / poison。

关键代码：

```c
err = bpf_core_parse_spec(prog_name, local_btf, relo, local_spec);
...
for (i = 0, j = 0; i < cands->len; i++) {
	err = bpf_core_spec_match(local_spec, cands->cands[i].btf,
				  cands->cands[i].id, cand_spec);
	...
	err = bpf_core_calc_relo(prog_name, relo, relo_idx,
				 local_spec, cand_spec, &cand_res);
```

### 2.3.2 候选类型查找机制

`bpf_core_calc_relo_insn()` 本身不建立候选，而是接收外部准备好的 `cands`。这些候选是在上层按 **essential name**（忽略 `___flavor` 后缀）筛出来的。

源码注释 `src/relo_core.c:1251-1269`：

- `sample`、`sample___x`、`sample___y` 被视为同名 flavor；
- flavor 允许 BPF 程序容忍不同内核版本中的不兼容结构变体。

进入 `bpf_core_calc_relo_insn()` 后，会继续做两层过滤：

1. `bpf_core_spec_match()`：结构上能否匹配；
2. `bpf_core_calc_relo()`：算出的结果是否与其他候选一致。

若候选之间结果不一致，就报“ambiguity”。

---

## 2.4 字段重定位计算：`bpf_core_calc_field_relo()`

位置：`src/relo_core.c:679`

签名：

```c
static int bpf_core_calc_field_relo(const char *prog_name,
				    const struct bpf_core_relo *relo,
				    const struct bpf_core_spec *spec,
				    __u64 *val, __u32 *field_sz, __u32 *type_id,
				    bool *validate)
```

### 2.4.1 普通字段

若最后一级 accessor 指向命名字段：

- `spec->bit_offset` 给出位偏移；
- 解析成员类型得到字节大小、signedness；
- 对 `FIELD_BYTE_OFFSET/SIZE/SIGNED` 返回对应值。

### 2.4.2 数组访问

若最后一级是 `a[n]` 式数组下标，则 `acc->name == NULL`，走数组专门逻辑：

```c
if (!acc->name) {
	if (relo->kind == BPF_CORE_FIELD_BYTE_OFFSET) {
		*val = spec->bit_offset / 8;
		...
	} else if (relo->kind == BPF_CORE_FIELD_BYTE_SIZE) {
		...
	} else {
		return -EINVAL;
	}
}
```

即数组元素支持 offset/size，但不支持 signedness 等字段语义。

### 2.4.3 bitfield 特殊逻辑

这是 CO-RE 最容易被忽视的部分。

源码 `src/relo_core.c:742-809`：

```c
bitfield = bit_sz > 0;
if (bitfield) {
	byte_sz = mt->size;
	byte_off = bit_off / 8 / byte_sz * byte_sz;
	while (bit_off + bit_sz - byte_off * 8 > byte_sz * 8) {
		...
		byte_sz *= 2;
	}
}
```

含义：

- 对 bitfield，不能简单把“字段起始字节偏移”当成 load offset；
- libbpf 要找出一个**最小可覆盖整个 bitfield 的整型 load 窗口**；
- 然后再给出两类辅助 relocation：
  - `FIELD_LSHIFT_U64`
  - `FIELD_RSHIFT_U64`

其公式：

```c
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	*val = 64 - (bit_off + bit_sz - byte_off  * 8);
#else
	*val = (8 - byte_sz) * 8 + (bit_off - byte_off * 8);
#endif
...
*val = 64 - bit_sz;
```

组合起来的典型用法是：

1. 先按 `byte_off/byte_sz` 读取一个整数；
2. 左移到最高位对齐；
3. 再右移做符号或零扩展提取。

### 2.4.4 validate 语义

bitfield 情况下很多值与编译器 codegen 的约定有关，因此 libbpf 对 bitfield 默认关闭 imm/off 的严格校验：

```c
if (validate)
	*validate = !bitfield;
```

只有 signedness 和某些位移仍然要求严格一致。

---

## 2.5 类型重定位计算：`bpf_core_calc_type_relo()`

位置：`src/relo_core.c:820`

签名：

```c
static int bpf_core_calc_type_relo(const struct bpf_core_relo *relo,
				   const struct bpf_core_spec *spec,
				   __u64 *val, bool *validate)
```

行为很直接：

- 无目标类型时：返回 0（不存在）；
- `TYPE_ID_TARGET`：返回目标 root type ID；
- `TYPE_EXISTS/TYPE_MATCHES`：匹配成功即返回 1；
- `TYPE_SIZE`：调用 `btf__resolve_size()` 取目标类型大小；
- `TYPE_ID_LOCAL` 不在这里处理，而在 `bpf_core_calc_relo_insn()` 里特判。

注意 `TYPE_ID_TARGET` 默认关闭 validate：

```c
if (validate)
	*validate = false;
```

因为链接阶段可能已经改变了指令里原先携带的本地 type ID。

---

## 2.6 枚举值重定位：`bpf_core_calc_enumval_relo()`

位置：`src/relo_core.c:864`

签名：

```c
static int bpf_core_calc_enumval_relo(const struct bpf_core_relo *relo,
				      const struct bpf_core_spec *spec,
				      __u64 *val)
```

逻辑：

- `ENUMVAL_EXISTS`：有目标 spec 返回 1，否则 0；
- `ENUMVAL_VALUE`：读取 enum/enum64 成员值；
- 若目标枚举成员不存在，返回 `-EUCLEAN`，请求把指令 poison 掉。

---

## 2.7 类型匹配算法

### 2.7.1 成员匹配：`bpf_core_match_member()`

位置：`src/relo_core.c:482`

签名：

```c
static int bpf_core_match_member(const struct btf *local_btf,
				 const struct bpf_core_accessor *local_acc,
				 const struct btf *targ_btf,
				 __u32 targ_id,
				 struct bpf_core_spec *spec,
				 __u32 *next_targ_id)
```

这是“如何在目标 struct/union 中找到与本地字段同名的那个字段”的核心函数。

它的策略是：

1. 当前目标类型必须是 composite；
2. 取出本地字段名；
3. 枚举目标所有成员；
4. 若成员匿名，则递归深入；
5. 若成员命名且与本地字段名相同，再调用 `bpf_core_fields_are_compat()` 检查字段类型是否兼容；
6. 找到后把目标路径写入 `targ_spec`。

关键代码：

```c
if (str_is_empty(targ_name)) {
	found = bpf_core_match_member(..., m->type, ...);
} else if (strcmp(local_name, targ_name) == 0) {
	...
	found = bpf_core_fields_are_compat(local_btf,
					   local_member->type,
					   targ_btf, m->type);
```

### 2.7.2 名称匹配 vs 结构匹配

这里有两个层面：

#### (a) 候选类型层：名字优先

根类型候选是按 essential name（忽略 `___flavor`）筛选的，因此**先做名字匹配**。

#### (b) 字段层：名字 + 类型兼容

字段必须同名，然后再用 `bpf_core_fields_are_compat()` 判断兼容性。

兼容规则（`src/relo_core.c:396-412` 注释 + `413-464` 实现）大致是：

- struct/union：互相兼容；
- ptr：总是兼容；
- fwd/enum：要求名字（忽略 flavor）兼容或匿名；
- int：只要求不是老式 bitfield-like int，忽略 signedness/size；
- array：只递归比较元素类型，忽略维度；
- float：总兼容。

因此字段级匹配比“严格类型相等”宽松得多，它追求的是 **访问语义兼容**，而不是 C 类型系统意义上的完全等价。

### 2.7.3 `TYPE_MATCHES` 的结构匹配策略

更严格的匹配由 `__bpf_core_types_match()`（`src/relo_core.c:1561`）定义，用于 `BPF_CORE_TYPE_MATCHES`。

其规则比字段兼容更强：

- 名字必须匹配（忽略 flavor）；
- int 要求 size 与 signedness 一致；
- array 要求元素数相同；
- struct/union 要求本地所有成员在目标中都有同名且递归匹配的成员；
- 指针后方允许 struct/union 与对应 FWD 互相匹配；
- enum 与 enum64 可以互配，但枚举成员名集合必须兼容。

这个规则体现出：

> `FIELD_*` relocation 只要求“这个访问在目标类型上仍然成立”；
> `TYPE_MATCHES` 则要求“两个类型的结构语义仍可视为同一个类型”。

---

## 2.8 指令修补：`bpf_core_patch_insn()`

位置：`src/relo_core.c:1041`

签名：

```c
int bpf_core_patch_insn(const char *prog_name, struct bpf_insn *insn,
			int insn_idx, const struct bpf_core_relo *relo,
			int relo_idx, const struct bpf_core_relo_res *res)
```

### 2.8.1 支持的指令类别

源码注释 `src/relo_core.c:1024-1040` 给出支持范围：

1. `rX = imm`
2. `rX op= imm`
3. `ldimm64`
4. `ldx/st/stx` 的内存访问偏移

### 2.8.2 如何修改立即数/偏移

#### (a) ALU/ALU64

修改 `insn->imm`：

```c
if (res->validate && insn->imm != orig_val)
	return -EINVAL;
insn->imm = new_val;
```

#### (b) LDX/ST/STX

修改 `insn->off`：

```c
if (res->validate && insn->off != orig_val)
	return -EINVAL;
insn->off = new_val;
```

并在必要时调整访存宽度：

```c
if (res->new_sz != res->orig_sz) {
	...
	insn->code = BPF_MODE(insn->code) | insn_bpf_sz | BPF_CLASS(insn->code);
}
```

#### (c) LDIMM64

把 64 位值拆到两条指令的 `imm` 中：

```c
insn[0].imm = new_val;
insn[1].imm = new_val >> 32;
```

### 2.8.3 指令 poisoning

若 relocation 在“被条件守护的死代码路径”中可失败，libbpf 不直接报错，而是把指令变成一个无效 helper call：

```c
insn->code = BPF_JMP | BPF_CALL;
...
insn->imm = 195896080; /* "bad relo" */
```

如果该路径真的不可达，verifier 会忽略它；否则 verifier 会报错并把问题暴露出来。

### 2.8.4 内存宽度调整的安全条件

当字段大小变了，libbpf 只在两种情况下允许自动改 load/store 宽度：

1. 原类型和新类型都是指针；
2. 原类型和新类型都是**无符号整数**。

否则设置 `fail_memsz_adjust=true`，后续直接 poison 指令。

这一步是为了避免“偏移修对了，但读取字节数错了，结果值语义仍然错误”。

---

# Part 3：`btf_relocate.c`

## 3.1 场景和用途

### 3.1.1 它解决什么问题？

`btf_relocate.c` 处理的不是字段偏移 CO-RE，而是：

> 当一个 split BTF 绑定的是 ELF 中携带的“蒸馏 base BTF（`.BTF.base`）”，而运行时/用户态真正提供的是另一份完整 `base_btf` 时，如何把 split BTF 里引用的 base 类型 ID 和字符串偏移重新映射到真实 base。

入口函数：

| 函数 | 位置 | 签名 |
|---|---|---|
| `btf_relocate` | `src/btf_relocate.c:444` | `int btf_relocate(struct btf *btf, const struct btf *base_btf, __u32 **id_map)` |

### 3.1.2 与 CO-RE 的区别

| 维度 | `btf_relocate.c` | `relo_core.c` |
|---|---|---|
| 作用对象 | BTF 元数据本身 | BPF 指令中的 imm/off/mem size |
| 输入 | split BTF + distilled base BTF + real base BTF | local BTF + target BTF + CO-RE relocation records |
| 输出 | 改写后的 BTF type ID / string offset / base_btf 指针 | 每条 BPF 指令的新值 |
| 目标 | 让 split BTF 正确挂到真实 base BTF 上 | 让一次编译的 BPF 程序适配不同内核类型布局 |
| 粒度 | 类型系统级别 | 字段/类型/枚举成员访问级别 |

一句话：

- `btf_relocate.c` 是 **BTF 元数据重定位**；
- `relo_core.c` 是 **BPF 指令语义重定位**。

---

## 3.2 `btf_relocate()` 主流程

`src/btf_relocate.c:444-519`：

```c
r.dist_base_btf = btf__base_btf(btf);
...
for (id = r.nr_dist_base_types; id < nr_types; id++)
	r.id_map[id] = id + r.nr_base_types - r.nr_dist_base_types;
...
err = btf_relocate_map_distilled_base(&r);
...
for (...) btf_relocate_rewrite_type_id(&r, id);
for (...) btf_relocate_rewrite_strs(&r, ...);
btf_set_base_btf(btf, base_btf);
```

步骤：

1. 取出 `btf` 当前绑定的 distilled base BTF；
2. 为 split 区的 type ID 先整体平移到真实 base 之后；
3. 建立 distilled base type ID -> real base type ID 映射；
4. 重写 split BTF 里所有类型引用；
5. 重写 split BTF 里所有字符串偏移；
6. 最后把 `btf->base_btf` 从 distilled base 改成 real base。

---

## 3.3 蒸馏 base 的映射算法

### 3.3.1 验证蒸馏 base：`btf_relocate_validate_distilled_base()`

位置：`src/btf_relocate.c:383`

它要求 distilled base 里只能出现：

- named `INT/FLOAT/ENUM/STRUCT/UNION/FWD`

匿名类型和其他 kind 都非法。

这是因为 distilled base 本质上只是一份“可匹配轮廓索引”，不是完整 type graph。

### 3.3.2 建映射：`btf_relocate_map_distilled_base()`

位置：`src/btf_relocate.c:184`

这是 `btf_relocate.c` 的核心。

其算法：

1. 先把 distilled base 中所有类型抽成 `<name, size, id>` 数组并排序；
2. 对 split BTF 中嵌入式引用到的 distilled base struct/union，先标记 `BTF_IS_EMBEDDED`；
3. 统计 real base 中同名 composite 数量，判断某名字是否有歧义；
4. 遍历 real base 里的 named type，按 `(name[, size])` 去 binary search 匹配 distilled base；
5. 对每个候选，再按 kind-specific 规则二次验证；
6. 得出唯一映射，否则报错。

### 3.3.3 为什么要区分“嵌入式 composite”

函数：`btf_mark_embedded_composite_type_ids()`，`src/btf_relocate.c:132`

若 split struct/union 的某成员**直接嵌入**了一个 base struct/union，则大小必须匹配；若只是指针引用，则不要求大小匹配。

这和 `btf_dump_order_type()` 中“嵌入依赖比指针依赖更强”的思想是一致的：

- pointer 只需要符号身份；
- embedded member 需要真实布局兼容。

### 3.3.4 字符串重写：`btf_relocate_rewrite_strs()`

位置：`src/btf_relocate.c:412`

逻辑：

- 若字符串 offset 落在 distilled base 字符串区范围内，用 `str_map` 改成 real base 中对应 offset；
- 若是 split 自己新增的字符串，则整体平移：

```c
if (*str_off >= r->dist_str_len) {
	*str_off += r->base_str_len - r->dist_str_len;
} else {
	*str_off = r->str_map[*str_off];
}
```

这正好对应 split BTF 的“逻辑字符串空间”需要从 `distilled base + split` 切换成 `real base + split`。

---

# Part 4：`btf_iter.c` 的辅助作用

虽然 `src/btf_iter.c` 很短，但它是 `btf.c` 与 `btf_relocate.c` 大量遍历逻辑的基础设施。

## 4.1 关键函数

| 函数 | 位置 | 签名 |
|---|---|---|
| `btf_field_iter_init` | `src/btf_iter.c:16` | `int btf_field_iter_init(struct btf_field_iter *it, struct btf_type *t, enum btf_field_iter_kind iter_kind)` |
| `btf_field_iter_next` | `src/btf_iter.c:145` | `__u32 *btf_field_iter_next(struct btf_field_iter *it)` |

## 4.2 作用

它把“不同 BTF kind 中哪些字段是 type ID、哪些字段是 string offset”统一抽象成一个迭代器：

- `BTF_FIELD_ITER_IDS`：遍历所有 type ID 引用；
- `BTF_FIELD_ITER_STRS`：遍历所有字符串 offset 引用。

例如：

- dedup 要批量重写所有字符串；
- compact/remap 要批量重写所有 type ID；
- `btf_relocate.c` 也要对 split BTF 中所有引用做重写。

如果没有这个迭代器，每种 kind 都要手写一次遍历逻辑，复杂度会明显上升。

---

# Part 5：关键函数速查表

## 5.1 BTF 子系统

| 函数 | 位置 | 核心逻辑 |
|---|---|---|
| `btf_parse_hdr` | `btf.c:286` | 校验 header、section 布局、端序与 layout |
| `btf_parse_type_sec` | `btf.c:578` | 顺序扫描 type section，计算类型大小并建立 type_offs 索引 |
| `btf_new_empty` | `btf.c:1216` | 初始化可构建的 BTF 对象，支持 split BTF |
| `btf_parse_elf` | `btf.c:1447` | 从 ELF 取 `.BTF/.BTF.ext/.BTF.base` 并构造 BTF |
| `btf_parse_raw` | `btf.c:1559` | 解析原始 BTF blob |
| `btf__add_str` | `btf.c:2094` | 复用 base 字符串或写入本地 strset |
| `btf__add_type` | `btf.c:2230` | 复制单个类型并重写字符串偏移 |
| `btf__add_btf` | `btf.c:2240` | 批量追加另一个 BTF 的全部类型并重写 ID/字符串 |
| `btf__add_int` | `btf.c:2378` | 追加 INT 类型 |
| `btf__add_struct` | `btf.c:2602` | 追加 STRUCT 壳 |
| `btf__add_field` | `btf.c:2640` | 给当前 struct/union 追加字段 |
| `btf__dedup` | `btf.c:3891` | 执行完整 dedup pipeline |
| `btf_dedup_strings` | `btf.c:4198` | 字符串去重 + 垃圾回收 + offset 重写 |
| `btf_dedup_prep` | `btf.c:4556` | 把 base BTF 预置为 canonical 候选集 |
| `btf_dedup_struct_type` | `btf.c:5262` | struct/union/typedef 图等价 dedup |
| `btf_dedup_resolve_fwds` | `btf.c:5602` | 对剩余 FWD 做同名唯一解析 |
| `btf_dedup_compact_types` | `btf.c:5637` | 只保留 canonical 类型并重排 ID |
| `btf_dedup_remap_types` | `btf.c:5718` | 重写所有类型引用到新 ID |

## 5.2 BTF Dump

| 函数 | 位置 | 核心逻辑 |
|---|---|---|
| `btf_dump__dump_type` | `btf_dump.c:281` | 先排序再批量发射 C 定义 |
| `btf_dump_order_type` | `btf_dump.c:473` | 带强/弱依赖语义的拓扑排序 |
| `btf_dump_emit_type` | `btf_dump.c:689` | 根据 emit 状态发射定义或前置声明 |
| `btf_dump_emit_struct_def` | `btf_dump.c:967` | 输出 struct/union 定义、bitfield 与 padding |
| `btf_dump_emit_enum_def` | `btf_dump.c:1121` | 输出 enum/enum64 定义 |
| `btf_dump__emit_type_decl` | `btf_dump.c:1270` | 把 BTF 类型链还原为合法 C 声明 |

## 5.3 CO-RE

| 函数 | 位置 | 核心逻辑 |
|---|---|---|
| `bpf_core_parse_spec` | `relo_core.c:262` | 解析 `access_str` 为规范化访问路径 |
| `bpf_core_match_member` | `relo_core.c:482` | 在目标 composite 中递归查找同名兼容字段 |
| `bpf_core_spec_match` | `relo_core.c:558` | 将本地 spec 映射到目标 type candidate |
| `bpf_core_calc_field_relo` | `relo_core.c:679` | 计算字段 offset/size/signed/bitfield shifts |
| `bpf_core_calc_type_relo` | `relo_core.c:820` | 计算 type exists/size/id/matches |
| `bpf_core_calc_enumval_relo` | `relo_core.c:864` | 计算枚举成员存在性/值 |
| `bpf_core_calc_relo` | `relo_core.c:896` | 统一生成 `orig_val/new_val/poison/validate` |
| `bpf_core_patch_insn` | `relo_core.c:1041` | 修改 BPF 指令 imm/off/mem size，必要时 poison |
| `bpf_core_calc_relo_insn` | `relo_core.c:1297` | CO-RE 总入口，做 candidate 匹配、一致性检查与结果输出 |
| `__bpf_core_types_match` | `relo_core.c:1561` | `TYPE_MATCHES` 的严格结构匹配算法 |

## 5.4 BTF 元数据重定位

| 函数 | 位置 | 核心逻辑 |
|---|---|---|
| `btf_relocate_map_distilled_base` | `btf_relocate.c:184` | 建立 distilled base -> real base 的 type/string 映射 |
| `btf_relocate_validate_distilled_base` | `btf_relocate.c:383` | 验证蒸馏 base 结构合法性 |
| `btf_relocate_rewrite_strs` | `btf_relocate.c:412` | 改写 split BTF 内字符串偏移 |
| `btf_relocate` | `btf_relocate.c:444` | 完成 split BTF 对真实 base BTF 的整体重定位 |

---

# 结论

libbpf 的 BTF/CO-RE 体系可以概括成三层：

1. **BTF 容器层**（`btf.c`）
   - 负责格式解析、内部表示、构建、去重、split/base 关系维护；
2. **BTF 表达层**（`btf_dump.c`）
   - 负责把图状类型系统恢复为合法、尽量可编译的 C 代码；
3. **BTF 适配层**（`relo_core.c` + `btf_relocate.c`）
   - `btf_relocate.c` 解决 BTF 元数据与真实 base 的绑定；
   - `relo_core.c` 解决 BPF 指令对不同内核类型布局的适配。

其中最关键的设计思想有三点：

- **BTF 是图，不是表**：因此 dedup 和 dump 都必须做图遍历与图等价判断；
- **CO-RE 追求访问语义兼容，不追求字面类型相等**：字段匹配允许较宽松兼容；
- **split BTF 与 CO-RE 是两套不同层次的“重定位”**：前者修 BTF 元数据引用，后者修 BPF 指令语义。
