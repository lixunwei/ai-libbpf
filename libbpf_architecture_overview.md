# libbpf 整体架构概览

## 1. 项目基本信息

| 项目 | 信息 |
|---|---|
| 版本 | 1.8.0 |
| 源码规模 | ~51,204 行 (38,447行 .c + 12,757行 .h) |
| 核心语言 | C (gnu89) |
| 外部依赖 | libelf, zlib |
| 许可证 | LGPL-2.1 OR BSD-2-Clause |

---

## 2. 公开 API 设计

### 2.1 头文件总览

| 头文件 | 职责 | 目标用户 |
|---|---|---|
| `libbpf.h` | 核心 API: object/program/map/link 管理 | 用户态加载程序 |
| `bpf.h` | BPF syscall 低层封装 | 需要直接调用 syscall 的场景 |
| `btf.h` | BTF 类型信息 API | BTF 解析/构建工具 |
| `libbpf_common.h` | 公共宏 (LIBBPF_OPTS 等) | 所有 libbpf 用户 |
| `libbpf_legacy.h` | 遗留 API 兼容层 | 迁移旧代码 |
| `bpf_helpers.h` | BPF 程序端 helper/属性声明 | BPF C 程序 |
| `bpf_tracing.h` | Tracing 宏 (PT_REGS/BPF_PROG) | BPF tracing 程序 |
| `bpf_core_read.h` | CO-RE 读取宏 | 可移植 BPF 程序 |
| `bpf_endian.h` | 字节序转换 | BPF 网络程序 |
| `usdt.bpf.h` | USDT BPF 端支持 | USDT 跟踪程序 |

### 2.2 API 分组 (libbpf.h)

| 分组 | 函数数量 | 核心接口 |
|---|---|---|
| Object 生命周期 | ~16 | `bpf_object__open/load/close/pin` |
| Program 操作 | ~25+ | `bpf_program__attach*/fd/insns/type` |
| Map 操作 | ~20+ | `bpf_map__fd/lookup/update/delete/pin` |
| Link 操作 | ~10+ | `bpf_link__open/pin/detach/destroy` |
| Linker | ~7 | `bpf_linker__new/add_file/finalize/free` |
| Misc/Util | ~15+ | `libbpf_probe_*/version/strerror` |

### 2.3 BPF Syscall 封装 (bpf.h)

| 函数 | BPF 命令 |
|---|---|
| `bpf_prog_load()` | BPF_PROG_LOAD |
| `bpf_map_create()` | BPF_MAP_CREATE |
| `bpf_map_lookup_elem()` | BPF_MAP_LOOKUP_ELEM |
| `bpf_map_update_elem()` | BPF_MAP_UPDATE_ELEM |
| `bpf_map_delete_elem()` | BPF_MAP_DELETE_ELEM |
| `bpf_map_get_next_key()` | BPF_MAP_GET_NEXT_KEY |
| `bpf_map_freeze()` | BPF_MAP_FREEZE |
| `bpf_obj_pin()` | BPF_OBJ_PIN |
| `bpf_obj_get()` | BPF_OBJ_GET |
| `bpf_link_create()` | BPF_LINK_CREATE |
| `bpf_link_detach()` | BPF_LINK_DETACH |
| `bpf_link_update()` | BPF_LINK_UPDATE |
| `bpf_btf_load()` | BPF_BTF_LOAD |
| `bpf_iter_create()` | BPF_ITER_CREATE |
| `bpf_raw_tracepoint_open()` | BPF_RAW_TRACEPOINT_OPEN |
| `bpf_prog_test_run_opts()` | BPF_PROG_TEST_RUN |
| `bpf_enable_stats()` | BPF_ENABLE_STATS |
| `bpf_prog_get_fd_by_id()` | BPF_PROG_GET_FD_BY_ID |
| `bpf_map_get_fd_by_id()` | BPF_MAP_GET_FD_BY_ID |
| `bpf_obj_get_info_by_fd()` | BPF_OBJ_GET_INFO_BY_FD |

### 2.4 BTF API 分类 (btf.h, ~40+ 函数)

| 分类 | 核心函数 |
|---|---|
| 解析/加载 | `btf__new/parse/parse_elf/parse_raw/load_vmlinux_btf/load_from_kernel_by_id` |
| 查询/检视 | `btf__type_cnt/type_by_id/resolve_size/find_by_name/name_by_offset/raw_data` |
| 构建/修改 | `btf__add_int/struct/union/enum/func/var/datasec/...` (30+种类型添加) |
| 高级操作 | `btf__dedup/relocate/permute/distill_base` |
| BTF ext | `btf_ext__new/free/raw_data` |
| Dump | `btf_dump__dump_type/free` |

### 2.5 核心设计模式

#### opts 结构体模式（可扩展 API 设计）
```c
struct bpf_object_open_opts {
    size_t sz;              // 结构体大小，用于版本兼容
    const char *object_name;
    // ... 其他可选参数 ...
    size_t :0;              // 强制对齐标记
};
#define bpf_object_open_opts__last_field ...

// 使用方式
LIBBPF_OPTS(bpf_object_open_opts, opts,
    .object_name = "my_prog",
);
```

#### 错误处理约定
- **新 API**: 返回 `NULL`(指针) 或 `-errno`(整型)，同时设置 `errno`
- **旧 API**: ERR_PTR 风格（通过 `libbpf_get_error()` 检查）
- **内部**: `libbpf_err()` / `libbpf_err_errno()` / `libbpf_ptr()` 统一包装

#### 符号版本化 (libbpf.map)
- GNU version script 方案
- 从 `LIBBPF_0.0.1` 到 `LIBBPF_1.8.0` 逐版本累积
- `local: *;` 隐藏所有未导出符号
- 每个版本节点继承前一版本

---

## 3. 核心数据结构

### 3.1 struct bpf_object（核心容器）

定义位置: `libbpf.c:701-778`

```
struct bpf_object
├── 基本信息
│   ├── name[BPF_OBJ_NAME_LEN]   — 对象名称
│   ├── license[64]               — 许可证字符串
│   ├── kern_version              — 内核版本要求
│   └── state                     — 当前状态 (OPEN/PREPARED/LOADED)
│
├── 程序管理
│   ├── *programs                 — bpf_program 数组
│   └── nr_programs               — 程序数量
│
├── Map 管理
│   ├── *maps                     — bpf_map 数组
│   ├── nr_maps                   — 当前数量
│   └── maps_cap                  — 数组容量
│
├── BTF 信息
│   ├── *btf                      — 用户态 BTF
│   ├── *btf_ext                  — BTF 扩展信息 (func_info/line_info/core_relo)
│   ├── *btf_vmlinux              — 内核 vmlinux BTF（CO-RE 用）
│   └── *btf_vmlinux_override     — 自定义 BTF override
│
├── Extern / Kconfig
│   ├── *kconfig                  — kconfig 数据
│   ├── *externs                  — extern 变量描述数组
│   ├── nr_extern                 — extern 数量
│   └── kconfig_map_idx           — kconfig map 索引
│
├── ELF 工作区
│   └── efile (struct elf_state)  — libelf 解析上下文
│
├── 运行时
│   ├── *fd_array                 — fd 数组
│   ├── *feat_cache               — 内核特性缓存
│   ├── token_fd                  — BPF token fd
│   └── *token_path               — token 路径
│
└── 其它
    ├── *usdt_man                  — USDT 管理器
    └── *arena_data                — Arena 数据
```

### 3.2 struct bpf_program（程序实例）

定义位置: `libbpf.c:445-517`

```
struct bpf_program
├── 标识
│   ├── *name                     — 函数名
│   ├── *sec_name                 — section 名 (如 "tracepoint/...")
│   ├── sec_idx                   — ELF section 索引
│   └── *sec_def                  — section 定义（含程序类型映射）
│
├── 代码
│   ├── *insns                    — BPF 指令数组
│   ├── insns_cnt                 — 指令数
│   ├── sec_insn_off              — section 内偏移
│   └── sec_insn_cnt              — section 指令总数
│
├── 重定位
│   ├── *reloc_desc               — 重定位描述数组
│   └── nr_reloc                  — 重定位条目数
│
├── 子程序
│   ├── *subprogs                 — 子程序信息数组
│   └── subprog_cnt               — 子程序数量
│
├── 内核/Attach
│   ├── fd                        — 内核 prog fd
│   ├── autoload / autoattach     — 自动加载/attach 标志
│   ├── type                      — bpf_prog_type
│   ├── expected_attach_type      — 期望的 attach 类型
│   ├── attach_btf_id             — attach 的 BTF 类型 ID
│   └── attach_prog_fd            — attach 目标程序 fd
│
├── BTF 信息
│   ├── *func_info / func_info_cnt
│   └── *line_info / line_info_cnt
│
├── 调试
│   ├── *log_buf / log_size / log_level
│   └── hash[32]                  — 程序内容哈希
│
└── 反向引用
    └── *obj                       — 所属 bpf_object
```

### 3.3 struct bpf_map（Map 实例）

定义位置: `libbpf.c:563-597`

```
struct bpf_map
├── 标识
│   ├── *name / *real_name        — Map 名称
│   ├── sec_idx / sec_offset      — ELF 位置
│   └── libbpf_type               — libbpf 内部分类
│
├── 配置
│   ├── def (struct bpf_map_def)  — 类型/key_size/value_size/max_entries
│   ├── map_ifindex               — 网络设备索引
│   ├── numa_node                 — NUMA 节点
│   └── map_extra                 — 额外配置
│
├── 内核
│   ├── fd                        — 内核 map fd
│   └── inner_map_fd              — 内部 map fd (map-in-map)
│
├── BTF
│   ├── btf_var_idx               — BTF 变量索引
│   ├── btf_key_type_id           — key 的 BTF 类型
│   ├── btf_value_type_id         — value 的 BTF 类型
│   └── btf_vmlinux_value_type_id — vmlinux BTF 类型
│
├── 内存映射
│   ├── *mmaped                   — mmap 的数据区
│   └── *st_ops                   — struct_ops 信息
│
├── Pin / 状态
│   ├── *pin_path                 — pin 路径
│   ├── pinned / reused           — 状态标志
│   └── autocreate / autoattach   — 自动创建/attach
│
└── 反向引用
    └── *obj                       — 所属 bpf_object
```

### 3.4 struct btf_ext（BTF 扩展信息）

定义位置: `libbpf_internal.h:506-517`

```
struct btf_ext
├── hdr / *data                   — 原始头和数据
├── data_swapped                  — 字节序交换标记
├── swapped_endian                — 是否交换了字节序
├── data_size                     — 数据大小
└── 子段
    ├── func_info (btf_ext_info)  — 函数信息段
    ├── line_info (btf_ext_info)  — 行号信息段
    └── core_relo_info (btf_ext_info) — CO-RE 重定位信息段
```

### 3.5 内部工具数据结构

#### hashmap（哈希表）
- 开链法，初始 4 桶，负载 >75% 扩容
- key/value 兼容 `long` 或 `void*`
- 插入策略: ADD / SET / UPDATE / APPEND

#### strset（字符串集合）
- 连续 buffer 存储所有字符串（`\0` 分隔）
- hashmap 存偏移量实现去重
- 不为每个字符串单独 malloc

---

## 4. 对象生命周期

### 4.1 Open 阶段

```
bpf_object__open_file(path, opts)
  └── bpf_object__open_mem(data, size, opts)
        └── bpf_object_open(data, size, name, opts)
              ├── bpf_object__new(name, data, size, path)
              ├── bpf_object__elf_init()           — libelf 初始化
              ├── bpf_object__elf_collect()         — 收集 ELF sections
              │     ├── 识别 .text/.maps/.BTF 等 section
              │     ├── 创建 bpf_program 实例
              │     └── 创建 bpf_map 实例
              ├── bpf_object__collect_externs()     — 收集外部变量
              ├── bpf_object_fixup_btf()           — BTF 修正
              ├── bpf_object__init_maps()           — 初始化 Map 配置
              ├── bpf_object_init_progs()           — 初始化程序属性
              ├── bpf_object__collect_relos()       — 收集重定位信息
              └── bpf_object__elf_finish()          — 释放 ELF 资源
```

### 4.2 Prepare 阶段（Load 的前半部分）

```
bpf_object_prepare(obj)
  ├── bpf_object_prepare_token()         — 准备 BPF token
  ├── bpf_object__probe_loading()        — 探测加载能力
  ├── bpf_object__load_vmlinux_btf()     — 加载内核 BTF
  ├── bpf_object__resolve_externs()      — 解析外部引用
  ├── bpf_object__sanitize_maps()        — Map 清理/降级
  ├── bpf_object__init_kern_struct_ops_maps() — struct_ops 初始化
  ├── bpf_object__relocate()             — 执行重定位
  │     ├── CO-RE 重定位 (relo_core.c)
  │     ├── Map fd 重定位
  │     └── 子程序调用重定位
  ├── bpf_object__sanitize_and_load_btf() — BTF 加载到内核
  ├── bpf_object__create_maps()          — 创建 Maps
  └── bpf_object_prepare_progs()         — 准备程序
```

### 4.3 Load 阶段

```
bpf_object__load(obj)
  └── bpf_object_load(obj)
        ├── bpf_object_prepare(obj)          — 若未 prepare
        ├── bpf_object__load_progs(obj)      — 加载所有程序到内核
        │     └── 对每个 prog 调用 bpf_prog_load() syscall
        ├── bpf_object_post_load_cleanup()   — 清理临时数据
        └── state = OBJ_LOADED
```

### 4.4 Destroy 阶段

```
bpf_object__close(obj)
  ├── bpf_object_post_load_cleanup()
  ├── usdt_manager_free()
  ├── bpf_gen__free()
  ├── bpf_object__elf_finish()
  ├── bpf_object_unload()              — close 所有 fd
  ├── btf__free(btf / btf_vmlinux)
  ├── btf_ext__free(btf_ext)
  ├── 对每个 map: bpf_map__destroy()
  ├── 释放 externs/kconfig/token_path
  └── free(obj)
```

---

## 5. 模块分层架构

### 5.1 四层架构

```
┌─────────────────────────────────────────────────────────────┐
│                     功能/应用层                               │
│  libbpf.c | netlink.c | ringbuf.c | features.c | usdt.c    │
│  gen_loader.c | libbpf_probes.c                             │
├─────────────────────────────────────────────────────────────┤
│                   解析/重定位/工具层                          │
│  relo_core.c | btf_relocate.c | linker.c                   │
├─────────────────────────────────────────────────────────────┤
│                   数据结构/类型层                             │
│  btf.c | btf_dump.c | btf_iter.c | strset.c               │
├─────────────────────────────────────────────────────────────┤
│                     基础/叶子层                               │
│  hashmap.c | nlattr.c | zip.c | elf.c | bpf.c             │
│  libbpf_utils.c | bpf_prog_linfo.c                        │
└─────────────────────────────────────────────────────────────┘

外部依赖: libelf | zlib | linux kernel headers
```

### 5.2 模块依赖关系图

```
                    ┌─────────┐
                    │ hashmap │ (无依赖，最底层)
                    └────┬────┘
                         │
                    ┌────▼────┐
                    │  strset │
                    └────┬────┘
                         │
              ┌──────────▼──────────┐
              │       btf.c         │ (依赖 hashmap + strset)
              └──┬───────┬────┬─────┘
                 │       │    │
        ┌────────▼─┐  ┌──▼──┐ │
        │ btf_dump │  │btf_ │ │
        │          │  │iter │ │
        └──────────┘  └─────┘ │
                               │
         ┌─────────────────────▼─────────┐
         │          relo_core.c          │
         │        btf_relocate.c         │
         └───────────────┬───────────────┘
                         │
    ┌────────────────────▼────────────────────┐
    │              libbpf.c (核心)             │
    │  (依赖: bpf.c, btf.c, hashmap, zip,    │
    │   elf.c, relo_core, gen_loader)         │
    └──┬──────────┬──────────┬──────────┬─────┘
       │          │          │          │
  ┌────▼───┐ ┌───▼────┐ ┌───▼───┐ ┌───▼────────┐
  │netlink │ │ringbuf │ │ usdt  │ │gen_loader  │
  │(nlattr)│ │        │ │       │ │            │
  └────────┘ └────────┘ └───────┘ └────────────┘

  ┌──────────┐  ┌──────────────┐
  │features.c│  │libbpf_probes │ (都依赖 bpf.c)
  └──────────┘  └──────────────┘

  ┌──────────┐
  │ linker.c │ (依赖 btf.c + strset + libelf)
  └──────────┘
```

### 5.3 各模块外部依赖

| 模块 | 外部库 |
|---|---|
| libbpf.c | libelf, gelf, zlib |
| btf.c | gelf (ELF BTF 解析) |
| linker.c | libelf |
| usdt.c | libelf, gelf |
| elf.c | libelf, gelf |
| netlink.c | sys/socket, linux/rtnetlink |
| ringbuf.c | sys/epoll |
| 其余模块 | 仅 linux kernel headers |

---

## 6. BPF 程序端头文件

### 6.1 bpf_helpers.h — 核心辅助

| 分类 | 关键宏/符号 |
|---|---|
| Map 声明 | `__uint()`, `__type()`, `__array()`, `__ulong()` |
| Section | `SEC(name)` |
| 属性 | `__always_inline`, `__noinline`, `__weak`, `__hidden` |
| 标记 | `__kconfig`, `__ksym`, `__kptr`, `__percpu_kptr`, `__uptr` |
| 循环 | `bpf_for_each()`, `bpf_for()`, `bpf_repeat()` |
| 打印 | `bpf_printk`, `BPF_SEQ_PRINTF`, `BPF_SNPRINTF` |
| Tail call | `bpf_tail_call_static()` |
| 参数标注 | `__arg_ctx`, `__arg_nonnull`, `__arg_trusted` 等 |

### 6.2 bpf_tracing.h — 架构抽象

- 支持架构: x86, arm, arm64, s390, mips, powerpc, sparc, riscv, arc, loongarch
- 寄存器映射: `__PT_PARM1_REG` ... `__PT_PARM8_REG`, `__PT_RET_REG`, `__PT_SP_REG`, `__PT_IP_REG`
- 入口宏: `BPF_PROG()`, `BPF_KPROBE()`, `BPF_KRETPROBE()`, `BPF_UPROBE()`, `BPF_URETPROBE()`, `BPF_KSYSCALL()`

### 6.3 bpf_core_read.h — CO-RE 宏

| 宏 | 用途 |
|---|---|
| `bpf_core_field_exists(field)` | 检查字段是否存在 |
| `bpf_core_field_size(field)` | 获取字段大小 |
| `bpf_core_field_offset(field)` | 获取字段偏移 |
| `bpf_core_type_exists(type)` | 检查类型是否存在 |
| `bpf_core_type_size(type)` | 获取类型大小 |
| `bpf_core_type_matches(type)` | 类型匹配检查 |
| `BPF_CORE_READ(src, field)` | CO-RE 安全读取 |
| `BPF_CORE_READ_BITFIELD(s, f)` | 位域读取 |

---

## 7. 内存管理模式

### 7.1 数组增长
- 使用 `libbpf_reallocarray(ptr, count+1, sizeof(*ptr))` 逐个增长
- Map 数组有 `maps_cap` 容量预留

### 7.2 字符串管理
- 大量使用 `strdup()` 保存字符串
- 统一用 `zfree(&ptr)` 释放并置 NULL
- `strset` 内部用连续 buffer + 哈希去重（不为每个字符串单独分配）

### 7.3 错误清理
- 标准模式: `goto err_out` + 清理函数
- `bpf_object__close()` 作为"总清理"，任何阶段失败都可安全调用
- `bpf_program__exit()` 先 unload 再释放内部资源

---

## 8. 关键设计决策总结

| 设计点 | 决策 | 原因 |
|---|---|---|
| API 扩展性 | opts struct + sz 字段 | 二进制兼容，新字段可零值默认 |
| ABI 稳定性 | libbpf.map 符号版本 | 支持多版本共存 |
| 内部复用 | hashmap/strset 共享 | 避免重复实现，统一内存模式 |
| BTF 处理 | 与 ELF 解耦 | 支持 raw BTF、split BTF、内核 BTF 多来源 |
| CO-RE | 编译时标记 + 运行时重定位 | 一次编译，多版本运行 |
| 错误处理 | -errno + errno 双保险 | 兼容旧 ERR_PTR 和新 NULL 风格 |
| Map 声明 | BTF-defined maps (.maps section) | 比旧式 struct bpf_map_def 更灵活 |
