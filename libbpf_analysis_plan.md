# libbpf 源码深入分析与实践计划

## 输出约定

- **所有分析文档使用中文描述**
- **所有文档和实践代码落盘到本目录**: `libbpf/darren/`
- 分析文档: `darren/*.md`
- 实践代码: `darren/practice/*/`

---

## 项目概览

| 项目 | 信息 |
|---|---|
| libbpf 版本 | 1.8.0 |
| 源码规模 | ~51,204 行 (38,447行 .c + 12,757行 .h) |
| 核心文件数 | 22个 .c 文件 + 22个 .h 文件 |
| 最大文件 | libbpf.c (14,762行) |
| Linux Kernel 源码 | `/home/nio/sda/source/Linux/linux` |
| Kernel eBPF 知识库 | `/home/nio/sda/source/Linux/linux/darren/bpf/` (19篇深度分析) |
| Kernel 工具链知识 | `/home/nio/sda/source/Linux/linux/darren/tools/` (clangd, QEMU, ftrace等) |

### 源码文件规模排名

| 文件 | 行数 | 职责 |
|---|---|---|
| libbpf.c | 14,762 | 核心库：程序/对象/Map 加载与管理 |
| btf.c | 6,360 | BTF 类型信息解析、构建、dedup |
| linker.c | 3,116 | BPF 目标文件链接器 |
| btf_dump.c | 2,617 | BTF 信息格式化输出 |
| relo_core.c | 1,704 | CO-RE 重定位核心算法 |
| usdt.c | 1,688 | USDT (User Statically Defined Tracepoint) |
| bpf.c | 1,419 | BPF syscall 低层封装 |
| gen_loader.c | 1,253 | Skeleton 轻量级 loader 生成 |
| netlink.c | 938 | Netlink 通信 (XDP/TC attach) |
| features.c | 727 | 内核特性探测 |
| ringbuf.c | 684 | Ring Buffer 用户态消费者 |
| elf.c | 558 | ELF 解析 |
| btf_relocate.c | 519 | BTF 重定位 |
| libbpf_probes.c | 479 | 程序/Map 类型探测 |
| zip.c | 358 | ZIP 文件支持 (USDT用) |
| nlattr.c | 319 | Netlink 属性处理 |
| hashmap.c | 299 | 内部哈希表实现 |
| strset.c | 194 | 字符串集合 |
| libbpf_utils.c | 161 | 工具函数 |
| btf_iter.c | 59 | BTF 迭代器 |
| bpf_prog_linfo.c | 167 | 程序行信息 |

---

## 阶段一：索引建立与环境准备

### 任务 1.1：source-analysis 索引建立
**目标**: 对 libbpf 源码建立完整的代码索引，支持语义分析

**具体步骤**:
1. 调用 source-analysis skill，对 `/home/nio/sda/source/Linux/eBPF/libbpf` 建立索引
2. 索引类型包括:
   - **clangd** — LSP 语义分析（定义跳转、引用查找、调用层次、类型信息）
   - **zoekt** — 全文代码搜索
   - **ctags** — 符号索引（函数、结构体、宏定义）
   - **cscope** — 调用图追踪
3. 验证索引:
   - 测试 `bpf_object__open` 的定义查找
   - 测试 `struct bpf_object` 的引用查找
   - 测试 `bpf_prog_load` 的调用层次

### 任务 1.2：编译环境验证
**目标**: 确保 libbpf 可以正常编译，生成分析所需的编译数据库

**具体步骤**:
1. 安装编译依赖: `libelf-dev`, `zlib1g-dev`
2. 在 `src/` 下执行编译: `make`
3. 使用 `bear` 或手动方式生成 `compile_commands.json`（供 clangd 使用）
4. 确认编译产物: `libbpf.a`, `libbpf.so`

---

## 阶段二：架构层分析（自顶向下）

### 任务 2.1：公开 API 层分析
**目标**: 全面理解 libbpf 暴露给用户的接口

**分析文件**:
| 头文件 | 职责 |
|---|---|
| `libbpf.h` | 核心用户态 API（bpf_object/program/map/link 操作） |
| `bpf.h` | BPF syscall 低层封装（prog_load/map_create 等） |
| `btf.h` | BTF 类型信息 API（解析/构建/遍历） |
| `libbpf_common.h` | 公共宏、属性标记、版本定义 |
| `libbpf_legacy.h` | 遗留 API 兼容层 |
| `bpf_helpers.h` | BPF 程序端 helper 函数声明 |
| `bpf_tracing.h` | BPF 程序端 tracing 宏（PT_REGS 等） |
| `bpf_core_read.h` | BPF 程序端 CO-RE 读取宏 |
| `bpf_endian.h` | 字节序转换 |
| `usdt.bpf.h` | BPF 程序端 USDT 支持 |

**分析重点**:
- API 命名规范与设计模式（opts 结构体模式）
- API 版本兼容策略（libbpf.map 符号版本化）
- 错误处理模式（errno 返回 vs 指针返回）

**输出**: 整合到 `libbpf_architecture_overview.md`

### 任务 2.2：内部架构分析
**目标**: 理解 libbpf 内部核心数据结构和设计模式

**核心数据结构**:
```
bpf_object
  ├── bpf_program[]     — BPF 程序实例
  │     ├── 指令数据 (insns)
  │     ├── 重定位信息
  │     └── attach 类型
  ├── bpf_map[]         — BPF Map 实例
  │     ├── 类型/大小配置
  │     └── 内核 fd
  ├── btf / btf_ext     — BTF 类型信息
  └── ELF 数据          — 原始 ELF 解析结果
```

**分析重点**:
- `libbpf_internal.h` 中的内部结构定义
- 对象生命周期管理（open → load → destroy）
- 内存管理策略
- 错误传播机制

**输出**: 整合到 `libbpf_architecture_overview.md`

### 任务 2.3：模块依赖关系图
**目标**: 绘制各 .c 文件间的调用依赖关系

**方法**:
1. 利用 source-analysis 的调用层次分析
2. 分析各模块间的 #include 关系
3. 追踪核心函数的跨模块调用

**输出**: 整合到 `libbpf_architecture_overview.md`（含 ASCII/Mermaid 关系图）

---

## 阶段三：核心模块深度分析

### 任务 3.1：BPF 程序加载全流程 — `libbpf.c` (14,762行)
**目标**: 完整理解 BPF 程序从 ELF 文件到内核运行的全流程

**分析路径**:
```
bpf_object__open_file()
  → bpf_object__open_mem()     // 内存映射
  → bpf_object_open()          // ELF 解析初始化
  → bpf_object__elf_init()     // libelf 初始化
  → bpf_object__elf_collect()  // 收集 sections
  → bpf_object__collect_externs() // 外部变量
  → bpf_object__finalize_btf() // BTF 处理

bpf_object__load()
  → bpf_object__probe_loading() // 探测加载能力
  → bpf_object__resolve_externs() // 解析外部引用
  → bpf_object__sanitize_maps() // Map 清理
  → bpf_object__create_maps()  // 创建 Maps
  → bpf_object__relocate()     // 重定位（含 CO-RE）
  → bpf_object__load_progs()   // 加载程序到内核
```

**关联内核知识**:
- `ebpf_prog_loading_full_flow.md` — 内核端加载流程
- kernel 源码 `kernel/bpf/syscall.c` — `bpf_prog_load()` 系统调用处理

**输出**: `libbpf_program_loading_deep.md`

### 任务 3.2：BPF Syscall 封装层 — `bpf.c` (1,419行)
**目标**: 理解 libbpf 如何封装 BPF 系统调用

**核心函数**:
| 函数 | 对应 bpf cmd |
|---|---|
| `bpf_prog_load()` | BPF_PROG_LOAD |
| `bpf_map_create()` | BPF_MAP_CREATE |
| `bpf_map_lookup_elem()` | BPF_MAP_LOOKUP_ELEM |
| `bpf_map_update_elem()` | BPF_MAP_UPDATE_ELEM |
| `bpf_map_delete_elem()` | BPF_MAP_DELETE_ELEM |
| `bpf_obj_pin()` | BPF_OBJ_PIN |
| `bpf_obj_get()` | BPF_OBJ_GET |
| `bpf_link_create()` | BPF_LINK_CREATE |
| `bpf_prog_test_run_opts()` | BPF_PROG_TEST_RUN |

**分析重点**:
- `bpf_attr` 联合体的构造方式
- 重试机制与错误处理
- 特性探测（通过尝试创建并检查错误码）

**关联内核知识**:
- kernel 源码 `kernel/bpf/syscall.c`
- `ebpf_helper_kfunc_mechanism_deep.md`

**输出**: `libbpf_syscall_layer_deep.md`

### 任务 3.3：BTF 子系统 — `btf.c` (6,360行) + `btf_dump.c` (2,617行)
**目标**: 深入理解 BTF 类型系统在用户态的完整实现

**btf.c 分析路径**:
```
BTF 解析:
  btf__parse_elf() → btf__parse_raw() → btf_parse_raw()
    → 解析 header → 解析 type section → 解析 string section

BTF 构建:
  btf__new_empty() → btf__add_*() 系列函数
    → btf__add_int/struct/union/enum/typedef/func/...

BTF Dedup (去重):
  btf__dedup() — 核心算法，消除冗余类型
    → 字符串去重 → 类型图构建 → 等价类分析 → 合并
```

**btf_dump.c 分析路径**:
```
btf_dump__dump_type() — C 语言格式输出
  → 类型排序（拓扑排序，处理依赖）
  → 格式化输出（struct/union/enum/typedef）
```

**关联内核知识**:
- `ebpf_btf_core_deep.md` — BTF 核心原理
- `ebpf_btf_verifier_trampoline_jit_deep.md` — 内核 BTF 验证器

**输出**: `libbpf_btf_core_deep.md`

### 任务 3.4：CO-RE 重定位引擎 — `relo_core.c` (1,704行)
**目标**: 理解 CO-RE (Compile Once, Run Everywhere) 的核心算法

**核心函数**:
```
bpf_core_calc_relo_insn()
  → bpf_core_calc_field_relo()    // 字段重定位
  → bpf_core_calc_type_relo()     // 类型重定位
  → bpf_core_calc_enumval_relo()  // 枚举值重定位

bpf_core_match_member()           // 成员匹配算法
bpf_core_find_cands()             // 候选类型查找
```

**分析重点**:
- 类型匹配算法（结构体/联合体/枚举的名称+结构匹配）
- 字段偏移计算（位域处理、嵌套结构）
- 重定位种类: FIELD_BYTE_OFFSET, FIELD_EXISTS, TYPE_SIZE, ENUMVAL_VALUE 等
- 与内核 BTF 的对比匹配流程

**关联内核知识**:
- `ebpf_btf_core_deep.md` — CO-RE 内核端实现
- libbpf `bpf_core_read.h` — BPF 程序端宏

**输出**: 整合到 `libbpf_btf_core_deep.md`

### 任务 3.5：ELF 处理 — `elf.c` (558行)
**目标**: 理解 BPF ELF 文件格式与解析

**分析重点**:
- BPF ELF 的 section 命名约定（如 `tracepoint/xxx`, `kprobe/xxx`, `xdp`）
- 程序类型自动推断（section name → bpf_prog_type）
- Map 定义在 ELF 中的编码（.maps section）
- 符号表与重定位表的处理

**输出**: `libbpf_elf_linker_deep.md`

### 任务 3.6：BPF Linker — `linker.c` (3,116行)
**目标**: 理解 BPF 目标文件链接器的实现

**分析重点**:
- 多个 .o 文件的合并策略
- 符号解析（强/弱符号、全局/局部）
- BTF 信息合并与去重
- 重定位信息合并
- 与 bpftool linker 命令的关系

**关联**: 内核 `bpf_link` 概念（但不同——linker 是编译时，link 是运行时）

**输出**: 整合到 `libbpf_elf_linker_deep.md`

### 任务 3.7：Ring Buffer — `ringbuf.c` (684行)
**目标**: 理解用户态 Ring Buffer 消费者实现

**分析重点**:
```
ring_buffer__new()
  → mmap 映射内核 ring buffer 页面
  → epoll 注册

ring_buffer__poll() / ring_buffer__consume()
  → 读取 producer/consumer 位置
  → 处理 wrap-around
  → 回调用户处理函数
```

**关联内核知识**:
- `ebpf_perf_ringbuf_userspace_deep.md` — perf buffer vs ring buffer 对比
- 内核 `kernel/bpf/ringbuf.c`

**输出**: `libbpf_ringbuf_usdt_deep.md`

### 任务 3.8：USDT 支持 — `usdt.c` (1,688行)
**目标**: 理解用户态静态跟踪点的实现

**分析重点**:
- ELF note section 解析（.note.stapsdt）
- USDT 参数解析（位置表达式）
- Semaphore 机制（启用/禁用探测点）
- uprobe 底层实现
- ZIP 文件中的 USDT（用于 Java/.NET 等打包场景）

**输出**: 整合到 `libbpf_ringbuf_usdt_deep.md`

### 任务 3.9：Skeleton & Gen Loader — `gen_loader.c` (1,253行)
**目标**: 理解 BPF skeleton 和轻量级 loader 的生成

**分析重点**:
```
bpftool gen skeleton → 生成 .skel.h
  → 包含 BPF 程序字节码
  → 包含 open/load/attach/destroy 便捷函数

gen_loader:
  → 生成 BPF 指令序列来执行加载
  → 避免用户态 libbpf 依赖（内核自加载）
```

**关联**:
- bpftool skeleton 命令
- `ebpf_tailcall_bpf2bpf_deep.md`（函数调用机制）

**输出**: `libbpf_skeleton_genloader_deep.md`

### 任务 3.10：Netlink 通信 — `netlink.c` (938行) + `nlattr.c` (319行)
**目标**: 理解 XDP/TC 程序通过 netlink 进行 attach 的机制

**分析重点**:
- Netlink 消息构造（RTM_SETLINK, RTM_NEWLINK 等）
- XDP 程序 attach（generic/native/offloaded 模式）
- TC BPF 程序 attach（cls_bpf classifier）
- Netlink 属性编解码（nlattr）

**关联内核知识**:
- `ebpf_xdp_native_generic_deep.md` — XDP 实现
- `ebpf_networking_datapath_deep.md` — 网络数据路径

**输出**: `libbpf_netlink_features_deep.md`

### 任务 3.11：Feature Probing — `features.c` (727行) + `libbpf_probes.c` (479行)
**目标**: 理解内核 BPF 特性探测机制

**分析重点**:
```
libbpf_probe_bpf_prog_type()  — 探测程序类型支持
libbpf_probe_bpf_map_type()   — 探测 Map 类型支持
libbpf_probe_bpf_helper()     — 探测 Helper 函数支持
```

**探测原理**: 尝试创建最小 BPF 程序/Map，根据内核返回的错误码判断是否支持

**关联内核知识**:
- `ebpf_map_deep_analysis.md` — Map 类型全景
- `ebpf_map_impl_comparison_deep.md` — Map 实现对比

**输出**: 整合到 `libbpf_netlink_features_deep.md`

---

## 阶段四：关键数据流追踪

### 4.1 BPF 程序从源码到运行的完整路径
```
[用户编写 BPF C 代码]
        │
        ▼
[clang -target bpf] ──→ BPF ELF 目标文件 (.o)
        │                    │
        │               ┌────┴────────────┐
        │               │ .text (BPF指令)  │
        │               │ .maps (Map定义)  │
        │               │ .BTF (类型信息)  │
        │               │ .BTF.ext (行信息)│
        │               │ .rel* (重定位)   │
        │               └─────────────────┘
        ▼
[bpf_object__open()] ──→ libbpf 解析 ELF
        │
        ├─ ELF section 遍历与分类
        ├─ bpf_program 实例创建
        ├─ bpf_map 实例创建
        ├─ BTF 数据解析
        └─ 外部变量收集
        │
        ▼
[bpf_object__load()] ──→ libbpf 加载到内核
        │
        ├─ Map 创建 (bpf_map_create syscall)
        ├─ CO-RE 重定位 (relo_core.c)
        │     ├─ 读取内核 BTF (/sys/kernel/btf/vmlinux)
        │     ├─ 类型匹配
        │     └─ 指令修补
        ├─ Map fd 重定位 (指令中嵌入 Map fd)
        └─ 程序加载 (bpf_prog_load syscall)
              └─ 内核 verifier 校验
        │
        ▼
[bpf_program__attach_*()] ──→ attach 到内核 hook 点
        │
        ├─ kprobe/tracepoint → perf_event_open + ioctl
        ├─ XDP → netlink RTM_SETLINK
        ├─ TC → netlink (cls_bpf)
        ├─ cgroup → bpf_link_create syscall
        └─ ...
```

### 4.2 Map 创建与访问流程
```
[ELF .maps section] → bpf_object__init_maps()
        │
        ▼
[bpf_object__create_maps()] → bpf_map_create() syscall
        │
        ├─ 返回 Map fd
        ├─ 更新程序指令中的 Map fd 引用
        └─ 用户态通过 bpf_map__fd() 获取 fd
        │
        ▼
[用户态操作]:
  bpf_map__lookup_elem() → BPF_MAP_LOOKUP_ELEM
  bpf_map__update_elem() → BPF_MAP_UPDATE_ELEM
  bpf_map__delete_elem() → BPF_MAP_DELETE_ELEM
```

### 4.3 BTF 信息流
```
[clang 编译] → .BTF section (DWARF → BTF)
        │
        ▼
[libbpf btf__parse] → struct btf (用户态表示)
        │
        ├─ btf__dedup() → 类型去重
        ├─ CO-RE: 与内核 BTF 对比匹配
        │     └─ /sys/kernel/btf/vmlinux (内核BTF)
        └─ btf_dump: 格式化输出 (bpftool btf dump)
```

---

## 阶段五：实践验证

### 任务 5.1：QEMU 调试环境搭建
**目标**: 搭建可调试的 BPF 运行环境

**参考知识库**:
- `qemu_bpf_verification.md` — QEMU BPF 验证环境
- `qemu_ebpf_bpftrace_debug.md` — QEMU eBPF 调试
- `qemu_ftrace_setup.md` — QEMU ftrace 环境

**具体步骤**:
1. 编译自定义内核（启用 BPF 完整配置）
2. 制作 rootfs（包含 libbpf + bpftool + 示例程序）
3. QEMU 启动配置（GDB stub、网络、共享文件系统）

### 任务 5.2：编写示例 BPF 程序
**目标**: 通过实践验证源码分析结论

**示例程序清单** (存入 `darren/practice/`):

| 目录 | 程序 | 验证重点 |
|---|---|---|
| `tracepoint_example/` | syscall 跟踪 | 程序加载全流程 |
| `kprobe_example/` | 函数入口/返回跟踪 | perf_event attach |
| `xdp_example/` | 简单包过滤 | netlink attach |
| `ringbuf_example/` | 内核→用户态数据传递 | ringbuf 消费者 |
| `core_portable/` | 跨版本可移植程序 | CO-RE 重定位 |

每个示例包含:
- `*.bpf.c` — BPF 程序端代码
- `*.c` — 用户态加载代码
- `Makefile` — 编译脚本（使用 skeleton 模式）
- `README.md` — 说明与验证步骤

### 任务 5.3：调试工具验证
**目标**: 使用多种调试手段验证分析结论

| 工具 | 用途 | 关联知识 |
|---|---|---|
| GDB | 跟踪 libbpf 内部执行流程 | clangd_lsp_cli_practice.md |
| strace | 观察 bpf() syscall 调用参数 | — |
| bpftool | 查看加载结果、BTF 信息 | — |
| ftrace | 跟踪内核端 BPF 执行 | ftrace_hands_on_lab.md |
| perf | 性能分析 | — |

### 任务 5.4：BTF 与 CO-RE 实践
**目标**: 深入实践 BTF 和 CO-RE 机制

**具体步骤**:
1. 用 `pahole` 分析 vmlinux BTF（参考 `pahole_vmlinux_analysis.md`）
2. 编写 CO-RE 程序，在不同内核版本上测试
3. 用 `bpftool btf dump` 对比用户态/内核态 BTF
4. GDB 断点在 `bpf_core_calc_relo_insn()` 观察重定位过程

---

## 阶段六：知识整合与文档输出

### 输出文档清单（全部中文，存入 `darren/`）

| 文档 | 内容 | 对应分析阶段 |
|---|---|---|
| `libbpf_architecture_overview.md` | 整体架构、API 设计、核心数据结构、模块关系图 | 阶段二 |
| `libbpf_program_loading_deep.md` | 程序加载全流程深度分析 | 任务 3.1 |
| `libbpf_btf_core_deep.md` | BTF 子系统 + CO-RE 重定位引擎 | 任务 3.3 + 3.4 |
| `libbpf_syscall_layer_deep.md` | BPF syscall 封装层分析 | 任务 3.2 |
| `libbpf_elf_linker_deep.md` | ELF 处理 + BPF Linker | 任务 3.5 + 3.6 |
| `libbpf_ringbuf_usdt_deep.md` | Ring Buffer + USDT 实现 | 任务 3.7 + 3.8 |
| `libbpf_netlink_features_deep.md` | Netlink 通信 + Feature Probing | 任务 3.10 + 3.11 |
| `libbpf_skeleton_genloader_deep.md` | Skeleton 与 Gen Loader 生成 | 任务 3.9 |
| `libbpf_kernel_correlation.md` | libbpf ↔ 内核实现交叉引用总表 | 阶段六 |

### 实践代码目录结构
```
darren/
├── practice/
│   ├── Makefile                    # 顶层编译脚本
│   ├── tracepoint_example/
│   │   ├── trace_syscall.bpf.c
│   │   ├── trace_syscall.c
│   │   ├── Makefile
│   │   └── README.md
│   ├── kprobe_example/
│   ├── xdp_example/
│   ├── ringbuf_example/
│   └── core_portable/
├── libbpf_architecture_overview.md
├── libbpf_program_loading_deep.md
├── libbpf_btf_core_deep.md
├── libbpf_syscall_layer_deep.md
├── libbpf_elf_linker_deep.md
├── libbpf_ringbuf_usdt_deep.md
├── libbpf_netlink_features_deep.md
├── libbpf_skeleton_genloader_deep.md
└── libbpf_kernel_correlation.md
```

---

## 知识库关联映射

### libbpf 模块 → Kernel 知识库文档

| libbpf 模块 | Kernel 知识库文档 | 关联说明 |
|---|---|---|
| libbpf.c (程序加载) | `ebpf_prog_loading_full_flow.md` | 用户态加载 ↔ 内核端处理 |
| btf.c / relo_core.c | `ebpf_btf_core_deep.md` | BTF 解析 ↔ 内核 BTF 验证 |
| btf.c (verifier交互) | `ebpf_btf_verifier_trampoline_jit_deep.md` | BTF 信息在验证器中的使用 |
| bpf.c (helper/kfunc) | `ebpf_helper_kfunc_mechanism_deep.md` | helper 调用 ↔ 内核 helper 实现 |
| ringbuf.c | `ebpf_perf_ringbuf_userspace_deep.md` | 用户态消费 ↔ 内核端生产 |
| netlink.c (XDP) | `ebpf_xdp_native_generic_deep.md` | XDP attach ↔ 内核 XDP 处理 |
| netlink.c (网络) | `ebpf_networking_datapath_deep.md` | TC attach ↔ 网络数据路径 |
| gen_loader.c | `ebpf_tailcall_bpf2bpf_deep.md` | 程序调用机制 |
| features.c (map) | `ebpf_map_deep_analysis.md` | Map 探测 ↔ 内核 Map 实现 |
| features.c (map) | `ebpf_map_impl_comparison_deep.md` | Map 类型对比 |
| (安全相关) | `ebpf_cgroup_lsm_security_deep.md` | cgroup/LSM BPF |
| (verifier) | `ebpf_verifier_jit_deep.md` | 验证器全景 |
| (verifier) | `ebpf_verifier_register_tracking_deep.md` | 寄存器追踪 |
| (verifier) | `ebpf_verifier_state_pruning_deep.md` | 状态裁剪 |
| (sockmap) | `ebpf_sockmap_sk_msg_deep.md` | sockmap 机制 |
| (struct_ops) | `ebpf_struct_ops_iter_deep.md` | struct_ops/迭代器 |
| (struct_ops) | `ebpf_trampoline_struct_ops_deep.md` | trampoline 机制 |
| (JIT) | `ebpf_jit_compilation_deep.md` | JIT 编译 |

### 工具链 → 知识库文档

| 工具 | 知识库文档 | 用途 |
|---|---|---|
| clangd LSP | `clangd_kernel_setup.md` | 语义分析环境搭建 |
| clangd 实践 | `clangd_lsp_cli_practice.md` | LSP 命令行实践 |
| QEMU BPF 验证 | `qemu_bpf_verification.md` | BPF 验证环境 |
| QEMU eBPF 调试 | `qemu_ebpf_bpftrace_debug.md` | eBPF 调试环境 |
| QEMU ftrace | `qemu_ftrace_setup.md` | ftrace 环境 |
| pahole | `pahole_vmlinux_analysis.md` | BTF/DWARF 分析 |
| ftrace | `ftrace_hands_on_lab.md` | 内核跟踪实验 |

---

## 执行顺序建议

```
阶段一 (基础准备)
  │
  ├─ 1.1 source-analysis 索引 ──┐
  └─ 1.2 编译验证 ──────────────┤
                                 │
阶段二 (架构理解) ◄──────────────┘
  │
  ├─ 2.1 API 层分析
  ├─ 2.2 内部架构分析
  └─ 2.3 模块依赖图
  │
  ▼
阶段三 (核心模块) ← 按依赖关系推进
  │
  ├─ 3.1 程序加载 (最先，最核心)
  ├─ 3.2 syscall 封装 (并行)
  ├─ 3.3 BTF (依赖 3.1)
  ├─ 3.4 CO-RE (依赖 3.3)
  ├─ 3.5 ELF (并行)
  ├─ 3.6 Linker (依赖 3.5)
  ├─ 3.7 RingBuf (并行)
  ├─ 3.8 USDT (并行)
  ├─ 3.9 GenLoader (依赖 3.1)
  ├─ 3.10 Netlink (并行)
  └─ 3.11 Feature Probe (并行)
  │
  ▼
阶段四 (数据流) ← 整合阶段三的理解
  │
  ▼
阶段五 (实践) ← 可与阶段三并行推进
  │
  ├─ 5.1 QEMU 环境
  ├─ 5.2 示例程序 (依赖 5.1)
  ├─ 5.3 调试验证 (依赖 5.2)
  └─ 5.4 BTF/CO-RE 实践 (依赖 5.1 + 3.4)
  │
  ▼
阶段六 (文档) ← 贯穿全过程，每完成一个模块即输出
```
