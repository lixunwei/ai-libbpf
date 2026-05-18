# libbpf Skeleton 与 gen_loader 轻量加载器深度分析

## 0. 分析范围

- `src/gen_loader.c`（1253 行）
- `src/skel_internal.h`（443 行）
- 补充：`src/bpf_gen_internal.h` 中的 `struct bpf_gen`

---

## 1. Skeleton 概念与定位

### 1.1 什么是 Skeleton

在 libbpf 语境里，Skeleton 是“**把 BPF 对象及其用户态操作包装成一个自动生成的 C 接口**”。生成结果通常包含：

- `maps` 描述；
- `progs` 描述；
- `bss/rodata/data` 指针；
- `open/load/attach/destroy` 这类辅助 API。

### 1.2 标准 skeleton vs 轻量 skeleton

- **标准 skeleton**：生成 `*.skel.h`，运行时仍依赖用户态 libbpf 完成对象打开、重定位、加载、附加；
- **轻量 skeleton**：生成 `*.lskel.h`，把“加载过程”预编译成一段 loader BPF 程序和 data blob，运行时只需要 `bpf_load_and_run()`。

`skel_internal.h:129-133` 明确点名：

```c
/* The "bpftool gen skeleton -L" command generates lskel.h ... */
```

所以 `gen_loader.c` 解决的正是 `bpftool gen skeleton -L` 背后的实现问题。

---

## 2. 设计核心：用一段 BPF 程序去“加载另一批 BPF 对象”

### 2.1 总体思路

`gen_loader.c` 不是直接调 `bpf()`，而是**生成一段 `BPF_PROG_TYPE_SYSCALL` loader 程序**。这段程序在执行时调用：

- `BPF_FUNC_sys_bpf`
- `BPF_FUNC_sys_close`
- `BPF_FUNC_btf_find_by_name_kind`
- `BPF_FUNC_kallsyms_lookup_name`
- `BPF_FUNC_copy_from_user` / `BPF_FUNC_probe_read_kernel`

从而完成：

1. `BTF_LOAD`
2. `MAP_CREATE`
3. `PROG_LOAD`
4. `MAP_UPDATE_ELEM`
5. `MAP_FREEZE`
6. 各类 extern / kfunc / ksym / CO-RE 重定位

也就是说，**gen_loader 把“用户态 libbpf 的一部分加载逻辑”编译成了“内核可执行的 loader 指令流”**。

### 2.2 为什么能减少用户态 libbpf 依赖

因为运行时只需要：

1. 一个 data blob（里面放 `bpf_attr`、字符串、原始 insn、BTF、重定位信息）；
2. 一段 loader `bpf_insn[]`；
3. 一个 `struct bpf_loader_ctx`；
4. 调 `bpf_load_and_run()`。

标准 libbpf 的复杂对象生命周期，在生成阶段就已经“固化”为 loader bytecode 了。

---

## 3. `skel_internal.h`：运行时骨架 ABI

### 3.1 核心结构

- `struct bpf_map_desc`：`skel_internal.h:42-48`
- `struct bpf_prog_desc`：`skel_internal.h:49-51`
- `struct bpf_loader_ctx`：`skel_internal.h:57-63`
- `struct bpf_load_and_run_opts`：`skel_internal.h:65-77`

它们分别扮演：

- `bpf_map_desc`：loader 输出 `map_fd`，也允许输入覆盖 `max_entries/initial_value`；
- `bpf_prog_desc`：loader 输出 `prog_fd`；
- `bpf_loader_ctx`：运行时上下文（log buffer、flags 等）；
- `bpf_load_and_run_opts`：把 data/insns/signature/keyring 等统一打包给执行器。

### 3.2 运行时辅助 API

关键 helper：

- `skel_sys_bpf()`：`skel_internal.h:81-89`
- `skel_map_create()`：`skel_internal.h:229-252`
- `skel_map_update_elem()`：`skel_internal.h:254-267`
- `skel_map_freeze()`：`skel_internal.h:337-346`
- `bpf_load_and_run()`：`skel_internal.h:353-441`

### 3.3 `bpf_load_and_run()` 主流程

`bpf_load_and_run()`（`skel_internal.h:353-441`）是真正执行轻量 loader 的运行时入口：

1. 创建临时 array map `__loader.map` 保存 data blob；
2. `MAP_UPDATE_ELEM` 把 data blob 写进去；
3. 用户态模式下可 `MAP_FREEZE`；
4. 加载一段 `BPF_PROG_TYPE_SYSCALL` 程序 `__loader.prog`；
5. 用 `BPF_PROG_RUN` 执行它，把 `ctx` 作为输入；
6. loader 程序执行过程中再发出真正的 `BTF_LOAD/MAP_CREATE/PROG_LOAD`；
7. 成功后关闭临时 loader map/prog fd。

这正是“轻量 skeleton 自举”的本质。

---

## 4. `gen_loader.c`：生成器内部机制

### 4.1 `struct loader_stack`

`gen_loader.c:23-38` 描述了 loader 程序在 BPF 栈上的布局：

- `btf_fd`
- `inner_map_fd`
- `prog_fd[MAX_USED_PROGS]`

同时寄存器约定：

- `R6`：`ctx` 指针；
- `R7`：最近一次 `sys_bpf` 的返回值；
- `R9`：最近一次 `sys_close` 的返回值。

### 4.2 指令/数据双缓冲生成模型

生成器维护两块动态缓冲：

- `insn_start ~ insn_cur`
- `data_start ~ data_cur`

对应函数：

- `realloc_insn_buf()`：`gen_loader.c:50-71`
- `realloc_data_buf()`：`gen_loader.c:73-94`
- `emit()` / `emit2()`：`gen_loader.c:96-108`
- `add_data()`：`gen_loader.c:159-176`

这意味着生成器本质上是一个“小型汇编器”：

- `emit*` 负责产出 BPF 指令；
- `add_data()` 负责给这些指令准备常量池/`bpf_attr`/原始对象字节流。

### 4.3 初始化：`bpf_gen__init()`

- **位置**：`gen_loader.c:114-157`
- **签名**：`void bpf_gen__init(struct bpf_gen *gen, int log_level, int nr_progs, int nr_maps)`

主要工作：

1. 在 data blob 中预留 fd array；
2. 把 `ctx` 保存到 `R6`；
3. 清零 loader stack；
4. 预先生成 cleanup 跳板；
5. 记录 `cleanup_label`，后续所有失败路径都跳这里。

这决定了 loader 程序是一个“**前向生成、后向回跳到统一清理出口**”的结构。

### 4.4 `BTF_LOAD` 代码生成

- **函数**：`bpf_gen__load_btf()`
- **位置**：`gen_loader.c:472-502`

生成逻辑：

1. 把原始 BTF blob 放进 data；
2. 构造 `union bpf_attr`；
3. 从 `ctx` 回填 log buffer 参数；
4. 用 `emit_rel_store()` 把 `attr.btf` 指针指向 blob 中的 BTF 数据；
5. 生成 `BPF_BTF_LOAD` 系统调用；
6. 成功后把 `btf_fd` 存到 stack。

### 4.5 `MAP_CREATE` 代码生成

- **函数**：`bpf_gen__map_create()`
- **位置**：`gen_loader.c:504-581`

特点：

- 直接把 map 元信息编码进 `union bpf_attr`；
- 若 map 带 BTF 类型，则回填 `btf_fd`；
- 对 map-in-map，会回填 `inner_map_fd`；
- 支持在运行时从 `ctx->maps[i].max_entries` 覆盖默认值（`gen_loader.c:548-554`）。

### 4.6 attach target 与 extern 记录

- `bpf_gen__record_attach_target()`：`gen_loader.c:606-618`
- `bpf_gen__record_extern()`：`gen_loader.c:642-660`

生成阶段先只“记录事实”：

- 目标 attach 点叫什么、属于哪种 BTF kind；
- 某条指令上有哪些 extern/kfunc/ksym 重定位。

真正改写发生在 `bpf_gen__prog_load()` 前的 `emit_relos()` 阶段。

### 4.7 重定位生成：kfunc / typed ksym / typeless ksym / CO-RE

#### 关键函数

- `get_ksym_desc()`：`gen_loader.c:664-691`
- `emit_relo_kfunc_btf()`：`gen_loader.c:744-813`
- `emit_relo_ksym_typeless()`：`gen_loader.c:834-865`
- `emit_relo_ksym_btf()`：`gen_loader.c:881-929`
- `bpf_gen__record_relo_core()`：`gen_loader.c:931-945`
- `emit_relo()` / `emit_relos()`：`gen_loader.c:947-971`
- `cleanup_relos()`：`gen_loader.c:982-1012`

#### 设计要点

1. **同名符号复用描述符**：`get_ksym_desc()` 用 `(name, kind, is_ld64)` 去重；
2. **kfunc**：通过 `bpf_find_by_name_kind` 解析出 `btf_id + btf_obj_fd`，写回 call 指令的 `imm/off`；
3. **typed ksym**：同样用 BTF 查找，改写 `ldimm64` 的两个 half；
4. **typeless ksym**：回退到 `bpf_kallsyms_lookup_name()`，拿原始地址填 `ldimm64`；
5. **weak extern**：查找失败时不强制报错；
6. **CO-RE**：先记录 `struct bpf_core_relo`，后续在 `prog_load` 时作为 `core_relos` blob 一起提交。

### 4.8 `PROG_LOAD` 代码生成

- **函数**：`bpf_gen__prog_load()`
- **位置**：`gen_loader.c:1033-1158`

这是整个文件最重要的 API。它做的事包括：

1. 把 license、原始指令、func_info、line_info、core_relos 放入 data blob；
2. 如果目标端序与宿主不同，对 insn/info blob 做 `bswap`；
3. 组装 `union bpf_attr`；
4. 回填各种相对指针：`license/insns/func_info/line_info/core_relos/fd_array`；
5. 回填 log 配置、`prog_btf_fd`；
6. 如果有 attach target，则先通过 helper 查 `attach_btf_id/attach_btf_obj_fd`；
7. 执行所有 extern/ksym/kfunc relocation；
8. 发出 `BPF_PROG_LOAD`；
9. 清理重定位阶段临时 fd；
10. 成功后把 `prog_fd` 存入 stack。

### 4.9 map 数据初始化与 outer map 填充

- `bpf_gen__map_update_elem()`：`gen_loader.c:1160-1206`
- `bpf_gen__populate_outer_map()`：`gen_loader.c:1208-1235`
- `bpf_gen__map_freeze()`：`gen_loader.c:1237-1253`

`bpf_gen__map_update_elem()` 还有一个 skeleton 特有路径：

- 如果 `ctx->maps[i].initial_value` 非空：
  - 内核态用 `probe_read_kernel()`；
  - 用户态用 `copy_from_user()`；
- 再把读取后的值写入 map。

这正是轻量 skeleton 仍能支持 `.rodata/.data/.bss` 初始化的关键。

### 4.10 结束阶段：`bpf_gen__finish()`

- **位置**：`gen_loader.c:375-423`
- **签名**：`int bpf_gen__finish(struct bpf_gen *gen, int nr_progs, int nr_maps)`

完成：

1. 关闭临时 `btf_fd`；
2. 把 `prog_fd[]/map_fd[]` 搬运回 `ctx`；
3. 生成最终 `return 0`；
4. 若开启签名哈希，则回填 SHA256 更新点；
5. 输出最终 `opts->insns/data` 指针与大小。

---

## 5. 关键函数表

| 函数 | 位置 | 签名 | 核心逻辑 | 关键数据结构 |
|---|---|---|---|---|
| `bpf_gen__init` | `gen_loader.c:114` | `void bpf_gen__init(struct bpf_gen *gen, int log_level, int nr_progs, int nr_maps)` | 初始化 data/insn 缓冲、loader 栈、cleanup 跳板 | `struct loader_stack`, `struct bpf_gen` |
| `bpf_gen__finish` | `gen_loader.c:375` | `int bpf_gen__finish(struct bpf_gen *gen, int nr_progs, int nr_maps)` | 收尾、回写 fd、导出最终 loader 字节码与数据 | `struct bpf_loader_ctx` |
| `bpf_gen__load_btf` | `gen_loader.c:472` | `void bpf_gen__load_btf(struct bpf_gen *gen, const void *btf_raw_data, __u32 btf_raw_size)` | 生成 `BPF_BTF_LOAD` 指令序列 | `union bpf_attr` |
| `bpf_gen__map_create` | `gen_loader.c:504` | `void bpf_gen__map_create(struct bpf_gen *gen, enum bpf_map_type map_type, const char *map_name, __u32 key_size, __u32 value_size, __u32 max_entries, struct bpf_map_create_opts *map_attr, int map_idx)` | 生成 `BPF_MAP_CREATE` 并支持运行时覆盖 `max_entries` | `struct bpf_map_desc` |
| `bpf_gen__record_attach_target` | `gen_loader.c:606` | `void bpf_gen__record_attach_target(struct bpf_gen *gen, const char *attach_name, enum bpf_attach_type type)` | 记录 attach target 的 kind/name | `attach_target` 字符串 |
| `bpf_gen__record_extern` | `gen_loader.c:642` | `void bpf_gen__record_extern(struct bpf_gen *gen, const char *name, bool is_weak, bool is_typeless, bool is_ld64, int kind, int insn_idx)` | 记录 extern/ksym/kfunc relocation 元信息 | `struct ksym_relo_desc` |
| `get_ksym_desc` | `gen_loader.c:664` | `static struct ksym_desc *get_ksym_desc(struct bpf_gen *gen, struct ksym_relo_desc *relo)` | 对重复符号去重，避免反复创建 BTF FD | `struct ksym_desc` |
| `emit_relo_kfunc_btf` | `gen_loader.c:744` | `static void emit_relo_kfunc_btf(struct bpf_gen *gen, struct ksym_relo_desc *relo, int insn)` | 把 kfunc call 改写为 `imm=btf_id, off=fd_index` | `struct ksym_desc` |
| `emit_relo_ksym_typeless` | `gen_loader.c:834` | `static void emit_relo_ksym_typeless(struct bpf_gen *gen, struct ksym_relo_desc *relo, int insn)` | 用 `kallsyms_lookup_name` 填 raw address | `ldimm64` 指令 |
| `emit_relo_ksym_btf` | `gen_loader.c:881` | `static void emit_relo_ksym_btf(struct bpf_gen *gen, struct ksym_relo_desc *relo, int insn)` | 用 BTF 符号解析改写 typed ksym | `ldimm64` 指令 |
| `bpf_gen__record_relo_core` | `gen_loader.c:931` | `void bpf_gen__record_relo_core(struct bpf_gen *gen, const struct bpf_core_relo *core_relo)` | 收集 CO-RE 重定位记录 | `struct bpf_core_relo` |
| `bpf_gen__prog_load` | `gen_loader.c:1033` | `void bpf_gen__prog_load(struct bpf_gen *gen, enum bpf_prog_type prog_type, const char *prog_name, const char *license, struct bpf_insn *insns, size_t insn_cnt, struct bpf_prog_load_opts *load_attr, int prog_idx)` | 生成 `BPF_PROG_LOAD`，并集成 attach target、relos、BTF/func/line/core 信息 | `bpf_prog_load_opts` |
| `bpf_gen__map_update_elem` | `gen_loader.c:1160` | `void bpf_gen__map_update_elem(struct bpf_gen *gen, int map_idx, void *pvalue, __u32 value_size)` | 生成 map 初值写入流程 | `struct bpf_map_desc` |
| `bpf_gen__populate_outer_map` | `gen_loader.c:1208` | `void bpf_gen__populate_outer_map(struct bpf_gen *gen, int outer_map_idx, int slot, int inner_map_idx)` | 生成 map-in-map 填充指令 | `fd_array` |
| `bpf_gen__map_freeze` | `gen_loader.c:1237` | `void bpf_gen__map_freeze(struct bpf_gen *gen, int map_idx)` | 生成 `BPF_MAP_FREEZE` 指令 | `union bpf_attr` |
| `bpf_load_and_run` | `skel_internal.h:353` | `static inline int bpf_load_and_run(struct bpf_load_and_run_opts *opts)` | 运行时创建 loader map、装载 loader prog、执行 `BPF_PROG_RUN` | `struct bpf_load_and_run_opts` |

---

## 6. 代码片段与结构理解

### 6.1 生成器并不是“解释执行”，而是“编译出一段 loader 程序”

```c
/* gen_loader.c:269-278 */
static void emit_sys_bpf(struct bpf_gen *gen, int cmd, int attr, int attr_size)
{
    emit(gen, BPF_MOV64_IMM(BPF_REG_1, cmd));
    emit2(gen, BPF_LD_IMM64_RAW_FULL(BPF_REG_2, BPF_PSEUDO_MAP_IDX_VALUE,
                                     0, 0, 0, attr));
    emit(gen, BPF_MOV64_IMM(BPF_REG_3, attr_size));
    emit(gen, BPF_EMIT_CALL(BPF_FUNC_sys_bpf));
    emit(gen, BPF_MOV64_REG(BPF_REG_7, BPF_REG_0));
}
```

这段代码非常能说明问题：生成器并不是直接执行 `sys_bpf`，而是在输出 BPF 指令，让未来的 loader 程序去执行 `sys_bpf`。

### 6.2 轻量 skeleton 的最终运行时非常薄

```c
/* skel_internal.h:390-420 */
attr.prog_type = BPF_PROG_TYPE_SYSCALL;
attr.insns = (long) opts->insns;
...
err = prog_fd = skel_sys_bpf(BPF_PROG_LOAD, &attr, prog_load_attr_sz);
...
attr.test.prog_fd = prog_fd;
attr.test.ctx_in = (long) opts->ctx;
attr.test.ctx_size_in = opts->ctx->sz;
err = skel_sys_bpf(BPF_PROG_RUN, &attr, test_run_attr_sz);
```

运行时不再理解 BPF ELF 细节，而只是：

- 把“预编译好的 loader 程序”加载进去；
- 执行一次；
- 让 loader 程序自己完成真正对象的加载。

---

## 7. Skeleton 模式 vs 传统 libbpf 加载模式

| 维度 | 传统 libbpf | skeleton + gen_loader |
|---|---|---|
| 运行时依赖 | 需要 libbpf 用户态对象模型 | 可收敛为极薄 runtime |
| 加载逻辑位置 | 用户态 C 代码执行 | 生成期编译为 loader BPF 指令 |
| 对象解析 | 运行时解析 ELF/BTF/relos | 生成期已固化为 data blob + loader bytecode |
| 可移植性 | 灵活、功能全 | 更适合内嵌、分发、自包含场景 |
| 调试复杂度 | 用户态易单步 | 需要同时理解生成器与 loader bytecode |
| 适用场景 | 通用 libbpf 应用 | `bpftool gen skeleton -L`、轻量部署、减少依赖 |

一句话概括：

- **传统模式**：运行时解释 BPF 对象；
- **gen_loader 模式**：生成期把解释过程“提前编译”。

---

## 8. 总结

`gen_loader.c` 是 libbpf 里非常“系统化”的一个模块：

1. 它把 BPF 装载过程抽象成 **可再执行的指令流生成问题**；
2. 它通过 `skel_internal.h` 定义出一套轻量 runtime ABI；
3. 它支持 BTF、map、prog、extern/kfunc/ksym、CO-RE、map-in-map、初值写入等一整套能力；
4. 它是 `bpftool gen skeleton -L` 能够“摆脱大块运行时 libbpf 逻辑”的关键基础设施。

如果把 `libbpf.c` 看成“运行时解释器”，那 `gen_loader.c` 就像一个“提前把解释器输出编译成目标代码的 AOT 编译器”。
