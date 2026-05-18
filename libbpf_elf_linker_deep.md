# libbpf ELF 工具层与静态链接器深度分析

## 0. 分析范围

- `src/elf.c`（558 行）
- `src/linker.c`（3116 行）
- 辅助定位：clangd/cscope/readtags

> 先给一个重要结论：`src/elf.c` **并不负责**“section name → prog_type”的 BPF 程序类型映射；这一类 SEC 语义解析主要在 `libbpf.c` 的装载路径里。`elf.c` 在当前版本中的实际职责，是 **基于 libelf/gelf 做 ELF 符号遍历、版本符号处理与 uprobe 所需文件偏移解析**。真正的 BPF 静态链接核心在 `linker.c`。

---

## 1. `elf.c`：ELF 轻量解析与符号偏移求解

### 1.1 模块定位

`elf.c` 是一个“小而专”的 ELF 工具层，核心任务不是加载 BPF 对象，而是：

1. 打开 ELF 文件；
2. 遍历 `SHT_DYNSYM` / `SHT_SYMTAB`；
3. 解析 GNU version section（`SHT_GNU_versym` / `SHT_GNU_verdef`）；
4. 把符号虚拟地址转换为 **kernel uprobe 需要的文件偏移**。

### 1.2 与 BPF ELF 的关系

- `elf.c` 本身没有检查 `EM_BPF/ET_REL`；
- BPF 对象格式校验发生在 `linker.c:716-722`：要求 `ET_REL + EM_BPF + ELFCLASS64`；
- BPF section 命名规则（如 `xdp/`, `kprobe/`, `tracepoint/`）也不在本文件中实现。

因此若从“BPF ELF 格式特点”看，`elf.c` 更像 **通用 ELF 符号/版本解析器**，而 `linker.c` 才是 **BPF ELF 聚合器**。

### 1.3 解析流程（libelf/gelf）

关键代码片段：

- `elf_open()`：`elf.c:24-50`
- `elf_sym_iter_new()`：`elf.c:96-153`
- `elf_sym_iter_next()`：`elf.c:155-193`
- `elf_find_func_offset()`：`elf.c:276-370`

```c
/* elf.c:42-49 */
elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
...
elf_fd->fd = fd;
elf_fd->elf = elf;
```

这说明 libbpf 在这里直接使用 `libelf + gelf`，并采用 `ELF_C_READ_MMAP`，避免额外复制整文件。

### 1.4 GNU 版本符号处理

`elf_sym_iter_new()` 在处理 `SHT_DYNSYM` 时，会额外抓取：

- `SHT_GNU_versym`：`elf.c:136-139`
- `SHT_GNU_verdef`：`elf.c:141-150`

`elf_get_vername()`（`elf.c:195-220`）负责把 version index 解析成版本名；`symbol_match()`（`elf.c:223-256`）支持三种匹配形式：

- `foo`
- `foo@LIB_VER`
- `foo@@LIB_VER`

这正是 uprobes 附加到共享库导出符号时必须解决的问题。

### 1.5 虚拟地址 → 文件偏移

核心转换在 `elf_sym_offset()`（`elf.c:266-269`）：

```c
return sym->sym.st_value - sym->sh.sh_addr + sym->sh.sh_offset;
```

这是 `elf.c` 最关键的一行。其含义是：

- `st_value` 是符号在节内的虚拟地址；
- `sh_addr` 是节的虚拟基址；
- `sh_offset` 是节在文件中的偏移；
- 三者合成出 **uprobes 要求的 file offset**。

### 1.6 多重定义与强弱符号策略

`elf_find_func_offset()`（`elf.c:323-350`）和 `elf_resolve_syms_offsets()`（`elf.c:446-480`）都遵循同一原则：

- 若多个同名符号指向同一 offset：允许；
- 若出现多个不同 offset 的匹配：
  - 只有一个非弱符号时允许；
  - 两个都不是 `STB_WEAK` 时报歧义错误。

这和 `linker.c` 的符号冲突策略是一致的：**强符号优先，弱符号退让**。

### 1.7 `elf.c` 关键函数表

| 函数 | 位置 | 签名 | 核心逻辑 | 关键数据结构 |
|---|---|---|---|---|
| `elf_open` | `elf.c:24` | `int elf_open(const char *binary_path, struct elf_fd *elf_fd)` | 初始化 libelf、打开文件、`elf_begin()` 建立读取句柄 | `struct elf_fd`, `Elf *` |
| `elf_close` | `elf.c:53` | `void elf_close(struct elf_fd *elf_fd)` | 调用 `elf_end()` 和 `close()` 释放句柄 | `struct elf_fd` |
| `elf_find_next_scn_by_type` | `elf.c:62` | `static Elf_Scn *elf_find_next_scn_by_type(Elf *elf, int sh_type, Elf_Scn *scn)` | 顺序扫描 section，找指定 `sh_type` | `Elf_Scn`, `GElf_Shdr` |
| `elf_sym_iter_new` | `elf.c:96` | `static int elf_sym_iter_new(struct elf_sym_iter *iter, Elf *elf, const char *binary_path, int sh_type, int st_type)` | 初始化符号迭代器，绑定符号表/字符串表/version 表 | `struct elf_sym_iter` |
| `elf_sym_iter_next` | `elf.c:155` | `static struct elf_sym *elf_sym_iter_next(struct elf_sym_iter *iter)` | 逐个提取符合 `st_type` 的符号，并附带所在节头/version 信息 | `struct elf_sym` |
| `elf_get_vername` | `elf.c:195` | `static const char *elf_get_vername(struct elf_sym_iter *iter, int ver)` | 从 `SHT_GNU_verdef` 里把版本号还原成字符串 | `GElf_Verdef`, `GElf_Verdaux` |
| `symbol_match` | `elf.c:223` | `static bool symbol_match(...)` | 统一处理普通名、`@VER`、`@@VER` 匹配 | `struct elf_sym_iter`, `struct elf_sym` |
| `elf_find_func_offset` | `elf.c:276` | `long elf_find_func_offset(Elf *elf, const char *binary_path, const char *name)` | 查找函数并计算 uprobes 文件偏移，同时处理 stripped/静态/共享库场景 | `GElf_Ehdr`, `struct elf_sym_iter` |
| `elf_resolve_syms_offsets` | `elf.c:407` | `int elf_resolve_syms_offsets(const char *binary_path, int cnt, const char **syms, unsigned long **poffsets, int st_type)` | 批量解析多个符号 offset，内部排序后用 `bsearch` 加速 | `struct symbol` |
| `elf_resolve_pattern_offsets` | `elf.c:504` | `int elf_resolve_pattern_offsets(const char *binary_path, const char *pattern, unsigned long **poffsets, size_t *pcnt)` | 按 glob 模式匹配多个函数符号并收集 offset | `glob_match` |

---

## 2. `linker.c`：BPF 静态链接器

### 2.1 用途与典型场景

`linker.c` 是 libbpf 内部的 **BPF 静态链接器**。它解决的问题不是“把一个 `.o` 装进内核”，而是把 **多个 BPF ELF 对象合并成一个新的 ET_REL/EM_BPF 对象**。典型场景：

1. BPF library + application 的静态拼装；
2. 多个 `.o` 的 section/符号/BTF/BTF.ext 合并；
3. 先在用户态完成 extern 解析，再交给常规装载路径。

### 2.2 关键数据结构

`linker.c:31-161` 定义了整个链接器状态机：

- `struct src_sec`：单个输入节；记录 `dst_id/dst_off/sec_type_id`；
- `struct src_obj`：单个输入 ELF；记录 `sym_map/btf_type_map`；
- `struct dst_sec`：输出节；记录 `raw_data/sec_sz/sec_sym_idx/sec_vars`；
- `struct glob_sym`：全局/extern 符号的统一登记项；
- `struct bpf_linker`：最终链接器对象，持有输出 ELF、section 数组、字符串表、BTF、全局符号表。

### 2.3 总体流程：`new → add_file → finalize`

clangd 对 `bpf_linker_add_file()` 的调用展开如下：

```text
bpf_linker_add_file() [linker.c:490]
  -> linker_load_obj_file()      [664]
  -> linker_append_sec_data()    [1353]
  -> linker_append_elf_syms()    [1405]
  -> linker_append_elf_relos()   [2196]
  -> linker_append_btf()         [2412]
  -> linker_append_btf_ext()     [2630]
```

#### 2.3.1 创建阶段

- `bpf_linker__new()`：`linker.c:227-267`
- `bpf_linker__new_fd()`：`linker.c:269-309`
- `init_output_elf()`：`linker.c:359-487`

`init_output_elf()` 会预先建立：

1. 输出 ELF 头（`EM_BPF + ET_REL`）；
2. `.strtab`；
3. `.symtab`；
4. 空的 `struct btf`；
5. 特殊的全零符号 0。

#### 2.3.2 加入输入文件

- `bpf_linker__add_file()`：`linker.c:518-539`
- `bpf_linker_add_file()`：`linker.c:490-515`

这一步把一个输入对象拆成六个子阶段：

1. 读取并校验 ELF/BTF；
2. 合并数据节；
3. 合并符号表；
4. 重写重定位；
5. 合并 BTF；
6. 合并 BTF.ext。

#### 2.3.3 最终落盘

- `bpf_linker__finalize()`：`linker.c:2752-2818`
- `finalize_btf()`：`linker.c:2860-2939`
- `finalize_btf_ext()`：`linker.c:2968-3116`

最终阶段会：

- 先完成 `.BTF/.BTF.ext`；
- 再把 `strset` 收敛成真正的 `.strtab`；
- 调 `elf_update(..., ELF_C_NULL)` 固化布局；
- 调 `elf_update(..., ELF_C_WRITE)` 输出新 ELF。

---

## 3. 输入对象解析与校验

### 3.1 `linker_load_obj_file()`

- **位置**：`linker.c:664`
- **签名**：`static int linker_load_obj_file(struct bpf_linker *linker, struct src_obj *obj)`

核心逻辑：

1. `elf_begin(..., ELF_C_READ_MMAP, NULL)` 打开输入对象；
2. 校验字节序，首个输入文件决定输出端序（`linker.c:698-714`）；
3. 校验 `ET_REL/EM_BPF/ELFCLASS64`（`linker.c:716-722`）；
4. 遍历所有 section，识别 `SYMTAB`、`.BTF`、`.BTF.ext`、普通 PROGBITS/NOBITS/REL；
5. 忽略 `.strtab`、`.llvm_addrsig`、DWARF、`.rel.BTF*` 等无关节；
6. 执行四轮 sanity/fixup：
   - `linker_sanity_check_elf()` `linker.c:829`
   - `linker_sanity_check_btf()` `linker.c:1086`
   - `linker_sanity_check_btf_ext()` `linker.c:1121`
   - `linker_fixup_btf()` `linker.c:2317`

### 3.2 section 合并前的过滤策略

`is_ignored_sec()`（`linker.c:605-639`）会直接跳过：

- `.strtab`
- `.llvm_addrsig`
- 空 `.text`
- `.debug_*`
- `.rel.BTF` / `.rel.BTF.ext`

这说明链接器只处理“影响最终 BPF 可执行对象”的最小必要集。

---

## 4. Section 合并策略

### 4.1 输出节初始化与匹配

- `init_sec()`：`linker.c:1140-1194`
- `find_dst_sec_by_name()`：`linker.c:1196-1208`
- `secs_match()`：`linker.c:1211-1230`

策略非常直接：**按 section name 归并**。同名节必须满足：

- `sh_type` 相同；
- `sh_flags` 相同；
- `sh_entsize` 相同。

### 4.2 真实合并：`extend_sec()`

- **位置**：`linker.c:1259`
- **签名**：`static int extend_sec(struct bpf_linker *linker, struct dst_sec *dst, struct src_sec *src)`

关键逻辑：

1. 计算输出节对齐：取 `max(dst_align, src_align)`；
2. 先把已有 `dst->sec_sz` 对齐到新边界；
3. 再把 `src` 内容复制到对齐后位置；
4. 记录 `src->dst_off`，供后续符号/重定位/BTF 偏移修正；
5. 若是交叉端序且目标节是可执行节，则对新增 BPF 指令做 `bswap`（`linker.c:1319-1321`）。

这一步实际上决定了后续所有“地址修正”的基准坐标。

### 4.3 特殊节处理

`linker_append_sec_data()`（`linker.c:1353-1403`）里有两个重要特例：

- `license` 和 `version`：只允许完全相同内容，否则报错；
- `.maps` / `.data` / `.rodata` / `.text`：走正常拼接。

因此它不是 GNU ld 那种复杂 script 驱动的 linker，而是 **面向 BPF 场景的规则化 section concatenation**。

---

## 5. 符号解析策略：局部/全局、强/弱、extern

### 5.1 入口

- `linker_append_elf_syms()`：`linker.c:1405-1436`
- `linker_append_elf_sym()`：`linker.c:1995-2194`

### 5.2 局部符号

`STB_LOCAL` 直接进入输出 `SYMTAB`，不参与全局冲突解析；
`STT_SECTION` 只保留每个输出节一个 section symbol（`linker.c:2023-2027`, `2168-2170`）。

### 5.3 全局符号表 `glob_sym`

`find_glob_sym()` / `add_glob_sym()`：`linker.c:1446-1480`。

它们维护一个“全局命名空间”视图：

- `sym_idx`：输出 ELF 中的符号索引；
- `sec_id`：对应输出节；
- `btf_id`：最终 BTF 中该全局符号的类型；
- `is_extern/is_weak`：冲突决策位。

### 5.4 强/弱/extern 决策规则

在 `linker_append_elf_sym()` 中，最重要的分支是 `linker.c:2064-2147`：

1. 若同名全局符号已存在，先把 `obj->sym_map[src_sym_idx]` 指向已有输出符号；
2. 若“新符号”和“旧符号”都是非 extern 且都不是 weak，则报冲突；
3. 若新符号是强符号，则把已有记录升级为强符号；
4. 若新符号只是 extern，不覆盖已解析实体；
5. 若旧符号是 extern，而新符号是实体定义，则覆盖 `st_shndx/st_value/st_size`，完成 extern 解析。

可以把它总结成：

- **实体定义优先于 extern**；
- **强定义优先于弱定义**；
- **弱定义只能填坑，不能抢占已存在强定义**。

### 5.5 extern 的 BTF 完善

`complete_extern_btf_info()`（`linker.c:1926-1974`）做了一个很关键但容易忽视的动作：

- 对 `VAR`：把 extern linkage 改成 `BTF_VAR_GLOBAL_ALLOCATED`；
- 对 `FUNC`：把 linkage 改成 `BTF_FUNC_GLOBAL`，并把 extern 缺失的参数名补齐。

这样做的目的，是让最终 BTF dedup 能把“extern 壳”和“真实定义”合并起来。

---

## 6. 重定位表处理

### 6.1 校验

`linker_sanity_check_elf_relos()`（`linker.c:985-1061`）约束：

- 只接受 `R_BPF_64_64`、`R_BPF_64_32`、`R_BPF_64_ABS64`、`R_BPF_64_ABS32`；
- `sh_link` 必须指向 `SYMTAB`；
- `.rel<sec>` 的命名必须和被重定位节匹配；
- 指令节内重定位必须对齐到 `sizeof(struct bpf_insn)`。

### 6.2 真正改写：`linker_append_elf_relos()`

- **位置**：`linker.c:2196`
- **签名**：`static int linker_append_elf_relos(struct bpf_linker *linker, struct src_obj *obj)`

核心做两件事：

1. `r_offset += src_linked_sec->dst_off`：把重定位位置平移到合并后节内；
2. `obj->sym_map[src_sym_idx]`：把输入符号索引改写成输出符号索引。

对 `STT_SECTION` 还有额外修正（`linker.c:2258-2281`）：

- 如果被重定位的是可执行节中的 `call`，`imm` 需要加上 section 拼接位移；
- 否则普通数据引用也要加偏移；
- 非可执行节中针对 `STT_SECTION` 的重定位直接拒绝。

---

## 7. BTF 合并算法

### 7.1 输入 BTF 修正

`linker_fixup_btf()`（`linker.c:2317-2410`）先做两类准备：

1. 把 `DATASEC.size` 修正为真实 ELF section 大小；
2. 对全局变量，把 `btf_var_secinfo.offset` 对齐到符号真实 `st_value`。

同时，它还会为 `.kconfig/.ksyms` 之类“只存在于 BTF、不存在于 ELF”的节创建 **ephemeral section shell**。

### 7.2 BTF 类型兼容性判断

- `glob_sym_btf_matches()`：`linker.c:1482-1674`
- `map_defs_match()`：`linker.c:1676-1762`

`glob_sym_btf_matches()` 是整个链接器最核心的“类型相等判定器”：

- `INT/FLOAT/ENUM/ENUM64`：比 size；
- `PTR/ARRAY`：递归比底层 shape；
- `FUNC/VAR`：允许 extern/global linkage 兼容；
- `STRUCT/UNION`：精确模式下比字段数、字段名、offset、字段类型；
- `FUNC_PROTO`：比参数个数、参数类型、返回类型；
- `FWD` 可与同名 concrete struct/union 在非精确模式下兼容。

`.maps` 的全局变量不是普通变量，而是 map definition，所以额外走 `glob_map_defs_match()` → `map_defs_match()`，要求 map 类型、key/value size、flags、inner map 定义都一致。

### 7.3 追加类型与重映射

`linker_append_btf()`（`linker.c:2412-2611`）分三段：

1. 先追加非 `DATASEC` 类型，并建立 `obj->btf_type_map[src_id] -> dst_id`；
2. 再回过头修正所有新类型里的内部 type ID 引用；
3. 最后把各个 section 的 `btf_var_secinfo` 汇总到输出 `dst_sec->sec_vars`。

其中全局 `VAR/FUNC` 的处理很关键：

- 已存在同名全局符号时，直接复用已有 `btf_id`；
- 若 extern 被实体定义替换，还会重写其 underlying type。

### 7.4 最终 BTF / BTF.ext 生成

`finalize_btf()`（`linker.c:2860-2939`）流程：

1. 为每个 `dst_sec` 生成 consolidated `DATASEC`；
2. 先调用 `finalize_btf_ext()` 生成 `.BTF.ext`；
3. 再做 `btf__dedup()`；
4. 根据输出 ELF 字节序设置 BTF endianness；
5. 发射 `.BTF` 和 `.BTF.ext` 两个 ELF section。

`finalize_btf_ext()`（`linker.c:2968-3116`）会把 `func_info/line_info/core_relo` 重新按输出 section 重组，并统一写入新的 header + record-size 前缀格式。

---

## 8. 关键函数清单（`linker.c`）

| 函数 | 位置 | 签名 | 核心逻辑 | 关键数据结构 |
|---|---|---|---|---|
| `bpf_linker__new` | `linker.c:227` | `struct bpf_linker *bpf_linker__new(const char *filename, struct bpf_linker_opts *opts)` | 创建输出文件并初始化空 ELF | `struct bpf_linker` |
| `init_output_elf` | `linker.c:359` | `static int init_output_elf(struct bpf_linker *linker)` | 创建 `.strtab/.symtab`、空 BTF、符号 0 | `struct dst_sec`, `strset` |
| `bpf_linker_add_file` | `linker.c:490` | `static int bpf_linker_add_file(struct bpf_linker *linker, int fd, const char *filename)` | 串起单输入文件的完整合并流水线 | `struct src_obj` |
| `linker_load_obj_file` | `linker.c:664` | `static int linker_load_obj_file(struct bpf_linker *linker, struct src_obj *obj)` | 读取输入 ELF/BTF/BTF.ext 并做 sanity check | `struct src_obj`, `Elf64_Ehdr` |
| `extend_sec` | `linker.c:1259` | `static int extend_sec(struct bpf_linker *linker, struct dst_sec *dst, struct src_sec *src)` | 处理 section 拼接、对齐、端序和 `dst_off` 记录 | `struct dst_sec`, `struct src_sec` |
| `linker_append_sec_data` | `linker.c:1353` | `static int linker_append_sec_data(struct bpf_linker *linker, struct src_obj *obj)` | 合并数据节/代码节并处理 `license/version` 去重 | `struct dst_sec` |
| `glob_sym_btf_matches` | `linker.c:1482` | `static bool glob_sym_btf_matches(...)` | 递归判断两个全局符号的 BTF 兼容性 | `struct btf_type` |
| `map_defs_match` | `linker.c:1676` | `static bool map_defs_match(...)` | 对 `.maps` 定义做严格结构比较 | `struct btf_map_def` |
| `find_glob_sym_btf` | `linker.c:1842` | `static int find_glob_sym_btf(...)` | 从 BTF 中找到符号对应的 `VAR/FUNC/DATASEC` | `struct glob_sym`, `struct btf_var_secinfo` |
| `complete_extern_btf_info` | `linker.c:1926` | `static int complete_extern_btf_info(struct btf *dst_btf, int dst_id, struct btf *src_btf, int src_id)` | extern 解析后补齐 FUNC/VAR 的 BTF 细节 | `struct btf_param` |
| `linker_append_elf_sym` | `linker.c:1995` | `static int linker_append_elf_sym(...)` | 实现强/弱/extern/global/local 的冲突解析 | `struct glob_sym`, `Elf64_Sym` |
| `linker_append_elf_relos` | `linker.c:2196` | `static int linker_append_elf_relos(struct bpf_linker *linker, struct src_obj *obj)` | 重写 relocation offset 和 symbol index | `Elf64_Rel`, `obj->sym_map` |
| `linker_fixup_btf` | `linker.c:2317` | `static int linker_fixup_btf(struct src_obj *obj)` | 修正 DATASEC 尺寸与全局变量 offset | `struct src_sec` |
| `linker_append_btf` | `linker.c:2412` | `static int linker_append_btf(struct bpf_linker *linker, struct src_obj *obj)` | 合并类型、重映射 type ID、汇总 sec var info | `obj->btf_type_map` |
| `linker_append_btf_ext` | `linker.c:2630` | `static int linker_append_btf_ext(struct bpf_linker *linker, struct src_obj *obj)` | 合并 func/line/core_relo 信息并修正偏移/字符串 | `struct btf_ext_sec_data` |
| `bpf_linker__finalize` | `linker.c:2752` | `int bpf_linker__finalize(struct bpf_linker *linker)` | 最终生成 `.BTF/.BTF.ext/.strtab` 并写出 ELF | `struct bpf_linker` |
| `finalize_btf` | `linker.c:2860` | `static int finalize_btf(struct bpf_linker *linker)` | 汇总 DATASEC、去重 BTF、发射 `.BTF` | `struct btf` |
| `finalize_btf_ext` | `linker.c:2968` | `static int finalize_btf_ext(struct bpf_linker *linker)` | 组装最终 `.BTF.ext` blob | `struct btf_ext_header` |

---

## 9. 总结

- `elf.c` 是 **ELF 符号/版本/偏移解析器**，主要服务于 uprobe/USDT 这类按符号附加的场景；
- `linker.c` 才是 **真正的 BPF 静态链接器**：负责 section 拼接、符号决策、重定位重写、BTF/BTF.ext 合并；
- 其总体设计原则非常清晰：
  1. **同名 section 直接拼接**；
  2. **强定义压过弱定义，实体压过 extern**；
  3. **所有全局符号都要有 BTF 可验证的类型一致性**；
  4. **把输入对象的偏移、符号索引、type ID 全部重写成输出对象坐标系**。
