# libbpf 工具模块深度分析
## 0. 分析范围与方法
本文分析 libbpf `src/` 目录中六个偏工具层、基础设施层的源文件：`libbpf_probes.c`、`zip.c`、`hashmap.c`、`strset.c`、`btf_iter.c`、`bpf_prog_linfo.c`。
这些文件的共同点是：它们都不是 `bpf_object__open()`、`bpf_object__load()` 这种主流程入口，却在能力探测、格式适配、容器、字符串去重、BTF 重写、调试辅助等方面，给更大的上层模块提供“通用积木”。
本次分析结合了源码阅读与交叉引用工具：
`readtags`：确认函数定义与行号；；`cscope -L3`：确认 caller/callee；；`clangd-lsp-client.py`：确认 references 与部分 outgoing calls；；`rg`/`view`：检查 `src/` 内真实调用点上下文。
索引状态有效：仓库存在 `compile_commands.json`，`.ai-search/ctags/tags`、`.ai-search/cscope/cscope.out` 可直接查询，clangd 也已有后台索引分片。
因此下文中的“谁调用它”和“它依赖谁”，不是纯人工猜测，而是经过静态索引交叉验证的结论。
---
## 1. `libbpf_probes.c`：内核能力探测与最小化试探装载
**1.1 模块职责与架构位置** `libbpf_probes.c` 在架构上属于 libbpf 的 capability discovery 层。它不负责真正的 BPF 对象装载，也不维护长期对象状态，而是通过构造“足够小、足够合法”的探测请求，让内核直接回答：某种 program type、map type、helper 组合是否可用。
这种设计比“按内核版本硬编码能力表”更稳健。原因很现实：同一主线版本可能带回移 patch，发行版还会改写版本字符串，而 verifier 的真实行为才是最终标准。
因此，`libbpf_probes.c` 实际是在做行为探测。它的职责不是推理未来，而是用真实 syscall 去测试当下运行的内核。
**1.2 关键对象：它几乎是纯过程式模块** 这个文件没有复杂的长期结构体。核心状态都落在局部栈对象里：
`struct utsname info`：内核版本字符串来源；；`struct bpf_prog_load_opts opts`：program probe 参数；；`struct bpf_map_create_opts opts`：map probe 参数；；`struct btf_header hdr`：构造 raw BTF 头；；若干最小 BPF 指令数组与最小 BTF 类型数组。
换句话说，这个模块的复杂度不在对象生命周期，而在“不同能力应该如何最小化触发”的知识编码。
**1.3 内核版本修正：Ubuntu 与 Debian 特判** 最先值得注意的是 `get_kernel_version()`，定义在`libbpf_probes.c:80`。它不是简单地信任 `uname().release`，而是先检查 Ubuntu 与 Debian 的发行版特化信息。
关键代码：
```c
static __u32 get_ubuntu_kernel_version(void)
{
const char *ubuntu_kver_file = "/proc/version_signature";
...
ret = fscanf(f, "%*s %*s %u.%u.%u\n", &major, &minor, &patch);
...
return KERNEL_VERSION(major, minor, patch);
}
```
```c
static __u32 get_debian_kernel_version(struct utsname *info)
{
p = strstr(info->version, "Debian ");
...
if (sscanf(p, "Debian %u.%u.%u", &major, &minor, &patch) != 3)
return 0;
return KERNEL_VERSION(major, minor, patch);
}
```
这个逻辑背后的真实问题是：某些内核接口仍会检查 `kern_version`，而发行版暴露给用户的 `release` 与内核内部期望的 patchlevel不一定一致。
`cscope -L3 get_kernel_version` 还显示，这个 helper 不仅被本文件内部 `probe_prog_load()` 使用，还被 `libbpf.c` 主流程复用：
`libbpf.c:1552`，`bpf_object__new()` 初始化 `obj->kern_version`；；`libbpf.c:8804`，`bpf_object__resolve_externs()` 解析
`LINUX_KERNEL_VERSION` extern。
因此它虽然放在 probes 文件里，但已经承担了 libbpf 统一运行时内核版本获取器的角色。
**1.4 `probe_prog_load()`：程序类能力探测的核心发动机** 内部真正的核心是 `probe_prog_load()`，定义在`libbpf_probes.c:103`。它接受 program type、最小指令数组以及可选 verifier log，并针对不同 program type 设置必要的附加参数。
最关键的一段是大 `switch`：
```c
switch (prog_type) {
case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
opts.expected_attach_type = BPF_CGROUP_INET4_CONNECT;
break;
case BPF_PROG_TYPE_KPROBE:
opts.kern_version = get_kernel_version();
break;
case BPF_PROG_TYPE_TRACING:
case BPF_PROG_TYPE_LSM:
opts.expected_attach_type = BPF_TRACE_FENTRY;
opts.attach_btf_id = 1;
exp_err = -EINVAL;
exp_msg = "attach_btf_id 1 is not a function";
break;
...
}
```
这里不是简单填参数，而是在表达一张“合法触发路径表”：如果不给 `CGROUP_SOCK_ADDR` 补 `expected_attach_type`，你测到的就只是“参数错误”；如果不给 `KPROBE` 补 `kern_version`，你测到的可能是老接口兼容性问题；如果不给 `TRACING/LSM/EXT` 补 `attach_btf_id`，那甚至还没走到真正相关的 verifier 分支。
更有意思的是 `exp_err` 与 `exp_msg`。对于一部分能力，libbpf 不追求“探测请求最终成功”，而是追求“请求在预期更深层的地方失败”。比如 `attach_btf_id 1 is not a function` 这样的 verifier 文案，反而说明 tracing/lsm 这层语义已经被识别了。
这是一种非常工程化的“预期失败即成功”策略。
**1.5 `libbpf_probe_bpf_prog_type()`：极小程序验证 program type** 对外 API `libbpf_probe_bpf_prog_type()` 定义在`libbpf_probes.c:205`，声明在 `libbpf.h:1781`。它只生成两条最小指令：
```c
struct bpf_insn insns[] = {
BPF_MOV64_IMM(BPF_REG_0, 0),
BPF_EXIT_INSN()
};
```
然后调用 `probe_prog_load()`。clangd 的 outgoing 结果也表明这个函数几乎只是薄包装层：
调 `probe_prog_load()`；；调 `libbpf_err()` 规范化返回值。
值得注意的是，clangd references 与 `rg` 都没有在 `src/` 内找到其他内部调用点，只看到 `libbpf.h` 中的 public declaration。这说明它主要面向 libbpf 使用者，而不是 libbpf 自己的装载主路径高频调用 API。
**1.6 raw BTF 装载：为更复杂 probe 提供“最小 BTF 载体”** `libbpf__load_raw_btf_hdr()` 与 `libbpf__load_raw_btf()`定义在 `libbpf_probes.c:221` 与 `249`，声明在 `libbpf_internal.h:424-427`。它们把分散的 BTF header/type/string/layout 数据，重新拼成一段连续的 raw blob，然后调用 `bpf_btf_load()`。
核心片段：
```c
btf_len = hdr->hdr_len + hdr->type_off + hdr->type_len +
  hdr->str_len + hdr->layout_len;
raw_btf = malloc(btf_len);
...
memcpy(raw_btf + hdr->hdr_len + hdr->type_off, raw_types, hdr->type_len);
memcpy(raw_btf + hdr->hdr_len + hdr->str_off, str_sec, hdr->str_len);
if (layout_sec)
memcpy(raw_btf + hdr->hdr_len + hdr->layout_off,
       layout_sec, hdr->layout_len);
```
它本质上是一个内部通用 helper，作用不是处理普通用户 BTF 文件，而是支持 probe 期间动态构造最小 BTF。
从近期历史看，这个 helper 仍在随 probe 需求演进：`fd04b4e` 为旧内核 layout 兼容性加入了 sanitization 相关支持，`a3b317a` 则把 `token_fd` 贯穿到了探测逻辑里。
**1.7 `load_local_storage_btf()`：手工拼最小 BTF 类型图** 某些 map type，特别是 local storage 系列，仅凭 key/value/max_entries 不够，还要有合适的 BTF key/value type。
于是 `load_local_storage_btf()` 在`libbpf_probes.c:265` 手工构造一个极小 BTF：
```c
const char strs[] = "\0bpf_spin_lock\0val\0cnt\0l";
__u32 types[] = {
BTF_TYPE_INT_ENC(...),
BTF_TYPE_ENC(...),
BTF_MEMBER_ENC(...),
BTF_TYPE_ENC(...),
BTF_MEMBER_ENC(...),
BTF_MEMBER_ENC(...),
};
```
它表达的语义只是：
一个 `int`；；一个带 `val` 成员的 `struct bpf_spin_lock`；；一个带 `cnt` 与 `l` 成员的 `struct val`。
也就是说，libbpf 不依赖外部 BTF 文件，而是在用户态内联生成“足以让内核验证继续推进”的最小类型图。
**1.8 `probe_map_create()`：不同 map type 的最小合法 recipe** map 能力探测的核心函数是 `probe_map_create()`，定义在`libbpf_probes.c:292`。它和 `probe_prog_load()` 一样，本质是一张 recipe 表。
例如：
`STACK_TRACE` 要求 `value_size = sizeof(__u64)`；；`LPM_TRIE` 需要 `BPF_F_NO_PREALLOC`；；`QUEUE/STACK` 的 `key_size = 0`；；`RINGBUF/USER_RINGBUF` 需要页大小作为 `max_entries`；；`ARRAY_OF_MAPS/HASH_OF_MAPS` 要先创建 inner map；；`SK_STORAGE/INODE_STORAGE/TASK_STORAGE/CGRP_STORAGE`
则要求附带 BTF。
片段如下：
```c
case BPF_MAP_TYPE_LPM_TRIE:
key_size = sizeof(__u64);
value_size = sizeof(__u64);
opts.map_flags = BPF_F_NO_PREALLOC;
break;
...
case BPF_MAP_TYPE_ARRAY_OF_MAPS:
case BPF_MAP_TYPE_HASH_OF_MAPS:
fd_inner = bpf_map_create(BPF_MAP_TYPE_HASH, NULL,
  sizeof(__u32), sizeof(__u32), 1, NULL);
opts.inner_map_fd = fd_inner;
```
```c
case BPF_MAP_TYPE_SK_STORAGE:
case BPF_MAP_TYPE_INODE_STORAGE:
case BPF_MAP_TYPE_TASK_STORAGE:
case BPF_MAP_TYPE_CGRP_STORAGE:
btf_key_type_id = 1;
btf_value_type_id = 3;
btf_fd = load_local_storage_btf();
break;
```
这段逻辑的核心不是算法难度，而是对 map 创建前置条件的理解深度。
**1.9 `libbpf_probe_bpf_helper()`：用 verifier 文案做细粒度判定** helper probe 的 public API 定义在 `libbpf_probes.c:430`，声明在 `libbpf.h:1808`。它构造的程序同样极小：
```c
struct bpf_insn insns[] = {
BPF_EMIT_CALL((__u32)helper_id),
BPF_EXIT_INSN(),
};
```
真正有意思的是它不止看 syscall 成败，而是解析 verifier 日志：
```c
if (ret == 0 && (strstr(buf, "invalid func ") ||
 strstr(buf, "unknown func ") ||
 strstr(buf, "program of this type cannot use helper ")))
return 0;
return 1;
```
这里把三种情形区分开：
verifier 根本不认识 helper；；verifier 认识 helper，但当前 prog type 不允许使用；；verifier 认识 helper，且这次失败只是因为 probe 程序不满足其他条件。
前两类都算“不支持”，第三类则被近似地视为“支持”。
这比只看 errno 更贴近真实语义。
**1.10 被谁使用，以及设计取舍** 交叉引用结论可以分成两层。
第一层，内部 helper `get_kernel_version()` 被`libbpf.c` 主流程实际复用，说明它已经成为运行时 kernel version code 的统一来源。
第二层，三个 public probe API——`libbpf_probe_bpf_prog_type()`、`libbpf_probe_bpf_map_type()`、`libbpf_probe_bpf_helper()`——在 `src/` 内几乎没有别的内部调用点，说明它们更偏向对库使用者开放的探测接口。
这个文件最重要的设计取舍可以总结为五点：
1. 优先行为探测，而不是纯版本判断；2. 输入必须是“最小合法”，否则 probe 结果没有意义；3. 接受“在预期深层失败即成功”的 probe 模型；4. 必要时依赖 verifier log 文本而不是只看 errno；5. 所有 probe 都是无状态事务，资源就地创建、就地释放。
从 libbpf 整体架构看，`libbpf_probes.c` 是一组经过经验沉淀的 recipe 集合。上层用户看到的是几个简单 API，底层实际包含了对不同 program/map/helper 语义前提的细致理解。
---
## 2. `zip.c`：为 APK 内 `.so` 定位服务的最小 ZIP 解析器
**2.1 模块职责与边界** `zip.c` 的职责非常专一：给定一个 ZIP/APK 文件，找到里面某个成员文件的原始数据位置，然后把这段数据交给上层去当成 ELF 解析。
因此它不是通用 ZIP 库。`zip.h:8-15` 已明确说明只支持基础子集，不支持：
encryption；；streaming/data descriptor；；multi-part archive；；ZIP64。
这个边界与 libbpf 的实际场景完全一致：上层只需要在 Android APK 中找到未压缩的 `.so`，然后计算 uprobe 所需的文件偏移。
**2.2 关键数据结构：直接映射磁盘布局** 本文件最核心的结构是三个 packed on-disk header：
```c
struct end_of_cd_record {
__u32 magic;
__u16 this_disk;
__u16 cd_disk;
__u16 cd_records;
__u16 cd_records_total;
__u32 cd_size;
__u32 cd_offset;
__u16 comment_length;
} __attribute__((packed));
```
```c
struct cd_file_header {
__u32 magic;
...
__u32 compressed_size;
__u16 file_name_length;
__u16 extra_field_length;
__u16 file_comment_length;
__u32 offset;
} __attribute__((packed));
```
```c
struct local_file_header {
__u32 magic;
...
__u32 compressed_size;
__u16 file_name_length;
__u16 extra_field_length;
} __attribute__((packed));
```
这些结构都用 `packed`，因为 ZIP 文件格式没有 C 结构体 padding，而且内存中的偏移未必自然对齐。这意味着 `zip.c` 采用的是“mmap 后直接解释二进制布局”的路线，而不是把每个字段解析复制到独立宿主对象里。
真正的运行时状态只有：
```c
struct zip_archive {
void *data;
__u32 size;
__u32 cd_offset;
__u32 cd_records;
};
```
它只保存整文件映射、大小以及 central directory 的位置和条目数。没有索引缓存、没有目录树、没有解压状态。
**2.3 `check_access()`：所有读取的安全闸门** 几乎所有 on-disk 结构访问都先经过 `check_access()`：
```c
static void *check_access(struct zip_archive *archive, __u32 offset, __u32 size)
{
if (offset + size > archive->size || offset > offset + size)
return NULL;
return archive->data + offset;
}
```
这里有两个安全目标：
防止普通越界；；防止 `offset + size` 的整数回绕。
第二个检查尤其重要。如果只写 `offset + size > archive->size`，那么在无符号加法溢出时可能会漏报。
也正因为有这一层，后面的 EOCD、central directory、local file header 解析都可以把“是否可读”统一交给 `check_access()`。
**2.4 EOCD 发现：从文件尾部反向扫描** ZIP central directory 的入口不是固定偏移，因为 end-of-central-directory 记录尾部可以带最多 64K 的 comment。
`try_parse_end_of_cd()` 负责验证“某个 offset 看起来是否像 EOCD”，而 `find_cd()` 负责在文件尾部的 64K 窗口内反向扫描。
核心代码：
```c
offset = archive->size - sizeof(struct end_of_cd_record);
limit = (int64_t)offset - (1 << 16);

for (; offset >= 0 && offset > limit && rc != 0; offset--) {
rc = try_parse_end_of_cd(archive, offset);
if (rc == -ENOTSUP)
break;
}
```
`try_parse_end_of_cd()` 又区分了两类失败：
`-EINVAL`：这个 offset 不是合法 EOCD；；`-ENOTSUP`：它是合法 EOCD，但 archive 用了不支持的特性，
比如 ZIP64 或多磁盘。
这层区分很重要，因为它让上层能知道“数据损坏”与“格式合法但超范围”之间的差别。
**2.5 archive 打开与关闭：整文件 `mmap` 的零拷贝策略** `zip_archive_open()` 采用非常直接的零拷贝策略：
1. `open()` 文件；2. `lseek(..., SEEK_END)` 获取大小；3. `mmap(PROT_READ, MAP_PRIVATE)` 映射整文件；4. 调 `find_cd()` 找 central directory；5. 成功则返回 `struct zip_archive *`。
这说明 `zip.c` 不是一个“流式解析器”，而是一个“整文件内存视图解释器”。这种策略对 APK 场景非常合适：
输入通常只是一个普通文件；；后续还要把 entry 数据直接交给 `elf_memory()`；；不值得引入额外拷贝或缓存层。
`zip_archive_close()` 则只做 `munmap + free`，资源模型很干净。
**2.6 entry 查找：先扫 central directory，再跳 local header** 真正的查找接口是 `zip_archive_find_entry()`，定义在`zip.c:298`。它先在 central directory 中按文件名线性扫描，找到匹配项后，再通过 `cdfh->offset` 跳回 local file header，由 `get_entry_at_offset()` 取出最终数据。
关键路径如下：
```c
for (i = 0; i < archive->cd_records; ++i) {
cdfh = check_access(archive, offset, sizeof(*cdfh));
...
cdfh_name = check_access(archive, offset, cdfh_name_length);
...
if ((cdfh_flags & FLAG_ENCRYPTED) == 0 &&
    (cdfh_flags & FLAG_HAS_DATA_DESCRIPTOR) == 0 &&
    file_name_length == cdfh_name_length &&
    memcmp(file_name, archive->data + offset, file_name_length) == 0) {
return get_entry_at_offset(archive, cdfh->offset, out);
}
}
```
`get_entry_at_offset()` 再继续完成：
验证 local file header magic；；拒绝 encrypted 或 data descriptor 模式；；跳过文件名与 extra field；；返回 `data` 指针、长度与 archive 内偏移。
结果对象是 `struct zip_entry`：
`compression`；；`name/name_length`；；`data/data_length`；；`data_offset`。
这里仍然没有做解压。`compression` 只是被保存并上抛给调用方判断。
**2.7 在 libbpf 里的真实用法：只服务 archive 中 ELF 偏移定位** 交叉引用十分集中。`rg`、clangd references 与 `cscope` 都表明：
`zip_archive_open()` 被 `libbpf.c:12504` 调用；；`zip_archive_find_entry()` 被 `libbpf.c:12511` 调用；；`zip_archive_close()` 被 `libbpf.c:12545` 调用。
调用上下文是 `libbpf.c:12496-12546` 的`elf_find_func_offset_from_archive()`：
```c
archive = zip_archive_open(archive_path);
ret = zip_archive_find_entry(archive, file_name, &entry);
...
if (entry.compression) {
ret = -LIBBPF_ERRNO__FORMAT;
goto out;
}
elf = elf_memory((void *)entry.data, entry.data_length);
```
这几行已经把 `zip.c` 的架构角色说透了：它是 archive member → ELF memory image 之间的格式桥接层。它不关心 uprobes 本身，也不关心 ELF 符号解析，只负责把 archive 中的成员定位出来。
**2.8 设计取舍** `zip.c` 的设计取舍非常鲜明：
1. 只实现 libbpf 需要的 ZIP 子集，避免引入外部依赖；2. 只支持读取未压缩 entry，不承担解压责任；3. 基于整文件 `mmap` 和 packed 结构直接解释，代码短而直接；4. 统一用 `check_access()` 做边界检查，避免解析代码散落越界逻辑；5. 用 `-EINVAL` / `-ENOTSUP` 区分坏数据与超出支持范围的数据。
因此它不是“功能完整”的 ZIP 解析器，而是一个为 APK 内 `.so` 场景量身定制的小型格式适配层。
---
## 3. `hashmap.c`：libbpf 内部通用散列表容器
**3.1 模块职责与接口风格** `hashmap.c` 是多个子系统共享的基础容器。它不是给最终用户直接操作的大型通用库，而是 libbpf 自己内部的“轻量字典 / multimap / cache”实现。
它的设计目标很务实：
支持整数 key/value 和指针 key/value；；支持唯一插入、覆盖、只更新、追加多值四种语义；；足够快；；足够小；；不引入线程同步开销。
文件头第一句就写明了：`Generic non-thread safe hash map implementation.`
**3.2 数据结构：`long` 承载的轻量多态** 头文件 `hashmap.h` 中的两个核心结构如下：
```c
struct hashmap_entry {
union {
long key;
const void *pkey;
};
union {
long value;
void *pvalue;
};
struct hashmap_entry *next;
};
```
```c
struct hashmap {
hashmap_hash_fn hash_fn;
hashmap_equal_fn equal_fn;
void *ctx;
struct hashmap_entry **buckets;
size_t cap;
size_t cap_bits;
size_t sz;
};
```
实现上它用 `long` 统一承载整数或指针，再通过 union 别名给调用者提供 `pkey/pvalue` 语义。
真正的“泛型体验”来自头文件宏：
```c
#define hashmap__insert(map, key, value, strategy, old_key, old_value) \
hashmap_insert((map), (long)(key), (long)(value), (strategy), \
       hashmap_cast_ptr(old_key), hashmap_cast_ptr(old_value))
```
`hashmap_cast_ptr()` 里的 `_Static_assert` 会检查指针大小是否与`long` 匹配。这让 libbpf 在纯 C 环境中做出了一种很轻量的“伪泛型容器”。
**3.3 基础算法：桶链表 + 乘法散列 + 按需扩容** 桶索引选择依赖头文件中的 `hash_bits()`：
```c
static inline size_t hash_bits(size_t h, int bits)
{
if (bits == 0)
return 0;
#if (__SIZEOF_SIZE_T__ == __SIZEOF_LONG_LONG__)
return (h * 11400714819323198485llu) >>
       (__SIZEOF_LONG_LONG__ * 8 - bits);
#else
return (h * 2654435769lu) >> (__SIZEOF_LONG__ * 8 - bits);
#endif
}
```
本质上就是乘法散列后取高位，配合 2 的幂大小 bucket array 使用。
冲突处理采用最简单的单链表头插法：
```c
static void hashmap_add_entry(struct hashmap_entry **pprev,
      struct hashmap_entry *entry)
{
entry->next = *pprev;
*pprev = entry;
}
```
扩容阈值是 75% 负载：
```c
static bool hashmap_needs_to_grow(struct hashmap *map)
{
return (map->cap == 0) || ((map->sz + 1) * 4 / 3 > map->cap);
}
```
最小容量是 4 个桶，每次扩容直接翻倍并整体 rehash。对于 libbpf 内部常见的中小规模表，这是非常合理的复杂度/代码量平衡。
**3.4 插入策略：一个 API 覆盖 map、cache 与 multimap** `hashmap_insert()` 最大的价值不只是“插入”，而是通过 `enum hashmap_insert_strategy` 同时支持四种语义：
`HASHMAP_ADD`：若 key 已存在则失败；；`HASHMAP_SET`：存在则覆盖，不存在则新增；；`HASHMAP_UPDATE`：只更新已有项；；`HASHMAP_APPEND`：允许重复 key，形成多值链。
核心分支：
```c
if (strategy != HASHMAP_APPEND &&
    hashmap_find_entry(map, key, h, NULL, &entry)) {
...
if (strategy == HASHMAP_SET || strategy == HASHMAP_UPDATE) {
entry->key = key;
entry->value = value;
return 0;
} else if (strategy == HASHMAP_ADD) {
return -EEXIST;
}
}

if (strategy == HASHMAP_UPDATE)
return -ENOENT;
```
这段逻辑非常关键。它让 libbpf 不必维护多套容器：一个基础 hashmap 就能覆盖 set、cache、只更新索引，以及“相同 hash/相同 key 对应多个候选值”的 multimap 场景。
**3.5 查找、删除与清理：ownership 明确留给调用者** 查找内部共用 `hashmap_find_entry()`，删除则利用 `pprev` 技巧把头节点和中间节点统一处理：
```c
if (!hashmap_find_entry(map, key, h, &pprev, &entry))
return false;
...
hashmap_del_entry(pprev, entry);
free(entry);
map->sz--;
```
需要特别强调的是 `hashmap__clear()` 的语义：它只释放 `struct hashmap_entry` 节点本身，并不会自动释放 key/value 所指向的内存对象。
这说明 ownership 不在容器层，而在调用者层。为此，`hashmap_insert()` / `hashmap_delete()`都支持通过 `old_key/old_value` 把旧对象交还给调用者，以便外部自行回收。
这种策略很符合 libbpf 风格：容器语义清晰，但不替业务对象决定生命周期。
**3.6 在 libbpf 中的实际使用面非常广** clangd references 显示 `hashmap_insert()` 在多个模块被直接调用：
`btf.c:2186`、`4004`、`5526`、`5528`；；`btf_dump.c:1655`；；`libbpf.c:6061`；；`strset.c:70`、`168`；；`usdt.c:978`、`991`。
几个典型用法能够清楚展示四种插入策略的意义。
#### (1) `btf.c`：去重候选表与名字索引
`btf.c:4004`：
```c
static int btf_dedup_table_add(struct btf_dedup *d, long hash, __u32 type_id)
{
return hashmap__append(d->dedup_table, hash, type_id);
}
```
这里必须允许同一个 hash 下挂多个候选 type，所以选择 `HASHMAP_APPEND`，把普通 hashmap 直接变成 multimap。
`btf.c:5526-5528`：
```c
err = hashmap__add(names_map, t->name_off, type_id);
if (err == -EEXIST)
err = hashmap__set(names_map, t->name_off, 0, NULL, NULL);
```
这里又利用 `ADD` + `SET` 表达出一层额外语义：唯一名字映射到 type_id；一旦重名，值就被覆盖成 0，表示“不再唯一”。
#### (2) `libbpf.c`：CO-RE 候选缓存
`libbpf.c:6061`：
```c
err = hashmap__set(cand_cache, local_id, cands, NULL, NULL);
```
这是典型缓存语义。key 是 `local_id`，value 是候选列表对象指针。存在就覆盖，不存在就新建。
#### (3) `usdt.c`：字符串指针到 spec ID 的缓存
`usdt.c:978` 与 `991`：
```c
err = hashmap__add(specs_hash, target->spec_str, *spec_id);
```
这里 key 直接是字符串指针，说明 hashmap 的 pointer key 能力不是“备选功能”，而是被真实依赖的。
#### (4) `strset.c`：作为字符串去重索引
`strset__new()` 用 `hashmap__new()` 建立字符串索引，`strset__add_str()` 用 `HASHMAP_ADD` 完成唯一化。换句话说，`strset` 本质上是“连续字符串 blob + hashmap 索引”的复合结构。
#### (5) `btf_dump.c`：名字冲突计数与旧 key 回收
`btf_dump.c:1655`：
```c
err = hashmap__set(name_map, new_name, dup_cnt, &old_name, NULL);
```
这里同时利用了覆盖语义和 `old_key` 回传能力，这样旧的名字字符串就能被上层回收释放。
**3.7 设计取舍** `hashmap.c` 的设计取舍可以概括为：
1. 明确不做线程安全，换取更小的实现；2. 通过宏和 `long` 承载实现轻量泛型；3. 用四种插入策略提升复用率；4. 容器只管理 entry，不管理业务对象生命周期；5. 不追求最复杂的哈希技术，而追求简单稳定、足够快。
从 libbpf 的整体代码风格看，`hashmap.c` 是一个典型的“不是最花哨，但极其实用”的内部基础容器。
---
## 4. `strset.c`：字符串 blob 与稳定偏移的去重器
**4.1 模块职责：不是普通 set，而是 string table builder** `strset.c` 看似是在做“字符串集合”，但它真正解决的问题是：如何维护一个连续的 NUL 结尾字符串 blob，并为每个唯一字符串返回稳定 offset。
这与普通 `set<string>` 的目标不同。在 libbpf 中，字符串经常最终要写回二进制 section：
BTF string section；；linker 生成的新 ELF `.strtab`；；各种需要稳定 string offset 的元数据区域。
因此 `strset.c` 的输出不是布尔“是否存在”，而是“这个字符串在最终 blob 中的偏移”。
**4.2 数据结构：存储层与索引层分离** `struct strset` 定义很小：
```c
struct strset {
void *strs_data;
size_t strs_data_len;
size_t strs_data_cap;
size_t strs_data_max_len;
struct hashmap *strs_hash;
};
```
这可以拆成两层理解：
`strs_data` + `*_len/cap/max_len`：负责真正的连续字符串存储；；`strs_hash`：负责按内容去重并返回 offset。
最关键的一点是：hashmap 里的 key/value 都不是外部 `char *`，而是 offset。
对应的 hash/equal 实现是：
```c
static size_t strset_hash_fn(long key, void *ctx)
{
const struct strset *s = ctx;
const char *str = s->strs_data + key;
return str_hash(str);
}
```
```c
static bool strset_equal_fn(long key1, long key2, void *ctx)
{
const struct strset *s = ctx;
const char *str1 = s->strs_data + key1;
const char *str2 = s->strs_data + key2;
return strcmp(str1, str2) == 0;
}
```
这意味着 `strset` 不是“指针集合”，而是“偏移索引的字符串表”。
**4.3 构造函数：支持从既有 string blob 反建索引** `strset__new()` 不仅支持空集创建，还支持用一段已有字符串区初始化：
```c
if (init_data) {
set->strs_data = malloc(init_data_sz);
memcpy(set->strs_data, init_data, init_data_sz);
set->strs_data_len = init_data_sz;
...
for (off = 0; off < set->strs_data_len;
     off += strlen(set->strs_data + off) + 1) {
err = hashmap__add(hash, off, off);
if (err == -EEXIST)
continue;
}
}
```
这让 `strset` 很适合接管一段已有 string table，并在其上继续做去重与追加。如果原始数据中存在重复字符串，hashmap 索引会自动忽略重复项，只保留第一个可见 offset。
**4.4 最巧妙的点：查找/插入前先把外部字符串临时写到尾部** `strset__find_str()` 与 `strset__add_str()`最有代表性的技巧是：无论查找还是插入，都会先把待查字符串临时写到 `strs_data` 当前尾部。
查找代码：
```c
len = strlen(s) + 1;
p = strset_add_str_mem(set, len);
new_off = set->strs_data_len;
memcpy(p, s, len);

if (hashmap__find(set->strs_hash, new_off, &old_off))
return old_off;
return -ENOENT;
```
插入代码：
```c
len = strlen(s) + 1;
p = strset_add_str_mem(set, len);
new_off = set->strs_data_len;
memcpy(p, s, len);

err = hashmap__insert(set->strs_hash, new_off, new_off,
      HASHMAP_ADD, &old_off, NULL);
if (err == -EEXIST)
return old_off;
...
set->strs_data_len += len;
return new_off;
```
为什么要这样做？因为 `strset` 的 hash/equal 都是基于 offset 回到 `strs_data` 中取字符串，所以“外部传进来的 `const char *s`”如果想参与 hashmap 比较，就必须先在 `strs_data` 里拥有一个临时位置。
这是一种非常典型的内部表示驱动设计：一旦选择“offset 作为唯一键”，查找路径就必须让外部输入先变成 offset 可寻址对象。
**4.5 为什么尾部的临时垃圾是可接受的** 这套做法看上去像会制造垃圾字节，但源码注释已经说明原因：在 `strs_data_len` 增长之前，尾部那段临时写入对外仍然不可见。
也就是说，`strset` 明确区分了：
已分配容量 `strs_data_cap`；；已提交长度 `strs_data_len`。
如果最终发现字符串已存在，就直接返回旧 offset，而临时写入的数据只是“未提交区”的残留内容。这确实会浪费一点容量，但换来的是非常简单而高效的查重路径。
**4.6 与其他模块的交叉关系** clangd references 显示 `strset__add_str()` 主要被两类大模块使用：
`btf.c:2109`、`4179`、`4215`；；`linker.c:409`、`450`、`1170`、`2151`、`2828`。
#### (1) `btf.c`：BTF string section 的构建与去重
`btf.c:2109`：
```c
off = strset__add_str(btf->strs_set, s);
...
btf->hdr.str_len = strset__data_size(btf->strs_set);
```
这里 `strset` 就是 BTF string section 的后端容器。
`btf.c:4205-4215` 里 dedup 过程还会重新创建一套 `strset`，并显式把空字符串 `""` 放到 offset 0，以满足 BTF 对 string section 的基本约定。
#### (2) `linker.c`：新的 ELF `.strtab` 构建器
`linker.c` 中多处调用 `strset__add_str()`：
`409`：为 `.strtab` 节自身名字分配 offset；；`450`：为 `.symtab` 节名分配 offset；；`1170`：复制源 section 名；；`2151`：为新增全局符号分配 `st_name`；；`2828`：为新建 section 分配 `sh_name`。
例如：
```c
str_off = strset__add_str(linker->strtab_strs, sec->sec_name);
```
这说明 `strset` 在 linker 里扮演的就是字符串表生成器角色。
**4.7 设计取舍** `strset.c` 的设计取舍可以总结为：
1. 目标不是一般意义的 set，而是可序列化 string table；2. 以 offset 作为主键，天然适合 BTF/ELF 之类格式；3. 复用 `hashmap` 做内容去重，把物理存储与逻辑索引分开；4. 接受尾部未提交垃圾，换取更简单的查找/插入路径；5. 不提供复杂删除语义，因为典型使用场景是单调构建字符串表。
所以 `strset.c` 看起来小，但它背后承载的是 BTF 与 ELF 链接两条大路径里的字符串后端。
---
## 5. `btf_iter.c`：统一遍历 BTF 类型中的 type ID 与 string offset
**5.1 模块职责：把 BTF kind-specific 遍历逻辑收敛成统一原语** `btf_iter.c` 的 `iter` 不是 BPF iterator program，而是 BTF type field iterator。
它要解决的问题是：不同 `BTF_KIND_*` 对象内部，引用其他 type ID 或字符串 offset 的字段分布并不一致。如果每个上层模块都自己写：
`switch (btf_kind(t))`；；`ARRAY` 看 `btf_array.type/index_type`；；`STRUCT/UNION` 看 `btf_member.type`；；`FUNC_PROTO` 看返回值与参数；；`DATASEC` 看 `btf_var_secinfo.type`；
那么 `btf.c`、`btf_relocate.c`、`linker.c`都会充满重复代码。
`btf_iter.c` 的作用就是把这类 kind-specific 遍历逻辑集中起来，让上层只需要写：
```c
btf_field_iter_init(&it, t, BTF_FIELD_ITER_IDS);
while ((type_id = btf_field_iter_next(&it))) { ... }
```
或者：
```c
btf_field_iter_init(&it, t, BTF_FIELD_ITER_STRS);
while ((str_off = btf_field_iter_next(&it))) { ... }
```
**5.2 关键数据结构：`btf_field_desc` 与 `btf_field_iter`** 描述 schema 的对象定义在 `libbpf_internal.h:571-586`：
```c
struct btf_field_desc {
int t_off_cnt, t_offs[2];
int m_sz;
int m_off_cnt, m_offs[1];
};
```
```c
struct btf_field_iter {
struct btf_field_desc desc;
void *p;
int m_idx;
int off_idx;
int vlen;
};
```
`btf_field_desc` 的思想非常简单但很有效：
`t_offs[]` 表示“type 本体上的一次性字段偏移”；；`m_sz` 和 `m_offs[]` 表示“如果 type 后面跟着成员数组，
则每个成员内部哪些偏移需要遍历”。
`btf_field_iter` 则是最小运行时状态：当前描述、当前游标、当前成员下标、当前偏移下标和成员数。
这里没有回调对象、没有堆分配、没有复杂虚表。整个抽象几乎压缩到了“字段偏移描述 + 一点状态机”。
**5.3 `btf_field_iter_init()`：把 `btf_kind` 映射成遍历描述** `btf_field_iter_init()` 定义在 `btf_iter.c:16`。它根据两维输入构造 `desc`：
遍历模式：`BTF_FIELD_ITER_IDS` 或 `BTF_FIELD_ITER_STRS`；；BTF kind：`INT`、`PTR`、`ARRAY`、`STRUCT`、`FUNC_PROTO` 等。
比如 type ID 模式下：
```c
case BTF_KIND_PTR:
case BTF_KIND_TYPEDEF:
case BTF_KIND_FUNC:
case BTF_KIND_VAR:
it->desc = (struct btf_field_desc) {
1, {offsetof(struct btf_type, type)}
};
break;
```
```c
case BTF_KIND_ARRAY:
it->desc = (struct btf_field_desc) {
2, {sizeof(struct btf_type) + offsetof(struct btf_array, type),
    sizeof(struct btf_type) + offsetof(struct btf_array, index_type)}
};
break;
```
```c
case BTF_KIND_STRUCT:
case BTF_KIND_UNION:
it->desc = (struct btf_field_desc) {
0, {},
sizeof(struct btf_member),
1, {offsetof(struct btf_member, type)}
};
break;
```
字符串模式下则改为遍历 `name_off` 等字段。
因此，`btf_field_iter_init()` 本质上是把“BTF 各 kind 的字段布局知识”转成一个可执行描述对象。
**5.4 `btf_field_iter_next()`：返回字段地址而不是字段值** `btf_field_iter_next()` 定义在 `btf_iter.c:145`，返回值是 `__u32 *`，而不是 `__u32`。
这是整个模块最关键的接口设计。因为上层很多时候不是只想读取字段，而是想原地改写它：
重写 type ID；；重写 string offset；；验证字段是否越界。
核心状态机：
```c
if (it->m_idx < 0) {
if (it->off_idx < it->desc.t_off_cnt)
return it->p + it->desc.t_offs[it->off_idx++];
it->m_idx = 0;
it->p += sizeof(struct btf_type);
it->off_idx = 0;
}
```
```c
if (it->off_idx >= it->desc.m_off_cnt) {
it->m_idx++;
it->p += it->desc.m_sz;
it->off_idx = 0;
}
if (it->m_idx < it->vlen)
return it->p + it->desc.m_offs[it->off_idx++];
```
可以把它理解成两阶段遍历：
1. 先遍历 type-level 字段；2. 再遍历 member-level 字段数组。
状态结束时把 `it->p = NULL`，后续调用就返回 `NULL`。
**5.5 它如何被 `btf.c`、`btf_relocate.c`、`linker.c` 复用** clangd references 显示 `btf_field_iter_init()` 被：
`btf.c` 多处；；`btf_relocate.c` 多处；；`linker.c` 多处。
这些调用非常能说明其角色。
#### (1) `btf.c`：字符串与 type ID 的统一重写原语
`btf.c:2217-2224`：
```c
err = btf_field_iter_init(&it, t, BTF_FIELD_ITER_STRS);
while ((str_off = btf_field_iter_next(&it))) {
err = btf_rewrite_str(p, str_off);
...
}
```
`btf.c:2303-2320`：
```c
err = btf_field_iter_init(&it, t, BTF_FIELD_ITER_IDS);
while ((type_id = btf_field_iter_next(&it))) {
...
}
```
`btf.c:5727-5739`：
```c
r = btf_field_iter_init(&it, t, BTF_FIELD_ITER_IDS);
while ((type_id = btf_field_iter_next(&it))) {
resolved_id = resolve_type_id(d, *type_id);
new_id = d->hypot_map[resolved_id];
*type_id = new_id;
}
```
这说明 `btf_iter.c` 已经成为 BTF add/dedup/remap 工作流的基础原语。
#### (2) `btf_relocate.c`：重定位前后的一致性重写器
`btf_relocate.c:73-78`：
```c
err = btf_field_iter_init(&it, t, BTF_FIELD_ITER_IDS);
while ((id = btf_field_iter_next(&it)))
*id = r->id_map[*id];
```
`btf_relocate.c:419-430`：
```c
err = btf_field_iter_init(&it, t, BTF_FIELD_ITER_STRS);
while ((str_off = btf_field_iter_next(&it))) {
...
}
```
这说明 relocation 子系统不需要关心具体 kind 的字段布局，只需要消费 iterator 暴露出来的“所有相关字段”。
#### (3) `linker.c`：BTF 合并后的合法性检查与 remap
`linker.c:1101-1114`：
```c
err = btf_field_iter_init(&it, t, BTF_FIELD_ITER_IDS);
while ((type_id = btf_field_iter_next(&it))) {
if (*type_id >= n)
return -EINVAL;
}
```
```c
err = btf_field_iter_init(&it, t, BTF_FIELD_ITER_STRS);
while ((str_off = btf_field_iter_next(&it))) {
if (!btf__str_by_offset(obj->btf, *str_off))
return -EINVAL;
}
```
`linker.c:2489-2497` 又利用它批量重写目标 BTF 中的 type ID。因此 `btf_iter.c` 在 linker 里既是验证器，又是重写器的基础抽象。
**5.6 设计取舍** `btf_iter.c` 的设计取舍非常漂亮：
1. 把 BTF schema 知识集中为 descriptor，而不是散落在多个大文件；2. 返回字段指针，天然支持读与写两种上层需求；3. 只支持 `IDS` 和 `STRS` 两种视角，但这已经覆盖绝大多数 BTF rewrite 场景；4. 无堆分配、无回调，抽象非常轻；5. 对未知或不支持的 kind 直接返回 `-EINVAL`，避免静默漏处理。
从代码量看它很小，但从复用价值看，它显著压缩了 `btf.c`、`btf_relocate.c`、`linker.c` 的重复样板代码。
---
## 6. `bpf_prog_linfo.c`：把程序行号信息变成可查询索引
**6.1 模块职责与使用场景** `bpf_prog_linfo.c` 处理的是 `struct bpf_prog_info` 中的 line info。它不生成 line info，而是把内核返回的原始数据整理成更适合查询的对象。
其服务场景包括：
根据 xlated 指令偏移查找源码位置信息；；根据 JIT 后地址查找对应源码行；；把 `jited_ksyms`、`jited_func_lens` 与 `jited_line_info`
串成便于工具层消费的索引。
和前面几个基础模块不同，它更多是一个对外辅助 API，而不是 libbpf 内部装载主路径的必经之路。
**6.2 核心数据结构：两份原始数据 + 两张辅助索引** 内部对象 `struct bpf_prog_linfo` 定义在 `bpf_prog_linfo.c:11`：
```c
struct bpf_prog_linfo {
void *raw_linfo;
void *raw_jited_linfo;
__u32 *nr_jited_linfo_per_func;
__u32 *jited_linfo_func_idx;
__u32 nr_linfo;
__u32 nr_jited_func;
__u32 rec_size;
__u32 jited_rec_size;
};
```
可以把它看成四部分：
1. `raw_linfo`：原始 xlated line info 副本；2. `raw_jited_linfo`：原始 jited line info 副本；3. `jited_linfo_func_idx[]`：每个 JIT function 在全局数组中的起始下标；4. `nr_jited_linfo_per_func[]`：每个 JIT function 对应多少条 line info。
这两张辅助表的意义非常大：它们把“一整条全局 line info 序列”切分成“按函数分区的局部窗口”，从而让地址级查询不必每次都从头扫全量数组。
**6.3 构造函数 `bpf_prog_linfo__new()`：先校验，再复制，再增量增强** `bpf_prog_linfo__new()` 定义在 `bpf_prog_linfo.c:100`，声明在 `libbpf.h:1752`。它的构造流程很分层：
第一步，确认基础 line info 是否存在且 record 足够大：
```c
nr_linfo = info->nr_line_info;
if (!nr_linfo)
return errno = EINVAL, NULL;

if (info->line_info_rec_size <
    offsetof(struct bpf_line_info, file_name_off))
return errno = EINVAL, NULL;
```
第二步，复制 xlated line info 到自己的持久内存中：
```c
data_sz = (__u64)nr_linfo * prog_linfo->rec_size;
prog_linfo->raw_linfo = malloc(data_sz);
memcpy(prog_linfo->raw_linfo, (void *)(long)info->line_info, data_sz);
```
第三步，再检查 jited 相关元数据是否成套齐全：
```c
if (!nr_jited_func ||
    !info->jited_line_info ||
    info->nr_jited_line_info != nr_linfo ||
    info->jited_line_info_rec_size < sizeof(__u64) ||
    info->nr_jited_func_lens != nr_jited_func ||
    !info->jited_ksyms ||
    !info->jited_func_lens)
return prog_linfo;
```
如果条件不满足，构造函数并不会失败，而是直接返回一个“只有 xlated line info 能力”的对象。
这说明它把能力分成两个层次：
基础层：`insn_off -> line_info`；；增强层：`jited addr -> line_info`。
**6.4 `dissect_jited_func()`：从全局 jited line info 切出函数边界** 真正最关键的内部算法是 `dissect_jited_func()`，定义在`bpf_prog_linfo.c:22`。
问题背景是：内核给的 `raw_jited_linfo` 是全局顺序数组，但一个 BPF program JIT 后可能包含多个 function，我们需要知道每个 function 对应的 line info 子区间。
核心逻辑：
```c
if (ksym_func[0] != *jited_linfo)
goto errout;
prog_linfo->jited_linfo_func_idx[0] = 0;
```
```c
for (prev_i = 0, i = 1, f = 1;
     i < nr_linfo && f < nr_jited_func;
     i++) {
raw_jited_linfo += prog_linfo->jited_rec_size;
last_jited_linfo = *jited_linfo;
jited_linfo = raw_jited_linfo;

if (ksym_func[f] == *jited_linfo) {
prog_linfo->jited_linfo_func_idx[f] = i;
...
prog_linfo->nr_jited_linfo_per_func[f - 1] = i - prev_i;
prev_i = i;
f++;
} else if (*jited_linfo <= last_jited_linfo) {
goto errout;
}
}
```
它依赖两个不变量：
`raw_jited_linfo` 内地址单调递增；；某函数的第一条 jited line info 地址应等于 `ksym_func[f]`。
一旦识别出边界，就更新两张索引表：
`jited_linfo_func_idx[f]`；；`nr_jited_linfo_per_func[f]`。
最终，一个原本线性的全局数组被切成了按函数可直接寻址的区块。
**6.5 校验为什么如此严格** `dissect_jited_func()` 里还有两条很关键的 sanity check：
```c
if (last_jited_linfo - ksym_func[f - 1] + 1 > ksym_len[f - 1])
goto errout;
```
```c
else if (*jited_linfo <= last_jited_linfo)
goto errout;
```
前者确保上一函数最后一条 jited line info没有越过该函数长度边界；后者确保同一函数内部地址严格递增。
这说明作者并没有把内核返回的 line info 元数据当成绝对可信输入，而是把它视为“需要额外验证的一组外部数据”。
**6.6 查询接口：按 `addr` 和按 `insn_off` 两条路径** `bpf_prog_linfo__lfind_addr_func()` 定义在 `bpf_prog_linfo.c:181`。它先用 `func_idx` 与 `nr_skip` 计算该函数在全局数组中的起始位置，再在这个子区间里线性前进，寻找“不大于目标地址的最后一条 line info”。
核心片段：
```c
start = prog_linfo->jited_linfo_func_idx[func_idx] + nr_skip;
raw_jited_linfo = prog_linfo->raw_jited_linfo + (start * jited_rec_size);
...
for (i = 0; i < nr_linfo; i++) {
if (addr < *jited_linfo)
break;
...
}
return raw_linfo - rec_size;
```
`bpf_prog_linfo__lfind()` 则按 `insn_off` 查询，逻辑几乎对称：
```c
raw_linfo = prog_linfo->raw_linfo + (nr_skip * rec_size);
linfo = raw_linfo;
if (insn_off < linfo->insn_off)
return errno = ENOENT, NULL;
...
for (i = 0; i < nr_linfo; i++) {
if (insn_off < linfo->insn_off)
break;
...
}
return raw_linfo - rec_size;
```
这两个接口都没有使用二分。这背后的判断大概是：line info 规模通常不大到需要更复杂的索引结构，而线性扫描更简单、更稳妥，也更容易与 `nr_skip` 语义配合。
**6.7 在 libbpf 内部的使用关系：更偏向对外 API** 这里的交叉引用和前几个基础模块很不一样。`rg` 与 clangd references 都显示：
`bpf_prog_linfo__new()`、`__free()`、`__lfind()`、`__lfind_addr_func()`
在 `src/` 里几乎没有别的内部调用点；
主要可见引用来自 `libbpf.h:1750-1757` 的 public declarations。
这说明它在当前架构里主要是：
libbpf 对外提供的便利封装；；供外部工具、调试器或上层应用消费；；而不是 libbpf 内部对象装载、BTF、linker 主流程的一部分。
从这个意义上讲，`bpf_prog_linfo.c` 属于“生态接口层工具模块”。
**6.8 设计取舍** 这个文件的设计取舍可以概括为：
1. 先复制内核返回的原始数据，再建立自己的索引；2. 基础 line info 能力与 jited 增强能力分层，缺一部分时也尽量返回可用对象；3. 用两张数组索引把全局 jited line info 按函数切片；4. 对 record size、地址单调性、长度边界做保守校验；5. 查询路径保持简单，优先稳定和可读性，而不是过早复杂化。
因此 `bpf_prog_linfo.c` 的价值并不在于算法炫目，而在于它把原本较难直接消费的 `bpf_prog_info` 元数据整理成了稳定、可查询、可复用的工具对象。
---
## 7. libbpf_utils.c — 错误处理与 SHA-256

### 7.1 概述

`libbpf_utils.c` (256 行) 包含两个不相关的功能模块：

1. **错误码字符串化** — 将 libbpf 自定义错误码和系统 errno 转为可读字符串
2. **SHA-256 哈希** — 纯 C 实现的 SHA-256 算法（无外部依赖）

### 7.2 错误处理

#### libbpf_strerror()

公开 API，处理三类错误码：

```c
int libbpf_strerror(int err, char *buf, size_t size)
{
    if (err < __LIBBPF_ERRNO__START)
        return strerror_r(err, buf, size);     // 标准系统错误
    if (err < __LIBBPF_ERRNO__END)
        return snprintf(buf, size, "%s", libbpf_strerror_table[...]);  // libbpf 自定义错误
    return snprintf(buf, size, "Unknown libbpf error %d", err);  // 未知
}
```

libbpf 定义了 10 个自定义错误码（LIBELF/FORMAT/KVERSION/ENDIAN/INTERNAL/
RELOC/VERIFY/PROG2BIG/KVER/PROGTYPE/WRNGPID/INVSEQ/NLPARSE），均映射到
`libbpf_strerror_table[]` 中的描述字符串。

#### libbpf_errstr()

内部使用的轻量级版本，通过 switch-case 直接返回 errno 的字符串名：

```c
const char *libbpf_errstr(int err)
{
    switch (err) {
    case -EINVAL: return "-EINVAL";
    case -ENOMEM: return "-ENOMEM";
    // ... 约 50 个 errno
    default:
        snprintf(buf, sizeof(buf), "%d", err);  // thread-local buffer
        return buf;
    }
}
```

在 libbpf 内部通过 `#define errstr(err) libbpf_errstr(err)` 宏广泛使用于
`pr_warn("failed: %s\n", errstr(err))` 风格的日志输出。

### 7.3 SHA-256 实现

libbpf 内嵌了完整的 SHA-256 实现，避免对 OpenSSL/libcrypto 的外部依赖。

**调用者**：
- `libbpf.c:4603` — 计算 BPF 程序指令的哈希值（用于程序去重/标识）
- `gen_loader.c:462` — gen_loader 数据段哈希

**实现**：标准 FIPS 180-4 SHA-256 算法，64 轮压缩，使用循环展开优化（每次
处理 8 轮），支持任意长度输入的 padding 处理。

```c
void libbpf_sha256(const void *data, size_t len, __u8 out[SHA256_DIGEST_LENGTH])
```

**设计选择**：自包含实现而非依赖外部库，保持 libbpf 的最小依赖特性
（仅依赖 libelf + zlib）。

---

## 8. nlattr.c — Netlink 属性编解码

### 8.1 概述

`nlattr.c` (194 行) 实现了 Netlink 消息中 TLV (Type-Length-Value) 属性的
解析与验证。这是 libbpf 与内核通过 Netlink 协议通信的基础设施。

### 8.2 Netlink 属性格式

```
┌─────────────────────────────────┐
│ struct nlattr                   │
│ ├── nla_len:  属性总长度 (含头) │
│ └── nla_type: 属性类型          │
├─────────────────────────────────┤
│ payload (变长数据)              │
├─────────────────────────────────┤
│ padding (对齐到 4 字节)         │
└─────────────────────────────────┘
```

### 8.3 核心函数

#### libbpf_nla_parse() — 属性流解析

将连续的 Netlink 属性流解析为按类型索引的数组：

```c
int libbpf_nla_parse(struct nlattr *tb[], int maxtype,
                     struct nlattr *head, int len,
                     struct libbpf_nla_policy *policy)
```

遍历属性流，按 `nla_type` 存入 `tb[]` 数组。如果提供了 `policy`，
同时进行类型和长度验证。

#### libbpf_nla_parse_nested() — 嵌套属性解析

对嵌套属性（属性的 payload 本身是属性流）递归调用 `libbpf_nla_parse()`。

#### libbpf_nla_dump_errormsg() — 错误消息提取

从 Netlink ACK 消息中提取内核扩展错误信息 (`NLMSGERR_ATTR_MSG`)：

```c
int libbpf_nla_dump_errormsg(struct nlmsghdr *nlh)
{
    // 解析 NLM_F_ACK_TLVS 中的扩展属性
    // 提取并打印内核错误消息
}
```

### 8.4 验证策略

通过 `libbpf_nla_policy` 结构定义每种属性类型的约束：

| 属性类型 | 最小长度 |
|---------|---------|
| NLA_U8 | 1 字节 |
| NLA_U16 | 2 字节 |
| NLA_U32 | 4 字节 |
| NLA_U64 | 8 字节 |
| NLA_STRING | 1 字节 (需 NULL 结尾) |
| NLA_FLAG | 0 字节 |

### 8.5 调用关系

`nlattr.c` 专供 `netlink.c` 使用：

```
netlink.c
├── libbpf_nla_parse()           — 解析 CTRL_ATTR、IFLA、TCA 等属性
├── libbpf_nla_parse_nested()    — 解析 IFLA_XDP、TCA_BPF 嵌套属性
└── libbpf_nla_dump_errormsg()   — 提取 Netlink 错误消息
```

具体调用场景：
- XDP 程序查询：解析 `IFLA_XDP` 嵌套属性获取 XDP 程序 ID
- TC 程序查询：解析 `TCA_BPF` 嵌套属性获取 TC 过滤器信息
- 通用 Netlink 族 ID 发现：解析 `CTRL_ATTR_FAMILY_ID`

---

## 9. 总结：八个模块共同体现的 libbpf 工具层风格
把这八个文件放在一起看，它们共同展现出非常典型的 libbpf 工具层风格。
第一，职责边界极窄。`zip.c` 只做 APK/ZIP entry 定位，`btf_iter.c` 只做字段遍历，`strset.c` 只做字符串 blob 去重，`libbpf_probes.c` 只做 capability probe recipe，`nlattr.c` 只做 Netlink TLV 解析，`libbpf_utils.c` 只做错误字符串化和哈希。这种"小模块 + 强边界"的做法让上层大文件更容易维持结构清晰。
第二，优先工程上足够好的方案，而不是抽象上最通用的方案。`zip.c` 不追求完整 ZIP，`hashmap.c` 不追求线程安全或高级哈希技巧，`strset.c` 接受未提交尾部垃圾，`bpf_prog_linfo.c` 用线性扫描而不是复杂索引，`libbpf_utils.c` 自带 SHA-256 而非引入外部加密库，都是这种风格的体现。
第三，基础设施一旦写对，复用面很广。`hashmap.c` 贯穿 BTF、CO-RE、USDT、`strset`、`btf_dump`；`strset.c` 同时支撑 BTF 与 linker；`btf_iter.c` 同时支撑 BTF add/dedup/relocate/link；`libbpf_probes.c` 则把不同 program/map/helper 的能力判定统一抽象到最小 probe 路径之上；`libbpf_errstr()` 通过宏定义成为所有模块的标准错误输出方式。
第四，libbpf 很擅长把"格式知识"与"业务流程"分离。`zip.c` 把 ZIP 格式解析从 `libbpf.c` 中剥离；`btf_iter.c` 把 BTF kind-specific 遍历从 `btf.c` / `linker.c`中剥离；`strset.c` 把字符串表构建从 BTF 与 ELF 链接逻辑中剥离；`nlattr.c` 把 Netlink TLV 编解码从 `netlink.c` 的业务逻辑中剥离。这让上层文件可以更多表达"要做什么"，而不是"底层格式怎么遍历"。
所以，这八个文件虽然都不算"明星模块"，却共同构成了 libbpf 能保持可维护性的重要原因：复杂的大功能并不是靠单个巨型文件堆出来的，而是靠一批边界清楚、复用率高、工程判断细致的工具模块支撑起来的。
