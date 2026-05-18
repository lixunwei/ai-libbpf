# libbpf Ring Buffer 与 USDT 深度分析

## 0. 分析范围

- `src/ringbuf.c`（684 行）
- `src/usdt.c`（1688 行）
- 补充：`src/zip.c`（ZIP 基础设施）

---

## 1. `ringbuf.c`：用户态 ring buffer 实现

### 1.1 模块定位

`ringbuf.c` 同时实现了两套方向相反的缓冲区：

1. **ring buffer**：内核 BPF 程序生产，用户态消费；
2. **user ring buffer**：用户态生产，内核 BPF 程序消费。

核心结构：

- `struct ring`：`ringbuf.c:25-33`
- `struct ring_buffer`：`ringbuf.c:35-41`
- `struct user_ring_buffer`：`ringbuf.c:43-52`
- `struct ringbuf_hdr`：`ringbuf.c:55-58`

### 1.2 内存映射布局

#### 1.2.1 普通 ring buffer（内核 → 用户）

`ring_buffer__add()`（`ringbuf.c:75-170`）的 mmap 方案：

```c
/* ringbuf.c:122-150 */
/* Map writable consumer page */
mmap(..., PROT_READ | PROT_WRITE, ..., map_fd, 0);

/* Map read-only producer page and data pages */
mmap(..., PROT_READ, ..., map_fd, rb->page_size);
r->producer_pos = tmp;
r->data = tmp + rb->page_size;
```

布局可概括为：

```text
[consumer page]          可读写，用户更新 consumer_pos
[producer page]          只读，内核更新 producer_pos
[data area x 2]          只读，映射两倍大小，便于跨尾部连续读取
```

这里“data area 映射两倍”是本文件最关键的实现技巧：当样本跨越环尾时，用户态仍可把它当作线性内存读取，而不用做两段拷贝。

#### 1.2.2 user ring buffer（用户 → 内核）

`user_ringbuf_map()`（`ringbuf.c:447-515`）刚好反过来：

- consumer page 只读；
- producer page + data pages 可读写；
- 仍然映射双倍 data area。

### 1.3 同步模型

`ringbuf_process_ring()`（`ringbuf.c:234-278`）使用 acquire/release 语义：

- `smp_load_acquire(r->consumer_pos)`：读取消费者位置；
- `smp_load_acquire(r->producer_pos)`：读取生产者位置；
- `smp_load_acquire(len_ptr)`：读取样本头；
- `smp_store_release(r->consumer_pos, cons_pos)`：提交消费进度。

这与内核 `kernel/bpf/ringbuf.c` 的发布/提交协议一一对应：

- 生产者先写数据，再清 `BUSY_BIT`；
- 消费者先看 `len` 和标志位，再读 payload；
- `DISCARD_BIT` 表示该样本被丢弃。

### 1.4 `ring_buffer__new/poll/consume` 主流程

clangd 对 `ring_buffer__new()` 的 outgoing 调用链：

```text
ring_buffer__new() [ringbuf.c:189]
  -> getpagesize()
  -> epoll_create1()
  -> ring_buffer__add()
  -> ring_buffer__free()
```

#### 创建

- `ring_buffer__new()`：`ringbuf.c:189-221`
- `ring_buffer__add()`：`ringbuf.c:75-170`

流程：

1. 分配 `struct ring_buffer`；
2. 记录页大小；
3. 创建 `epoll_fd`；
4. 对首个 map 执行 `ring_buffer__add()`；
5. 在 `__add()` 内完成 map info 校验、mmap、`epoll_ctl(ADD)`。

#### 消费

- `ring_buffer__consume_n()`：`ringbuf.c:287-305`
- `ring_buffer__consume()`：`ringbuf.c:312-330`
- `ring_buffer__poll()`：`ringbuf.c:336-357`

`poll()` 只是“先 `epoll_wait()`，再调 `ringbuf_process_ring()`”；真正的 record 解析都在 `ringbuf_process_ring()`。

#### 单条样本处理

`ringbuf_process_ring()`（`ringbuf.c:248-270`）逻辑：

1. 通过 `cons_pos & mask` 找到头部；
2. 读取 `len`；
3. 若 `BUSY_BIT` 仍在，说明生产者尚未提交，立即退出；
4. 用 `roundup_len()`（`ringbuf.c:223-232`）跨过 header + padding；
5. 若没有 `DISCARD_BIT`，把 `sample` 传给用户回调；
6. 更新 `consumer_pos`。

### 1.5 与 perf buffer 的对比

虽然 `ringbuf.c` 本身不直接实现 perf buffer，但从接口和数据通路上，差异很清楚：

| 维度 | ring buffer | perf buffer |
|---|---|---|
| 内核对象 | `BPF_MAP_TYPE_RINGBUF` | perf event array |
| 事件组织 | 单共享 ring | 每 CPU 独立缓冲区更常见 |
| 用户态读取 | 直接 mmap + 头部协议 | perf event header 协议 |
| 唤醒模型 | map fd 可直接 `epoll` | perf fd `poll/epoll` |
| 跨 CPU 顺序 | 更容易做全局顺序消费 | 天然分 CPU |
| 复制成本 | 更低，针对可变长样本优化 | 历史包袱更多 |

### 1.6 与内核 `kernel/bpf/ringbuf.c` 的对应关系

`ringbuf.c` 的用户态实现是内核 ringbuf 协议的镜像：

- `consumer_pos/producer_pos` 的语义一致；
- `BPF_RINGBUF_BUSY_BIT` / `BPF_RINGBUF_DISCARD_BIT` 完全对齐；
- 双映射 data area 的技巧依赖内核端 ring layout；
- 用户态 `user_ring_buffer__reserve/submit` 则对应内核 `__bpf_user_ringbuf_peek()` 的消费路径。

### 1.7 `ringbuf.c` 关键函数表

| 函数 | 位置 | 签名 | 核心逻辑 | 关键数据结构 |
|---|---|---|---|---|
| `ring_buffer__add` | `ringbuf.c:75` | `int ring_buffer__add(struct ring_buffer *rb, int map_fd, ring_buffer_sample_fn sample_cb, void *ctx)` | 校验 map 类型、执行双 mmap、挂到 epoll | `struct ring`, `struct bpf_map_info` |
| `ring_buffer__new` | `ringbuf.c:189` | `struct ring_buffer *ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx, const struct ring_buffer_opts *opts)` | 创建管理器和 epoll，并添加首个 ring | `struct ring_buffer` |
| `roundup_len` | `ringbuf.c:223` | `static inline int roundup_len(__u32 len)` | 去掉 busy/discard 位并按 8 字节对齐 | `BPF_RINGBUF_HDR_SZ` |
| `ringbuf_process_ring` | `ringbuf.c:234` | `static int64_t ringbuf_process_ring(struct ring *r, size_t n)` | 解析 header、判断 busy/discard、回调样本、推进 consumer | `struct ringbuf_hdr` |
| `ring_buffer__consume_n` | `ringbuf.c:287` | `int ring_buffer__consume_n(struct ring_buffer *rb, size_t n)` | 不阻塞地轮询所有 ring，最多消费 n 条 | `struct ring_buffer` |
| `ring_buffer__consume` | `ringbuf.c:312` | `int ring_buffer__consume(struct ring_buffer *rb)` | 不阻塞全量消费 | `struct ring_buffer` |
| `ring_buffer__poll` | `ringbuf.c:336` | `int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms)` | `epoll_wait()` 后只处理就绪 ring | `epoll_event` |
| `user_ring_buffer__new` | `ringbuf.c:517` | `struct user_ring_buffer *user_ring_buffer__new(int map_fd, const struct user_ring_buffer_opts *opts)` | 建立用户态生产方向的 ring | `struct user_ring_buffer` |
| `user_ring_buffer__reserve` | `ringbuf.c:579` | `void *user_ring_buffer__reserve(struct user_ring_buffer *rb, __u32 size)` | 检查空间、写 busy header、推进 `producer_pos` | `struct ringbuf_hdr` |
| `user_ring_buffer__reserve_blocking` | `ringbuf.c:630` | `void *user_ring_buffer__reserve_blocking(struct user_ring_buffer *rb, __u32 size, int timeout_ms)` | 空间不足时借助 `epoll_wait(EPOLLOUT)` 阻塞等待 | `timespec`, `epoll` |

---

## 2. `usdt.c`：USDT 用户态探针管理器

### 2.1 模块定位

`usdt.c` 的设计中心是 `struct usdt_manager`（`usdt.c:254-266`）。

它把 USDT 支持拆成两部分：

1. **BPF 侧**：`usdt.bpf.h` 提供 spec map 和 IP→spec_id map；
2. **用户态侧**：`usdt_manager` 负责发现 probe、解析参数规格、写 map、附加 uprobes。

文件开头的大块注释（`usdt.c:24-189`）已经把实现思路说得很清楚：

- USDT 本质是“带 note 元数据的 uprobe”；
- 同一 `provider:name` 可能对应多个 call site；
- 不同 call site 可能有不同参数位置表达式；
- 因而 libbpf 为“唯一参数规格”分配 `spec_id`，并把规格写入 BPF map；
- 新内核可直接用 BPF cookie 传 `spec_id`，旧内核则回退到 IP→spec_id map。

### 2.2 `.note.stapsdt` 解析

#### ELF 基础校验

- `sanity_check_usdt_elf()`：`usdt.c:324-374`
- `find_elf_sec_by_name()`：`usdt.c:376-402`
- `parse_elf_segs()`：`usdt.c:419-467`

这里只接受：

- `ELF_K_ELF`
- `ELFCLASS32/64` 且与当前用户态字宽匹配
- `ET_EXEC` 或 `ET_DYN`
- 与宿主一致的 endianness

#### note 解析

`parse_usdt_note()`（`usdt.c:1183-1235`）把一条 `NT_STAPSDT` note 拆成：

- `provider`
- `name`
- `args`
- `loc_addr`
- `base_addr`
- `sema_addr`

对应结构就是 `struct usdt_note`（`usdt.c:234-244`）。

### 2.3 目标地址收集：`collect_usdt_targets()`

- **位置**：`usdt.c:615-851`
- **签名**：`static int collect_usdt_targets(struct usdt_manager *man, struct elf_fd *elf_fd, const char *path, pid_t pid, const char *usdt_provider, const char *usdt_name, __u64 usdt_cookie, struct usdt_target **out_targets, size_t *out_target_cnt)`

它是整个 USDT 附加路径最重要的函数，完成四件事：

1. 找到 `.note.stapsdt` 与可选 `.stapsdt.base`；
2. 遍历所有 STAPSDT note，只保留目标 `provider:name`；
3. 处理 prelink/base address 补偿，把 note 地址修正成真实地址；
4. 把虚拟地址转换成：
   - `rel_ip`：uprobes attach 需要的 file offset；
   - `abs_ip`：旧内核无 BPF cookie 时作为查表 key；
   - `sema_off`：可选 semaphore 在文件中的 offset。

代码片段（`usdt.c:701-726`）：

```c
usdt_abs_ip = note.loc_addr;
if (base_addr && note.base_addr)
    usdt_abs_ip += base_addr - note.base_addr;
...
seg = find_elf_seg(segs, seg_cnt, usdt_abs_ip);
usdt_rel_ip = usdt_abs_ip - seg->start + seg->offset;
```

这就是“STAPSDT note 地址 → uprobe attach offset”的关键转换。

### 2.4 参数规格解析（位置表达式）

#### 规格入口

- `parse_usdt_spec()`：`usdt.c:1239-1280`
- `parse_usdt_arg()`：各架构实现，x86_64 在 `usdt.c:1331-1414`
- `calc_pt_regs_off()`：x86_64 在 `usdt.c:1286-1329`

#### 支持的表达式类型

以 x86_64 为例，`parse_usdt_arg()` 支持四类：

1. **常量**：`4@$71`
2. **寄存器**：`-4@%eax`
3. **寄存器间接寻址**：`-4@-20(%rbp)`
4. **SIB（scale-index-base）**：`1@-96(%rbp,%rax,8)`

解析结果写入 `struct usdt_arg_spec`（`usdt.c:206-222`），其字段会直接送进 BPF map，让 `bpf/usdt.bpf.h` 里的 BPF 代码在运行时取参。

### 2.5 semaphore 机制

USDT note 里可带 `sema_addr`。`collect_usdt_targets()` 在 `usdt.c:773-798` 把它转换成文件 offset；同时 `usdt_manager_new()` 会探测内核是否支持 uprobe refcount（`usdt.c:294-299`）。

如果内核不支持自动 refcount，而 probe 又声明了 semaphore，libbpf 会拒绝附加，避免用户态“以为已启用、但实际上 sema 不会递增”的错误语义。

### 2.6 uprobe 底层实现

#### 管理器创建

`usdt_manager_new()`（`usdt.c:268-313`）会探测四种能力：

- `FEAT_BPF_COOKIE`
- `ref_ctr_offset` sysfs 支持（USDT semaphore）
- `FEAT_UPROBE_MULTI_LINK`
- `FEAT_UPROBE_SYSCALL`

#### 附加主流程

clangd 对 `usdt_manager_attach_usdt()` 的 outgoing 调用链：

```text
usdt_manager_attach_usdt() [usdt.c:1005]
  -> elf_open()
  -> sanity_check_usdt_elf()
  -> collect_usdt_targets()
  -> allocate_spec_id()
  -> bpf_map_update_elem()
  -> bpf_program__attach_uprobe_opts()
  -> bpf_program__attach_uprobe_multi()
```

`usdt_manager_attach_usdt()`（`usdt.c:1005-1178`）做的事：

1. 打开目标 ELF；
2. 收集所有匹配 probe 位置；
3. 用 hashmap 以 `spec_str` 为 key 做“同 attach 内部”的 spec 去重；
4. 为每个新 spec 分配 `spec_id`，写入 `__bpf_usdt_specs` map；
5. 若无 BPF cookie，则写 `abs_ip -> spec_id` 到 `__bpf_usdt_ip_to_spec_id`；
6. 如果内核支持 multi-uprobe，就批量附加；否则逐个 `bpf_program__attach_uprobe_opts()`。

#### spec ID 复用

`allocate_spec_id()`（`usdt.c:950-1003`）有两个层次的复用：

- 当前一次 attach 内，按 `spec_str` 去重；
- attach detach 后，把 spec_id 放回 `free_spec_ids`，供后续 attach 重用。

### 2.7 ZIP 支持（与 `zip.c` 的关系）

用户提到“ZIP 文件支持（zip.c 配合）”。从当前源码看，需要 **准确区分**：

- `zip.c` 确实是 libbpf 的 ZIP 归档解析基础设施；
- 但 **当前 `usdt.c` 没有直接调用 `zip_archive_open()` / `zip_archive_find_entry()`**；
- 因此 ZIP 不是 `usdt.c` 的主流程组成部分，而是 libbpf 内部相邻能力。

`zip.c` 的关键点：

- `zip_archive_open()`：`zip.c:198`
- `find_cd()`：`zip.c:175`
- `try_parse_end_of_cd()`：`zip.c:146`
- `zip_archive_find_entry()`：`zip.c:298`

它提供的是“从 ZIP/JAR 一类容器中找成员文件”的能力，但不能说当前版本 `usdt.c` 已直接走 ZIP 路径。

### 2.8 `usdt.c` 关键函数表

| 函数 | 位置 | 签名 | 核心逻辑 | 关键数据结构 |
|---|---|---|---|---|
| `usdt_manager_new` | `usdt.c:268` | `struct usdt_manager *usdt_manager_new(struct bpf_object *obj)` | 找 USDT support maps，并探测 cookie/sema/multi/sycall 能力 | `struct usdt_manager` |
| `sanity_check_usdt_elf` | `usdt.c:324` | `static int sanity_check_usdt_elf(Elf *elf, const char *path)` | 校验 ELF 类型、位宽、端序 | `GElf_Ehdr` |
| `find_elf_sec_by_name` | `usdt.c:376` | `static int find_elf_sec_by_name(Elf *elf, const char *sec_name, GElf_Shdr *shdr, Elf_Scn **scn)` | 按名字找 section | `Elf_Scn`, `GElf_Shdr` |
| `parse_elf_segs` | `usdt.c:419` | `static int parse_elf_segs(Elf *elf, const char *path, struct elf_seg **segs, size_t *seg_cnt)` | 收集 PT_LOAD 段，构建地址/offset 映射 | `struct elf_seg` |
| `parse_vma_segs` | `usdt.c:469` | `static int parse_vma_segs(int pid, const char *lib_path, struct elf_seg **segs, size_t *seg_cnt)` | 从 `/proc/<pid>/maps` 获取共享库实际映射段 | `struct elf_seg` |
| `collect_usdt_targets` | `usdt.c:615` | `static int collect_usdt_targets(...)` | 解析 `.note.stapsdt`、修正 prelink、换算 `abs_ip/rel_ip/sema_off`、构造 `usdt_target` | `struct usdt_target`, `struct usdt_note` |
| `bpf_link_usdt_detach` | `usdt.c:871` | `static int bpf_link_usdt_detach(struct bpf_link *link)` | 销毁 uprobe/link，回收 spec_id，清理 IP→spec 映射 | `struct bpf_link_usdt` |
| `allocate_spec_id` | `usdt.c:950` | `static int allocate_spec_id(struct usdt_manager *man, struct hashmap *specs_hash, struct bpf_link_usdt *link, struct usdt_target *target, int *spec_id, bool *is_new)` | 复用或分配新的 spec_id | `hashmap`, `free_spec_ids` |
| `usdt_manager_attach_usdt` | `usdt.c:1005` | `struct bpf_link *usdt_manager_attach_usdt(struct usdt_manager *man, const struct bpf_program *prog, pid_t pid, const char *path, const char *usdt_provider, const char *usdt_name, __u64 usdt_cookie)` | 完成发现、解析、spec map 写入、uprobe 附加 | `struct usdt_target`, `struct bpf_link_usdt` |
| `parse_usdt_note` | `usdt.c:1183` | `static int parse_usdt_note(GElf_Nhdr *nhdr, const char *data, size_t name_off, size_t desc_off, struct usdt_note *note)` | 从 ELF note 中提取 provider/name/args/三类地址 | `struct usdt_note` |
| `parse_usdt_spec` | `usdt.c:1239` | `static int parse_usdt_spec(struct usdt_spec *spec, const struct usdt_note *note, __u64 usdt_cookie)` | 逐项解析参数表达式并写入 `usdt_spec` | `struct usdt_spec` |
| `calc_pt_regs_off` | `usdt.c:1286` | `static int calc_pt_regs_off(const char *reg_name)` | 把寄存器名映射为 `pt_regs` 偏移 | `struct pt_regs` |
| `parse_usdt_arg` | `usdt.c:1331` | `static int parse_usdt_arg(const char *arg_str, int arg_num, struct usdt_arg_spec *arg, int *arg_sz)` | 解析常量/寄存器/寄存器解引用/SIB 表达式 | `struct usdt_arg_spec` |

---

## 3. 总结

- `ringbuf.c` 是 libbpf 中“零拷贝式事件通道”的用户态实现，核心是 **双 mmap + acquire/release 协议 + epoll**；
- `usdt.c` 则把“静态探针”抽象成“**多位置 uprobe + 参数规格 map + spec_id 分配器**”；
- 两者都体现了 libbpf 一贯的设计：
  - 数据结构尽量平铺；
  - 用户态状态机清晰；
  - 把复杂性收敛成几个关键 map/offset/ID 的重写问题。
