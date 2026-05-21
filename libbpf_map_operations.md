# BPF Map 类型与操作大全
本文基于 `src/libbpf.map`、`src/libbpf.h`、`src/bpf.h`、`include/uapi/linux/bpf.h` 整理。
---
## 1. Map 概述
### 1.1 Map 在 BPF 中的角色
- BPF Map 是 eBPF 世界里最核心的状态容器。
- 它承担三类角色：
  - **内核态状态存储**：程序之间共享计数器、配置、缓存、索引。
  - **内核态 ↔ 用户态数据交换**：用户态读取统计、写入配置、消费事件。
  - **内核对象关联存储**：把状态绑到 socket、task、inode、cgroup 等内核对象上。
- 从实现上看，Map 是由 `bpf()` syscall 创建、由内核持有生命周期、通过 FD 引用的内核对象。
- 从抽象上看，libbpf 把 Map 又封装成 `struct bpf_map`，让用户看到更高层的 metadata。
### 1.2 Map 生命周期
1. 用户态发起 `BPF_MAP_CREATE`。
2. 内核返回 map FD。
3. 程序加载时，libbpf 把 BPF 指令中的 map 引用重写成真实 FD。
4. 运行期间，BPF 程序通过 helper 操作 map。
5. 用户态通过 low-level syscall wrapper 或 libbpf 高层 API 操作同一个 map。
6. 如需跨进程/跨生命周期保留 map，可执行 pin。
7. FD 关闭且没有 pin 或其他引用后，map 被内核回收。
### 1.3 libbpf 中的 map 管理
- `struct bpf_map` 是 libbpf 的高层抽象，保存：
  - map 名字；
  - type、key/value size、max_entries、flags；
  - BTF type id；
  - pin path；
  - inner map / initial value / autoattach / autocreate 等附加信息。
- `bpf_object__find_map_by_name()`、`bpf_object__next_map()` 等接口围绕这个高层抽象工作。
- 真正发给内核的是 `bpf_attr` 中的 map 创建/操作字段。
### 1.4 BTF-defined maps
- 现代 libbpf 推荐把 map 定义写成 BTF-defined syntax，并放在 `SEC(".maps")`。
- `src/bpf_helpers.h` 中的关键宏：
  - `__uint(name, val)`
  - `__type(name, val)`
  - `__array(name, val)`
  - `SEC(name)`
- 这种写法让 libbpf 可以直接从 BTF 里读出 map 元信息，而不依赖老式 `struct bpf_map_def`。
- `src/libbpf_legacy.h` 也明确说明：`SEC("maps")` 老式 map 定义在 1.0+ 不再是主线。
### 1.5 Map 访问的三层接口
| 层次 | 代表接口 | 特点 |
|---|---|---|
| 内核态 helper | `bpf_map_lookup_elem()`、`bpf_tail_call()` | 在 BPF 程序里使用 |
| 用户态 syscall wrapper | `bpf_map_update_elem()`、`bpf_map_create()` | 几乎一一对应 `bpf()` 命令 |
| libbpf 高层 API | `bpf_map__update_elem()`、`bpf_map__pin()` | 带对象语义、size 校验、自动管理 |
---
## 2. Map 类型分类与详解
### 2.1 HASH
- **类别**：通用存储类
- **用途简述**：任意 key-value 字典。
- **key/value 类型**：`key` 固定大小；`value` 固定大小。
- **常见标志**：`BPF_F_NO_PREALLOC`、`BPF_F_ZERO_SEED`、`BPF_F_RDONLY`、`BPF_F_WRONLY`。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_HASH);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_map_lookup_elem` / `bpf_map_update_elem` / `bpf_map_delete_elem`。
- **用户态操作 API**：`bpf_map__lookup_elem`、`bpf_map__update_elem`、`bpf_map__delete_elem`。
- **实现/语义备注**：最常见的数据通道，适合状态缓存、计数器、索引表。
- **补充说明**：最基础的 KV 模型，很多更复杂 map 的直觉都可以先类比 HASH 再理解差异。
### 2.2 PERCPU_HASH
- **类别**：通用存储类
- **用途简述**：每 CPU 一份 value 的 hash。
- **key/value 类型**：`key` 固定；`value` 逻辑上固定，但实际按 CPU 数扩展并按 8 字节对齐。
- **常见标志**：`BPF_F_NO_PREALLOC`、`BPF_F_ZERO_SEED`。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_PERCPU_HASH);` + `SEC(".maps")`。
- **内核态 helper**：helper 同 HASH，但 value 语义是 per-CPU。
- **用户态操作 API**：用户态读取时通常要准备 `round_up(value_size, 8) * nr_cpus` 缓冲区。
- **实现/语义备注**：适合热点计数，避免跨 CPU cache line 竞争。
### 2.3 LRU_HASH
- **类别**：通用存储类
- **用途简述**：带 LRU 淘汰的 hash。
- **key/value 类型**：`key/value` 与 HASH 相同。
- **常见标志**：`BPF_F_NO_COMMON_LRU`、`BPF_F_NUMA_NODE`。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_LRU_HASH);` + `SEC(".maps")`。
- **内核态 helper**：helper 同 HASH。
- **用户态操作 API**：用户态 API 同 HASH。
- **实现/语义备注**：适合 bounded cache；当达到 `max_entries` 时内核回收旧项。
### 2.4 LRU_PERCPU_HASH
- **类别**：通用存储类
- **用途简述**：per-CPU value + LRU 淘汰。
- **key/value 类型**：`key` 固定；`value` 为 per-CPU 语义。
- **常见标志**：`BPF_F_NO_COMMON_LRU`。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);` + `SEC(".maps")`。
- **内核态 helper**：helper 同 HASH。
- **用户态操作 API**：用户态 API 同 HASH / PERCPU_HASH。
- **实现/语义备注**：常见于高频 telemetry，既要低争用，又要自动淘汰。
### 2.5 ARRAY
- **类别**：通用存储类
- **用途简述**：按整数索引访问的定长数组。
- **key/value 类型**：`key` 常为 `__u32`；`value` 固定大小。
- **常见标志**：`BPF_F_MMAPABLE`、`BPF_F_RDONLY_PROG`、`BPF_F_WRONLY_PROG`。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_ARRAY);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_map_lookup_elem`；更新通常仍用 `bpf_map_update_elem`。
- **用户态操作 API**：用户态可用高层 map API；mmap 场景还可以直接映射。
- **实现/语义备注**：适合配置表、状态槽、全局变量 backing map。
- **补充说明**：全局变量 `.data/.bss/.rodata` backing map 从行为上也很接近 ARRAY。
### 2.6 PERCPU_ARRAY
- **类别**：通用存储类
- **用途简述**：每 CPU 一份 value 的数组。
- **key/value 类型**：`key` 常为 `__u32`；`value` 为 per-CPU 布局。
- **常见标志**：`BPF_F_MMAPABLE` 在此类 map 上通常不是主路线。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);` + `SEC(".maps")`。
- **内核态 helper**：helper 同 ARRAY。
- **用户态操作 API**：用户态读取需要按 CPU 展开缓冲。
- **实现/语义备注**：适合 per-CPU 计数器与热点路径统计。
### 2.7 LPM_TRIE
- **类别**：通用存储类
- **用途简述**：最长前缀匹配 trie。
- **key/value 类型**：`key` 通常是 `struct bpf_lpm_trie_key_u8`；`value` 自定义。
- **常见标志**：`BPF_F_NO_PREALLOC` 常见且通常必需。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_LPM_TRIE);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_map_lookup_elem`、`bpf_map_update_elem`、`bpf_map_delete_elem`。
- **用户态操作 API**：用户态通过普通 map syscall 管理前缀项。
- **实现/语义备注**：典型场景是 CIDR、前缀路由、ACL 匹配。
- **补充说明**：`key` 的 `prefixlen` 与后续字节数组共同决定最长前缀匹配结果。
### 2.8 BLOOM_FILTER
- **类别**：通用存储类
- **用途简述**：近似集合，用于 membership test。
- **key/value 类型**：`key` 通常不用；`value` 表示要插入/查询的元素。
- **常见标志**：`map_extra` 低位用于 hash function 个数。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_BLOOM_FILTER);` + `SEC(".maps")`。
- **内核态 helper**：通常通过 generic map lookup/update 语义完成 test/insert。
- **用户态操作 API**：用户态仍走 `bpf_map_create` 与通用 elem API。
- **实现/语义备注**：优点是空间效率高，缺点是有 false positive。
### 2.9 QUEUE
- **类别**：队列/栈类
- **用途简述**：FIFO 容器。
- **key/value 类型**：无显式 key；`value` 为元素类型。
- **常见标志**：创建时常见 `key_size = 0`。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_QUEUE);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_map_push_elem`、`bpf_map_pop_elem`、`bpf_map_peek_elem`。
- **用户态操作 API**：用户态用 `bpf_map_lookup_and_delete_elem` 或 low-level 对应命令消费。
- **实现/语义备注**：适合轻量消息缓冲，但不提供 ringbuf 那种零拷贝模型。
### 2.10 STACK
- **类别**：队列/栈类
- **用途简述**：LIFO 容器。
- **key/value 类型**：无显式 key；`value` 为元素类型。
- **常见标志**：与 QUEUE 类似。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_STACK);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_map_push_elem`、`bpf_map_pop_elem`、`bpf_map_peek_elem`。
- **用户态操作 API**：用户态 API 与 QUEUE 类似。
- **实现/语义备注**：适合回收池、对象缓存、简单工作栈。
### 2.11 RINGBUF
- **类别**：队列/栈类
- **用途简述**：内核生产、用户态消费的高效 ring buffer。
- **key/value 类型**：无用户自定义 key；记录按 event record 组织。
- **常见标志**：`BPF_F_RB_OVERWRITE` 可开启 overwrite mode。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_RINGBUF);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_ringbuf_output`、`reserve`、`submit`、`discard`、`query`、`reserve_dynptr`。
- **用户态操作 API**：用户态常用 `ring_buffer__new`、`ring_buffer__poll`、`ring_buffer__consume_n`。
- **实现/语义备注**：这是现代事件通道首选，优先于老的 perf event array。
- **补充说明**：如果关注延迟和开销，优先考虑 ringbuf；如果关注兼容更老内核，再考虑 perf event array。
### 2.12 USER_RINGBUF
- **类别**：队列/栈类
- **用途简述**：用户态生产、内核消费的 ring buffer。
- **key/value 类型**：无显式 key；record 由用户态 reserve/submit。
- **常见标志**：flags 依内核实现与 map create 语义。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_USER_RINGBUF);` + `SEC(".maps")`。
- **内核态 helper**：内核端主要 helper 是 `bpf_user_ringbuf_drain`。
- **用户态操作 API**：用户态 API 是 `user_ring_buffer__new`、`reserve`、`submit`、`discard`。
- **实现/语义备注**：适合把控制消息或批量数据从用户态推给 BPF。
- **补充说明**：它把传统单向事件通道倒转了方向：生产者在用户态，消费者在 BPF。
### 2.13 PROG_ARRAY
- **类别**：程序控制类
- **用途简述**：存放 program FD，供 tail call。
- **key/value 类型**：`key` 常为 `__u32` 索引；`value` 是 program FD/ID 语义。
- **常见标志**：flags 一般较少。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_PROG_ARRAY);` + `SEC(".maps")`。
- **内核态 helper**：关键 helper 是 `bpf_tail_call`。
- **用户态操作 API**：用户态用 `bpf_map_update_elem` 把 program FD 填进槽位。
- **实现/语义备注**：适合拆分大程序、实现多阶段处理 pipeline。
- **补充说明**：tail call 跳转不会返回；失败时才会继续执行当前程序后续指令。
### 2.14 ARRAY_OF_MAPS
- **类别**：程序控制类
- **用途简述**：外层数组，value 是 inner map。
- **key/value 类型**：`key` 常为 `__u32`；`value` 从用户视角是 inner map FD。
- **常见标志**：`BPF_F_INNER_MAP` 与 `inner_map_fd` 相关。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);` + `SEC(".maps")`。
- **内核态 helper**：内核端通常先 `bpf_map_lookup_elem` 取到 inner map，再对 inner map 操作。
- **用户态操作 API**：用户态常用 `bpf_map__set_inner_map_fd` 或 `bpf_map_create_opts.inner_map_fd`。
- **实现/语义备注**：适合分片、命名空间隔离、按槽位切换工作集。
- **补充说明**：outer map 的 value 并不是普通内存块，而是对 inner map 的引用关系。
### 2.15 HASH_OF_MAPS
- **类别**：程序控制类
- **用途简述**：外层 hash，value 是 inner map。
- **key/value 类型**：`key` 任意固定大小；`value` 语义是 inner map。
- **常见标志**：`inner_map_fd` 是创建前提。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);` + `SEC(".maps")`。
- **内核态 helper**：helper 模式与 ARRAY_OF_MAPS 相同。
- **用户态操作 API**：用户态 API 同 ARRAY_OF_MAPS。
- **实现/语义备注**：适合动态 key 到 inner map 的映射。
### 2.16 DEVMAP
- **类别**：网络类
- **用途简述**：XDP redirect 到 netdevice。
- **key/value 类型**：`key` 常为 ifindex-like 整数；`value` 包含 device/queue 元信息。
- **常见标志**：`BPF_F_RDONLY_PROG` 等普通标志按需使用。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_DEVMAP);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_redirect_map`。
- **用户态操作 API**：用户态用通用 update API 写入目标网卡。
- **实现/语义备注**：典型场景是 XDP fast redirect。
- **补充说明**：XDP redirect 到网卡时，DEVMAP 和 CPUMAP 是两个最重要的数据通道。
### 2.17 DEVMAP_HASH
- **类别**：网络类
- **用途简述**：hash 形式的 devmap。
- **key/value 类型**：`key` 可自定义；`value` 仍是 device 元信息。
- **常见标志**：标志与 DEVMAP 接近。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_redirect_map`。
- **用户态操作 API**：用户态 API 同 DEVMAP。
- **实现/语义备注**：适合需要按自定义 key 选择输出设备。
### 2.18 CPUMAP
- **类别**：网络类
- **用途简述**：XDP redirect 到目标 CPU。
- **key/value 类型**：`key` 常为 CPU id；`value` 是队列/批处理参数。
- **常见标志**：创建参数会影响 queue 大小和 CPU 重定向行为。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_CPUMAP);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_redirect_map`。
- **用户态操作 API**：用户态用通用 update API 维护 CPU 目标。
- **实现/语义备注**：常用于把 XDP RX 流量卸给工作 CPU。
### 2.19 XSKMAP
- **类别**：网络类
- **用途简述**：AF_XDP socket 映射表。
- **key/value 类型**：`key` 常为 queue id；`value` 是 XSK socket FD。
- **常见标志**：标志一般较少。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_XSKMAP);` + `SEC(".maps")`。
- **内核态 helper**：XDP 程序里常用 `bpf_redirect_map` 重定向到 AF_XDP socket。
- **用户态操作 API**：用户态通过 libxdp/AF_XDP 套接字初始化后再写入 map。
- **实现/语义备注**：是 AF_XDP 零拷贝路径的核心粘合层。
### 2.20 SOCKMAP
- **类别**：网络类
- **用途简述**：把 socket 组织成数组/表，供 sk_msg/sk_skb redirect。
- **key/value 类型**：`key` 常为整数；`value` 是 socket FD。
- **常见标志**：`BPF_F_RDONLY` 等权限标志按需使用。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_SOCKMAP);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_sk_redirect_map`、`bpf_msg_redirect_map` 等。
- **用户态操作 API**：用户态用通用 update API 填 socket FD。
- **实现/语义备注**：适合透明代理、L7 分流、socket 级重定向。
- **补充说明**：SOCKMAP / SOCKHASH 经常与 `sk_msg`、`sk_skb` 程序类型一起出现。
### 2.21 SOCKHASH
- **类别**：网络类
- **用途简述**：hash 形式的 socket map。
- **key/value 类型**：`key` 常是 4-tuple 或自定义 session key；`value` 是 socket FD。
- **常见标志**：和 SOCKMAP 类似。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_SOCKHASH);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_sk_redirect_hash`、`bpf_msg_redirect_hash` 等。
- **用户态操作 API**：用户态 API 同 SOCKMAP。
- **实现/语义备注**：适合动态连接表。
### 2.22 REUSEPORT_SOCKARRAY
- **类别**：网络类
- **用途简述**：`SO_REUSEPORT` socket 选择数组。
- **key/value 类型**：`key` 常为 index；`value` 是 socket FD。
- **常见标志**：标志少，关键是 attach 场景。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);` + `SEC(".maps")`。
- **内核态 helper**：核心 helper 是 `bpf_sk_select_reuseport`。
- **用户态操作 API**：用户态在 listener 组建立后把 socket 填入 map。
- **实现/语义备注**：适合实现自定义 listen socket 负载均衡。
### 2.23 SK_STORAGE
- **类别**：存储类
- **用途简述**：给 socket 对象挂本地存储。
- **key/value 类型**：`key` 不由用户显式管理；`value` 是自定义结构。
- **常见标志**：创建时常见 local storage 相关语义。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_SK_STORAGE);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_sk_storage_get`、`bpf_sk_storage_delete`。
- **用户态操作 API**：用户态通常不按 key 遍历，而是通过对象生命周期间接使用。
- **实现/语义备注**：适合给每个 socket 附带状态机、统计、策略缓存。
- **补充说明**：local storage map 的 key 隐式绑定在内核对象本身，因此使用体验与传统 KV map 很不同。
### 2.24 INODE_STORAGE
- **类别**：存储类
- **用途简述**：给 inode 对象挂本地存储。
- **key/value 类型**：`key` 隐含在 inode 对象；`value` 自定义。
- **常见标志**：标志取决于 local storage 能力。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_INODE_STORAGE);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_inode_storage_get`、`bpf_inode_storage_delete`。
- **用户态操作 API**：用户态可通过常规 map introspection 查看，但典型逻辑在 BPF 侧。
- **实现/语义备注**：适合文件对象级别的状态缓存。
### 2.25 TASK_STORAGE
- **类别**：存储类
- **用途简述**：给 task_struct 挂本地存储。
- **key/value 类型**：`key` 隐含为 task；`value` 自定义。
- **常见标志**：常配合 tracing/sched 程序使用。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_TASK_STORAGE);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_task_storage_get`、`bpf_task_storage_delete`。
- **用户态操作 API**：用户态更多负责创建 map 与读取总体统计。
- **实现/语义备注**：适合 task 生命周期追踪。
### 2.26 CGRP_STORAGE
- **类别**：存储类
- **用途简述**：给 cgroup 对象挂本地存储。
- **key/value 类型**：`key` 隐含为 cgroup；`value` 自定义。
- **常见标志**：用于替代已 deprecated 的旧 cgroup storage map。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_cgrp_storage_get`、`bpf_cgrp_storage_delete`。
- **用户态操作 API**：用户态侧依然使用通用 map 创建与 introspection。
- **实现/语义备注**：适合 cgroup 级资源记账或策略状态。
### 2.27 PERF_EVENT_ARRAY
- **类别**：特殊类
- **用途简述**：把 BPF 事件写入 perf event。
- **key/value 类型**：`key` 常为 CPU id；`value` 是 perf event FD。
- **常见标志**：`BPF_F_PRESERVE_ELEMS` 等标志与共享场景有关。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_perf_event_output`。
- **用户态操作 API**：用户态高层消费 API 是 `perf_buffer__new` / `perf_buffer__poll`。
- **实现/语义备注**：老牌事件通道，兼容广，但编程模型比 ringbuf 更重。
### 2.28 STACK_TRACE
- **类别**：特殊类
- **用途简述**：保存 stack trace，返回 stack id。
- **key/value 类型**：`key` 由内核分配/管理；`value` 是栈地址或 build-id 信息。
- **常见标志**：`BPF_F_STACK_BUILD_ID` 很关键。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_STACK_TRACE);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_get_stackid`、相关 stack helper。
- **用户态操作 API**：用户态常用 `bpf_map_lookup_elem` 解析 stack record。
- **实现/语义备注**：适合 profiling、热点调用栈聚合。
### 2.29 CGROUP_ARRAY
- **类别**：特殊类
- **用途简述**：保存 cgroup 引用，供 helper 判断隶属关系。
- **key/value 类型**：`key` 常为 index；`value` 是 cgroup FD/ID 语义。
- **常见标志**：标志通常较少。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);` + `SEC(".maps")`。
- **内核态 helper**：`bpf_skb_under_cgroup`、`bpf_current_task_under_cgroup` 等 helper 会用到。
- **用户态操作 API**：用户态通过通用 update API 管理条目。
- **实现/语义备注**：适合把策略作用域外部化为 cgroup 集合。
### 2.30 STRUCT_OPS
- **类别**：特殊类
- **用途简述**：把 BPF 实现注册成内核可调用的 struct ops。
- **key/value 类型**：`key` 常为 0 或固定布局；`value` 是一整个 ops 结构。
- **常见标志**：`BPF_F_LINK` 在 link-backed struct_ops 场景里重要。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_STRUCT_OPS);` + `SEC(".maps")`。
- **内核态 helper**：内核并非通过通用 lookup/update 使用它，而是把其内容注册成内核回调。
- **用户态操作 API**：用户态特有 API 是 `bpf_map__attach_struct_ops`，并可用 `bpf_link__update_map` 更新。
- **实现/语义备注**：适合 TCP congestion control、调度器扩展等高级场景。
- **补充说明**：这是 libbpf map 抽象里最“像内核扩展注册表”的一种，不只是数据容器。
### 2.31 ARENA
- **类别**：特殊类
- **用途简述**：提供可 mmap 的 arena 内存池，支持 BPF 与用户态共享地址空间。
- **key/value 类型**：`key`/`value` 不是传统 KV 语义，重点在 arena address space。
- **常见标志**：`BPF_F_SEGV_ON_FAULT`、`BPF_F_NO_USER_CONV`，`map_extra` 还携带 mmap 基址。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_ARENA);` + `SEC(".maps")`。
- **内核态 helper**：BPF 侧通常与 kptr/arena pointer 语义一起使用，而不是普通 map elem helper。
- **用户态操作 API**：用户态重点是 `bpf_map_create` 后 `mmap()` map FD。
- **实现/语义备注**：这是非常新的能力，适合复杂共享内存结构。
- **补充说明**：ARENA 更接近“共享内存 allocator 后端”，而不是普通意义上的容器。
### 2.32 INSN_ARRAY
- **类别**：特殊类补充
- **用途简述**：存放 `struct bpf_insn_array_entry` 的指令数组。
- **key/value 类型**：`key` 常为 index；`value` 类型在 UAPI 头文件有专门定义。
- **常见标志**：属于 very new map type。
- **libbpf 声明方式**：`__uint(type, BPF_MAP_TYPE_INSN_ARRAY);` + `SEC(".maps")`。
- **内核态 helper**：BPF 侧语义取决于对应内核支持路径。
- **用户态操作 API**：用户态仍以 `bpf_map_create` 与通用 update/lookup 为入口。
- **实现/语义备注**：可把它看作对程序/指令元数据的新型容器。
### 2.31 类型对照总结
- **通用存储类**：面向 KV 或索引式存储，是绝大多数状态共享的基础。
- **队列/栈类**：面向生产/消费或容器语义，不强调 key。
- **程序控制类**：核心不是数据本身，而是控制程序跳转或组织 inner map。
- **网络类**：核心是 redirect、socket 选择或 packet steering。
- **存储类**：核心是“把状态挂到具体内核对象上”。
- **特殊类**：要么承担事件通道、堆栈采样、struct_ops 注册，要么承担 very new 内存/元数据能力。
---
## 3. libbpf Map API 大全（53 个核心接口 + 扩展接口）
### 3.1 53 个核心接口
1. `bpf_object__find_map_by_name` — **查找/遍历**；按名字拿 `struct bpf_map *`。
2. `bpf_object__find_map_fd_by_name` — **查找/遍历**；按名字直接取 map FD。
3. `bpf_object__next_map` — **查找/遍历**；正向遍历 object 内 map。
4. `bpf_object__prev_map` — **查找/遍历**；反向遍历 object 内 map。
5. `bpf_map__fd` — **属性获取/设置**；获取 map FD。
6. `bpf_map__name` — **属性获取/设置**；获取 map 名。
7. `bpf_map__type` — **属性获取/设置**；获取 map type。
8. `bpf_map__set_type` — **属性获取/设置**；设置 map type。
9. `bpf_map__max_entries` — **属性获取/设置**；读取最大项数。
10. `bpf_map__set_max_entries` — **属性获取/设置**；修改最大项数。
11. `bpf_map__map_flags` — **属性获取/设置**；读取 map_flags。
12. `bpf_map__set_map_flags` — **属性获取/设置**；修改 map_flags。
13. `bpf_map__numa_node` — **属性获取/设置**；读取 NUMA node。
14. `bpf_map__set_numa_node` — **属性获取/设置**；设置 NUMA node。
15. `bpf_map__key_size` — **属性获取/设置**；读取 key size。
16. `bpf_map__set_key_size` — **属性获取/设置**；设置 key size。
17. `bpf_map__value_size` — **属性获取/设置**；读取 value size。
18. `bpf_map__set_value_size` — **属性获取/设置**；设置 value size。
19. `bpf_map__btf_key_type_id` — **属性获取/设置**；读取 key BTF type id。
20. `bpf_map__btf_value_type_id` — **属性获取/设置**；读取 value BTF type id。
21. `bpf_map__ifindex` — **属性获取/设置**；读取 ifindex。
22. `bpf_map__set_ifindex` — **属性获取/设置**；设置 ifindex。
23. `bpf_map__map_extra` — **属性获取/设置**；读取 map_extra。
24. `bpf_map__set_map_extra` — **属性获取/设置**；设置 map_extra。
25. `bpf_map__set_autocreate` — **生命周期**；控制 load 时是否自动创建。
26. `bpf_map__autocreate` — **生命周期**；读取 autocreate 状态。
27. `bpf_map__set_pin_path` — **生命周期**；记录 pin path。
28. `bpf_map__pin_path` — **生命周期**；读取 pin path。
29. `bpf_map__is_pinned` — **生命周期**；判断是否 pinned。
30. `bpf_map__pin` — **生命周期**；执行 pin。
31. `bpf_map__unpin` — **生命周期**；执行 unpin。
32. `bpf_map__set_inner_map_fd` — **生命周期**；为 map-in-map 指定 inner map 模板 FD。
33. `bpf_map__lookup_elem` — **数据操作**；高层 lookup，带 size 校验。
34. `bpf_map__update_elem` — **数据操作**；高层 update，带 size 校验。
35. `bpf_map__delete_elem` — **数据操作**；高层 delete。
36. `bpf_map__lookup_and_delete_elem` — **数据操作**；高层原子取出并删除。
37. `bpf_map__get_next_key` — **数据操作**；高层遍历 key。
38. `bpf_map_create` — **底层 syscall**；包装 `BPF_MAP_CREATE`。
39. `bpf_map_lookup_elem` — **底层 syscall**；包装 `BPF_MAP_LOOKUP_ELEM`。
40. `bpf_map_lookup_elem_flags` — **底层 syscall**；lookup with flags。
41. `bpf_map_update_elem` — **底层 syscall**；包装 `BPF_MAP_UPDATE_ELEM`。
42. `bpf_map_delete_elem` — **底层 syscall**；包装 `BPF_MAP_DELETE_ELEM`。
43. `bpf_map_delete_elem_flags` — **底层 syscall**；delete with flags。
44. `bpf_map_lookup_and_delete_elem` — **底层 syscall**；包装 `LOOKUP_AND_DELETE`。
45. `bpf_map_lookup_and_delete_elem_flags` — **底层 syscall**；lookup-and-delete with flags。
46. `bpf_map_get_next_key` — **底层 syscall**；包装 `BPF_MAP_GET_NEXT_KEY`。
47. `bpf_map_freeze` — **底层 syscall**；包装 `BPF_MAP_FREEZE`。
48. `bpf_map_delete_batch` — **底层 syscall**；批量删除。
49. `bpf_map_lookup_batch` — **底层 syscall**；批量查询。
50. `bpf_map_lookup_and_delete_batch` — **底层 syscall**；批量查询并删除。
51. `bpf_map_update_batch` — **底层 syscall**；批量更新。
52. `bpf_map_get_next_id` — **底层 syscall**；遍历内核里所有 map id。
53. `bpf_map_get_fd_by_id` — **底层 syscall**；按 id 取 map FD。
### 3.2 扩展接口
- `bpf_map_get_fd_by_id_opts`
- `bpf_map_get_info_by_fd`
- `bpf_map__reuse_fd`
- `bpf_map__is_internal`
- `bpf_map__set_initial_value`
- `bpf_map__initial_value`
- `bpf_map__inner_map`
- `bpf_map__attach_struct_ops`
- `bpf_link__update_map`
- `bpf_map__set_autoattach`
- `bpf_map__autoattach`
- `bpf_map__set_exclusive_program`
- `bpf_map__exclusive_program`
### 3.3 如何理解这套 API 的分层
- 53 个核心接口里，最重要的是三组：
  - `bpf_object__*map*`：找 map、遍历 map；
  - `bpf_map__*`：基于高层对象做 metadata 与 CRUD；
  - `bpf_map_*`：直接包装内核 `bpf()` map 命令。
- 扩展接口则把 map 带向更复杂的 attach/初始化/ownership 语义。
---
## 4. BTF-Defined Maps 声明语法
### 4.1 基础模板

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct event);
} my_map SEC(".maps");
```

### 4.2 常用字段解释
- `type`：map 类型。
- `max_entries`：容量。
- `key` / `value`：BTF 类型。
- `map_flags`：创建标志。
- `inner_map_idx` / inner map 模板：map-in-map 才需要。
- `pinning`：某些 skeleton/workflow 会结合 pin path 使用。
### 4.3 HASH 示例

```c
struct event {
    __u64 ts;
    __u32 pid;
    char comm[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct event);
} events SEC(".maps");
```

### 4.4 PERCPU_ARRAY 示例

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} percpu_cnt SEC(".maps");
```

### 4.5 LPM_TRIE 示例

```c
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 addr;
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
} routes SEC(".maps");
```

### 4.6 RINGBUF 示例

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");
```

### 4.7 PROG_ARRAY 示例

```c
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} jumps SEC(".maps");
```

### 4.8 ARRAY_OF_MAPS 示例

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 16);
    __type(key, __u32);
    __array(values, int);
} outer SEC(".maps");
```

### 4.9 DEVMAP 示例

```c
struct devmap_val {
    __u32 ifindex;
    __u32 bpf_prog_fd;
};
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct devmap_val);
} tx_ports SEC(".maps");
```

### 4.10 SOCKHASH 示例

```c
struct sock_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u32 ports;
};
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, __u64);
} sock_hash SEC(".maps");
```

### 4.11 STRUCT_OPS 示例

```c
struct {
    __uint(type, BPF_MAP_TYPE_STRUCT_OPS);
    __uint(map_flags, BPF_F_LINK);
    __type(key, int);
    __type(value, struct tcp_congestion_ops);
} ca_ops SEC(".maps");
```

### 4.12 ARENA 示例

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(max_entries, 1 << 20);
    __uint(map_flags, BPF_F_SEGV_ON_FAULT);
    __type(key, __u32);
    __type(value, __u64);
} arena SEC(".maps");
```

### 4.13 声明语法的实践建议
- 优先使用 `SEC(".maps")`。
- 让 `key`/`value` 都有真实 BTF 类型，而不是只靠大小。
- 对 per-CPU map，要在用户态代码里同步考虑 CPU 数与 8 字节对齐。
- 对 map-in-map，先创建 inner map 模板，再把 FD 注入 outer map。
- 对 `STRUCT_OPS`、`ARENA`、`USER_RINGBUF` 这类高级 map，优先从仓库示例或 selftests 拓展。
---
## 5. Map 操作模式对比
| 操作 | 内核态 helper | 用户态 syscall | libbpf 高级 API |
|---|---|---|---|
| 查找 | `bpf_map_lookup_elem()` | `BPF_MAP_LOOKUP_ELEM` / `bpf_map_lookup_elem()` | `bpf_map__lookup_elem()` |
| 更新 | `bpf_map_update_elem()` | `BPF_MAP_UPDATE_ELEM` / `bpf_map_update_elem()` | `bpf_map__update_elem()` |
| 删除 | `bpf_map_delete_elem()` | `BPF_MAP_DELETE_ELEM` / `bpf_map_delete_elem()` | `bpf_map__delete_elem()` |
| 查找并删除 | `bpf_map_lookup_and_delete_elem()` | `BPF_MAP_LOOKUP_AND_DELETE_ELEM` | `bpf_map__lookup_and_delete_elem()` |
| 遍历 | `bpf_for_each_map_elem()` 或逐 key 逻辑 | `BPF_MAP_GET_NEXT_KEY` | `bpf_map__get_next_key()` |
| 批量查找 | 无统一 helper | `BPF_MAP_LOOKUP_BATCH` | 直接用 `bpf_map_lookup_batch()` |
| 批量更新 | 无统一 helper | `BPF_MAP_UPDATE_BATCH` | 直接用 `bpf_map_update_batch()` |
| 队列 push/pop | `bpf_map_push_elem()` 等 | 通用 elem 命令/取删组合 | 高层常直接走 low-level |
| ringbuf 输出 | `bpf_ringbuf_output()` | 不适用 | `ring_buffer__new()` / `poll()` 消费 |
| tail call | `bpf_tail_call()` | 更新 `PROG_ARRAY` 槽位 | 通常高层对象 + `bpf_map__fd()` 配合 |
| pin | 不适用 | `BPF_OBJ_PIN` / `bpf_obj_pin()` | `bpf_map__pin()` |
| map-in-map | 查 outer map 拿 inner 引用 | `inner_map_fd` / update outer entry | `bpf_map__set_inner_map_fd()` |
| struct_ops attach | 不适用 | link / map 相关命令组合 | `bpf_map__attach_struct_ops()` |
| XDP redirect | `bpf_redirect_map()` | 用户态维护 DEVMAP/CPUMAP | 高层 map API + attach API 组合 |
---
## 6. 常见使用场景
### 6.1 用户态 ↔ 内核态数据传递
- 最常见组合是：
  - 配置/状态放在 `HASH`、`ARRAY`、`PERCPU_ARRAY`；
  - 事件流放在 `RINGBUF` 或 `PERF_EVENT_ARRAY`。
- 一个典型模式是：
  - 用户态先写配置 map；
  - BPF 程序按 key 查配置；
  - 遇到事件时把 event 推到 ringbuf；
  - 用户态 poll ringbuf 并落盘/展示。
### 6.2 程序间共享数据
- 多个 BPF program 可以共享同一张 map。
- 多个进程也可以通过 pin 后的路径重新 `bpf_obj_get()` 获得同一张 map。
- 这是把 BPF 应用拆成 loader、controller、observer 多进程架构时最常见的做法。
### 6.3 Tail call
- `PROG_ARRAY` + `bpf_tail_call()` 可以把大程序拆成多个小程序。
- 优点是：
  - 每个子程序 verifier 压力更小；
  - 可以动态更新某个阶段对应的 program FD；
  - 便于做模块化 pipeline。
- 缺点是 tail call 预算有限，且失败时会继续执行当前程序。
### 6.4 XDP redirect
- `DEVMAP` / `DEVMAP_HASH` 用于把包导到网卡。
- `CPUMAP` 用于把包导到 CPU。
- `XSKMAP` 用于把包导到 AF_XDP socket。
- 这三种 map 共同构成 XDP 高性能数据面的核心路由设施。
### 6.5 Per-object local storage
- `SK_STORAGE`、`TASK_STORAGE`、`INODE_STORAGE`、`CGRP_STORAGE` 最大特点是 key 隐式绑定对象。
- 相比普通 hash：
  - 不需要自己维护对象 ID 到状态的映射；
  - 生命周期更自然；
  - 适合对象级缓存与状态机。
### 6.6 何时选 perf buffer，何时选 ringbuf
- 新应用优先选 `RINGBUF`。
- 需要兼容较老内核或已有 perf 基础设施时再用 `PERF_EVENT_ARRAY`。
- 如果需要用户态反向生产记录，则看 `USER_RINGBUF`。
### 6.7 何时需要 map-in-map
- 当数据天然分层，或者需要在运行期替换某一组 map 时，outer map + inner map 很有价值。
- 例如：
  - 按 tenant 保存独立统计表；
  - 按 CPU/NUMA 节点切换不同工作集；
  - 动态装载不同策略表。
### 6.8 何时需要 STRUCT_OPS / ARENA
- `STRUCT_OPS` 适合把 BPF 程序注册成某个内核子系统的 ops 实现。
- `ARENA` 适合需要复杂共享内存结构、指针语义、mmap 地址空间协同的高级应用。
- 这两者都不是“普通 KV 容器”，要把它们当成功能型基础设施。
---
## 7. 总结
- 从 `include/uapi/linux/bpf.h` 看，map type 已从最早的 HASH/ARRAY 扩展到 local storage、ringbuf、struct_ops、arena、insn_array。
- 从 `src/bpf.h` 看，libbpf 为 map 提供了接近内核命令全集的 syscall wrapper。
- 从 `src/libbpf.h` 看，libbpf 又在此之上叠加了高层 `struct bpf_map` 抽象。
- 读源码时最重要的心智模型是：
  - **类型** 决定语义；
  - **helper** 决定 BPF 程序里怎么用；
  - **syscall wrapper** 决定用户态怎么精细控制；
  - **高层 API** 决定日常工程里怎么把这些能力组合起来。
- 一旦把这四层关系理顺，libbpf 的 map 世界就会非常清晰。
