# libbpf 与 Linux 内核实现交叉引用

## 概述

本文档建立 libbpf 用户态代码与 Linux 内核 BPF 子系统之间的对应关系，
帮助在分析 libbpf 时快速定位内核端对应实现，反之亦然。

内核源码位置: `/home/nio/sda/source/Linux/linux`
内核知识库: `/home/nio/sda/source/Linux/linux/darren/bpf/`

---

## 1. 系统调用层对应

### 1.1 bpf() 系统调用入口

| libbpf (bpf.c) | 内核 (kernel/bpf/syscall.c) |
|---|---|
| `sys_bpf(cmd, attr, size)` | `SYSCALL_DEFINE3(bpf, int cmd, union bpf_attr __user *, uattr, unsigned int, size)` |
| → `__sys_bpf()` 分发到各 cmd handler |

### 1.2 命令对应表

| libbpf 函数 | BPF cmd | 内核处理函数 | 内核源文件 |
|---|---|---|---|
| `bpf_prog_load()` | BPF_PROG_LOAD | `bpf_prog_load()` | kernel/bpf/syscall.c |
| `bpf_map_create()` | BPF_MAP_CREATE | `map_create()` | kernel/bpf/syscall.c |
| `bpf_map_lookup_elem()` | BPF_MAP_LOOKUP_ELEM | `map_lookup_elem()` | kernel/bpf/syscall.c |
| `bpf_map_update_elem()` | BPF_MAP_UPDATE_ELEM | `map_update_elem()` | kernel/bpf/syscall.c |
| `bpf_map_delete_elem()` | BPF_MAP_DELETE_ELEM | `map_delete_elem()` | kernel/bpf/syscall.c |
| `bpf_obj_pin()` | BPF_OBJ_PIN | `bpf_obj_pin_user()` | kernel/bpf/inode.c |
| `bpf_obj_get()` | BPF_OBJ_GET | `bpf_obj_get_user()` | kernel/bpf/inode.c |
| `bpf_link_create()` | BPF_LINK_CREATE | `link_create()` | kernel/bpf/syscall.c |
| `bpf_btf_load()` | BPF_BTF_LOAD | `bpf_btf_load()` | kernel/bpf/btf.c |
| `bpf_prog_test_run_opts()` | BPF_PROG_TEST_RUN | `bpf_prog_test_run()` | net/bpf/test_run.c |
| `bpf_raw_tracepoint_open()` | BPF_RAW_TRACEPOINT_OPEN | `bpf_raw_tracepoint_open()` | kernel/bpf/syscall.c |
| `bpf_iter_create()` | BPF_ITER_CREATE | `bpf_iter_create()` | kernel/bpf/bpf_iter.c |

---

## 2. 程序加载流程对应

### 2.1 libbpf 用户态 → 内核态

```
[libbpf 用户态]                         [内核态]
                                        
bpf_object__open()                      (无内核交互)
  ├─ ELF 解析                           
  ├─ BTF 解析                           
  └─ 重定位信息收集                      
                                        
bpf_object__load()                      
  ├─ btf_load() ──────────────────────→ bpf_btf_load()
  │                                       → btf_parse() → btf_check_all_types()
  ├─ bpf_map_create() ────────────────→ map_create()
  │                                       → find_and_alloc_map() → map->ops->map_alloc()
  ├─ CO-RE 重定位 (纯用户态)            
  ├─ bpf_prog_load() ─────────────────→ bpf_prog_load()
  │                                       → bpf_check() [verifier]
  │                                       → bpf_prog_select_runtime() [JIT]
  └─ bpf_link_create() ───────────────→ link_create()
                                           → 根据 attach_type 分发
```

### 2.2 内核程序加载详细路径

```
bpf_prog_load() [kernel/bpf/syscall.c]
  ├── bpf_prog_alloc()              — 分配 bpf_prog 结构
  ├── copy_from_user(insns)         — 拷贝指令到内核
  ├── bpf_prog_load_check_attach()  — 检查 attach 参数
  ├── bpf_check() [verifier]        — 验证器核心
  │     ├── check_cfg()             — 控制流图检查
  │     ├── do_check()              — 逐指令验证
  │     │     ├── 寄存器状态追踪
  │     │     ├── 边界检查
  │     │     └── helper 调用校验
  │     └── check_max_stack_depth() — 栈深度检查
  ├── bpf_prog_select_runtime()     — JIT 编译
  │     └── bpf_int_jit_compile()   — 架构相关 JIT
  └── bpf_prog_new_fd()            — 关联到文件描述符
```

**关联知识库**:
- `ebpf_prog_loading_full_flow.md` — 完整内核加载流程
- `ebpf_verifier_jit_deep.md` — 验证器与 JIT 全景
- `ebpf_verifier_register_tracking_deep.md` — 寄存器追踪
- `ebpf_verifier_state_pruning_deep.md` — 状态裁剪优化

---

## 3. BTF 对应关系

### 3.1 用户态 BTF 处理 vs 内核 BTF 验证

| libbpf (btf.c) | 内核 (kernel/bpf/btf.c) |
|---|---|
| `btf__parse_elf()` — 从 ELF 解析 | `btf_parse()` — 验证用户上传的 BTF |
| `btf__dedup()` — 类型去重 | (无对应，去重在用户态完成) |
| `btf__load_into_kernel()` | `bpf_btf_load()` → `btf_parse()` |
| `btf__load_vmlinux_btf()` — 读取 /sys/kernel/btf/vmlinux | 内核导出 vmlinux BTF |
| `btf_dump__dump_type()` | (无对应，dump 是用户态功能) |

### 3.2 CO-RE 重定位对应

| libbpf (relo_core.c) | 内核 |
|---|---|
| 读取内核 BTF (`/sys/kernel/btf/vmlinux`) | 内核生成并导出 BTF |
| 类型匹配 (`bpf_core_match_member()`) | (纯用户态算法) |
| 指令修补 | (加载前完成，内核看到的是已修补指令) |
| `bpf_core_field_exists` 编译标记 | verifier 看到的是常量 0/1 |

**关键**: CO-RE 重定位完全在用户态完成，内核 verifier 看到的是已经修补好的指令。

**关联知识库**: `ebpf_btf_core_deep.md`

---

## 4. Map 对应关系

### 4.1 创建与操作

| libbpf 操作 | 内核实现 | 内核源文件 |
|---|---|---|
| `bpf_map_create(BPF_MAP_TYPE_HASH, ...)` | `htab_map_alloc()` | kernel/bpf/hashtab.c |
| `bpf_map_create(BPF_MAP_TYPE_ARRAY, ...)` | `array_map_alloc()` | kernel/bpf/arraymap.c |
| `bpf_map_create(BPF_MAP_TYPE_RINGBUF, ...)` | `ringbuf_map_alloc()` | kernel/bpf/ringbuf.c |
| `bpf_map_create(BPF_MAP_TYPE_PERF_EVENT_ARRAY, ...)` | `perf_event_array_map_alloc()` | kernel/bpf/arraymap.c |
| `bpf_map_create(BPF_MAP_TYPE_LRU_HASH, ...)` | `htab_map_alloc()` | kernel/bpf/hashtab.c |
| `bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, ...)` | `prog_array_map_alloc()` | kernel/bpf/arraymap.c |

### 4.2 Ring Buffer 用户态/内核态交互

```
[libbpf ringbuf.c]                    [kernel/bpf/ringbuf.c]

ring_buffer__new()                    
  └─ mmap() ─────────────────────────→ ringbuf_map_mmap_kern/user()
     ├─ producer page (内核写)                           
     └─ data pages (共享)                                

ring_buffer__poll()                   BPF 程序端:
  └─ 读 consumer_pos                  bpf_ringbuf_reserve()
     └─ 处理 records                    → bpf_ringbuf_submit()
        └─ 更新 consumer_pos              → 更新 producer_pos
```

**关联知识库**: 
- `ebpf_map_deep_analysis.md` — Map 类型全景
- `ebpf_map_impl_comparison_deep.md` — 实现对比
- `ebpf_perf_ringbuf_userspace_deep.md` — perf/ringbuf 用户态交互

---

## 5. 程序 Attach 对应关系

### 5.1 各种 Attach 方式

| libbpf attach 函数 | 内核机制 | 内核源文件 |
|---|---|---|
| `bpf_program__attach_kprobe()` | kprobe + perf_event | kernel/trace/trace_kprobe.c |
| `bpf_program__attach_tracepoint()` | tracepoint + perf_event | kernel/trace/trace_events.c |
| `bpf_program__attach_raw_tracepoint()` | raw_tracepoint | kernel/bpf/syscall.c |
| `bpf_program__attach_xdp()` | netlink → dev_xdp_install() | net/core/dev.c |
| `bpf_program__attach_cgroup()` | BPF_LINK_CREATE + cgroup | kernel/bpf/cgroup.c |
| `bpf_program__attach_lsm()` | BPF trampoline | kernel/bpf/trampoline.c |
| `bpf_program__attach_trace()` | fentry/fexit trampoline | kernel/bpf/trampoline.c |
| `bpf_program__attach_freplace()` | extension prog | kernel/bpf/trampoline.c |
| `bpf_program__attach_usdt()` | uprobe | kernel/trace/trace_uprobe.c |
| `bpf_program__attach_netfilter()` | BPF_LINK_CREATE + netfilter | net/netfilter/nf_bpf_link.c |

### 5.2 XDP Attach 详细对应

```
[libbpf netlink.c]                    [内核]

bpf_xdp_attach()                     
  └─ netlink RTM_SETLINK              → rtnl_setlink()
     └─ IFLA_XDP                        → dev_change_xdp_fd()
        ├─ XDP_FLAGS_DRV_MODE             → dev_xdp_install() [native]
        ├─ XDP_FLAGS_SKB_MODE             → generic_xdp_install() [generic]
        └─ XDP_FLAGS_HW_MODE             → offload [NIC firmware]
```

**关联知识库**:
- `ebpf_xdp_native_generic_deep.md` — XDP 实现
- `ebpf_networking_datapath_deep.md` — 网络数据路径
- `ebpf_trampoline_struct_ops_deep.md` — trampoline 机制

---

## 6. Verifier 相关

libbpf 本身不包含 verifier，但与之密切交互：

| libbpf 行为 | 与 verifier 的关系 |
|---|---|
| 设置 `log_buf/log_level` | verifier 输出日志到此 buffer |
| BTF func_info/line_info | verifier 用于更好的错误消息 |
| CO-RE 重定位 | 消除 verifier 看到的"未知偏移" |
| Map fd 重定位 | 让 verifier 知道 map 类型信息 |
| `BPF_F_TEST_STATE_FREQ` | 控制 verifier 状态频率 |

**关联知识库**:
- `ebpf_verifier_jit_deep.md`
- `ebpf_verifier_register_tracking_deep.md`
- `ebpf_verifier_state_pruning_deep.md`

---

## 7. JIT 编译

| 阶段 | 位置 | 说明 |
|---|---|---|
| libbpf 提交 BPF 字节码 | 用户态 | 通过 bpf_prog_load |
| verifier 验证通过 | 内核 | bpf_check() |
| JIT 编译 | 内核 | bpf_prog_select_runtime() |
| 运行原生机器码 | 内核 | 直接执行 JIT 产物 |

**关联知识库**: `ebpf_jit_compilation_deep.md`

---

## 8. 特殊机制对应

### 8.1 Tail Call / BPF-to-BPF

| 概念 | libbpf | 内核 |
|---|---|---|
| Tail call | PROG_ARRAY map + `bpf_tail_call()` helper | `__bpf_prog_run()` 中的 tail_call 处理 |
| BPF-to-BPF 调用 | 子程序重定位 (libbpf.c) | verifier 展开 + JIT patch |

**关联知识库**: `ebpf_tailcall_bpf2bpf_deep.md`

### 8.2 Struct Ops

| 概念 | libbpf | 内核 |
|---|---|---|
| 定义 | `.struct_ops` section + BTF | `struct bpf_struct_ops` 注册 |
| 注册 | `bpf_map__attach_struct_ops()` | BPF_MAP_TYPE_STRUCT_OPS map update |

**关联知识库**: `ebpf_struct_ops_iter_deep.md`, `ebpf_trampoline_struct_ops_deep.md`

### 8.3 LSM / Security

| 概念 | libbpf | 内核 |
|---|---|---|
| LSM hook | `SEC("lsm/hook_name")` | BPF LSM trampoline |
| cgroup attach | `bpf_program__attach_cgroup()` | kernel/bpf/cgroup.c |

**关联知识库**: `ebpf_cgroup_lsm_security_deep.md`

### 8.4 Sockmap

| 概念 | libbpf | 内核 |
|---|---|---|
| Sockmap | BPF_MAP_TYPE_SOCKMAP/SOCKHASH | net/core/sock_map.c |
| SK_MSG 程序 | `SEC("sk_msg")` | net/core/skmsg.c |

**关联知识库**: `ebpf_sockmap_sk_msg_deep.md`

---

## 9. 文件系统接口

| 接口 | libbpf 使用 | 说明 |
|---|---|---|
| `/sys/kernel/btf/vmlinux` | `btf__load_vmlinux_btf()` | 内核导出的 vmlinux BTF |
| `/sys/kernel/btf/<module>` | `btf__load_module_btf()` | 内核模块 BTF |
| `/sys/fs/bpf/` | `bpf_obj_pin/get()` | BPF 文件系统 (pinning) |
| `/proc/kallsyms` | USDT/kprobe 地址解析 | 内核符号表 |
| `/sys/bus/event_source/devices/` | perf_event attach | perf 子系统 |

---

## 10. 调试与观测对应

| 用户态工具 | 内核接口 | 用途 |
|---|---|---|
| `bpftool prog show` | BPF_OBJ_GET_INFO_BY_FD | 查看加载的程序 |
| `bpftool map dump` | BPF_MAP_LOOKUP_BATCH | 导出 map 内容 |
| `bpftool btf dump` | BPF_OBJ_GET_INFO_BY_FD + BTF data | 查看 BTF |
| `strace -e bpf` | sys_bpf() 入口 | 跟踪 BPF syscall |
| ftrace `bpf_*` | 内核函数 | 跟踪内核 BPF 执行 |

---

## 11. 版本兼容策略总结

| 场景 | libbpf 策略 | 内核行为 |
|---|---|---|
| 新 libbpf + 旧内核 | 探测特性 → 降级/跳过 | 未知字段返回 EINVAL |
| 旧 libbpf + 新内核 | attr 尾部为零 | 内核忽略零值新字段 |
| CO-RE 跨版本 | BTF 匹配 + 指令修补 | 内核不感知 CO-RE |
| Map 降级 | sanitize_maps() 替换不支持的类型 | 返回 EINVAL 触发降级 |
| Link 不支持 | 回退到 raw_tracepoint_open | 旧内核无 BPF_LINK_CREATE |
