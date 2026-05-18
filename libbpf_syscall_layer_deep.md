# libbpf BPF Syscall 封装层深度分析

## 概述

`bpf.c` (1,419行) 是 libbpf 对 Linux `bpf()` 系统调用的封装层。它将内核的单一 `bpf(cmd, attr, size)` 接口拆分为类型安全、易用的 C 函数，同时处理了兼容性、重试和错误报告。

---

## 1. 底层基础设施

### 1.1 系统调用入口 (bpf.c:72-85)

```c
// 最底层：直接调用 bpf() 系统调用
static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

// 带 fd 安全检查的变体（确保 fd > 2，避免占用 stdin/stdout/stderr）
static inline int sys_bpf_fd(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    int fd = sys_bpf(cmd, attr, size);
    return ensure_good_fd(fd);  // 若 fd <= 2，dup 到更高编号
}
```

### 1.2 程序加载重试机制 (bpf.c:87-96)

```c
int sys_bpf_prog_load(union bpf_attr *attr, unsigned int size, int attempts)
{
    int fd;
    do {
        fd = sys_bpf_fd(BPF_PROG_LOAD, attr, size);
    } while (fd < 0 && errno == EAGAIN && --attempts > 0);
    return fd;
}
```

**设计要点**：
- `EAGAIN` 时自动重试（默认 `PROG_LOAD_ATTEMPTS = 5`）
- 内核在资源紧张时可能返回 EAGAIN

### 1.3 内存限制处理 (bpf.c:98-166)

```c
int probe_memcg_account(int token_fd)  // 探测内核是否支持 memcg 记账
int bump_rlimit_memlock(void)          // 提升 RLIMIT_MEMLOCK（旧内核需要）
```

**兼容策略**：
- Linux 5.11+ 使用 memcg 记账，不需要 RLIMIT_MEMLOCK
- 通过尝试加载使用 `bpf_ktime_get_coarse_ns` 的程序来探测
- 旧内核自动调用 `setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)`

---

## 2. attr 构造模式

所有 wrapper 函数遵循统一模式：

```c
int bpf_xxx(params..., const struct bpf_xxx_opts *opts)
{
    // 1. 确定 attr 大小（使用 offsetofend 确保前向兼容）
    const size_t attr_sz = offsetofend(union bpf_attr, last_field);
    union bpf_attr attr;

    // 2. 提升内存限制（仅 map/prog 创建需要）
    bump_rlimit_memlock();

    // 3. 校验 opts
    if (!OPTS_VALID(opts, bpf_xxx_opts))
        return libbpf_err(-EINVAL);

    // 4. 清零 attr 后填充
    memset(&attr, 0, attr_sz);
    attr.field1 = value1;
    attr.field2 = OPTS_GET(opts, field2, default_value);
    ...

    // 5. 调用系统调用
    fd = sys_bpf_fd(BPF_CMD, &attr, attr_sz);
    return libbpf_err_errno(fd);
}
```

**关键设计**：
- `offsetofend` 决定传给内核的 attr 大小，确保新字段被包含
- `memset(&attr, 0, attr_sz)` 确保未设置的字段为零（内核会忽略零值的新字段）
- `OPTS_GET(opts, field, default)` 安全获取可选参数

---

## 3. 函数分类详解

### 3.1 Map 操作 (bpf.c:168-583)

| 函数 | BPF 命令 | 行号 | 说明 |
|---|---|---|---|
| `bpf_map_create()` | BPF_MAP_CREATE | 168 | 创建 Map，返回 fd |
| `bpf_map_update_elem()` | BPF_MAP_UPDATE_ELEM | 390 | 更新元素 |
| `bpf_map_lookup_elem()` | BPF_MAP_LOOKUP_ELEM | 407 | 查找元素 |
| `bpf_map_lookup_elem_flags()` | BPF_MAP_LOOKUP_ELEM | 422 | 带 flags 查找 |
| `bpf_map_lookup_and_delete_elem()` | BPF_MAP_LOOKUP_AND_DELETE_ELEM | 438 | 原子查找并删除 |
| `bpf_map_delete_elem()` | BPF_MAP_DELETE_ELEM | 469 | 删除元素 |
| `bpf_map_get_next_key()` | BPF_MAP_GET_NEXT_KEY | 498 | 迭代 key |
| `bpf_map_freeze()` | BPF_MAP_FREEZE | 513 | 冻结 Map（只读） |
| `bpf_map_delete_batch()` | BPF_MAP_DELETE_BATCH | 554 | 批量删除 |
| `bpf_map_lookup_batch()` | BPF_MAP_LOOKUP_BATCH | 561 | 批量查找 |
| `bpf_map_update_batch()` | BPF_MAP_UPDATE_BATCH | 578 | 批量更新 |

**bpf_map_create() 详解** (bpf.c:168-211):
```c
int bpf_map_create(enum bpf_map_type map_type, const char *map_name,
                   __u32 key_size, __u32 value_size, __u32 max_entries,
                   const struct bpf_map_create_opts *opts)
```
- 支持字段: btf_fd, btf_key/value_type_id, inner_map_fd, map_flags, map_extra, numa_node, map_ifindex, token_fd, excl_prog_hash
- 若内核支持 FEAT_PROG_NAME，设置 map 名称

### 3.2 程序加载 (bpf.c:238-388)

**bpf_prog_load() 详解**:

```c
int bpf_prog_load(enum bpf_prog_type prog_type, const char *prog_name,
                  const char *license, const struct bpf_insn *insns,
                  size_t insn_cnt, struct bpf_prog_load_opts *opts)
```

**加载流程**:
1. 校验参数和 opts
2. 填充 attr：prog_type, license, insns, attach 信息, BTF 信息, log 配置
3. 首次尝试 `sys_bpf_prog_load()`（最多重试 attempts 次）
4. 若失败 E2BIG：可能是 func_info/line_info record size 不匹配
   - 用 `alloc_zero_tailing_info()` 重新对齐记录，再试
5. 若 log_level==0 但提供了 log_buf：设 log_level=1 重试以获取错误详情

**opts 支持的字段**:
- expected_attach_type, prog_btf_fd, prog_flags, prog_ifindex
- kern_version, token_fd, attach_btf_id, attach_prog_fd
- log_buf/log_size/log_level
- func_info/line_info + rec_size + cnt
- fd_array/fd_array_cnt

### 3.3 Object Pin/Get (bpf.c:585-630)

```c
int bpf_obj_pin_opts(int fd, const char *pathname, const struct bpf_obj_pin_opts *opts)
int bpf_obj_get_opts(const char *pathname, const struct bpf_obj_get_opts *opts)
```

- Pin: 将 fd (prog/map/link) 固定到 BPF 文件系统路径
- Get: 从 BPF 文件系统路径获取 fd
- 支持 path_fd (AT_FDCWD 风格) 和 file_flags

### 3.4 Program Attach/Detach (bpf.c:632-726)

```c
int bpf_prog_attach_opts(int prog_fd, int target, enum bpf_attach_type type,
                         const struct bpf_prog_attach_opts *opts)
int bpf_prog_detach_opts(int prog_fd, int target, enum bpf_attach_type type,
                         const struct bpf_prog_detach_opts *opts)
```

- 旧式 attach/detach（cgroup 等直接 attach 场景）
- 新式推荐使用 `bpf_link_create()`

### 3.5 Link 操作 (bpf.c:727-964)

**bpf_link_create() 详解** (bpf.c:727-925):

这是最复杂的 wrapper，根据 attach_type 填充不同的 union 字段：

| attach_type | 特定字段 |
|---|---|
| BPF_TRACE_ITER | iter_info, iter_info_len |
| BPF_PERF_EVENT | perf_event.bpf_cookie |
| BPF_TRACE_KPROBE_MULTI | kprobe_multi.{flags,cnt,syms,addrs,cookies} |
| BPF_TRACE_UPROBE_MULTI | uprobe_multi.{flags,cnt,path,offsets,ref_ctr_offsets,cookies,pid} |
| BPF_TRACE_RAW_TP/FENTRY/FEXIT/LSM | tracing.cookie |
| BPF_NETFILTER | netfilter.{pf,hooknum,priority,flags} |
| BPF_TCX_INGRESS/EGRESS | tcx.{relative_fd/id,expected_revision} |
| BPF_NETKIT_PRIMARY/PEER | netkit.{relative_fd/id,expected_revision} |
| BPF_CGROUP_* (30+种) | cgroup.{relative_fd/id,expected_revision} |

**回退机制**: 若 BPF_LINK_CREATE 返回 EINVAL 且是 fentry/fexit/lsm/raw_tp 类型，回退到 `bpf_raw_tracepoint_open()` 兼容旧内核。

### 3.6 信息查询 (bpf.c:1078-1228)

| 函数 | 说明 |
|---|---|
| `bpf_prog_get_next_id()` | 遍历所有 prog ID |
| `bpf_map_get_next_id()` | 遍历所有 map ID |
| `bpf_btf_get_next_id()` | 遍历所有 BTF ID |
| `bpf_link_get_next_id()` | 遍历所有 link ID |
| `bpf_prog_get_fd_by_id()` | ID → fd |
| `bpf_map_get_fd_by_id()` | ID → fd |
| `bpf_obj_get_info_by_fd()` | fd → info 结构体 |

所有 `_opts` 变体支持 `token_fd` 用于权限委托。

### 3.7 其它操作 (bpf.c:966-1419)

| 函数 | BPF 命令 | 说明 |
|---|---|---|
| `bpf_iter_create()` | BPF_ITER_CREATE | 创建 BPF 迭代器 |
| `bpf_prog_query_opts()` | BPF_PROG_QUERY | 查询 attach 的程序列表 |
| `bpf_prog_test_run_opts()` | BPF_PROG_TEST_RUN | 测试运行 BPF 程序 |
| `bpf_raw_tracepoint_open()` | BPF_RAW_TRACEPOINT_OPEN | 打开 raw tracepoint |
| `bpf_btf_load()` | BPF_BTF_LOAD | 加载 BTF 到内核 |
| `bpf_enable_stats()` | BPF_ENABLE_STATS | 启用 BPF 统计 |
| `bpf_task_fd_query()` | BPF_TASK_FD_QUERY | 查询任务 fd 对应的 BPF 信息 |
| `bpf_prog_bind_map()` | BPF_PROG_BIND_MAP | 绑定 map 到 prog |
| `bpf_token_create()` | BPF_TOKEN_CREATE | 创建 BPF token |

---

## 4. 错误处理机制

### 4.1 三层错误处理

```
sys_bpf() 返回:
  成功: fd >= 0 或 ret == 0
  失败: -1, errno 被设置

libbpf 内部包装:
  libbpf_err_errno(fd)  — 若 fd < 0，返回 -errno
  libbpf_err(-EINVAL)   — 直接返回负错误码

用户看到:
  成功: fd >= 0 或 0
  失败: 负错误码 (-EINVAL, -ENOMEM, etc.)，errno 也被设置
```

### 4.2 ensure_good_fd() 机制

```c
// 确保返回的 fd > 2（避免占用 stdin/stdout/stderr）
// 若 fd 是 0/1/2，执行 dup3() 到更高编号后 close 原 fd
int ensure_good_fd(int fd);
```

---

## 5. 前向兼容设计

### 5.1 attr 大小截断

```c
const size_t attr_sz = offsetofend(union bpf_attr, last_known_field);
```

- 只传递到最后一个已知字段的大小
- 新内核可以接受更大的 attr（多余部分需为零）
- 旧内核忽略不认识的尾部字段

### 5.2 OPTS_VALID / OPTS_GET 宏

```c
// 检查 opts 结构体有效性（sz 字段正确）
OPTS_VALID(opts, type_name)

// 安全获取 opts 字段，不存在时返回默认值
OPTS_GET(opts, field_name, default_value)

// 检查从某字段到末尾是否全为零（检测使用了未知字段）
OPTS_ZEROED(opts, last_field)
```

---

## 6. 与内核 syscall.c 的对应关系

| libbpf bpf.c | kernel/bpf/syscall.c |
|---|---|
| `sys_bpf(BPF_PROG_LOAD, ...)` | `bpf_prog_load()` → verifier → JIT |
| `sys_bpf(BPF_MAP_CREATE, ...)` | `map_create()` → 分配 map 对象 |
| `sys_bpf(BPF_MAP_LOOKUP_ELEM, ...)` | `map_lookup_elem()` → map->ops->map_lookup_elem() |
| `sys_bpf(BPF_LINK_CREATE, ...)` | `link_create()` → 根据 attach_type 分发 |
| `sys_bpf(BPF_BTF_LOAD, ...)` | `btf_load()` → BTF 验证 |
| `sys_bpf(BPF_OBJ_PIN, ...)` | `bpf_obj_pin_user()` → BPF fs 操作 |

**关联内核知识库**:
- `ebpf_prog_loading_full_flow.md` — 内核加载全流程
- `ebpf_helper_kfunc_mechanism_deep.md` — helper/kfunc 机制
- `ebpf_map_deep_analysis.md` — Map 内核实现

---

## 7. 设计总结

| 设计决策 | 实现方式 | 原因 |
|---|---|---|
| 单系统调用 → 多函数 | 每个 BPF cmd 对应一个 C 函数 | 类型安全，文档化 |
| 前向兼容 | offsetofend + memset 0 | 新旧内核/libbpf 互操作 |
| 可扩展参数 | opts struct + sz | 添加字段无需破坏 ABI |
| fd 安全 | ensure_good_fd() | 避免 fd 0/1/2 冲突 |
| 重试机制 | EAGAIN 自动重试 | 内核资源临时不足 |
| 内存限制 | 自动探测 + 提升 | 兼容 memlock/memcg 两种模式 |
| 错误报告 | -errno 返回 + errno 设置 | 统一错误处理模式 |
| 旧内核回退 | link_create → raw_tracepoint_open | 兼容不支持 link 的旧内核 |
