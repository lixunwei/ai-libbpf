# libbpf Attach 机制深度分析

## 0. 分析范围
- 主文件：`src/libbpf.c`；重点源码范围：`libbpf.c:9965-13735`；补充结构：`src/libbpf_internal.h:191-197`；补充 syscall 封装：`src/bpf.c`；补充网络侧 attach：`src/netlink.c`
> 本文聚焦“libbpf 如何把一个已经 load 的 BPF program 连接到内核 hook”。
>
> 其中最核心的观察是：
>
> 1. **generic attach 路径** 由 `bpf_program__attach()` 驱动；
> 2. **program-specific attach 路径** 由 `section_defs[]` 中的 `prog_attach_fn` 决定；
> 3. **target-specific attach 路径**（如 XDP/cgroup/tcx/netkit/struct_ops）往往不能只靠 `SEC()` 自动推导，还需要用户在运行时提供 `ifindex`、`cgroup_fd`、`map_fd` 等目标，因此通常走显式 API，而不是 `bpf_program__attach()`。
---

## 1. 概述：attach 在 libbpf 中的角色
在 libbpf 中，`load` 解决的是“把字节码和 map 送进内核并通过 verifier”； `attach` 解决的是“把已经 load 的 program 接到某个执行点上”。 从职责划分看，attach 机制有四层：
1. **SEC() 到 program 类型/attach 类型的静态映射**； 2. **用户态 attach helper 的路由与参数解析**； 3. **具体 attach backend 的执行**，例如：
- `perf_event_open + ioctl(PERF_EVENT_IOC_SET_BPF)`；`bpf_link_create(BPF_PERF_EVENT/BPF_TRACE_FENTRY/...)`；`bpf_raw_tracepoint_open`；`RTM_SETLINK + IFLA_XDP`；`bpf_map_update_elem`；
4. **`bpf_link` 生命周期管理**，保证 attach 结果可 pin、可 update、可 detach、可 destroy。
因此，attach 不是单一 syscall，而是一整套“从 section metadata 到 kernel hook object”的连接框架。 在当前源码里，attach 的入口并不只有一个：
- **通用入口**：`bpf_program__attach()`（`libbpf.c:13596-13623`）；**显式入口**：`bpf_program__attach_kprobe_opts()`；`bpf_program__attach_uprobe_opts()`；`bpf_program__attach_tracepoint_opts()`；`bpf_program__attach_xdp()`；`bpf_program__attach_cgroup()` / `_opts()`；`bpf_program__attach_tcx()`；`bpf_program__attach_netkit()`；`bpf_program__attach_iter()`；`bpf_map__attach_struct_ops()`。
一个重要结论是： **`bpf_program__attach()` 只覆盖 section table 中显式绑定了 `prog_attach_fn` 的那部分 program。** 也就是说，generic attach 很强，但并不包打天下。 ---

## 2. 核心数据结构

## 2.1 `struct bpf_link`：attach 结果的统一抽象
定义位于 `src/libbpf_internal.h:191-197`：

```c
struct bpf_link {
    int (*detach)(struct bpf_link *link);
    void (*dealloc)(struct bpf_link *link);
    char *pin_path;     /* NULL, if not pinned */
    int fd;             /* hook FD, -1 if not applicable */
    bool disconnected;
};

```
这个结构是 libbpf attach 框架的中心。 字段语义如下：
- `detach`：类型特定的 detach 回调；perf_event 链接、普通 link fd、struct_ops link 的 detach 方式都不同；`dealloc`：类型特定的析构函数；例如 `bpf_link_perf` 需要释放 `legacy_probe_name`；`pin_path`：若调用 `bpf_link__pin()` 成功，会记录 bpffs 路径；`fd`：对于大多数 link，就是内核 link fd；对于旧式 perf/ioctl attach，可能就是 perf event fd；对于无“真实 link fd”的旧式 struct_ops，`fd` 甚至直接是 map fd；`disconnected`：标记用户态对象是否“放弃对内核资源的所有权”；设为 `true` 后，`destroy` 不再自动 detach。

### 2.1.1 `bpf_link` 为什么重要
它解决了 attach API 最容易失控的三个问题：
1. **不同 attach backend 的返回物统一**； 2. **销毁逻辑统一**； 3. **pin/update/disconnect 语义统一**。
换句话说，libbpf 把“attach 成功后留下的句柄”标准化成了 `bpf_link`。

### 2.1.2 `bpf_link` 的三种典型物理形态

#### 形态 A：真实 BPF link fd
典型于：
- fentry/fexit/fmod_ret/lsm/iter；cgroup；xdp（`bpf_program__attach_xdp()` 的 link 路径）；tcx；netkit；kprobe/uprobe 的 PERF_LINK 模式；kprobe_multi/uprobe_multi；struct_ops with `BPF_F_LINK`。
此时：
- `link->fd` 是 `BPF_LINK_CREATE` 返回的 fd；detach 往往就是 `close(link->fd)` 或 `bpf_link_detach(link->fd)`。

#### 形态 B：perf event fd
典型于：
- kprobe/uprobe/tracepoint 的旧式 perf attach；`bpf_program__attach_perf_event_opts()` 的 ioctl fallback。
此时：
- `link->fd` 可能等于 perf event fd；或者 `link->fd` 是 link fd，而 `perf_event_fd` 保存在扩展结构中；detach 需要先 `PERF_EVENT_IOC_DISABLE`，再关 fd，必要时还要清理 legacy tracefs event。

#### 形态 C：伪 link / map-backed link
典型于旧式 struct_ops：
- 没有单独内核 link fd；attach 通过 `bpf_map_update_elem()` 激活 struct_ops；`link->fd` 直接保存 map fd；detach 时通过 `bpf_map_delete_elem(map_fd, &zero)` 撤销。
---

## 2.2 `struct bpf_sec_def`：SEC() 元信息描述符
定义位于 `libbpf.c:424-434`：

```c
struct bpf_sec_def {
    char *sec;
    enum bpf_prog_type prog_type;
    enum bpf_attach_type expected_attach_type;
    long cookie;
    int handler_id;

    libbpf_prog_setup_fn_t prog_setup_fn;
    libbpf_prog_prepare_load_fn_t prog_prepare_load_fn;
    libbpf_prog_attach_fn_t prog_attach_fn;
};

```
这个结构把 section 名称和 attach 语义绑定起来。 各字段含义：
- `sec`：SEC 前缀，例如 `"kprobe+"`、`"fentry+"`；`prog_type`：BPF 程序类型；`expected_attach_type`：内核 verifier 和 attach path 需要的 attach type；`cookie`：libbpf 私有附加参数；`prog_setup_fn` / `prog_prepare_load_fn`：load 前阶段使用；`prog_attach_fn`：真正的 attach 分发点。

### 2.2.1 `sec_def` 在 attach 中的价值
`sec_def` 把 attach 问题拆成两个阶段：
1. **静态阶段**：读 ELF 时，根据 `SEC()` 找到 `sec_def`； 2. **动态阶段**：attach 时执行 `sec_def->prog_attach_fn()`。
因此，libbpf attach 不是一堆 `if (strcmp(sec_name, ...))` 的硬编码链条； 它实际上是一个“**表驱动分发器**”。 ---

## 2.3 `section_defs[]`：attach 能力目录
`section_defs[]` 定义位于 `libbpf.c:9978-10084`。 这是 attach 机制最重要的静态表。 它做三件事：
1. 把 `SEC()` 名称映射到 `prog_type`； 2. 把 `SEC()` 名称映射到 `expected_attach_type`； 3. 对于支持 generic auto-attach 的 section，指定 `prog_attach_fn`。
典型条目：

```c
SEC_DEF("kprobe+",      KPROBE, 0, SEC_NONE, attach_kprobe),
SEC_DEF("uprobe+",      KPROBE, 0, SEC_NONE, attach_uprobe),
SEC_DEF("tracepoint+",  TRACEPOINT, 0, SEC_NONE, attach_tp),
SEC_DEF("fentry+",      TRACING, BPF_TRACE_FENTRY, SEC_ATTACH_BTF, attach_trace),
SEC_DEF("fexit+",       TRACING, BPF_TRACE_FEXIT, SEC_ATTACH_BTF, attach_trace),
SEC_DEF("lsm+",         LSM, BPF_LSM_MAC, SEC_ATTACH_BTF, attach_lsm),
SEC_DEF("iter+",        TRACING, BPF_TRACE_ITER, SEC_ATTACH_BTF, attach_iter),
SEC_DEF("xdp",          XDP, BPF_XDP, SEC_ATTACHABLE_OPT),
SEC_DEF("cgroup_skb/egress", CGROUP_SKB, BPF_CGROUP_INET_EGRESS, SEC_ATTACHABLE_OPT),
SEC_DEF("struct_ops+",  STRUCT_OPS, 0, SEC_NONE),

```

### 2.3.1 表中最值得注意的现象

#### 现象 A：并不是所有 attachable 类型都有 `prog_attach_fn`
例如：
- `xdp`；`cgroup_*`；`sockops`；`sk_msg`；`flow_dissector`；`cgroup/dev`；`struct_ops+`。
这些条目通常只有 `prog_type` 和 `expected_attach_type`，却没有 attach 函数。 原因不是“不支持 attach”，而是： **attach 目标在运行时才知道，无法仅靠 SEC() 决定。** 例如：
- XDP 需要 `ifindex`；cgroup attach 需要 `cgroup_fd`；struct_ops attach 需要 `map_fd`；tcx/netkit 需要 `ifindex` 以及可能的 insertion 参数。

#### 现象 B：`+` 后缀代表“允许更具体的 section 名称”
例如：
- `kprobe+` 匹配 `SEC("kprobe/do_sys_open")`；`tracepoint+` 匹配 `SEC("tracepoint/syscalls/sys_enter_openat")`；`fentry+` 匹配 `SEC("fentry/do_unlinkat")`。
这使 section string 自身就能编码 attach 目标。

#### 现象 C：BTF attach 类型集中复用 `attach_trace`
`tp_btf+`、`fentry+`、`fmod_ret+`、`fexit+`、`freplace+` 都指向 `attach_trace`。 这说明： **libbpf 把 BTF/trampoline 家族抽象成统一 backend。** ---

## 3. attach 分发机制

## 3.1 `bpf_program__attach()`：通用入口
源码位于 `libbpf.c:13596-13623`：

```c
struct bpf_link *bpf_program__attach(const struct bpf_program *prog)
{
    struct bpf_link *link = NULL;
    int err;

    if (!prog->sec_def || !prog->sec_def->prog_attach_fn)
        return libbpf_err_ptr(-EOPNOTSUPP);

    if (bpf_program__fd(prog) < 0)
        return libbpf_err_ptr(-EINVAL);

    err = prog->sec_def->prog_attach_fn(prog, prog->sec_def->cookie, &link);
    if (err)
        return libbpf_err_ptr(err);

    if (!link)
        return libbpf_err_ptr(-EOPNOTSUPP);

    return link;
}

```

### 3.1.1 这个入口只做四件事
1. 校验 `sec_def` 是否存在； 2. 校验该 `sec_def` 是否注册了 `prog_attach_fn`； 3. 校验 program 已经 load，拥有 fd； 4. 调用 `prog_attach_fn(prog, cookie, &link)`。
所以，`bpf_program__attach()` 自身并不懂 kprobe、uprobe、tracepoint、LSM。 它只负责**路由**。

### 3.1.2 `cookie` 的作用
调用时会把 `prog->sec_def->cookie` 传给 attach 函数。 在当前 attach 实现里，大多数 `attach_xxx()` 并不真正消费这个 `cookie`； 但这个设计允许 section handler 在不改函数签名的情况下扩展行为。

### 3.1.3 为什么有些 `SEC()` 明明 attachable，却不能走这个入口
因为 `bpf_program__attach()` 依赖 `prog_attach_fn`。 而 `xdp` / `cgroup` / `tcx` / `netkit` / `struct_ops` 在 `section_defs[]` 中没有 attach 函数。 因此：
- `SEC("xdp")` 能正确设置 program type 和 expected attach type；但 `bpf_program__attach(prog)` 仍会返回 `-EOPNOTSUPP`；必须改用 `bpf_program__attach_xdp(prog, ifindex)` 之类的显式 API。
---

## 3.2 12 个 `attach_xxx()`：generic attach 的真正实现者
在 `libbpf.c:9965-9976` 先声明，随后在 `12271-13550` 实现。 一共有 12 个：
1. `attach_kprobe` 2. `attach_ksyscall` 3. `attach_kprobe_multi` 4. `attach_kprobe_session` 5. `attach_uprobe_multi` 6. `attach_uprobe` 7. `attach_usdt` 8. `attach_tp` 9. `attach_raw_tp` 10. `attach_trace` 11. `attach_lsm` 12. `attach_iter`
这些函数的共同风格是：
- 先根据 `prog->sec_name` 解析目标；再调用对应显式 helper；最后把 `struct bpf_link *` 返回给 generic attach 调度器。

### 3.2.1 这些函数的职责边界
它们通常只负责：
- section string 解析；auto-attach 可行性判断；参数转换。
真正的 attach backend 常常在更底层的 helper 中：
- `bpf_program__attach_kprobe_opts()`；`bpf_program__attach_uprobe_opts()`；`bpf_program__attach_perf_event_opts()`；`bpf_program__attach_btf_id()`；`bpf_program__attach_iter()`；`bpf_program__attach_uprobe_multi()`；`bpf_program__attach_kprobe_multi_opts()`。
这体现出 libbpf attach 框架的一个设计原则： **generic attach 只做“SEC() 驱动的参数恢复”，通用显式 API 才做真正 attach。** ---

## 3.3 attach 分发总图
可以把整个 generic attach 路径概括为：

```text
ELF SEC() 字符串
    ↓
section_defs[] 匹配 sec_def
    ↓
prog->sec_def / prog->type / prog->expected_attach_type 确定
    ↓
bpf_program__attach()
    ↓
sec_def->prog_attach_fn(prog, cookie, &link)
    ↓
attach_xxx() 解析 sec_name
    ↓
底层 helper
    ↓
perf_event_open / bpf_link_create / bpf_raw_tracepoint_open / ...
    ↓
返回 struct bpf_link

```
这条路径把“字符串 section 元信息”最终变成“内核中已激活 hook 上的程序”。 ---

## 4. 各 attach 类型详解

## 4.1 perf_event 类：kprobe / uprobe / tracepoint
这一类 attach 的共同点是：
- attach 目标先表现为 **perf event**；program 再通过 ioctl 或 BPF link 绑定到 perf event 上；因此 perf_event 是“中介层”。
它们共用的核心 helper 是：
- `bpf_program__attach_perf_event_opts()`（`libbpf.c:11411-11487`）。

### 4.1.1 共享 backend：`bpf_program__attach_perf_event_opts()`
调用链骨架：

```text
具体 attach helper
    ↓
创建 perf event fd（pfd）
    ↓
bpf_program__attach_perf_event_opts(prog, pfd, opts)
    ├─ 新内核：bpf_link_create(prog_fd, pfd, BPF_PERF_EVENT, ...)
    └─ 旧内核：ioctl(PERF_EVENT_IOC_SET_BPF) + ioctl(PERF_EVENT_IOC_ENABLE)

```
源码关键点：
- `libbpf.c:11440-11452`：link 模式，走 `bpf_link_create(..., BPF_PERF_EVENT, ...)`；`libbpf.c:11453-11469`：ioctl fallback，走 `PERF_EVENT_IOC_SET_BPF`；`libbpf.c:11472-11479`：默认 `PERF_EVENT_IOC_ENABLE`；`libbpf.c:11377-11409`：对应的 perf link detach / dealloc。
底层系统调用 / ioctl：
- `bpf(BPF_LINK_CREATE, ...)`；`ioctl(PERF_EVENT_IOC_SET_BPF)`；`ioctl(PERF_EVENT_IOC_ENABLE)`；`ioctl(PERF_EVENT_IOC_DISABLE)`。
内核侧对应处理：
- `kernel/bpf/syscall.c: link_create()` 处理 `BPF_LINK_CREATE`；`kernel/events/core.c` 中 perf ioctl 路径处理 `PERF_EVENT_IOC_SET_BPF` / `ENABLE` / `DISABLE`；perf kprobe/uprobe/tracepoint PMU 各自再进入对应子系统。

### 4.1.2 三种 attach 模式：legacy / perf / link
这是 kprobe/uprobe 家族最重要的演进轨迹。

#### 模式 1：`PROBE_ATTACH_MODE_LEGACY`
路径：

```text
写 tracefs 的 kprobe_events/uprobe_events
    ↓
得到一个 trace event id
    ↓
perf_event_open(PERF_TYPE_TRACEPOINT)
    ↓
ioctl(PERF_EVENT_IOC_SET_BPF)

```
特点：
- 最老；依赖 tracefs/debugfs；需要额外清理动态创建的 event；没有真正的内核 link object。

#### 模式 2：`PROBE_ATTACH_MODE_PERF`
路径：

```text
perf_event_open(type=kprobe 或 uprobe PMU)
    ↓
ioctl(PERF_EVENT_IOC_SET_BPF)

```
特点：
- 不再改写 tracefs 事件文件；仍然依赖 perf event fd；仍然没有真正的 BPF link fd；detach 主要靠关 perf fd。

#### 模式 3：`PROBE_ATTACH_MODE_LINK`
路径：

```text
perf_event_open(...)
    ↓
bpf_link_create(..., BPF_PERF_EVENT, ...)

```
特点：
- 有真正 link fd；支持 pin；生命周期更清晰；与现代 BPF link 模型一致。

### 4.1.3 kprobe：最典型的 perf_event attach 家族

#### SEC() 映射
在 `section_defs[]` 中：
- `SEC("kprobe+")` → `attach_kprobe`；`SEC("kretprobe+")` → `attach_kprobe`
对应条目位于：`libbpf.c:9982`、`9985`。

#### auto-attach section 格式
典型格式：
- `SEC("kprobe/do_sys_open")`；`SEC("kprobe/do_sys_open+0x10")`；`SEC("kretprobe/do_sys_open")`

#### generic attach 调用链

```text
bpf_program__attach()                        (13596)
  → attach_kprobe()                         (12271)
    → bpf_program__attach_kprobe_opts()     (11806)
      → perf_event_open_probe() 或 legacy   (11552 / 11703)
      → bpf_program__attach_perf_event_opts()(11411)

```

#### `attach_kprobe()` 做什么
`attach_kprobe()`（`12271-12306`）主要负责：
- 判断是否是 `SEC("kprobe")` / `SEC("kretprobe")` 这种“不可 auto-attach”的裸 section；从 `prog->sec_name` 中解析出：`retprobe`；`func_name`；`offset`；然后调用 `bpf_program__attach_kprobe_opts()`。

#### `bpf_program__attach_kprobe_opts()` 的关键逻辑
位于 `11806-11900`。 关键步骤：
1. 读 `attach_mode`； 2. 通过 `determine_kprobe_perf_type() < 0` 判断内核是否支持 kprobe PMU； 3. 根据 `attach_mode` 修正 `legacy` / `force_ioctl_attach`； 4. `legacy == false` 时调用 `perf_event_open_probe(false, retprobe, ...)`； 5. `legacy == true` 时：
- `gen_probe_legacy_event_name()`；`perf_event_kprobe_open_legacy()`；
6. 最后统一进入 `bpf_program__attach_perf_event_opts()`； 7. 若 legacy attach 成功，把 `legacy_probe_name` 等信息塞入 `bpf_link_perf`，供 detach 时清理。

#### legacy 路径细节
关键 helper：
- `add_kprobe_event_legacy()`（`11678-11685`）；`remove_kprobe_event_legacy()`（`11687-11690`）；`perf_event_kprobe_open_legacy()`（`11703-11747`）
真正做的事是：
1. 往 `tracefs_kprobe_events()` 追加一条 `p:` 或 `r:` 规则； 2. 从 `/sys/kernel/{debug,}tracing/events/.../id` 读 event id； 3. 以 `PERF_TYPE_TRACEPOINT` 打开 perf event； 4. attach BPF 程序。

#### perf / link 路径细节
关键 helper：
- `determine_kprobe_perf_type()`（`11521-11526`）；`determine_kprobe_retprobe_bit()`（`11535-11540`）；`perf_event_open_probe()`（`11552-11596`）
这里直接读取：
- `/sys/bus/event_source/devices/kprobe/type`；`/sys/bus/event_source/devices/kprobe/format/retprobe`
然后构造 `perf_event_attr`：
- `attr.type = kprobe PMU type`；`attr.config` 携带 retprobe bit；`attr.config1 = 函数名指针`；`attr.config2 = offset`
最后走 `syscall(__NR_perf_event_open, ...)`。

#### 底层系统调用 / ioctl
- `perf_event_open`；`ioctl(PERF_EVENT_IOC_SET_BPF)`；`ioctl(PERF_EVENT_IOC_ENABLE)`；可选：`bpf(BPF_LINK_CREATE, ...)`

#### 内核侧对应处理函数
可按两层理解：
- perf_event 建立入口：`__do_sys_perf_event_open()`；kprobe PMU 具体建立：内核 perf kprobe 子系统；若是 legacy tracefs path，则先经过 tracefs kprobe event 注册逻辑，再由 tracepoint perf event 接入；若是 link 模式，则还会经过 `kernel/bpf/syscall.c:link_create()` 的 `BPF_PERF_EVENT` 分支。

#### 设计结论
kprobe attach 是 libbpf attach 演进最完整的缩影：
- 先有 tracefs legacy；再有 perf PMU；最后加上 BPF link。

### 4.1.4 ksyscall：kprobe 的 syscall 包装层

#### SEC() 映射
- `SEC("ksyscall+")` → `attach_ksyscall`；`SEC("kretsyscall+")` → `attach_ksyscall`
对应 `libbpf.c:9997-9998`。

#### 调用链

```text
bpf_program__attach()                    (13596)
  → attach_ksyscall()                   (12308)
    → bpf_program__attach_ksyscall()    (11913)
      → bpf_program__attach_kprobe_opts()(11806)

```

#### 核心逻辑
`attach_ksyscall()` 本身非常薄：
- 解析 `ksyscall/xxx` 或 `kretsyscall/xxx`；调用 `bpf_program__attach_ksyscall()`。
`bpf_program__attach_ksyscall()`（`11913-11938`）的关键是：
- 判断内核是否支持 syscall wrapper；若支持，构造 `__<arch>_sys_<name>`；否则退到 `__se_sys_<name>`；最后仍走 kprobe attach。

#### 底层机制
本质仍然是 kprobe/kretprobe。 只是 libbpf 帮用户把“syscall 名称”翻译成“内核里真正可探测的 wrapper 符号”。

#### 内核侧对应处理函数
与 kprobe 相同； 差异只在用户态符号解析阶段，而不在最终 attach backend。

### 4.1.5 kprobe_multi / kprobe.session：批量 kprobe link
虽然用户要求把批量类放到 4.7，但这里先建立 perf_event 家族对比很有帮助。 kprobe_multi 与普通 kprobe 的根本区别是：
- 它不以 perf event 为中介；它直接走 `bpf_link_create(BPF_TRACE_KPROBE_MULTI / SESSION)`。
因此它更接近 link 家族，而不再是传统 perf 家族。 这一点也说明： **“kprobe” 并不必然等于 “perf_event attach”。** 详细分析见 4.7。

### 4.1.6 uprobe：用户态符号探针

#### SEC() 映射
- `SEC("uprobe+")` → `attach_uprobe`；`SEC("uprobe.s+")` → `attach_uprobe`；`SEC("uretprobe+")` → `attach_uprobe`；`SEC("uretprobe.s+")` → `attach_uprobe`
对应 `libbpf.c:9983-9987`。

#### auto-attach section 格式
源码注释明确写在 `12892-12900`：

```text
u[ret]probe/binary:function[+offset]

```
例如：
- `SEC("uprobe//bin/bash:readline")`；`SEC("uretprobe/libc.so.6:malloc")`；`SEC("uprobe/mybin:foo+0x20")`

#### generic attach 调用链

```text
bpf_program__attach()                        (13596)
  → attach_uprobe()                         (12902)
    → bpf_program__attach_uprobe_opts()     (12756)
      → perf_event_open_probe() 或 legacy   (11552 / 12444)
      → bpf_program__attach_perf_event_opts()(11411)

```

#### `attach_uprobe()` 做什么
位于 `12902-12955`。 主要负责：
- 解析 `probe_type/binary:function[+offset]`；识别 `uretprobe`；解析 `+offset`；校验 `uretprobe` 不能带 offset；把 `func_name` 和 `binary_path` 交给 `bpf_program__attach_uprobe_opts()`。

#### `bpf_program__attach_uprobe_opts()` 的关键逻辑
位于 `12756-12890`。 其流程和 kprobe 非常像，但多了“文件路径和 ELF 符号解析”。 主要步骤：
1. 解析 attach mode； 2. 处理 archive path（`archive!/elf` 语法）； 3. 若 `binary_path` 不是绝对路径，则 `resolve_full_path()`； 4. 若给了 `func_name`：
- 从 ELF 或 archive ELF 里解析 `sym_off`；把它叠加到 `func_offset`；
5. 通过 `determine_uprobe_perf_type() < 0` 判断 legacy； 6. 非 legacy：`perf_event_open_probe(true, ...)`； 7. legacy：`perf_event_uprobe_open_legacy()`； 8. 最终进入 `bpf_program__attach_perf_event_opts()`。

#### legacy 路径细节
关键 helper：
- `add_uprobe_event_legacy()`（`12419-12426`）；`remove_uprobe_event_legacy()`（`12428-12431`）；`perf_event_uprobe_open_legacy()`（`12444-12485`）
其模式与 kprobe legacy 完全对应：
- 写 `uprobe_events`；读动态 tracepoint id；`perf_event_open(PERF_TYPE_TRACEPOINT)`；attach BPF。

#### perf / link 路径细节
关键 helper：
- `determine_uprobe_perf_type()`（`11528-11533`）；`determine_uprobe_retprobe_bit()`（`11542-11547`）；`perf_event_open_probe()`（`11552-11596`）
对于 uprobe，`perf_event_attr` 的关键字段为：
- `config1 = binary_path`；`config2 = file offset`；`pid` 过滤只对 uprobe 有意义；`ref_ctr_off` 支持 uprobe reference counter

#### 底层系统调用 / ioctl
- `perf_event_open`；`bpf(BPF_LINK_CREATE, BPF_PERF_EVENT)` 或 ioctl fallback；`PERF_EVENT_IOC_SET_BPF`；`PERF_EVENT_IOC_ENABLE`

#### 内核侧对应处理函数
- perf_event 建立入口：`__do_sys_perf_event_open()`；uprobe PMU 初始化路径：内核 perf uprobes 子系统；legacy 路径先经过 tracefs uprobes event 注册，再转成 tracepoint perf event；link 模式再经过 `kernel/bpf/syscall.c:link_create()` 的 perf-event link 分支。

### 4.1.7 USDT：建立在 uprobe 之上的语义层

#### SEC() 映射
- `SEC("usdt+")` → `attach_usdt`；`SEC("usdt.s+")` → `attach_usdt`
对应 `libbpf.c:9999-10000`。

#### auto-attach 格式
`attach_usdt()` 期望：

```text
SEC("usdt/<path>:<provider>:<name>")

```

#### 调用链

```text
bpf_program__attach()                     (13596)
  → attach_usdt()                        (13020)
    → bpf_program__attach_usdt()         (12967)
      → usdt_manager_attach_usdt()       (usdt.c)
        → 组合多路 uprobe / semaphore / spec 逻辑

```

#### `attach_usdt()` 做什么
- 解析 section string 中的 `path:provider:name`；调用 `bpf_program__attach_usdt(prog, -1, path, provider, name, NULL)`。

#### `bpf_program__attach_usdt()` 的关键逻辑
位于 `12967-13018`。 主要工作：
1. 校验 program 已 load； 2. 解析并补全 `binary_path`； 3. 懒加载 `obj->usdt_man`； 4. 调用 `usdt_manager_attach_usdt()`； 5. 由 USDT manager 生成真实 attach 组合。

#### 底层机制
USDT 不是新的内核 attach primitive。 它本质上还是：
- 用户态 ELF note / semaphore 元信息解析；若干 uprobe attach；必要时管理 USDT semaphore enable/disable。

#### 内核侧对应处理函数
最终仍落到 uprobes / perf_event / perf link 或 legacy uprobes event。 因此，USDT 是“**用户态探针元数据管理层**”，不是新的内核 hook 类型。

### 4.1.8 tracepoint：标准 trace event attach

#### SEC() 映射
- `SEC("tracepoint+")` → `attach_tp`；`SEC("tp+")` → `attach_tp`
对应 `libbpf.c:10010-10011`。

#### auto-attach section 格式
- `SEC("tracepoint/syscalls/sys_enter_execve")`；`SEC("tp/sched/sched_switch")`

#### 调用链

```text
bpf_program__attach()                           (13596)
  → attach_tp()                                (13139)
    → bpf_program__attach_tracepoint()         (13132)
      → bpf_program__attach_tracepoint_opts()  (13099)
        → perf_event_open_tracepoint()         (13067)
        → bpf_program__attach_perf_event_opts()(11411)

```

#### `perf_event_open_tracepoint()` 的逻辑
位于 `13067-13097`。 步骤：
1. `determine_tracepoint_id()` 读取 `tracefs/events/<cat>/<name>/id`； 2. 构造 `perf_event_attr`：
- `type = PERF_TYPE_TRACEPOINT`；`config = tp_id`
3. 调用 `perf_event_open`。

#### `attach_tp()` 的职责
位于 `13139-13169`。
- 判断是否是裸 `SEC("tp")` 或 `SEC("tracepoint")`；从 section 名称解析 `category` 和 `name`；调用 `bpf_program__attach_tracepoint()`。

#### 底层系统调用 / ioctl
- `perf_event_open(PERF_TYPE_TRACEPOINT)`；然后仍是：`bpf(BPF_LINK_CREATE, BPF_PERF_EVENT)`；或 ioctl `PERF_EVENT_IOC_SET_BPF` / `ENABLE`。

#### 内核侧对应处理函数
- tracepoint perf event 打开流程经 `__do_sys_perf_event_open()`；tracepoint 事件元数据由 tracing subsystem 管理；BPF 绑定可经 perf ioctl，或经 `kernel/bpf/syscall.c:link_create()` 生成 perf link。

### 4.1.9 raw tracepoint：绕过 perf_event 中介

#### SEC() 映射
- `SEC("raw_tracepoint+")` → `attach_raw_tp`；`SEC("raw_tp+")` → `attach_raw_tp`；`SEC("raw_tracepoint.w+")` → `attach_raw_tp`；`SEC("raw_tp.w+")` → `attach_raw_tp`
对应 `libbpf.c:10012-10015`。

#### 调用链

```text
bpf_program__attach()                           (13596)
  → attach_raw_tp()                            (13214)
    → bpf_program__attach_raw_tracepoint()     (13208)
      → bpf_program__attach_raw_tracepoint_opts()(13172)
        → bpf_raw_tracepoint_open_opts()

```

#### 关键逻辑
`bpf_program__attach_raw_tracepoint_opts()`（`13172-13206`）不走 perf_event。 它直接：
1. 分配一个最简单的 `struct bpf_link`； 2. 设置 `link->detach = bpf_link__detach_fd`； 3. 调用 `bpf_raw_tracepoint_open_opts(prog_fd, &raw_opts)`； 4. 返回一个 fd-backed link object。
这里的 fd 更接近“raw tracepoint attach fd”，不是 perf event fd。

#### 底层系统调用
- `bpf(BPF_RAW_TRACEPOINT_OPEN, ...)`

#### 内核侧对应处理函数
- `kernel/bpf/syscall.c` 中的 raw tracepoint open 路径；trace 执行逻辑在 `kernel/trace/bpf_trace.c` 一类 tracing 代码中。

#### 为什么 raw tracepoint 与 tracepoint 要分开
因为它们 attach 的中介对象不同：
- `tracepoint`：依赖 perf event；`raw tracepoint`：直接使用 BPF raw tracepoint API。
从 libbpf 的角度看，这两类 attach backend 完全不同。 ---

## 4.2 BPF trampoline 类：fentry / fexit / fmod_ret / tp_btf / freplace / lsm
这一类 attach 的共同特征是：
- attach 目标是 **BTF 描述的函数或 hook**；内核执行层依赖 **BPF trampoline**；用户态几乎不需要再显式创建 perf event；attach 主要通过 `bpf_link_create()` 完成。

### 4.2.1 SEC() 映射
在 `section_defs[]` 中，以下条目都走 BTF attach 家族：
- `tp_btf+` → `attach_trace` (`10016`)；`fentry+` → `attach_trace` (`10017`)；`fmod_ret+` → `attach_trace` (`10018`)；`fexit+` → `attach_trace` (`10019`)；`fentry.s+` → `attach_trace` (`10020`)；`fmod_ret.s+` → `attach_trace` (`10021`)；`fexit.s+` → `attach_trace` (`10022`)；`fsession+` → `attach_trace` (`10023`)；`fsession.s+` → `attach_trace` (`10024`)；`freplace+` → `attach_trace` (`10025`)；`lsm+` → `attach_lsm` (`10026`)；`lsm.s+` → `attach_lsm` (`10027`)；`iter+` / `iter.s+` 虽也依赖 BTF attach type，但有独立 attach helper，后文单列。

### 4.2.2 共用 backend：`bpf_program__attach_btf_id()`
位于 `13256-13289`。 调用链骨架：

```text
attach_trace() 或 attach_lsm()
  ↓
bpf_program__attach_trace() / bpf_program__attach_lsm()
  ↓
bpf_program__attach_btf_id()
  ↓
bpf_link_create(prog_fd, 0, expected_attach_type, &link_opts)

```
源码关键点：
- `13277`：注释明确指出，旧内核上 libbpf 会智能回退到 `BPF_RAW_TRACEPOINT_OPEN`；`13279`：调用 `bpf_link_create(prog_fd, 0, bpf_program__expected_attach_type(prog), &link_opts)`；`13278`：支持 `tracing.cookie`。

#### 底层系统调用
- 主路径：`bpf(BPF_LINK_CREATE, ...)`；老内核 fallback：`bpf(BPF_RAW_TRACEPOINT_OPEN, ...)`，仅适用于少数 attach type。

#### 内核侧对应处理函数
- `kernel/bpf/syscall.c: link_create()` 是系统调用入口；tracing attach 典型进入 tracing/trampoline 专属 link create 逻辑；真正执行层是 BPF trampoline；对 LSM，则 trampoline 最终接入 LSM hook 调度路径。

### 4.2.3 fentry / fexit / fmod_ret

#### SEC() 映射
- `fentry+` → `BPF_TRACE_FENTRY`；`fexit+` → `BPF_TRACE_FEXIT`；`fmod_ret+` → `BPF_MODIFY_RETURN`

#### 调用链

```text
bpf_program__attach()                  (13596)
  → attach_trace()                    (13307)
    → bpf_program__attach_trace()     (13291)
      → bpf_program__attach_btf_id()  (13256)
        → bpf_link_create(...)

```

#### section 名称承担的语义
例如：
- `SEC("fentry/do_unlinkat")`；`SEC("fexit/tcp_v4_connect")`；`SEC("fmod_ret/security_file_open")`
其中：
- 前缀决定 attach type；函数名决定 attach BTF ID；load 阶段会把这类 BTF attach 信息塞进 program aux / expected_attach_type。

#### 底层机制
- `BPF_LINK_CREATE`；attach_type 为 `BPF_TRACE_FENTRY` / `BPF_TRACE_FEXIT` / `BPF_MODIFY_RETURN`；内核内部通过 trampoline 在目标函数入口/出口/返回值改写点执行 BPF。

#### 内核侧对应处理函数
- syscall 入口：`kernel/bpf/syscall.c: link_create()`；trampoline 层：内核 BPF trampoline attach 逻辑；执行层：目标内核函数的 trampoline patch / dispatch。

### 4.2.4 `tp_btf`：BTF 版 tracepoint attach

#### SEC() 映射
- `tp_btf+` → `attach_trace`；`expected_attach_type = BPF_TRACE_RAW_TP`

#### 调用链
与 fentry 相同，只是 attach type 不同：

```text
attach_trace()
  → bpf_program__attach_trace()
    → bpf_program__attach_btf_id()
      → bpf_link_create(..., BPF_TRACE_RAW_TP, ...)

```

#### 本质
它把 raw tracepoint attach 从“按字符串 tracepoint name”提升到“按 BTF target 描述”。

### 4.2.5 freplace：EXT program 的替换式 attach

#### SEC() 映射
- `SEC("freplace+")` → `attach_trace`；`prog_type = EXT`

#### 两种 attach 形态
当前源码里同时存在两条路径：
1. generic attach 走 `attach_trace()` → `bpf_program__attach_trace()`； 2. 显式 API `bpf_program__attach_freplace()`（`13474-13509`）支持指定：
- `target_fd`；`attach_func_name`

#### 显式 API 调用链

```text
bpf_program__attach_freplace()             (13474)
  ├─ 有 target_fd：
  │    → libbpf_find_prog_btf_id()
  │    → bpf_program_attach_fd(..., "freplace", &target_opts)
  │    → bpf_link_create(...)
  └─ 无 target_fd：
       → bpf_program__attach_trace()

```

#### 关键点
当用户显式指定 target program 时：
- `libbpf_find_prog_btf_id()` 解析目标程序中要被替换的函数 BTF ID；`bpf_link_create()` 使用 `target_fd + target_btf_id` 建立替换关系。

#### 内核侧对应处理函数
- syscall 入口仍是 `link_create()`；具体 attach 由 EXT/trampoline 路径处理。

### 4.2.6 LSM：安全 hook 的 trampoline attach

#### SEC() 映射
- `SEC("lsm+")` → `attach_lsm`；`SEC("lsm.s+")` → `attach_lsm`；`expected_attach_type = BPF_LSM_MAC`
对应 `10026-10027`。

#### 调用链

```text
bpf_program__attach()                 (13596)
  → attach_lsm()                     (13313)
    → bpf_program__attach_lsm()      (13302)
      → bpf_program__attach_btf_id() (13256)
        → bpf_link_create(..., BPF_LSM_MAC, ...)

```

#### 关键特征
LSM attach 与 fentry/fexit 的用户态路径几乎完全一致； 差异主要体现在：
- program type 是 `LSM`；attach type 是 `BPF_LSM_MAC`；内核执行点不再是普通函数入口/出口，而是 LSM hook。

#### 底层系统调用
- `bpf(BPF_LINK_CREATE, ...)`

#### 内核侧对应处理函数
- syscall 入口：`kernel/bpf/syscall.c: link_create()`；attach 逻辑：BPF trampoline + LSM hook 桥接层；hook 运行于内核安全框架路径。

### 4.2.7 `lsm_cgroup+` 的特殊性
`section_defs[]` 里还有：
- `SEC("lsm_cgroup+")` → `prog_type = LSM`，`expected_attach_type = BPF_LSM_CGROUP`
但它**没有**配置 `prog_attach_fn`。 这很关键。 说明：
- libbpf 知道这是个 LSM cgroup program；但 generic `bpf_program__attach()` 不负责它的 attach；它属于“需要额外 target 上下文”的 attach 类型。
内核侧该类 program 最终与 cgroup + trampoline 结合运行，和普通 `BPF_LSM_MAC` 不同。 ---

## 4.3 网络类：XDP / tc / tcx / netkit
这一类 attach 的共同点是：
- attach 目标通常是 `ifindex` 对应的 netdevice；仅靠 section string 无法知道目标网卡；因此通常不走 `bpf_program__attach()` generic 分发。
这也是为什么：
- `section_defs[]` 里有 `xdp` / `tcx` / `netkit` 条目；但它们并没有 `prog_attach_fn`。

### 4.3.1 XDP：当前 libbpf 同时存在两条 attach 模型
这里要特别说明一个“表象冲突”：
- 从传统认知看，XDP attach 经常用 netlink `RTM_SETLINK + IFLA_XDP`；但在当前 `libbpf.c` 版本中，`bpf_program__attach_xdp()` 已经是 **link-based** API。
这两个说法都对，只是对应不同 libbpf API。

#### 路径 A：program-centric XDP attach（`libbpf.c`）
源码：`13371-13375`

```c
struct bpf_link *bpf_program__attach_xdp(const struct bpf_program *prog, int ifindex)
{
    return bpf_program_attach_fd(prog, ifindex, "xdp", NULL);
}

```
调用链：

```text
bpf_program__attach_xdp()          (13371)
  → bpf_program_attach_fd()        (13319)
    → bpf_link_create(prog_fd, ifindex, BPF_XDP, NULL)

```
也就是说，在当前 `libbpf.c` 版本里： **`bpf_program__attach_xdp()` 走的是 `BPF_LINK_CREATE`。**

#### 路径 B：device-centric XDP attach（`netlink.c`）
补充 API：`bpf_xdp_attach()`，定义在 `src/netlink.c:324-339`。 调用链：

```text
bpf_xdp_attach()                         (netlink.c:324)
  → __bpf_set_link_xdp_fd_replace()     (netlink.c:288)
    → RTM_SETLINK + IFLA_XDP nested attr

```
该路径构造的 netlink 属性包括：
- `IFLA_XDP_FD`；`IFLA_XDP_FLAGS`；`IFLA_XDP_EXPECTED_FD`（replace 时）

#### SEC() 映射
`section_defs[]` 中的 XDP 项：
- `xdp.frags/devmap` → `BPF_XDP_DEVMAP`；`xdp/devmap` → `BPF_XDP_DEVMAP`；`xdp.frags/cpumap` → `BPF_XDP_CPUMAP`；`xdp/cpumap` → `BPF_XDP_CPUMAP`；`xdp.frags` → `BPF_XDP`；`xdp` → `BPF_XDP`
对应 `10032-10037`。

#### 为什么 `section_defs[]` 不给 XDP 配 `attach_fn`
因为 XDP attach 至少还需要：
- `ifindex`；attach flags（driver/generic/hw/offload）；replace 语义
这些都无法从 `SEC("xdp")` 自身恢复出来。

#### 底层系统调用 / 协议
- link 路径：`bpf(BPF_LINK_CREATE, attach_type=BPF_XDP)`；传统路径：`NETLINK_ROUTE / RTM_SETLINK / IFLA_XDP`

#### 内核侧对应处理函数
- netlink XDP 路径：`net/core/rtnetlink.c` 接收 `RTM_SETLINK`，再调用 `dev_change_xdp_fd()`；link 路径：`kernel/bpf/syscall.c: link_create()` 的 `BPF_XDP` 分支，最终仍要把 program 挂到 netdevice XDP hook 上。

### 4.3.2 tc：经典 TC filter attach，仍以 netlink 为主

#### SEC() 映射
`section_defs[]` 中：
- `tc/ingress` → `SCHED_CLS, BPF_TCX_INGRESS`（别名，注释写明 alias for tcx）；`tc/egress` → `SCHED_CLS, BPF_TCX_EGRESS`；`tc` → `SCHED_CLS, 0`（deprecated / legacy）；`classifier` → `SCHED_CLS, 0`（deprecated / legacy）；`action` → `SCHED_ACT, 0`（deprecated / legacy）
对应 `10001-10007`。

#### 经典 TC attach API
不在 `libbpf.c` 这段源码中，而在 `netlink.c:734-806`：
- `bpf_tc_attach()`
调用链：

```text
bpf_tc_attach()                    (netlink.c:734)
  → RTM_NEWTFILTER
  → TCA_KIND="bpf"
  → TCA_OPTIONS nested attrs
  → libbpf_netlink_send_recv()

```

#### 关键属性
`bpf_tc_attach()` 会编码：
- `TCA_BPF_FD`；`TCA_BPF_NAME`；`TCA_BPF_FLAGS = TCA_BPF_FLAG_ACT_DIRECT`

#### 底层协议
- `NETLINK_ROUTE`；`RTM_NEWTFILTER`

#### 内核侧对应处理函数
- rtnetlink tc filter 创建路径；cls_bpf/act_bpf 等 TC 子系统逻辑处理 BPF filter/action 的装载与替换。

#### 与 tcx 的关系
当前 `section_defs[]` 已把 `tc/ingress`、`tc/egress` 标成 `alias for tcx`。 这说明 libbpf 正在把网络 filter attach 从旧 tc 管理模型逐渐迁移到 tcx link 模型。

### 4.3.3 tcx：现代 netdevice link attach

#### SEC() 映射
- `SEC("tcx/ingress")` → `BPF_TCX_INGRESS`；`SEC("tcx/egress")` → `BPF_TCX_EGRESS`
对应 `10003-10004`。

#### 调用链

```text
bpf_program__attach_tcx()          (13406)
  → bpf_program_attach_fd()        (13319)
    → bpf_link_create(prog_fd, ifindex, attach_type, &opts)

```

#### `bpf_program__attach_tcx()` 的关键逻辑
位于 `13406-13438`。 它支持：
- `relative_fd`；`relative_id`；`expected_revision`；`flags`
这说明 tcx 不只是“attach 到网卡”，还支持链式相对定位和 revision 检查。

#### 底层系统调用
- `bpf(BPF_LINK_CREATE, attach_type = BPF_TCX_INGRESS / BPF_TCX_EGRESS)`

#### 内核侧对应处理函数
- `kernel/bpf/syscall.c: link_create()`；net/tcx 子系统中处理 tcx link 的安装与相对位置逻辑。

### 4.3.4 netkit：netdevice hook 的另一套 link attach

#### SEC() 映射
- `SEC("netkit/primary")` → `BPF_NETKIT_PRIMARY`；`SEC("netkit/peer")` → `BPF_NETKIT_PEER`
对应 `10008-10009`。

#### 调用链

```text
bpf_program__attach_netkit()       (13441)
  → bpf_program_attach_fd()        (13319)
    → bpf_link_create(prog_fd, ifindex, attach_type, &opts)

```

#### `bpf_program__attach_netkit()` 的关键逻辑
位于 `13441-13472`。 它与 tcx 非常像：
- 校验 `ifindex != 0`；校验 `relative_fd` / `relative_id` 互斥；填充 `netkit.expected_revision / relative_fd / relative_id / flags`；最终 `bpf_link_create()`。

#### 底层系统调用
- `bpf(BPF_LINK_CREATE, attach_type = BPF_NETKIT_PRIMARY / PEER)`

#### 内核侧对应处理函数
- `kernel/bpf/syscall.c: link_create()`；`net/netkit` 子系统完成具体 hook 安装。

### 4.3.5 网络类 attach 的总体结论
网络类 attach 有两个鲜明特点：
1. **强依赖运行时 target**（`ifindex`）； 2. **新旧 API 并存**：
- 旧：netlink（XDP classic、TC classic）；新：BPF link（XDP link、tcx、netkit）。
所以从架构演进上看，网络 attach 也在向“link first”迁移。 ---

## 4.4 cgroup 类
cgroup attach 也是“显式 target attach”的典型代表。

### 4.4.1 SEC() 映射
`section_defs[]` 中的 cgroup 条目很多，代表 attach_type 的矩阵：
- `cgroup_skb/ingress` → `BPF_CGROUP_INET_INGRESS`；`cgroup_skb/egress` → `BPF_CGROUP_INET_EGRESS`；`cgroup/sock_create` → `BPF_CGROUP_INET_SOCK_CREATE`；`cgroup/sock_release` → `BPF_CGROUP_INET_SOCK_RELEASE`；`cgroup/bind4` → `BPF_CGROUP_INET4_BIND`；`cgroup/bind6` → `BPF_CGROUP_INET6_BIND`；`cgroup/connect4` → `BPF_CGROUP_INET4_CONNECT`；`cgroup/connect6` → `BPF_CGROUP_INET6_CONNECT`；`cgroup/sendmsg4` → `BPF_CGROUP_UDP4_SENDMSG`；`cgroup/recvmsg4` → `BPF_CGROUP_UDP4_RECVMSG`；`cgroup/sysctl` → `BPF_CGROUP_SYSCTL`；`cgroup/getsockopt` → `BPF_CGROUP_GETSOCKOPT`；`cgroup/setsockopt` → `BPF_CGROUP_SETSOCKOPT`；`cgroup/dev` → `BPF_CGROUP_DEVICE`；等等。
对应源码大致在 `10051-10079`。

### 4.4.2 为什么 cgroup 也不走 generic `bpf_program__attach()`
和 XDP 一样，原因不是“不能 attach”，而是：
- 必须知道目标 cgroup 的 fd；可能还要知道相对链接位置、revision、flags；单靠 `SEC()` 不够。
因此当前源码给了显式 API：
- `bpf_program__attach_cgroup()`（`13354-13357`）；`bpf_program__attach_cgroup_opts()`（`13377-13403`）

### 4.4.3 调用链

#### 简单版

```text
bpf_program__attach_cgroup()       (13354)
  → bpf_program_attach_fd()        (13319)
    → bpf_link_create(prog_fd, cgroup_fd, attach_type, NULL)

```

#### 带扩展参数版

```text
bpf_program__attach_cgroup_opts()  (13377)
  → 填充 bpf_link_create_opts.cgroup
  → bpf_program_attach_fd()        (13319)
    → bpf_link_create(...)

```

### 4.4.4 `bpf_program_attach_fd()` 的意义
这个 helper 位于 `13319-13351`，是 cgroup / xdp / netns / sockmap / tcx / netkit 的共用 attach 框架。 它做的事情极其统一：
1. 取 `prog_fd`； 2. 分配 `struct bpf_link`； 3. `attach_type = bpf_program__expected_attach_type(prog)`； 4. 调用 `bpf_link_create(prog_fd, target_fd, attach_type, opts)`； 5. 返回 `fd-backed bpf_link`。
这意味着： **一旦 attach 模型可以抽象成 “prog_fd + target_fd + attach_type + opts”，libbpf 就能用一个公共 helper 收敛复杂度。**

### 4.4.5 底层系统调用与旧接口
当前 link 路径：
- `bpf(BPF_LINK_CREATE, ...)`
旧接口：
- `bpf(BPF_PROG_ATTACH, ...)`
在 libbpf 中，旧接口封装位于 `src/bpf.c:650-677` 的 `bpf_prog_attach_opts()`：
- 最终 `sys_bpf(BPF_PROG_ATTACH, &attr, attr_sz)`。

### 4.4.6 内核侧对应处理函数
- link 路径：`kernel/bpf/syscall.c: link_create()`；cgroup 具体安装：`kernel/bpf/cgroup.c` 的 cgroup attach 逻辑，典型核心函数是 `cgroup_bpf_attach()`；旧接口路径：`cgroup_bpf_prog_attach()` 一类 helper 处理 `BPF_PROG_ATTACH`。

### 4.4.7 cgroup attach 的架构意义
cgroup attach 是 libbpf 从“直接把 prog 贴到 target 上”向“创建可管理 link 对象”过渡的重点区域之一。 它让：
- 层级继承；revision；相对位置；auto-detach；
都具备更稳定的用户态抽象。 ---

## 4.5 struct_ops
`struct_ops` 是整个 attach 体系里最“异类”的一种。 它不是把 program attach 到某个 hook 名称； 而是把一组 BPF function pointer 填进一个内核可识别的 ops 结构。

### 4.5.1 SEC() 映射
`section_defs[]` 中：
- `SEC("struct_ops+")` → `STRUCT_OPS`；`SEC("struct_ops.s+")` → `STRUCT_OPS`
对应 `10080-10081`。 注意：这里没有 `prog_attach_fn`。 因为 struct_ops 不是“program 级 attach”，而是“map 级 attach”。

### 4.5.2 真正入口：`bpf_map__attach_struct_ops()`
源码位于 `13644-13695`。 调用链：

```text
bpf_map__attach_struct_ops()              (13644)
  → bpf_map_update_elem(map->fd, &zero, kern_vdata, 0)
  ├─ 非 BPF_F_LINK：构造一个 map-backed pseudo link
  └─ BPF_F_LINK：bpf_link_create(map->fd, 0, BPF_STRUCT_OPS, NULL)

```

### 4.5.3 attach 过程的本质
`struct_ops` attach 的真正激活动作是：

```c
bpf_map_update_elem(map->fd, &zero, map->st_ops->kern_vdata, 0);

```
也就是说：
- libbpf 在 load 阶段准备好 `kern_vdata`；attach 阶段把它写进 map；内核收到 map update 后，识别这是 `BPF_MAP_TYPE_STRUCT_OPS`，进而把里面的函数指针注册进对应子系统。

### 4.5.4 两种 struct_ops attach 形态

#### 形态 A：无真实 link（旧式）
当 `!(map->def.map_flags & BPF_F_LINK)`：
- `link->link.fd = map->fd`；`link->map_fd = -1`；detach 时通过 `bpf_map_delete_elem(map_fd, &zero)`。

#### 形态 B：真实 struct_ops link
当 `map_flags` 包含 `BPF_F_LINK`：
- `bpf_link_create(map->fd, 0, BPF_STRUCT_OPS, NULL)`；得到真实 link fd；`map_fd` 单独保存用于 update。

### 4.5.5 `bpf_link__update_map()`：struct_ops 专属 update
位于 `13700-13735`。 调用链：

```text
bpf_link__update_map()
  → bpf_map_update_elem(new_map->fd, &zero, new_kern_vdata, 0)
  → bpf_link_update(link->fd, map->fd, NULL)

```
它允许：
- 先准备新的 struct_ops map value；再用 `BPF_LINK_UPDATE` 原子切换 link 背后的 map。

### 4.5.6 底层系统调用
- `bpf(BPF_MAP_UPDATE_ELEM, ...)`；可选：`bpf(BPF_LINK_CREATE, attach_type=BPF_STRUCT_OPS)`；更新时：`bpf(BPF_LINK_UPDATE, ...)`

### 4.5.7 内核侧对应处理函数
- map 更新入口：`kernel/bpf/syscall.c: map_update_elem()` → `bpf_map_update_value()`；`BPF_MAP_TYPE_STRUCT_OPS` 的具体处理：`kernel/bpf/bpf_struct_ops.c: bpf_struct_ops_map_update_elem()`；若使用真实 link：`bpf_struct_ops_link_create()` 处理 `BPF_STRUCT_OPS` link create。

### 4.5.8 设计结论
`struct_ops` 说明 libbpf 的 attach 概念并不局限于：
- perf event；tracing hook；netdevice hook。
它还可以是： **“通过 map 写入触发内核子系统注册”的 attach。** ---

## 4.6 iter
BPF iterator 在用户态 attach 语义上介于 tracing 和 file-based iterator 之间。

### 4.6.1 SEC() 映射
`section_defs[]` 中：
- `SEC("iter+")` → `attach_iter`；`SEC("iter.s+")` → `attach_iter`
对应 `10029-10030`。 `expected_attach_type = BPF_TRACE_ITER`。

### 4.6.2 调用链

```text
bpf_program__attach()                    (13596)
  → attach_iter()                       (13550)
    → bpf_program__attach_iter()        (13512)
      → bpf_link_create(..., BPF_TRACE_ITER, &opts)

```

### 4.6.3 `bpf_program__attach_iter()` 的逻辑
位于 `13512-13548`。 核心步骤：
1. 校验 `opts`； 2. 取 `link_info` / `link_info_len` 填入 `bpf_link_create_opts`； 3. 分配普通 `struct bpf_link`； 4. `link->detach = bpf_link__detach_fd`； 5. 调 `bpf_link_create(prog_fd, 0, BPF_TRACE_ITER, &link_create_opts)`； 6. 返回 link fd。

### 4.6.4 iter attach 的特别之处
attach 成功后得到的 link fd 还不是“读数据 fd”。 通常还要进一步：
- `bpf_iter_create(link_fd)`
从而得到一个可读的 iterator file descriptor。 这也是 iterator 与普通 tracing attach 最大的差别之一。

### 4.6.5 底层系统调用
- attach：`bpf(BPF_LINK_CREATE, BPF_TRACE_ITER, ...)`；消费：`bpf(BPF_ITER_CREATE, ...)`

### 4.6.6 内核侧对应处理函数
- attach 入口：`kernel/bpf/syscall.c: link_create()`；iterator attach 实现：`kernel/bpf/bpf_iter.c: bpf_iter_link_attach()`；iterator fd 创建：`kernel/bpf/syscall.c` 中 `BPF_ITER_CREATE` 路径；运行时读逻辑：`kernel/bpf/bpf_iter.c` 的 `bpf_iter_fops` / `bpf_seq_read()`。

### 4.6.7 与 tracing attach 的关系
iter 也使用 `expected_attach_type + BPF_LINK_CREATE`，所以从 attach 框架看，它像 tracing 家族。 但从语义看，它更像“把 BPF 程序变成一个 seq_file producer”。 ---

## 4.7 批量类：kprobe_multi / uprobe_multi / session
这一类 attach 代表 libbpf attach 的另一次跃迁：
- 不再对每个 probe 单独建立 perf event；改为一次 link 描述一批 probe 点；支持批量 cookies / offsets / symbols / session 语义。

### 4.7.1 kprobe_multi

#### SEC() 映射
- `SEC("kprobe.multi+")` → `attach_kprobe_multi`；`SEC("kretprobe.multi+")` → `attach_kprobe_multi`
对应 `9988-9989`。

#### generic attach 调用链

```text
bpf_program__attach()                        (13596)
  → attach_kprobe_multi()                   (12329)
    → bpf_program__attach_kprobe_multi_opts()(12153)
      → bpf_link_create(..., BPF_TRACE_KPROBE_MULTI, ...)

```

#### `attach_kprobe_multi()` 的职责
- 解析 section 中的 glob pattern；判定 retprobe；调用 `bpf_program__attach_kprobe_multi_opts()`。

#### `bpf_program__attach_kprobe_multi_opts()` 的关键逻辑
位于 `12153-12269`。 它支持两种输入模式：
1. `pattern` 模式； 2. 直接给 `syms[]` 或 `addrs[]` 模式。
若是 pattern：
- 无通配符且不要求 `unique_match` 时，可直接把符号名交给内核；否则用户态解析 `available_filter_functions(_addrs)` 或 kallsyms，得到地址数组。
随后：
- `retprobe` 决定是否带 `BPF_F_KPROBE_MULTI_RETURN`；`session` 决定 attach_type 是 `BPF_TRACE_KPROBE_MULTI` 还是 `BPF_TRACE_KPROBE_SESSION`；统一用 `bpf_link_create()` 建 link。

#### 底层系统调用
- `bpf(BPF_LINK_CREATE, attach_type = BPF_TRACE_KPROBE_MULTI / SESSION)`

#### 内核侧对应处理函数
- syscall 入口：`kernel/bpf/syscall.c: link_create()`；tracing/kprobe multi 子系统负责解析 syms/addrs/cookies 并建立批量探针。

### 4.7.2 kprobe.session

#### SEC() 映射
- `SEC("kprobe.session+")` → `attach_kprobe_session`
对应 `9990`。

#### 调用链

```text
bpf_program__attach()
  → attach_kprobe_session()
    → bpf_program__attach_kprobe_multi_opts(..., .session = true)
      → bpf_link_create(..., BPF_TRACE_KPROBE_SESSION, ...)

```

#### 语义差异
它不是普通 multi-kprobe 的 retprobe 变体，而是独立 session attach type。 源码也明确禁止：
- `retprobe && session` 同时为真。

### 4.7.3 uprobe_multi / uprobe.session

#### SEC() 映射
- `SEC("uprobe.multi+")` → `attach_uprobe_multi`；`SEC("uretprobe.multi+")` → `attach_uprobe_multi`；`SEC("uprobe.session+")` → `attach_uprobe_multi`；以及 sleepable 版本 `*.s+`
对应 `9991-9996`。

#### generic attach 调用链

```text
bpf_program__attach()                     (13596)
  → attach_uprobe_multi()                (12386)
    → bpf_program__attach_uprobe_multi() (12628)
      → bpf_link_create(..., BPF_TRACE_UPROBE_MULTI / SESSION, ...)

```

#### `attach_uprobe_multi()` 的职责
位于 `12386-12417`。 主要做：
- 解析 `probe_type/binary_path:func_name`；决定 `session` / `retprobe`；调用 `bpf_program__attach_uprobe_multi()`。

#### `bpf_program__attach_uprobe_multi()` 的关键逻辑
位于 `12628-12753`。 支持两大输入形态：
1. `path + func_pattern`； 2. `path + (syms 或 offsets) + cnt + 可选 ref_ctr_offsets/cookies`。
如果给 `func_pattern`：
- 先 resolve full path；再 `elf_resolve_pattern_offsets()`；把函数模式解析成一组 file offsets。
如果给 `syms`：
- `elf_resolve_syms_offsets()` 把符号名解析成 offsets。
随后：
- `attach_type = session ? BPF_TRACE_UPROBE_SESSION : BPF_TRACE_UPROBE_MULTI`；`retprobe` 对应 `BPF_F_UPROBE_MULTI_RETURN`；可选 `pid` 过滤；最终 `bpf_link_create()`。

#### 底层系统调用
- `bpf(BPF_LINK_CREATE, BPF_TRACE_UPROBE_MULTI / SESSION)`

#### 内核侧对应处理函数
- syscall 入口：`kernel/bpf/syscall.c: link_create()`；uprobes multi attach 子系统处理二进制路径、offset 数组和 cookies。

### 4.7.4 批量 attach 与传统 perf_event attach 的差别
批量 attach 带来了三个变化：
1. **中介对象不再是 perf event**； 2. **attach 结果天然是 link**； 3. **一个 link 可以代表多个探针点**。
因此，从演进视角看：
- 传统 kprobe/uprobe：`probe point -> perf event -> BPF`；multi/session：`link object -> probe set -> BPF`
这说明 attach 模型正在从“事件驱动”走向“对象驱动”。 ---

## 5. `bpf_link` 生命周期管理
attach 成功只是开始； 真正让 libbpf attach 机制稳定可用的是 `bpf_link` 生命周期 API。

## 5.1 生命周期总览

```text
创建 link
    ↓
使用 fd / pin / update
    ↓
可选 disconnect
    ↓
detach 或 destroy

```
更细化地说：

```text
attach_xxx() / 显式 attach API
    ↓
分配 struct bpf_link 或其派生结构
    ↓
设置 detach / dealloc / fd
    ↓
返回给用户
    ↓
用户可调用：
- bpf_link__fd()；bpf_link__pin()；bpf_link__unpin()；bpf_link__update_program()；bpf_link__update_map()   (struct_ops)；bpf_link__disconnect()；bpf_link__detach()；bpf_link__destroy()

```

## 5.2 `bpf_link__fd()` / `bpf_link__pin_path()`
定义位于：
- `11273-11276`：`bpf_link__fd()`；`11278-11281`：`bpf_link__pin_path()`
语义非常直接：
- `bpf_link__fd()` 返回当前 `link->fd`；`bpf_link__pin_path()` 返回已 pin 路径。
注意：
- 对于 perf/ioctl fallback，这个 fd 可能不是“真实 link fd”；对旧式 struct_ops，它甚至可能是 map fd。
因此，**`bpf_link__fd()` 返回的是 libbpf 句柄持有的底层 fd，不保证一定是内核 BPF link 类型 fd。**

## 5.3 `bpf_link__pin()` / `bpf_link__unpin()`
源码：
- `11322-11347`：pin；`11349-11362`：unpin

### pin 流程
1. 检查 `link->pin_path` 尚未存在； 2. `make_parent_dir(path)`； 3. `check_path(path)`； 4. `link->pin_path = strdup(path)`； 5. `bpf_obj_pin(link->fd, path)`。

### unpin 流程
1. 校验 `pin_path` 存在； 2. `unlink(pin_path)`； 3. 清空 `link->pin_path`。

### 语义注意点
只有当底层 fd 真正可被 `bpf_obj_pin()` pin 时，pin 才成立。 因此：
- 真实 BPF link fd：pin 语义最自然；纯 perf event fd 或伪 link：pin 语义不如真实 BPF link 稳定。
这也是现代 attach 倾向使用 `BPF_LINK_CREATE` 的原因之一。

## 5.4 `bpf_link__detach()`
源码：`11317-11320` 实现：

```c
return bpf_link_detach(link->fd) ? -errno : 0;

```
这里要注意一个容易忽略的点：
- `bpf_link__detach()` 调用的是 `bpf_link_detach()` syscall wrapper；这是“主动 detach 一个真实 BPF link fd”的语义；它并不等价于 `destroy`。
对于没有真实内核 link fd 的 attach 结果，这个 API 的适用性取决于底层 fd 类型。

## 5.5 `bpf_link__disconnect()`
源码：`11249-11252` 实现非常简单：

```c
link->disconnected = true;

```
但语义很重。

### 5.5.1 disconnect 的含义
它表示：
- 用户态 `struct bpf_link` 对象不再拥有“自动撤销内核 attach”的责任；之后 `bpf_link__destroy()` 只释放用户态对象，不再执行 `detach()`。

### 5.5.2 适用场景
典型场景：
- 你已经把 link pin 到 bpffs；希望用户态进程退出时，内核 attach 继续存在；此时应先 pin，再 disconnect，再 destroy 用户态对象。
这套语义是现代 link 模型非常重要的能力。

## 5.6 `bpf_link__destroy()`
源码：`11254-11270` 流程：
1. `IS_ERR_OR_NULL(link)` 直接返回； 2. 若 `!disconnected && detach != NULL`，执行 `link->detach(link)`； 3. 释放 `pin_path`； 4. 若有 `dealloc`，调类型特定析构； 5. 否则 `free(link)`。

### 5.6.1 destroy 与 detach 的关系
- `detach` 是“撤销内核 attach”；`destroy` 是“销毁 libbpf 用户态句柄”；正常情况下，destroy 会先 detach，再 free；但如果 `disconnect == true`，destroy 就只 free，不 detach。

### 5.6.2 为什么 `dealloc` 单独存在
因为某些 link 类型有额外资源。 例如 `bpf_link_perf`：
- 除了基础 `bpf_link`，还持有 `perf_event_fd`；可能还持有 `legacy_probe_name`；因此需要 `bpf_link_perf_dealloc()`。

## 5.7 perf link 的特化生命周期
扩展结构 `struct bpf_link_perf` 定义在 `11365-11372`：

```c
struct bpf_link_perf {
    struct bpf_link link;
    int perf_event_fd;
    char *legacy_probe_name;
    bool legacy_is_kprobe;
    bool legacy_is_retprobe;
};

```

### 5.7.1 `bpf_link_perf_detach()`
位于 `11377-11401`。 逻辑：
1. `ioctl(perf_event_fd, PERF_EVENT_IOC_DISABLE)`； 2. 若 `perf_event_fd != link->fd`，关闭 perf_event_fd； 3. 关闭 `link->fd`； 4. 如果有 `legacy_probe_name`：
- kprobe 走 `remove_kprobe_event_legacy()`；uprobe 走 `remove_uprobe_event_legacy()`。
这说明 perf attach 的 detach 复杂度明显高于纯 link attach。

### 5.7.2 `bpf_link_perf_dealloc()`
位于 `11403-11409`。 它只负责：
- `free(legacy_probe_name)`；`free(perf_link)`。
也就是说：
- detach 负责“关闭/撤销内核对象”；dealloc 负责“释放用户态内存”。

## 5.8 `bpf_link__update_program()`
源码：`11224-11236` 调用链：

```text
bpf_link__update_program()
  → bpf_link_update(link_fd, new_prog_fd, NULL)

```
底层系统调用：
- `bpf(BPF_LINK_UPDATE, ...)`
适用场景：
- 对于支持 replace/update 的 link 类型，原位切换 program；避免先 detach 再重挂的窗口期。

## 5.9 `bpf_link__update_map()`：struct_ops 专属 update
源码：`13700-13735`。 它做两件事：
1. 准备新 struct_ops map value； 2. 调 `bpf_link_update(link->fd, map->fd, NULL)` 完成切换。
这说明在 libbpf 里，`update` 不只是 program replacement； 它还可以是 map-backed struct_ops replacement。

## 5.10 生命周期管理的总体结论
`bpf_link` 让 attach 从“一次性动作”升级成“可管理对象”。 这带来四个工程收益：
1. 可安全销毁； 2. 可 pin 持久化； 3. 可 update； 4. 可显式放弃所有权（disconnect）。
这也是现代 BPF attach API 的核心方向。 ---

## 6. 与内核交互的底层机制对照
下面把 libbpf attach 机制按“用户态入口 / 内核原语 / 典型内核处理函数”做一次收敛。
> 说明：内核侧函数名会随内核版本和子系统重构略有差异；下表列的是当前主线内核中最典型的入口或实现点。
| libbpf attach 类型 | 用户态入口 | 用户态底层原语 | 典型内核入口/处理函数 | 备注 |
|---|---|---|---|---|
| kprobe legacy | `bpf_program__attach_kprobe_opts()` | 写 `kprobe_events` + `perf_event_open` + `PERF_EVENT_IOC_SET_BPF` | tracefs kprobe event 注册 + `__do_sys_perf_event_open()` + perf ioctl | 最老路径 |
| kprobe perf | `bpf_program__attach_kprobe_opts()` | `perf_event_open(kprobe PMU)` + `SET_BPF` | `__do_sys_perf_event_open()` + perf kprobe PMU | 无 tracefs 动态 event |
| kprobe link | `bpf_program__attach_kprobe_opts()` | `perf_event_open` + `BPF_LINK_CREATE(BPF_PERF_EVENT)` | `__do_sys_perf_event_open()` + `kernel/bpf/syscall.c:link_create()` | 现代路径 |
| ksyscall | `bpf_program__attach_ksyscall()` | 同 kprobe | 同 kprobe | 只是多一层 syscall wrapper 符号解析 |
| uprobe legacy | `bpf_program__attach_uprobe_opts()` | 写 `uprobe_events` + `perf_event_open` + `SET_BPF` | tracefs uprobes event 注册 + `__do_sys_perf_event_open()` | 最老路径 |
| uprobe perf | `bpf_program__attach_uprobe_opts()` | `perf_event_open(uprobe PMU)` + `SET_BPF` | `__do_sys_perf_event_open()` + perf uprobes PMU | 支持 pid/filter/ref_ctr |
| uprobe link | `bpf_program__attach_uprobe_opts()` | `perf_event_open` + `BPF_LINK_CREATE(BPF_PERF_EVENT)` | `__do_sys_perf_event_open()` + `link_create()` | 现代路径 |
| USDT | `bpf_program__attach_usdt()` | 由 USDT manager 展开成若干 uprobe attach | 最终仍进 uprobes / perf link / legacy uprobes | USDT 本身不是新 syscall |
| tracepoint | `bpf_program__attach_tracepoint_opts()` | `perf_event_open(PERF_TYPE_TRACEPOINT)` + link/ioctl | `__do_sys_perf_event_open()` + perf ioctl 或 `link_create()` | 标准 trace event |
| raw tracepoint | `bpf_program__attach_raw_tracepoint_opts()` | `BPF_RAW_TRACEPOINT_OPEN` | `kernel/bpf/syscall.c` raw tp open 路径 | 不依赖 perf_event |
| tp_btf | `bpf_program__attach_trace()` | `BPF_LINK_CREATE(BPF_TRACE_RAW_TP)` | `link_create()` + tracing attach | BTF 版 raw tp |
| fentry/fexit/fmod_ret | `bpf_program__attach_trace()` | `BPF_LINK_CREATE(BPF_TRACE_*)` | `link_create()` + trampoline attach | trampoline 核心路径 |
| freplace | `bpf_program__attach_freplace()` | `BPF_LINK_CREATE` 或旧核 fallback | `link_create()` + EXT/trampoline attach | 可指定 `target_fd + target_btf_id` |
| LSM | `bpf_program__attach_lsm()` | `BPF_LINK_CREATE(BPF_LSM_MAC)` | `link_create()` + LSM trampoline attach | 直接挂安全 hook |
| iter | `bpf_program__attach_iter()` | `BPF_LINK_CREATE(BPF_TRACE_ITER)` | `kernel/bpf/bpf_iter.c: bpf_iter_link_attach()` | 后续还要 `BPF_ITER_CREATE` |
| XDP（link API） | `bpf_program__attach_xdp()` | `BPF_LINK_CREATE(BPF_XDP)` | `link_create()` + XDP link attach | 当前 `libbpf.c` 路径 |
| XDP（netlink API） | `bpf_xdp_attach()` | `RTM_SETLINK + IFLA_XDP` | `rtnetlink` → `dev_change_xdp_fd()` | 传统 device-centric API |
| TC 经典 | `bpf_tc_attach()` | `RTM_NEWTFILTER + TCA_BPF_*` | rtnetlink tc filter 路径 | 经典 netlink attach |
| tcx | `bpf_program__attach_tcx()` | `BPF_LINK_CREATE(BPF_TCX_*)` | `link_create()` + tcx 子系统 | 支持 relative revision |
| netkit | `bpf_program__attach_netkit()` | `BPF_LINK_CREATE(BPF_NETKIT_*)` | `link_create()` + netkit 子系统 | 网络新 attach 类型 |
| cgroup link | `bpf_program__attach_cgroup()` | `BPF_LINK_CREATE` | `link_create()` + `kernel/bpf/cgroup.c: cgroup_bpf_attach()` | 现代 cgroup attach |
| cgroup old | `bpf_prog_attach_opts()` | `BPF_PROG_ATTACH` | `cgroup_bpf_prog_attach()` | 旧接口仍存在 |
| struct_ops | `bpf_map__attach_struct_ops()` | `BPF_MAP_UPDATE_ELEM`，可选 `BPF_LINK_CREATE(BPF_STRUCT_OPS)` | `bpf_map_update_value()` → `bpf_struct_ops_map_update_elem()` / `bpf_struct_ops_link_create()` | map 驱动的 attach |
| kprobe_multi | `bpf_program__attach_kprobe_multi_opts()` | `BPF_LINK_CREATE(BPF_TRACE_KPROBE_MULTI)` | `link_create()` + multi-kprobe attach | 一个 link 绑定多点 |
| kprobe.session | `bpf_program__attach_kprobe_multi_opts(...session)` | `BPF_LINK_CREATE(BPF_TRACE_KPROBE_SESSION)` | `link_create()` + session attach | session 语义 |
| uprobe_multi | `bpf_program__attach_uprobe_multi()` | `BPF_LINK_CREATE(BPF_TRACE_UPROBE_MULTI)` | `link_create()` + multi-uprobe attach | 批量 file offsets |
| uprobe.session | `bpf_program__attach_uprobe_multi(...session)` | `BPF_LINK_CREATE(BPF_TRACE_UPROBE_SESSION)` | `link_create()` + session attach | 批量用户态探针 |

### 6.1 一个统一视角：attach backend 其实只有几类
尽管 libbpf attach API 很多，但底层原语其实主要就这几种：
1. `perf_event_open` 2. `ioctl(PERF_EVENT_IOC_*)` 3. `bpf(BPF_LINK_CREATE)` 4. `bpf(BPF_RAW_TRACEPOINT_OPEN)` 5. `bpf(BPF_PROG_ATTACH)` 6. `bpf(BPF_MAP_UPDATE_ELEM)` 7. `NETLINK_ROUTE` 消息
libbpf 的工作，就是把不同 SEC()/target/API 组合映射到这些原语之一。

### 6.2 attach backend 的收敛趋势
从新接口设计可以明显看出：
- tracing 家族在向 `BPF_LINK_CREATE` 收敛；network 家族在向 `BPF_LINK_CREATE` 收敛；cgroup 家族也在向 `BPF_LINK_CREATE` 收敛；只有兼容性和历史负担较重的领域，仍保留 perf ioctl 或 netlink 旧路径。
---

## 7. 版本演进：legacy → perf → link
attach 机制的演进主线，可以概括为：

```text
字符串/tracefs 时代
    ↓
perf event 时代
    ↓
BPF link 时代

```

## 7.1 第一阶段：legacy 时代
代表：
- kprobe legacy；uprobe legacy
做法：
1. 在 tracefs/debugfs 中创建动态 event； 2. 通过 event id 建 perf event； 3. 再把 BPF 程序挂进去。
优点：
- 能在老内核工作；借助已有 tracing 基础设施。
缺点：
- 对 tracefs 有副作用；资源生命周期分散在多个对象上；需要手工清理 event；pin / update / ownership 语义薄弱。

## 7.2 第二阶段：perf PMU 时代
代表：
- kprobe perf；uprobe perf；tracepoint perf attach
做法：
- 直接 `perf_event_open()` 创建可探测对象；通过 `PERF_EVENT_IOC_SET_BPF` 绑定程序。
相对 legacy 的改进：
- 少了一层 tracefs 动态 event 管理；kprobe/uprobe 通过专用 PMU 更直接；对性能与资源管理更友好。
但仍有局限：
- attach 生命周期依赖 perf fd；用户态对象不是统一的 link；pin/update/disconnect 都不够自然。

## 7.3 第三阶段：BPF link 时代
代表：
- fentry/fexit/fmod_ret/lsm/iter；kprobe/uprobe 的 PERF_LINK 模式；xdp link API；cgroup link；tcx；netkit；multi-kprobe / multi-uprobe；struct_ops real link
做法：
- 用 `BPF_LINK_CREATE` 直接建立“attach 关系对象”；用户态统一用 `struct bpf_link` 管理它。
相对 perf 时代的改进：
1. **对象语义清晰**：attach 关系本身就是内核对象； 2. **生命周期统一**：detach / destroy / pin / update 都有标准模型； 3. **可持久化**：pin 到 bpffs； 4. **可替换**：`BPF_LINK_UPDATE`； 5. **多种 hook 收敛到同一 syscall 家族**。

## 7.4 为什么 libbpf 仍保留旧路径
因为 libbpf 需要同时满足：
- 向后兼容老内核；向前支持新 hook；给用户稳定 API。
所以源码里常见这种模式：
- 能用 link 就优先 link；不行就退 perf ioctl；再不行就退 legacy；甚至对某些 attach type 自动 fallback 到 raw tracepoint。
这正是 `bpf_program__attach_perf_event_opts()` 与 `bpf_program__attach_btf_id()` 中“先尝试 modern path，再 fallback”的设计原因。

## 7.5 未来方向
从当前代码趋势看，attach 机制未来大概率继续朝以下方向发展：
1. 更多 hook 迁移到 `BPF_LINK_CREATE`； 2. 旧式 perf ioctl / tracefs attach 继续保留，但更多退居兼容层； 3. 网络 attach 进一步从 netlink old-style 迁到 link-based API； 4. `bpf_link` 成为 attach 生命周期的唯一中心对象。
---

## 8. 总结：如何理解 libbpf attach 机制
如果把 libbpf attach 机制压缩成一句话，可以这样概括： **libbpf 用 `section_defs[]` 把 SEC() 解释成 attach 语义，用一组 `attach_xxx()` / 显式 attach helper 把这些语义翻译成 perf_event、BPF link、netlink 或 map update，再用 `bpf_link` 统一管理 attach 结果的生命周期。** 进一步拆开，它有五个关键设计点：
1. **表驱动**：
- `section_defs[]` 不是文档，而是 attach 行为目录；
2. **分层清晰**：
- generic attach 负责路由；具体 helper 负责 attach backend；
3. **兼容性强**：
- legacy / perf / link 三代机制并存；
4. **对象化管理**：
- `bpf_link` 统一承载 pin/update/detach/destroy；
5. **持续向 link 收敛**：
- 新 attach 类型几乎都优先使用 `BPF_LINK_CREATE`。
从源码角度看，`libbpf.c:9965-13735` 这一大段代码其实就是 libbpf attach 子系统的核心：
- 上半段定义 attach family 的目录和 backend helper；中段实现 perf_event / kprobe / uprobe / tracepoint / BTF attach；下半段统一到 `bpf_program__attach()`、`bpf_program_attach_fd()`、`bpf_link` 生命周期管理。
因此，理解 libbpf attach，最重要的不是记住某一个 API 名字； 而是记住下面这个统一公式：

```text
SEC() / API 参数
    ↓
sec_def / expected_attach_type / target_fd
    ↓
选择 attach backend
    ↓
得到 bpf_link
    ↓
用统一生命周期接口管理它

```
一旦理解这条主线，kprobe、uprobe、tracepoint、LSM、XDP、cgroup、struct_ops、iter 看似分散，实际上都只是同一 attach 框架下的不同 backend。 ---

## 9. 附：关键源码索引

### 9.1 核心结构
- `src/libbpf_internal.h:191-197`：`struct bpf_link`；`src/libbpf.c:424-434`：`struct bpf_sec_def`；`src/libbpf.c:9978-10084`：`section_defs[]`

### 9.2 通用 lifecycle
- `src/libbpf.c:11224-11236`：`bpf_link__update_program`；`src/libbpf.c:11249-11252`：`bpf_link__disconnect`；`src/libbpf.c:11254-11270`：`bpf_link__destroy`；`src/libbpf.c:11273-11276`：`bpf_link__fd`；`src/libbpf.c:11317-11320`：`bpf_link__detach`；`src/libbpf.c:11322-11347`：`bpf_link__pin`；`src/libbpf.c:11349-11362`：`bpf_link__unpin`

### 9.3 perf_event 家族
- `src/libbpf.c:11411-11487`：`bpf_program__attach_perf_event_opts`；`src/libbpf.c:11521-11526`：`determine_kprobe_perf_type`；`src/libbpf.c:11528-11533`：`determine_uprobe_perf_type`；`src/libbpf.c:11552-11596`：`perf_event_open_probe`；`src/libbpf.c:11703-11747`：`perf_event_kprobe_open_legacy`；`src/libbpf.c:11806-11900`：`bpf_program__attach_kprobe_opts`；`src/libbpf.c:12756-12890`：`bpf_program__attach_uprobe_opts`；`src/libbpf.c:13067-13097`：`perf_event_open_tracepoint`；`src/libbpf.c:13099-13129`：`bpf_program__attach_tracepoint_opts`

### 9.4 generic attach 函数
- `src/libbpf.c:12271-12306`：`attach_kprobe`；`src/libbpf.c:12308-12327`：`attach_ksyscall`；`src/libbpf.c:12329-12358`：`attach_kprobe_multi`；`src/libbpf.c:12360-12384`：`attach_kprobe_session`；`src/libbpf.c:12386-12417`：`attach_uprobe_multi`；`src/libbpf.c:12902-12955`：`attach_uprobe`；`src/libbpf.c:13020-13047`：`attach_usdt`；`src/libbpf.c:13139-13169`：`attach_tp`；`src/libbpf.c:13214-13253`：`attach_raw_tp`；`src/libbpf.c:13307-13310`：`attach_trace`；`src/libbpf.c:13313-13316`：`attach_lsm`；`src/libbpf.c:13550-13554`：`attach_iter`；`src/libbpf.c:13596-13623`：`bpf_program__attach`

### 9.5 显式 attach API
- `src/libbpf.c:12153-12269`：`bpf_program__attach_kprobe_multi_opts`；`src/libbpf.c:12628-12753`：`bpf_program__attach_uprobe_multi`；`src/libbpf.c:12967-13018`：`bpf_program__attach_usdt`；`src/libbpf.c:13256-13289`：`bpf_program__attach_btf_id`；`src/libbpf.c:13319-13351`：`bpf_program_attach_fd`；`src/libbpf.c:13354-13357`：`bpf_program__attach_cgroup`；`src/libbpf.c:13371-13375`：`bpf_program__attach_xdp`；`src/libbpf.c:13377-13403`：`bpf_program__attach_cgroup_opts`；`src/libbpf.c:13406-13438`：`bpf_program__attach_tcx`；`src/libbpf.c:13441-13472`：`bpf_program__attach_netkit`；`src/libbpf.c:13474-13509`：`bpf_program__attach_freplace`；`src/libbpf.c:13512-13548`：`bpf_program__attach_iter`；`src/libbpf.c:13644-13695`：`bpf_map__attach_struct_ops`；`src/libbpf.c:13700-13735`：`bpf_link__update_map`

### 9.6 补充网络与旧接口
- `src/netlink.c:288-339`：XDP netlink attach；`src/netlink.c:734-806`：经典 `bpf_tc_attach`；`src/bpf.c:650-677`：`BPF_PROG_ATTACH` 封装；`src/bpf.c:893-924`：`BPF_LINK_CREATE` 与旧 attach fallback；`src/bpf.c:940-963`：`BPF_LINK_UPDATE`
