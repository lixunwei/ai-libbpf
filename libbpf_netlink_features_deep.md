# libbpf Netlink 通信层与内核特性探测深度分析

## 0. 分析范围

- `src/netlink.c`
- `src/nlattr.c`（并补充 `src/nlattr.h` 中的编码辅助）
- `src/features.c`
- `src/libbpf_probes.c`
- 补充结构：`src/libbpf_internal.h:350-416`

---

## 1. `netlink.c + nlattr.c`：Netlink 通信基础

### 1.1 Netlink 抽象层分工

- `netlink.c`：负责 **socket、send/recv、XDP/TC 业务消息**；
- `nlattr.c`：负责 **TLV 属性解析与校验**；
- `nlattr.h`：提供 **编码辅助**（`nlattr_add()` / nested begin/end）。

关键结构：

- `struct libbpf_nla_req`：`nlattr.h:57-65`
- `struct libbpf_nla_policy`：`nlattr.h:46-55`
- `struct xdp_link_info`：`netlink.c:31-37`
- `struct xdp_id_md`：`netlink.c:39-44`
- `struct xdp_features_md`：`netlink.c:46-50`

### 1.2 消息发送/接收主流程

#### 打开 socket

`libbpf_netlink_open()`（`netlink.c:52-93`）流程：

1. `socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, proto)`；
2. 尝试开启 `NETLINK_EXT_ACK`；
3. `bind()`；
4. `getsockname()` 取回内核分配的 `nl_pid`。

#### 收发封装

- `libbpf_netlink_send_recv()`：`netlink.c:224-249`
- `libbpf_netlink_recv()`：`netlink.c:132-221`

`send_recv()` 只做三件事：

1. 打开 socket；
2. 给 `nlmsg_seq` 填 `time(NULL)`；
3. `send()` 后进入 `libbpf_netlink_recv()`。

`libbpf_netlink_recv()` 的关键检查：

- `nlmsg_pid` 必须匹配；
- `nlmsg_seq` 必须匹配；
- `NLMSG_ERROR` 统一转成负 errno；
- 若有 ACK TLV，则调用 `libbpf_nla_dump_errormsg()` 打印内核扩展错误。

### 1.3 nlattr 编解码

#### 解码

- `libbpf_nla_parse()`：`nlattr.c:104-133`
- `libbpf_nla_parse_nested()`：`nlattr.c:148-154`
- `validate_nla()`：`nlattr.c:45-79`

它们遵循标准 Netlink TLV：

- `nla_type`
- `nla_len`
- payload

并通过 `policy` 做最小/最大长度和字符串 NUL 终止校验。

#### 编码

真正的编码 helper 在 `nlattr.h`：

- `nlattr_add()`：`nlattr.h:141-158`
- `nlattr_begin_nested()`：`nlattr.h:160-168`
- `nlattr_end_nested()`：`nlattr.h:170-174`

这套接口直接操作 `struct libbpf_nla_req` 的尾部，逐步推进 `req->nh.nlmsg_len`。

代码片段：

```c
/* nlattr.h:146-156 */
if (NLMSG_ALIGN(req->nh.nlmsg_len) + NLA_ALIGN(NLA_HDRLEN + len) > sizeof(*req))
    return -EMSGSIZE;
...
req->nh.nlmsg_len = NLMSG_ALIGN(req->nh.nlmsg_len) + NLA_ALIGN(nla->nla_len);
```

这说明 libbpf 的 Netlink builder 是“**固定小 buffer + 逐属性追加**”模型。

---

## 2. XDP 程序 attach/query

### 2.1 attach：generic / native / offloaded

XDP 的附加入口是：

- `__bpf_set_link_xdp_fd_replace()`：`netlink.c:288-322`
- `bpf_xdp_attach()`：`netlink.c:324-339`
- `bpf_xdp_detach()`：`netlink.c:341-344`

`bpf_xdp_attach()` 只负责处理 `old_prog_fd → XDP_FLAGS_REPLACE`，真正发消息的是 `__bpf_set_link_xdp_fd_replace()`。

消息构造要点：

- `RTM_SETLINK`
- `ifinfomsg.ifi_index = ifindex`
- 嵌套属性 `IFLA_XDP`
  - `IFLA_XDP_FD`
  - `IFLA_XDP_FLAGS`
  - `IFLA_XDP_EXPECTED_FD`（替换时）

XDP attach mode 的意义：

- `XDP_FLAGS_SKB_MODE`：generic / skb path
- `XDP_FLAGS_DRV_MODE`：native / driver path
- `XDP_FLAGS_HW_MODE`：offloaded / NIC 硬件卸载

### 2.2 query

- `get_xdp_info()`：`netlink.c:362-405`
- `bpf_xdp_query()`：`netlink.c:433-506`
- `bpf_xdp_query_id()`：`netlink.c:508-530`

`bpf_xdp_query()` 先通过 `RTM_GETLINK` 解析 `IFLA_XDP_*` 属性，再可选通过 generic netlink `netdev` family 追加抓取 feature flags。

---

## 3. TC BPF attach

### 3.1 qdisc 管理

- `tc_qdisc_modify()`：`netlink.c:597-619`
- `tc_qdisc_create_excl()`：`netlink.c:621-624`
- `bpf_tc_hook_create()`：`netlink.c:631-641`
- `bpf_tc_hook_destroy()`：`netlink.c:647-665`

对于 ingress/egress，libbpf 默认使用 `clsact`。`attach_point_to_config()`（`netlink.c:554-573`）会把 `BPF_TC_INGRESS/BPF_TC_EGRESS` 统一映射为 `clsact` qdisc 语义。

### 3.2 filter attach

`bpf_tc_attach()`（`netlink.c:734-806`）是 TC attach 的核心入口。重要字段：

- `RTM_NEWTFILTER`
- `tcm_ifindex`
- `tcm_parent`（由 `tc_get_tcm_parent()` 计算）
- `tcm_info = priority + protocol`
- `TCA_KIND = "bpf"`
- `TCA_OPTIONS`
  - `TCA_BPF_FD`
  - `TCA_BPF_NAME`
  - `TCA_BPF_FLAGS = TCA_BPF_FLAG_ACT_DIRECT`

`get_tc_info()` / `__get_tc_info()`（`netlink.c:672-709`）负责从回包里提取：

- `prog_id`
- `handle`
- `priority`

### 3.3 detach / query

- `__bpf_tc_detach()`：`netlink.c:808-867`
- `bpf_tc_detach()`：`netlink.c:869-879`
- `bpf_tc_query()`：`netlink.c:881-938`

detach 分两种：

1. 指定 `handle+priority` 删除单个 filter；
2. flush 模式清空 attach point。

---

## 4. `features.c + libbpf_probes.c`：内核特性探测

### 4.1 总体思想

libbpf 的特性探测并不依赖“读内核版本号猜功能”，而是走 **最小可执行探针**：

- 创建一个最小 map；
- 或加载一个最小程序；
- 或上传一个最小 BTF blob；
- 然后根据返回值/errno/验证器日志判断是否支持。

这比“版本表”更稳健，也能覆盖 backport 内核。

### 4.2 缓存结构

定义在 `libbpf_internal.h`：

- `enum kern_feature_id`：`libbpf_internal.h:350-401`
- `enum kern_feature_result`：`libbpf_internal.h:404-408`
- `struct kern_feature_cache`：`libbpf_internal.h:410-413`

```c
struct kern_feature_cache {
    enum kern_feature_result res[__FEAT_CNT];
    int token_fd;
};
```

缓存策略非常简单：

- `FEAT_UNKNOWN`：未探测；
- `FEAT_SUPPORTED`：已确认支持；
- `FEAT_MISSING`：已确认不支持，或探测失败时保守记为不支持。

### 4.3 顶层入口：`feat_supported()`

- **位置**：`features.c:704-727`
- **签名**：`bool feat_supported(struct kern_feature_cache *cache, enum kern_feature_id feat_id)`

逻辑：

1. 若无自定义 cache，则使用全局 `feature_cache`（`features.c:620`）；
2. 若状态是 `FEAT_UNKNOWN`，调用 `feature_probes[feat_id].probe(token_fd)`；
3. `ret > 0` → `FEAT_SUPPORTED`；
4. `ret == 0` → `FEAT_MISSING`；
5. `ret < 0` → 打警告并保守记为 `FEAT_MISSING`。

### 4.4 `features.c`：有哪些特性

`feature_probes[]` 表（`features.c:622-702`）列出了一批典型能力：

- `FEAT_GLOBAL_DATA`
- `FEAT_BTF`
- `FEAT_BTF_FUNC`
- `FEAT_BTF_DATASEC`
- `FEAT_ARRAY_MMAP`
- `FEAT_EXP_ATTACH_TYPE`
- `FEAT_PROBE_READ_KERN`
- `FEAT_BPF_COOKIE`
- `FEAT_UPROBE_MULTI_LINK`
- `FEAT_UPROBE_SYSCALL`
- `FEAT_BTF_LAYOUT`

### 4.5 程序类型支持如何探测

入口：`libbpf_probe_bpf_prog_type()`（`libbpf_probes.c:205-219`）

内部调用 `probe_prog_load()`（`libbpf_probes.c:103-203`）：

- 构造 2 条指令的最小程序：
  - `r0 = 0`
  - `exit`
- 再根据不同 `prog_type` 补齐：
  - `expected_attach_type`
  - `kern_version`
  - tracing/ext/lsm 的 `attach_btf_id`
- 如果加载成功，认为该程序类型支持。

### 4.6 Map 类型支持如何探测

入口：`libbpf_probe_bpf_map_type()`（`libbpf_probes.c:419-428`）

内部调用 `probe_map_create()`（`libbpf_probes.c:292-417`）：

- 按不同 map type 设置最小合法 `key_size/value_size/max_entries/flags`；
- 特殊处理 map-in-map、storage map、ringbuf、arena、struct_ops 等；
- 调 `bpf_map_create()`；
- 依据是否成功创建判断支持性。

### 4.7 Helper 支持如何探测

入口：`libbpf_probe_bpf_helper()`（`libbpf_probes.c:430-479`）

探测方式：

1. 构造一个只有 `CALL helper_id` + `EXIT` 的最小程序；
2. 调 `probe_prog_load()` 把 verifier log 收集到 `buf`；
3. 若日志含有：
   - `invalid func`
   - `unknown func`
   - `program of this type cannot use helper`
   则判定“不支持”；
4. 其他错误视为“helper 存在，只是参数/上下文不满足”。

这种实现非常实用：**探测目标是 helper 是否存在/允许，而不是最小程序一定要完全可运行**。

### 4.8 探测原理的三个典型例子

#### 例 1：全局数据支持

`probe_kern_global_data()`（`features.c:47-78`）会：

1. 创建一个 array map；
2. 构造 `BPF_LD_MAP_VALUE` 指令直接取 map value；
3. 若内核支持 global data/direct value relocation，则程序可加载。

#### 例 2：BTF 支持

`probe_kern_btf()`（`features.c:80-90`）上传最小 BTF blob；
`probe_kern_btf_func()` / `probe_kern_btf_datasec()` 等再逐个追加更高阶 kind。

#### 例 3：BPF cookie / multi-uprobe / uprobe syscall

- `probe_kern_bpf_cookie()`：`features.c:427-441`
- `probe_uprobe_multi_link()`：`features.c:362-425`
- `probe_uprobe_syscall()`：`features.c:577-589`

这些探针直接面向“新 attach 能力”，从而被 `usdt.c` 等模块复用。

---

## 5. 关键函数表

### 5.1 Netlink / nlattr

| 函数 | 位置 | 签名 | 核心逻辑 | 关键数据结构 |
|---|---|---|---|---|
| `libbpf_netlink_open` | `netlink.c:52` | `static int libbpf_netlink_open(__u32 *nl_pid, int proto)` | 建 AF_NETLINK socket，开启 EXT_ACK，绑定并返回 pid | `sockaddr_nl` |
| `libbpf_netlink_recv` | `netlink.c:132` | `static int libbpf_netlink_recv(int sock, __u32 nl_pid, int seq, __dump_nlmsg_t _fn, libbpf_dump_nlmsg_t fn, void *cookie)` | 接收多段消息、校验 pid/seq、处理 `NLMSG_ERROR/DONE` | `nlmsghdr`, `nlmsgerr` |
| `libbpf_netlink_send_recv` | `netlink.c:224` | `static int libbpf_netlink_send_recv(struct libbpf_nla_req *req, int proto, __dump_nlmsg_t parse_msg, libbpf_dump_nlmsg_t parse_attr, void *cookie)` | 统一收发封装 | `struct libbpf_nla_req` |
| `__bpf_set_link_xdp_fd_replace` | `netlink.c:288` | `static int __bpf_set_link_xdp_fd_replace(int ifindex, int fd, int old_fd, __u32 flags)` | 构造 `RTM_SETLINK + IFLA_XDP` 消息 | `ifinfomsg`, `nlattr` |
| `bpf_xdp_attach` | `netlink.c:324` | `int bpf_xdp_attach(int ifindex, int prog_fd, __u32 flags, const struct bpf_xdp_attach_opts *opts)` | 处理 replace 语义并发起 XDP attach | `bpf_xdp_attach_opts` |
| `bpf_xdp_query` | `netlink.c:433` | `int bpf_xdp_query(int ifindex, int xdp_flags, struct bpf_xdp_query_opts *opts)` | 查询 attach mode/prog id/feature_flags | `xdp_id_md`, `xdp_features_md` |
| `bpf_tc_hook_create` | `netlink.c:631` | `int bpf_tc_hook_create(struct bpf_tc_hook *hook)` | 创建 clsact/qdisc | `bpf_tc_hook` |
| `bpf_tc_attach` | `netlink.c:734` | `int bpf_tc_attach(const struct bpf_tc_hook *hook, struct bpf_tc_opts *opts)` | 构造 `RTM_NEWTFILTER + TCA_OPTIONS` 附加 BPF classifier | `bpf_tc_opts`, `tcmsg` |
| `bpf_tc_detach` | `netlink.c:869` | `int bpf_tc_detach(const struct bpf_tc_hook *hook, const struct bpf_tc_opts *opts)` | 删除单个 TC filter | `bpf_tc_opts` |
| `bpf_tc_query` | `netlink.c:881` | `int bpf_tc_query(const struct bpf_tc_hook *hook, struct bpf_tc_opts *opts)` | 查询已附加 filter 的 id/handle/priority | `bpf_cb_ctx` |
| `libbpf_nla_parse` | `nlattr.c:104` | `int libbpf_nla_parse(struct nlattr *tb[], int maxtype, struct nlattr *head, int len, struct libbpf_nla_policy *policy)` | 解码 TLV 并按 type 建索引表 | `nlattr`, `libbpf_nla_policy` |
| `libbpf_nla_parse_nested` | `nlattr.c:148` | `int libbpf_nla_parse_nested(struct nlattr *tb[], int maxtype, struct nlattr *nla, struct libbpf_nla_policy *policy)` | 解析 nested 属性 | `nlattr` |
| `libbpf_nla_dump_errormsg` | `nlattr.c:157` | `int libbpf_nla_dump_errormsg(struct nlmsghdr *nlh)` | 打印 Netlink extended ACK 错误 | `NLMSGERR_ATTR_MSG` |
| `nlattr_add` | `nlattr.h:141` | `static inline int nlattr_add(struct libbpf_nla_req *req, int type, const void *data, int len)` | 编码单个属性 | `struct libbpf_nla_req` |
| `nlattr_begin_nested` | `nlattr.h:160` | `static inline struct nlattr *nlattr_begin_nested(struct libbpf_nla_req *req, int type)` | 开始 nested 块 | `nlattr` |
| `nlattr_end_nested` | `nlattr.h:170` | `static inline void nlattr_end_nested(struct libbpf_nla_req *req, struct nlattr *tail)` | 回填 nested 属性总长度 | `nlattr` |

### 5.2 features / probes

| 函数 | 位置 | 签名 | 核心逻辑 | 关键数据结构 |
|---|---|---|---|---|
| `feat_supported` | `features.c:704` | `bool feat_supported(struct kern_feature_cache *cache, enum kern_feature_id feat_id)` | 延迟探测 + 结果缓存 | `struct kern_feature_cache` |
| `probe_kern_global_data` | `features.c:47` | `static int probe_kern_global_data(int token_fd)` | 构造最小 `BPF_LD_MAP_VALUE` 程序探测 global data | `bpf_prog_load_opts` |
| `probe_kern_btf` | `features.c:80` | `static int probe_kern_btf(int token_fd)` | 上传最小 BTF blob | `btf_header` |
| `probe_uprobe_multi_link` | `features.c:362` | `static int probe_uprobe_multi_link(int token_fd)` | 通过 `bpf_link_create(BPF_TRACE_UPROBE_MULTI)` 检测 multi-uprobe | `bpf_link_create_opts` |
| `probe_kern_bpf_cookie` | `features.c:427` | `static int probe_kern_bpf_cookie(int token_fd)` | 调 `BPF_FUNC_get_attach_cookie` 探测 cookie helper | `bpf_insn[]` |
| `probe_prog_load` | `libbpf_probes.c:103` | `static int probe_prog_load(enum bpf_prog_type prog_type, const struct bpf_insn *insns, size_t insns_cnt, char *log_buf, size_t log_buf_sz)` | 最小程序加载器；按 prog_type 补齐 attach type / kern_version 等 | `bpf_prog_load_opts` |
| `libbpf_probe_bpf_prog_type` | `libbpf_probes.c:205` | `int libbpf_probe_bpf_prog_type(enum bpf_prog_type prog_type, const void *opts)` | 对外程序类型探测 API | `bpf_insn[]` |
| `probe_map_create` | `libbpf_probes.c:292` | `static int probe_map_create(enum bpf_map_type map_type)` | 按 map 类型构造最小合法属性并调用 `bpf_map_create` | `bpf_map_create_opts` |
| `libbpf_probe_bpf_map_type` | `libbpf_probes.c:419` | `int libbpf_probe_bpf_map_type(enum bpf_map_type map_type, const void *opts)` | 对外 map 类型探测 API | `bpf_map_type` |
| `libbpf_probe_bpf_helper` | `libbpf_probes.c:430` | `int libbpf_probe_bpf_helper(enum bpf_prog_type prog_type, enum bpf_func_id helper_id, const void *opts)` | 通过 verifier log 判断 helper 是否存在/可用 | verifier log buffer |

---

## 6. 总结

- `netlink.c` 把 XDP/TC 这种“网络栈配置问题”统一翻译成 **RTNETLINK + NLA**；
- `nlattr.c/h` 提供了 libbpf 私有的 **小型 Netlink 编解码器**；
- `features.c + libbpf_probes.c` 则构成一个“**以最小 BPF 程序/Map/BTF 为探针**”的能力检测层；
- 这两层组合起来，决定了 libbpf 既能“说对内核听得懂的话”，也能“在真正加载前先知道内核会不会买账”。
