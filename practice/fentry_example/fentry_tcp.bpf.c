// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* 记录进入 tcp_sendmsg 时的上下文，供 fexit 阶段补全返回值。 */
struct inflight_event {
__u32 pid;
__u32 family;
__u16 sport;
__u16 dport;
__u32 saddr_v4;
__u32 daddr_v4;
__u8 saddr_v6[16];
__u8 daddr_v6[16];
__u64 bytes_sent;
char comm[16];
};

/* 输出到用户态的 TCP 发送事件。 */
struct event {
__u32 pid;
__u32 family;
__u16 sport;
__u16 dport;
__u32 saddr_v4;
__u32 daddr_v4;
__u8 saddr_v6[16];
__u8 daddr_v6[16];
__u64 bytes_sent;
__s32 return_value;
char comm[16];
};

struct {
__uint(type, BPF_MAP_TYPE_HASH);
__uint(max_entries, 10240);
__type(key, __u64);
__type(value, struct inflight_event);
} inflight SEC(".maps");

struct {
__uint(type, BPF_MAP_TYPE_RINGBUF);
__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int fill_tuple(struct sock *sk, struct inflight_event *e)
{
__u16 family;

family = BPF_CORE_READ(sk, __sk_common.skc_family);
if (family != AF_INET && family != AF_INET6)
return -1;

e->family = family;
e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
if (family == AF_INET) {
e->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
e->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
} else {
BPF_CORE_READ_INTO(e->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
BPF_CORE_READ_INTO(e->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
}

return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t size)
{
struct inflight_event e = {};
__u64 id;

(void)msg;
if (!sk)
return 0;

if (fill_tuple(sk, &e) < 0)
return 0;

id = bpf_get_current_pid_tgid();
e.pid = id >> 32;
e.bytes_sent = size;
bpf_get_current_comm(&e.comm, sizeof(e.comm));
bpf_map_update_elem(&inflight, &id, &e, BPF_ANY);
return 0;
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(handle_tcp_sendmsg_exit, struct sock *sk, struct msghdr *msg, size_t size, int ret)
{
struct inflight_event *inflight_event;
struct event *e;
__u64 id;

(void)sk;
(void)msg;
(void)size;
id = bpf_get_current_pid_tgid();
inflight_event = bpf_map_lookup_elem(&inflight, &id);
if (!inflight_event)
return 0;

e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e)
goto out;

e->pid = inflight_event->pid;
e->family = inflight_event->family;
e->sport = inflight_event->sport;
e->dport = inflight_event->dport;
e->saddr_v4 = inflight_event->saddr_v4;
e->daddr_v4 = inflight_event->daddr_v4;
__builtin_memcpy(e->saddr_v6, inflight_event->saddr_v6, sizeof(e->saddr_v6));
__builtin_memcpy(e->daddr_v6, inflight_event->daddr_v6, sizeof(e->daddr_v6));
e->bytes_sent = inflight_event->bytes_sent;
e->return_value = ret;
__builtin_memcpy(e->comm, inflight_event->comm, sizeof(e->comm));
bpf_ringbuf_submit(e, 0);

out:
bpf_map_delete_elem(&inflight, &id);
return 0;
}
