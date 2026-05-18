// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";

/* 记录 tcp_connect 时的地址和端口信息。 */

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

struct event {
__u32 pid;
__u32 family;
__u16 sport;
__u16 dport;
__u32 saddr_v4;
__u32 daddr_v4;
__u8 saddr_v6[16];
__u8 daddr_v6[16];
char comm[16];
};

struct {
__uint(type, BPF_MAP_TYPE_RINGBUF);
__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int handle_tcp_connect(struct pt_regs *ctx)
{
struct sock *sk;
struct event *e;
__u16 family;

sk = (struct sock *)PT_REGS_PARM1(ctx);
if (!sk)
return 0;

family = BPF_CORE_READ(sk, __sk_common.skc_family);
if (family != AF_INET && family != AF_INET6)
return 0;

e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e)
return 0;

e->pid = bpf_get_current_pid_tgid() >> 32;
e->family = family;
e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
bpf_get_current_comm(&e->comm, sizeof(e->comm));

if (family == AF_INET) {
e->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
e->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
} else {
BPF_CORE_READ_INTO(e->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
BPF_CORE_READ_INTO(e->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
}

bpf_ringbuf_submit(e, 0);
return 0;
}
