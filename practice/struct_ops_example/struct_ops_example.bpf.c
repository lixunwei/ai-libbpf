// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "GPL";

/* 演示如何使用 icsk_ca_priv 保存自定义拥塞控制状态。 */
struct aimd_ca {
	__u32 acked_accum;
	__u32 loss_events;
};

static __always_inline struct tcp_sock *tcp_sk_local(struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

static __always_inline struct aimd_ca *aimd_ca_local(struct sock *sk)
{
	struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;

	return (struct aimd_ca *)icsk->icsk_ca_priv;
}

SEC("struct_ops")
void BPF_PROG(simple_aimd_init, struct sock *sk)
{
	struct aimd_ca *ca = aimd_ca_local(sk);

	ca->acked_accum = 0;
	ca->loss_events = 0;
}

/* 慢启动阶段快速增长，拥塞避免阶段按 ACK 数做加性增大。 */
SEC("struct_ops")
void BPF_PROG(simple_aimd_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
	struct tcp_sock *tp = tcp_sk_local(sk);
	struct aimd_ca *ca = aimd_ca_local(sk);
	__u32 cwnd;
	__u32 clamp;
	__u32 delta;
	__u32 new_cwnd;

	(void)ack;
	if (!tp->is_cwnd_limited || !acked)
		return;

	cwnd = tp->snd_cwnd ? tp->snd_cwnd : 1;
	clamp = tp->snd_cwnd_clamp ? tp->snd_cwnd_clamp : cwnd;
	if (cwnd < tp->snd_ssthresh) {
		new_cwnd = cwnd + acked;
		if (new_cwnd > clamp)
			new_cwnd = clamp;
		tp->snd_cwnd = new_cwnd;
		return;
	}

	ca->acked_accum += acked;
	if (ca->acked_accum < cwnd)
		return;

	delta = ca->acked_accum / cwnd;
	ca->acked_accum -= delta * cwnd;
	new_cwnd = tp->snd_cwnd + delta;
	if (new_cwnd > clamp)
		new_cwnd = clamp;
	tp->snd_cwnd = new_cwnd;
}

/* 发生丢包时执行乘性减小，并重置拥塞避免阶段的累计 ACK。 */
SEC("struct_ops")
__u32 BPF_PROG(simple_aimd_ssthresh, struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk_local(sk);
	struct aimd_ca *ca = aimd_ca_local(sk);
	__u32 new_ssthresh = tp->snd_cwnd >> 1;

	ca->acked_accum = 0;
	ca->loss_events++;
	if (new_ssthresh < 2)
		new_ssthresh = 2;
	return new_ssthresh;
}

/* 误判丢包时恢复到更大的拥塞窗口。 */
SEC("struct_ops")
__u32 BPF_PROG(simple_aimd_undo_cwnd, struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk_local(sk);

	return tp->prior_cwnd > tp->snd_cwnd ? tp->prior_cwnd : tp->snd_cwnd;
}

SEC(".struct_ops")
struct tcp_congestion_ops simple_aimd = {
	.init = (void *)simple_aimd_init,
	.cong_avoid = (void *)simple_aimd_cong_avoid,
	.ssthresh = (void *)simple_aimd_ssthresh,
	.undo_cwnd = (void *)simple_aimd_undo_cwnd,
	.name = "bpf_aimd",
};
