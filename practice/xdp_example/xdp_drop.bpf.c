// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";
/* drop_port 为 0 时仅统计，不丢包。 */
const volatile __u16 drop_port = 0;

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct datarec {
	__u64 packets;
	__u64 drops;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct datarec);
} xdp_stats SEC(".maps");

static __always_inline void count_packet(struct datarec *rec)
{
	if (rec)
		rec->packets++;
}

static __always_inline void count_drop(struct datarec *rec)
{
	if (rec)
		rec->drops++;
}

static __always_inline int parse_dport(void *data, void *data_end, __u8 proto, __u16 *dport)
{
	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcp = data;

		if ((void *)(tcp + 1) > data_end)
			return -1;
		*dport = bpf_ntohs(tcp->dest);
		return 0;
	}

	if (proto == IPPROTO_UDP) {
		struct udphdr *udp = data;

		if ((void *)(udp + 1) > data_end)
			return -1;
		*dport = bpf_ntohs(udp->dest);
		return 0;
	}

	return -1;
}

SEC("xdp")
int xdp_drop_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct datarec *rec;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	__u32 key = 0;
	__u16 dport;

	rec = bpf_map_lookup_elem(&xdp_stats, &key);
	count_packet(rec);

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;
	if (!drop_port)
		return XDP_PASS;

	if (parse_dport((void *)iph + iph->ihl * 4, data_end, iph->protocol, &dport) < 0)
		return XDP_PASS;
	if (dport != drop_port)
		return XDP_PASS;

	count_drop(rec);
	return XDP_DROP;
}
