// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#endif

enum pkt_proto_index {
	PROTO_TCP = 0,
	PROTO_UDP,
	PROTO_ICMP,
	PROTO_OTHER,
	PROTO_MAX,
};

/* 按协议统计入站报文数量。 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, PROTO_MAX);
	__type(key, __u32);
	__type(value, __u64);
} pkt_counters SEC(".maps");

/* 用户态通过该 map 下发需要丢弃的目标端口。 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u16);
} blocked_port_map SEC(".maps");

static __always_inline void count_packet(__u32 index)
{
	__u64 *value;

	value = bpf_map_lookup_elem(&pkt_counters, &index);
	if (value)
		(*value)++;
}

/* 仅在 TCP/UDP 场景下检查目标端口是否命中阻断规则。 */
static __always_inline int should_drop_l4(__u8 ip_proto, void *l4hdr,
					  void *data_end)
{
	__u32 key = 0;
	__u16 *blocked_port;
	__u16 dport;

	blocked_port = bpf_map_lookup_elem(&blocked_port_map, &key);
	if (!blocked_port || !*blocked_port)
		return 0;

	if (ip_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l4hdr;

		if ((void *)(tcp + 1) > data_end)
			return 0;
		dport = bpf_ntohs(tcp->dest);
	} else if (ip_proto == IPPROTO_UDP) {
		struct udphdr *udp = l4hdr;

		if ((void *)(udp + 1) > data_end)
			return 0;
		dport = bpf_ntohs(udp->dest);
	} else {
		return 0;
	}

	return dport == *blocked_port;
}

SEC("tc")
int tc_count_and_drop(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u8 ip_proto;
	void *l3hdr;
	void *l4hdr;
	__u32 index;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	l3hdr = eth + 1;
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
		struct iphdr *iph = l3hdr;

		if ((void *)(iph + 1) > data_end)
			return TC_ACT_OK;
		l4hdr = (__u8 *)iph + iph->ihl * 4;
		if (l4hdr > data_end)
			return TC_ACT_OK;
		ip_proto = iph->protocol;
	} else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = l3hdr;

		if ((void *)(ip6h + 1) > data_end)
			return TC_ACT_OK;
		l4hdr = ip6h + 1;
		ip_proto = ip6h->nexthdr;
	} else {
		count_packet(PROTO_OTHER);
		return TC_ACT_OK;
	}

	if (ip_proto == IPPROTO_TCP)
		index = PROTO_TCP;
	else if (ip_proto == IPPROTO_UDP)
		index = PROTO_UDP;
	else if (ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6)
		index = PROTO_ICMP;
	else
		index = PROTO_OTHER;

	count_packet(index);
	if (should_drop_l4(ip_proto, l4hdr, data_end))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}
