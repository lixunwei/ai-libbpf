// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";

/* 记录每个目的 IPv4 地址的出向包计数。 */
struct {
__uint(type, BPF_MAP_TYPE_HASH);
__uint(max_entries, 1024);
__type(key, __u32);
__type(value, __u64);
} ip_stats SEC(".maps");

/* 用户态可在加载前设置要阻断的 IPv4 地址，0 表示不阻断。 */
const volatile __u32 blocked_ip;

SEC("cgroup_skb/egress")
int handle_egress(struct __sk_buff *skb)
{
void *data = (void *)(long)skb->data;
void *data_end = (void *)(long)skb->data_end;
struct iphdr *iph = data;
__u32 daddr;
__u64 init_value = 1;
__u64 *value;

if ((void *)(iph + 1) > data_end)
return 1;
if (iph->version != 4)
return 1;

daddr = iph->daddr;
value = bpf_map_lookup_elem(&ip_stats, &daddr);
if (value)
__sync_fetch_and_add(value, 1);
else
bpf_map_update_elem(&ip_stats, &daddr, &init_value, BPF_ANY);

if (blocked_ip && daddr == blocked_ip)
return 0;

return 1;
}
