// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "libbpf.h"
#include "xdp_drop.skel.h"

struct datarec {
__u64 packets;
__u64 drops;
};

static volatile sig_atomic_t exiting;

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
if (level == LIBBPF_DEBUG)
return 0;
return vfprintf(stderr, fmt, args);
}

static void sig_handler(int signo)
{
(void)signo;
exiting = 1;
}

static void usage(const char *prog)
{
fprintf(stderr,
"用法: %s -i <网卡名> [-p 端口] [-N]\n"
"  -i iface  指定需要挂载 XDP 的网卡\n"
"  -p port   指定需要丢弃的目标端口，不指定则仅统计\n"
"  -N        使用 native/driver 模式，默认使用 skb 模式\n",
prog);
}

/* 汇总所有 CPU 上的 XDP 统计值。 */
static int read_stats(int map_fd, struct datarec *total)
{
struct datarec *values;
int nr_cpus;
__u32 key = 0;
int i;

nr_cpus = libbpf_num_possible_cpus();
if (nr_cpus < 0)
return nr_cpus;

values = calloc(nr_cpus, sizeof(*values));
if (!values)
return -ENOMEM;

if (bpf_map_lookup_elem(map_fd, &key, values) < 0) {
free(values);
return -errno;
}

memset(total, 0, sizeof(*total));
for (i = 0; i < nr_cpus; i++) {
total->packets += values[i].packets;
total->drops += values[i].drops;
}

free(values);
return 0;
}

int main(int argc, char **argv)
{
struct xdp_drop_bpf *skel = NULL;
struct datarec total = {};
const char *ifname = NULL;
__u16 drop_port = 0;
__u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
int ifindex;
int map_fd;
int err;
int opt;

libbpf_set_print(libbpf_print_fn);
signal(SIGINT, sig_handler);
signal(SIGTERM, sig_handler);

while ((opt = getopt(argc, argv, "i:p:N")) != -1) {
switch (opt) {
case 'i':
ifname = optarg;
break;
case 'p':
drop_port = (__u16)strtoul(optarg, NULL, 10);
break;
case 'N':
xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
break;
default:
usage(argv[0]);
return 1;
}
}

if (!ifname) {
usage(argv[0]);
return 1;
}

ifindex = if_nametoindex(ifname);
if (!ifindex) {
fprintf(stderr, "无法解析网卡 %s\n", ifname);
return 1;
}

skel = xdp_drop_bpf__open();
if (!skel) {
fprintf(stderr, "打开 skeleton 失败\n");
return 1;
}

skel->rodata->drop_port = drop_port;
err = xdp_drop_bpf__load(skel);
if (err) {
fprintf(stderr, "加载 BPF 对象失败: %d\n", err);
goto cleanup;
}

err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_drop_prog), xdp_flags, NULL);
if (err) {
fprintf(stderr, "挂载 XDP 程序失败: %d\n", err);
goto cleanup;
}

map_fd = bpf_map__fd(skel->maps.xdp_stats);
printf("XDP 已挂载到 %s，drop_port=%u，按 Ctrl+C 退出...\n", ifname, drop_port);
while (!exiting) {
err = read_stats(map_fd, &total);
if (err) {
fprintf(stderr, "读取统计失败: %d\n", err);
goto detach;
}

printf("packets=%llu drops=%llu\n",
       (unsigned long long)total.packets,
       (unsigned long long)total.drops);
sleep(1);
}

printf("开始卸载 XDP 程序...\n");

 detach:
bpf_xdp_detach(ifindex, xdp_flags, NULL);
cleanup:
xdp_drop_bpf__destroy(skel);
return err ? 1 : 0;
}
