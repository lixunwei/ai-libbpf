// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "libbpf.h"
#include "tc_example.skel.h"

enum pkt_proto_index {
	PROTO_TCP = 0,
	PROTO_UDP,
	PROTO_ICMP,
	PROTO_OTHER,
	PROTO_MAX,
};

static volatile sig_atomic_t exiting;

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
			   va_list args)
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
		"用法: %s -i <网卡名> [-p 端口]\n"
		"  -i iface  指定需要挂载 TC ingress 的网卡\n"
		"  -p port   指定需要阻断的目标端口，不指定则仅统计\n",
		prog);
}

/* 汇总某个协议在所有 CPU 上的统计值。 */
static int read_counter(int map_fd, __u32 key, __u64 *total)
{
	__u64 *values;
	int nr_cpus;
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

	*total = 0;
	for (i = 0; i < nr_cpus; i++)
		*total += values[i];

	free(values);
	return 0;
}

/* 周期性打印 TCP/UDP/ICMP/Other 四类报文计数。 */
static int print_stats(int map_fd)
{
	static const char *names[PROTO_MAX] = {
		[PROTO_TCP] = "TCP",
		[PROTO_UDP] = "UDP",
		[PROTO_ICMP] = "ICMP",
		[PROTO_OTHER] = "Other",
	};
	__u64 totals[PROTO_MAX] = {};
	__u32 key;
	int err;

	for (key = 0; key < PROTO_MAX; key++) {
		err = read_counter(map_fd, key, &totals[key]);
		if (err)
			return err;
	}

	for (key = 0; key < PROTO_MAX; key++)
		printf("%s=%llu ", names[key], (unsigned long long)totals[key]);
	printf("\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct tc_example_bpf *skel = NULL;
	struct bpf_tc_hook hook = {};
	struct bpf_tc_opts opts = {};
	const char *ifname = NULL;
	__u32 key = 0;
	__u16 blocked_port = 0;
	int ifindex;
	int stats_fd;
	int err = 0;
	int opt;
	bool hook_created = false;
	bool attached = false;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while ((opt = getopt(argc, argv, "i:p:")) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case 'p':
			blocked_port = (__u16)strtoul(optarg, NULL, 10);
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

	skel = tc_example_bpf__open();
	if (!skel) {
		fprintf(stderr, "打开 skeleton 失败\n");
		return 1;
	}

	err = tc_example_bpf__load(skel);
	if (err) {
		fprintf(stderr, "加载 BPF 对象失败: %s\n", strerror(-err));
		goto cleanup;
	}

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.blocked_port_map),
				  &key, &blocked_port, BPF_ANY);
	if (err) {
		err = -errno;
		fprintf(stderr, "更新 blocked_port_map 失败: %s\n",
			strerror(errno));
		goto cleanup;
	}

	hook.sz = sizeof(hook);
	hook.ifindex = ifindex;
	hook.attach_point = BPF_TC_INGRESS;

	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "创建 TC hook 失败: %s\n", strerror(-err));
		goto cleanup;
	}
	hook_created = err == 0;

	opts.sz = sizeof(opts);
	opts.prog_fd = bpf_program__fd(skel->progs.tc_count_and_drop);
	opts.handle = 1;
	opts.priority = 1;
	opts.flags = BPF_TC_F_REPLACE;

	err = bpf_tc_attach(&hook, &opts);
	if (err) {
		fprintf(stderr, "附加 TC 程序失败: %s\n", strerror(-err));
		goto cleanup;
	}
	attached = true;

	stats_fd = bpf_map__fd(skel->maps.pkt_counters);
	printf("TC ingress 程序已挂载到 %s，blocked_port=%u，按 Ctrl+C "
	       "退出...\n",
	       ifname, blocked_port);
	while (!exiting) {
		err = print_stats(stats_fd);
		if (err) {
			fprintf(stderr, "读取统计失败: %s\n", strerror(-err));
			goto cleanup;
		}
		sleep(1);
	}

cleanup:
	if (attached) {
		int detach_err;

		detach_err = bpf_tc_detach(&hook, &opts);
		if (detach_err && detach_err != -ENOENT)
			fprintf(stderr, "卸载 TC 程序失败: %s\n",
				strerror(-detach_err));
	}
	if (hook_created) {
		int destroy_err;

		destroy_err = bpf_tc_hook_destroy(&hook);
		if (destroy_err && destroy_err != -ENOENT)
			fprintf(stderr, "销毁 TC hook 失败: %s\n",
				strerror(-destroy_err));
	}
	tc_example_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
