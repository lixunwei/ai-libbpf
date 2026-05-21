// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bpf.h"
#include "kprobe_tcp.skel.h"
#include "libbpf.h"

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

/* 将 IPv4/IPv6 地址格式化后输出。 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char saddr[INET6_ADDRSTRLEN] = {};
	char daddr[INET6_ADDRSTRLEN] = {};

	(void)ctx;
	if (data_sz < sizeof(*e))
		return 0;

	if (e->family == AF_INET) {
		inet_ntop(AF_INET, &e->saddr_v4, saddr, sizeof(saddr));
		inet_ntop(AF_INET, &e->daddr_v4, daddr, sizeof(daddr));
	} else if (e->family == AF_INET6) {
		inet_ntop(AF_INET6, e->saddr_v6, saddr, sizeof(saddr));
		inet_ntop(AF_INET6, e->daddr_v6, daddr, sizeof(daddr));
	} else {
		snprintf(saddr, sizeof(saddr), "unknown");
		snprintf(daddr, sizeof(daddr), "unknown");
	}

	printf("PID=%u COMM=%-16s %s:%u -> %s:%u\n", e->pid, e->comm, saddr, e->sport, daddr,
	       e->dport);
	return 0;
}

int main(void)
{
	struct kprobe_tcp_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = kprobe_tcp_bpf__open();
	if (!skel) {
		fprintf(stderr, "打开 skeleton 失败\n");
		return 1;
	}

	err = kprobe_tcp_bpf__load(skel);
	if (err) {
		fprintf(stderr, "加载 BPF 对象失败: %d\n", err);
		goto cleanup;
	}

	err = kprobe_tcp_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "附加 kprobe 失败: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "创建 ring buffer 失败: %d\n", err);
		goto cleanup;
	}

	printf("开始跟踪 tcp_connect，按 Ctrl+C 退出...\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 200);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "轮询 ring buffer 失败: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	ring_buffer__free(rb);
	kprobe_tcp_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
