// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bpf.h"
#include "core_task_info.skel.h"
#include "libbpf.h"

struct event {
	__u32 pid;
	__u32 tgid;
	__u64 start_time;
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

/* 展示 CO-RE 读取到的任务字段。 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	(void)ctx;
	if (data_sz < sizeof(*e))
		return 0;

	printf("CO-RE event: pid=%u tgid=%u comm=%-16s start_time=%llu\n", e->pid, e->tgid, e->comm,
	       (unsigned long long)e->start_time);
	return 0;
}

int main(void)
{
	struct core_task_info_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = core_task_info_bpf__open();
	if (!skel) {
		fprintf(stderr, "打开 skeleton 失败\n");
		return 1;
	}

	err = core_task_info_bpf__load(skel);
	if (err) {
		fprintf(stderr, "加载 BPF 对象失败: %d\n", err);
		goto cleanup;
	}

	err = core_task_info_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "附加 tracepoint 失败: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "创建 ring buffer 失败: %d\n", err);
		goto cleanup;
	}

	printf("CO-RE 示例已启动，按 Ctrl+C 退出...\n");
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
	core_task_info_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
