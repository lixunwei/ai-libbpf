// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bpf.h"
#include "libbpf.h"
#include "lsm_file_open.skel.h"

struct event {
	__u32 pid;
	char comm[16];
	char path[256];
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

/* 解析并打印被 LSM 拒绝的文件访问事件。 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	(void)ctx;
	if (data_sz < sizeof(*e))
		return 0;

	printf("拒绝访问: PID=%u COMM=%-16s PATH=%s\n", e->pid, e->comm, e->path);
	return 0;
}

int main(void)
{
	struct lsm_file_open_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = lsm_file_open_bpf__open();
	if (!skel) {
		fprintf(stderr, "打开 skeleton 失败\n");
		return 1;
	}

	err = lsm_file_open_bpf__load(skel);
	if (err) {
		fprintf(stderr, "加载 BPF LSM 对象失败: %d\n", err);
		goto cleanup;
	}

	err = lsm_file_open_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "附加 LSM 程序失败: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "创建 ring buffer 失败: %d\n", err);
		goto cleanup;
	}

	printf("开始监控文件访问，命中 /tmp/blocked 将被拒绝，按 Ctrl+C 退出...\n");
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
	lsm_file_open_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
