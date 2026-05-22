// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "libbpf.h"
#include "struct_ops_example.skel.h"

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

/* 读取系统当前可用的拥塞控制算法列表，并确认新算法已经注册。 */
static int read_available_cc(char *buf, size_t buf_sz)
{
	FILE *fp;
	size_t nread;

	fp = fopen("/proc/sys/net/ipv4/tcp_available_congestion_control", "r");
	if (!fp)
		return -errno;

	nread = fread(buf, 1, buf_sz - 1, fp);
	if (ferror(fp)) {
		int err = -errno;

		fclose(fp);
		return err;
	}
	buf[nread] = '\0';
	fclose(fp);
	return 0;
}

int main(void)
{
	struct struct_ops_example_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	char available[256] = {};
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = struct_ops_example_bpf__open();
	if (!skel) {
		fprintf(stderr, "打开 skeleton 失败\n");
		return 1;
	}

	err = struct_ops_example_bpf__load(skel);
	if (err) {
		fprintf(stderr, "加载 struct_ops 对象失败: %s\n",
			strerror(-err));
		goto cleanup;
	}

	link = bpf_map__attach_struct_ops(skel->maps.simple_aimd);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "注册拥塞控制算法失败: %s\n", strerror(-err));
		goto cleanup;
	}

	err = read_available_cc(available, sizeof(available));
	if (err) {
		fprintf(stderr,
			"读取 tcp_available_congestion_control 失败: %s\n",
			strerror(-err));
		goto cleanup;
	}

	printf("已注册拥塞控制算法: bpf_aimd\n");
	printf("tcp_available_congestion_control: %s", available);
	if (!strstr(available, "bpf_aimd")) {
		err = -ENOENT;
		fprintf(stderr, "系统列表中未找到 bpf_aimd\n");
		goto cleanup;
	}

	printf("验证成功，按 Ctrl+C 退出并注销算法...\n");
	while (!exiting)
		sleep(1);

cleanup:
	bpf_link__destroy(link);
	struct_ops_example_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
