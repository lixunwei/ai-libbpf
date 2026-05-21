// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "cgroup_egress.skel.h"
#include "libbpf.h"

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

/* 遍历哈希表并打印每个目的 IP 的计数。 */
static int dump_ip_stats(int map_fd)
{
	__u32 current_key;
	__u32 next_key;
	__u64 value;
	char ip[INET_ADDRSTRLEN];
	int err;

	memset(&current_key, 0, sizeof(current_key));
	printf("当前目的 IP 统计：\n");
	err = bpf_map_get_next_key(map_fd, NULL, &next_key);
	if (err) {
		if (errno != ENOENT)
			fprintf(stderr, "读取 map 首个 key 失败: %s\n", strerror(errno));
		printf("  (暂无数据)\n");
		return 0;
	}

	while (1) {
		if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
			inet_ntop(AF_INET, &next_key, ip, sizeof(ip));
			printf("  %s -> %llu\n", ip, (unsigned long long)value);
		} else {
			fprintf(stderr, "查询 map 值失败: %s\n", strerror(errno));
		}

		current_key = next_key;
		err = bpf_map_get_next_key(map_fd, &current_key, &next_key);
		if (err) {
			if (errno != ENOENT)
				fprintf(stderr, "读取下一个 key 失败: %s\n", strerror(errno));
			break;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *cgroup_path = "/sys/fs/cgroup/user.slice";
	const char *blocked_ip_arg = NULL;
	struct cgroup_egress_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	int err;

	if (argc > 1)
		cgroup_path = argv[1];
	if (argc > 2)
		blocked_ip_arg = argv[2];
	if (argc > 3) {
		fprintf(stderr, "用法: %s [cgroup路径] [可选阻断IPv4]\n", argv[0]);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = cgroup_egress_bpf__open();
	if (!skel) {
		fprintf(stderr, "打开 skeleton 失败\n");
		return 1;
	}

	if (blocked_ip_arg) {
		if (inet_pton(AF_INET, blocked_ip_arg, &skel->rodata->blocked_ip) != 1) {
			fprintf(stderr, "无效的 IPv4 地址: %s\n", blocked_ip_arg);
			err = -EINVAL;
			goto cleanup;
		}
	}

	err = cgroup_egress_bpf__load(skel);
	if (err) {
		fprintf(stderr, "加载 cgroup BPF 对象失败: %d\n", err);
		goto cleanup;
	}

	cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY);
	if (cgroup_fd < 0) {
		err = -errno;
		fprintf(stderr, "打开 cgroup 目录失败: %s\n", strerror(errno));
		goto cleanup;
	}

	link = bpf_program__attach_cgroup(skel->progs.handle_egress, cgroup_fd);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "附加 cgroup egress 程序失败: %d\n", err);
		goto cleanup;
	}

	printf("已附加到 cgroup: %s\n", cgroup_path);
	if (blocked_ip_arg)
		printf("阻断目的 IPv4: %s\n", blocked_ip_arg);
	printf("每 2 秒输出一次统计，按 Ctrl+C 退出...\n");

	while (!exiting) {
		sleep(2);
		dump_ip_stats(bpf_map__fd(skel->maps.ip_stats));
	}

	printf("退出前再次输出一次统计：\n");
	dump_ip_stats(bpf_map__fd(skel->maps.ip_stats));
	err = 0;

cleanup:
	bpf_link__destroy(link);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	cgroup_egress_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
