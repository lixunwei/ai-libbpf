// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "iter_example.skel.h"
#include "libbpf.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
			   va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

int main(void)
{
	struct iter_example_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	char buf[4096];
	ssize_t nread;
	int iter_fd = -1;
	int err = 0;

	libbpf_set_print(libbpf_print_fn);

	skel = iter_example_bpf__open();
	if (!skel) {
		fprintf(stderr, "打开 skeleton 失败\n");
		return 1;
	}

	err = iter_example_bpf__load(skel);
	if (err) {
		fprintf(stderr, "加载 iterator 对象失败: %s\n", strerror(-err));
		goto cleanup;
	}

	link = bpf_program__attach_iter(skel->progs.dump_task, NULL);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "附加 iterator 程序失败: %s\n", strerror(-err));
		goto cleanup;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
		err = iter_fd;
		fprintf(stderr, "创建 iterator fd 失败: %s\n", strerror(-err));
		goto cleanup;
	}

	printf("开始读取任务迭代器输出:\n");
	while ((nread = read(iter_fd, buf, sizeof(buf))) > 0) {
		if (fwrite(buf, 1, nread, stdout) != (size_t)nread) {
			err = -EIO;
			fprintf(stderr, "写出 iterator 数据失败\n");
			goto cleanup;
		}
	}
	if (nread < 0) {
		err = -errno;
		fprintf(stderr, "读取 iterator 数据失败: %s\n",
			strerror(errno));
	}

cleanup:
	if (iter_fd >= 0)
		close(iter_fd);
	bpf_link__destroy(link);
	iter_example_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
