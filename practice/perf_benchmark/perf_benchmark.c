// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "bpf.h"
#include "libbpf.h"
#include "perf_benchmark.skel.h"

#define DEFAULT_ITERATIONS 1000000ULL
#define TARGET_FILE "./perf_benchmark_target.txt"

enum bench_type {
	BENCH_BASELINE = 0,
	BENCH_KPROBE,
	BENCH_FENTRY,
	BENCH_TRACEPOINT,
};

struct bench_result {
	const char *name;
	bool skipped;
	__u64 elapsed_ns;
	__u64 hits;
	int err;
};

static volatile sig_atomic_t exiting;

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args) {
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static void sig_handler(int signo) {
	(void)signo;
	exiting = 1;
}

/* 将 libbpf 错误码格式化为中文提示。 */
static void print_libbpf_error(const char *stage, int err) {
	char buf[256];

	if (!libbpf_strerror(err, buf, sizeof(buf)))
		fprintf(stderr, "%s失败: %s (%d)\n", stage, buf, err);
	else
		fprintf(stderr, "%s失败: %d\n", stage, err);
}

/* 将通用 errno 风格错误码格式化输出。 */
static void print_errno_error(const char *stage, int err) {
	fprintf(stderr, "%s失败: %s (%d)\n", stage, strerror(-err), err);
}

static void usage(const char *prog) {
	fprintf(stderr,
		"用法: %s [-n 次数]\n"
		"  -n iterations  指定 openat 基准次数，默认 1000000\n",
		prog);
}

/* 预先尝试放宽 memlock，避免在具备权限时仍因限制过低而加载失败。 */
static void setup_libbpf_env(void) {
	int err;

	err = libbpf_set_memlock_rlim(512UL << 20);
	if (err)
		print_libbpf_error("提升 RLIMIT_MEMLOCK", err);
}

static __u64 timespec_to_ns(const struct timespec *ts) {
	return (__u64)ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

/* 汇总每 CPU 数组 map 中的命中次数。 */
static int read_hits(int map_fd, __u64 *total) {
	__u64 *values;
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

	*total = 0;
	for (i = 0; i < nr_cpus; i++)
		*total += values[i];

	free(values);
	return 0;
}

/* 在当前目录准备一个固定文件，避免文件创建成本污染结果。 */
static int prepare_target_file(const char *path) {
	static const char payload[] = "libbpf perf benchmark\n";
	ssize_t written;
	int fd;

	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0) {
		perror("创建基准文件失败");
		return -errno;
	}

	written = write(fd, payload, sizeof(payload) - 1);
	if (written != (ssize_t)(sizeof(payload) - 1)) {
		if (written < 0)
			perror("写入基准文件失败");
		close(fd);
		return written < 0 ? -errno : -EIO;
	}

	if (close(fd) < 0) {
		perror("关闭基准文件失败");
		return -errno;
	}

	return 0;
}

/* 使用统一的 openat 工作负载触发函数入口与 syscall tracepoint。 */
static int run_workload(const char *path, __u64 iterations, __u64 *elapsed_ns) {
	struct timespec start;
	struct timespec end;
	__u64 i;
	int fd;

	if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
		perror("读取开始时间失败");
		return -errno;
	}

	for (i = 0; i < iterations; i++) {
		if (exiting)
			return -EINTR;

		fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
		if (fd < 0) {
			perror("执行 openat 工作负载失败");
			return -errno;
		}

		if (close(fd) < 0) {
			perror("关闭工作负载文件失败");
			return -errno;
		}
	}

	if (clock_gettime(CLOCK_MONOTONIC, &end) < 0) {
		perror("读取结束时间失败");
		return -errno;
	}

	*elapsed_ns = timespec_to_ns(&end) - timespec_to_ns(&start);
	return 0;
}

/* 仅保留当前轮测试需要自动加载的程序。 */
static int select_program(struct perf_benchmark_bpf *skel, enum bench_type type) {
	int err;

	err = bpf_program__set_autoload(skel->progs.bench_kprobe, type == BENCH_KPROBE);
	if (err)
		return err;

	err = bpf_program__set_autoload(skel->progs.bench_fentry, type == BENCH_FENTRY);
	if (err)
		return err;

	err = bpf_program__set_autoload(skel->progs.bench_tracepoint, type == BENCH_TRACEPOINT);
	if (err)
		return err;

	return 0;
}

static int result_map_fd(struct perf_benchmark_bpf *skel, enum bench_type type) {
	switch (type) {
	case BENCH_KPROBE:
		return bpf_map__fd(skel->maps.kprobe_hits);
	case BENCH_FENTRY:
		return bpf_map__fd(skel->maps.fentry_hits);
	case BENCH_TRACEPOINT:
		return bpf_map__fd(skel->maps.tracepoint_hits);
	case BENCH_BASELINE:
	default:
		return -EINVAL;
	}
}

/* 单轮基准：加载指定程序、运行工作负载、读取计数结果。 */
static int run_single_benchmark(enum bench_type type, const char *path, __u64 iterations,
				struct bench_result *result) {
	struct perf_benchmark_bpf *skel = NULL;
	int map_fd;
	int err;

	result->skipped = false;
	result->elapsed_ns = 0;
	result->hits = 0;
	result->err = 0;

	if (type == BENCH_BASELINE)
		return run_workload(path, iterations, &result->elapsed_ns);

	skel = perf_benchmark_bpf__open();
	if (!skel) {
		fprintf(stderr, "打开 perf_benchmark skeleton 失败\n");
		return -ENOMEM;
	}

	err = select_program(skel, type);
	if (err) {
		print_libbpf_error("设置 autoload", err);
		goto out;
	}

	err = perf_benchmark_bpf__load(skel);
	if (err) {
		print_libbpf_error("加载 BPF 对象", err);
		result->skipped = true;
		result->err = err;
		err = 0;
		goto out;
	}

	err = perf_benchmark_bpf__attach(skel);
	if (err) {
		print_libbpf_error("附加 BPF 程序", err);
		result->skipped = true;
		result->err = err;
		err = 0;
		goto out;
	}

	err = run_workload(path, iterations, &result->elapsed_ns);
	if (err)
		goto out;

	map_fd = result_map_fd(skel, type);
	if (map_fd < 0) {
		err = map_fd;
		goto out;
	}

	err = read_hits(map_fd, &result->hits);
	if (err)
		goto out;

out:
	perf_benchmark_bpf__destroy(skel);
	return err;
}

static void print_row(const struct bench_result *baseline,
		      const struct bench_result *result, __u64 iterations)
{
	char elapsed_buf[32];
	char overhead_buf[32];
	char ratio_buf[32];
	double elapsed_ms;
	double overhead_ns;
	double ratio;
	long long diff_ns;

	if (result->skipped) {
		printf("%-11s %-11s %-15s %-10s %llu\n", result->name, "跳过", "-", "-",
		       (unsigned long long)result->hits);
		return;
	}

	elapsed_ms = (double)result->elapsed_ns / 1000000.0;
	snprintf(elapsed_buf, sizeof(elapsed_buf), "%.3f", elapsed_ms);
	if (result == baseline) {
		printf("%-11s %-11s %-15s %-10s %llu\n", result->name, elapsed_buf, "-", "1.00x",
		       (unsigned long long)result->hits);
		return;
	}

	diff_ns = (long long)result->elapsed_ns - (long long)baseline->elapsed_ns;
	overhead_ns = (double)diff_ns / (double)iterations;
	ratio = baseline->elapsed_ns ?
		(double)result->elapsed_ns / (double)baseline->elapsed_ns : 0.0;
	snprintf(overhead_buf, sizeof(overhead_buf), "%.2f", overhead_ns);
	snprintf(ratio_buf, sizeof(ratio_buf), "%.2fx", ratio);
	printf("%-11s %-11s %-15s %-10s %llu\n", result->name, elapsed_buf,
	       overhead_buf, ratio_buf, (unsigned long long)result->hits);
}

static void print_results(const struct bench_result *results, __u64 iterations) {
	printf("\n=== BPF 挂载机制性能对比 ===\n");
	printf("操作次数: %llu\n\n", (unsigned long long)iterations);
	printf("%-11s %-11s %-15s %-10s %s\n", "类型", "耗时(ms)", "每次开销(ns)", "相对基准",
	       "命中次数");
	printf("---------------------------------------------------------------\n");
	print_row(&results[BENCH_BASELINE], &results[BENCH_BASELINE], iterations);
	print_row(&results[BENCH_BASELINE], &results[BENCH_KPROBE], iterations);
	print_row(&results[BENCH_BASELINE], &results[BENCH_FENTRY], iterations);
	print_row(&results[BENCH_BASELINE], &results[BENCH_TRACEPOINT], iterations);
}

int main(int argc, char **argv) {
	struct bench_result results[] = {
	    [BENCH_BASELINE] = {.name = "无 BPF"},
	    [BENCH_KPROBE] = {.name = "kprobe"},
	    [BENCH_FENTRY] = {.name = "fentry"},
	    [BENCH_TRACEPOINT] = {.name = "tracepoint"},
	};
	__u64 iterations = DEFAULT_ITERATIONS;
	int err;
	int opt;
	int i;

	libbpf_set_print(libbpf_print_fn);
	setup_libbpf_env();
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while ((opt = getopt(argc, argv, "n:h")) != -1) {
		switch (opt) {
		case 'n':
			iterations = strtoull(optarg, NULL, 10);
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (!iterations) {
		fprintf(stderr, "基准次数必须大于 0\n");
		return 1;
	}

	err = prepare_target_file(TARGET_FILE);
	if (err)
		return 1;

	for (i = 0; i <= BENCH_TRACEPOINT; i++) {
		err = run_single_benchmark(i, TARGET_FILE, iterations, &results[i]);
		if (err) {
			if (err == -EINTR)
				fprintf(stderr, "收到中断信号，提前结束\n");
			else
				print_errno_error("执行基准", err);
			unlink(TARGET_FILE);
			return 1;
		}

		if (!results[i].skipped && i != BENCH_BASELINE && results[i].hits != iterations)
			fprintf(stderr, "警告: %s 命中次数为 %llu，低于预期 %llu\n",
				results[i].name, (unsigned long long)results[i].hits,
				(unsigned long long)iterations);
	}

	print_results(results, iterations);
	unlink(TARGET_FILE);
	return 0;
}
