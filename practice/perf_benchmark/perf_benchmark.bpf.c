// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * 三类程序都只做最小化的每 CPU 计数。
 * 真正的额外开销由用户态通过相同工作负载的墙钟时间差估算。
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} kprobe_hits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} fentry_hits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} tracepoint_hits SEC(".maps");

static __always_inline void count_hit(void *map) {
	__u32 key = 0;
	__u64 *value;

	value = bpf_map_lookup_elem(map, &key);
	if (value)
		(*value)++;
}

SEC("kprobe/do_sys_openat2")
int bench_kprobe(struct pt_regs *ctx) {
	(void)ctx;
	count_hit(&kprobe_hits);
	return 0;
}

SEC("fentry/do_sys_openat2")
int BPF_PROG(bench_fentry, int dfd, const char *filename, struct open_how *how) {
	(void)dfd;
	(void)filename;
	(void)how;
	count_hit(&fentry_hits);
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int bench_tracepoint(struct trace_event_raw_sys_enter *ctx) {
	(void)ctx;
	count_hit(&tracepoint_hits);
	return 0;
}
