// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

/* 通过 ring buffer 向用户态发送 openat 事件。 */
struct event {
	__u32 pid;
	char comm[16];
	char filename[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	const char *filename;

	filename = (const char *)ctx->args[1];
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	if (bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename) < 0)
		e->filename[0] = '\0';

	bpf_ringbuf_submit(e, 0);
	return 0;
}
