// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

/* 演示 reserve/submit 模式发送 exec 事件。 */
struct event {
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx)
{
	struct task_struct *task;
	struct event *e;
	__u64 id;

	(void)ctx;
	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tgid = (__u32)id;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
