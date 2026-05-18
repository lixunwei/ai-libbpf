// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "GPL";

/* 使用 CO-RE 读取 task_struct 中的核心字段。 */
struct event {
__u32 pid;
__u32 tgid;
__u64 start_time;
char comm[16];
};

struct {
__uint(type, BPF_MAP_TYPE_RINGBUF);
__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_core_exec(void *ctx)
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
bpf_get_current_comm(&e->comm, sizeof(e->comm));

if (bpf_core_field_exists(task->start_boottime))
e->start_time = BPF_CORE_READ(task, start_boottime);
else
e->start_time = BPF_CORE_READ(task, start_time);

bpf_ringbuf_submit(e, 0);
return 0;
}
