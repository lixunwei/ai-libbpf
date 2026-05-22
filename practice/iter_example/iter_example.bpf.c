// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

char LICENSE[] SEC("license") = "GPL";

SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	char comm[16] = {};
	__u32 pid;
	__u32 tgid;
	__u32 state;

	if (ctx->meta->seq_num == 0) {
		static const char header[] =
			"pid      tgid     comm             state\n";

		bpf_seq_write(seq, header, sizeof(header) - 1);
	}

	if (!task)
		return 0;

	pid = BPF_CORE_READ(task, pid);
	tgid = BPF_CORE_READ(task, tgid);
	state = BPF_CORE_READ(task, __state);
	BPF_CORE_READ_INTO(comm, task, comm);
	BPF_SEQ_PRINTF(seq, "%-8d %-8d %-16s 0x%x\n", pid, tgid, comm, state);
	return 0;
}
