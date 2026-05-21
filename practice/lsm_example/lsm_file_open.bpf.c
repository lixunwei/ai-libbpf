// SPDX-License-Identifier: GPL-2.0
#include "../vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef EPERM
#define EPERM 1
#endif

/* 通过 ring buffer 输出被拒绝的文件访问事件。 */
struct event {
__u32 pid;
char comm[16];
char path[256];
};

struct {
__uint(type, BPF_MAP_TYPE_RINGBUF);
__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static const char blocked_path[] = "/tmp/blocked";

static __always_inline int path_contains_blocked(const char *path)
{
int i;
int j;

#pragma unroll
for (i = 0; i <= 256 - (int)sizeof(blocked_path); i++) {
if (path[i] == '\0')
return 0;
#pragma unroll
for (j = 0; j < (int)sizeof(blocked_path) - 1; j++) {
if (path[i + j] != blocked_path[j])
goto next;
}
return 1;
next:
continue;
}

return 0;
}

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
struct event *e;
struct path path = {};
char resolved[256] = {};
long ret;

if (!file)
return 0;

BPF_CORE_READ_INTO(&path, file, f_path);
ret = bpf_d_path(&path, resolved, sizeof(resolved));
if (ret < 0)
return 0;

if (!path_contains_blocked(resolved))
return 0;

e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (e) {
e->pid = bpf_get_current_pid_tgid() >> 32;
bpf_get_current_comm(&e->comm, sizeof(e->comm));
__builtin_memcpy(e->path, resolved, sizeof(e->path));
bpf_ringbuf_submit(e, 0);
}

return -EPERM;
}
