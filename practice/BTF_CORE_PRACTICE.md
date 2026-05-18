# BTF 与 CO-RE 实践指南

## 概述

本文档指导 BTF (BPF Type Format) 和 CO-RE (Compile Once - Run Everywhere) 的
实践验证，结合 libbpf 源码分析结论进行动手验证。

**相关分析文档**:
- `darren/libbpf_btf_core_deep.md` — BTF 与 CO-RE 源码深度分析
- `darren/libbpf_kernel_correlation.md` — libbpf ↔ 内核交叉引用

**相关内核知识库**:
- `linux/darren/bpf/ebpf_btf_core_deep.md` — 内核 BTF/CO-RE 实现
- `linux/darren/tools/pahole_vmlinux_analysis.md` — pahole 分析 vmlinux

---

## 1. BTF 基础操作

### 1.1 查看 vmlinux BTF

```bash
# 验证内核 BTF 可用
ls -la /sys/kernel/btf/vmlinux

# 生成 vmlinux.h（包含所有内核类型定义）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
wc -l vmlinux.h   # 通常 150000+ 行

# 查看特定类型
bpftool btf dump file /sys/kernel/btf/vmlinux format c | \
    grep -A 30 "^struct task_struct {"
```

### 1.2 使用 pahole 分析

```bash
# pahole 查看结构体布局
pahole -C task_struct vmlinux | head -50

# 查看特定字段偏移
pahole -C task_struct vmlinux | grep -E "(pid|tgid|comm)"
# 输出示例:
#   pid_t    pid;    /* 2288  4 */
#   pid_t    tgid;   /* 2292  4 */
#   char     comm[TASK_COMM_LEN]; /* 2560  16 */

# 对比不同内核版本的偏移变化
# 这就是 CO-RE 需要解决的问题！
```

### 1.3 查看 BPF 程序的 BTF

```bash
# 查看 .bpf.o 中的 BTF 信息
bpftool btf dump file trace_openat.bpf.o

# 查看特定类型 ID
bpftool btf dump file trace_openat.bpf.o format c

# 用 readelf 查看 BTF section
readelf -S trace_openat.bpf.o | grep -i btf
# .BTF          — BTF 类型数据
# .BTF.ext      — BTF 扩展（行信息、func_info、CO-RE重定位记录）
```

---

## 2. CO-RE 重定位原理验证

### 2.1 查看 CO-RE 重定位记录

```bash
# 使用 llvm-objdump 查看重定位
llvm-objdump -r core_task_info.bpf.o | head -30

# 使用 bpftool 查看带 CO-RE 标注的字节码
bpftool prog dump xlated id <prog_id> linum
```

### 2.2 CO-RE 重定位类型

libbpf 源码 (relo_core.c) 中定义了以下重定位类型:

```c
// 字段偏移读取 — BPF_CORE_READ() 生成
BPF_CORE_FIELD_BYTE_OFFSET   // 字段字节偏移
BPF_CORE_FIELD_BYTE_SIZE     // 字段字节大小
BPF_CORE_FIELD_EXISTS        // 字段是否存在

// 类型信息
BPF_CORE_TYPE_ID_LOCAL        // 本地类型 ID
BPF_CORE_TYPE_ID_TARGET       // 目标类型 ID
BPF_CORE_TYPE_EXISTS          // 类型是否存在
BPF_CORE_TYPE_SIZE            // 类型大小
BPF_CORE_TYPE_MATCHES         // 类型是否匹配

// 枚举
BPF_CORE_ENUMVAL_EXISTS       // 枚举值是否存在
BPF_CORE_ENUMVAL_VALUE        // 枚举值
```

### 2.3 GDB 跟踪 CO-RE 重定位过程

```gdb
# 在 CO-RE 核心函数设断点
(gdb) break bpf_object__relocate_core
(gdb) break bpf_core_calc_relo_insn

# 运行程序
(gdb) run

# 在 bpf_core_calc_relo_insn 断点处:
(gdb) print *relo          # 重定位记录
(gdb) print relo->kind     # 重定位类型
(gdb) print relo->access_str_off  # 访问路径字符串偏移

# 查看类型匹配结果
(gdb) print targ_res->orig_val    # 原始值（编译时偏移）
(gdb) print targ_res->new_val     # 新值（运行时偏移）
(gdb) print targ_res->validate    # 是否需要验证

# 查看指令修补
(gdb) print *insn          # 修补前的指令
(gdb) next                 # 执行修补
(gdb) print *insn          # 修补后的指令
```

---

## 3. 实验：验证字段偏移重定位

### 3.1 编写测试程序

```c
// test_core_offset.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

SEC("tp/syscalls/sys_enter_write")
int trace_write(void *ctx) {
    struct task_struct *task = (void *)bpf_get_current_task();
    
    // CO-RE 读取 — 编译时记录偏移，运行时重定位
    pid_t pid = BPF_CORE_READ(task, pid);
    pid_t tgid = BPF_CORE_READ(task, tgid);
    
    // 嵌套读取
    pid_t parent_pid = BPF_CORE_READ(task, parent, pid);
    
    // 字段存在性检查
    if (bpf_core_field_exists(task->loginuid)) {
        // 只在有 loginuid 字段的内核上执行
    }
    
    bpf_printk("pid=%d tgid=%d parent_pid=%d\n", pid, tgid, parent_pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 3.2 编译并查看重定位

```bash
# 编译
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
    -I../../src -I../../include \
    -c test_core_offset.bpf.c -o test_core_offset.bpf.o

# 查看 .BTF.ext 中的 CO-RE 重定位记录
bpftool btf dump file test_core_offset.bpf.o format raw | \
    grep -A5 "core_relo"

# 或者用 llvm-objdump
llvm-objdump --section=.BTF.ext test_core_offset.bpf.o
```

### 3.3 对比编译时和运行时偏移

```bash
# 编译时的偏移（从 vmlinux.h 中 task_struct 的定义推断）
# 这是 clang 编译时看到的偏移

# 运行时偏移（libbpf 从 /sys/kernel/btf/vmlinux 读取）
bpftool btf dump file /sys/kernel/btf/vmlinux format c | \
    grep -B2 -A2 "pid_t.*pid;" | head -10

# 用 pahole 精确查看
pahole -C task_struct /sys/kernel/btf/vmlinux 2>/dev/null | grep "pid"
# 或
pahole -C task_struct vmlinux | grep "pid"
```

---

## 4. 实验：跨内核版本可移植性

### 4.1 模拟字段偏移变化

```c
// 方法: 用不同内核编译的 vmlinux.h，对比生成的 .bpf.o

// 如果有多个内核版本的 BTF:
// /sys/kernel/btf/vmlinux (当前内核)
// /path/to/kernel-5.10/vmlinux (旧内核)
// /path/to/kernel-6.5/vmlinux (新内核)

// 用 bpftool 检查不同版本的类型偏移
bpftool btf dump file /path/to/vmlinux-5.10 format c | \
    grep -A30 "^struct task_struct {"

bpftool btf dump file /path/to/vmlinux-6.5 format c | \
    grep -A30 "^struct task_struct {"
```

### 4.2 测试 bpf_core_field_exists

```c
// 测试内核版本差异的字段
SEC("tp/syscalls/sys_enter_write")
int test_field_exists(void *ctx) {
    struct task_struct *task = (void *)bpf_get_current_task();
    
    // thread_info 嵌入方式在 4.9→5.x 之间变化
    if (bpf_core_field_exists(task->thread_info)) {
        bpf_printk("thread_info is embedded in task_struct\n");
    }
    
    // pidfd 在 5.3+ 才有
    if (bpf_core_field_exists(task->signal->has_child_subreaper)) {
        bpf_printk("has_child_subreaper exists\n");
    }
    
    return 0;
}
```

---

## 5. libbpf CO-RE 内部机制验证

### 5.1 源码关键路径

基于 `libbpf_btf_core_deep.md` 分析的关键函数:

```
bpf_object__relocate_core()       [libbpf.c]
  ├── record_relo_core()          — 收集重定位记录
  ├── bpf_core_apply_relo_insn()  — 应用单条重定位
  │   ├── bpf_core_calc_relo_insn() [relo_core.c]
  │   │   ├── bpf_core_match_type()  — 类型匹配
  │   │   ├── bpf_core_calc_field_relo() — 字段偏移计算
  │   │   └── bpf_core_patch_insn()  — 指令修补
  │   └── (修改 insn->imm 或 insn->off)
  └── 循环处理所有程序的所有重定位
```

### 5.2 验证类型匹配算法

```gdb
# 断在类型匹配
(gdb) break bpf_core_types_match
(gdb) run

# 查看本地类型 vs 目标类型
(gdb) print local_type    # BPF 程序中使用的类型
(gdb) print targ_type     # 内核 BTF 中的类型
(gdb) print local_acc     # 字段访问路径
```

---

## 6. BTF Dedup 算法验证

### 6.1 观察 BTF dedup 效果

```bash
# 查看原始 BTF 大小
readelf -S vmlinux | grep .BTF
# .BTF: 可能 5-10MB

# BTF dedup 后的大小
ls -la /sys/kernel/btf/vmlinux
# 通常 2-4MB

# libbpf 的 btf__dedup() 做了什么？
# - 字符串去重
# - 类型去重（结构化等价）
# - 消除冗余的前向声明
```

### 6.2 GDB 跟踪 dedup

```gdb
(gdb) break btf__dedup
(gdb) break btf_dedup_strings
(gdb) break btf_dedup_prim_types
(gdb) break btf_dedup_struct_types
(gdb) break btf_dedup_compact_types

# 查看 dedup 前后的类型数量变化
(gdb) print btf->nr_types      # dedup 前
(gdb) finish                    # 等 btf__dedup 返回
(gdb) print btf->nr_types      # dedup 后
```

---

## 7. 实验检查清单

| 实验 | 验证点 | 预期结果 |
|---|---|---|
| pahole vmlinux | task_struct.pid 偏移 | 与 CO-RE 重定位值匹配 |
| BPF_CORE_READ | 运行时字段读取 | 正确获取 pid/tgid/comm |
| field_exists | 不存在的字段 | 分支被消除，程序仍能加载 |
| 跨版本运行 | 同一 .bpf.o 在不同内核运行 | 自动重定位，正确运行 |
| GDB CO-RE | orig_val vs new_val | 编译时偏移 ≠ 运行时偏移 |
| BTF dedup | nr_types 变化 | dedup 后类型数量减少 |
