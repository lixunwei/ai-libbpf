# libbpf 调试验证指南

## 概述

本文档指导如何使用各种调试工具验证 libbpf 源码分析结论，
覆盖从用户态到内核态的完整调试路径。

---

## 1. GDB 调试 libbpf 内部流程

### 1.1 编译调试版本

```bash
cd /home/nio/sda/source/Linux/eBPF/libbpf/src
make clean
make CFLAGS="-g -O0 -DDEBUG"
```

### 1.2 关键断点

```gdb
# === 对象生命周期 ===
break bpf_object__open_file        # ELF 打开入口
break bpf_object_open              # 核心 open 逻辑
break bpf_object__elf_init         # ELF 初始化
break bpf_object__elf_collect      # section 收集

# === Map 创建 ===
break bpf_object__create_maps      # 创建所有 map
break bpf_map_create               # 单个 map syscall

# === BTF 处理 ===
break btf__new                     # BTF 解析
break btf__load_into_kernel        # BTF 上传到内核
break bpf_object__relocate_core    # CO-RE 重定位入口
break bpf_core_calc_relo_insn      # 单条指令重定位

# === 程序加载 ===
break bpf_object__load_progs       # 加载所有程序
break bpf_prog_load                # 单个 prog syscall
break bpf_object__relocate         # 重定位入口

# === Attach ===
break bpf_program__attach          # 通用 attach
break bpf_program__attach_kprobe   # kprobe attach
break bpf_program__attach_tracepoint # tracepoint attach
```

### 1.3 GDB 调试会话示例

```gdb
gdb ./trace_openat

# 在关键函数设断点
(gdb) break bpf_object__open_file
(gdb) break bpf_object__elf_collect
(gdb) break bpf_object__relocate_core
(gdb) break bpf_prog_load

# 运行
(gdb) run

# 断在 open_file 时，查看参数
(gdb) print path
(gdb) print opts->sz

# 继续到 elf_collect，查看解析结果
(gdb) continue
(gdb) print obj->nr_programs
(gdb) print obj->nr_maps
(gdb) print obj->btf

# 继续到 CO-RE 重定位
(gdb) continue
(gdb) print *relo       # 查看重定位记录
(gdb) print targ_res    # 查看目标解析结果

# 继续到 prog_load，查看 syscall 参数
(gdb) continue
(gdb) print attr->prog_type
(gdb) print attr->insn_cnt
(gdb) print attr->license
```

### 1.4 追踪数据结构

```gdb
# 打印 bpf_object 完整结构
(gdb) set print pretty on
(gdb) print *obj

# 查看程序列表
(gdb) print obj->programs[0]
(gdb) print obj->programs[0].name
(gdb) print obj->programs[0].sec_name
(gdb) print obj->programs[0].type

# 查看 map 列表
(gdb) print obj->maps[0]
(gdb) print obj->maps[0].name
(gdb) print obj->maps[0].def.type
(gdb) print obj->maps[0].def.key_size

# 查看 BTF 类型
(gdb) print obj->btf->nr_types
(gdb) print obj->btf->types_data
```

---

## 2. strace 观察 BPF Syscall

### 2.1 基本跟踪

```bash
# 只跟踪 bpf 和 perf_event_open 系统调用
strace -e bpf,perf_event_open,ioctl -f ./trace_openat 2>&1 | tee strace.log

# 带时间戳的详细输出
strace -e bpf -v -tt -T ./trace_openat 2>&1 | head -100
```

### 2.2 预期输出分析

```
# 典型加载流程的 syscall 序列:

# 1. 创建 BTF（如果内核支持）
bpf(BPF_BTF_LOAD, {btf=..., btf_size=...}) = 3

# 2. 创建 Map
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_RINGBUF, ...}) = 4

# 3. 加载程序
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_TRACEPOINT, insn_cnt=XX, ...}) = 5

# 4. Attach（通过 perf_event_open）
perf_event_open({type=PERF_TYPE_TRACEPOINT, ...}) = 6
ioctl(6, PERF_EVENT_IOC_SET_BPF, 5) = 0
ioctl(6, PERF_EVENT_IOC_ENABLE, 0) = 0
```

### 2.3 过滤与统计

```bash
# 只看 bpf syscall 的命令类型统计
strace -e bpf -c ./trace_openat 2>&1

# 看 map 操作的详细参数
strace -e bpf -v ./trace_openat 2>&1 | grep MAP

# 看程序加载的 log_buf（验证器输出）
strace -e bpf -v -s 4096 ./trace_openat 2>&1 | grep -A5 PROG_LOAD
```

---

## 3. bpftool 查看加载结果

### 3.1 查看已加载程序

```bash
# 列出所有 BPF 程序
bpftool prog list

# 查看特定程序详情（假设 id=42）
bpftool prog show id 42

# dump 程序的 JIT 汇编
bpftool prog dump jited id 42

# dump 程序的 BPF 字节码
bpftool prog dump xlated id 42

# 查看程序的 BTF 信息
bpftool prog dump xlated id 42 linum
```

### 3.2 查看 Map

```bash
# 列出所有 map
bpftool map list

# 查看 map 内容
bpftool map dump id 5

# 查看特定 key 的值
bpftool map lookup id 5 key 0x01 0x00 0x00 0x00

# Pin map 到文件系统
bpftool map pin id 5 /sys/fs/bpf/my_map
```

### 3.3 查看 BTF

```bash
# 列出内核 BTF
bpftool btf list

# dump 特定 BTF 中的类型
bpftool btf dump id 1 format c | head -100

# 查看 vmlinux BTF 中特定类型
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A20 "struct task_struct {"
```

### 3.4 查看 Link

```bash
# 列出所有 BPF link
bpftool link list

# 查看 link 详情
bpftool link show id 1
```

---

## 4. ftrace 跟踪内核端 BPF 执行

### 4.1 跟踪 BPF 系统调用处理

```bash
# 设置跟踪的内核函数
cd /sys/kernel/debug/tracing

echo '__sys_bpf' > set_ftrace_filter
echo 'bpf_prog_load' >> set_ftrace_filter
echo 'bpf_check' >> set_ftrace_filter
echo 'do_check' >> set_ftrace_filter
echo 'bpf_map_alloc' >> set_ftrace_filter

echo function_graph > current_tracer
echo 1 > tracing_on

# 运行 BPF 程序
/path/to/trace_openat &
sleep 2

# 查看结果
cat trace | head -100
echo 0 > tracing_on
```

### 4.2 跟踪 BPF 程序执行

```bash
# 跟踪 BPF 程序被触发的路径
echo 'bpf_trace_run*' > set_ftrace_filter
echo 'bpf_prog_run' >> set_ftrace_filter
echo function > current_tracer
echo 1 > tracing_on

# 触发事件（例如 open 一个文件）
cat /etc/passwd > /dev/null

cat trace
```

### 4.3 kprobe 跟踪 verifier

```bash
# 跟踪 verifier 的验证过程
echo 0 > tracing_on
echo > trace
echo 'bpf_check' > set_ftrace_filter
echo 'do_check_common' >> set_ftrace_filter
echo 'check_subprogs' >> set_ftrace_filter
echo 'check_btf_info' >> set_ftrace_filter
echo function_graph > current_tracer
echo 1 > tracing_on

# 加载一个新 BPF 程序
bpftool prog load test.bpf.o /sys/fs/bpf/test

cat trace
```

---

## 5. 综合调试方法论

### 5.1 libbpf 加载全流程跟踪

```
用户态 (GDB + strace)          │  内核态 (ftrace + GDB)
─────────────────────────────── │  ────────────────────────────
bpf_object__open_file()        │
  → elf_init, elf_collect      │
  → btf__new()                 │
                               │
bpf_object__load()             │
  → create_maps                │
    → bpf(BPF_MAP_CREATE)      │  → map_create() → bpf_map_alloc()
  → relocate_core              │
  → load_progs                 │
    → bpf(BPF_PROG_LOAD)       │  → bpf_prog_load() → bpf_check()
                               │    → do_check() [verifier]
                               │    → bpf_int_jit_compile()
bpf_program__attach()          │
  → perf_event_open()          │  → perf_event_alloc()
  → ioctl(SET_BPF)             │  → perf_event_set_bpf_prog()
```

### 5.2 问题排查检查清单

| 症状 | 检查点 | 工具 |
|---|---|---|
| open 失败 | ELF 格式正确？section 名正确？ | readelf -S xxx.bpf.o |
| map 创建失败 | 类型/大小参数？权限？ | strace -e bpf |
| 验证器拒绝 | log_buf 输出 | strace -v -s 4096 |
| CO-RE 重定位失败 | vmlinux BTF 存在？类型匹配？ | bpftool btf dump |
| attach 失败 | hook 点存在？权限？ | cat available_filter_functions |
| 无事件输出 | 程序是否加载？hook 是否触发？ | bpftool prog list + ftrace |

---

## 6. 实践验证路线图

```
阶段1: 编译调试版 libbpf (CFLAGS="-g -O0")
  ↓
阶段2: GDB 跟踪完整 open→load→attach 流程
  ↓
阶段3: strace 对照验证 syscall 序列
  ↓
阶段4: bpftool 确认加载结果
  ↓
阶段5: ftrace 内核端验证（需 QEMU 或 root）
  ↓
阶段6: 修改示例程序触发各种错误路径，验证错误处理
```
