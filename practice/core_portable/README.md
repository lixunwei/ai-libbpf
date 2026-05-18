# core_portable

## 用途
该示例展示 CO-RE（Compile Once – Run Everywhere）的基本用法：
- BPF 程序通过 `bpf_get_current_task_btf()` 获取当前 `task_struct`；
- 使用 `BPF_CORE_READ()` 读取 `pid/tgid/comm/start_time`；
- 通过 `bpf_core_field_exists()` 兼容不同内核字段差异。

## CO-RE 原理说明
CO-RE 的核心是：
1. 编译期基于 `vmlinux.h` 和 BTF 信息生成重定位信息；
2. 加载期由 libbpf 根据目标内核实际 BTF 自动修正字段偏移；
3. 因此同一个 BPF ELF 文件可以跨多个内核版本运行，只要相关类型在 BTF 中可解析。

本示例中，`task_struct` 的 `start_boottime` 与 `start_time` 在不同内核上可能存在差异，因此示例使用 `bpf_core_field_exists()` 进行兼容处理，体现 CO-RE 可移植性。

## 编译方法
```bash
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice/core_portable
make
```

## 运行方法
```bash
sudo ./core_task_info
```

另开一个终端执行一些命令，例如：
```bash
sleep 1
/bin/echo hello
```

## 预期输出
```text
CO-RE 示例已启动，按 Ctrl+C 退出...
CO-RE event: pid=41025 tgid=41025 comm=sleep            start_time=1234567890
CO-RE event: pid=41026 tgid=41026 comm=echo             start_time=1234567999
```
