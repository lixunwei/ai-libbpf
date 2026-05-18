# ringbuf_example

## 用途
该示例演示 ring buffer 的典型数据传递方式：
- BPF 侧使用 `bpf_ringbuf_reserve()` / `bpf_ringbuf_submit()` 发送事件；
- 用户态使用 `ring_buffer__poll()` 消费事件；
- 触发点选择 `sched_process_exec`，因此每次执行新程序都会产生一条事件。

## 编译方法
```bash
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice/ringbuf_example
make
```

## 运行方法
```bash
sudo ./ringbuf_event
```

另开一个终端执行一些命令，例如：
```bash
ls
uname -a
```

## 预期输出
```text
开始消费 ring buffer 事件，按 Ctrl+C 退出...
exec: pid=30124 tgid=30124 ppid=29871 comm=ls
exec: pid=30125 tgid=30125 ppid=29871 comm=uname
```
