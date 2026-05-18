# tracepoint_example

## 用途
该示例通过 `tracepoint/syscalls/sys_enter_openat` 跟踪进程打开文件的系统调用，记录 `pid`、进程名和文件名，并通过 ring buffer 发送到用户态。

## 编译方法
```bash
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice/tracepoint_example
make
```

或在顶层目录统一编译：
```bash
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice
make all
```

## 运行方法
```bash
sudo ./trace_openat
```

另开一个终端执行：
```bash
touch /tmp/demo.txt
cat /etc/hosts
```

## 预期输出
```text
开始跟踪 openat，按 Ctrl+C 退出...
PID=12345 COMM=bash             FILE=/etc/hosts
PID=12346 COMM=touch            FILE=/tmp/demo.txt
```
