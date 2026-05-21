# fentry_example

## 用途
该示例演示使用 `fentry/fexit` trampoline 跟踪 `tcp_sendmsg`：
- `fentry` 直接获取函数参数，记录发送请求的字节数与套接字四元组；
- `fexit` 获取返回值，并通过 ring buffer 将完整事件送到用户态；
- 相比 `kprobe`，`fentry/fexit` 无需 `int3` 断点，开销更低。

## 编译方法
```bash
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice/fentry_example
make
```

## 运行方法
```bash
sudo ./fentry_tcp
```

另开一个终端触发 TCP 发送，例如：
```bash
curl http://127.0.0.1:8080
```

## 预期输出
```text
开始跟踪 tcp_sendmsg，按 Ctrl+C 退出...
PID=32401 COMM=curl             请求=78 返回=78 127.0.0.1:45210 -> 127.0.0.1:8080
```
