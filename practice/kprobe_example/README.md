# kprobe_example

## 用途
该示例通过 `kprobe/tcp_connect` 跟踪内核 TCP 连接建立过程，记录发起连接的进程、源/目的地址和端口，并通过 ring buffer 发送到用户态打印。

## 编译方法
```bash
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice/kprobe_example
make
```

## 运行方法
```bash
sudo ./kprobe_tcp
```

另开一个终端触发连接：
```bash
curl http://127.0.0.1:8080
```

## 预期输出
```text
开始跟踪 tcp_connect，按 Ctrl+C 退出...
PID=22341 COMM=curl             127.0.0.1:45018 -> 127.0.0.1:8080
```
