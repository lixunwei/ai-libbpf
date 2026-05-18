# xdp_example

## 用途
该示例演示最基础的 XDP 包处理流程：
- 统计经过网卡的数据包数量；
- 可选地按目标端口丢弃 TCP/UDP 流量；
- 用户态每秒读取一次统计值。

## 编译方法
```bash
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice/xdp_example
make
```

## 运行方法
只统计不过滤：
```bash
sudo ./xdp_drop -i eth0
```

丢弃目标端口为 8080 的包：
```bash
sudo ./xdp_drop -i eth0 -p 8080
```

如果驱动支持，也可以切换到 native 模式：
```bash
sudo ./xdp_drop -i eth0 -p 8080 -N
```

## 预期输出
```text
XDP 已挂载到 eth0，drop_port=8080，按 Ctrl+C 退出...
packets=1287 drops=24
packets=1432 drops=31
```
