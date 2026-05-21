# cgroup_example

## 用途
该示例演示 `cgroup_skb/egress` 程序的典型用法：
- 对指定 cgroup 的出向 IPv4 流量进行统计；
- 按目的 IP 维护包计数哈希表；
- 可选阻断某个目的 IPv4 地址的出向流量（返回 `0` 表示丢弃，返回 `1` 表示放行）。

## 环境要求
- 需要使用 **cgroup v2**；
- 程序附加的目标目录必须是 cgroup v2 层级中的有效 cgroup；
- 默认路径为 `/sys/fs/cgroup/user.slice`，也可以通过命令行传入其他 cgroup 路径。

可以用以下命令确认：
```bash
stat -fc %T /sys/fs/cgroup
```
若输出为 `cgroup2fs`，说明当前系统已启用 cgroup v2。

## 编译方法
```bash
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice/cgroup_example
make
```

## 运行方法
默认附加到 `user.slice`：
```bash
sudo ./cgroup_egress
```

指定 cgroup 路径并阻断某个目标 IPv4：
```bash
sudo ./cgroup_egress /sys/fs/cgroup/user.slice 8.8.8.8
```

## 预期输出
```text
已附加到 cgroup: /sys/fs/cgroup/user.slice
阻断目的 IPv4: 8.8.8.8
每 2 秒输出一次统计，按 Ctrl+C 退出...
当前目的 IP 统计：
  1.1.1.1 -> 12
  8.8.8.8 -> 4
```
