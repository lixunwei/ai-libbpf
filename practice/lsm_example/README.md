# lsm_example

## 用途
该示例演示使用 BPF LSM 在 `file_open` 安全钩子上实现简单访问控制：
- 通过 `bpf_d_path()` 获取当前打开文件的完整路径；
- 当路径包含 `/tmp/blocked` 时返回 `-EPERM` 拒绝访问；
- 同时把被拒绝的访问事件通过 ring buffer 上报到用户态。

## 内核要求
运行该示例前，需要满足以下条件：
- 内核配置启用 `CONFIG_BPF_LSM=y`；
- 启动参数需要让 `bpf` LSM 生效，例如：`lsm=lockdown,yama,integrity,apparmor,bpf`。

可以用下面的命令检查：
```bash
cat /sys/kernel/security/lsm
```
如果输出中包含 `bpf`，说明 BPF LSM 已启用。

## 编译方法
```bash
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice/lsm_example
make
```

## 运行方法
```bash
sudo ./lsm_file_open
```

另开一个终端测试：
```bash
touch /tmp/blocked.txt
cat /tmp/blocked.txt
```

## 预期输出
```text
开始监控文件访问，命中 /tmp/blocked 将被拒绝，按 Ctrl+C 退出...
拒绝访问: PID=33518 COMM=cat              PATH=/tmp/blocked.txt
```
