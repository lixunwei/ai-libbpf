# QEMU eBPF 调试环境搭建指南

## 概述

本文档指导如何搭建 QEMU 虚拟环境来调试 libbpf 和 BPF 程序。
基于内核知识库中的实践经验。

**参考知识库**:
- `/home/nio/sda/source/Linux/linux/darren/tools/qemu_bpf_verification.md`
- `/home/nio/sda/source/Linux/linux/darren/tools/qemu_ebpf_bpftrace_debug.md`
- `/home/nio/sda/source/Linux/linux/darren/tools/qemu_ftrace_setup.md`

---

## 1. 内核配置要求

### 1.1 BPF 核心配置

```
# BPF 基础
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_EVENTS=y
CONFIG_BPF_LSM=y

# BTF 支持（CO-RE 必须）
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y

# Map 类型
CONFIG_BPF_STREAM_PARSER=y
CONFIG_NETFILTER_XT_MATCH_BPF=y
CONFIG_NET_ACT_BPF=y
CONFIG_NET_CLS_BPF=y

# XDP
CONFIG_XDP_SOCKETS=y
CONFIG_XDP_SOCKETS_DIAG=y

# Tracing
CONFIG_KPROBES=y
CONFIG_UPROBE_EVENTS=y
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y

# 调试
CONFIG_GDB_SCRIPTS=y
CONFIG_FRAME_POINTER=y
```

### 1.2 生成配置

```bash
cd /home/nio/sda/source/Linux/linux

# 基于 defconfig 添加 BPF 支持
make ARCH=x86_64 defconfig
scripts/config --enable BPF_SYSCALL
scripts/config --enable BPF_JIT
scripts/config --enable BPF_JIT_ALWAYS_ON
scripts/config --enable BPF_EVENTS
scripts/config --enable DEBUG_INFO_BTF
scripts/config --enable DEBUG_INFO_DWARF5
scripts/config --enable KPROBES
scripts/config --enable UPROBE_EVENTS
scripts/config --enable FTRACE
make olddefconfig
```

---

## 2. 内核编译

```bash
cd /home/nio/sda/source/Linux/linux

# x86_64 编译（本机调试最简单）
make -j$(nproc) ARCH=x86_64

# 生成 BTF（需要 pahole >= 1.16）
# BTF 会自动嵌入 vmlinux（如果 pahole 可用）

# 验证 BTF 生成
file vmlinux | grep BTF
readelf -S vmlinux | grep .BTF

# 生成 compile_commands.json（可选，用于 clangd）
scripts/clang-tools/gen_compile_commands.py
```

---

## 3. Rootfs 制作

### 3.1 使用 debootstrap（完整 Debian rootfs）

```bash
ROOTFS_DIR=/tmp/bpf-rootfs
mkdir -p $ROOTFS_DIR

# 创建最小 Debian rootfs
sudo debootstrap --arch=amd64 bullseye $ROOTFS_DIR http://deb.debian.org/debian

# 安装必要工具
sudo chroot $ROOTFS_DIR apt-get install -y \
    libbpf-dev bpftool strace gdb \
    iproute2 iputils-ping net-tools \
    build-essential libelf-dev zlib1g-dev

# 制作 ext4 镜像
dd if=/dev/zero of=rootfs.img bs=1M count=2048
mkfs.ext4 rootfs.img
sudo mount rootfs.img /mnt
sudo cp -a $ROOTFS_DIR/* /mnt/
sudo umount /mnt
```

### 3.2 简化方案：initramfs

```bash
# 最小 initramfs 用于快速测试
mkdir -p /tmp/initramfs/{bin,lib,proc,sys,dev,tmp}

# 复制静态链接的 busybox
cp $(which busybox) /tmp/initramfs/bin/
# 或者编译静态 busybox

# 复制 libbpf 示例程序（静态链接）
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice
make LDFLAGS="-static"
cp tracepoint_example/trace_openat /tmp/initramfs/bin/

# 创建 init 脚本
cat > /tmp/initramfs/init << 'EOF'
#!/bin/busybox sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t debugfs debugfs /sys/kernel/debug
mount -t bpf bpf /sys/fs/bpf
echo "=== BPF 环境就绪 ==="
cat /proc/version
ls /sys/kernel/btf/vmlinux && echo "BTF: OK" || echo "BTF: MISSING"
exec /bin/busybox sh
EOF
chmod +x /tmp/initramfs/init

# 打包 initramfs
cd /tmp/initramfs && find . | cpio -o -H newc | gzip > /tmp/initramfs.cpio.gz
```

---

## 4. QEMU 启动

### 4.1 基本启动（x86_64）

```bash
KERNEL=/home/nio/sda/source/Linux/linux/arch/x86/boot/bzImage

# 使用 initramfs（快速测试）
qemu-system-x86_64 \
    -kernel $KERNEL \
    -initrd /tmp/initramfs.cpio.gz \
    -append "console=ttyS0 nokaslr" \
    -nographic \
    -m 2G \
    -smp 4 \
    -enable-kvm \
    -cpu host

# 使用 rootfs 镜像（完整环境）
qemu-system-x86_64 \
    -kernel $KERNEL \
    -drive file=rootfs.img,format=raw \
    -append "root=/dev/sda console=ttyS0 nokaslr" \
    -nographic \
    -m 4G \
    -smp 4 \
    -enable-kvm \
    -cpu host \
    -net nic -net user,hostfwd=tcp::2222-:22
```

### 4.2 带 GDB 调试

```bash
# 启动 QEMU（暂停在启动处等待 GDB）
qemu-system-x86_64 \
    -kernel $KERNEL \
    -initrd /tmp/initramfs.cpio.gz \
    -append "console=ttyS0 nokaslr" \
    -nographic -m 2G -smp 4 \
    -enable-kvm -cpu host \
    -s -S    # -s: GDB stub on :1234, -S: 暂停等待

# 另一终端连接 GDB
cd /home/nio/sda/source/Linux/linux
gdb vmlinux
(gdb) target remote :1234
(gdb) hbreak bpf_prog_load        # 在 BPF 加载处设断点
(gdb) continue
```

### 4.3 共享文件系统（9p）

```bash
# 将 libbpf 示例目录共享给 QEMU 客户机
qemu-system-x86_64 \
    ... \
    -virtfs local,path=/home/nio/sda/source/Linux/eBPF/libbpf/darren/practice,mount_tag=practice,security_model=mapped-xattr

# 客户机内挂载:
# mount -t 9p -o trans=virtio practice /mnt/practice
```

---

## 5. 验证 BPF 环境

在 QEMU 客户机内执行:

```bash
# 1. 检查 BPF 文件系统
mount | grep bpf
# bpf on /sys/fs/bpf type bpf

# 2. 检查 BTF 可用性
ls /sys/kernel/btf/vmlinux
# /sys/kernel/btf/vmlinux

# 3. 检查 BPF JIT
cat /proc/sys/net/core/bpf_jit_enable
# 1

# 4. 检查可跟踪函数数
cat /sys/kernel/debug/tracing/available_filter_functions | wc -l
# ~55000+

# 5. 运行 bpftool 验证
bpftool feature probe
bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
```

---

## 6. 调试 libbpf 加载流程

### 6.1 用户态 GDB 调试 libbpf

```bash
# 编译带调试信息的 libbpf
cd /home/nio/sda/source/Linux/eBPF/libbpf/src
make clean && make CFLAGS="-g -O0"

# 编译示例程序（带调试信息）
cd /home/nio/sda/source/Linux/eBPF/libbpf/darren/practice/tracepoint_example
make CFLAGS="-g -O0"

# GDB 调试
gdb ./trace_openat
(gdb) break bpf_object__open_file
(gdb) break bpf_object__load
(gdb) break bpf_object__create_maps
(gdb) break bpf_prog_load
(gdb) run
```

### 6.2 用 strace 观察 syscall

```bash
strace -e bpf,perf_event_open,ioctl ./trace_openat 2>&1 | head -50
```

### 6.3 用 ftrace 跟踪内核端

```bash
# 跟踪 BPF 相关内核函数
echo 'bpf_prog_load' > /sys/kernel/debug/tracing/set_ftrace_filter
echo 'bpf_check' >> /sys/kernel/debug/tracing/set_ftrace_filter
echo 'bpf_int_jit_compile' >> /sys/kernel/debug/tracing/set_ftrace_filter
echo function > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/tracing_on

# 运行 BPF 程序
./trace_openat &
sleep 1

# 查看跟踪结果
cat /sys/kernel/debug/tracing/trace
```

---

## 7. 常见问题

| 问题 | 解决方案 |
|---|---|
| BTF 不可用 | 确认 CONFIG_DEBUG_INFO_BTF=y 且 pahole >= 1.16 |
| bpf() 返回 EPERM | `echo 0 > /proc/sys/kernel/unprivileged_bpf_disabled` 或用 root |
| 程序验证失败 | 检查 `bpf_prog_load()` 的 log_buf 输出 |
| map 创建失败 ENOMEM | 旧内核需提升 RLIMIT_MEMLOCK |
| CO-RE 重定位失败 | 确认 /sys/kernel/btf/vmlinux 存在 |
| XDP attach 失败 | 确认网卡驱动支持 XDP（QEMU virtio-net 支持 generic XDP）|
