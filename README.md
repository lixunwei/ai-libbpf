# ai-libbpf — libbpf 源码深入分析与实践

基于 [libbpf](https://github.com/libbpf/libbpf) v1.8.0 的全方位源码分析，配合可编译的 BPF 示例程序和调试实践指南。

## 📚 分析文档

| 文档 | 内容概要 |
|------|----------|
| [架构总览](libbpf_architecture_overview.md) | API 分层设计、核心数据结构、模块依赖关系 |
| [程序加载流程](libbpf_program_loading_deep.md) | `open → prepare → load` 完整调用链（含源码行号） |
| [BTF 与 CO-RE](libbpf_btf_core_deep.md) | BTF 解析/dedup/上传 + CO-RE 重定位引擎全解析 |
| [Syscall 封装层](libbpf_syscall_layer_deep.md) | `bpf.c` 中所有 `bpf()` 系统调用的封装 |
| [ELF 解析与链接器](libbpf_elf_linker_deep.md) | ELF section 解析 + BPF 静态链接器 |
| [Ring Buffer 与 USDT](libbpf_ringbuf_usdt_deep.md) | 高性能数据通道 + 用户态探针 |
| [Netlink 与特性探测](libbpf_netlink_features_deep.md) | 网络子系统交互 + 内核特性检测 |
| [Skeleton 与 gen_loader](libbpf_skeleton_genloader_deep.md) | 代码生成 + 轻量级加载器 |
| [内核交叉引用](libbpf_kernel_correlation.md) | libbpf 函数 ↔ 内核实现对照表 |
| [分析计划](libbpf_analysis_plan.md) | 完整项目规划与执行记录 |

## 🔧 实践示例

5 个可编译运行的 BPF 程序，覆盖主要使用场景：

```
practice/
├── tracepoint_example/   # 跟踪 sys_enter_openat（ringbuf 传递事件）
├── kprobe_example/       # kprobe 跟踪 tcp_connect
├── xdp_example/          # XDP 包统计与丢弃
├── ringbuf_example/      # sched_process_exec 进程事件
└── core_portable/        # CO-RE 可移植 task_struct 读取
```

### 编译

```bash
# 前置依赖
sudo apt install clang-14 libelf-dev zlib1g-dev linux-tools-common

# 编译所有示例
cd practice
make          # 默认使用 bundled vmlinux.h

# 使用当前内核 BTF 生成 vmlinux.h
make USE_KERNEL_BTF=1
```

### 运行

```bash
# 需要 root 权限（加载 BPF 程序）
sudo ./practice/tracepoint_example/trace_openat
sudo ./practice/kprobe_example/kprobe_tcp
sudo ./practice/xdp_example/xdp_drop <interface>
```

## 🐛 调试指南

| 文档 | 内容 |
|------|------|
| [QEMU 环境搭建](practice/QEMU_SETUP.md) | 内核配置、rootfs 制作、QEMU 启动、GDB 远程调试 |
| [调试方法](practice/DEBUG_GUIDE.md) | GDB 断点、strace 跟踪、bpftool 检查、ftrace 内核端 |
| [BTF/CO-RE 实践](practice/BTF_CORE_PRACTICE.md) | pahole 分析、CO-RE 重定位验证、跨版本测试 |

## 🏗️ 项目结构

```
.
├── *.md                    # 10 篇源码分析文档（中文）
└── practice/
    ├── Makefile            # 顶层构建（自动编译 libbpf + 示例）
    ├── QEMU_SETUP.md       # QEMU 调试环境
    ├── DEBUG_GUIDE.md      # 调试工具使用
    ├── BTF_CORE_PRACTICE.md # BTF/CO-RE 实验
    └── {5个示例目录}/
        ├── *.bpf.c        # BPF 内核态程序
        ├── *.c            # 用户态加载程序
        ├── Makefile        # 子目录编译
        └── README.md       # 中文说明
```

## 📖 关联知识库

本项目与以下 Linux 内核知识库配合使用：

- **eBPF 内核实现**：verifier、JIT、maps、trampoline 等 19 篇深度分析
- **调试工具**：clangd、QEMU BPF 调试、ftrace 实验、pahole 分析

## 📝 分析方法

- 使用 **clangd LSP** 进行精确的语义分析（调用层次、定义跳转）
- 使用 **cscope** 进行大规模调用关系搜索
- 使用 **zoekt** 进行全文本代码搜索
- 使用 **ctags** 进行符号索引查询
- 结合 **git log/blame** 理解代码演进

## License

分析文档采用 CC BY 4.0 许可。示例代码采用 GPL-2.0（与 BPF 程序惯例一致）。
