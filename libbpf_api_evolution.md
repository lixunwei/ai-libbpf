# libbpf API 版本演进

本文基于 `src/libbpf.map`、`src/libbpf.h`、`src/bpf.h`、`src/libbpf_legacy.h`、`src/libbpf_common.h` 与仓库文档整理。

当前 `libbpf.map` 共定义 26 个导出符号版本：
- `LIBBPF_0.0.1`
- `LIBBPF_0.0.2`
- `LIBBPF_0.0.3`
- `LIBBPF_0.0.4`
- `LIBBPF_0.0.5`
- `LIBBPF_0.0.6`
- `LIBBPF_0.0.7`
- `LIBBPF_0.0.8`
- `LIBBPF_0.0.9`
- `LIBBPF_0.1.0`
- `LIBBPF_0.2.0`
- `LIBBPF_0.3.0`
- `LIBBPF_0.4.0`
- `LIBBPF_0.5.0`
- `LIBBPF_0.6.0`
- `LIBBPF_0.7.0`
- `LIBBPF_0.8.0`
- `LIBBPF_1.0.0`
- `LIBBPF_1.1.0`
- `LIBBPF_1.2.0`
- `LIBBPF_1.3.0`
- `LIBBPF_1.4.0`
- `LIBBPF_1.5.0`
- `LIBBPF_1.6.0`
- `LIBBPF_1.7.0`
- `LIBBPF_1.8.0`

版本继承链可概括为：

```text
LIBBPF_0.0.1 -> LIBBPF_0.0.2 -> LIBBPF_0.0.3 -> LIBBPF_0.0.4 -> LIBBPF_0.0.5
-> LIBBPF_0.0.6 -> LIBBPF_0.0.7 -> LIBBPF_0.0.8 -> LIBBPF_0.0.9 -> LIBBPF_0.1.0
-> LIBBPF_0.2.0 -> LIBBPF_0.3.0 -> LIBBPF_0.4.0 -> LIBBPF_0.5.0 -> LIBBPF_0.6.0
-> LIBBPF_0.7.0 -> LIBBPF_0.8.0 -> LIBBPF_1.0.0 -> LIBBPF_1.1.0 -> LIBBPF_1.2.0
-> LIBBPF_1.3.0 -> LIBBPF_1.4.0 -> LIBBPF_1.5.0 -> LIBBPF_1.6.0 -> LIBBPF_1.7.0 -> LIBBPF_1.8.0
```

---

## 1. 符号版本机制

### 1.1 GNU symbol versioning 原理

- GNU symbol versioning 允许同一个 shared library 在 ABI 层面对导出符号分代管理。
- 动态链接器在装载程序时，不只看符号名，还会看“符号名 + 版本标签”的组合。
- 对 libbpf 而言，版本标签写在 `src/libbpf.map`，最终进入 `.gnu.version*` 相关 ELF section。
- 老程序链接到旧版本 symbol 时，即使新库继续演进，也仍可解析到兼容实现。
- 新程序可以链接到新版本 symbol，而不破坏已发布二进制对旧 ABI 的依赖。
- 这也是 libbpf 能在 1.0.0 发生语义升级时，仍尽量保住动态链接兼容性的关键机制。

### 1.2 `libbpf.map` 文件格式

- `libbpf.map` 使用 linker version script 语法。
- 每个版本块大致长这样：

```ld
LIBBPF_0.0.2 {
    global:
        bpf_map_lookup_elem_flags;
        bpf_object__btf;
        bpf_object__find_map_fd_by_name;
    local:
        *;
} LIBBPF_0.0.1;
```

- 版本块名如 `LIBBPF_0.6.0` 对应一个可见 ABI 层级。
- `global:` 下列出对外导出的 symbol。
- `local:` 用于把没有明确列在 `global:` 的其余 symbol 变成库内可见。
- 最后的 `} LIBBPF_0.0.1;` 表示当前版本继承前一版的导出集合。

### 1.3 `global:` 与 `local: *;` 的含义

- `global:` 表示这些符号可被外部可执行文件或其他库链接。
- `local: *;` 表示除 `global:` 明确列出的符号外，其余一律隐藏。
- 这种“白名单导出”策略有两个好处：
  - 保证 ABI 面可控，不会把内部 helper、static-like wrapper 意外暴露。
  - 让未来重构更自由，因为内部实现不构成 ABI 承诺。
- 对维护者来说，向 `libbpf.map` 增加 symbol，等价于正式承诺一个新的公共 API。

### 1.4 版本继承链

- 版本脚本中的 `LIBBPF_0.0.2 { ... } LIBBPF_0.0.1;` 含义不是“复制代码”，而是“继承可见 ABI 集合”。
- 因此 `LIBBPF_1.8.0` 进程中可见的并不只是 1.8.0 那几个新符号，而是整个祖先链上的全部导出符号。
- 从 API 使用角度看：
  - 新版程序可以链接老 symbol。
  - 老版程序运行在新 libbpf.so 上时，也能解析自己原本依赖的 symbol version。
- 从维护角度看：
  - 新增 API：放到新版本块。
  - 旧 API 保 ABI：保留原 symbol version。
  - 真正的 breaking changes 更多体现在语义与推荐用法，而不一定是删导出符号。

### 1.5 libbpf 为什么特别依赖 symbol versioning

- libbpf 同时面对三个变化面：kernel feature、用户程序写法、库自身抽象。
- kernel feature 变化快，意味着 libbpf 必须不断引入新 API 包装新 syscall、新 map type、新 attach 点。
- 用户程序通常以 distro package 形式动态链接 libbpf，ABI 稳定性比 header 级别 API 演进更重要。
- 0.x 到 1.x 的迁移期里，libbpf 还需要同时背负 legacy API 与新风格 API。
- symbol versioning 让这些目标可以并行推进。

---

## 2. 各版本关键 API 变更

本节按 `libbpf.map` 顺序逐版列出“重要新增 API”，不是完整 symbol 清单。

### 2.1 LIBBPF_0.0.1

- **定位**：首个稳定导出符号集合，奠定 object / program / map / BTF 四条主线。
- **基础 object API**：`bpf_object__open`、`bpf_object__load`、`bpf_object__close` 形成最早的 open-load-close 工作流。
- **基础 map API**：`bpf_map_lookup_elem`、`bpf_map_update_elem`、`bpf_map_delete_elem`、`bpf_map_get_next_key` 覆盖最小 CRUD。
- **基础 map 元数据**：`bpf_map__fd`、`bpf_map__name`、`bpf_map__pin`、`bpf_map__unpin` 支持 FD 查询与 pinning。
- **基础 program API**：`bpf_program__fd`、`bpf_program__set_type`、`bpf_program__set_expected_attach_type` 是最早的 program 配置接口。
- **基础 load/attach**：`bpf_prog_attach`、`bpf_prog_detach`、`bpf_prog_query`、`bpf_raw_tracepoint_open` 提供 attach 面能力。
- **基础 BTF**：`btf__new`、`btf__type_by_id`、`btf__resolve_type`、`btf__resolve_size` 让用户态可解析 BTF。
- **日志与错误**：`libbpf_set_print`、`libbpf_get_error`、`libbpf_strerror` 确立早期错误处理模型。

### 2.2 LIBBPF_0.0.2

- **增量重点**：开始补齐 object 与 BTF raw data 访问能力。
- **新符号**：`bpf_map_lookup_elem_flags` 允许把 lookup flags 显式传到内核。
- **新符号**：`bpf_object__btf`、`bpf_object__find_map_fd_by_name` 让 object 内部信息更易枚举。
- **新符号**：`btf__get_raw_data`、`btf_ext__new`、`btf_ext__get_raw_data` 推动 BTF.ext 使用。
- **影响**：从这版开始，libbpf 不再只提供 load API，还逐步成为 BTF 工具库。

### 2.3 LIBBPF_0.0.3

- **增量重点**：引入更细粒度的 map 管理。
- **新符号**：`bpf_map__is_internal` 区分用户定义 map 与 libbpf 自动生成的 internal map。
- **新符号**：`bpf_map_freeze` 暴露 `BPF_MAP_FREEZE`，可以在用户态把 map 置为只读布局。
- **影响**：internal map 概念后来成为 global data、kconfig extern、ksym extern 的基础。

### 2.4 LIBBPF_0.0.4

- **增量重点**：attach API 与 perf_buffer/BTF dump 开始成形。
- **新符号**：`bpf_link__destroy` 开始把 attach 生命周期抽象为 `bpf_link`。
- **新符号**：`bpf_program__attach_kprobe`、`attach_uprobe`、`attach_tracepoint`、`attach_raw_tracepoint`、`attach_perf_event`。
- **新符号**：`perf_buffer__free`、`perf_buffer__poll` 让 perf event array 有了高层消费接口。
- **新符号**：`btf_dump__dump_type`、`btf_dump__free`、`btf__parse_elf` 提高 BTF 可视化能力。
- **影响**：libbpf 从“加载器”进一步扩展为“attach + event consumption + BTF tooling”平台。

### 2.5 LIBBPF_0.0.5

- **增量重点**：补充按 ID 枚举 BTF。
- **新符号**：`bpf_btf_get_next_id`。
- **影响**：与 `bpf_btf_get_fd_by_id` 配合后，用户态可以遍历内核注册的 BTF 对象。

### 2.6 LIBBPF_0.0.6

- **增量重点**：object 打开方式、pin path 管理、trace attach 继续扩展。
- **新符号**：`bpf_object__open_file`、`bpf_object__open_mem` 取代单一按路径打开的早期接口思路。
- **新符号**：`bpf_map__set_pin_path`、`bpf_map__is_pinned`、`bpf_map__get_pin_path`。
- **新符号**：`bpf_program__attach_trace` 统一 trace 类 attach。
- **新符号**：`libbpf_find_vmlinux_btf_id`、`btf__find_by_name_kind` 提高 BTF 检索能力。
- **影响**：这一版已经能看到“以 opts 与 metadata 驱动复杂加载”的方向。

### 2.7 LIBBPF_0.0.7

- **增量重点**：skeleton、batch map ops、struct_ops 初见雏形。
- **新符号**：`bpf_map_lookup_batch`、`bpf_map_update_batch`、`bpf_map_delete_batch`、`bpf_map_lookup_and_delete_batch`。
- **新符号**：`bpf_map__attach_struct_ops` 首次把 `STRUCT_OPS` map attach 暴露为高层 API。
- **新符号**：`bpf_object__open_skeleton`、`load_skeleton`、`attach_skeleton`、`detach_skeleton`、`destroy_skeleton`。
- **新符号**：`bpf_program__attach` 作为通用 attach dispatcher。
- **新符号**：`bpf_program__name`、`bpf_object__find_program_by_name`。
- **影响**：这版标志着 skeleton 工作流正式进入公开 API。

### 2.8 LIBBPF_0.0.8

- **增量重点**：`bpf_link` 抽象开始成为 attach 首选。
- **新符号**：`bpf_link__fd`、`bpf_link__pin`、`bpf_link__unpin`、`bpf_link__pin_path`、`bpf_link__open`。
- **新符号**：`bpf_link_create`、`bpf_link_update` 把一部分 attach/update 直接下沉到 syscall 层。
- **新符号**：`bpf_program__attach_cgroup`、`attach_lsm`、`set_attach_target`。
- **新符号**：`bpf_prog_attach_opts` 与 `bpf_map__set_initial_value` 体现 opts-based API 思路。
- **影响**：面向 link 的生命周期管理开始替代“attach 后只拿 raw FD”的旧模式。

### 2.9 LIBBPF_0.0.9

- **增量重点**：ringbuf、iter、netns attach。
- **新符号**：`ring_buffer__new`、`ring_buffer__add`、`ring_buffer__poll`、`ring_buffer__consume`、`ring_buffer__free`。
- **新符号**：`bpf_iter_create`、`bpf_program__attach_iter`。
- **新符号**：`bpf_program__attach_netns`。
- **新符号**：`bpf_enable_stats`、`bpf_link_get_fd_by_id`、`bpf_link_get_next_id`。
- **影响**：ringbuf 在事件传输路径上与 perf_buffer 并存，后续逐渐成为首选。

### 2.10 LIBBPF_0.1.0

- **增量重点**：map/program 属性访问器和 XDP attach 完善。
- **新符号**：`bpf_map__type`、`key_size`、`value_size`、`max_entries`、`map_flags`、`numa_node`、`ifindex` 及对应 setter。
- **新符号**：`bpf_program__attach_xdp`、`bpf_program__autoload`、`bpf_program__set_autoload`。
- **新符号**：`btf__parse`、`btf__parse_raw`、`btf__pointer_size`、`btf__set_pointer_size`。
- **影响**：从这一版开始，map metadata 的高层访问器基本齐备。

### 2.11 LIBBPF_0.2.0

- **增量重点**：freplace、prog bind map、BTF builder 系列。
- **新符号**：`bpf_prog_bind_map` 为只读 global data 等场景提供基础。
- **新符号**：`bpf_prog_test_run_opts`。
- **新符号**：`bpf_program__attach_freplace`、`bpf_program__section_name`。
- **新符号**：大批 `btf__add_*` builder API，使 libbpf 可作为 BTF 构建器使用。
- **新符号**：`perf_buffer__buffer_cnt`、`buffer_fd`、`epoll_fd`、`consume_buffer`。
- **影响**：BTF 不再只是解析对象，开始支持增量构造与编辑。

### 2.12 LIBBPF_0.3.0

- **增量重点**：split BTF 与 ring buffer epoll 能力。
- **新符号**：`btf__base_btf`、`btf__parse_split`、`btf__parse_raw_split`、`btf__parse_elf_split`、`btf__new_empty_split`。
- **新符号**：`ring_buffer__epoll_fd`。
- **影响**：为 module BTF、split BTF、外部 BTF 组合场景铺路。

### 2.13 LIBBPF_0.4.0

- **增量重点**：linker、tc hook、map-in-map 元信息。
- **新符号**：`bpf_linker__new`、`add_file`、`finalize`、`free`。
- **新符号**：`bpf_tc_hook_create`、`bpf_tc_attach`、`bpf_tc_query`、`bpf_tc_detach`、`bpf_tc_hook_destroy`。
- **新符号**：`bpf_map__inner_map`、`bpf_object__set_kversion`、`btf__add_float`、`btf__add_type`。
- **影响**：libbpf 开始不仅处理单个 object，还支持链接多个 BPF object。

### 2.14 LIBBPF_0.5.0

- **增量重点**：strict mode、gen_loader、load into kernel。
- **新符号**：`libbpf_set_strict_mode` 用于提前适配 1.0 语义。
- **新符号**：`bpf_object__gen_loader` 代表 gen_loader 能力公开。
- **新符号**：`btf__load_vmlinux_btf`、`btf__load_module_btf`、`btf__load_into_kernel`。
- **新符号**：`bpf_program__attach_kprobe_opts`、`attach_uprobe_opts`、`attach_tracepoint_opts`、`attach_perf_event_opts`。
- **新符号**：`bpf_map__pin_path`、`bpf_map__initial_value`、`bpf_map_lookup_and_delete_elem_flags`。
- **影响**：这版把 1.0 前夜的迁移工具和更现代的 attach 方式都铺好了。

### 2.15 LIBBPF_0.6.0

- **增量重点**：libbpf 自身版本 API、新的 low-level bpf syscall 包装。
- **新符号**：`libbpf_major_version`、`libbpf_minor_version`、`libbpf_version_string`。
- **新符号**：`bpf_map_create` 与新形态 `bpf_prog_load`。
- **新符号**：`bpf_object__next_map`、`prev_map`、`next_program`、`prev_program`。
- **新符号**：`perf_buffer__new`、`perf_buffer__new_raw`。
- **新符号**：`btf__dedup`、`btf_dump__new`、`btf__add_btf`、`btf__add_decl_tag`、`btf__add_type_tag`。
- **影响**：很多旧的 ad-hoc API 被新 low-level/opts 组合替代。

### 2.16 LIBBPF_0.7.0

- **增量重点**：feature probing、XDP 管理、log buffer 控制。
- **新符号**：`libbpf_probe_bpf_prog_type`、`libbpf_probe_bpf_map_type`、`libbpf_probe_bpf_helper`。
- **新符号**：`bpf_xdp_attach`、`bpf_xdp_detach`、`bpf_xdp_query`、`bpf_xdp_query_id`。
- **新符号**：`bpf_btf_load`。
- **新符号**：`bpf_program__set_log_buf`、`set_log_level`、`log_buf`、`log_level`。
- **新符号**：`libbpf_set_memlock_rlim`。
- **影响**：兼容性处理开始从“假设内核支持”切换到“运行时探测”。

### 2.17 LIBBPF_0.8.0

- **增量重点**：map 高层 CRUD、USDT、kprobe_multi、subskeleton。
- **新符号**：`bpf_map__lookup_elem`、`update_elem`、`delete_elem`、`lookup_and_delete_elem`、`get_next_key`。
- **新符号**：`bpf_map__set_autocreate`、`bpf_map__autocreate`。
- **新符号**：`bpf_object__open_subskeleton`、`bpf_object__destroy_subskeleton`。
- **新符号**：`bpf_program__attach_kprobe_multi_opts`、`bpf_program__attach_usdt`、`bpf_program__attach_trace_opts`。
- **新符号**：`libbpf_register_prog_handler`、`libbpf_unregister_prog_handler`。
- **影响**：高层 map 数据操作终于补齐，BTF-defined map 使用体验显著提升。

### 2.18 LIBBPF_1.0.0

- **增量重点**：稳定 API 里程碑。
- **新符号**：`bpf_obj_get_opts`、`bpf_prog_query_opts`。
- **新符号**：`bpf_program__attach_ksyscall`、`bpf_program__autoattach`、`bpf_program__set_autoattach`。
- **新符号**：`btf__add_enum64`、`btf__add_enum64_value`。
- **新符号**：`libbpf_bpf_attach_type_str`、`libbpf_bpf_link_type_str`、`libbpf_bpf_map_type_str`、`libbpf_bpf_prog_type_str`。
- **新符号**：`perf_buffer__buffer`。
- **影响**：从版本号上看是 breaking release；从 ABI 看依旧依赖 symbol versioning 保持向后兼容。

### 2.19 LIBBPF_1.1.0

- **增量重点**：token-aware get-by-id 与 user_ring_buffer。
- **新符号**：`bpf_btf_get_fd_by_id_opts`、`bpf_link_get_fd_by_id_opts`、`bpf_map_get_fd_by_id_opts`、`bpf_prog_get_fd_by_id_opts`。
- **新符号**：`user_ring_buffer__new`、`reserve`、`reserve_blocking`、`submit`、`discard`、`free`。
- **影响**：开始把更细的权限控制与用户态主动生产数据通道带入 libbpf。

### 2.20 LIBBPF_1.2.0

- **增量重点**：按 FD 获取 info，以及 link-map 更新。
- **新符号**：`bpf_btf_get_info_by_fd`、`bpf_link_get_info_by_fd`、`bpf_map_get_info_by_fd`、`bpf_prog_get_info_by_fd`。
- **新符号**：`bpf_link__update_map`。
- **影响**：对象 introspection 与运行时调试能力继续增强。

### 2.21 LIBBPF_1.3.0

- **增量重点**：netfilter、tcx、netkit、uprobe_multi、ring introspection。
- **新符号**：`bpf_program__attach_netfilter`、`attach_tcx`、`attach_netkit`、`attach_uprobe_multi`。
- **新符号**：`bpf_obj_pin_opts`、`bpf_prog_detach_opts`、`bpf_object__unpin`。
- **新符号**：`ring__avail_data_size`、`ring__consumer_pos`、`ring__producer_pos`、`ring__map_fd`、`ring__size`、`ring__consume`。
- **影响**：attach 点从 tracing/networking 向更细粒度内核子系统扩展。

### 2.22 LIBBPF_1.4.0

- **增量重点**：token create、raw tracepoint opts、new split BTF。
- **新符号**：`bpf_token_create`。
- **新符号**：`bpf_program__attach_raw_tracepoint_opts`、`bpf_raw_tracepoint_open_opts`。
- **新符号**：`btf__new_split`、`btf_ext__raw_data`。
- **影响**：权限模型与 raw tracepoint attach 的现代形态逐步完成。

### 2.23 LIBBPF_1.5.0

- **增量重点**：token FD 透传、sockmap attach、ring consume_n。
- **新符号**：`bpf_object__token_fd`。
- **新符号**：`bpf_program__attach_sockmap`。
- **新符号**：`bpf_map__autoattach`、`bpf_map__set_autoattach`。
- **新符号**：`btf__distill_base`、`btf__relocate`、`btf_ext__endianness`、`btf_ext__set_endianness`。
- **新符号**：`ring__consume_n`、`ring_buffer__consume_n`。
- **影响**：BTF 重定位与 ring 消费策略继续成熟。

### 2.24 LIBBPF_1.6.0

- **增量重点**：linker 输入源扩展、prepare 阶段公开、prog stream read。
- **新符号**：`bpf_linker__add_buf`、`bpf_linker__add_fd`、`bpf_linker__new_fd`。
- **新符号**：`bpf_object__prepare`。
- **新符号**：`bpf_prog_stream_read`。
- **新符号**：`bpf_program__attach_cgroup_opts`、`func_info`、`func_info_cnt`、`line_info`、`line_info_cnt`。
- **新符号**：`btf__add_decl_attr`、`btf__add_type_attr`。
- **影响**：object 生命周期从 open/load 细化为 open/prepare/load。

### 2.25 LIBBPF_1.7.0

- **增量重点**：exclusive map ownership 与 struct_ops 关联。
- **新符号**：`bpf_map__set_exclusive_program`、`bpf_map__exclusive_program`。
- **新符号**：`bpf_prog_assoc_struct_ops`、`bpf_program__assoc_struct_ops`。
- **新符号**：`btf__permute`。
- **影响**：map-program 关系不再只是“共享 FD”，开始有更强的 ownership 约束。

### 2.26 LIBBPF_1.8.0

- **增量重点**：对象克隆与可配置 empty BTF。
- **新符号**：`bpf_program__clone`、`btf__new_empty_opts`。
- **关联主题**：虽然 `libbpf.map` 1.8.0 只新增少量导出符号，但 libbpf 头文件已覆盖 token、arena、insn_array 等更现代场景。
- **影响**：1.x 后半程的 API 更偏向能力精修，而不是早期那种大批量新增入口。

### 2.27 从版本演进看出的三条主线

- **主线一：object/program/map 基础面越来越高层化**。早期以 open/load + raw FD 为主，后续逐步增加 metadata accessor、高层 CRUD、skeleton、autoattach。
- **主线二：BTF/CO-RE 从附加能力变成核心能力**。从 `btf__new`、`btf__parse` 到 `btf__add_*`、`btf__relocate`，libbpf 逐渐承担类型系统中枢角色。
- **主线三：attach 生命周期统一到 `bpf_link` 与 opts-based API**。这让 API 可以在不破坏 ABI 的前提下逐步扩展参数。

---

## 3. API 设计模式演进

### 3.1 opts struct 模式

- libbpf 现代 API 大量采用 `struct xxx_opts`。
- 典型例子包括：
  - `struct bpf_object_open_opts`
  - `struct bpf_map_create_opts`
  - `struct bpf_prog_load_opts`
  - `struct bpf_btf_load_opts`
  - `struct bpf_link_create_opts`
  - `struct bpf_uprobe_opts` / `bpf_uprobe_multi_opts`
- 每个 opts struct 的第一个成员几乎都是 `size_t sz;`。

### 3.2 `sz` 字段如何实现前向/后向兼容

- 老程序使用较小版本的 opts struct 编译时，只会填到它已知字段，`sz` 也随之较小。
- 新版 libbpf 看到较小的 `sz`，就只读取结构体前半部分字段。
- 新程序使用较大 opts struct 编译时，若运行到旧版 libbpf，旧库也可以只识别它已知的前缀字段。
- 这是一种典型的“struct size handshake”模式。
- 相关 header 中还会定义 `xxx_opts__last_field` 宏，帮助库端检查尾部字段是否可用。

### 3.3 `DECLARE_LIBBPF_OPTS` / `LIBBPF_OPTS`

- 在 `src/libbpf_common.h` 中，真正的核心宏是 `LIBBPF_OPTS(TYPE, NAME, ...)`。
- 它会：
  - 对整个 struct 做 `memset(0)`；
  - 自动填 `NAME.sz = sizeof(struct TYPE)`；
  - 再应用调用者提供的初始化字段。
- 在 `src/libbpf_legacy.h` 中，`DECLARE_LIBBPF_OPTS` 只是 `LIBBPF_OPTS` 的兼容别名。
- 这样写的价值在于：
  - padding byte 尽量清零；
  - 新增字段默认是 0；
  - 调用点写法统一。

### 3.4 从函数式 API 到 opts-based API 的迁移

- 早期 libbpf 更偏好“一个函数 + 若干固定参数”的 C 接口。
- 这种形式在参数少时简单，但一旦 attach 点、日志、token、cookie、fd array 等需求出现，就会失控。
- 因而后续大量 API 都出现以下迁移路径：
  - 先有简单 API；
  - 然后增加 `*_opts` 版本；
  - 最终推荐使用 opts 版本，旧 API 仅保留兼容。
- 例子：
  - `bpf_object__open` -> `bpf_object__open_file/open_mem + bpf_object_open_opts`
  - `bpf_prog_attach` -> `bpf_prog_attach_opts`
  - `bpf_raw_tracepoint_open` -> `bpf_raw_tracepoint_open_opts`
  - `bpf_program__attach_uprobe` -> `bpf_program__attach_uprobe_opts` / `attach_uprobe_multi`

### 3.5 高层 API 与底层 syscall wrapper 并存

- libbpf 一直同时维护两层接口：
  - **高层接口**：面向 `bpf_object` / `bpf_program` / `bpf_map` 对象模型；
  - **低层接口**：直接包装 `bpf()` syscall，例如 `bpf_map_create`、`bpf_btf_load`。
- 高层接口更强调 size checking、BTF-defined metadata、自动资源管理。
- 低层接口更强调精确映射内核命令，方便高级用户控制 `bpf_attr` 语义。
- 这两层接口共同构成 libbpf 的 API 哲学：既做“框架”，也做“薄包装器”。

### 3.6 deprecated API 的处理

- `src/libbpf_common.h` 提供 `LIBBPF_DEPRECATED(msg)` 与 `LIBBPF_DEPRECATED_SINCE(major, minor, msg)`。
- 其目标不是立刻删符号，而是：
  - 在编译期发出 deprecation warning；
  - 给用户迁移窗口；
  - 避免直接破坏 ABI。
- `src/libbpf_legacy.h` 进一步集中放置“discouraged 或 deprecated”的入口。
- 典型例子：
  - `libbpf_get_error()` 在 1.0 以后仍保留，但官方不再推荐。
  - `libbpf_set_strict_mode()` 在 1.0 后已是 no-op，只为兼容预先适配过 1.0 的应用。
  - `bpf_program__get_type()` / `get_expected_attach_type()` 这类命名不一致入口被移入 legacy header。

### 3.7 命名风格演进

- 早期 API 带有一些历史命名痕迹，如 `get_*` 风格和不完全对称的 attach 名。
- 进入 0.6+ 之后，libbpf 更偏向：
  - `bpf_map__xxx`：面向高层对象；
  - `bpf_map_xxx`：面向低层 syscall wrapper；
  - `bpf_program__attach_xxx[_opts]`：面向 attach 场景；
  - `btf__xxx`：面向 BTF 操作。
- 这种命名把“抽象层次”编码进了函数名前缀。

---

## 4. 1.0.0 breaking changes

### 4.1 先说结论

- `1.0.0` 是 **API/语义 breaking release**，但不是“大规模 ABI 删符号 release”。
- 由于 libbpf 使用 GNU symbol versioning，很多旧 symbol 仍然存在。
- 真正变化最大的是：错误模型、strict mode 结果、legacy 写法接受度、推荐接口集合。

### 4.2 严格意义上的“移除 API”要怎么理解

- 从 `libbpf.map` 看，1.0.0 并没有像某些库那样直接删除大量旧 symbol。
- 因此“移除的 API 列表”更准确地说，是 **从主线工作流里退出** 或 **不再被推荐/不再被接受的旧接口和旧行为**。
- 这也是 libbpf 兼顾 ABI 稳定与 API 整理的典型方式。

### 4.3 1.0 时代被淘汰或退居兼容层的内容

- **ERR_PTR 风格指针错误返回**：1.0 模式下改为返回 `NULL` 并设置 `errno`。
- **低层 API 统一 direct negative error codes**：不再只返回 `-1` 然后依赖 `errno`。
- **legacy `SEC("maps")` map definitions**：在 1.0+ 不再支持，转向 BTF-defined `SEC(".maps")`。
- **宽松 section 名匹配**：`LIBBPF_STRICT_SEC_NAME` 思路在 1.0 之后成为默认语义。
- **全局 object list 语义**：`LIBBPF_STRICT_NO_OBJECT_LIST` 所指向的旧行为不再是主流。
- **`libbpf_set_strict_mode()` 作为运行期开关**：1.0 后本质上变成 no-op。
- **`libbpf_get_error()` 作为标准错误提取方式**：仍可用，但官方文档明确不再推荐。

### 4.4 行为变更清单

- **指针返回函数**：出错时返回 `NULL`，查看 `errno`。
- **整数返回函数**：出错时优先直接返回负错误码。
- **program section 解析**：更严格，历史别名或模糊前缀不再都被接受。
- **legacy map syntax**：`SEC("maps")` 老式定义变成错误，BTF-defined `.maps` 成为唯一主线。
- **strict mode 预演功能**：从“可选”变成“默认世界观”。

### 4.5 迁移指南概述

- **第一步**：把 object open/load/attach 路径切到 opts-based API。
- **第二步**：把所有 `SEC("maps")` 改成 BTF-defined `SEC(".maps")`。
- **第三步**：检查错误处理。
  - 指针：判空 + 读 `errno`；
  - 整数：直接判 `< 0`。
- **第四步**：把 legacy attach API 换成 `*_opts`、`bpf_link` 或 skeleton 工作流。
- **第五步**：对 feature-sensitive 功能使用 probing，而不是硬编码 kernel version。
- **第六步**：若历史代码依赖 `libbpf_set_strict_mode()`，可以保留调用，但不要再把它当成未来兼容策略。

### 4.6 迁移时最容易踩坑的点

- 把 `libbpf_get_error(ptr)` 留在新代码里，结果错误被别的库调用覆盖。
- 继续使用 `SEC("maps")` 老式 map 定义。
- 假设新内核 feature 一定存在，而不做 `libbpf_probe_bpf_map_type()` / `libbpf_probe_bpf_helper()` 检测。
- 仍把 attach 生命周期当作“拿一个 raw FD 就结束”，忽视 `bpf_link` 的 pin/update/detach 管理。

---

## 5. 与 kernel 版本对应关系

### 5.1 先说原则：libbpf 版本不直接绑定 kernel 版本

- 仓库 `README.md` 明确强调：libbpf 是 **kernel-agnostic** 的，应该独立打包和版本化。
- 也就是说，`libbpf 1.8.0` 不等于“必须搭配某个固定 kernel”。
- 真正决定功能是否能用的是：
  - kernel 是否支持对应 syscall command；
  - 是否支持对应 map type / prog type / helper；
  - 是否有 BTF、module BTF、global data、token、uprobe syscall 等特性。

### 5.2 源码里能直接看到的几个锚点

- `src/libbpf_internal.h` 写明：
  - `FEAT_PROG_NAME` 对应 **v4.14** 起的 program/map name 支持；
  - `FEAT_GLOBAL_DATA` 对应 **v5.2** 起的 global data section 支持。
- 同一枚举还列出了 `FEAT_BTF`、`FEAT_BTF_FUNC`、`FEAT_MODULE_BTF`、`FEAT_BPF_COOKIE`、`FEAT_UPROBE_MULTI_LINK`、`FEAT_UPROBE_SYSCALL`、`FEAT_BTF_LAYOUT` 等能力。
- 这些 feature ID 才是 libbpf 适配 kernel 差异的真正开关。

### 5.3 可以采用的“粗粒度阶段对应”

- **0.0.x 早期阶段**：重心在基础 load/attach/map/BTF，适配面以 4.x/5.x 内核基础 eBPF 能力为主。
- **0.1.0 ~ 0.4.0**：map metadata、BTF builder、tc hook、linker 逐渐成熟，适合把 libbpf 当完整用户态 SDK。
- **0.5.0 ~ 0.8.0**：strict mode、gen_loader、feature probing、high-level map CRUD、USDT、kprobe_multi，把“可移植 BPF 应用框架”形态做完整。
- **1.0.0**：API 稳定面完成收口，重点不是绑定新 kernel，而是统一用户态语义。
- **1.1.0 ~ 1.8.0**：更多依赖较新 kernel feature，如 token、user_ring_buffer、uprobe_multi、tcx、netkit、arena、insn_array。

### 5.4 BPF CO-RE 与 kernel 的关系

- CO-RE 依赖 kernel BTF，而不是单纯依赖 `uname -r`。
- `docs/libbpf_overview.rst` 解释了 CO-RE 的核心：
  - 目标程序携带 BTF relocation；
  - 运行时读取 `/sys/kernel/btf/vmlinux`；
  - libbpf 把程序里的类型/字段引用重定位到当前内核真实布局。
- 因此 CO-RE 的判断应是“目标内核是否有可用 BTF/BTF.ext 及相关 feature”，而不是“它是不是某个版本以上”。

### 5.5 feature probing 如何处理差异

- libbpf 把 feature probing 做成了公开 API：
  - `libbpf_probe_bpf_prog_type()`
  - `libbpf_probe_bpf_map_type()`
  - `libbpf_probe_bpf_helper()`
- 其内部实现位于 `src/libbpf_probes.c`，而 object load 过程还会配合 `kernel_supports()` 缓存更多 feature。
- 实践上建议：
  - map type 是否能建：先 probe map type；
  - helper 是否能在某 prog type 内使用：probe helper；
  - 某 attach 模式是否可用：走相应高层 API，必要时检查返回错误并降级。

### 5.6 libbpf 的兼容性策略不是“拒绝运行”，而是“降级运行”

- 如果 kernel 太老，libbpf 可能：
  - 跳过 BTF upload；
  - 关闭 global data 相关路径；
  - 回退到 legacy attach 方式；
  - 禁用某些 map autocreate/autoattach 能力；
  - 返回明确错误码，让应用自行决定是否继续。
- 这也是 README 所说“gracefully handle older kernels”的具体含义。

### 5.7 实践建议

- 发布应用时，记录 **最低验证 kernel feature 集合**，不要只记录“最低 kernel 版本”。
- 文档中同时写清：
  - 是否要求 BTF；
  - 是否要求 global data；
  - 是否要求 ringbuf/user_ringbuf；
  - 是否要求 token/arena/insn_array 等 very new feature。
- 当 feature 不满足时，优先设计 fallback path，而不是直接让整个程序不可用。

---

## 6. 总结

- `libbpf.map` 记录的 26 个版本，实际就是 libbpf 公开 ABI 的演进年表。
- 0.0.x 解决“能打开、能加载、能 attach、能读 BTF”的基础问题。
- 0.5.0 ~ 0.8.0 把 strict mode、feature probing、skeleton、高层 map CRUD 补齐。
- 1.0.0 把接口语义统一成稳定 API 世界观。
- 1.1.0 ~ 1.8.0 则继续向 token、user ring buffer、uprobe_multi、tcx、arena 等新内核能力扩张。
- 从设计方法论看，libbpf 最成功的地方不只是 API 多，而是把 symbol versioning、opts struct、feature probing、legacy compatibility 四件事组合成了一个可长期维护的 ABI 策略。
