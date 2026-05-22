LIBBPF_SRC := $(abspath ../../src)
LIBBPF_OBJ := $(LIBBPF_SRC)/libbpf.a
CLANG ?= clang-14
BPFTOOL ?= $(abspath tooling/bpftool)
CC ?= gcc
SUBDIRS := tracepoint_example kprobe_example xdp_example ringbuf_example core_portable fentry_example lsm_example cgroup_example tc_example struct_ops_example iter_example

.PHONY: all clean $(SUBDIRS)

all: prereqs $(SUBDIRS)

prereqs: $(LIBBPF_OBJ) bpf/libbpf.h bpf/skel_internal.h vmlinux.h

$(LIBBPF_OBJ):
	$(MAKE) -C $(LIBBPF_SRC)

bpf:
	mkdir -p $@

bpf/libbpf.h: | bpf
	printf '#include "../../../src/libbpf.h"\n' > $@

bpf/skel_internal.h: | bpf
	printf '#include "../../../src/skel_internal.h"\n' > $@

VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
VMLINUX_FALLBACK := ../../.github/actions/build-selftests/vmlinux.h
USE_KERNEL_BTF ?= 0

vmlinux.h:
	@if [ "$(USE_KERNEL_BTF)" = "1" ]; then \
		$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@; \
		echo "Generated $@ from $(VMLINUX_BTF)"; \
	else \
		cp $(VMLINUX_FALLBACK) $@; \
		echo "Copied bundled vmlinux.h from $(VMLINUX_FALLBACK)"; \
	fi

$(SUBDIRS): prereqs
	$(MAKE) -C $@

clean:
	for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean; done
	rm -f vmlinux.h
	rm -rf bpf
