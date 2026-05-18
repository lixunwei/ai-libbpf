EXAMPLE := core_task_info
LIBBPF_SRC := $(abspath ../../../src)
LIBBPF_OBJ := $(LIBBPF_SRC)/libbpf.a
INCLUDES := -I$(LIBBPF_SRC) -I../../../include -I../../../include/uapi -I.. -I.
CLANG ?= clang-14
BPFTOOL ?= $(abspath ../tooling/bpftool)
CC ?= gcc
BPF_CFLAGS := -g -O2 -Wall -target bpf -D__TARGET_ARCH_x86 $(INCLUDES)
USER_CFLAGS := -g -O2 -Wall $(INCLUDES)
USER_LDFLAGS := $(LIBBPF_OBJ) -lelf -lz

.PHONY: all clean prepare

all: $(EXAMPLE)

prepare:
	$(MAKE) -C .. vmlinux.h bpf/libbpf.h bpf/skel_internal.h
	$(MAKE) -C $(LIBBPF_SRC)

$(EXAMPLE): $(EXAMPLE).c $(EXAMPLE).skel.h | prepare
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

%.bpf.o: %.bpf.c ../vmlinux.h | prepare
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -f $(EXAMPLE) $(EXAMPLE).bpf.o $(EXAMPLE).skel.h
