# struct_ops BPF 示例 - Makefile

CLANG ?= clang-14
BPFTOOL ?= ../tooling/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
	-I.. -I../bpf -I../../../src -I../../../include -I../../../include/uapi

USER_CFLAGS := -g -O2 -Wall -I.. -I../bpf -I../../../src -I../../../include -I../../../include/uapi
USER_LDFLAGS := -L../../../src -lbpf -lelf -lz -lpthread

APP := struct_ops_example

.PHONY: all clean

all: $(APP)

%.bpf.o: %.bpf.c vmlinux.h bpf
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(APP): $(APP).c $(APP).skel.h
	gcc $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS)

vmlinux.h bpf:
	@test -f ../vmlinux.h || (echo "Run 'make prereqs' in parent dir first"; exit 1)
	@ln -sf ../vmlinux.h vmlinux.h
	@ln -sfn ../bpf bpf

clean:
	rm -f *.o *.skel.h $(APP) vmlinux.h bpf
