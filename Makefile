# SPDX-License-Identifier: GPL-2.0
#
# Standalone Makefile for LPC 2026 Ftrace Consumer Classification &
# Livepatch Coexistence Suite (14 Ftrace Consumers A-N & 28 klp Scenarios)

CLANG      ?= clang
CFLAGS     ?= -g -O2 -Wall

DEFAULT_KDIR := $(abspath $(CURDIR)/../linux)
ifneq ($(wildcard $(DEFAULT_KDIR)/Makefile),)
KDIR       ?= $(DEFAULT_KDIR)
else
KDIR       ?= /lib/modules/$(shell uname -r)/build
endif
PWD        := $(shell pwd)

BPFTOOL    ?= $(shell command -v bpftool 2>/dev/null)
ifeq ($(BPFTOOL),)
BPFTOOL    := $(KDIR)/tools/bpf/bpftool/bpftool
endif

SYS_LIBBPF := $(wildcard /usr/include/bpf/bpf_helpers.h)
ifeq ($(SYS_LIBBPF),)
LIBBPF_SRC  := $(KDIR)/tools/lib/bpf
LIBBPF_A    := $(LIBBPF_SRC)/libbpf.a
BPF_INCLUDE := -I$(KDIR)/tools/lib -I$(KDIR)/tools/include/uapi
USER_LIBS   := $(LIBBPF_A) -lelf -lz
else
LIBBPF_A    :=
BPF_INCLUDE := -I/usr/include
USER_LIBS   := -lbpf -lelf -lz
endif

ifneq ($(wildcard $(KDIR)/vmlinux),)
BTF_SRC := $(KDIR)/vmlinux
else
BTF_SRC := /sys/kernel/btf/vmlinux
endif

BPF_TARGET  := bpf_coexist_users.bpf.o
USER_TARGET := bpf_coexist_users
VMLINUX_H   := vmlinux.h

all: modules $(BPF_TARGET) $(USER_TARGET)

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

$(VMLINUX_H): $(BTF_SRC)
	$(BPFTOOL) btf dump file $(BTF_SRC) format c > $@

$(LIBBPF_A):
	$(MAKE) -C $(LIBBPF_SRC)

$(BPF_TARGET): bpf_coexist_users.bpf.c $(VMLINUX_H)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 $(BPF_INCLUDE) -I. \
		-Wno-missing-declarations -c $< -o $@

$(USER_TARGET): bpf_coexist_users.c $(LIBBPF_A)
	$(CC) $(CFLAGS) $(BPF_INCLUDE) $< $(USER_LIBS) -o $@

test: all
	KDIR=$(KDIR) ./vm_start.sh -a ./run_coexistence_experiment.sh

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(BPF_TARGET) $(USER_TARGET) $(VMLINUX_H)

.PHONY: all clean modules test
