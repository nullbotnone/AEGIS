# AEGIS eBPF Build System

# Paths
BPF_SRC := $(wildcard src/bpf/*.c)
BPF_OBJ := $(BPF_SRC:.c=.bpf.o)
USER_SRC := $(wildcard src/attestation/*.py)

# Compiler
CLANG ?= $(firstword $(wildcard /usr/bin/clang /usr/bin/clang-18 /usr/bin/clang-17 /usr/bin/clang-16 /usr/bin/clang-15 /usr/local/bin/clang /usr/local/bin/clang-18 /usr/local/bin/clang-17 /usr/local/bin/clang-16 /usr/local/bin/clang-15))
LLVMLD ?= llvm-ld
STRIP ?= strip

# Architecture
ARCH ?= x86_64
TARGET := bpf

# Kernel headers
KERNEL_VERSION := $(shell uname -r)
LINUX_INCLUDE := /usr/include/$(shell uname -m)-linux-gnu
BPF_INCLUDE := /usr/include/bpf

# Flags
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -Wall
BPF_CFLAGS += -I/usr/include -I$(BPF_INCLUDE) -I$(LINUX_INCLUDE)
BPF_CFLAGS += -g -D__BPF_TRACING__

# Installation
PREFIX ?= /usr/local
SBINDIR := $(PREFIX)/sbin
SHAREDIR := $(PREFIX)/share/aegis

# Default target
all: check bpfall

check: checksetup
	@echo "=== AEGIS eBPF Setup Check ==="
	@uname -r | grep -q "5.14" && echo "✓ Kernel 5.14 detected" || echo "⚠ Kernel may not support all eBPF features"
	@id -u | grep -q "^0$$" && echo "✓ Running as root" || echo "⚠ Must run as root for eBPF"
	@test -n "$(CLANG)" && echo "✓ clang available: $(CLANG)" || echo "✗ clang not found"
	@ls $(BPF_INCLUDE)/bpf_helpers.h >/dev/null 2>&1 && echo "✓ bpf headers found" || echo "⚠ bpf headers missing"
	@echo ""

checksetup:
	@echo "Checking eBPF build prerequisites..."
	@test -n "$(CLANG)" || (echo "✗ clang not found" && exit 1)

bpfall: $(BPF_OBJ)
	@echo "=== eBPF objects built ==="
	@ls -la $(BPF_OBJ)

%.bpf.o: %.c
	@echo "Compiling $< -> $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

install: bpfall
	@echo "Installing AEGIS eBPF components..."
	install -d $(SHAREDIR)
	install -m 755 src/attestation/bpf_collector.py $(SHAREDIR)/
	install -m 644 $(BPF_OBJ) $(SHAREDIR)/
	install -m 644 src/bpf/aegis_probe.c $(SHAREDIR)/
	@echo "Installed to $(SHAREDIR)"

clean:
	rm -f src/bpf/*.bpf.o
	rm -f src/bpf/*.stripped

test: bpfall
	@echo "=== Running eBPF sanity test ==="
	@echo "(Requires root)"
	@# Quick syntax check - don't actually load
	@file src/bpf/aegis_probe.bpf.o | grep -q "ELF" && echo "✓ Valid ELF binary" || echo "✗ Invalid ELF"

.PHONY: all check checksetup bpfall install clean test