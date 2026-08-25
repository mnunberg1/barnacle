# Build the BPF object and the userspace loader.
#
# Intended to run *inside* the bpf container (docker compose exec bpf make),
# because vmlinux.h is generated from the BTF of the kernel we will attach to.

CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc
CXX     ?= g++

OUT      := build
UNAME_M  := $(shell uname -m)
ARCH     := $(shell echo $(UNAME_M) | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/; s/mips.*/mips/')
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror \
              -I$(OUT) -Ibpf
CFLAGS     ?= -g -O2 -Wall
CXXFLAGS   ?= -g -O2 -Wall -std=c++17
LDLIBS     := -lbpf -lelf -lz

.PHONY: all clean check
all: $(OUT)/agent

$(OUT):
	mkdir -p $(OUT)

# CO-RE: the type definitions come from the running kernel's own BTF, so the
# same source builds against whatever kernel the container lands on.
$(OUT)/vmlinux.h: | $(OUT)
	@test -r $(VMLINUX_BTF) || { \
		echo "error: $(VMLINUX_BTF) not readable."; \
		echo "The kernel needs CONFIG_DEBUG_INFO_BTF and /sys must be mounted."; \
		exit 1; }
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

# mysql_reroute.bpf.c uses uprobes on a client library, not kernel
# tracepoints -- it does not touch vmlinux.h's contents, but still includes
# it for the plain __u8/__u32/... typedefs, so the dependency stays.
$(OUT)/mysql_reroute.bpf.o: bpf/mysql_reroute.bpf.c bpf/mysql_reroute.h bpf/proto.h $(OUT)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@command -v llvm-strip >/dev/null && llvm-strip -g $@ || true

$(OUT)/mysql_reroute.skel.h: $(OUT)/mysql_reroute.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OUT)/agent: src/agent.cpp $(OUT)/mysql_reroute.skel.h
	$(CXX) $(CXXFLAGS) -I$(OUT) -Ibpf $< $(LDLIBS) -o $@

# Translator unit tests need neither root nor a kernel.
check:
	python3 -m unittest discover -s translator -p 'test_*.py' -v

clean:
	rm -rf $(OUT)
