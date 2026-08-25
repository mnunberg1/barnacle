# Transparent MySQL query cache.
#
# Run inside the bpf container (see demo/README.md to bring it up):
#
#   docker compose -f demo/docker-compose.yml exec bpf make          everything
#   docker compose -f demo/docker-compose.yml exec bpf make check    tests that need no kernel or root
#   docker compose -f demo/docker-compose.yml exec bpf make test     everything, including privileged tests
#
# Components:
#
#   qcache    entry point. Runs on the host, finds target programs inside
#             containers via /proc, decides whether each is attachable.
#   agent     userspace daemon: agent_pipe pool, cache, mini-protocol.
#   kclient   kernel eBPF: sockops classifier + sk_msg redirect.
#   uclient   bpftime probes injected into target processes.
#   common    MySQL protocol, Valkey client, session tracking.

CLANG    ?= clang
BPFTOOL  ?= bpftool
CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -g -O2 -Wall -Wextra -std=c++17
CFLAGS   ?= -g -O2 -Wall

OUT     := build
UNAME_M := $(shell uname -m)
ARCH    := $(shell echo $(UNAME_M) | sed 's/x86_64/x86/; s/aarch64/arm64/')
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -I$(OUT) -Isrc

# bpftime is built from source; these come from its build tree. `make
# bpftime-paths` prints what was detected.
BPFTIME_DIR ?= /tmp/bpftime
BPFTIME_INC := -I$(BPFTIME_DIR)/vm/include -I$(BPFTIME_DIR)/runtime/include \
               -I$(BPFTIME_DIR)/runtime -I$(BPFTIME_DIR)/build/runtime \
               -I$(BPFTIME_DIR)/third_party -I$(BPFTIME_DIR)/third_party/spdlog/include \
               -I$(BPFTIME_DIR)/build/libbpf/uapi -I$(BPFTIME_DIR)/build/libbpf \
               -I$(BPFTIME_DIR)/build/FridaGum-prefix/src/FridaGum \
               -I$(BPFTIME_DIR)/runtime/src -I$(BPFTIME_DIR)/vm/vm-core/include \
               -I$(BPFTIME_DIR)/vm/compat/include -I$(BPFTIME_DIR)/attach/base_attach_impl
BPFTIME_LIBS := $(BPFTIME_DIR)/build/runtime/libruntime.a \
                $(BPFTIME_DIR)/build/vm/vm-core/libbpftime_vm.a \
                $(BPFTIME_DIR)/build/vm/compat/llvm-vm/libllvmbpf_vm.a \
                $(BPFTIME_DIR)/build/vm/compat/llvm-vm/libbpftime_llvm_vm.a \
                $(BPFTIME_DIR)/build/third_party/spdlog/libspdlog.a \
                $(BPFTIME_DIR)/build/libbpf/libbpf.a
LLVM_LIBS := $(shell llvm-config-18 --libs --system-libs 2>/dev/null || echo -lLLVM-18)

COMMON_SRC := src/common/mysql/protocol.cpp src/common/valkey.cpp src/common/session.cpp

.PHONY: all clean check test bpftime-paths

all: $(OUT)/qcache $(OUT)/agent $(OUT)/kclient.bpf.o $(OUT)/uclient.bpf.o \
     $(OUT)/uclient_loader $(OUT)/test_protocol

$(OUT):
	mkdir -p $(OUT)

# CO-RE: types come from the running kernel's own BTF.
$(OUT)/vmlinux.h: | $(OUT)
	@test -r $(VMLINUX_BTF) || { echo "error: $(VMLINUX_BTF) unreadable"; exit 1; }
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

# --- kclient: kernel eBPF -------------------------------------------------

$(OUT)/kclient.bpf.o: src/kclient/kclient.bpf.c src/kclient/kclient.h $(OUT)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -Isrc/kclient -c $< -o $@

$(OUT)/kclient.skel.h: $(OUT)/kclient.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# --- uclient: bpftime probes ---------------------------------------------

$(OUT)/uclient.bpf.o: src/uclient/uclient.bpf.c $(OUT)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUT)/uclient.skel.h: $(OUT)/uclient.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Static libbpf: elf_find_func_offset_from_file is internal and is not
# exported from the shared library, but the override attach path needs it.
$(OUT)/uclient_loader: src/uclient/loader.c $(OUT)/uclient.skel.h
	$(CC) $(CFLAGS) -I$(OUT) -Isrc/uclient $< -o $@ \
	  /usr/lib/$(UNAME_M)-linux-gnu/libbpf.a -lelf -lz -lpthread

# --- agent: the userspace daemon -----------------------------------------

$(OUT)/agent: src/agent/main.cpp src/agent/pipes.cpp src/common/valkey.cpp \
              $(OUT)/kclient.skel.h
	$(CXX) $(CXXFLAGS) -I$(OUT) -Isrc/kclient -Isrc/agent \
	  src/agent/main.cpp src/agent/pipes.cpp src/common/valkey.cpp \
	  -o $@ -lbpf -lelf -lz

# --- qcache: the entry point ---------------------------------------------
#
# Deliberately depends on nothing but libstdc++: it runs on the host, where
# libbpf and bpftime may not be installed at all, and its job is to report
# what it finds rather than to load anything itself.
$(OUT)/qcache: src/qcache/main.cpp src/qcache/config.cpp src/qcache/discover.cpp | $(OUT)
	$(CXX) $(CXXFLAGS) $^ -o $@

# --- tests ----------------------------------------------------------------

$(OUT)/test_protocol: tests/test_protocol.cpp src/common/mysql/protocol.cpp | $(OUT)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(OUT)/test_pipes: tests/test_pipes.cpp src/agent/pipes.cpp $(OUT)/kclient.skel.h
	$(CXX) $(CXXFLAGS) -I$(OUT) -Isrc/kclient -Isrc/agent \
	  tests/test_pipes.cpp src/agent/pipes.cpp -o $@ -lbpf -lelf -lz

$(OUT)/test_redirect: tests/test_redirect.c $(OUT)/kclient.skel.h
	$(CC) $(CFLAGS) -I$(OUT) -Isrc/kclient $< -o $@ -lbpf -lelf -lz

$(OUT)/test_shm_bridge: tests/test_shm_bridge.cpp src/agent/shm_bridge.cpp
	$(CXX) $(CXXFLAGS) -Isrc/agent $(BPFTIME_INC) $^ -o $@ \
	  -Wl,--start-group $(BPFTIME_LIBS) -Wl,--end-group \
	  $(LLVM_LIBS) -lpthread -ldl -lelf -lz

# Needs neither kernel nor root -- the practical benefit of keeping protocol
# parsing in userspace.
check: $(OUT)/test_protocol
	./$(OUT)/test_protocol

# Privileged: sockmap attach and bpftime shared memory.
test: check $(OUT)/test_redirect $(OUT)/test_pipes
	./$(OUT)/test_redirect
	./$(OUT)/test_pipes

bpftime-paths:
	@echo "BPFTIME_DIR = $(BPFTIME_DIR)"
	@test -d $(BPFTIME_DIR)/build && echo "  build tree: found" || \
	  echo "  build tree: MISSING (build bpftime first)"

clean:
	rm -rf $(OUT)
