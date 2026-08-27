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
#   barnacle  entry point (qc-barnacle). Runs on the host, finds target
#             programs inside containers via /proc, decides whether each is
#             attachable, and injects the agent. Python: it reads /proc and
#             runs a subprocess, and must work on a host with no toolchain.
#   daemon    the userspace daemon (qc-daemon): dpipe pool, cache,
#             mini-protocol. Owns the shared state, which lives in kernel BPF
#             maps and arenas.
#   kclient   kernel eBPF: the two sk_msg redirect programs.
#   uclient   the agent Frida injects into target processes (libqcagent.so),
#             plus the injector (qc-inject). Ordinary C++: it maps the arena,
#             parses MySQL with src/common, and holds per-connection state.
#             eBPF is used only where code must run in the kernel, which here
#             means kclient alone.
#   common    MySQL protocol, Valkey client, session tracking.

CLANG    ?= clang
BPFTOOL  ?= bpftool
CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -g -O2 -Wall -Wextra -std=c++20
CFLAGS   ?= -g -O2 -Wall

OUT     := build
UNAME_M := $(shell uname -m)
ARCH    := $(shell echo $(UNAME_M) | sed 's/x86_64/x86/; s/aarch64/arm64/')
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -I$(OUT) -Isrc



COMMON_SRC := src/common/mysql/protocol.cpp src/common/valkey.cpp src/common/session.cpp

.PHONY: all clean check test frida-paths

all: $(OUT)/qc-barnacle $(OUT)/qc-daemon $(OUT)/kclient.bpf.o \
     $(OUT)/libqcagent.so $(OUT)/qc-inject

$(OUT):
	mkdir -p $(OUT)

# CO-RE: types come from the running kernel's own BTF.
$(OUT)/vmlinux.h: | $(OUT)
	@test -r $(VMLINUX_BTF) || { echo "error: $(VMLINUX_BTF) unreadable"; exit 1; }
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

# --- kclient: kernel eBPF -------------------------------------------------

$(OUT)/kclient.bpf.o: src/kclient/kclient.bpf.c src/common/defs.h $(OUT)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUT)/kclient.skel.h: $(OUT)/kclient.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# --- uclient: a native agent, injected by Frida ---------------------------
#
# NOT eBPF. eBPF is used only where code must run in the kernel, which in this
# project means kclient alone. In a client process the BPF model bought
# nothing and cost a lot: no per-process state (a BPF "global" is a .bss map
# in one shared segment, so two clients share it), no mmap (a program cannot
# make syscalls, so the arena was unreachable), verifier bounds that forced a
# 512-byte statement cap and a hand-rolled subset of MySQL framing, and no way
# to call bpf() to splice a socket. As ordinary C++ all four simply go away.
#
# Frida is what bpftime used underneath for injection and hooking; this uses
# it directly. `make frida-paths` prints what was detected.
FRIDA_DIR ?= /opt/frida
FRIDA_SYS := -lpthread -ldl -lm -lresolv

# shared.cpp is compiled separately on purpose: frida-gum.h and libbpf's
# bpf.h both declare bpf_insn, as an enum and a struct respectively, so they
# cannot appear in one translation unit.
$(OUT)/qcagent_shared.o: src/uclient/shared.cpp | $(OUT)
	$(CXX) $(CXXFLAGS) -fPIC -Isrc -c $< -o $@

$(OUT)/qcagent_bpfsys.o: src/uclient/bpfsys.c | $(OUT)
	$(CC) $(CFLAGS) -fPIC -Isrc -c $< -o $@

# Everything static except libc.
#
# The agent is dlopen'd inside a process we do not control, which may be in
# another container with a completely different filesystem. Any shared
# dependency has to exist in THAT mount namespace, and libbpf almost never
# does -- injection fails with "libbpf.so.1: cannot open shared object file"
# before a single hook is installed. Linking it in makes the agent portable to
# any target the injector can reach.
LIBDIR := /usr/lib/$(UNAME_M)-linux-gnu

# -Wl,--no-undefined because a shared object happily links with symbols it
# never resolves, and the failure then lands at dlopen time inside somebody
# else's process -- as "undefined symbol" from a library that has already
# replaced their SSL_read. Refuse it here instead.
$(OUT)/libqcagent.so: src/uclient/agent.cpp $(OUT)/qcagent_shared.o \
                      $(OUT)/qcagent_bpfsys.o \
                      src/common/session.cpp src/common/stmtlist.cpp \
                      src/common/mysql/resultset.cpp \
                      src/common/mysql/protocol.cpp | $(OUT)
	$(CXX) $(CXXFLAGS) -fPIC -shared -Isrc -I$(FRIDA_DIR) $^ -o $@ \
	  -Wl,--no-undefined \
	  $(FRIDA_DIR)/libfrida-gum.a \
	  -static-libstdc++ -static-libgcc $(FRIDA_SYS)

$(OUT)/qc-inject: src/uclient/inject.cpp | $(OUT)
	$(CXX) $(CXXFLAGS) -Isrc -I$(FRIDA_DIR) $< -o $@ \
	  $(FRIDA_DIR)/libfrida-core.a $(FRIDA_SYS)

frida-paths:
	@echo "FRIDA_DIR = $(FRIDA_DIR)"
	@test -f $(FRIDA_DIR)/libfrida-gum.a && echo "  gum:  found" || echo "  gum:  MISSING"
	@test -f $(FRIDA_DIR)/libfrida-core.a && echo "  core: found" || echo "  core: MISSING"

# --- qc-daemon: the userspace daemon --------------------------------------
#
# Owns everything shared: loads kclient, creates the maps and the arena,
# builds the dpipe pool, answers requests.
$(OUT)/qc-daemon: src/daemon/main.cpp src/daemon/arena.cpp src/daemon/dpipes.cpp \
                  src/common/stmtlist.cpp src/common/valkey.cpp \
                  src/common/mysql/resultset.cpp src/common/mysql/protocol.cpp \
                  $(OUT)/kclient.skel.h
	$(CXX) $(CXXFLAGS) -I$(OUT) -Isrc \
	  src/daemon/main.cpp src/daemon/arena.cpp src/daemon/dpipes.cpp \
	  src/common/stmtlist.cpp src/common/valkey.cpp \
	  src/common/mysql/resultset.cpp src/common/mysql/protocol.cpp \
	  -o $@ -lbpf -lelf -lz

# --- qc-barnacle: the entry point -----------------------------------------
#
# Python, and copied rather than compiled. It reads /proc, matches strings and
# runs a subprocess -- no protocol work, no BPF map, not on any hot path. It
# also runs on the HOST, where libbpf and a C++ toolchain may not exist at
# all, which is the second reason not to build it.
$(OUT)/qc-barnacle: src/barnacle/qc-barnacle | $(OUT)
	cp $< $@
	chmod +x $@

# --- tests ----------------------------------------------------------------

# GoogleTest for the userspace units. gtest_main supplies main(), so the
# tests are just TEST() blocks.
GTEST_LIBS := -lgtest -lgtest_main -lpthread

$(OUT)/test_protocol: tests/test_protocol.cpp src/common/mysql/protocol.cpp | $(OUT)
	$(CXX) $(CXXFLAGS) -Isrc $^ -o $@ $(GTEST_LIBS)

$(OUT)/test_session: tests/test_session.cpp src/common/session.cpp \
                     src/common/mysql/protocol.cpp | $(OUT)
	$(CXX) $(CXXFLAGS) -Isrc $^ -o $@ $(GTEST_LIBS)

$(OUT)/test_resultset: tests/test_resultset.cpp src/common/mysql/resultset.cpp \
                       src/common/mysql/protocol.cpp | $(OUT)
	$(CXX) $(CXXFLAGS) -Isrc $^ -o $@ $(GTEST_LIBS)

$(OUT)/test_request: tests/test_request.cpp src/common/session.cpp \
                     src/common/stmtlist.cpp src/common/mysql/protocol.cpp | $(OUT)
	$(CXX) $(CXXFLAGS) -Isrc $^ -o $@ $(GTEST_LIBS)

# The gate for the whole redirect design: can we reach a socket owned by
# another process? Re-execs itself as the child, so it must be one binary.
$(OUT)/test_xproc: tests/test_xproc.c $(OUT)/kclient.skel.h
	$(CC) $(CFLAGS) -I$(OUT) -Isrc $< -o $@ -lbpf -lelf -lz

# Which kernel features are actually available here. Loads programs and
# creates maps without attaching anything, so it is safe to run anywhere and
# tells us up front whether the arena memory model and the LRU timer sweeper
# are reachable on this kernel.
$(OUT)/test_caps: tests/test_caps.c | $(OUT)
	$(CC) $(CFLAGS) $< -o $@ -lbpf -lelf -lz

# Needs neither kernel nor root -- the practical benefit of keeping protocol
# parsing in userspace.
check: $(OUT)/test_protocol $(OUT)/test_session $(OUT)/test_request \
       $(OUT)/test_resultset
	./$(OUT)/test_protocol
	./$(OUT)/test_session
	./$(OUT)/test_request
	./$(OUT)/test_resultset

# Privileged: sockmap attach and kernel feature probes.
#
# test_xproc runs three ways deliberately. --no-sockops is the control: if it
# passes while the default fails, the fault is in classify() or the cgroup
# attach rather than in the redirect. --socketpair answers whether
# architecture.txt's socketpair(2) can back a dpipe at all, and is expected to
# fail -- so it is reported, not asserted.
test: check $(OUT)/test_caps $(OUT)/test_xproc
	./$(OUT)/test_caps
	./$(OUT)/test_xproc --in-proc
	./$(OUT)/test_xproc
	-./$(OUT)/test_xproc --socketpair

# Everything the tree still knows how to build.
clean-stale:
	rm -f $(OUT)/uclient.bpf.o $(OUT)/uclient.skel.h $(OUT)/uclient_loader \
	      $(OUT)/test_pipes $(OUT)/test_redirect $(OUT)/test_shm_bridge \
	      $(OUT)/qcdemo $(OUT)/test_daemon $(OUT)/agent $(OUT)/qcache \
	      $(OUT)/qcinject $(OUT)/test_stmtlist

clean:
	rm -rf $(OUT)
