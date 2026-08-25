# Transparent MySQL query cache.
#
# Intended to run inside the bpf container:
#
#   docker compose exec bpf make
#   docker compose exec bpf make check
#   docker compose exec bpf demo/cache_demo.sh
#
# The cache itself is plain userspace C++ and needs no kernel support, no
# root and no BPF toolchain -- it hooks the client's TLS library from inside
# the client process. That is a deliberate consequence of intercepting above
# TLS rather than on the wire.

CXX      ?= g++
CXXFLAGS ?= -g -O2 -Wall -Wextra -std=c++17 -fPIC

OUT := build

PROTO_SRC := src/mysql/protocol.cpp
CACHE_SRC := src/cache/preload.cpp src/cache/session.cpp src/cache/valkey.cpp
TEST_SRC  := src/mysql/test_protocol.cpp

.PHONY: all clean check test-protocol

all: $(OUT)/libqcache.so

$(OUT):
	mkdir -p $(OUT)

# The preload library is what gets injected into a client process. It is
# self-contained on purpose: anything linked here lands in the address space
# of every traced application.
$(OUT)/libqcache.so: $(CACHE_SRC) $(PROTO_SRC) | $(OUT)
	$(CXX) $(CXXFLAGS) -shared $(CACHE_SRC) $(PROTO_SRC) -o $@ -ldl -lpthread

$(OUT)/test_protocol: $(TEST_SRC) $(PROTO_SRC) | $(OUT)
	$(CXX) $(CXXFLAGS) $(TEST_SRC) $(PROTO_SRC) -o $@

test-protocol: $(OUT)/test_protocol
	./$(OUT)/test_protocol

# Protocol framing tests need no kernel, no root and no database -- which is
# the main practical benefit of having moved this logic out of BPF C.
check: test-protocol
	python3 -m unittest discover -s translator -p 'test_*.py' -v

clean:
	rm -rf $(OUT)
