# CMakeLists.txt exists for IDE support (CLion, VS Code + clangd), not as a
# replacement for the Makefile, which is the supported way to build.
#
# Only the parts that build anywhere are configured here. The eBPF objects
# (kclient, uclient) need clang's BPF target plus a vmlinux.h generated from
# the running kernel's own BTF, and the agent needs libbpf -- none of which
# exist on a macOS workstation. Those stay in the Makefile; this file's job is
# to hand the editor a correct compile_commands.json for the code that is
# ordinary userspace C++.
cmake_minimum_required(VERSION 3.16)
project(valkey_qcache CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# qcache: the entry point. Deliberately dependency-free -- it runs on the
# host, reads /proc, and reports; it loads nothing itself.
add_executable(qcache
    src/qcache/main.cpp
    src/qcache/config.cpp
    src/qcache/discover.cpp)
target_include_directories(qcache PRIVATE src/qcache)

# Protocol parsing: pure computation over byte buffers, so it builds and
# tests without a kernel, root, or a database.
add_library(qcache_mysql STATIC src/common/mysql/protocol.cpp)
target_include_directories(qcache_mysql PUBLIC src/common)

add_executable(test_protocol tests/test_protocol.cpp)
target_link_libraries(test_protocol PRIVATE qcache_mysql)

enable_testing()
add_test(NAME protocol COMMAND test_protocol)
