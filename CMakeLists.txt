# CMakeLists.txt exists for IDE support (CLion, VS Code + clangd), not as a
# replacement for the Makefile.
#
# Unlike earlier incarnations of this project, nothing here needs a kernel,
# root, BPF toolchain, or a vmlinux.h generated from the target kernel's BTF.
# The cache intercepts inside the client process, above TLS, so it is ordinary
# userspace C++ and builds anywhere -- including macOS, for editing and for
# running the protocol tests.
cmake_minimum_required(VERSION 3.16)
project(valkey_qcache CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(PROTO_SRC src/mysql/protocol.cpp)
set(CACHE_SRC src/cache/preload.cpp src/cache/session.cpp src/cache/valkey.cpp)

# The library injected into client processes via LD_PRELOAD.
add_library(qcache SHARED ${CACHE_SRC} ${PROTO_SRC})
target_include_directories(qcache PRIVATE src)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(qcache PRIVATE dl pthread)
endif()

# Protocol tests: no kernel, no root, no database.
add_executable(test_protocol src/mysql/test_protocol.cpp ${PROTO_SRC})
target_include_directories(test_protocol PRIVATE src)

enable_testing()
add_test(NAME protocol COMMAND test_protocol)
