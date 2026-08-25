# CMakeLists.txt exists for IDE support (CLion, VS Code + CMake Tools /
# clangd), not as a replacement for the Makefile, which remains the only
# supported way to actually build and run this project -- always inside the
# `bpf` container:
#
#   docker compose exec bpf make
#
# eBPF does not exist outside Linux, and this project's BPF object needs
# vmlinux.h generated from the *target kernel's own* BTF at build time, so
# there is no such thing as building it on macOS/Windows at all. On a Linux
# host with the same toolchain the container has (clang, bpftool,
# libbpf-dev), the targets below mirror the Makefile closely enough to also
# work standalone. On any other host, they fall back to IDE-only stub
# targets built against include/bpf_stub -- see that directory's headers for
# what they do and don't provide. Either way, this file's real job is
# handing your editor a correct compile_commands.json.
cmake_minimum_required(VERSION 3.16)
project(valkey_ebpf C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_program(CLANG_EXECUTABLE clang)
    find_program(BPFTOOL_EXECUTABLE bpftool)
    if(NOT CLANG_EXECUTABLE OR NOT BPFTOOL_EXECUTABLE)
        message(FATAL_ERROR
            "valkey-ebpf: this is a Linux host but clang/bpftool were not "
            "found. Run `docker compose exec bpf make` instead, or install "
            "the same packages docker/Dockerfile does.")
    endif()

    set(VMLINUX_BTF "/sys/kernel/btf/vmlinux" CACHE STRING
        "Path to the running kernel's BTF, dumped into vmlinux.h")

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
        set(BPF_ARCH x86)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(BPF_ARCH arm64)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ppc64le")
        set(BPF_ARCH powerpc)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "mips")
        set(BPF_ARCH mips)
    else()
        set(BPF_ARCH ${CMAKE_SYSTEM_PROCESSOR})
    endif()

    set(GEN_DIR ${CMAKE_BINARY_DIR}/generated)
    file(MAKE_DIRECTORY ${GEN_DIR})

    # CO-RE: same as the Makefile, the type definitions come from the
    # running kernel's own BTF, so this only produces a correct vmlinux.h
    # when run on the machine (container) you intend to attach on.
    add_custom_command(
        OUTPUT ${GEN_DIR}/vmlinux.h
        COMMAND ${BPFTOOL_EXECUTABLE} btf dump file ${VMLINUX_BTF} format c > ${GEN_DIR}/vmlinux.h
        COMMENT "Dumping kernel BTF (${VMLINUX_BTF}) to vmlinux.h"
        VERBATIM)

    # mysql_reroute.bpf.c uprobes a client library rather than touching
    # kernel tracepoints, but still includes vmlinux.h for the plain
    # __u8/__u32/... typedefs, so it shares the same vmlinux.h dependency.
    add_custom_command(
        OUTPUT ${GEN_DIR}/mysql_reroute.bpf.o
        COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH}
                -Wall -Werror -I${GEN_DIR} -I${CMAKE_SOURCE_DIR}/bpf
                -c ${CMAKE_SOURCE_DIR}/bpf/mysql_reroute.bpf.c -o ${GEN_DIR}/mysql_reroute.bpf.o
        DEPENDS ${CMAKE_SOURCE_DIR}/bpf/mysql_reroute.bpf.c
                ${CMAKE_SOURCE_DIR}/bpf/mysql_reroute.h
                ${CMAKE_SOURCE_DIR}/bpf/proto.h
                ${GEN_DIR}/vmlinux.h
        COMMENT "Compiling mysql_reroute.bpf.c for BPF target"
        VERBATIM)

    add_custom_command(
        OUTPUT ${GEN_DIR}/mysql_reroute.skel.h
        COMMAND ${BPFTOOL_EXECUTABLE} gen skeleton ${GEN_DIR}/mysql_reroute.bpf.o > ${GEN_DIR}/mysql_reroute.skel.h
        DEPENDS ${GEN_DIR}/mysql_reroute.bpf.o
        COMMENT "Generating mysql_reroute.skel.h"
        VERBATIM)

    add_custom_target(mysql_reroute_skeleton DEPENDS ${GEN_DIR}/mysql_reroute.skel.h)

    add_executable(agent src/agent.cpp)
    target_include_directories(agent PRIVATE ${GEN_DIR} bpf)
    target_link_libraries(agent PRIVATE bpf elf z)
    add_dependencies(agent mysql_reroute_skeleton)
else()
    message(STATUS
        "valkey-ebpf: non-Linux host (${CMAKE_SYSTEM_NAME}) -- configuring "
        "IDE-only stub targets against include/bpf_stub. eBPF does not "
        "exist outside Linux; these exist purely so clangd/CLion/VS Code "
        "can parse and navigate the code with working autocomplete. "
        "`cmake --build` is not expected to produce a working binary here. "
        "The real build always runs inside the bpf container: "
        "docker compose exec bpf make")

    add_executable(agent src/agent.cpp)
    target_include_directories(agent PRIVATE include/bpf_stub bpf)

    add_library(mysql_reroute_bpf_stub OBJECT bpf/mysql_reroute.bpf.c)
    target_include_directories(mysql_reroute_bpf_stub PRIVATE include/bpf_stub bpf)
    set_target_properties(mysql_reroute_bpf_stub PROPERTIES EXCLUDE_FROM_ALL TRUE)
endif()
