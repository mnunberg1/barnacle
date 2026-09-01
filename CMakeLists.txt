# CMakeLists.txt exists for IDE support (CLion, VS Code + clangd), not as a
# replacement for the Makefile, which is the supported way to build.
#
# On Linux with a BPF toolchain, use the Makefile. Off Linux, this configures
# every source against ide_shims/ so an editor can parse and navigate the
# whole tree -- including the eBPF program and the parts that use libbpf,
# neither of which exists on a workstation.
#
# Nothing built off Linux is runnable. The shims declare signatures with no
# definitions, so targets are syntax-only there; that is deliberate, since a
# fake implementation would misrepresent what the code does.
cmake_minimum_required(VERSION 3.16)
project(barnacle C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SHIMS ${CMAKE_SOURCE_DIR}/ide_shims)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(ON_LINUX TRUE)
else()
    set(ON_LINUX FALSE)
    message(STATUS
        "barnacle: non-Linux host (${CMAKE_SYSTEM_NAME}) -- configuring "
        "against ide_shims/ for editor support only. eBPF does not exist here; "
        "build with 'docker compose -f demo/docker-compose.yml exec ctl make'.")
endif()

# --- always native: no Linux-only headers involved -----------------------

# Includes are written relative to the source root, so that is what goes on
# the path -- PUBLIC, since every test below includes these headers the same
# way the sources do.
add_library(barnacle_mysql STATIC
    src/common/mysql/protocol.cpp
    src/common/mysql/resultset.cpp)
target_include_directories(barnacle_mysql PUBLIC src)

# GoogleTest drives the userspace units. It is usually absent on a
# workstation, so the tests are optional here -- the point of this file off
# Linux is that everything PARSES, and the Makefile is what actually runs
# them in the container.
enable_testing()
find_package(GTest QUIET)
if(GTest_FOUND)
    add_executable(test_protocol tests/test_protocol.cpp)
    target_link_libraries(test_protocol PRIVATE barnacle_mysql GTest::gtest GTest::gtest_main)
    add_test(NAME protocol COMMAND test_protocol)

    add_executable(test_session tests/test_session.cpp src/common/session.cpp)
    target_include_directories(test_session PRIVATE src)
    target_link_libraries(test_session PRIVATE barnacle_mysql GTest::gtest GTest::gtest_main)
    add_test(NAME session COMMAND test_session)

    add_executable(test_request tests/test_request.cpp src/common/session.cpp
        src/common/stmtlist.cpp)
    # test_request reaches defs.h, which reaches <linux/bpf.h>. Off Linux
    # that comes from the shims, the same way the eBPF targets get it.
    target_include_directories(test_request PRIVATE src)
    if(NOT ON_LINUX)
        target_include_directories(test_request PRIVATE ${SHIMS})
    endif()
    target_link_libraries(test_request PRIVATE barnacle_mysql GTest::gtest GTest::gtest_main)
    add_test(NAME request COMMAND test_request)

    add_executable(test_resultset tests/test_resultset.cpp)
    target_link_libraries(test_resultset PRIVATE barnacle_mysql GTest::gtest GTest::gtest_main)
    add_test(NAME resultset COMMAND test_resultset)
else()
    message(STATUS "barnacle: GoogleTest not found -- unit tests not configured")
endif()

# --- everything else: real on Linux, shimmed elsewhere -------------------

# Parse-only targets off Linux. OBJECT libraries rather than executables so
# CMake never tries to link against symbols the shims deliberately leave
# undefined.
function(add_shimmed_target name)
    add_library(${name} OBJECT ${ARGN})
    target_include_directories(${name} PRIVATE
        src src/kclient src/daemon src/uclient src/common)
    if(NOT ON_LINUX)
        target_include_directories(${name} BEFORE PRIVATE ${SHIMS})
    endif()
    set_target_properties(${name} PROPERTIES EXCLUDE_FROM_ALL TRUE)
endfunction()

add_shimmed_target(daemon_objs
    src/daemon/main.cpp
    src/daemon/arena.cpp
    src/daemon/dpipes.cpp
    src/common/stmtlist.cpp
    src/common/valkey.cpp)

add_shimmed_target(session_objs src/common/session.cpp)

# The eBPF program. Compiled for the BPF target by the Makefile; here it is
# only ever parsed, which is still worth having -- this is the file where a
# typo costs the most time to find. kclient is the ONLY eBPF in the project:
# userspace interception is a Frida agent, not a BPF program.
add_shimmed_target(kclient_bpf src/kclient/kclient.bpf.c)

# uclient is ordinary C++ now. It needs frida-gum, which is not on a
# workstation, so only the half that does not touch Frida is parsed here.
add_shimmed_target(uclient_objs src/uclient/shared.cpp)

add_shimmed_target(privileged_tests
    tests/test_caps.c
    tests/test_xproc.c)
