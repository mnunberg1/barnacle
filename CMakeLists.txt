# CMakeLists.txt exists for IDE support (CLion, VS Code + clangd), not as a
# replacement for the Makefile, which is the supported way to build.
#
# On Linux with a BPF toolchain, use the Makefile. Off Linux, this configures
# every source against ide_shims/ so an editor can parse and navigate the
# whole tree -- including the eBPF programs and the parts that use libbpf and
# bpftime, none of which exist on a workstation.
#
# Nothing built off Linux is runnable. The shims declare signatures with no
# definitions, so targets are syntax-only there; that is deliberate, since a
# fake implementation would misrepresent what the code does.
cmake_minimum_required(VERSION 3.16)
project(valkey_qcache C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SHIMS ${CMAKE_SOURCE_DIR}/ide_shims)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(ON_LINUX TRUE)
else()
    set(ON_LINUX FALSE)
    message(STATUS
        "valkey-qcache: non-Linux host (${CMAKE_SYSTEM_NAME}) -- configuring "
        "against ide_shims/ for editor support only. eBPF does not exist here; "
        "build with 'docker compose exec bpf make'.")
endif()

# --- always native: no Linux-only headers involved -----------------------

add_executable(qcache
    src/qcache/main.cpp
    src/qcache/config.cpp
    src/qcache/discover.cpp)
target_include_directories(qcache PRIVATE src/qcache)

add_library(qcache_mysql STATIC src/common/mysql/protocol.cpp)
target_include_directories(qcache_mysql PUBLIC src/common)

add_executable(test_protocol tests/test_protocol.cpp)
target_link_libraries(test_protocol PRIVATE qcache_mysql)

enable_testing()
add_test(NAME protocol COMMAND test_protocol)

# --- everything else: real on Linux, shimmed elsewhere -------------------

# Parse-only targets off Linux. OBJECT libraries rather than executables so
# CMake never tries to link against symbols the shims deliberately leave
# undefined.
function(add_shimmed_target name)
    add_library(${name} OBJECT ${ARGN})
    target_include_directories(${name} PRIVATE
        src src/kclient src/agent src/uclient src/common)
    if(NOT ON_LINUX)
        target_include_directories(${name} BEFORE PRIVATE ${SHIMS})
        # Cosmetic on this path: macOS deprecates syscall(2), which
        # attach_override.h calls.
        target_compile_options(${name} PRIVATE -Wno-deprecated-declarations)
    endif()
    set_target_properties(${name} PROPERTIES EXCLUDE_FROM_ALL TRUE)
endfunction()

add_shimmed_target(agent_objs
    src/agent/main.cpp
    src/agent/pipes.cpp
    src/common/valkey.cpp)

add_shimmed_target(shm_bridge_objs src/agent/shm_bridge.cpp)
if(NOT ON_LINUX)
    # The real header lives in bpftime's source tree; ide_shims provides a
    # stand-in so this parses.
    target_include_directories(shm_bridge_objs BEFORE PRIVATE ${SHIMS})
endif()

add_shimmed_target(session_objs src/common/session.cpp)

# The eBPF programs. Compiled for the BPF target by the Makefile; here they
# are only ever parsed, which is still worth having -- these are the files
# where a typo costs the most time to find.
add_shimmed_target(kclient_bpf src/kclient/kclient.bpf.c)
add_shimmed_target(uclient_bpf src/uclient/uclient.bpf.c)

add_shimmed_target(uclient_loader_objs src/uclient/loader.c)

add_shimmed_target(privileged_tests
    tests/test_pipes.cpp
    tests/test_redirect.c
    tests/test_shm_bridge.cpp)
