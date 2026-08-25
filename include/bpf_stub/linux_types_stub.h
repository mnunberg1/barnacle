#pragma once
/*
 * Non-Linux (e.g. macOS) stand-ins for the kernel/libbpf integer typedefs, so
 * an IDE's clangd can parse the bpf and src source trees without a real
 * Linux plus libbpf toolchain installed. This whole include/bpf_stub tree
 * exists ONLY to keep the editor's diagnostics and autocomplete useful while
 * browsing code that actually builds and runs inside
 * `docker compose exec bpf make` -- there is no BPF subsystem outside Linux,
 * so nothing here is meant to produce a working binary. See CMakeLists.txt.
 */
#ifndef VALKEY_EBPF_LINUX_TYPES_STUB_H
#define VALKEY_EBPF_LINUX_TYPES_STUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t  __u8;
typedef int8_t   __s8;
typedef uint16_t __u16;
typedef int16_t  __s16;
typedef uint32_t __u32;
typedef int32_t  __s32;
typedef uint64_t __u64;
typedef int64_t  __s64;

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

#endif /* VALKEY_EBPF_LINUX_TYPES_STUB_H */
