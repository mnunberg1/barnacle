/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
/*
 * bpfsys.h - the four bpf(2) calls the agent actually makes.
 *
 * Plain syscalls rather than libbpf. The agent does not load ELF objects or
 * create maps; it opens pins the daemon already made and reads and writes
 * them. Everything else libbpf offers costs it libelf, which costs zlib and
 * zstd, and every one of those is a shared object that has to exist in
 * whatever container we are injected into.
 *
 * That is not hypothetical: injection into another container failed with
 * "libbpf.so.1: cannot open shared object file" before a single hook was
 * installed. With these the agent needs nothing but libc.
 *
 * C rather than C++ because it is four syscalls.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Open a pinned map. Returns a descriptor, or -1. */
int bncl_bpf_obj_get(const char *path);

/* Map element access. All return 0 on success, -1 otherwise. */
int bncl_bpf_lookup(int fd, const void *key, void *value);
int bncl_bpf_update(int fd, const void *key, const void *value, uint64_t flags);
int bncl_bpf_delete(int fd, const void *key);

#ifdef __cplusplus
}
#endif
