#pragma once
/*
 * Stand-in for libbpf's userspace bpf/bpf.h -- the fd-based syscall wrappers.
 *
 * A different header, with different signatures, from bpf/bpf_helpers.h's
 * BPF-program-side functions of the same names. bpf_map_update_elem() here
 * takes an fd; there it takes a map pointer.
 */
#ifndef VALKEY_QCACHE_SHIM_BPF_BPF_H
#define VALKEY_QCACHE_SHIM_BPF_BPF_H

#include <stddef.h>
#include <stdint.h>

#ifndef __u32
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

/* Real UAPI values. BPF_SK_SKB_VERDICT is 38, not adjacent to the others --
 * it was added years later. */
enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS = 0,
	BPF_CGROUP_SOCK_OPS = 3,
	BPF_SK_SKB_STREAM_PARSER = 4,
	BPF_SK_SKB_STREAM_VERDICT = 5,
	BPF_SK_MSG_VERDICT = 7,
	BPF_CGROUP_INET4_CONNECT = 10,
	BPF_SK_SKB_VERDICT = 38,
};

int bpf_map_lookup_elem(int fd, const void *key, void *value);
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
int bpf_map_delete_elem(int fd, const void *key);
int bpf_map_get_next_key(int fd, const void *key, void *next_key);

int bpf_prog_attach(int prog_fd, int attachable_fd, enum bpf_attach_type type,
		     unsigned int flags);
int bpf_prog_detach2(int prog_fd, int attachable_fd, enum bpf_attach_type type);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_QCACHE_SHIM_BPF_BPF_H */
