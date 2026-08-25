#pragma once
/*
 * IDE-indexing stub for libbpf's userspace bpf/bpf.h (the fd-based syscall
 * wrappers src/agent.cpp call) -- a different
 * header, with different signatures, from bpf/bpf_helpers.h's *BPF-program*
 * side helpers of the same name. Declarations only, no bodies; see
 * bpf/bpf_helpers.h in this directory for why.
 */
#ifndef VALKEY_EBPF_BPF_BPF_STUB_H
#define VALKEY_EBPF_BPF_BPF_STUB_H

#include "../linux_types_stub.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Real value from linux/bpf.h (UAPI), re-exported by the real libbpf.h. */
enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

int bpf_map_lookup_elem(int fd, const void *key, void *value);
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
int bpf_map_delete_elem(int fd, const void *key);

/* Only the attach types agent.cpp actually uses; real UAPI values (see
 * enum bpf_attach_type in the kernel's linux/bpf.h). */
enum bpf_attach_type {
	BPF_CGROUP_SOCK_OPS = 3,
	BPF_SK_MSG_VERDICT = 7,
	BPF_SK_SKB_VERDICT = 38,
};

int bpf_prog_attach(int prog_fd, int attachable_fd, enum bpf_attach_type type,
		     unsigned int flags);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_EBPF_BPF_BPF_STUB_H */
