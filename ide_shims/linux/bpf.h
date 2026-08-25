#pragma once
/*
 * Stand-in for Linux's UAPI <linux/bpf.h>. The project's own code uses
 * libbpf's wrappers rather than raw UAPI, so only what bpftime's
 * attach_override.h references is declared.
 */
#ifndef VALKEY_QCACHE_SHIM_LINUX_BPF_H
#define VALKEY_QCACHE_SHIM_LINUX_BPF_H

#include <stdint.h>

#include "types.h"

/* Attach types. BPF_MODIFY_RETURN is the one bpftime's override path reuses
 * to signal that the program may replace a function's return value. */
enum {
	BPF_MODIFY_RETURN = 26,
};

enum bpf_cmd {
	BPF_MAP_CREATE = 0,
	BPF_MAP_LOOKUP_ELEM = 1,
	BPF_MAP_UPDATE_ELEM = 2,
	BPF_MAP_DELETE_ELEM = 3,
	BPF_PROG_LOAD = 5,
	BPF_PROG_ATTACH = 8,
	BPF_PROG_DETACH = 9,
	BPF_LINK_CREATE = 28,
};

/* Truncated: only the perf-event attach shape the override path fills in. */
union bpf_attr {
	struct {
		__u32 prog_fd;
		__u32 target_fd;
		__u32 attach_type;
		__u32 attach_flags;
	} link_create;
	struct {
		__u32 target_fd;
		__u32 attach_bpf_fd;
		__u32 attach_type;
		__u32 attach_flags;
	} prog_attach;
	char __raw[128];
};

#endif /* VALKEY_QCACHE_SHIM_LINUX_BPF_H */
