#pragma once
/*
 * Stand-in for Linux's UAPI <linux/bpf.h>. The project uses libbpf's wrappers
 * rather than raw UAPI, so only the enumerations and flags actually named in
 * src/ and tests/ are declared here.
 */
#ifndef BNCL_SHIM_LINUX_BPF_H
#define BNCL_SHIM_LINUX_BPF_H

#include <stdint.h>

#include "types.h"

/* Attach types. Real UAPI values.
 *
 * BPF_SK_SKB_VERDICT is 38, not adjacent to the others -- it was added years
 * later. */
enum bpf_attach_type {
        BPF_CGROUP_INET_INGRESS = 0,
        BPF_CGROUP_SOCK_OPS = 3,
        BPF_SK_SKB_STREAM_PARSER = 4,
        BPF_SK_SKB_STREAM_VERDICT = 5,
        BPF_SK_MSG_VERDICT = 7,
        BPF_CGROUP_INET4_CONNECT = 10,
        BPF_SK_SKB_VERDICT = 38,
};

/*
 * Program, map and helper identifiers, for the capability probe.
 *
 * Deliberately declared WITHOUT explicit values, unlike bpf_attach_type in
 * bpf/bpf.h. Those are spelled out because they document a real UAPI number a
 * reader might rely on; these are not, because the probe only ever passes them
 * straight back to libbpf on Linux, where the real uapi header supplies the
 * values. Inventing numbers here would produce a header that looks
 * authoritative and is not.
 */
enum bpf_prog_type {
        BPF_PROG_TYPE_SCHED_CLS,
        BPF_PROG_TYPE_SOCK_OPS,
        BPF_PROG_TYPE_SK_SKB,
        BPF_PROG_TYPE_SK_MSG,
};

enum bpf_map_type {
        BPF_MAP_TYPE_ARRAY,
        BPF_MAP_TYPE_SOCKMAP,
        BPF_MAP_TYPE_SOCKHASH,
        BPF_MAP_TYPE_SK_STORAGE,
        BPF_MAP_TYPE_RINGBUF,
};

enum bpf_func_id {
        BPF_FUNC_sock_map_update,
        BPF_FUNC_sock_hash_update,
        BPF_FUNC_msg_redirect_map,
        BPF_FUNC_msg_redirect_hash,
        BPF_FUNC_msg_pop_data,
        BPF_FUNC_sk_storage_get,
        BPF_FUNC_get_netns_cookie,
        BPF_FUNC_timer_init,
        BPF_FUNC_sk_redirect_map,
        BPF_FUNC_get_socket_cookie,
        BPF_FUNC_skb_pull_data,
};

/* Map must be mmapable from userspace -- what makes an arena reachable as
 * ordinary memory in a process that did not create it. */
#define BPF_F_MMAPABLE (1U << 10)

/* Real UAPI values. Attach flags for cgroup programs: MULTI lets several
 * programs attach to the same cgroup and hook, which matters because we do
 * not own the cgroup and must not evict whatever is already there. */
#define BPF_F_ALLOW_OVERRIDE (1U << 0)
#define BPF_F_ALLOW_MULTI (1U << 1)

/* One word in the real thing too. Embedded in a map value to serialise
 * writers; the verifier enforces the locking rules around it. */
struct bpf_spin_lock {
        __u32 val;
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

#endif /* BNCL_SHIM_LINUX_BPF_H */
