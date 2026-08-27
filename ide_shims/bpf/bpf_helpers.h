#pragma once
/*
 * Stand-in for libbpf's bpf/bpf_helpers.h -- the header a BPF *program*
 * includes. Declarations only, no bodies: enough for clangd to type-check
 * call sites, and honest about the fact that none of it can run here.
 */
#ifndef VALKEY_QCACHE_SHIM_BPF_HELPERS_H
#define VALKEY_QCACHE_SHIM_BPF_HELPERS_H

#include "../vmlinux.h"

#ifdef __cplusplus
extern "C" {
#endif

/* On a real BPF target this places the object into an ELF section bpftool
 * reads back (".maps", "license", "sockops", "uprobe/lib:sym"). Mach-O has no
 * equivalent syntax, so this is deliberately a no-op rather than a broken
 * imitation. */
#define SEC(name)

/* Verbatim from the real header. These encode a map's attributes into an
 * anonymous member's *type*, which is how bpftool recovers them from BTF.
 * Portable C, so they are reused as-is. */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
/* For attributes too large to encode as an array bound -- map_extra, which
 * carries the arena's fixed virtual address. */
#define __ulong(name, val) enum name##__##val { name##__value = val } name

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

/* Redirect flag: deliver into the target socket's INGRESS queue, so bytes
 * look like they arrived from the network. Without it they would be sent out
 * of the socket instead. */
enum {
	BPF_F_INGRESS = (1ULL << 0),
};

/* Only the map types this project declares; real UAPI values. */
enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_ARENA = 33,
};

/* Map creation flags this project uses. Real UAPI values. */
enum {
	BPF_F_NO_PREALLOC = (1U << 0),
	BPF_F_MMAPABLE = (1U << 10),
};

/* libbpf pins the map under its own name in bpffs at load time, and reuses
 * an existing pin if one is there. This is how the daemon and the client
 * processes end up holding the same maps without passing descriptors. */
enum libbpf_pin_type {
	LIBBPF_PIN_NONE = 0,
	LIBBPF_PIN_BY_NAME = 1,
};

/* --- map access --- */
void *bpf_map_lookup_elem(void *map, const void *key);
long bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags);
long bpf_map_delete_elem(void *map, const void *key);

/* --- process/context --- */
__u64 bpf_get_current_pid_tgid(void);
__u64 bpf_get_current_uid_gid(void);
__u64 bpf_ktime_get_ns(void);
long bpf_get_current_comm(void *buf, __u32 size);
void *bpf_get_current_task_btf(void);

/* --- memory --- */
long bpf_probe_read_user(void *dst, __u32 size, const void *unsafe_ptr);
long bpf_probe_read_kernel(void *dst, __u32 size, const void *unsafe_ptr);
long bpf_probe_read_kernel_str(void *dst, __u32 size, const void *unsafe_ptr);
long bpf_probe_write_user(void *unsafe_ptr, const void *src, __u32 size);

/* --- sockmap --- */
long bpf_sock_hash_update(struct bpf_sock_ops *skops, void *map, void *key, __u64 flags);
long bpf_msg_redirect_hash(struct sk_msg_md *msg, void *map, void *key, __u64 flags);
/* The index-keyed form, for a SOCKMAP rather than a SOCKHASH. */
long bpf_msg_redirect_map(struct sk_msg_md *msg, void *map, __u32 key, __u64 flags);

/* Per-socket storage, keyed by the socket itself rather than by anything
 * derived from it. Freed with the socket, so it cannot outlive what it
 * describes. */
void *bpf_sk_storage_get(void *map, void *sk, void *value, __u64 flags);
long bpf_sk_storage_delete(void *map, void *sk);
long bpf_sk_redirect_hash(struct __sk_buff *skb, void *map, void *key, __u64 flags);
long bpf_msg_pull_data(struct sk_msg_md *msg, __u32 start, __u32 end, __u64 flags);
long bpf_msg_cork_bytes(struct sk_msg_md *msg, __u32 bytes);
long bpf_msg_pop_data(struct sk_msg_md *msg, __u32 start, __u32 len, __u64 flags);
long bpf_skb_load_bytes(const void *skb, __u32 offset, void *to, __u32 len);

/*
 * Override a function's return value from a uprobe.
 *
 * Only legal when the program was attached with BPF_TYPE_UPROBE_OVERRIDE. A
 * plain uprobe has no override callback installed, and calling this from one
 * throws and aborts the *target process* -- see docs/TLS_INTERCEPTION.md. The
 * declaration cannot express that constraint; the comment has to.
 */
long bpf_override_return(struct pt_regs *ctx, __u64 rc);

/* --- ringbuf --- */
void *bpf_ringbuf_reserve(void *ringbuf, __u64 size, __u64 flags);
void bpf_ringbuf_submit(void *data, __u64 flags);
void bpf_ringbuf_discard(void *data, __u64 flags);
long bpf_ringbuf_output(void *ringbuf, void *data, __u64 size, __u64 flags);

/* --- debug --- */
long bpf_trace_printk(const char *fmt, __u32 fmt_size, ...);
#define bpf_printk(fmt, ...)                                                      \
	({                                                                        \
		static const char ____fmt[] = fmt;                                \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);        \
	})

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_QCACHE_SHIM_BPF_HELPERS_H */
