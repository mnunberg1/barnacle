#pragma once
/*
 * IDE-indexing stub for libbpf's bpf/bpf_helpers.h (the header BPF-target
 * programs include). Not a functional
 * implementation: every helper below is declared, never defined, which is
 * enough for clangd to type-check call sites without a link step. See
 * CMakeLists.txt and linux_types_stub.h.
 */
#ifndef VALKEY_EBPF_BPF_HELPERS_STUB_H
#define VALKEY_EBPF_BPF_HELPERS_STUB_H

#include "../linux_types_stub.h"

#ifdef __cplusplus
extern "C" {
#endif

/* On a real BPF target this places the object in an ELF section bpftool
 * looks for (".maps", "license", "tracepoint/..."). There is no such
 * pipeline here, and macOS's Mach-O section-name syntax differs from ELF's,
 * so this is a deliberate no-op rather than an attempt to replicate it. */
#define SEC(name)

/* Verbatim from the real bpf_helpers.h -- these encode a map's field values
 * into an anonymous member's *type* so bpftool can read them back out of
 * BTF; portable C, safe to reuse as-is. */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

/* Only the map types this project actually declares; real UAPI values. */
enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_RINGBUF = 27,
};

void *bpf_map_lookup_elem(void *map, const void *key);
long bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags);
long bpf_map_delete_elem(void *map, const void *key);

long bpf_probe_read_user(void *dst, __u32 size, const void *unsafe_ptr);
long bpf_probe_read_kernel(void *dst, __u32 size, const void *unsafe_ptr);
long bpf_probe_read_kernel_str(void *dst, __u32 size, const void *unsafe_ptr);
long bpf_probe_write_user(void *unsafe_ptr, const void *src, __u32 size);

__u64 bpf_ktime_get_ns(void);
__u64 bpf_get_current_pid_tgid(void);
__u64 bpf_get_current_uid_gid(void);
long bpf_get_current_comm(void *buf, __u32 size_of_buf);
void *bpf_get_current_task_btf(void);

void *bpf_ringbuf_reserve(void *ringbuf, __u64 size, __u64 flags);
void bpf_ringbuf_submit(void *data, __u64 flags);
void bpf_ringbuf_discard(void *data, __u64 flags);

/* sockmap: struct bpf_sock_ops/sk_msg_md/__sk_buff are declared in
 * vmlinux.h (this directory), matching where the real, BTF-derived
 * versions of those structs come from. */
long bpf_sock_hash_update(struct bpf_sock_ops *skops, void *map, void *key, __u64 flags);
long bpf_msg_pull_data(struct sk_msg_md *msg, __u32 start, __u32 end, __u64 flags);
long bpf_msg_cork_bytes(struct sk_msg_md *msg, __u32 bytes);
long bpf_msg_pop_data(struct sk_msg_md *msg, __u32 start, __u32 len, __u64 flags);
long bpf_skb_load_bytes(const void *skb, __u32 offset, void *to, __u32 len);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_EBPF_BPF_HELPERS_STUB_H */
