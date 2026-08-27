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

/* Real libbpf does the same. The enum types the syscall wrappers take are
 * UAPI, not libbpf's own -- and C++ will not accept a forward reference to an
 * enum, so they have to be complete here rather than declared ahead. */
#include <linux/bpf.h>

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

int bpf_map_lookup_elem(int fd, const void *key, void *value);
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
int bpf_map_delete_elem(int fd, const void *key);
int bpf_map_get_next_key(int fd, const void *key, void *next_key);

/* Opts structs in libbpf all lead with their own size, so the library can
 * tell which fields a caller was compiled against. LIBBPF_OPTS fills that in;
 * the real macro wraps a statement expression, which this does not need. */
struct bpf_map_create_opts {
	size_t sz;
	__u32 btf_fd;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 map_flags;
	__u64 map_extra;
};

#define LIBBPF_OPTS(TYPE, NAME, ...) \
	struct TYPE NAME = { .sz = sizeof(struct TYPE), __VA_ARGS__ }

int bpf_map_create(enum bpf_map_type map_type, const char *name, __u32 key_size,
		    __u32 value_size, __u32 max_entries,
		    const struct bpf_map_create_opts *opts);

int bpf_prog_attach(int prog_fd, int attachable_fd, enum bpf_attach_type type,
		     unsigned int flags);
int bpf_prog_detach2(int prog_fd, int attachable_fd, enum bpf_attach_type type);

/* bpffs pins: how a process that did not create a map gets a descriptor for
 * it. This is the route UCLIENT's loader uses to reach the sockmaps -- the
 * client registers its own socket, so it needs the map, not a kernel program. */
int bpf_obj_pin(int fd, const char *pathname);
int bpf_obj_get(const char *pathname);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_QCACHE_SHIM_BPF_BPF_H */
