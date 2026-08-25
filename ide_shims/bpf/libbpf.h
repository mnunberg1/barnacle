#pragma once
/*
 * Stand-in for libbpf's bpf/libbpf.h -- the object/program/map API the
 * loaders use.
 */
#ifndef VALKEY_QCACHE_SHIM_LIBBPF_H
#define VALKEY_QCACHE_SHIM_LIBBPF_H

#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>

#include "bpf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct bpf_map;     /* opaque */
struct bpf_program; /* opaque */
struct bpf_link;    /* opaque */
struct bpf_object;  /* opaque */

int bpf_map__fd(const struct bpf_map *map);
const char *bpf_map__name(const struct bpf_map *map);
int bpf_program__fd(const struct bpf_program *prog);
const char *bpf_program__name(const struct bpf_program *prog);
void bpf_program__set_expected_attach_type(struct bpf_program *prog,
					    enum bpf_attach_type type);

struct bpf_link *bpf_program__attach(const struct bpf_program *prog);
struct bpf_link *bpf_program__attach_cgroup(const struct bpf_program *prog,
					     int cgroup_fd);
void bpf_link__destroy(struct bpf_link *link);

enum libbpf_print_level {
	LIBBPF_WARN,
	LIBBPF_INFO,
	LIBBPF_DEBUG,
};
typedef int (*libbpf_print_fn_t)(enum libbpf_print_level level, const char *fmt,
				  va_list args);
libbpf_print_fn_t libbpf_set_print(libbpf_print_fn_t fn);

/* Internal to libbpf and not exported from the shared object, which is why
 * the uclient loader links against libbpf.a rather than libbpf.so. */
long elf_find_func_offset_from_file(const char *binary_path, const char *name);

struct ring_buffer;
typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
struct ring_buffer *ring_buffer__new(int map_fd, ring_buffer_sample_fn cb, void *ctx,
				      const void *opts);
int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms);
void ring_buffer__free(struct ring_buffer *rb);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_QCACHE_SHIM_LIBBPF_H */
