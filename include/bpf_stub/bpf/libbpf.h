#pragma once
/*
 * IDE-indexing stub for libbpf's bpf/libbpf.h -- just enough of the skeleton
 * loader / ring buffer API surface for src/agent.cpp to type-check.
 * Declarations only, no bodies; see
 * bpf/bpf_helpers.h in this directory for why.
 */
#ifndef VALKEY_EBPF_LIBBPF_STUB_H
#define VALKEY_EBPF_LIBBPF_STUB_H

#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h> /* pid_t */

#include "bpf.h" /* enum bpf_attach_type */

#ifdef __cplusplus
extern "C" {
#endif

struct bpf_map;     /* opaque */
struct bpf_program;  /* opaque */
struct bpf_link;     /* opaque */

int bpf_map__fd(const struct bpf_map *map);
int bpf_program__fd(const struct bpf_program *prog);
void bpf_program__set_expected_attach_type(struct bpf_program *prog, enum bpf_attach_type type);
struct bpf_link *bpf_program__attach_cgroup(const struct bpf_program *prog, int cgroup_fd);
void bpf_link__destroy(struct bpf_link *link);

enum libbpf_print_level {
	LIBBPF_WARN,
	LIBBPF_INFO,
	LIBBPF_DEBUG,
};

typedef int (*libbpf_print_fn_t)(enum libbpf_print_level level, const char *format,
				  va_list args);
libbpf_print_fn_t libbpf_set_print(libbpf_print_fn_t fn);

struct ring_buffer; /* opaque */
typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);

struct ring_buffer *ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx,
				      const void *opts);
int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms);
void ring_buffer__free(struct ring_buffer *rb);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_EBPF_LIBBPF_STUB_H */
