#pragma once
/*
 * Stand-in for libbpf's bpf/libbpf.h -- the object/program/map API the
 * loaders use.
 */
#ifndef BNCL_SHIM_LIBBPF_H
#define BNCL_SHIM_LIBBPF_H

#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>

#include "bpf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Truncated to the field this project sets. `sz` leads every libbpf opts
 * struct so the library can tell which fields the caller was built against. */
struct bpf_object_open_opts {
        size_t sz;
        const char *object_name;
        int relaxed_maps;
        const char *pin_root_path;
};

struct bpf_map;     /* opaque */
struct bpf_program; /* opaque */
struct bpf_link;    /* opaque */
struct bpf_object;  /* opaque */

/* Removes every pin the object created under `path`. The daemon calls this on
 * the way out so a dead daemon does not leave live maps pinned behind it. */
int bpf_object__unpin_maps(struct bpf_object *obj, const char *path);

int bpf_map__fd(const struct bpf_map *map);
const char *bpf_map__name(const struct bpf_map *map);
/* Resize before load, so the daemon can honour its -S/-C options without a
 * rebuild. After load this fails; max_entries is fixed once a map exists. */
int bpf_map__set_max_entries(struct bpf_map *map, unsigned int max_entries);
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

/* Feature probes. Each loads a throwaway program or creates a throwaway map
 * and reports whether the kernel accepted it: 1 yes, 0 no, negative on error.
 * Nothing is attached. The enum types come in via bpf.h above. */
int libbpf_probe_bpf_prog_type(enum bpf_prog_type prog_type, const void *opts);
int libbpf_probe_bpf_map_type(enum bpf_map_type map_type, const void *opts);
int libbpf_probe_bpf_helper(enum bpf_prog_type prog_type, enum bpf_func_id helper_id,
                             const void *opts);

struct ring_buffer;
typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
struct ring_buffer *ring_buffer__new(int map_fd, ring_buffer_sample_fn cb, void *ctx,
                                      const void *opts);
int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms);
void ring_buffer__free(struct ring_buffer *rb);

#ifdef __cplusplus
}
#endif

#endif /* BNCL_SHIM_LIBBPF_H */
