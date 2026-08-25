#pragma once
/*
 * Stand-in for bpftime's runtime/include/bpftime_shm.hpp.
 *
 * This is the door a process OUTSIDE bpftime's syscall interception uses to
 * reach the maps a bpftime-loaded program is using: a library call that maps
 * the segment directly, not a bpf() syscall. That distinction is what lets
 * the agent hold real kernel BPF fds for kclient while also reading uclient's
 * userspace maps.
 */
#ifndef VALKEY_QCACHE_SHIM_BPFTIME_SHM_HPP
#define VALKEY_QCACHE_SHIM_BPFTIME_SHM_HPP

#include <cstddef>
#include <cstdint>

namespace bpftime {

enum class shm_open_type {
	SHM_NO_CREATE,
	SHM_OPEN_ONLY,       /* attach to an existing segment; never create */
	SHM_CREATE_OR_OPEN,
	SHM_REMOVE_ONLY,
};

/* Truncated to the fields this project reads. Note `max_ents`, not
 * `max_entries` -- the shorter name is what upstream uses. */
struct bpf_map_attr {
	int map_type = 0;
	uint32_t key_size = 0;
	uint32_t value_size = 0;
	uint32_t max_ents = 0;
	uint64_t flags = 0;
};

} // namespace bpftime

extern "C" {

void bpftime_initialize_global_shm(bpftime::shm_open_type type);
void bpftime_destroy_global_shm(void);

int bpftime_maps_create(int fd, const char *name, bpftime::bpf_map_attr attr);
int bpftime_map_get_info(int fd, bpftime::bpf_map_attr *out_attr, const char **out_name,
			  int *out_type);
const void *bpftime_map_lookup_elem(int fd, const void *key);
long bpftime_map_update_elem(int fd, const void *key, const void *value, uint64_t flags);
long bpftime_map_delete_elem(int fd, const void *key);
int bpftime_map_get_next_key(int fd, const void *key, void *next_key);

} // extern "C"

#endif /* VALKEY_QCACHE_SHIM_BPFTIME_SHM_HPP */
