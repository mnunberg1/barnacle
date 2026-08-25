#pragma once
/*
 * Stand-in for bpftime's runtime/src/bpftime_shm_internal.hpp.
 *
 * Internal rather than public, and used anyway for one reason: maps are
 * addressed by an index into the shm handler table, and there is no public
 * way to find one by name. Walking the handler table is what bpftimetool does
 * too. Hardcoding indices instead would break the moment uclient's map
 * creation order changed.
 */
#ifndef VALKEY_QCACHE_SHIM_BPFTIME_SHM_INTERNAL_HPP
#define VALKEY_QCACHE_SHIM_BPFTIME_SHM_INTERNAL_HPP

#include "bpftime_shm.hpp"

#include <cstddef>
#include <string>
#include <variant>

namespace bpftime {

/* Real type is a boost::interprocess string living in the shared segment.
 * std::string is close enough for parsing: only .c_str() is ever called. */
struct bpf_map_handler {
	std::string name;

	uint32_t get_key_size() const;
	uint32_t get_value_size() const;
	uint32_t get_max_entries() const;
};

struct bpf_prog_handler {
	std::string name;
};

struct bpf_link_handler {
	std::string name;
};

using handler_variant =
	std::variant<std::monostate, bpf_map_handler, bpf_prog_handler, bpf_link_handler>;

class handler_manager {
public:
	size_t size() const;
	const handler_variant &get_handler(int fd) const;
};

class bpftime_shm {
public:
	const handler_manager *get_manager() const;
};

/* Global holder the runtime initializes; the agent reads through it after
 * bpftime_initialize_global_shm(). */
struct shm_holder_t {
	bpftime_shm global_shared_memory;
};

extern shm_holder_t shm_holder;

} // namespace bpftime

#endif /* VALKEY_QCACHE_SHIM_BPFTIME_SHM_INTERNAL_HPP */
