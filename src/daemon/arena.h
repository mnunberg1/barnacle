// SPDX-License-Identifier: GPL-2.0
#pragma once
/*
 * arena.h - the shared allocation region.
 *
 * A BPF arena mapped at QC_ARENA_VA in every process that opens it. Statement
 * text and cached response bodies live here, which is what lets a client read
 * a cached result straight out of memory instead of having it copied through
 * the control socket.
 *
 * --- why a bump allocator that wraps -------------------------------------
 *
 * Nothing is freed individually. Entries are short-lived under a TTL, and a
 * chunk that gets overwritten after a wrap is only reachable through a
 * statement record that has already been replaced -- so a reader either sees
 * the old record and old bytes, or the new record and new bytes, never a
 * mixture. A real allocator would buy the ability to reclaim early, which
 * nothing here needs, at the cost of free-list bookkeeping in memory several
 * processes write to.
 *
 * The ordering rule that makes that true lives in the caller, not here:
 * payload bytes must be written BEFORE the record that points at them is
 * published.
 */

#include "common/defs.h"

#include <cstddef>
#include <cstdint>

namespace qcd {

class Arena {
public:
	/* Map the arena. `map_fd` is the BPF arena map, from the skeleton or a
	 * pin. Returns false if it could not be mapped at QC_ARENA_VA -- which
	 * is fatal rather than degraded, because a different address makes
	 * every pointer in the design meaningless. */
	bool open(int map_fd);
	void close();

	bool ok() const
	{
		return base != nullptr;
	}

	/* Bump-allocate `n` bytes, 8-aligned. Returns nullptr only if `n` is
	 * larger than the whole arena. */
	void *alloc(size_t n);

	/* Copy a blob in and return where it landed. */
	void *put(const void *src, size_t n);

	size_t used() const
	{
		return next;
	}
	size_t capacity() const
	{
		return cap;
	}
	/* How many times the bump pointer has wrapped. Worth watching: a high
	 * rate means entries are being overwritten before their TTL expires,
	 * i.e. the arena is too small for the working set. */
	uint64_t wraps() const
	{
		return nwrap;
	}

private:
	uint8_t *base = nullptr;
	size_t cap = 0;
	size_t next = 0;
	uint64_t nwrap = 0;
};

} // namespace qcd
