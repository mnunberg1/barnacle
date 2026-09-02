// SPDX-License-Identifier: GPL-2.0
#pragma once
/*
 * arena.h - the shared allocation region, and the allocator over it.
 *
 * A BPF arena mapped at BNCL_ARENA_VA in every process that opens it.
 * Statement records, statement text and cached response bodies live here,
 * which is what lets a client read a cached result straight out of memory
 * instead of having it copied through the control socket.
 *
 * --- a real allocator, not a bump pointer -------------------------------
 *
 * This used to hand out addresses by advancing a pointer and wrapping at the
 * end. That is the smallest thing that works, and it works by never reusing
 * memory until it has used all the rest -- which is also its whole problem.
 * A statement removed from the list, or a payload replaced by a newer one,
 * held its bytes until the pointer came round again. The arena therefore had
 * to be sized for total churn rather than for live data, and the wrap itself
 * was the only reclamation: entries were overwritten on a schedule set by
 * allocation volume rather than by whether anyone still wanted them.
 *
 * So: an ordinary free-list heap. Blocks carry a header and a footer holding
 * their size, free blocks are linked into a list, and freeing coalesces with
 * both neighbours. First fit, one free list, no size classes -- allocation
 * happens once per statement per TTL, which is nowhere near a hot path, and a
 * simple allocator that is obviously correct is worth more here than a fast
 * one that is not.
 *
 * --- freeing memory other processes are reading -------------------------
 *
 * The hard part is not the allocator, it is knowing when a block is dead.
 * Clients hold raw pointers into the arena and read them without telling
 * anyone, so a block freed at the wrong moment is read as whatever replaces
 * it. Two things together make that safe:
 *
 *   struct stmt is refcounted, so a record cannot be reclaimed while a
 *   client is using it; and
 *
 *   nothing is freed the moment it dies. Dead blocks are RETIRED with a
 *   timestamp and freed only once a grace period has passed, which covers
 *   the window between a client resolving a pointer and taking its
 *   reference -- microseconds against a bound of seconds.
 *
 * Retirement is what the bump allocator was providing accidentally, by
 * distance rather than by time. This provides it deliberately, and bounded.
 */

#include "common/defs.h"

#include <cstddef>
#include <cstdint>

namespace bncl::daemon {

/*
 * How long a retired block waits before its memory is handed out again.
 *
 * It has to outlast the longest gap between a client resolving a pointer into
 * the arena and taking a reference on what it points at. That gap is a
 * handful of instructions; seconds are four orders of magnitude of margin, and
 * cost nothing but a little memory held slightly longer than necessary.
 */
constexpr uint64_t RETIRE_GRACE_NS = 5ull * 1000 * 1000 * 1000;

class Arena {
public:
    /* Map the arena and lay out the heap. `map_fd` is the BPF arena map,
     * from the skeleton or a pin. Returns false if it could not be mapped
     * at BNCL_ARENA_VA -- which is fatal rather than degraded, because a
     * different address makes every pointer in the design meaningless. */
    bool open(int map_fd);
    void close();

    /*
     * Lay the heap out over memory somebody else owns.
     *
     * open() is this plus the mmap. Split out because the allocator is
     * ordinary logic over a byte range and has no business needing a
     * kernel, a BPF map or root to be tested -- tests/test_arena.cpp
     * hands it a malloc'd block and exercises every path in it.
     */
    bool init(void *mem, size_t len);

    bool ok() const
    {
        return base != nullptr;
    }

    /* Allocate `n` bytes, 8-aligned, or nullptr if the heap cannot fit
     * them. Unlike the bump allocator this really can fail: the heap is
     * finite and full is a state it can reach. */
    void *alloc(size_t n);

    /* Copy a blob in and return where it landed. */
    void *put(const void *src, size_t n);

    /*
     * Give a block back.
     *
     * Immediate, and therefore only for memory nobody else can have seen
     * -- an allocation being unwound before it was published, say. For
     * anything a client may hold a pointer to, use retire().
     */
    void free(void *p);

    /*
     * Give a block back, once it is safe to.
     *
     * The block stops being reachable now and its memory is handed out
     * again only after RETIRE_GRACE_NS. This is the call for a payload
     * that has been replaced, or a statement record that has been
     * unpublished: both may be under a client's eye at this instant.
     */
    void retire(void *p, uint64_t now);

    /* Free everything whose grace period has elapsed. Cheap enough for
     * the daemon's idle tick, which is where it is called. */
    void reclaim(uint64_t now);

    size_t used() const;
    size_t capacity() const
    {
        return cap;
    }
    /* Blocks retired but not yet freed. A number that climbs and never
     * falls means reclaim() is not being called. */
    size_t retired() const;

    bncl_ctl *ctl() const
    {
        return (bncl_ctl *)base;
    }

private:
    uint8_t *base = nullptr;
    size_t cap = 0;
    /* Whether close() should unmap. init() is given memory it does not
     * own; open() maps its own and must give it back. */
    bool mapped = false;
};

} // namespace bncl::daemon
