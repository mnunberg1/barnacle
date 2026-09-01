// SPDX-License-Identifier: GPL-2.0
#include "daemon/arena.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>

namespace bncld
{

namespace
{

/*
 * One block, free or in use.
 *
 * `size` is the whole block including this header and the footer, so walking
 * forward is `here + size` and nothing has to be remembered between steps.
 * The footer repeats the size, which is what lets free() find the block that
 * ENDS just before this one and merge with it -- the only way to coalesce
 * backwards without keeping a separate index of block starts.
 *
 * `next`/`prev` are only meaningful while the block is free, and live in what
 * is otherwise payload. A free block therefore has a minimum size, which is
 * why MIN_BLOCK exists and why a split that would leave less than that just
 * hands out the slack instead.
 */
struct Blk {
    uint32_t size;
    uint32_t free;
    uint32_t next; /* free list, offsets from the arena base */
    uint32_t prev;
};

struct Foot {
    uint32_t size;
};

constexpr size_t align8(size_t n)
{
    return (n + 7) & ~(size_t)7;
}

constexpr size_t HDR = sizeof(struct Blk);
constexpr size_t FTR = sizeof(struct Foot);

/*
 * Block sizes are multiples of 8, not just payloads.
 *
 * A block is a header, a payload and a footer laid out end to end, and the
 * next block begins where this one stops -- so if a block's TOTAL size is not
 * a multiple of 8, every block after it is misaligned by however much the
 * error has accumulated. Header and footer are 16 and 4, which is exactly the
 * case that gets this wrong: aligning only the payload leaves each block four
 * bytes off. The four bytes of slack land between payload and footer, where
 * nothing reads them.
 */
constexpr size_t MIN_BLOCK = align8(HDR + FTR);

/*
 * A retired block, waiting out its grace period.
 *
 * Kept in the block's own payload -- it is dead memory that nothing may hand
 * out yet, so it is the natural place to record why. That means retirement
 * needs no allocation of its own, which matters: retiring on a full heap must
 * not be the thing that fails.
 */
struct Retired {
    uint64_t at;
    uint32_t next;
    uint32_t _pad;
};

} // namespace

/* --- walking the heap ---------------------------------------------------- */

#define BLK(off) ((struct Blk *)(base + (off)))
#define FOOT(off) ((struct Foot *)(base + (off) + BLK(off)->size - FTR))
#define OFF(p) ((uint32_t)((uint8_t *)(p) - base))

bool Arena::open(int map_fd)
{
    size_t len = (size_t)BNCL_ARENA_PAGES * 4096;

    if (map_fd < 0) {
        return false;
    }

    /*
     * MAP_FIXED, deliberately.
     *
     * The arena has to land at the same address in every process or the
     * pointers stored in it mean nothing outside whoever wrote them.
     * Asking for a hint and accepting whatever we get would appear to work
     * in the daemon and then hand clients garbage, which is the worst
     * possible failure mode -- so if this address is unavailable, fail
     * loudly here.
     */
    void *p =
        mmap((void *)BNCL_ARENA_VA, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, map_fd, 0);

    if (p == MAP_FAILED) {
        fprintf(stderr, "arena: cannot map %zu bytes at %#llx: %s\n", len,
                (unsigned long long)BNCL_ARENA_VA, strerror(errno));
        return false;
    }

    if (!init(p, len)) {
        munmap(p, len);
        return false;
    }
    mapped = true;
    return true;
}

bool Arena::init(void *mem, size_t len)
{
    if (!mem || len <= BNCL_CTL_BYTES + MIN_BLOCK) {
        return false;
    }

    base = (uint8_t *)mem;
    cap = len;

    /* One free block covering everything past the control area. */
    struct bncl_ctl *c = ctl();
    uint32_t start = BNCL_CTL_BYTES;
    uint32_t size = (uint32_t)(cap - BNCL_CTL_BYTES);

    memset(c, 0, sizeof(*c));
    c->heap = start;
    c->heap_end = start + size;
    c->free_head = start;
    c->retire = 0;
    c->used = 0;

    struct Blk *b = BLK(start);

    b->size = size;
    b->free = 1;
    b->next = 0;
    b->prev = 0;
    FOOT(start)->size = size;
    return true;
}

void Arena::close()
{
    if (base && mapped) {
        munmap(base, cap);
    }
    base = nullptr;
    cap = 0;
    mapped = false;
}

/* --- the free list ------------------------------------------------------- */

namespace
{
/* Offsets, so 0 can mean "none": the heap never starts at 0 because the
 * control block is there. */
constexpr uint32_t NIL = 0;
} // namespace

void *Arena::alloc(size_t n)
{
    if (!base || n == 0) {
        return nullptr;
    }

    size_t want = align8(align8(n) + HDR + FTR);

    if (want < MIN_BLOCK) {
        want = MIN_BLOCK;
    }
    if (want > cap) {
        return nullptr;
    }

    struct bncl_ctl *c = ctl();

    /* First fit. A best-fit scan would pack better, but this list is
     * short and the cost of a poor fit here is a few wasted bytes in a
     * 16 MiB heap. */
    for (uint32_t off = c->free_head; off != NIL; off = BLK(off)->next) {
        struct Blk *b = BLK(off);

        if (b->size < want) {
            continue;
        }

        /* Unlink before deciding what to do with it, so the split
         * below only ever has to insert. */
        if (b->prev) {
            BLK(b->prev)->next = b->next;
        } else {
            c->free_head = b->next;
        }
        if (b->next) {
            BLK(b->next)->prev = b->prev;
        }

        /* Split only if the remainder is a usable block. Otherwise
         * the caller gets the slack, which is cheaper than tracking a
         * fragment nothing can ever be put in. */
        if (b->size - want >= MIN_BLOCK) {
            uint32_t rest_off = off + (uint32_t)want;
            struct Blk *rest = BLK(rest_off);

            rest->size = b->size - (uint32_t)want;
            rest->free = 1;
            rest->prev = NIL;
            rest->next = c->free_head;
            if (c->free_head) {
                BLK(c->free_head)->prev = rest_off;
            }
            c->free_head = rest_off;
            FOOT(rest_off)->size = rest->size;

            b->size = (uint32_t)want;
            FOOT(off)->size = b->size;
        }

        b->free = 0;
        c->used += b->size - HDR - FTR;
        return base + off + HDR;
    }
    return nullptr; /* heap full */
}

void *Arena::put(const void *src, size_t n)
{
    void *p = alloc(n);

    if (!p) {
        return nullptr;
    }
    memcpy(p, src, n);
    return p;
}

void Arena::free(void *p)
{
    if (!base || !p) {
        return;
    }

    struct bncl_ctl *c = ctl();
    uint32_t off = OFF(p) - (uint32_t)HDR;
    struct Blk *b = BLK(off);

    if (b->free) {
        return; /* double free; refuse rather than corrupt the list */
    }
    c->used -= b->size - HDR - FTR;

    /* Coalesce forward. The next block starts where this one ends, and is
     * only mergeable if it is inside the heap and free. */
    uint32_t after = off + b->size;

    if (after < c->heap_end && BLK(after)->free) {
        struct Blk *nb = BLK(after);

        if (nb->prev) {
            BLK(nb->prev)->next = nb->next;
        } else {
            c->free_head = nb->next;
        }
        if (nb->next) {
            BLK(nb->next)->prev = nb->prev;
        }
        b->size += nb->size;
    }

    /* Coalesce backward, via the previous block's footer -- the only
     * thing that says where it began. */
    if (off > c->heap) {
        struct Foot *pf = (struct Foot *)(base + off - FTR);
        uint32_t prev_off = off - pf->size;

        if (prev_off >= c->heap && BLK(prev_off)->free) {
            struct Blk *pb = BLK(prev_off);

            if (pb->prev) {
                BLK(pb->prev)->next = pb->next;
            } else {
                c->free_head = pb->next;
            }
            if (pb->next) {
                BLK(pb->next)->prev = pb->prev;
            }
            pb->size += b->size;
            off = prev_off;
            b = pb;
        }
    }

    b->free = 1;
    b->prev = NIL;
    b->next = c->free_head;
    if (c->free_head) {
        BLK(c->free_head)->prev = off;
    }
    c->free_head = off;
    FOOT(off)->size = b->size;
}

void Arena::retire(void *p, uint64_t now)
{
    if (!base || !p) {
        return;
    }

    struct bncl_ctl *c = ctl();
    uint32_t off = OFF(p) - (uint32_t)HDR;
    struct Blk *b = BLK(off);

    if (b->free) {
        return;
    }
    /* The record goes in the block's own payload. A block big enough to
     * have been allocated is big enough to hold this, because MIN_BLOCK
     * covers the free-list links which are larger. */
    if (b->size < HDR + sizeof(struct Retired) + FTR) {
        free(p); /* too small to track; it was never worth reusing */
        return;
    }

    struct Retired *r = (struct Retired *)(base + off + HDR);

    r->at = now;
    r->next = c->retire;
    c->retire = off;
}

void Arena::reclaim(uint64_t now)
{
    if (!base) {
        return;
    }

    struct bncl_ctl *c = ctl();
    uint32_t off = c->retire;
    uint32_t keep = NIL;

    c->retire = NIL;

    /* Walked once, rebuilding the list of those not yet due. Order does
     * not matter: every entry is checked on every pass. */
    while (off != NIL) {
        struct Retired *r = (struct Retired *)(base + off + HDR);
        uint64_t at = r->at;
        uint32_t next = r->next;

        if (now >= at && now - at >= RETIRE_GRACE_NS) {
            free(base + off + HDR);
        } else {
            r->next = keep;
            keep = off;
        }
        off = next;
    }
    c->retire = keep;
}

size_t Arena::used() const
{
    return base ? (size_t)ctl()->used : 0;
}

size_t Arena::retired() const
{
    size_t n = 0;

    if (!base) {
        return 0;
    }
    for (uint32_t off = ctl()->retire; off != NIL;) {
        struct Retired *r = (struct Retired *)(base + off + HDR);

        n++;
        off = r->next;
    }
    return n;
}

} // namespace bncld
