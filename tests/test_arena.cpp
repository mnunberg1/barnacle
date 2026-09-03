// SPDX-License-Identifier: GPL-2.0
/*
 * test_arena.cpp - the shared heap.
 *
 * The allocator is ordinary logic over a byte range, so it is tested over a
 * malloc'd one: no kernel, no BPF map, no root. Every case here is a fixed
 * sequence with a checked outcome rather than a randomised soak, because a
 * soak that fails once in a while tells you almost nothing about which of
 * these paths is wrong.
 */
#include "daemon/arena.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

/* Big enough that a handful of allocations is not the whole heap, small
 * enough that exhausting it in a test is quick. */
constexpr size_t HEAP = 64 * 1024;

class ArenaTest : public ::testing::Test {
protected:
    void SetUp() override {
        mem.assign(HEAP, 0);
        ASSERT_TRUE(a.init(mem.data(), mem.size()));
    }

    std::vector<uint8_t> mem;
    bncl::daemon::Arena a;
};

} // namespace

TEST_F(ArenaTest, AllocReturnsUsableDistinctMemory) {
    void *p = a.alloc(100);
    void *q = a.alloc(100);

    ASSERT_NE(p, nullptr);
    ASSERT_NE(q, nullptr);
    EXPECT_NE(p, q);

    /* Writing one must not disturb the other. */
    memset(p, 0xAA, 100);
    memset(q, 0xBB, 100);
    EXPECT_EQ(((uint8_t *)p)[99], 0xAA);
    EXPECT_EQ(((uint8_t *)q)[0], 0xBB);
}

TEST_F(ArenaTest, AllocIsEightByteAligned) {
    for (size_t n = 1; n <= 64; n++) {
        void *p = a.alloc(n);

        ASSERT_NE(p, nullptr) << "n=" << n;
        EXPECT_EQ((uintptr_t)p % 8, 0u) << "n=" << n;
    }
}

TEST_F(ArenaTest, PutCopies) {
    const char msg[] = "select 1";
    void *p = a.put(msg, sizeof(msg));

    ASSERT_NE(p, nullptr);
    EXPECT_STREQ((const char *)p, msg);
}

TEST_F(ArenaTest, UsedTracksLiveBytesAndReturnsToZero) {
    EXPECT_EQ(a.used(), 0u);

    void *p = a.alloc(1000);

    ASSERT_NE(p, nullptr);
    /* At least what was asked for: the block is rounded up, and a split
     * that would leave an unusable remainder hands over the slack. */
    EXPECT_GE(a.used(), 1000u);

    a.free(p);
    EXPECT_EQ(a.used(), 0u);
}

TEST_F(ArenaTest, FreedMemoryIsHandedOutAgain) {
    void *p = a.alloc(512);

    ASSERT_NE(p, nullptr);
    a.free(p);

    void *q = a.alloc(512);

    /* The point of having an allocator at all: the same bytes come back,
     * rather than the heap marching forward until it wraps. */
    EXPECT_EQ(p, q);
}

TEST_F(ArenaTest, AdjacentFreesCoalesce) {
    /* Three in a row, then free all three. If the middle one did not
     * merge with both neighbours, the heap is left with fragments and the
     * big allocation below cannot be satisfied. */
    void *p = a.alloc(8000);
    void *q = a.alloc(8000);
    void *r = a.alloc(8000);

    ASSERT_NE(p, nullptr);
    ASSERT_NE(q, nullptr);
    ASSERT_NE(r, nullptr);

    a.free(q); /* middle first, so it has a live block on each side */
    a.free(p); /* coalesces forward into q */
    a.free(r); /* coalesces backward into p+q */

    EXPECT_EQ(a.used(), 0u);
    EXPECT_NE(a.alloc(24000), nullptr);
}

TEST_F(ArenaTest, CoalesceBackwardUsesThePreviousFooter) {
    void *p = a.alloc(4000);
    void *q = a.alloc(4000);

    ASSERT_NE(p, nullptr);
    ASSERT_NE(q, nullptr);

    a.free(p); /* p free, q live: nothing to merge forward with */
    a.free(q); /* must find p by walking back over p's footer */

    EXPECT_EQ(a.used(), 0u);
    EXPECT_EQ(a.alloc(8000), p);
}

TEST_F(ArenaTest, ExhaustionReturnsNullRatherThanOverrunning) {
    std::vector<void *> got;

    for (;;) {
        void *p = a.alloc(4096);

        if (!p) {
            break;
        }
        /* Every block must lie inside the memory we handed init(). */
        EXPECT_GE((uint8_t *)p, mem.data());
        EXPECT_LE((uint8_t *)p + 4096, mem.data() + mem.size());
        got.push_back(p);
    }
    EXPECT_FALSE(got.empty());

    /* And the heap is reusable afterwards. */
    for (void *p : got) {
        a.free(p);
    }
    EXPECT_EQ(a.used(), 0u);
    EXPECT_NE(a.alloc(4096), nullptr);
}

TEST_F(ArenaTest, AllocLargerThanTheHeapFails) {
    EXPECT_EQ(a.alloc(HEAP * 2), nullptr);
}

TEST_F(ArenaTest, ZeroSizedAllocFails) {
    EXPECT_EQ(a.alloc(0), nullptr);
}

TEST_F(ArenaTest, DoubleFreeIsRefused) {
    void *p = a.alloc(256);

    ASSERT_NE(p, nullptr);
    a.free(p);
    size_t after = a.used();

    a.free(p); /* must not corrupt the free list or the counter */
    EXPECT_EQ(a.used(), after);
    EXPECT_NE(a.alloc(256), nullptr);
}

/* --- retirement ---------------------------------------------------------- */

TEST_F(ArenaTest, RetiredMemoryIsNotReusedBeforeItsGrace) {
    void *p = a.alloc(4096);

    ASSERT_NE(p, nullptr);
    a.retire(p, 1000);
    EXPECT_EQ(a.retired(), 1u);

    /* One nanosecond short of the grace period. */
    a.reclaim(1000 + bncl::daemon::RETIRE_GRACE_NS - 1);
    EXPECT_EQ(a.retired(), 1u);

    /* Still held, so a fresh allocation must land somewhere else --
     * which is the whole guarantee a client reading those bytes is
     * relying on. */
    void *q = a.alloc(4096);

    ASSERT_NE(q, nullptr);
    EXPECT_NE(p, q);
}

TEST_F(ArenaTest, RetiredMemoryComesBackAfterItsGrace) {
    void *p = a.alloc(4096);

    ASSERT_NE(p, nullptr);
    a.retire(p, 1000);

    a.reclaim(1000 + bncl::daemon::RETIRE_GRACE_NS);
    EXPECT_EQ(a.retired(), 0u);
    EXPECT_EQ(a.used(), 0u);
    EXPECT_EQ(a.alloc(4096), p);
}

TEST_F(ArenaTest, ReclaimLeavesTheNotYetDue) {
    void *p = a.alloc(1024);
    void *q = a.alloc(1024);

    ASSERT_NE(p, nullptr);
    ASSERT_NE(q, nullptr);
    a.retire(p, 1000);
    a.retire(q, 5000);

    /* Due for p, not for q. */
    a.reclaim(1000 + bncl::daemon::RETIRE_GRACE_NS);
    EXPECT_EQ(a.retired(), 1u);

    a.reclaim(5000 + bncl::daemon::RETIRE_GRACE_NS);
    EXPECT_EQ(a.retired(), 0u);
    EXPECT_EQ(a.used(), 0u);
}

TEST_F(ArenaTest, ReclaimOnAnEmptyRetireListIsHarmless) {
    a.reclaim(1);
    a.reclaim(bncl::daemon::RETIRE_GRACE_NS * 10);
    EXPECT_EQ(a.retired(), 0u);
    EXPECT_EQ(a.used(), 0u);
}
