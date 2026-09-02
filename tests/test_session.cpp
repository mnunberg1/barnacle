// SPDX-License-Identifier: GPL-2.0
/*
 * Unit tests for response tracking and the cache-safety decisions.
 *
 * This is where the transaction caveat lives. A response is only safe to
 * cache if the server was not mid-transaction when it produced it, and the
 * only way to know that is to walk the response to its terminating packet and
 * read the status flags. Everything here exists to make that walk correct on
 * the shapes a real server produces.
 *
 * The awkward cases are deliberate rather than exhaustive:
 *
 *   - mysql::CLIENT_DEPRECATE_EOF changes the packet count of an otherwise identical
 *     result set, so the same bytes mean different things depending on what
 *     the two sides negotiated.
 *   - 0xFE is overloaded. Short, it terminates; long, it is an ordinary row
 *     whose first column happens to start with that byte.
 *
 * No kernel, no root, no database.
 */
#include "common/session.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace {

mysql::Message msg(const std::vector<uint8_t> &payload, uint8_t seq = 1)
{
    mysql::Message m;

    m.payload = payload;
    m.first_seq = seq;
    m.last_seq = seq;
    m.wire_size = payload.size() + mysql::kHeaderLen;
    return m;
}

/* What a real connection negotiates. Status flags are only present on the
 * wire when these are set, so tests that care about transactions have to use
 * them -- with caps of 0 the flags are simply not there to read. */
const uint32_t kCaps = mysql::CLIENT_PROTOCOL_41 | mysql::CLIENT_TRANSACTIONS;

/* OK: 0x00, affected_rows (lenenc), last_insert_id (lenenc), status, warnings. */
std::vector<uint8_t> okPacket(uint16_t status)
{
    return {0x00, 0x00, 0x00, (uint8_t)(status & 0xFF), (uint8_t)(status >> 8), 0x00, 0x00};
}

/* EOF, pre-DEPRECATE_EOF form: 0xFE, warnings, status. Exactly five bytes --
 * a different shape from OK, not merely a shorter one. */
std::vector<uint8_t> eofPacket(uint16_t status)
{
    return {0xFE, 0x00, 0x00, (uint8_t)(status & 0xFF), (uint8_t)(status >> 8)};
}

/* The DEPRECATE_EOF-era terminator: an OK packet wearing an 0xFE header. */
std::vector<uint8_t> okEofPacket(uint16_t status)
{
    return {0xFE, 0x00, 0x00, (uint8_t)(status & 0xFF), (uint8_t)(status >> 8), 0x00, 0x00};
}

std::vector<uint8_t> errPacket()
{
    return {0xFF, 0x48, 0x04, '#', 'H', 'Y', '0', '0', '0', 'b', 'o', 'o', 'm'};
}

/* A column-count header, then one column definition per column. Contents do
 * not matter to the tracker -- only that a packet arrived. */
std::vector<uint8_t> columnCount(uint8_t n)
{
    return {n};
}

std::vector<uint8_t> columnDef()
{
    return {0x03, 'd', 'e', 'f', 0x00};
}

std::vector<uint8_t> row()
{
    return {0x01, 'x'};
}

/* Drive a whole result set through the tracker and return it for inspection.
 * `caps` decides whether an EOF separates the definitions from the rows. */
bncl::ResponseTracker runResultSet(uint32_t caps, uint16_t final_status, int ncols, int nrows)
{
    bncl::ResponseTracker t;

    t.begin(caps);
    EXPECT_FALSE(t.feed(msg(columnCount((uint8_t)ncols))));
    for (int i = 0; i < ncols; i++) {
        EXPECT_FALSE(t.feed(msg(columnDef())));
    }
    if (!(caps & mysql::CLIENT_DEPRECATE_EOF)) {
        EXPECT_FALSE(t.feed(msg(eofPacket(0))));
    }
    for (int i = 0; i < nrows; i++) {
        EXPECT_FALSE(t.feed(msg(row())));
    }
    EXPECT_TRUE(t.feed(msg((caps & mysql::CLIENT_DEPRECATE_EOF) ? okEofPacket(final_status)
                                                                : eofPacket(final_status))));
    return t;
}

} // namespace

TEST(Session, SingleOkCompletesAndIsCacheable)
{
    bncl::ResponseTracker t;

    t.begin(0);
    EXPECT_TRUE(t.feed(msg(okPacket(0))));
    EXPECT_TRUE(t.complete());
    EXPECT_FALSE(t.poisoned());
    EXPECT_FALSE(t.inTransaction());
}

TEST(Session, ErrorIsPoisoned)
{
    bncl::ResponseTracker t;

    t.begin(0);
    EXPECT_TRUE(t.feed(msg(errPacket())));
    EXPECT_TRUE(t.complete());
    /* Errors are cheap to reproduce and may be session-specific. */
    EXPECT_TRUE(t.poisoned());
}

TEST(Session, LocalInfileIsPoisoned)
{
    bncl::ResponseTracker t;

    t.begin(0);
    /* 0xFB introduces a LOCAL INFILE request -- the server asking the
     * client for a file. Out of scope, and never cacheable. */
    EXPECT_TRUE(t.feed(msg({0xFB, '/', 't', 'm', 'p', '/', 'f'})));
    EXPECT_TRUE(t.complete());
    EXPECT_TRUE(t.poisoned());
}

TEST(Session, OpenTransactionIsDetected)
{
    bncl::ResponseTracker t;

    t.begin(kCaps);
    EXPECT_TRUE(t.feed(msg(okPacket(mysql::SERVER_STATUS_IN_TRANS))));
    EXPECT_TRUE(t.inTransaction());
    /* Not poisoned as such -- the response is well formed. It is the
     * transaction that makes it unsafe to cache, which is the caller's
     * decision to make. */
    EXPECT_FALSE(t.poisoned());
}

TEST(Session, MoreResultsExistsIsPoisoned)
{
    bncl::ResponseTracker t;

    t.begin(kCaps);
    /* Only the first set would be captured, so replay would be truncated. */
    EXPECT_TRUE(t.feed(msg(okPacket(mysql::SERVER_MORE_RESULTS_EXISTS))));
    EXPECT_TRUE(t.poisoned());
}

TEST(Session, ResultSetWithEofSeparator)
{
    /* No DEPRECATE_EOF: an EOF packet sits between the column definitions
     * and the rows, so the tracker must expect one more packet. */
    bncl::ResponseTracker t = runResultSet(kCaps, 0, 2, 3);

    EXPECT_TRUE(t.complete());
    EXPECT_FALSE(t.poisoned());
    EXPECT_FALSE(t.inTransaction());
}

TEST(Session, ResultSetWithDeprecateEof)
{
    /* Same logical response, one fewer packet. Getting this branch wrong
     * silently mis-counts every result set on a modern connection. */
    bncl::ResponseTracker t = runResultSet(kCaps | mysql::CLIENT_DEPRECATE_EOF, 0, 2, 3);

    EXPECT_TRUE(t.complete());
    EXPECT_FALSE(t.poisoned());
}

TEST(Session, ResultSetInTransaction)
{
    bncl::ResponseTracker t =
        runResultSet(kCaps | mysql::CLIENT_DEPRECATE_EOF, mysql::SERVER_STATUS_IN_TRANS, 1, 1);

    EXPECT_TRUE(t.complete());
    EXPECT_TRUE(t.inTransaction());
}

TEST(Session, LongFeLedPacketIsARowNotATerminator)
{
    /* The overloaded-0xFE trap: a row whose first column value begins with
     * 0xFE. Short means terminator, long means data. Treating this as the
     * end would truncate the cached response. */
    bncl::ResponseTracker t;
    std::vector<uint8_t> fat_row(32, 0xAA);

    fat_row[0] = 0xFE;

    t.begin(kCaps | mysql::CLIENT_DEPRECATE_EOF);
    EXPECT_FALSE(t.feed(msg(columnCount(1))));
    EXPECT_FALSE(t.feed(msg(columnDef())));
    EXPECT_FALSE(t.feed(msg(fat_row)));
    EXPECT_FALSE(t.complete());

    EXPECT_TRUE(t.feed(msg(okEofPacket(0))));
    EXPECT_TRUE(t.complete());
    EXPECT_FALSE(t.poisoned());
}

TEST(Session, ErrorMidResultSetIsPoisoned)
{
    bncl::ResponseTracker t;

    t.begin(kCaps | mysql::CLIENT_DEPRECATE_EOF);
    EXPECT_FALSE(t.feed(msg(columnCount(1))));
    EXPECT_FALSE(t.feed(msg(columnDef())));
    EXPECT_TRUE(t.feed(msg(errPacket())));
    EXPECT_TRUE(t.poisoned());
}

/*
 * Transaction state has to survive a result set on a connection that did NOT
 * mysql::negotiate mysql::CLIENT_DEPRECATE_EOF, where the terminator is a real five-byte
 * EOF rather than an OK packet in EOF clothing.
 *
 * This is the case that decides whether caching is safe on such a connection:
 * miss the flag and a response produced inside a transaction looks cacheable.
 */
TEST(Session, TransactionDetectedFromPlainEofTerminator)
{
    bncl::ResponseTracker t = runResultSet(kCaps, mysql::SERVER_STATUS_IN_TRANS, 1, 1);

    EXPECT_TRUE(t.complete());
    EXPECT_TRUE(t.inTransaction());
}

TEST(Session, FeedAfterDoneIsIdempotent)
{
    bncl::ResponseTracker t;

    t.begin(kCaps);
    EXPECT_TRUE(t.feed(msg(okPacket(0))));
    /* Trailing packets must not reopen a finished response. */
    EXPECT_TRUE(t.feed(msg(row())));
    EXPECT_TRUE(t.complete());
    EXPECT_FALSE(t.poisoned());
}

TEST(Session, BeginResetsPreviousState)
{
    bncl::ResponseTracker t;

    t.begin(0);
    EXPECT_TRUE(t.feed(msg(errPacket())));
    EXPECT_TRUE(t.poisoned());

    /* A connection is reused for statement after statement; stale poison
     * would suppress caching for the life of the connection. */
    t.begin(0);
    EXPECT_FALSE(t.poisoned());
    EXPECT_FALSE(t.complete());
    EXPECT_TRUE(t.feed(msg(okPacket(0))));
    EXPECT_FALSE(t.poisoned());
}

TEST(Connection, ResetClearsPerStatementState)
{
    bncl::Connection c;

    c.caps = mysql::CLIENT_DEPRECATE_EOF;
    c.awaiting_response = true;
    c.capturing = true;
    c.pending_query = "SELECT 1";
    c.captured = {1, 2, 3};

    c.reset();

    EXPECT_FALSE(c.awaiting_response);
    EXPECT_FALSE(c.capturing);
    EXPECT_TRUE(c.pending_query.empty());
    EXPECT_TRUE(c.captured.empty());
    /* Negotiated capabilities outlive a statement -- they belong to the
     * connection, and re-deriving them is impossible once TLS is up. */
    EXPECT_EQ(c.caps, (uint32_t)mysql::CLIENT_DEPRECATE_EOF);
}
