// SPDX-License-Identifier: GPL-2.0
/*
 * Unit tests for result-set parsing and regeneration.
 *
 * The point of holding a response as DATA rather than as bytes is that the
 * cached answer stops depending on the connection it was captured from. These
 * tests are mostly about that independence: same rows, different negotiated
 * capabilities, different sequence numbering, still correct.
 *
 * The central fixture is not invented. It is 374 bytes captured off the wire
 * from a real MySQL 8.4 server answering the demo query, so a round-trip
 * proving byte equality is proving it against the real framing rather than
 * against this code's own idea of it.
 *
 * No kernel, no root, no database.
 */
#include "common/mysql/resultset.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

namespace {

/* A real response: SELECT sku, name, price FROM products WHERE
 * category = 'tools' AND SLEEP(1.5) = 0 -- 3 columns, 6 rows, captured from a
 * connection that did NOT negotiate CLIENT_DEPRECATE_EOF. */
const uint8_t CAPTURED[] = {
    0x01, 0x00, 0x00, 0x01, 0x03, 0x30, 0x00, 0x00, 0x02, 0x03, 0x64, 0x65, 0x66, 0x04, 0x73, 0x68,
    0x6f, 0x70, 0x08, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x73, 0x08, 0x70, 0x72, 0x6f, 0x64,
    0x75, 0x63, 0x74, 0x73, 0x03, 0x73, 0x6b, 0x75, 0x03, 0x73, 0x6b, 0x75, 0x0c, 0x2d, 0x00, 0x80,
    0x00, 0x00, 0x00, 0xfd, 0x03, 0x50, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x03, 0x03, 0x64, 0x65,
    0x66, 0x04, 0x73, 0x68, 0x6f, 0x70, 0x08, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x73, 0x08,
    0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x73, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x04, 0x6e, 0x61,
    0x6d, 0x65, 0x0c, 0x2d, 0x00, 0x00, 0x02, 0x00, 0x00, 0xfd, 0x01, 0x10, 0x00, 0x00, 0x00, 0x34,
    0x00, 0x00, 0x04, 0x03, 0x64, 0x65, 0x66, 0x04, 0x73, 0x68, 0x6f, 0x70, 0x08, 0x70, 0x72, 0x6f,
    0x64, 0x75, 0x63, 0x74, 0x73, 0x08, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x73, 0x05, 0x70,
    0x72, 0x69, 0x63, 0x65, 0x05, 0x70, 0x72, 0x69, 0x63, 0x65, 0x0c, 0x3f, 0x00, 0x0c, 0x00, 0x00,
    0x00, 0xf6, 0x01, 0x10, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x05, 0xfe, 0x00, 0x00, 0x22, 0x00,
    0x1a, 0x00, 0x00, 0x06, 0x07, 0x53, 0x4b, 0x55, 0x2d, 0x30, 0x30, 0x31, 0x0b, 0x43, 0x6c, 0x61,
    0x77, 0x20, 0x48, 0x61, 0x6d, 0x6d, 0x65, 0x72, 0x05, 0x31, 0x38, 0x2e, 0x35, 0x30, 0x1f, 0x00,
    0x00, 0x07, 0x07, 0x53, 0x4b, 0x55, 0x2d, 0x30, 0x30, 0x32, 0x10, 0x42, 0x61, 0x6c, 0x6c, 0x20,
    0x50, 0x65, 0x65, 0x6e, 0x20, 0x48, 0x61, 0x6d, 0x6d, 0x65, 0x72, 0x05, 0x32, 0x32, 0x2e, 0x30,
    0x30, 0x1e, 0x00, 0x00, 0x08, 0x07, 0x53, 0x4b, 0x55, 0x2d, 0x30, 0x30, 0x33, 0x0e, 0x43, 0x6f,
    0x72, 0x64, 0x6c, 0x65, 0x73, 0x73, 0x20, 0x44, 0x72, 0x69, 0x6c, 0x6c, 0x06, 0x31, 0x32, 0x39,
    0x2e, 0x39, 0x39, 0x19, 0x00, 0x00, 0x09, 0x07, 0x53, 0x4b, 0x55, 0x2d, 0x30, 0x30, 0x34, 0x0a,
    0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x20, 0x53, 0x65, 0x74, 0x05, 0x36, 0x34, 0x2e, 0x32, 0x35,
    0x1b, 0x00, 0x00, 0x0a, 0x07, 0x53, 0x4b, 0x55, 0x2d, 0x30, 0x30, 0x37, 0x0c, 0x54, 0x61, 0x70,
    0x65, 0x20, 0x4d, 0x65, 0x61, 0x73, 0x75, 0x72, 0x65, 0x05, 0x31, 0x31, 0x2e, 0x30, 0x30, 0x1a,
    0x00, 0x00, 0x0b, 0x07, 0x53, 0x4b, 0x55, 0x2d, 0x30, 0x30, 0x38, 0x0b, 0x4c, 0x61, 0x73, 0x65,
    0x72, 0x20, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x05, 0x38, 0x39, 0x2e, 0x30, 0x30, 0x05, 0x00, 0x00,
    0x0c, 0xfe, 0x00, 0x00, 0x22, 0x00};

/* What that connection had negotiated. */
const uint32_t CAPS_NO_DEPRECATE =
    bncl::mysql_proto::CLIENT_PROTOCOL_41 | bncl::mysql_proto::CLIENT_TRANSACTIONS;
const uint32_t CAPS_DEPRECATE = CAPS_NO_DEPRECATE | bncl::mysql_proto::CLIENT_DEPRECATE_EOF;

bncl::mysql_proto::ResultSet parseCaptured()
{
    bncl::mysql_proto::ResultSet rs;

    EXPECT_TRUE(
        bncl::mysql_proto::parseResultSet(CAPTURED, sizeof(CAPTURED), CAPS_NO_DEPRECATE, rs));
    return rs;
}

/* Count wire packets in a stream, so framing can be checked without caring
 * what is in them. */
size_t countPackets(const std::vector<uint8_t> &v)
{
    bncl::mysql_proto::MessageReader rd;
    bncl::mysql_proto::Message m;
    size_t n = 0;

    rd.append(v.data(), v.size());
    while (rd.next(m)) {
        n++;
    }
    return n;
}

} // namespace

TEST(ResultSet, ParsesACapturedResponse)
{
    bncl::mysql_proto::ResultSet rs = parseCaptured();

    ASSERT_EQ(rs.cols.size(), 3u);
    EXPECT_EQ(rs.cols[0].name, "sku");
    EXPECT_EQ(rs.cols[1].name, "name");
    EXPECT_EQ(rs.cols[2].name, "price");
    /* Metadata the cache never reads but a client might. */
    EXPECT_EQ(rs.cols[0].catalog, "def");
    EXPECT_EQ(rs.cols[0].schema, "shop");
    EXPECT_EQ(rs.cols[0].table, "products");

    ASSERT_EQ(rs.rows.size(), 6u);
    ASSERT_EQ(rs.rows[0].size(), 3u);
    EXPECT_EQ(*rs.rows[0][0], "SKU-001");
    EXPECT_EQ(*rs.rows[5][0], "SKU-008");
}

TEST(ResultSet, ReEncodeIsByteIdenticalToTheCapture)
{
    /* The strongest check available: same capabilities, same starting
     * sequence, so regeneration must reproduce the server's own bytes. Any
     * disagreement about length-encoding widths, filler bytes or the shape
     * of the terminator shows up here. */
    bncl::mysql_proto::ResultSet rs = parseCaptured();
    std::vector<uint8_t> again =
        bncl::mysql_proto::encodeResultSet(rs, CAPS_NO_DEPRECATE, CAPTURED[3]);

    ASSERT_EQ(again.size(), sizeof(CAPTURED));
    EXPECT_EQ(memcmp(again.data(), CAPTURED, sizeof(CAPTURED)), 0);
}

TEST(ResultSet, DeprecateEofChangesThePacketCount)
{
    /* The reason bytes cannot simply be replayed. Same rows, one fewer
     * packet, because no EOF separates the definitions from the rows. */
    bncl::mysql_proto::ResultSet rs = parseCaptured();

    size_t without = countPackets(bncl::mysql_proto::encodeResultSet(rs, CAPS_NO_DEPRECATE, 1));
    size_t with = countPackets(bncl::mysql_proto::encodeResultSet(rs, CAPS_DEPRECATE, 1));

    /* 1 header + 3 defs + 1 EOF + 6 rows + 1 terminator = 12 */
    EXPECT_EQ(without, 12u);
    EXPECT_EQ(with, without - 1);
}

TEST(ResultSet, ReEncodedForADifferentConnectionStillParses)
{
    /* A response captured without DEPRECATE_EOF, served to a client that
     * negotiated it. Replaying the captured bytes would leave that client
     * a packet out of step; regenerating does not. */
    bncl::mysql_proto::ResultSet rs = parseCaptured();
    std::vector<uint8_t> other = bncl::mysql_proto::encodeResultSet(rs, CAPS_DEPRECATE, 1);
    bncl::mysql_proto::ResultSet back;

    ASSERT_TRUE(
        bncl::mysql_proto::parseResultSet(other.data(), other.size(), CAPS_DEPRECATE, back));
    ASSERT_EQ(back.cols.size(), rs.cols.size());
    ASSERT_EQ(back.rows.size(), rs.rows.size());
    for (size_t i = 0; i < rs.rows.size(); i++) {
        EXPECT_EQ(back.rows[i], rs.rows[i]);
    }
}

TEST(ResultSet, SequenceNumberingFollowsTheTargetConnection)
{
    /* Sequence ids restart per command, so a cached response has to be
     * numbered for whoever is replaying it, not for whoever produced it. */
    bncl::mysql_proto::ResultSet rs = parseCaptured();

    for (uint8_t start : {(uint8_t)1, (uint8_t)7}) {
        std::vector<uint8_t> v = bncl::mysql_proto::encodeResultSet(rs, CAPS_NO_DEPRECATE, start);
        EXPECT_EQ(v[3], start);
        /* And each subsequent packet increments. */
        bncl::mysql_proto::MessageReader rd;
        bncl::mysql_proto::Message m;
        uint8_t want = start;

        rd.append(v.data(), v.size());
        while (rd.next(m)) {
            EXPECT_EQ(m.first_seq, want);
            want++;
        }
    }
}

TEST(ResultSet, SequenceIdWrapsAtByteBoundary)
{
    bncl::mysql_proto::ResultSet rs = parseCaptured();
    std::vector<uint8_t> v = bncl::mysql_proto::encodeResultSet(rs, CAPS_NO_DEPRECATE, 250);
    bncl::mysql_proto::MessageReader rd;
    bncl::mysql_proto::Message m;
    uint8_t want = 250;

    /* 12 packets from 250 runs past 255; the id is one byte and wraps. */
    rd.append(v.data(), v.size());
    while (rd.next(m)) {
        EXPECT_EQ(m.first_seq, want);
        want++;
    }
}

TEST(ResultSet, NullIsDistinctFromEmptyString)
{
    /* On the wire NULL is 0xFB and an empty string is a zero-length
     * length-encoded string. Conflating them would turn one into the other
     * on every cache hit. */
    bncl::mysql_proto::ResultSet rs;
    bncl::mysql_proto::Column c;

    c.catalog = "def";
    c.name = "v";
    rs.cols.push_back(c);
    rs.rows.push_back({std::nullopt});
    rs.rows.push_back({std::string("")});

    std::vector<uint8_t> v = bncl::mysql_proto::encodeResultSet(rs, CAPS_DEPRECATE, 1);
    bncl::mysql_proto::ResultSet back;

    ASSERT_TRUE(bncl::mysql_proto::parseResultSet(v.data(), v.size(), CAPS_DEPRECATE, back));
    ASSERT_EQ(back.rows.size(), 2u);
    EXPECT_FALSE(back.rows[0][0].has_value());
    ASSERT_TRUE(back.rows[1][0].has_value());
    EXPECT_EQ(*back.rows[1][0], "");
}

TEST(ResultSet, TransactionStatusSurvivesTheRoundTrip)
{
    /* The flag that decides whether caching was permitted in the first
     * place has to come back out intact. */
    bncl::mysql_proto::ResultSet rs = parseCaptured();

    rs.status = bncl::mysql_proto::SERVER_STATUS_IN_TRANS;

    std::vector<uint8_t> v = bncl::mysql_proto::encodeResultSet(rs, CAPS_DEPRECATE, 1);
    bncl::mysql_proto::ResultSet back;

    ASSERT_TRUE(bncl::mysql_proto::parseResultSet(v.data(), v.size(), CAPS_DEPRECATE, back));
    EXPECT_EQ(back.status & bncl::mysql_proto::SERVER_STATUS_IN_TRANS,
              bncl::mysql_proto::SERVER_STATUS_IN_TRANS);
}

TEST(ResultSet, EmptyResultSetHasNoRows)
{
    bncl::mysql_proto::ResultSet rs = parseCaptured();

    rs.rows.clear();

    std::vector<uint8_t> v = bncl::mysql_proto::encodeResultSet(rs, CAPS_DEPRECATE, 1);
    bncl::mysql_proto::ResultSet back;

    ASSERT_TRUE(bncl::mysql_proto::parseResultSet(v.data(), v.size(), CAPS_DEPRECATE, back));
    EXPECT_EQ(back.cols.size(), 3u);
    EXPECT_TRUE(back.rows.empty());
}

TEST(ResultSet, LongValueUsesAWiderLengthPrefix)
{
    /* Past 250 bytes a value's length no longer fits the one-byte form, so
     * the encoder has to widen and the parser has to follow it. */
    bncl::mysql_proto::ResultSet rs;
    bncl::mysql_proto::Column c;
    std::string big(70000, 'x');

    c.catalog = "def";
    c.name = "v";
    rs.cols.push_back(c);
    rs.rows.push_back({big});

    std::vector<uint8_t> v = bncl::mysql_proto::encodeResultSet(rs, CAPS_DEPRECATE, 1);
    bncl::mysql_proto::ResultSet back;

    ASSERT_TRUE(bncl::mysql_proto::parseResultSet(v.data(), v.size(), CAPS_DEPRECATE, back));
    ASSERT_EQ(back.rows.size(), 1u);
    EXPECT_EQ(*back.rows[0][0], big);
}

TEST(ResultSet, RejectsWhatIsNotAResultSet)
{
    bncl::mysql_proto::ResultSet rs;

    /* An OK packet. */
    const uint8_t ok[] = {0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
    EXPECT_FALSE(bncl::mysql_proto::parseResultSet(ok, sizeof(ok), CAPS_DEPRECATE, rs));

    /* An error. */
    const uint8_t err[] = {0x05, 0x00, 0x00, 0x01, 0xFF, 0x48, 0x04, 0x23, 0x48};
    EXPECT_FALSE(bncl::mysql_proto::parseResultSet(err, sizeof(err), CAPS_DEPRECATE, rs));

    /* A capture that stops before the terminator must not look complete. */
    EXPECT_FALSE(bncl::mysql_proto::parseResultSet(CAPTURED, 40, CAPS_NO_DEPRECATE, rs));
}
