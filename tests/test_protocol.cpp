// SPDX-License-Identifier: GPL-2.0
/*
 * Unit tests for the MySQL protocol layer.
 *
 * These run with no kernel, no root, no database and no container -- which is
 * the whole reason the protocol work lives in userspace rather than in BPF C.
 * The framing rules exercised here (continuation packets, sequence
 * renumbering, the overloaded 0xFE header) are precisely the ones that were
 * impossible to test in the previous architecture, and that a cached-response
 * replay will get wrong if they are subtly off.
 */
#include "common/mysql/protocol.h"

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

/* Build a single wire packet. */
static std::vector<uint8_t> pkt(const std::vector<uint8_t> &payload, uint8_t seq)
{
    std::vector<uint8_t> v;
    uint32_t n = (uint32_t)payload.size();

    v.push_back((uint8_t)(n & 0xFF));
    v.push_back((uint8_t)((n >> 8) & 0xFF));
    v.push_back((uint8_t)((n >> 16) & 0xFF));
    v.push_back(seq);
    v.insert(v.end(), payload.begin(), payload.end());
    return v;
}

TEST(Protocol, LenEnc)
{
    /* 1-byte form */
    {
        const uint8_t d[] = {0x05};
        size_t pos = 0;
        uint64_t v = 0;

        EXPECT_TRUE(mysql::readLenEnc(d, sizeof(d), pos, v));
        EXPECT_EQ(v, 5u);
        EXPECT_EQ(pos, 1u);
    }
    /* 2-byte form (0xFC) */
    {
        const uint8_t d[] = {0xFC, 0x34, 0x12};
        size_t pos = 0;
        uint64_t v = 0;

        EXPECT_TRUE(mysql::readLenEnc(d, sizeof(d), pos, v));
        EXPECT_EQ(v, 0x1234u);
        EXPECT_EQ(pos, 3u);
    }
    /* 3-byte form (0xFD) */
    {
        const uint8_t d[] = {0xFD, 0x56, 0x34, 0x12};
        size_t pos = 0;
        uint64_t v = 0;

        EXPECT_TRUE(mysql::readLenEnc(d, sizeof(d), pos, v));
        EXPECT_EQ(v, 0x123456u);
        EXPECT_EQ(pos, 4u);
    }
    /* Truncation must be rejected, not read past the end. */
    {
        const uint8_t d[] = {0xFC, 0x34};
        size_t pos = 0;
        uint64_t v = 0;

        EXPECT_TRUE(!mysql::readLenEnc(d, sizeof(d), pos, v));
    }
}

TEST(Protocol, ReaderBasic)
{
    mysql::MessageReader r;
    mysql::Message m;
    auto p = pkt({0x03, 'S', 'E', 'L'}, 0);

    r.append(p.data(), p.size());
    EXPECT_TRUE(r.next(m));
    EXPECT_EQ(m.payload.size(), 4u);
    EXPECT_EQ(m.first_seq, 0);
    EXPECT_EQ(m.payload[0], 0x03);
    EXPECT_TRUE(!r.next(m)); /* nothing left */
}

/* A packet split across several append() calls must not be emitted early --
 * this is the case that occurs constantly in reality, because neither recv()
 * nor SSL_read respects message boundaries. */
TEST(Protocol, ReaderSplit)
{
    mysql::MessageReader r;
    mysql::Message m;
    auto p = pkt({0x03, 'a', 'b', 'c', 'd'}, 7);

    for (size_t i = 0; i < p.size(); i++) {
        bool last = (i + 1 == p.size());

        r.append(p.data() + i, 1);
        EXPECT_EQ(r.next(m), last);
    }
    EXPECT_EQ(m.payload.size(), 5u);
    EXPECT_EQ(m.first_seq, 7);
}

/* Several packets delivered in one append() must all be recoverable. */
TEST(Protocol, ReaderMultiple)
{
    mysql::MessageReader r;
    mysql::Message m;
    auto a = pkt({1}, 0);
    auto b = pkt({2, 2}, 1);
    std::vector<uint8_t> both = a;

    both.insert(both.end(), b.begin(), b.end());
    r.append(both.data(), both.size());

    EXPECT_TRUE(r.next(m));
    EXPECT_EQ(m.payload.size(), 1u);
    EXPECT_TRUE(r.next(m));
    EXPECT_EQ(m.payload.size(), 2u);
    EXPECT_EQ(m.first_seq, 1);
    EXPECT_TRUE(!r.next(m));
}

/* The >=16 MiB continuation rule: a full-size packet means "more follows".
 * The old BPF implementation never handled this at all. */
TEST(Protocol, ReaderContinuation)
{
    mysql::MessageReader r;
    mysql::Message m;
    std::vector<uint8_t> big(mysql::kMaxPayload, 'x');
    auto p1 = pkt(big, 0);
    auto p2 = pkt({'e', 'n', 'd'}, 1);

    r.append(p1.data(), p1.size());
    EXPECT_TRUE(!r.next(m)); /* full-size packet: message is not complete yet */
    r.append(p2.data(), p2.size());
    EXPECT_TRUE(r.next(m));
    EXPECT_EQ(m.payload.size(), (size_t)mysql::kMaxPayload + 3);
    EXPECT_EQ(m.first_seq, 0);
    EXPECT_EQ(m.last_seq, 1);
}

/* A message that is an exact multiple of mysql::kMaxPayload is terminated by a
 * zero-length packet. Getting this wrong hangs the parser forever. */
TEST(Protocol, ReaderExactMultiple)
{
    mysql::MessageReader r;
    mysql::Message m;
    std::vector<uint8_t> big(mysql::kMaxPayload, 'y');
    auto p1 = pkt(big, 0);
    auto p2 = pkt({}, 1);

    r.append(p1.data(), p1.size());
    EXPECT_TRUE(!r.next(m));
    r.append(p2.data(), p2.size());
    EXPECT_TRUE(r.next(m));
    EXPECT_EQ(m.payload.size(), (size_t)mysql::kMaxPayload);
}

TEST(Protocol, EncodeRoundtrip)
{
    std::vector<uint8_t> payload(70000, 'z');
    auto wire = mysql::encodeMessage(payload.data(), payload.size(), 3);
    mysql::MessageReader r;
    mysql::Message m;

    r.append(wire.data(), wire.size());
    EXPECT_TRUE(r.next(m));
    EXPECT_EQ(m.payload.size(), payload.size());
    EXPECT_EQ(m.first_seq, 3);
    EXPECT_TRUE(memcmp(m.payload.data(), payload.data(), payload.size()) == 0);
}

/* Renumbering is what makes a cached response replayable onto a connection
 * whose sequence counter sits somewhere else. */
TEST(Protocol, Renumber)
{
    auto a = pkt({1}, 0);
    auto b = pkt({2}, 1);
    auto c = pkt({3}, 2);
    std::vector<uint8_t> stream = a;

    stream.insert(stream.end(), b.begin(), b.end());
    stream.insert(stream.end(), c.begin(), c.end());

    EXPECT_TRUE(mysql::renumber(stream, 5));
    EXPECT_EQ(stream[3], 5);
    EXPECT_EQ(stream[3 + 5], 6);
    EXPECT_EQ(stream[3 + 10], 7);

    /* Wraparound at 256 must not corrupt the stream. */
    EXPECT_TRUE(mysql::renumber(stream, 254));
    EXPECT_EQ(stream[3], 254);
    EXPECT_EQ(stream[3 + 5], 255);
    EXPECT_EQ(stream[3 + 10], 0);

    /* A truncated stream must be rejected rather than half-rewritten. */
    std::vector<uint8_t> bad = {0x10, 0x00, 0x00, 0x00, 0x01};

    EXPECT_TRUE(!mysql::renumber(bad, 0));
}

TEST(Protocol, ExtractQuery)
{
    const char *sql = "SELECT 1";

    /* Plain mysql::COM_QUERY. */
    {
        std::vector<uint8_t> p = {mysql::COM_QUERY};

        p.insert(p.end(), sql, sql + strlen(sql));
        std::string_view out;

        EXPECT_TRUE(mysql::extractQuery(p.data(), p.size(), 0, out));
        EXPECT_EQ(out, std::string_view(sql));
    }

    /* With mysql::CLIENT_QUERY_ATTRIBUTES the two length-encoded counts sit
     * between the command byte and the text. Knowing the capability makes
     * this exact -- the previous architecture had to guess from content. */
    {
        std::vector<uint8_t> p = {mysql::COM_QUERY, 0x00, 0x01};

        p.insert(p.end(), sql, sql + strlen(sql));
        std::string_view out;

        EXPECT_TRUE(mysql::extractQuery(p.data(), p.size(), mysql::CLIENT_QUERY_ATTRIBUTES, out));
        EXPECT_EQ(out, std::string_view(sql));

        /* Parsing the same bytes without the flag must yield the
         * attribute bytes as part of the statement -- i.e. the flag
         * genuinely changes the answer, which is why guessing was
         * unsafe. */
        std::string_view naive;

        EXPECT_TRUE(mysql::extractQuery(p.data(), p.size(), 0, naive));
        EXPECT_TRUE(naive != std::string_view(sql));
    }

    /* Bound parameters are out of scope; bail rather than misparse. */
    {
        std::vector<uint8_t> p = {mysql::COM_QUERY, 0x01, 0x01, 0x00};
        std::string_view out;

        EXPECT_TRUE(!mysql::extractQuery(p.data(), p.size(), mysql::CLIENT_QUERY_ATTRIBUTES, out));
    }

    /* Non-mysql::COM_QUERY commands are rejected. */
    {
        std::vector<uint8_t> p = {mysql::COM_STMT_PREPARE, 'x'};
        std::string_view out;

        EXPECT_TRUE(!mysql::extractQuery(p.data(), p.size(), 0, out));
    }
}

/* 0xFE is overloaded, and the disambiguation depends on both length and the
 * negotiated mysql::CLIENT_DEPRECATE_EOF. Getting this wrong corrupts result-set
 * parsing in ways that only show up on some servers. */
TEST(Protocol, Classify)
{
    {
        const uint8_t d[] = {0xFF, 0x00, 0x04};

        EXPECT_TRUE(mysql::classifyResponse(d, sizeof(d), 0) == mysql::ResponseKind::Err);
    }
    {
        const uint8_t d[] = {0x00, 0x00, 0x00};

        EXPECT_TRUE(mysql::classifyResponse(d, sizeof(d), 0) == mysql::ResponseKind::Ok);
    }
    {
        /* Short 0xFE without DEPRECATE_EOF is a genuine EOF marker. */
        const uint8_t d[] = {0xFE, 0x00, 0x00};

        EXPECT_TRUE(mysql::classifyResponse(d, sizeof(d), 0) == mysql::ResponseKind::Eof);
        /* With DEPRECATE_EOF the same bytes are an OK packet. */
        EXPECT_TRUE(mysql::classifyResponse(d, sizeof(d), mysql::CLIENT_DEPRECATE_EOF) ==
                    mysql::ResponseKind::Ok);
    }
    {
        /* A column count of 1 introduces a result set. */
        const uint8_t d[] = {0x01};

        EXPECT_TRUE(mysql::classifyResponse(d, sizeof(d), 0) == mysql::ResponseKind::ResultSet);
    }
}

/* mysql::SERVER_STATUS_IN_TRANS is the flag that gates caching entirely. */
TEST(Protocol, ParseOkTransactionFlag)
{
    /* OK, affected_rows=0, last_insert_id=0, status=IN_TRANS, warnings=0 */
    const uint8_t in_trans[] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    mysql::OkPacket ok;

    EXPECT_TRUE(mysql::parseOk(in_trans, sizeof(in_trans), mysql::CLIENT_PROTOCOL_41, ok));
    EXPECT_TRUE((ok.status_flags & mysql::SERVER_STATUS_IN_TRANS) != 0);

    const uint8_t autocommit[] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};

    EXPECT_TRUE(mysql::parseOk(autocommit, sizeof(autocommit), mysql::CLIENT_PROTOCOL_41, ok));
    EXPECT_TRUE((ok.status_flags & mysql::SERVER_STATUS_IN_TRANS) == 0);
    EXPECT_TRUE((ok.status_flags & mysql::SERVER_STATUS_AUTOCOMMIT) != 0);
}

/* An SSLRequest is a HandshakeResponse41 truncated before the username. That
 * length distinction is the reliable TLS-upgrade signal -- far better than
 * inferring encryption from whether later bytes parse as MySQL, since the
 * server greeting is plaintext on every connection including TLS ones. */
TEST(Protocol, ClientHandshakeSSLRequest)
{
    std::vector<uint8_t> p(32, 0);
    uint32_t caps = mysql::CLIENT_PROTOCOL_41 | mysql::CLIENT_SSL;

    p[0] = (uint8_t)(caps & 0xFF);
    p[1] = (uint8_t)((caps >> 8) & 0xFF);
    p[2] = (uint8_t)((caps >> 16) & 0xFF);
    p[3] = (uint8_t)((caps >> 24) & 0xFF);

    mysql::ClientHandshake ch;

    EXPECT_TRUE(mysql::parseClientHandshake(p.data(), p.size(), ch));
    EXPECT_TRUE(ch.ssl_request);
    EXPECT_TRUE((ch.capabilities & mysql::CLIENT_SSL) != 0);

    /* Same prefix plus a username is a full response, not an upgrade. */
    const char *user = "app";

    p.insert(p.end(), user, user + strlen(user) + 1);
    p.push_back(0); /* empty auth response */

    mysql::ClientHandshake full;

    EXPECT_TRUE(mysql::parseClientHandshake(p.data(), p.size(), full));
    EXPECT_TRUE(!full.ssl_request);
    EXPECT_EQ(full.username, std::string("app"));
}
