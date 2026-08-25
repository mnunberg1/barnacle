// SPDX-License-Identifier: GPL-2.0
/*
 * Unit tests for the MySQL protocol layer.
 *
 * These run with no kernel, no root, no database and no container -- which is
 * the whole reason the protocol work was moved out of BPF C and into
 * userspace. The framing rules exercised here (continuation packets,
 * sequence renumbering, the overloaded 0xFE header) are precisely the ones
 * that were impossible to test in the previous architecture and that a
 * cached-response replay will get wrong if they are subtly off.
 *
 * Deliberately dependency-free: a tiny CHECK macro rather than a test
 * framework, matching this project's minimal-dependency build.
 */
#include "../src/common/mysql/protocol.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace mysql;

static int g_failures;
static int g_checks;

#define CHECK(cond)                                                                      \
	do {                                                                             \
		g_checks++;                                                              \
		if (!(cond)) {                                                           \
			g_failures++;                                                    \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
		}                                                                        \
	} while (0)

#define CHECK_EQ(a, b)                                                                   \
	do {                                                                             \
		g_checks++;                                                              \
		auto _a = (a);                                                           \
		auto _b = (b);                                                           \
		if (!(_a == _b)) {                                                       \
			g_failures++;                                                    \
			fprintf(stderr, "FAIL %s:%d: %s == %s\n", __FILE__, __LINE__,    \
				#a, #b);                                                 \
		}                                                                        \
	} while (0)

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

static void test_lenenc()
{
	/* 1-byte form */
	{
		const uint8_t d[] = { 0x05 };
		size_t pos = 0;
		uint64_t v = 0;

		CHECK(readLenEnc(d, sizeof(d), pos, v));
		CHECK_EQ(v, 5u);
		CHECK_EQ(pos, 1u);
	}
	/* 2-byte form (0xFC) */
	{
		const uint8_t d[] = { 0xFC, 0x34, 0x12 };
		size_t pos = 0;
		uint64_t v = 0;

		CHECK(readLenEnc(d, sizeof(d), pos, v));
		CHECK_EQ(v, 0x1234u);
		CHECK_EQ(pos, 3u);
	}
	/* 3-byte form (0xFD) */
	{
		const uint8_t d[] = { 0xFD, 0x56, 0x34, 0x12 };
		size_t pos = 0;
		uint64_t v = 0;

		CHECK(readLenEnc(d, sizeof(d), pos, v));
		CHECK_EQ(v, 0x123456u);
		CHECK_EQ(pos, 4u);
	}
	/* Truncation must be rejected, not read past the end. */
	{
		const uint8_t d[] = { 0xFC, 0x34 };
		size_t pos = 0;
		uint64_t v = 0;

		CHECK(!readLenEnc(d, sizeof(d), pos, v));
	}
}

static void test_reader_basic()
{
	MessageReader r;
	Message m;
	auto p = pkt({ 0x03, 'S', 'E', 'L' }, 0);

	r.append(p.data(), p.size());
	CHECK(r.next(m));
	CHECK_EQ(m.payload.size(), 4u);
	CHECK_EQ(m.first_seq, 0);
	CHECK_EQ(m.payload[0], 0x03);
	CHECK(!r.next(m)); /* nothing left */
}

/* A packet split across several append() calls must not be emitted early --
 * this is the case that occurs constantly in reality, because neither recv()
 * nor SSL_read respects message boundaries. */
static void test_reader_split()
{
	MessageReader r;
	Message m;
	auto p = pkt({ 0x03, 'a', 'b', 'c', 'd' }, 7);

	for (size_t i = 0; i < p.size(); i++) {
		bool last = (i + 1 == p.size());

		r.append(p.data() + i, 1);
		CHECK_EQ(r.next(m), last);
	}
	CHECK_EQ(m.payload.size(), 5u);
	CHECK_EQ(m.first_seq, 7);
}

/* Several packets delivered in one append() must all be recoverable. */
static void test_reader_multiple()
{
	MessageReader r;
	Message m;
	auto a = pkt({ 1 }, 0);
	auto b = pkt({ 2, 2 }, 1);
	std::vector<uint8_t> both = a;

	both.insert(both.end(), b.begin(), b.end());
	r.append(both.data(), both.size());

	CHECK(r.next(m));
	CHECK_EQ(m.payload.size(), 1u);
	CHECK(r.next(m));
	CHECK_EQ(m.payload.size(), 2u);
	CHECK_EQ(m.first_seq, 1);
	CHECK(!r.next(m));
}

/* The >=16 MiB continuation rule: a full-size packet means "more follows".
 * The old BPF implementation never handled this at all. */
static void test_reader_continuation()
{
	MessageReader r;
	Message m;
	std::vector<uint8_t> big(kMaxPayload, 'x');
	auto p1 = pkt(big, 0);
	auto p2 = pkt({ 'e', 'n', 'd' }, 1);

	r.append(p1.data(), p1.size());
	CHECK(!r.next(m)); /* full-size packet: message is not complete yet */
	r.append(p2.data(), p2.size());
	CHECK(r.next(m));
	CHECK_EQ(m.payload.size(), (size_t)kMaxPayload + 3);
	CHECK_EQ(m.first_seq, 0);
	CHECK_EQ(m.last_seq, 1);
}

/* A message that is an exact multiple of kMaxPayload is terminated by a
 * zero-length packet. Getting this wrong hangs the parser forever. */
static void test_reader_exact_multiple()
{
	MessageReader r;
	Message m;
	std::vector<uint8_t> big(kMaxPayload, 'y');
	auto p1 = pkt(big, 0);
	auto p2 = pkt({}, 1);

	r.append(p1.data(), p1.size());
	CHECK(!r.next(m));
	r.append(p2.data(), p2.size());
	CHECK(r.next(m));
	CHECK_EQ(m.payload.size(), (size_t)kMaxPayload);
}

static void test_encode_roundtrip()
{
	std::vector<uint8_t> payload(70000, 'z');
	auto wire = encodeMessage(payload.data(), payload.size(), 3);
	MessageReader r;
	Message m;

	r.append(wire.data(), wire.size());
	CHECK(r.next(m));
	CHECK_EQ(m.payload.size(), payload.size());
	CHECK_EQ(m.first_seq, 3);
	CHECK(memcmp(m.payload.data(), payload.data(), payload.size()) == 0);
}

/* Renumbering is what makes a cached response replayable onto a connection
 * whose sequence counter sits somewhere else. */
static void test_renumber()
{
	auto a = pkt({ 1 }, 0);
	auto b = pkt({ 2 }, 1);
	auto c = pkt({ 3 }, 2);
	std::vector<uint8_t> stream = a;

	stream.insert(stream.end(), b.begin(), b.end());
	stream.insert(stream.end(), c.begin(), c.end());

	CHECK(renumber(stream, 5));
	CHECK_EQ(stream[3], 5);
	CHECK_EQ(stream[3 + 5], 6);
	CHECK_EQ(stream[3 + 10], 7);

	/* Wraparound at 256 must not corrupt the stream. */
	CHECK(renumber(stream, 254));
	CHECK_EQ(stream[3], 254);
	CHECK_EQ(stream[3 + 5], 255);
	CHECK_EQ(stream[3 + 10], 0);

	/* A truncated stream must be rejected rather than half-rewritten. */
	std::vector<uint8_t> bad = { 0x10, 0x00, 0x00, 0x00, 0x01 };

	CHECK(!renumber(bad, 0));
}

static void test_extract_query()
{
	const char *sql = "SELECT 1";

	/* Plain COM_QUERY. */
	{
		std::vector<uint8_t> p = { COM_QUERY };

		p.insert(p.end(), sql, sql + strlen(sql));
		std::string_view out;

		CHECK(extractQuery(p.data(), p.size(), 0, out));
		CHECK_EQ(out, std::string_view(sql));
	}

	/* With CLIENT_QUERY_ATTRIBUTES the two length-encoded counts sit
	 * between the command byte and the text. Knowing the capability makes
	 * this exact -- the previous architecture had to guess from content. */
	{
		std::vector<uint8_t> p = { COM_QUERY, 0x00, 0x01 };

		p.insert(p.end(), sql, sql + strlen(sql));
		std::string_view out;

		CHECK(extractQuery(p.data(), p.size(), CLIENT_QUERY_ATTRIBUTES, out));
		CHECK_EQ(out, std::string_view(sql));

		/* Parsing the same bytes without the flag must yield the
		 * attribute bytes as part of the statement -- i.e. the flag
		 * genuinely changes the answer, which is why guessing was
		 * unsafe. */
		std::string_view naive;

		CHECK(extractQuery(p.data(), p.size(), 0, naive));
		CHECK(naive != std::string_view(sql));
	}

	/* Bound parameters are out of scope; bail rather than misparse. */
	{
		std::vector<uint8_t> p = { COM_QUERY, 0x01, 0x01, 0x00 };
		std::string_view out;

		CHECK(!extractQuery(p.data(), p.size(), CLIENT_QUERY_ATTRIBUTES, out));
	}

	/* Non-COM_QUERY commands are rejected. */
	{
		std::vector<uint8_t> p = { COM_STMT_PREPARE, 'x' };
		std::string_view out;

		CHECK(!extractQuery(p.data(), p.size(), 0, out));
	}
}

/* 0xFE is overloaded, and the disambiguation depends on both length and the
 * negotiated CLIENT_DEPRECATE_EOF. Getting this wrong corrupts result-set
 * parsing in ways that only show up on some servers. */
static void test_classify()
{
	{
		const uint8_t d[] = { 0xFF, 0x00, 0x04 };

		CHECK(classifyResponse(d, sizeof(d), 0) == ResponseKind::Err);
	}
	{
		const uint8_t d[] = { 0x00, 0x00, 0x00 };

		CHECK(classifyResponse(d, sizeof(d), 0) == ResponseKind::Ok);
	}
	{
		/* Short 0xFE without DEPRECATE_EOF is a genuine EOF marker. */
		const uint8_t d[] = { 0xFE, 0x00, 0x00 };

		CHECK(classifyResponse(d, sizeof(d), 0) == ResponseKind::Eof);
		/* With DEPRECATE_EOF the same bytes are an OK packet. */
		CHECK(classifyResponse(d, sizeof(d), CLIENT_DEPRECATE_EOF) ==
		      ResponseKind::Ok);
	}
	{
		/* A column count of 1 introduces a result set. */
		const uint8_t d[] = { 0x01 };

		CHECK(classifyResponse(d, sizeof(d), 0) == ResponseKind::ResultSet);
	}
}

/* SERVER_STATUS_IN_TRANS is the flag that gates caching entirely. */
static void test_parse_ok_transaction_flag()
{
	/* OK, affected_rows=0, last_insert_id=0, status=IN_TRANS, warnings=0 */
	const uint8_t in_trans[] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
	OkPacket ok;

	CHECK(parseOk(in_trans, sizeof(in_trans), CLIENT_PROTOCOL_41, ok));
	CHECK((ok.status_flags & SERVER_STATUS_IN_TRANS) != 0);

	const uint8_t autocommit[] = { 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };

	CHECK(parseOk(autocommit, sizeof(autocommit), CLIENT_PROTOCOL_41, ok));
	CHECK((ok.status_flags & SERVER_STATUS_IN_TRANS) == 0);
	CHECK((ok.status_flags & SERVER_STATUS_AUTOCOMMIT) != 0);
}

/* An SSLRequest is a HandshakeResponse41 truncated before the username. That
 * length distinction is the reliable TLS-upgrade signal -- far better than
 * inferring encryption from whether later bytes parse as MySQL, since the
 * server greeting is plaintext on every connection including TLS ones. */
static void test_client_handshake_ssl_request()
{
	std::vector<uint8_t> p(32, 0);
	uint32_t caps = CLIENT_PROTOCOL_41 | CLIENT_SSL;

	p[0] = (uint8_t)(caps & 0xFF);
	p[1] = (uint8_t)((caps >> 8) & 0xFF);
	p[2] = (uint8_t)((caps >> 16) & 0xFF);
	p[3] = (uint8_t)((caps >> 24) & 0xFF);

	ClientHandshake ch;

	CHECK(parseClientHandshake(p.data(), p.size(), ch));
	CHECK(ch.ssl_request);
	CHECK((ch.capabilities & CLIENT_SSL) != 0);

	/* Same prefix plus a username is a full response, not an upgrade. */
	const char *user = "app";

	p.insert(p.end(), user, user + strlen(user) + 1);
	p.push_back(0); /* empty auth response */

	ClientHandshake full;

	CHECK(parseClientHandshake(p.data(), p.size(), full));
	CHECK(!full.ssl_request);
	CHECK_EQ(full.username, std::string("app"));
}

int main()
{
	test_lenenc();
	test_reader_basic();
	test_reader_split();
	test_reader_multiple();
	test_reader_continuation();
	test_reader_exact_multiple();
	test_encode_roundtrip();
	test_renumber();
	test_extract_query();
	test_classify();
	test_parse_ok_transaction_flag();
	test_client_handshake_ssl_request();

	printf("%d checks, %d failures\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
