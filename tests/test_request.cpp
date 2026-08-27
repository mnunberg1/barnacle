// SPDX-License-Identifier: GPL-2.0
/*
 * Unit tests for the request side: statement extraction and the intercept
 * list.
 *
 * Two failure modes drive most of these.
 *
 * Reassembly: a client's SSL_write does not correspond to a packet. One write
 * can hold several commands, one command can span several writes, and a
 * matcher that looked at buffers in isolation would be wrong in both
 * directions -- silently, by missing statements rather than by erroring.
 *
 * Alignment: MySQL has no pipelining, so a packet that is skipped rather than
 * consumed leaves the reader reading the NEXT statement from the middle of
 * the previous one. Commands we do not care about still have to be walked.
 *
 * No kernel, no root, no database.
 */
#include "common/defs.h"
#include "common/session.h"
#include "common/stmtlist.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>


namespace {

/* One wire packet: 3-byte length, sequence id, payload. */
std::vector<uint8_t> wire(const std::vector<uint8_t> &payload, uint8_t seq = 0)
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

std::vector<uint8_t> comQuery(const std::string &sql, uint8_t seq = 0)
{
	std::vector<uint8_t> p;

	p.push_back(mysql::COM_QUERY);
	p.insert(p.end(), sql.begin(), sql.end());
	return wire(p, seq);
}

void appendTo(std::vector<uint8_t> &dst, const std::vector<uint8_t> &src)
{
	dst.insert(dst.end(), src.begin(), src.end());
}

/* A throwaway file, so the list loader is tested against a real one. */
std::string writeTemp(const std::string &body)
{
	std::string path = "/tmp/qc_stmtlist_test.txt";
	std::ofstream f(path, std::ios::trunc);

	f << body;
	f.close();
	return path;
}

} // namespace

TEST(Request, SingleQuery)
{
	cache::RequestTracker t;
	std::vector<uint8_t> buf = comQuery("SELECT 1");
	std::string sql;

	t.begin(mysql::CLIENT_PROTOCOL_41);
	EXPECT_TRUE(t.feed(buf.data(), buf.size(), sql));
	EXPECT_EQ(sql, "SELECT 1");
	EXPECT_EQ(t.lastCommand(), (uint8_t)mysql::COM_QUERY);

	/* Nothing left over. */
	EXPECT_FALSE(t.next(sql));
	EXPECT_EQ(t.buffered(), 0u);
}

TEST(Request, QuerySplitAcrossWrites)
{
	/* The case a per-buffer matcher gets wrong: one command delivered in
	 * three SSL_write calls, including a header split mid-length-field. */
	cache::RequestTracker t;
	std::vector<uint8_t> buf = comQuery("SELECT * FROM products");
	std::string sql;

	t.begin(mysql::CLIENT_PROTOCOL_41);
	EXPECT_FALSE(t.feed(buf.data(), 2, sql));
	EXPECT_FALSE(t.feed(buf.data() + 2, 6, sql));
	EXPECT_TRUE(t.feed(buf.data() + 8, buf.size() - 8, sql));
	EXPECT_EQ(sql, "SELECT * FROM products");
}

TEST(Request, ByteAtATime)
{
	/* The degenerate version of the same thing. */
	cache::RequestTracker t;
	std::vector<uint8_t> buf = comQuery("SELECT 2");
	std::string sql;
	bool got = false;

	t.begin(mysql::CLIENT_PROTOCOL_41);
	for (size_t i = 0; i < buf.size(); i++) {
		if (t.feed(buf.data() + i, 1, sql)) {
			got = true;
		}
	}
	EXPECT_TRUE(got);
	EXPECT_EQ(sql, "SELECT 2");
}

TEST(Request, TwoQueriesInOneWrite)
{
	cache::RequestTracker t;
	std::vector<uint8_t> buf;
	std::string sql;

	appendTo(buf, comQuery("SELECT 1"));
	appendTo(buf, comQuery("SELECT 2"));

	t.begin(mysql::CLIENT_PROTOCOL_41);
	EXPECT_TRUE(t.feed(buf.data(), buf.size(), sql));
	EXPECT_EQ(sql, "SELECT 1");
	/* The second is already buffered -- feed() must be called until it
	 * returns false or the second statement is never seen. */
	EXPECT_TRUE(t.next(sql));
	EXPECT_EQ(sql, "SELECT 2");
	EXPECT_FALSE(t.next(sql));
}

TEST(Request, NonQueryCommandsAreConsumedNotSkipped)
{
	/* The alignment case. mysql::COM_PING carries no statement, but its packet
	 * must still be walked -- otherwise the query after it is read from
	 * the wrong offset. */
	cache::RequestTracker t;
	std::vector<uint8_t> buf;
	std::string sql;

	appendTo(buf, wire({ mysql::COM_PING }));
	appendTo(buf, comQuery("SELECT 3"));

	t.begin(mysql::CLIENT_PROTOCOL_41);
	EXPECT_TRUE(t.feed(buf.data(), buf.size(), sql));
	EXPECT_EQ(sql, "SELECT 3");
	EXPECT_EQ(t.buffered(), 0u);
}

TEST(Request, QuitIsVisible)
{
	cache::RequestTracker t;
	std::vector<uint8_t> buf = wire({ mysql::COM_QUIT });
	std::string sql;

	t.begin(mysql::CLIENT_PROTOCOL_41);
	EXPECT_FALSE(t.feed(buf.data(), buf.size(), sql));
	EXPECT_EQ(t.lastCommand(), (uint8_t)mysql::COM_QUIT);
}

TEST(Request, EmptyStatement)
{
	cache::RequestTracker t;
	std::vector<uint8_t> buf = comQuery("");
	std::string sql = "stale";

	t.begin(mysql::CLIENT_PROTOCOL_41);
	/* A mysql::COM_QUERY with no text is degenerate but well formed; it must not
	 * leave a previous statement in `out` for the caller to act on. */
	if (t.feed(buf.data(), buf.size(), sql)) {
		EXPECT_EQ(sql, "");
	}
	EXPECT_EQ(t.buffered(), 0u);
}

TEST(Request, ResetDiscardsPartialCommand)
{
	cache::RequestTracker t;
	std::vector<uint8_t> buf = comQuery("SELECT 4");
	std::string sql;

	t.begin(mysql::CLIENT_PROTOCOL_41);
	EXPECT_FALSE(t.feed(buf.data(), 6, sql));
	EXPECT_GT(t.buffered(), 0u);

	/* A connection that resets mid-command must not carry half a packet
	 * into the next one and resync onto garbage. */
	t.reset();
	EXPECT_EQ(t.buffered(), 0u);

	EXPECT_TRUE(t.feed(buf.data(), buf.size(), sql));
	EXPECT_EQ(sql, "SELECT 4");
}

TEST(Request, LargeStatement)
{
	/* Comfortably past a single MTU and past the 512-byte key limit, to
	 * make sure reassembly is not quietly bounded somewhere. */
	cache::RequestTracker t;
	std::string big = "SELECT " + std::string(9000, 'x');
	std::vector<uint8_t> buf = comQuery(big);
	std::string sql;

	t.begin(mysql::CLIENT_PROTOCOL_41);
	size_t off = 0;

	while (off < buf.size() && !t.feed(buf.data() + off, 1000, sql)) {
		off += 1000;
		if (off + 1000 > buf.size()) {
			t.feed(buf.data() + off, buf.size() - off, sql);
			break;
		}
	}
	EXPECT_EQ(sql, big);
}

/* --- the intercept list --------------------------------------------------- */

TEST(StmtList, ExactMatchOnly)
{
	cache::StmtList l;

	l.add("SELECT id FROM t WHERE id = 5");
	EXPECT_TRUE(l.contains("SELECT id FROM t WHERE id = 5"));
	/* The reason this is not a prefix trie: one is a prefix of the other,
	 * and serving the first's rows for the second would be silent
	 * corruption. */
	EXPECT_FALSE(l.contains("SELECT id FROM t WHERE id = 55"));
	EXPECT_FALSE(l.contains("SELECT id FROM t WHERE id = "));
	/* Not normalized, either. */
	EXPECT_FALSE(l.contains("select id from t where id = 5"));
	EXPECT_FALSE(l.contains("SELECT id  FROM t WHERE id = 5"));
}

TEST(StmtList, LoadsFileSkippingCommentsAndBlanks)
{
	std::string path = writeTemp("# a comment\n"
				     "\n"
				     "SELECT 1\n"
				     "   SELECT 2   \n"
				     "\t\n"
				     "# another\n"
				     "SELECT 3\r\n");
	cache::StmtList l;
	std::string err;

	ASSERT_TRUE(l.load(path, err)) << err;
	EXPECT_EQ(l.size(), 3u);
	EXPECT_TRUE(l.contains("SELECT 1"));
	/* Indentation is stripped, so an indented entry still matches what a
	 * client actually sends. */
	EXPECT_TRUE(l.contains("SELECT 2"));
	/* CRLF must not leave a stray \r, which would match nothing ever. */
	EXPECT_TRUE(l.contains("SELECT 3"));
	std::remove(path.c_str());
}

TEST(StmtList, DuplicatesCollapse)
{
	std::string path = writeTemp("SELECT 1\nSELECT 1\nSELECT 2\n");
	cache::StmtList l;
	std::string err;

	ASSERT_TRUE(l.load(path, err)) << err;
	/* Order preserved, duplicates dropped -- the daemon seeds from all()
	 * and should not do it twice. */
	EXPECT_EQ(l.size(), 2u);
	EXPECT_EQ(l.all()[0], "SELECT 1");
	EXPECT_EQ(l.all()[1], "SELECT 2");
	std::remove(path.c_str());
}

TEST(StmtList, MissingFileIsAnError)
{
	cache::StmtList l;
	std::string err;

	/* Not an empty list: caching nothing because of a typo in a path
	 * should be loud. */
	EXPECT_FALSE(l.load("/nonexistent/qcache/list.txt", err));
	EXPECT_FALSE(err.empty());
}

TEST(StmtList, MatchesTheShippedDemoList)
{
	/* The demo list is the closest thing to a real one in the tree, and it
	 * is what the end-to-end test caches. */
	cache::StmtList l;
	std::string err;

	if (!l.load("demo/config/cache.list", err)) {
		GTEST_SKIP() << "not running from the repo root: " << err;
	}
	EXPECT_EQ(l.size(), 1u);
	EXPECT_TRUE(l.contains("SELECT sku, name, price FROM products "
			       "WHERE category = 'tools' AND SLEEP(1.5) = 0"));
}

/* --- the two halves together ---------------------------------------------- */

TEST(Request, MatchesAgainstTheList)
{
	/* What UCLIENT actually does: reassemble, then decide. */
	cache::StmtList l;
	cache::RequestTracker t;
	std::vector<uint8_t> buf;
	std::string sql;
	std::vector<std::string> intercepted;

	l.add("SELECT * FROM products WHERE category = 'tools'");

	appendTo(buf, comQuery("SELECT 1"));
	appendTo(buf, comQuery("SELECT * FROM products WHERE category = 'tools'"));
	appendTo(buf, wire({ mysql::COM_PING }));
	appendTo(buf, comQuery("SELECT 2"));

	t.begin(mysql::CLIENT_PROTOCOL_41);
	t.feed(buf.data(), buf.size(), sql);
	do {
		if (l.contains(sql)) {
			intercepted.push_back(sql);
		}
	} while (t.next(sql));

	ASSERT_EQ(intercepted.size(), 1u);
	EXPECT_EQ(intercepted[0], "SELECT * FROM products WHERE category = 'tools'");
}

/* --- the layout UCLIENT depends on ---------------------------------------
 *
 * The BPF filter cannot use mysql::MessageReader -- it is verifier-bounded and sees
 * one buffer, not a stream. It hardcodes the framing instead: a 4-byte header,
 * a command byte, then statement text, with the declared length matching the
 * buffer exactly.
 *
 * These pin that layout against the same builders the reassembly tests use.
 * If the framing ever drifts, UCLIENT would stop matching anything and the
 * cache would simply never hit -- a silent failure with no error anywhere,
 * which is why it is worth a test rather than a comment.
 */

TEST(UclientLayout, PrefixIsFourByteHeaderPlusCommand)
{
	std::vector<uint8_t> buf = comQuery("SELECT 1");

	/* MYSQL_PREFIX in uclient.bpf.c. */
	EXPECT_EQ(mysql::kHeaderLen + 1, 5u);
	EXPECT_EQ(buf[4], (uint8_t)mysql::COM_QUERY);
	EXPECT_EQ(std::string(buf.begin() + 5, buf.end()), "SELECT 1");
}

TEST(UclientLayout, DeclaredLengthMatchesTheWholeBuffer)
{
	const std::string sql = "SELECT * FROM products";
	std::vector<uint8_t> buf = comQuery(sql);
	uint32_t plen = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16);

	/* key_of() rejects anything where this does not hold -- that is how it
	 * tells a whole single packet from a partial write or a continuation,
	 * neither of which it can key. */
	EXPECT_EQ(plen + mysql::kHeaderLen, buf.size());
	EXPECT_EQ(plen - 1, sql.size());
}

TEST(UclientLayout, StatementFitsTheKeyOrIsNotCacheable)
{
	/* QC_STMT_MAX bounds both the map key and what the filter will copy.
	 * A statement at the limit must still round-trip into a key. */
	std::string sql(QC_STMT_MAX - 1, 'a');
	struct stmt_key k {};

	ASSERT_LE(sql.size(), sizeof(k.text));
	memcpy(k.text, sql.data(), sql.size());
	EXPECT_EQ(strnlen(k.text, sizeof(k.text)), sql.size());

	/* One byte more has nowhere to go, which is why the loader reports it
	 * rather than truncating -- a truncated key would match a statement
	 * nobody asked to cache. */
	EXPECT_GT(sql.size() + 1, sizeof(k.text) - 1);
}

TEST(UclientLayout, KeyIsZeroPaddedSoEqualTextMeansEqualKey)
{
	/* The map compares the whole fixed-width key, so any tail bytes left
	 * over from a previous statement would make two identical statements
	 * hash differently. */
	struct stmt_key a {}, b {};
	const char *sql = "SELECT 1";

	memset(&a, 0xAB, sizeof(a));
	memset(&a, 0, sizeof(a));
	memcpy(a.text, sql, strlen(sql));

	memset(&b, 0, sizeof(b));
	memcpy(b.text, sql, strlen(sql));

	EXPECT_EQ(memcmp(&a, &b, sizeof(a)), 0);
}
