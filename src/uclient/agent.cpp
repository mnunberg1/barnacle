// SPDX-License-Identifier: GPL-2.0
/*
 * agent.cpp - UCLIENT, as a native agent injected into a live process.
 *
 * Frida injects this shared object into an already-running client and
 * gum_interceptor_replace() swaps out the TLS library's entry points. That is
 * the same mechanism bpftime used -- bpftime is a userspace eBPF runtime
 * built on top of Frida -- with the eBPF layer removed.
 *
 * --- why not eBPF here ----------------------------------------------------
 *
 * The BPF programming model earns its keep in KCLIENT, which genuinely runs
 * in the kernel. In UCLIENT it bought nothing and cost a great deal:
 *
 *   no per-process state   a BPF "global" is a .bss map living in one shared
 *                          segment, so two attached clients read and write the
 *                          same variable. Measured, not assumed.
 *   no mmap                a BPF program cannot make syscalls, and no helper
 *                          maps memory, so the shared arena was unreachable.
 *   verifier bounds        a 512-byte statement cap, no reassembly across
 *                          writes, and a hand-rolled subset of MySQL framing
 *                          duplicating code that already exists and is tested.
 *   no map access          popping the dpipe freelist and splicing a socket
 *                          are ordinary bpf() syscalls, which a BPF program
 *                          cannot make.
 *
 * All four dissolve here. State is ordinary C++; the arena is a plain mmap;
 * parsing is src/common/mysql, unmodified and unit-tested; and the dpipe
 * handshake is just syscalls, because this is just a program.
 *
 * --- the safety invariant -------------------------------------------------
 *
 * Suppressing a query the client cannot be answered for is unrecoverable: the
 * statement never reaches the server, so the following read blocks forever.
 * Therefore SSL_write is only suppressed when the complete response is
 * already in hand. Letting a query through is always safe; that is the
 * default, and every failure path takes it.
 */
#include "common/mysql/resultset.h"
#include "common/session.h"
#include "common/stmtlist.h"

#include <cstdio>
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>
#include <poll.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "uclient/shared.h"

#include <frida-gum.h>

namespace {

/* --- the originals we replaced ------------------------------------------- */

int (*real_SSL_write)(void *ssl, const void *buf, int num);
int (*real_SSL_write_ex)(void *ssl, const void *buf, size_t num, size_t *written);
int (*real_SSL_read)(void *ssl, void *buf, int num);
int (*real_SSL_read_ex)(void *ssl, void *buf, size_t num, size_t *readbytes);

/* Looked up, never replaced. The splice is registered against the socket, and
 * only the SSL object knows which one that is. */
int (*real_SSL_get_fd)(const void *ssl);


int sockOf(void *ssl)
{
	return real_SSL_get_fd ? real_SSL_get_fd(ssl) : -1;
}


/*
 * Per-connection state.
 *
 * Keyed by the SSL object, which is what identifies a connection from inside
 * the library. This is an ordinary container in ordinary process memory --
 * the thing a BPF program could not have.
 */
struct Conn {
	cache::RequestTracker req;
	cache::ResponseTracker resp;

	/* A response we owe the caller, and how far through it we are. Drained
	 * across as many SSL_read calls as the client chooses to make: it
	 * picks the buffer size, not us. */
	std::vector<uint8_t> owed;
	size_t owed_off = 0;

	/* Set once the server tells us a transaction is open. While it is,
	 * nothing is served from cache: reads inside a transaction may see
	 * uncommitted state private to this session. */
	bool in_txn = false;
	bool started = false;

	/* --- read-through capture ---------------------------------------
	 *
	 * A statement we let through because it was not cached, and the
	 * response accumulating for it. Responses arrive across as many
	 * SSL_read calls as the library felt like making, so they have to be
	 * reassembled before they mean anything.
	 */
	std::string pending;
	std::vector<uint8_t> captured;
	mysql::MessageReader rd;
	bool capturing = false;

	/* The connection's framing, learned by watching a real response.
	 * Unknown until then -- we attach mid-connection and never see the
	 * handshake, so it cannot be read, only inferred. */
	uint32_t caps = 0;
	bool caps_known = false;

	/* Sequence id of the last COM_QUERY seen, so a regenerated response
	 * continues that connection's numbering rather than guessing. */
	uint8_t last_seq = 0;

	/* --- agent mode --------------------------------------------------
	 *
	 * Set between asking the daemon and hearing back. While it holds, the
	 * socket is spliced to a dpipe and carries the daemon conversation
	 * rather than server traffic, so raw reads on it must be intercepted
	 * before OpenSSL tries to decrypt them as TLS records.
	 */
	bool awaiting = false;
	uint32_t dpipe = 0;
	int sock = -1;

	/* The query we suppressed, kept so it can be sent for real if the
	 * daemon says the cache does not have it. Being able to re-send is
	 * what makes suppression recoverable -- a native agent can call
	 * SSL_write, which is precisely what the eBPF version could not. */
	std::vector<uint8_t> query;

	/* The daemon's verdict, once its reply has been consumed off the
	 * socket. 0xFFFF means nothing has arrived yet. */
	uint32_t status = 0xFFFF;

	/* When the wait for that verdict runs out.
	 *
	 * architecture.txt requires this: a daemon that never answers must not
	 * strand the client. Without it the caller retries SSL_read forever --
	 * the read hook keeps returning EINTR, OpenSSL keeps reporting
	 * WANT_READ, and the application spins. On expiry the dpipe is
	 * released and the original query is sent for real, which is always
	 * safe.
	 */
	uint64_t deadline_ns = 0;
};

/* How long a client waits for the daemon before giving up and going to the
 * server. The doc suggests 100ms; the daemon answers in microseconds, so this
 * only ever fires when something is wrong. */
constexpr uint64_t AGENT_TIMEOUT_NS = 100ull * 1000 * 1000;

uint64_t nowNs()
{
	struct timespec ts {};

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

std::mutex g_lock;
std::map<void *, Conn> g_conns;
/* Only sockets currently spliced. Kept separate so the read hook can reject
 * an uninteresting fd with one lookup and no locking of the SSL map. */
std::map<int, Conn *> g_spliced;
cache::StmtList g_list;
bool g_ready;

struct {
	unsigned long writes, matched, served, passthrough, txn_skip, published;
	unsigned long asked, pool_empty, resent, timeouts;
} g_stat;

Conn &connFor(void *ssl)
{
	Conn &c = g_conns[ssl];

	if (!c.started) {
		/* Capabilities are not known without watching the handshake,
		 * which happens before we attach to a live process. Assume the
		 * modern set; extractQuery only needs QUERY_ATTRIBUTES to be
		 * right, and a wrong guess means a miss, never a wrong hit. */
		c.req.begin(mysql::CLIENT_PROTOCOL_41 | mysql::CLIENT_TRANSACTIONS);
		c.started = true;
	}
	return c;
}

/* --- the write side ------------------------------------------------------ */

/* Returns true if the write was handled -- i.e. suppressed because we can
 * answer it. False means "let the real function run", which is always safe. */
bool handleWrite(void *ssl, int sock, const void *buf, size_t num)
{
	std::lock_guard<std::mutex> lk(g_lock);
	Conn &c = connFor(ssl);
	std::string sql;

	g_stat.writes++;

	/* Feed every byte, whether or not we care about it. MySQL has no
	 * pipelining, so a packet skipped rather than parsed leaves the reader
	 * misaligned for everything after it. */
	if (!c.req.feed((const uint8_t *)buf, num, sql)) {
		return false;
	}

	do {
		c.last_seq = c.req.lastSeq();

		/* A command was sent, so a response is about to begin. Realign
		 * the tracker to it: MySQL has no pipelining, so exactly one
		 * response is outstanding, and a tracker left mid-stream from
		 * an earlier one reports completion at the wrong packet. */
		c.resp.begin(c.caps_known ? c.caps
					  : (mysql::CLIENT_PROTOCOL_41 |
					     mysql::CLIENT_TRANSACTIONS));

		if (!g_list.contains(sql)) {
			continue;
		}
		g_stat.matched++;

		if (c.in_txn) {
			/* Caching is bypassed outright while a transaction is
			 * open, per the caveat this whole design exists under.
			 * Not captured either: the rows may reflect
			 * uncommitted state private to this session. */
			g_stat.txn_skip++;
			continue;
		}

		std::vector<uint8_t> canon;
		uint32_t id = 0;

		if (!qcagent::lookupPayload(sql, canon, id)) {
			/* Read-through. Let the query run and capture what
			 * comes back, so the next caller hits. */
			c.pending = sql;
			c.captured.clear();
			c.rd.reset();
			c.capturing = true;
			continue;
		}

		(void)canon;
		(void)id;

		/* Ask the daemon. Take a dpipe, splice this connection to it,
		 * post the request, and return -- the reply lands on the
		 * client's own socket, which is the one it was going to wait on
		 * anyway. Nothing here waits, because this is the application's
		 * thread inside SSL_write. */
		if (!qcagent::acquire(sql, sock, c.dpipe)) {
			g_stat.pool_empty++;
			continue; /* pool exhausted: let the query through */
		}
		if (!qcagent::askLookup(sock)) {
			qcagent::release(sock, c.dpipe);
			continue;
		}

		c.awaiting = true;
		c.status = 0xFFFF;
		c.deadline_ns = nowNs() + AGENT_TIMEOUT_NS;
		c.sock = sock;
		c.pending = sql;
		c.query.assign((const uint8_t *)buf, (const uint8_t *)buf + num);
		g_spliced[sock] = &c;
		g_stat.asked++;
		return true; /* suppress: the query is the daemon's problem now */
	} while (c.req.next(sql));

	g_stat.passthrough++;
	return false;
}

/* --- the read side ------------------------------------------------------- */

/* Hand over as much of the owed response as this call has room for. Returns 0
 * when there is nothing owed, meaning the real SSL_read should run. */
size_t drainLocked(Conn &c, void *buf, size_t cap)
{
	if (c.owed_off >= c.owed.size()) {
		return 0;
	}

	size_t n = c.owed.size() - c.owed_off;

	if (n > cap) {
		n = cap;
	}
	memcpy(buf, c.owed.data() + c.owed_off, n);
	c.owed_off += n;
	if (c.owed_off >= c.owed.size()) {
		c.owed.clear();
		c.owed_off = 0;
	}
	return n;
}

size_t drain(void *ssl, void *buf, size_t cap)
{
	std::lock_guard<std::mutex> lk(g_lock);
	auto it = g_conns.find(ssl);

	if (it == g_conns.end()) {
		return 0;
	}
	return drainLocked(it->second, buf, cap);
}

/*
 * Work out whether this connection negotiated CLIENT_DEPRECATE_EOF.
 *
 * It cannot be read: the handshake happened before we attached. But the two
 * framings are distinguishable after the fact, because a result set parses
 * cleanly under exactly one of them -- the other is a packet out of step. So
 * try both and believe whichever works.
 *
 * Getting this wrong is not subtle. A regenerated response framed for the
 * wrong capability leaves the client's parser misaligned for the rest of the
 * connection, so nothing is served until it is known.
 */
bool inferCaps(const std::vector<uint8_t> &resp, uint32_t &out)
{
	const uint32_t base = mysql::CLIENT_PROTOCOL_41 | mysql::CLIENT_TRANSACTIONS;
	mysql::ResultSet plain, deprecated;
	bool ok_plain = mysql::parseResultSet(resp.data(), resp.size(), base, plain);
	bool ok_dep = mysql::parseResultSet(resp.data(), resp.size(),
					    base | mysql::CLIENT_DEPRECATE_EOF,
					    deprecated);

	/* Both can "succeed" on the same bytes: without DEPRECATE_EOF there is
	 * an extra EOF packet between the definitions and the rows, and a
	 * DEPRECATE_EOF parse mistakes it for the terminator -- stopping early
	 * and reporting zero rows. Whichever reading consumes more rows is the
	 * real one. */
	if (ok_plain && ok_dep) {
		if (plain.rows.size() >= deprecated.rows.size()) {
			out = base;
		} else {
			out = base | mysql::CLIENT_DEPRECATE_EOF;
		}
		return true;
	}
	if (ok_plain) {
		out = base;
		return true;
	}
	if (ok_dep) {
		out = base | mysql::CLIENT_DEPRECATE_EOF;
		return true;
	}
	return false;
}

/*
 * Watch a real server response: track transaction state, learn the framing,
 * and -- if this was a statement we let through on purpose -- capture it for
 * the cache.
 *
 * This is the read-through path. Nothing is fetched speculatively; the cache
 * only ever learns statements someone actually ran.
 */
void observe(void *ssl, int sock, const void *buf, size_t n)
{
	std::lock_guard<std::mutex> lk(g_lock);
	Conn &c = connFor(ssl);
	mysql::Message m;

	c.sock = sock;
	c.rd.append((const uint8_t *)buf, n);
	if (c.capturing) {
		c.captured.insert(c.captured.end(), (const uint8_t *)buf,
				  (const uint8_t *)buf + n);
	}

	while (c.rd.next(m)) {
		if (c.resp.feed(m)) {
			c.in_txn = c.resp.inTransaction();

			bool poisoned = c.resp.poisoned();

			if (!c.capturing) {
				continue;
			}
			c.capturing = false;

			std::vector<uint8_t> whole;

			whole.swap(c.captured);

			uint32_t caps = 0;

			if (!c.caps_known && inferCaps(whole, caps)) {
				c.caps = caps;
				c.caps_known = true;
			}
			if (poisoned || c.in_txn || !c.caps_known) {
				continue;
			}

			/* Re-encode under the canonical capabilities before
			 * handing it over, so what is stored does not carry
			 * this connection's framing decisions. */
			mysql::ResultSet rs;

			if (!mysql::parseResultSet(whole.data(), whole.size(), c.caps,
						   rs)) {
				continue;
			}

			std::vector<uint8_t> canon =
				mysql::encodeResultSet(rs, qcagent::CANONICAL_CAPS, 1);

			/* Read-through: hand the response to the daemon so the
			 * next caller hits. Needs its own dpipe -- the one used
			 * for the lookup went back on the freelist when the
			 * verdict arrived. */
			uint32_t key = 0;

			if (qcagent::acquire(c.pending, c.sock, key)) {
				if (qcagent::askStore(c.sock, canon)) {
					g_stat.published++;
				}
				qcagent::release(c.sock, key);
			}
			c.pending.clear();
		}
	}
}

/* --- the daemon's reply -------------------------------------------------- */

/*
 * Take the daemon's verdict off a spliced socket.
 *
 * While a connection is in agent mode the bytes arriving on it are a
 * four-byte agent_reply, not TLS records. They must be consumed here, before
 * OpenSSL sees them and fails to decrypt what is not a record --
 * architecture.txt calls for capturing raw reads even when SSL is active, and
 * this is that.
 *
 * Returns true if the reply was consumed.
 */
bool takeReply(Conn *c, int fd)
{
	qcagent::Reply r {};
	struct pollfd pfd = { fd, POLLIN, 0 };
	uint64_t now = nowNs();
	int ms = 0;

	/* Wait only as long as the deadline allows. This is not the network:
	 * the daemon is a local process answering from shared memory, so the
	 * wait is microseconds and the bound only matters when something is
	 * wrong. architecture.txt asks for exactly this timer. */
	if (c->deadline_ns > now) {
		ms = (int)((c->deadline_ns - now) / 1000000ull);
	}
	if (poll(&pfd, 1, ms) <= 0) {
		return false;
	}

	/* Safe to read straight off the socket: it is spliced to a dpipe, so
	 * what is on it is the daemon's reply, not TLS. Nothing else in the
	 * process is reading this fd -- the application is inside SSL_read,
	 * which is us. */
	ssize_t n = read(fd, &r, sizeof(r));

	if (n != (ssize_t)sizeof(r)) {
		return false;
	}
	c->status = r.status;
	return true;
}

/*
 * Act on the verdict, once it has been consumed.
 *
 * Returns the number of bytes placed in the caller's buffer, or 0 to let the
 * real SSL_read run.
 */
size_t settle(void *ssl, Conn &c, void *buf, size_t cap)
{
	if (!c.awaiting) {
		return 0;
	}
	if (c.status == 0xFFFF) {
		takeReply(&c, c.sock);
	}
	if (c.status == 0xFFFF) {
		/* Out of time. Fall through to the passthrough path below,
		 * which releases the pipe and sends the query for real. */
		g_stat.timeouts++;
	}

	int sock = c.sock;
	uint32_t key = c.dpipe;

	c.awaiting = false;
	g_spliced.erase(sock);

	/* Give the connection back before anything else: while it is spliced
	 * every byte it sends goes to the daemon rather than the server. */
	qcagent::release(sock, key);

	if (c.status == qcagent::REPLY_OK && c.caps_known) {
		std::vector<uint8_t> canon;
		uint32_t id = 0;
		mysql::ResultSet rs;

		if (qcagent::lookupPayload(c.pending, canon, id) &&
		    mysql::parseResultSet(canon.data(), canon.size(),
					  qcagent::CANONICAL_CAPS, rs)) {
			/* Stored canonically, re-framed for THIS connection.
			 * Replaying the stored bytes would only work for a
			 * connection that negotiated identically and stood at
			 * the same sequence id. */
			c.owed = mysql::encodeResultSet(rs, c.caps,
							(uint8_t)(c.last_seq + 1));
			c.owed_off = 0;
			c.pending.clear();
			g_stat.served++;
			return drainLocked(c, buf, cap);
		}
	}

	/*
	 * Anything else means the client has to ask the server after all --
	 * including REPLY_OK when the framing is still unknown, since a
	 * response framed for the wrong capability would desynchronise the
	 * parser for the rest of the connection.
	 *
	 * The query was suppressed, so it has to be sent for real now. This is
	 * the step the eBPF version had no way to perform, and without it a
	 * suppressed miss left the client waiting forever.
	 */
	if (!c.query.empty()) {
		real_SSL_write(ssl, c.query.data(), (int)c.query.size());
		g_stat.resent++;
		/* Capture what comes back, so the next caller hits. */
		c.captured.clear();
		c.rd.reset();
		c.capturing = true;
	}
	return 0;
}

/* --- replacements -------------------------------------------------------- */

int rep_SSL_write(void *ssl, const void *buf, int num)
{
	if (num > 0 && handleWrite(ssl, sockOf(ssl), buf, (size_t)num)) {
		return num; /* the caller believes every byte was sent */
	}
	return real_SSL_write(ssl, buf, num);
}

int rep_SSL_write_ex(void *ssl, const void *buf, size_t num, size_t *written)
{
	if (num > 0 && handleWrite(ssl, sockOf(ssl), buf, num)) {
		if (written) {
			*written = num;
		}
		return 1;
	}
	return real_SSL_write_ex(ssl, buf, num, written);
}

int rep_SSL_read(void *ssl, void *buf, int num)
{
	if (num > 0) {
		{
			std::lock_guard<std::mutex> lk(g_lock);
			Conn &c = connFor(ssl);
			size_t n = settle(ssl, c, buf, (size_t)num);

			if (n) {
				return (int)n;
			}
		}

		size_t n = drain(ssl, buf, (size_t)num);

		if (n) {
			return (int)n;
		}
	}

	int r = real_SSL_read(ssl, buf, num);

	if (r > 0) {
		observe(ssl, sockOf(ssl), buf, (size_t)r);
	}
	return r;
}

int rep_SSL_read_ex(void *ssl, void *buf, size_t num, size_t *readbytes)
{
	if (num > 0) {
		{
			std::lock_guard<std::mutex> lk(g_lock);
			Conn &c = connFor(ssl);
			size_t n = settle(ssl, c, buf, num);

			if (n) {
				if (readbytes) {
					*readbytes = n;
				}
				return 1;
			}
		}

		size_t n = drain(ssl, buf, num);

		if (n) {
			if (readbytes) {
				*readbytes = n;
			}
			return 1;
		}
	}

	int r = real_SSL_read_ex(ssl, buf, num, readbytes);

	if (r == 1 && readbytes && *readbytes > 0) {
		observe(ssl, sockOf(ssl), buf, *readbytes);
	}
	return r;
}

/* --- setup --------------------------------------------------------------- */

/*
 * Resolve a TLS entry point.
 *
 * Named module first, then a whole-process search, then dlsym. libssl is
 * routinely dlopen'd late -- Python loads it via _ssl long after startup --
 * so which of these succeeds depends on when we attached, and being wrong
 * about it means silently hooking nothing.
 */
gpointer resolve(const char *sym)
{
	static const char *mods[] = { "libssl.so.3", "libssl.so", NULL };

	/* Named module first. gum_module_find_export_by_name() takes a
	 * GumModule in Frida 17 -- older releases took the name directly. */
	for (int i = 0; mods[i]; i++) {
		GumModule *m = gum_process_find_module_by_name(mods[i]);

		if (!m) {
			continue;
		}

		gpointer p = GSIZE_TO_POINTER(gum_module_find_export_by_name(m, sym));

		if (p) {
			return p;
		}
	}

	/* Then anywhere in the process, then the loader itself. libssl is
	 * routinely dlopen'd late -- Python loads it via _ssl long after
	 * startup -- so which of these succeeds depends on when we attached,
	 * and being wrong means silently hooking nothing. */
	gpointer p = GSIZE_TO_POINTER(gum_module_find_global_export_by_name(sym));

	if (p) {
		return p;
	}
	return dlsym(RTLD_DEFAULT, sym);
}

void hook(GumInterceptor *ic, const char *sym, gpointer repl, gpointer *orig)
{
	gpointer target = resolve(sym);

	if (!target) {
		fprintf(stderr, "qcagent: %s not found\n", sym);
		return;
	}
	if (gum_interceptor_replace(ic, target, repl, NULL, orig) != 0) {
		fprintf(stderr, "qcagent: cannot replace %s\n", sym);
		return;
	}
	fprintf(stderr, "qcagent: hooked %s\n", sym);
}

} // namespace

/*
 * Frida's entrypoint, called once when the library is injected.
 *
 * The signature matters. `stay_resident` must be set, or Frida unloads this
 * object as soon as the function returns -- taking the hooks with it and
 * leaving the target running patched trampolines into freed memory. It is
 * NOT also a constructor: declaring both makes it run twice.
 */
extern "C" void qcagent_init(const gchar *data, gboolean *stay_resident,
			     gpointer user_data)
{
	const char *list = data && *data ? data : getenv("QCACHE_LIST");
	std::string err;
	GumInterceptor *ic;

	(void)data;
	(void)user_data;
	if (stay_resident) {
		*stay_resident = TRUE;
	}
	if (g_ready) {
		return; /* already injected once */
	}

	fprintf(stderr, "qcagent: loading into pid %d\n", getpid());

	if (!g_list.load(list && *list ? list : "demo/config/cache.list", err)) {
		fprintf(stderr, "qcagent: %s\n", err.c_str());
		return;
	}
	if (!qcagent::openShared()) {
		return;
	}
	g_ready = true;

	gum_init_embedded();
	ic = gum_interceptor_obtain();
	gum_interceptor_begin_transaction(ic);
	hook(ic, "SSL_write", (gpointer)rep_SSL_write, (gpointer *)&real_SSL_write);
	hook(ic, "SSL_write_ex", (gpointer)rep_SSL_write_ex,
	     (gpointer *)&real_SSL_write_ex);
	hook(ic, "SSL_read", (gpointer)rep_SSL_read, (gpointer *)&real_SSL_read);
	hook(ic, "SSL_read_ex", (gpointer)rep_SSL_read_ex,
	     (gpointer *)&real_SSL_read_ex);

	gum_interceptor_end_transaction(ic);

	/* Looked up, never replaced: the splice is registered against the
	 * socket, and only the SSL object knows which one that is. */
	real_SSL_get_fd = (int (*)(const void *))resolve("SSL_get_fd");
	if (!real_SSL_get_fd) {
		fprintf(stderr, "qcagent: SSL_get_fd not found; nothing can be "
				"spliced\n");
	}


	fprintf(stderr, "qcagent: ready, %zu statement(s)\n", g_list.size());
}

extern "C" __attribute__((destructor)) void qcagent_fini(void)
{
	fprintf(stderr,
		"qcagent: writes=%lu matched=%lu asked=%lu served=%lu resent=%lu\n"
		"qcagent: published=%lu timeouts=%lu pool_empty=%lu txn_skip=%lu\n",
		g_stat.writes, g_stat.matched, g_stat.asked, g_stat.served,
		g_stat.resent, g_stat.published, g_stat.timeouts, g_stat.pool_empty,
		g_stat.txn_skip);
}
