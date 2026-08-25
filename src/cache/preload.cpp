// SPDX-License-Identifier: GPL-2.0
/*
 * preload.cpp - transparent MySQL query cache, injected via LD_PRELOAD.
 *
 * Sits between a client application and its TLS library, on the plaintext
 * side. For statements on the cache list:
 *
 *   HIT   the query is never sent. The client is handed the cached response
 *         and never learns the database was not consulted.
 *   MISS  the query goes through untouched; the response is captured on its
 *         way back and written to the cache for next time.
 *
 * Everything else passes through with only the bookkeeping needed to know
 * which connection is in what state.
 *
 * ---------------------------------------------------------------------------
 * Why the interception points are what they are
 *
 * Encryption happens inside the client, so the only place plaintext exists is
 * either side of the TLS library's own read/write calls. That is where we sit
 * -- above TLS, below the application. No proxy, no certificates, no need to
 * route to the database ourselves.
 *
 * Three hooks, each doing one job (all validated by spike/FINDINGS.md before
 * this was written):
 *
 *   SSL_write   see the outgoing query; suppress it on a cache hit
 *   read/recv   return EINTR while a response is owed, so the client never
 *               blocks waiting for bytes the server was never asked for.
 *               OpenSSL reads this as "retry later" and leaves the session
 *               intact.
 *   SSL_read    hand back the cached response
 *
 * Both OpenSSL entry-point families are hooked. This is not belt-and-braces:
 * the mysql CLI calls SSL_read/SSL_write while CPython's _ssl calls only
 * SSL_read_ex/SSL_write_ex, so covering one family silently misses every
 * Python client.
 */
#include "../mysql/protocol.h"
#include "session.h"
#include "valkey.h"

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct ssl_st SSL;

namespace {

using namespace mysql;
using cache::Connection;
using cache::Valkey;

/* --- real functions, resolved lazily ------------------------------------
 *
 * Lazily, not at startup, because a TLS library may not be loaded yet. In a
 * Python process the first call we intercept is a read() during interpreter
 * startup -- long before `import ssl` dlopen()s _ssl.so. Resolving SSL_*
 * eagerly at that moment yields null for every one of them.
 */
int (*real_SSL_write)(SSL *, const void *, int);
int (*real_SSL_read)(SSL *, void *, int);
int (*real_SSL_write_ex)(SSL *, const void *, size_t, size_t *);
int (*real_SSL_read_ex)(SSL *, void *, size_t, size_t *);
ssize_t (*real_read)(int, void *, size_t);
ssize_t (*real_recv)(int, void *, size_t, int);
ssize_t (*real_write)(int, const void *, size_t);
ssize_t (*real_send)(int, const void *, size_t, int);
int (*real_close)(int);

void *resolve(void **slot, const char *name)
{
	static void *libssl;

	if (*slot) {
		return *slot;
	}
	*slot = dlsym(RTLD_NEXT, name);
	if (*slot) {
		return *slot;
	}
	/* CPython dlopen()s _ssl.so with RTLD_LOCAL, so libssl lands in a
	 * private namespace RTLD_NEXT cannot see. Our hook is still reached
	 * (calls bind against the global scope first) but the genuine
	 * function needs an explicit handle. RTLD_NOLOAD never causes a load
	 * of its own. */
	if (!libssl) {
		libssl = dlopen("libssl.so.3", RTLD_NOW | RTLD_NOLOAD);
		if (!libssl) {
			libssl = dlopen("libssl.so", RTLD_NOW | RTLD_NOLOAD);
		}
	}
	if (libssl) {
		*slot = dlsym(libssl, name);
	}
	return *slot;
}

/* --- configuration ------------------------------------------------------ */

struct Config {
	std::set<std::string> cacheable;
	std::string valkey_host = "valkey";
	uint16_t valkey_port = 6379;
	int ttl = 30;
	bool verbose = false;
	bool enabled = true;
};

Config g_cfg;
bool g_ready;

/* Leaked for the same reason as the connection map below: teardown ordering. */
Valkey &valkey()
{
	static Valkey *v = new Valkey();

	return *v;
}

std::mutex &valkey_lock()
{
	static std::mutex *m = new std::mutex();

	return *m;
}

void logf(const char *fmt, ...)
{
	va_list ap;

	if (!g_cfg.verbose) {
		return;
	}
	fprintf(stderr, "[qcache] ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	fflush(stderr);
}

std::string trim(const std::string &s)
{
	size_t a = s.find_first_not_of(" \t\r\n");
	size_t b = s.find_last_not_of(" \t\r\n");

	if (a == std::string::npos) {
		return "";
	}
	return s.substr(a, b - a + 1);
}

void loadConfig()
{
	const char *p;

	if ((p = getenv("QCACHE_VALKEY_HOST"))) {
		g_cfg.valkey_host = p;
	}
	if ((p = getenv("QCACHE_VALKEY_PORT"))) {
		g_cfg.valkey_port = (uint16_t)atoi(p);
	}
	if ((p = getenv("QCACHE_TTL"))) {
		g_cfg.ttl = atoi(p);
	}
	g_cfg.verbose = getenv("QCACHE_VERBOSE") != nullptr;
	if ((p = getenv("QCACHE_DISABLE"))) {
		g_cfg.enabled = false;
	}

	const char *list = getenv("QCACHE_LIST");

	if (!list) {
		list = "config/cache.list";
	}
	std::ifstream in(list);

	if (!in) {
		logf("no cache list at %s -- nothing will be cached", list);
		return;
	}
	std::string line;

	while (std::getline(in, line)) {
		std::string t = trim(line);

		if (t.empty() || t[0] == '#') {
			continue;
		}
		g_cfg.cacheable.insert(t);
	}
	logf("loaded %zu cacheable statement(s) from %s", g_cfg.cacheable.size(),
	     list);
}

void ensureInit()
{
	if (g_ready) {
		return;
	}
	g_ready = true;
	real_read = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
	real_recv = (ssize_t (*)(int, void *, size_t, int))dlsym(RTLD_NEXT, "recv");
	loadConfig();
}

/* --- reentrancy guard ----------------------------------------------------
 *
 * Our own hooks must never re-enter themselves. Two ways that happens:
 * logging calls fprintf, which calls write(); and the Valkey client does
 * socket I/O of its own. Either would take a non-recursive mutex twice on
 * one thread and deadlock. Anything reached while the guard is held falls
 * straight through to the real function.
 */
thread_local bool t_in_hook;

struct HookGuard {
	bool ok;

	HookGuard() : ok(!t_in_hook)
	{
		if (ok) {
			t_in_hook = true;
		}
	}
	~HookGuard()
	{
		if (ok) {
			t_in_hook = false;
		}
	}
};

/* --- per-connection state ------------------------------------------------
 *
 * Keyed by file descriptor rather than SSL*, because the interesting part of
 * a connection happens before an SSL* exists.
 *
 * MySQL negotiates capabilities in PLAINTEXT: the server's greeting and the
 * client's reply are both sent in the clear, and only then does the socket
 * upgrade to TLS. Those capabilities decide result-set framing
 * (CLIENT_DEPRECATE_EOF) and where the statement text begins
 * (CLIENT_QUERY_ATTRIBUTES), so we have to observe the handshake through the
 * raw read()/write() hooks and then join that state up with the SSL_* traffic
 * that follows. The fd is the only identifier common to both phases --
 * SSL_get_fd() bridges from an SSL* back to it.
 *
 * Without this the capabilities default to zero and both of the above are
 * guessed, which is the exact failure mode this project has hit before.
 */
/* Deliberately heap-allocated and never freed.
 *
 * A preload library outlives its own static destructors: close() in
 * particular is called by libc during process teardown, after namespace-scope
 * objects have already been destroyed. Touching a destroyed std::map or
 * std::mutex from there is undefined behaviour, and in practice aborts. The
 * standard fix for interposition libraries is to leak these on purpose --
 * the process is exiting anyway.
 */
std::mutex &conn_lock()
{
	static std::mutex *m = new std::mutex();

	return *m;
}

std::map<int, Connection> &conns()
{
	static std::map<int, Connection> *m = new std::map<int, Connection>();

	return *m;
}

Connection &conn_for(int fd)
{
	std::lock_guard<std::mutex> g(conn_lock());

	return conns()[fd];
}

void forget_conn(int fd)
{
	std::lock_guard<std::mutex> g(conn_lock());

	conns().erase(fd);
}

int (*real_SSL_get_fd)(const SSL *);

int fd_of(SSL *ssl)
{
	resolve((void **)&real_SSL_get_fd, "SSL_get_fd");
	return real_SSL_get_fd ? real_SSL_get_fd(ssl) : -1;
}

/* What a hit owes the caller. Per-thread because a suppressed query and its
 * injected response always happen on the same thread, back to back. */
thread_local std::vector<uint8_t> t_inject;
thread_local size_t t_inject_off;
thread_local bool t_armed;

std::string cacheKey(const Connection &c, const std::string &sql)
{
	/* Scoped to the database so identical text against different schemas
	 * cannot collide. Deliberately simple for now -- user identity and
	 * session variables (time_zone, sql_mode, charset) can also change
	 * what a query returns, and a production key would include them. */
	(void)c;
	return "qc:" + sql;
}

/* Serve a hit: renumber the cached bytes to this connection's sequence and
 * hand them to the caller.
 *
 * Renumbering is what makes replay legal. MySQL resets the packet sequence id
 * at the start of every command, so a response captured during one command
 * lines up at the start of another -- but only after the ids are rewritten to
 * match where this connection actually is.
 */
bool armInjection(std::vector<uint8_t> resp, uint8_t start_seq)
{
	if (!renumber(resp, start_seq)) {
		logf("cached entry is not a well-formed packet stream; ignoring");
		return false;
	}
	t_inject = std::move(resp);
	t_inject_off = 0;
	t_armed = true;
	return true;
}

/* --- outgoing: watch queries, serve hits --------------------------------
 *
 * Returns true if the caller should suppress the real write.
 */
/* Observe the plaintext handshake on the raw socket, before TLS exists.
 * Called from the read()/write() hooks, never from the SSL_* ones. */
/* Does this buffer actually begin with a well-formed MySQL packet that
 * accounts for exactly its length?
 *
 * Necessary because parseClientHandshake() accepts any buffer of 32+ bytes --
 * it has no way to know what it is looking at. Without this check the
 * plaintext hooks happily "parse" a TLS ClientHello, or a write to stdout, as
 * a MySQL handshake and poison the connection's capabilities with garbage.
 * Requiring the declared payload length to match the buffer exactly is a
 * cheap, strong filter. */
bool looksLikeMysqlPacket(const uint8_t *p, size_t len)
{
	if (len <= mysql::kHeaderLen) {
		return false;
	}
	uint32_t plen = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);

	return plen == len - mysql::kHeaderLen;
}

void observeHandshakeOut(int fd, const void *buf, size_t len)
{
	Connection &c = conn_for(fd);
	const uint8_t *p = (const uint8_t *)buf;
	ClientHandshake ch;

	/* Once the SSLRequest has gone out, everything further on this socket
	 * is TLS records. Continuing to parse them as MySQL is how the
	 * capabilities got corrupted before this guard existed. */
	if (c.handshake_done || c.tls) {
		return;
	}
	if (!looksLikeMysqlPacket(p, len)) {
		return;
	}
	if (!parseClientHandshake(p + mysql::kHeaderLen, len - mysql::kHeaderLen, ch)) {
		return;
	}
	c.caps = negotiate(c.server_caps, ch.capabilities);
	if (ch.ssl_request) {
		/* Truncated form: the connection is about to go encrypted.
		 * This is the reliable TLS signal -- far better than trying to
		 * infer it from whether later bytes parse as MySQL, since the
		 * greeting is plaintext on every connection either way. */
		c.tls = true;
		logf("fd %d: TLS upgrade requested; client caps=0x%08x", fd,
		     ch.capabilities);
	} else {
		c.handshake_done = true;
		logf("fd %d: handshake done; caps=0x%08x deprecate_eof=%d query_attrs=%d",
		     fd, c.caps, (c.caps & CLIENT_DEPRECATE_EOF) ? 1 : 0,
		     (c.caps & CLIENT_QUERY_ATTRIBUTES) ? 1 : 0);
	}
}

void observeHandshakeIn(int fd, const void *buf, size_t len)
{
	Connection &c = conn_for(fd);
	mysql::MessageReader r;
	mysql::Message m;
	ServerHandshake sh;

	if (c.server_caps != 0 || c.tls) {
		return;
	}
	if (!looksLikeMysqlPacket((const uint8_t *)buf, len)) {
		return;
	}
	r.append((const uint8_t *)buf, len);
	if (!r.next(m)) {
		return;
	}
	if (!parseServerHandshake(m.payload.data(), m.payload.size(), sh)) {
		return;
	}
	c.server_caps = sh.capabilities;
	logf("fd %d: server greeting %s caps=0x%08x", fd, sh.server_version.c_str(),
	     sh.capabilities);
}

bool onWrite(int fd, const void *buf, size_t len)
{
	ensureInit();
	if (!g_cfg.enabled || len < mysql::kHeaderLen || fd < 0) {
		return false;
	}

	Connection &c = conn_for(fd);
	const uint8_t *p = (const uint8_t *)buf;

	/* If the handshake was observed in plaintext we already have the
	 * negotiated capabilities. If it was not -- for instance because this
	 * library attached mid-connection -- fall back to whatever the client
	 * advertises here, which still beats assuming zero. */
	if (!c.handshake_done) {
		ClientHandshake ch;

		if (parseClientHandshake(p + mysql::kHeaderLen, len - mysql::kHeaderLen,
					  ch) &&
		    !ch.ssl_request) {
			c.caps = negotiate(c.server_caps, ch.capabilities);
			c.handshake_done = true;
			logf("fd %d: handshake seen post-TLS; caps=0x%08x", fd, c.caps);
			return false;
		}
	}

	std::string_view sql;

	if (!extractQuery(p + mysql::kHeaderLen, len - mysql::kHeaderLen, c.caps, sql)) {
		return false; /* not a COM_QUERY we understand */
	}

	std::string stmt = trim(std::string(sql));

	c.reset();

	/* Track the response to EVERY statement, cacheable or not. This is how
	 * transaction state is learned: the IN_TRANS flag arrives on the
	 * response to whatever opened the transaction, and that statement is
	 * not itself something we would cache. */
	c.awaiting_response = true;
	c.tracker.begin(c.caps);
	c.response_reader.reset();

	if (c.in_transaction) {
		/* Reads inside a transaction may observe uncommitted state.
		 * Neither serve nor populate the cache until it ends. */
		logf("in transaction; bypassing cache for: %s", stmt.c_str());
		return false;
	}
	if (!g_cfg.cacheable.count(stmt)) {
		return false;
	}

	/* The response to this command must start at the sequence id
	 * immediately after the request packet's own. */
	uint8_t start_seq = (uint8_t)(p[3] + 1);
	std::vector<uint8_t> hit;
	bool found;

	{
		std::lock_guard<std::mutex> g(valkey_lock());

		valkey().connect(g_cfg.valkey_host, g_cfg.valkey_port);
		found = valkey().get(cacheKey(c, stmt), hit);
	}

	if (found && !hit.empty() && armInjection(std::move(hit), start_seq)) {
		logf("HIT  %s", stmt.c_str());
		return true; /* suppress: the server is never asked */
	}

	logf("MISS %s", stmt.c_str());
	c.pending_query = stmt;
	c.capturing = true;
	return false;
}

/* --- incoming: capture responses, complete hits ------------------------- */

void onRead(int fd, const void *buf, size_t len)
{
	if (fd < 0) {
		return;
	}

	Connection &c = conn_for(fd);

	if (!c.awaiting_response) {
		return;
	}

	/* Bytes are only hoarded for statements we mean to cache; the reader
	 * runs for all of them, because transaction state has to be observed
	 * regardless. */
	if (c.capturing) {
		c.captured.insert(c.captured.end(), (const uint8_t *)buf,
				   (const uint8_t *)buf + len);
	}
	c.response_reader.append((const uint8_t *)buf, len);

	mysql::Message m;

	while (c.response_reader.next(m)) {
		if (!c.tracker.feed(m)) {
			continue;
		}

		/* Response complete. */
		bool ok = !c.tracker.poisoned();

		if (c.tracker.inTransaction()) {
			/* The server has told us a transaction is open. Stop
			 * caching on this connection until it closes. */
			c.in_transaction = true;
			ok = false;
			logf("transaction opened; caching disabled on this "
			     "connection");
		} else {
			c.in_transaction = false;
		}

		if (ok && !c.pending_query.empty() && !c.captured.empty()) {
			std::lock_guard<std::mutex> g(valkey_lock());

			valkey().connect(g_cfg.valkey_host, g_cfg.valkey_port);
			if (valkey().setex(cacheKey(c, c.pending_query), c.captured,
					    g_cfg.ttl)) {
				logf("STORED %s (%zu bytes, ttl=%ds)",
				     c.pending_query.c_str(), c.captured.size(),
				     g_cfg.ttl);
			}
		}
		c.reset();
		break;
	}
}

/* Copy the next slice of an armed injection into the caller's buffer. */
int drainInjection(void *buf, size_t cap)
{
	size_t left = t_inject.size() - t_inject_off;
	size_t n = left < cap ? left : cap;

	if (n == 0) {
		t_armed = false;
		t_inject.clear();
		return 0;
	}
	memcpy(buf, t_inject.data() + t_inject_off, n);
	t_inject_off += n;
	if (t_inject_off >= t_inject.size()) {
		t_armed = false;
		t_inject.clear();
		t_inject_off = 0;
	}
	return (int)n;
}

} // namespace

/* --- interposed symbols ------------------------------------------------- */

extern "C" {

int SSL_write(SSL *ssl, const void *buf, int num)
{
	ensureInit();
	{
		HookGuard g;

		if (g.ok && num > 0 && onWrite(fd_of(ssl), buf, (size_t)num)) {
			return num; /* suppressed; report success */
		}
	}
	resolve((void **)&real_SSL_write, "SSL_write");
	return real_SSL_write(ssl, buf, num);
}

int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
{
	ensureInit();
	{
		HookGuard g;

		if (g.ok && num > 0 && onWrite(fd_of(ssl), buf, num)) {
			if (written) {
				*written = num;
			}
			return 1;
		}
	}
	resolve((void **)&real_SSL_write_ex, "SSL_write_ex");
	return real_SSL_write_ex(ssl, buf, num, written);
}

/* Plaintext side. Two jobs: hold the client off while a cached response is
 * owed, and watch the pre-TLS handshake go by so the negotiated capabilities
 * are known rather than assumed.
 *
 * EINTR rather than EAGAIN for the hold-off: it is legal on both blocking and
 * non-blocking descriptors, whereas EAGAIN nominally cannot occur on a
 * blocking one and some client code treats it as fatal there.
 */
ssize_t read(int fd, void *buf, size_t count)
{
	ensureInit();
	if (t_armed) {
		errno = EINTR;
		return -1;
	}

	ssize_t ret = real_read(fd, buf, count);

	if (ret > 0) {
		HookGuard g;

		if (g.ok) {
			observeHandshakeIn(fd, buf, (size_t)ret);
		}
	}
	return ret;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	ensureInit();
	if (t_armed) {
		errno = EINTR;
		return -1;
	}

	ssize_t ret = real_recv(fd, buf, len, flags);

	if (ret > 0) {
		HookGuard g;

		if (g.ok) {
			observeHandshakeIn(fd, buf, (size_t)ret);
		}
	}
	return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
	ensureInit();
	{
		HookGuard g;

		if (g.ok && count > 0) {
			observeHandshakeOut(fd, buf, count);
		}
	}
	resolve((void **)&real_write, "write");
	return real_write(fd, buf, count);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	ensureInit();
	{
		HookGuard g;

		if (g.ok && len > 0) {
			observeHandshakeOut(fd, buf, len);
		}
	}
	resolve((void **)&real_send, "send");
	return real_send(fd, buf, len, flags);
}

/* Connections are keyed by fd, and fds are recycled. Without this a later
 * connection would inherit the previous occupant's capabilities and
 * transaction state. */
int close(int fd)
{
	ensureInit();
	{
		HookGuard g;

		if (g.ok && fd >= 0) {
			forget_conn(fd);
		}
	}
	resolve((void **)&real_close, "close");
	return real_close(fd);
}

int SSL_read(SSL *ssl, void *buf, int num)
{
	ensureInit();
	if (t_armed) {
		int n = drainInjection(buf, (size_t)num);

		if (n > 0) {
			return n;
		}
	}
	resolve((void **)&real_SSL_read, "SSL_read");
	int ret = real_SSL_read(ssl, buf, num);

	if (ret > 0) {
		HookGuard g;

		if (g.ok) {
			onRead(fd_of(ssl), buf, (size_t)ret);
		}
	}
	return ret;
}

int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
{
	ensureInit();
	if (t_armed) {
		int n = drainInjection(buf, num);

		if (n > 0) {
			if (readbytes) {
				*readbytes = (size_t)n;
			}
			return 1;
		}
	}
	resolve((void **)&real_SSL_read_ex, "SSL_read_ex");
	int ret = real_SSL_read_ex(ssl, buf, num, readbytes);

	if (ret == 1 && readbytes && *readbytes > 0) {
		HookGuard g;

		if (g.ok) {
			onRead(fd_of(ssl), buf, *readbytes);
		}
	}
	return ret;
}

} // extern "C"
