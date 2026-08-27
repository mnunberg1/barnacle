// SPDX-License-Identifier: GPL-2.0
/*
 * main.cpp - the DAEMON.
 *
 * Owns everything shared: it loads KCLIENT, creates the maps and the arena,
 * builds the dpipe pool, and answers requests. Clients never talk to Valkey
 * themselves; they ask the daemon, and the answer comes back through a socket
 * they were already waiting on.
 *
 * Flow for one intercepted statement:
 *
 *   1. UCLIENT decides a statement is worth intercepting, pops a dpipe index
 *      off dpipe_freelist, records the statement in that dpipe, splices its
 *      own socket to the pipe, and wakes the daemon.
 *
 *   2. The daemon resolves the statement -- arena, then Valkey -- and writes
 *      a four-byte reply into the pipe.
 *
 *   3. KCLIENT redirects those bytes into the client socket's receive queue,
 *      so a client in recv() or epoll_wait() wakes exactly as it would for a
 *      real server response.
 *
 *   4. On AGENT_OK the payload is NOT in that reply. It is in the arena,
 *      which the client already has mapped, so a result set is never copied
 *      through the control path.
 *
 * --- how the daemon learns there is work ----------------------------------
 *
 * The client writes a byte on its own (already spliced) socket, which the
 * redirect delivers to the dpipe the daemon is holding. So the notification
 * arrives on the same descriptor the reply will go out on, and the daemon
 * needs no separate channel at all.
 *
 * architecture.txt lists this as one of three options for wakeup_daemon() and
 * worries it is expensive with many connections. With epoll it is not: the
 * cost is proportional to ready descriptors, not to the pool size. The
 * ringbuffer alternatives have a direction problem -- BPF_MAP_TYPE_RINGBUF is
 * written by BPF and read by userspace, USER_RINGBUF is the reverse, and here
 * both ends are userspace. Swapping mechanisms later is contained to
 * wakeupWait() below.
 */
#include "agent/arena.h"
#include "agent/dpipes.h"
#include "common/defs.h"
#include "common/mysql/resultset.h"
#include "common/stmtlist.h"
#include "common/valkey.h"

#include <cerrno>
#include <ctime>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/epoll.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "kclient.skel.h"

namespace {

volatile sig_atomic_t g_exiting;

uint64_t now_ns()
{
	struct timespec ts {};

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/*
 * Has the arena copy outlived its TTL?
 *
 * The arena is a cache tier in its own right, not a mirror of Valkey -- so it
 * needs its own expiry. Without this a response is served from local memory
 * forever: Valkey expiring the key, or being flushed entirely, would have no
 * effect at all, because nothing would ever look there again.
 *
 * A record with no timestamp has never been published; treat it as expired so
 * the first request fetches rather than serving whatever the pointer happens
 * to reference.
 */
bool expired(const struct stmt *st, uint64_t now)
{
	if (!st->stmt_ttl) {
		return false; /* ttl 0 means "do not expire" */
	}
	if (!st->stmt_ts) {
		return true;
	}
	return now - st->stmt_ts > (uint64_t)st->stmt_ttl * 1000000000ull;
}

void on_signal(int)
{
	g_exiting = 1;
}

struct Options {
	std::string stmt_list;
	std::string valkey_host = "valkey";
	uint16_t valkey_port = 6379;
	uint16_t mysql_port = 3306;
	uint32_t pipes = 64;
	uint32_t max_stmts = QC_MAX_STMTS;
	uint32_t max_pipes = QC_MAX_PIPES;
	int ttl = 60;
	int error_ttl = 30;
	bool verbose = false;
};

class Daemon {
public:
	explicit Daemon(const Options &o) : opt(o)
	{
	}

	bool start();
	void run();
	void stop();

private:
	bool attachSplices();
	bool seedStatements();
	void serve(int fd);
	void reply(int fd, uint8_t status, uint32_t stmt_id);
	bool store(uint32_t key, const std::vector<uint8_t> &body);
	bool readExactly(int fd, void *buf, size_t n);

	Options opt;
	struct kclient_bpf *skel = nullptr;
	qcd::Arena arena;
	qcd::Pool pool;
	cache::StmtList list;
	cache::Valkey valkey;
	std::unordered_map<int, uint32_t> key_of_fd;
	int epfd = -1;
	bool c2d_on = false, d2c_on = false;
};

bool Daemon::attachSplices()
{
	/* One attach per side. Which map a program is attached to is how it
	 * knows its direction -- sk_msg has no way to tell from the context. */
	if (bpf_prog_attach(bpf_program__fd(skel->progs.splice_c2d),
			    bpf_map__fd(skel->maps.cpipe_map), BPF_SK_MSG_VERDICT,
			    0)) {
		fprintf(stderr, "daemon: attach client->dpipe failed: %s\n",
			strerror(errno));
		return false;
	}
	c2d_on = true;

	if (bpf_prog_attach(bpf_program__fd(skel->progs.splice_d2c),
			    bpf_map__fd(skel->maps.dpipe_map), BPF_SK_MSG_VERDICT, 0)) {
		fprintf(stderr, "daemon: attach dpipe->client failed: %s\n",
			strerror(errno));
		return false;
	}
	d2c_on = true;
	return true;
}

/*
 * Publish the administrator's list into stmts_map.
 *
 * Each record goes in the arena, and the map holds a pointer to it -- the map
 * cannot hold the record itself, because a dpipe refers to a statement by
 * pointer and a pointer into a map value means nothing to another process.
 *
 * Records start with no payload rather than PENDING: nothing is being fetched
 * yet, and a client arriving before the first fetch should cause one rather
 * than wait on a fetch that is not happening.
 */
bool Daemon::seedStatements()
{
	uint32_t id = 1;

	if (opt.stmt_list.empty()) {
		fprintf(stderr, "daemon: no statement list given; nothing will be "
				"intercepted\n");
		return true;
	}

	std::string err;

	if (!list.load(opt.stmt_list, err)) {
		fprintf(stderr, "daemon: %s\n", err.c_str());
		return false;
	}

	int fd = bpf_map__fd(skel->maps.stmts_map);

	for (const std::string &sql : list.all()) {
		struct stmt_key key {};
		struct stmt *rec;
		char *txt;
		stmt_ref ref;

		if (sql.size() > QC_STMT_MAX - 1) {
			fprintf(stderr,
				"daemon: statement too long to cache (%zu > %d), "
				"skipping: %.60s...\n",
				sql.size(), QC_STMT_MAX - 1, sql.c_str());
			continue;
		}

		txt = (char *)arena.put(sql.c_str(), sql.size() + 1);
		rec = (struct stmt *)arena.alloc(sizeof(*rec));
		if (!txt || !rec) {
			fprintf(stderr, "daemon: arena exhausted seeding statements\n");
			return false;
		}

		/* Zeroed, so stmt_data is NULL. That is what marks it unfetched:
		 * STMT_S_LOCAL is the zero value, so state alone cannot say
		 * "nothing here" -- the payload pointer does. */
		memset(rec, 0, sizeof(*rec));
		rec->stmt_txt = txt;
		rec->stmt_len = sql.size();
		rec->stmt_id = id++;
		rec->stmt_ttl = (uint32_t)opt.ttl;

		memcpy(key.text, sql.data(), sql.size());
		ref = (stmt_ref)(unsigned long)rec;
		if (bpf_map_update_elem(fd, &key, &ref, BPF_ANY)) {
			fprintf(stderr, "daemon: cannot publish statement: %s\n",
				strerror(errno));
			return false;
		}
	}
	fprintf(stderr, "daemon: %zu statement(s) from %s\n", list.size(),
		opt.stmt_list.c_str());
	return true;
}

bool Daemon::start()
{
	LIBBPF_OPTS(bpf_object_open_opts, oo, .pin_root_path = QC_PIN_DIR);

	skel = kclient_bpf__open_opts(&oo);
	if (!skel) {
		fprintf(stderr, "daemon: cannot open BPF skeleton\n");
		return false;
	}

	/* Sizes are compile-time defaults; resize before load so a deployment
	 * can tune them without a rebuild. */
	bpf_map__set_max_entries(skel->maps.stmts_map, opt.max_stmts);
	bpf_map__set_max_entries(skel->maps.dpipe_map, opt.max_pipes);
	bpf_map__set_max_entries(skel->maps.cpipe_map, opt.max_pipes);
	bpf_map__set_max_entries(skel->maps.dpipe_freelist, opt.max_pipes);
	bpf_map__set_max_entries(skel->maps.dpipes, opt.max_pipes);

	if (kclient_bpf__load(skel)) {
		fprintf(stderr, "daemon: BPF load failed: %s (need root?)\n",
			strerror(errno));
		return false;
	}

	{
		__u32 k, v;

		k = QC_CFG_ENABLED;
		v = 1;
		bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);
		k = QC_CFG_PORT;
		v = opt.mysql_port;
		bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);
		k = QC_CFG_ERROR_TTL;
		v = (__u32)opt.error_ttl;
		bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);
	}

	if (!arena.open(bpf_map__fd(skel->maps.arena))) {
		return false;
	}
	if (!attachSplices()) {
		return false;
	}
	if (!seedStatements()) {
		return false;
	}

	qcd::PoolMaps pm;

	pm.dpipe_map = bpf_map__fd(skel->maps.dpipe_map);
	pm.dpipes = bpf_map__fd(skel->maps.dpipes);
	pm.freelist = bpf_map__fd(skel->maps.dpipe_freelist);
	pm.meta = bpf_map__fd(skel->maps.dpipes_meta_map);
	pm.info = bpf_map__fd(skel->maps.pipe_sk_info_map);
	if (!pool.init(pm, opt.pipes)) {
		fprintf(stderr, "daemon: pipe pool init failed\n");
		return false;
	}

	epfd = epoll_create1(0);
	if (epfd < 0) {
		return false;
	}
	for (uint32_t i = 0; i < opt.pipes; i++) {
		qcd::Pipe *p = pool.byKey(i);
		struct epoll_event ev {};

		ev.events = EPOLLIN;
		ev.data.fd = p->sfd;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, p->sfd, &ev)) {
			fprintf(stderr, "daemon: epoll_ctl failed: %s\n",
				strerror(errno));
			return false;
		}
		key_of_fd[p->sfd] = p->key;
	}

	valkey.connect(opt.valkey_host, opt.valkey_port);
	if (!valkey.healthy()) {
		fprintf(stderr,
			"daemon: warning -- Valkey %s:%u unreachable; every lookup "
			"will report CACHE_ERROR\n",
			opt.valkey_host.c_str(), (unsigned)opt.valkey_port);
	}

	fprintf(stderr,
		"daemon: ready -- %u pipes, %u stmt slots, arena %zu KiB at %#llx,\n"
		"        pins under %s, cache %s:%u, mysql port %u\n",
		opt.pipes, opt.max_stmts, arena.capacity() / 1024,
		(unsigned long long)QC_ARENA_VA, QC_PIN_DIR, opt.valkey_host.c_str(),
		(unsigned)opt.valkey_port, (unsigned)opt.mysql_port);
	return true;
}

void Daemon::reply(int sfd, uint8_t status, uint32_t stmt_id)
{
	struct agent_reply r {};

	r.status = status;
	r.stmt_id = stmt_id;

	/* On sfd, which is the socket dpipe_map holds -- that is what lets
	 * sk_msg see this send at all. The redirect puts these four bytes in
	 * the client's receive queue, which is what wakes it. On AGENT_OK the
	 * payload is already in the arena. */
	if (write(sfd, &r, sizeof(r)) != (ssize_t)sizeof(r)) {
		fprintf(stderr, "daemon: short reply on fd %d: %s\n", sfd,
			strerror(errno));
	}
}

bool Daemon::readExactly(int fd, void *buf, size_t n)
{
	uint8_t *p = (uint8_t *)buf;
	size_t got = 0;

	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);

		if (r <= 0) {
			return false;
		}
		got += (size_t)r;
	}
	return true;
}

/*
 * Take a response a client observed and put it in the cache.
 *
 * The bytes arrive already canonicalised -- the client parsed what the server
 * sent and re-encoded it under QC_CANONICAL_CAPS -- so what is stored no
 * longer carries the framing decisions of the connection it came from. It
 * goes to Valkey for other machines and into the arena for this one.
 */
bool Daemon::store(uint32_t key, const std::vector<uint8_t> &body)
{
	struct dpipe rec {};

	if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.dpipes), &key, &rec) ||
	    !rec.stmt) {
		return false;
	}

	struct stmt *st = (struct stmt *)rec.stmt;
	std::string sql(st->stmt_txt ? (const char *)st->stmt_txt : "",
			(size_t)st->stmt_len);

	if (sql.empty() || body.empty()) {
		return false;
	}

	/* Refuse anything that does not parse as a result set. A client should
	 * not be able to poison the cache with bytes nobody can replay, and
	 * the check is cheap next to the fetch that produced them. */
	mysql::ResultSet rs;

	if (!mysql::parseResultSet(body.data(), body.size(), QC_CANONICAL_CAPS, rs)) {
		fprintf(stderr, "daemon: refusing unparseable response for %.40s\n",
			sql.c_str());
		return false;
	}
	if (rs.status & mysql::SERVER_STATUS_IN_TRANS) {
		/* Produced inside a transaction: may reflect uncommitted state
		 * private to that session. */
		return false;
	}

	if (valkey.healthy() || valkey.connect(opt.valkey_host, opt.valkey_port)) {
		valkey.setex("qc:" + sql, body, opt.ttl);
	}

	/* Bytes into the arena first, then the record that points at them: a
	 * reader that sees a payload must be able to trust it is there. */
	void *p = arena.put(body.data(), body.size());

	if (!p) {
		return false;
	}

	struct timespec ts {};

	clock_gettime(CLOCK_MONOTONIC, &ts);
	st->stmt_data = p;
	st->stmt_data_len = body.size();
	st->stmt_ttl = (uint32_t)opt.ttl;
	st->stmt_ts = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
	__atomic_store_n(&st->stmt_state, STMT_S_LOCAL, __ATOMIC_RELEASE);

	if (opt.verbose) {
		fprintf(stderr, "daemon: STORE %zu bytes, %zu row(s)  %.40s\n",
			body.size(), rs.rows.size(), sql.c_str());
	}
	return true;
}

void Daemon::serve(int fd)
{
	struct qc_req req {};

	if (!readExactly(fd, &req, sizeof(req))) {
		return;
	}

	auto it = key_of_fd.find(fd);

	if (it == key_of_fd.end()) {
		return;
	}

	uint32_t key = it->second;

	if (req.kind == QC_REQ_STORE) {
		std::vector<uint8_t> body(req.len);

		if (req.len == 0 || req.len > QC_STORE_MAX ||
		    !readExactly(fd, body.data(), req.len)) {
			pool.release(key);
			return;
		}
		store(key, body);
		/* No reply: the client is not waiting. It already has the
		 * answer -- that is where these bytes came from. */
		pool.release(key);
		return;
	}
	struct dpipe rec {};

	if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.dpipes), &key, &rec)) {
		fprintf(stderr, "daemon: no record for dpipe %u\n", key);
		return;
	}

	/*
	 * Splice our own end before answering.
	 *
	 * The client spliced its socket to us, but that only covers
	 * client->daemon. sk_msg reads the sk_storage of whichever socket is
	 * SENDING, so for the reply to be redirected the dpipe socket needs its
	 * own entry naming the client. Without this the write goes to the
	 * pipe's far end and the client waits forever -- which is exactly the
	 * silent hang this whole design exists to avoid.
	 */
	{
		qcd::Pipe *p = pool.byKey(key);
		struct pipe_sk_info ci {};

		ci.key = key; /* dpipe[key] is spliced to cpipe[key] */
		ci.paired = 1;
		/* On sfd: the socket we are about to send from, and the one
		 * sk_msg will consult. */
		if (!p || bpf_map_update_elem(bpf_map__fd(skel->maps.pipe_sk_info_map),
					      &p->sfd, &ci, BPF_ANY)) {
			fprintf(stderr, "daemon: cannot splice dpipe %u back: %s\n", key,
				strerror(errno));
			return;
		}
	}

	/* The wakeup carries nothing but the fact that it happened. Everything
	 * needed is reachable from the pipe: the client wrote its statement
	 * into the record before waking us. */
	if (!rec.stmt) {
		if (opt.verbose) {
			fprintf(stderr, "daemon: dpipe %u woke with no statement\n", key);
		}
		reply(fd, AGENT_CACHE_ERROR, 0);
		pool.release(key);
		return;
	}

	struct stmt *st = (struct stmt *)rec.stmt;
	uint64_t now = now_ns();
	uint8_t status;

	/* A hit needs all three: the right state, an actual payload, and one
	 * that has not aged out. STMT_S_LOCAL is the zero value, so state
	 * alone would call every unseeded record a hit. */
	if (st->stmt_state == STMT_S_LOCAL && st->stmt_data && !expired(st, now)) {
		status = AGENT_OK;
	} else if (!valkey.healthy() &&
		   !valkey.connect(opt.valkey_host, opt.valkey_port)) {
		status = AGENT_CACHE_ERROR;
	} else {
		std::string sql(st->stmt_txt ? (const char *)st->stmt_txt : "",
				(size_t)st->stmt_len);
		std::vector<uint8_t> payload;

		if (!sql.empty() && valkey.get("qc:" + sql, payload) && !payload.empty()) {
			/* Bytes into the arena FIRST, then the record that
			 * points at them. A reader that sees STMT_S_LOCAL must
			 * be able to trust the payload is already there. */
			void *p = arena.put(payload.data(), payload.size());

			if (p) {
				st->stmt_data = p;
				st->stmt_data_len = payload.size();
				st->stmt_ttl = (uint32_t)opt.ttl;
				st->stmt_ts = now;
				__atomic_store_n(&st->stmt_state, STMT_S_LOCAL,
						 __ATOMIC_RELEASE);
				status = AGENT_OK;
			} else {
				status = AGENT_CACHE_ERROR;
			}
		} else {
			/* Nothing upstream either. Drop the stale local copy so
			 * the next request re-fetches rather than serving bytes
			 * we have just been told are gone. */
			st->stmt_data = 0;
			st->stmt_data_len = 0;
			st->stmt_ts = 0;
			status = AGENT_WRITE_THROUGH;
		}
	}

	if (opt.verbose) {
		const char *what = status == AGENT_OK	       ? "HIT"
				   : status == AGENT_WRITE_THROUGH ? "MISS"
								   : "ERROR";

		fprintf(stderr, "daemon: %-5s dpipe=%u stmt=%u\n", what, key,
			st->stmt_id);
	}

	reply(fd, status, st->stmt_id);

	/* The client releases the dpipe, not us. architecture.txt puts that on
	 * the client, and releasing here as well would push the same key onto
	 * the freelist twice -- handing one pipe to two connections. */
}

void Daemon::run()
{
	std::vector<struct epoll_event> events(64);

	while (!g_exiting) {
		int n = epoll_wait(epfd, events.data(), (int)events.size(), 500);

		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		for (int i = 0; i < n; i++) {
			serve(events[i].data.fd);
		}
	}
}

void Daemon::stop()
{
	pool.shutdown();
	if (epfd >= 0) {
		::close(epfd);
	}
	if (c2d_on && skel) {
		bpf_prog_detach2(bpf_program__fd(skel->progs.splice_c2d),
				 bpf_map__fd(skel->maps.cpipe_map),
				 BPF_SK_MSG_VERDICT);
	}
	if (d2c_on && skel) {
		bpf_prog_detach2(bpf_program__fd(skel->progs.splice_d2c),
				 bpf_map__fd(skel->maps.dpipe_map), BPF_SK_MSG_VERDICT);
	}
	arena.close();
	if (skel) {
		kclient_bpf__destroy(skel);
	}
}

void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"  -l PATH   statement list to cache (e.g. demo/config/cache.list)\n"
		"  -H HOST   valkey host (default valkey)\n"
		"  -P PORT   valkey port (default 6379)\n"
		"  -m PORT   mysql port to classify (default 3306)\n"
		"  -n N      dpipe pool size (default 64)\n"
		"  -S N      max cacheable statements (default %d)\n"
		"  -C N      max concurrent hijacked connections (default %d)\n"
		"  -t SECS   cache TTL (default 60)\n"
		"  -e SECS   error TTL (default 30)\n"
		"  -v        verbose\n",
		prog, QC_MAX_STMTS, QC_MAX_PIPES);
}

} // namespace

int main(int argc, char **argv)
{
	Options opt;

	for (int i = 1; i < argc; i++) {
		std::string a = argv[i];
		auto next = [&]() -> const char * {
			if (i + 1 >= argc) {
				usage(argv[0]);
				exit(1);
			}
			return argv[++i];
		};

		if (a == "-l") {
			opt.stmt_list = next();
		} else if (a == "-H") {
			opt.valkey_host = next();
		} else if (a == "-P") {
			opt.valkey_port = (uint16_t)atoi(next());
		} else if (a == "-m") {
			opt.mysql_port = (uint16_t)atoi(next());
		} else if (a == "-n") {
			opt.pipes = (uint32_t)atoi(next());
		} else if (a == "-S") {
			opt.max_stmts = (uint32_t)atoi(next());
		} else if (a == "-C") {
			opt.max_pipes = (uint32_t)atoi(next());
		} else if (a == "-t") {
			opt.ttl = atoi(next());
		} else if (a == "-e") {
			opt.error_ttl = atoi(next());
		} else if (a == "-v") {
			opt.verbose = true;
		} else {
			usage(argv[0]);
			return 1;
		}
	}

	if (opt.pipes > opt.max_pipes) {
		opt.pipes = opt.max_pipes;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	Daemon d(opt);

	if (!d.start()) {
		d.stop();
		return 1;
	}
	d.run();
	d.stop();
	fprintf(stderr, "daemon: exiting\n");
	return 0;
}
