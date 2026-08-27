// SPDX-License-Identifier: GPL-2.0
#include "uclient/shared.h"

#include "common/defs.h"
#include "uclient/bpfsys.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <sys/mman.h>
#include <unistd.h>

#define PIN(name) QC_PIN_DIR "/" name

namespace qcagent {

/* The mirrored definitions in shared.h must match the real ones. This is the
 * one file that can see both. */
static_assert(sizeof(Reply) == sizeof(struct agent_reply),
	      "qcagent::Reply has drifted from struct agent_reply");
static_assert(REPLY_OK == AGENT_OK && REPLY_WRITE_THROUGH == AGENT_WRITE_THROUGH &&
		      REPLY_CACHE_ERROR == (uint8_t)AGENT_CACHE_ERROR,
	      "qcagent reply statuses have drifted from enum agent_status");
static_assert(CANONICAL_CAPS == QC_CANONICAL_CAPS,
	      "qcagent::CANONICAL_CAPS has drifted from QC_CANONICAL_CAPS");

namespace {

uint8_t *g_arena;
int g_stmts_fd = -1;
int g_dpipes_fd = -1;
int g_freelist_fd = -1;
int g_meta_fd = -1;
int g_cpipes_fd = -1;
int g_info_fd = -1;

/*
 * Post bytes to the daemon over the spliced socket.
 *
 * A short write is treated as failure rather than retried. This runs on the
 * application's thread inside a TLS call: looping until the kernel accepts
 * the rest is exactly the block we must not introduce. The requests here are
 * a few bytes, or a response the socket buffer has room for; if one does not
 * fit, the statement simply does not get cached this time.
 */
bool post(int fd, const void *buf, size_t n)
{
	ssize_t w = write(fd, buf, n);

	return w == (ssize_t)n;
}

/* Take a dpipe off the freelist. Losing the race is normal and means the
 * query goes to the server as it otherwise would. */
bool popDpipe(uint32_t &key)
{
	struct dpipes_meta meta {};
	uint32_t zero = 0, slot;

	if (qc_bpf_lookup(g_meta_fd, &zero, &meta) || meta.num_free == 0) {
		return false;
	}
	slot = meta.num_free - 1;
	if (qc_bpf_lookup(g_freelist_fd, &slot, &key)) {
		return false;
	}
	meta.num_free = slot;
	return qc_bpf_update(g_meta_fd, &zero, &meta, 0) == 0;
}

void pushDpipe(uint32_t key)
{
	struct dpipes_meta meta {};
	uint32_t zero = 0;

	if (qc_bpf_lookup(g_meta_fd, &zero, &meta)) {
		return;
	}

	uint32_t slot = meta.num_free;

	/* The key must be visible in the slot before num_free admits the slot
	 * exists, or another client could pop an index not yet written. */
	if (qc_bpf_update(g_freelist_fd, &slot, &key, 0)) {
		return;
	}
	meta.num_free = slot + 1;
	qc_bpf_update(g_meta_fd, &zero, &meta, 0);
}

} // namespace

bool openShared()
{
	int fd = qc_bpf_obj_get(PIN("arena"));

	if (fd < 0) {
		fprintf(stderr, "qcagent: no arena pin (daemon not running?)\n");
		return false;
	}

	/* MAP_FIXED: the arena must land where the daemon put it, or the
	 * pointers stored inside it mean nothing here. A different address
	 * would appear to work and then hand out garbage, so fail loudly. */
	void *p = mmap((void *)QC_ARENA_VA, (size_t)QC_ARENA_PAGES * 4096,
		       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);

	if (p != (void *)QC_ARENA_VA) {
		fprintf(stderr, "qcagent: arena did not map at the shared address\n");
		return false;
	}
	g_arena = (uint8_t *)p;

	g_stmts_fd = qc_bpf_obj_get(PIN("stmts_map"));
	g_dpipes_fd = qc_bpf_obj_get(PIN("dpipes"));
	g_freelist_fd = qc_bpf_obj_get(PIN("dpipe_freelist"));
	g_meta_fd = qc_bpf_obj_get(PIN("dpipes_meta_map"));
	g_cpipes_fd = qc_bpf_obj_get(PIN("cpipe_map"));
	g_info_fd = qc_bpf_obj_get(PIN("pipe_sk_info_map"));

	if (g_stmts_fd < 0 || g_dpipes_fd < 0 || g_freelist_fd < 0 || g_meta_fd < 0 ||
	    g_cpipes_fd < 0 || g_info_fd < 0) {
		fprintf(stderr, "qcagent: daemon maps missing under %s\n", QC_PIN_DIR);
		return false;
	}
	return true;
}

bool lookupPayload(const std::string &sql, std::vector<uint8_t> &out, uint32_t &id)
{
	struct stmt_key k {};
	stmt_ref ref = 0;

	if (!g_arena || sql.size() > QC_STMT_MAX - 1) {
		return false;
	}
	memcpy(k.text, sql.data(), sql.size());
	if (qc_bpf_lookup(g_stmts_fd, &k, &ref) || !ref) {
		return false;
	}

	struct stmt *st = (struct stmt *)(unsigned long)ref;

	/* STMT_S_LOCAL is the zero value, so state alone cannot say "present";
	 * the payload pointer is what does. Acquire, to pair with the daemon's
	 * release store: seeing LOCAL must mean the bytes are already there. */
	if (__atomic_load_n(&st->stmt_state, __ATOMIC_ACQUIRE) != STMT_S_LOCAL ||
	    !st->stmt_data || !st->stmt_data_len) {
		return false;
	}

	if (st->stmt_ttl && st->stmt_ts) {
		struct timespec ts {};

		clock_gettime(CLOCK_MONOTONIC, &ts);

		uint64_t now = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;

		if (now > st->stmt_ts &&
		    (now - st->stmt_ts) / 1000000000ull > st->stmt_ttl) {
			return false;
		}
	}

	const uint8_t *p = (const uint8_t *)st->stmt_data;

	out.assign(p, p + st->stmt_data_len);
	id = st->stmt_id;
	return true;
}

bool acquire(const std::string &sql, int sock, uint32_t &key)
{
	struct stmt_key k {};
	stmt_ref ref = 0;

	if (!g_arena || sql.size() > QC_STMT_MAX - 1) {
		return false;
	}

	/* Only statements the administrator listed have a record to point at. */
	memcpy(k.text, sql.data(), sql.size());
	if (qc_bpf_lookup(g_stmts_fd, &k, &ref) || !ref) {
		return false;
	}
	if (!popDpipe(key)) {
		return false;
	}

	struct dpipe rec {};

	if (qc_bpf_lookup(g_dpipes_fd, &key, &rec)) {
		pushDpipe(key);
		return false;
	}

	/* Point the pipe at the statement. This is what lets the request carry
	 * nothing but a key: everything else hangs off the pipe. */
	rec.stmt = (struct stmt *)(unsigned long)ref;
	rec.cpipe_key = key;
	rec.in_use = 1;
	qc_bpf_update(g_dpipes_fd, &key, &rec, 0);

	/* Hijack our own socket. Both calls take a plain fd because we own it;
	 * the daemon could not do this for us even if it wanted to. */
	struct pipe_sk_info si {};

	si.peer_key = key;
	si.paired = 1;
	if (qc_bpf_update(g_cpipes_fd, &key, &sock, 0) ||
	    qc_bpf_update(g_info_fd, &sock, &si, 0)) {
		pushDpipe(key);
		return false;
	}
	return true;
}

bool askLookup(int sock)
{
	struct qc_req req {};

	req.kind = QC_REQ_LOOKUP;
	req.len = 0;
	return post(sock, &req, sizeof(req));
}

bool askStore(int sock, const std::vector<uint8_t> &canonical)
{
	struct qc_req req {};

	if (canonical.empty() || canonical.size() > QC_STORE_MAX) {
		return false;
	}
	req.kind = QC_REQ_STORE;
	req.len = (uint32_t)canonical.size();

	/* Header and body in one write: two would let another thread's request
	 * interleave on the same pipe, and a short second write would leave
	 * the daemon waiting for bytes that never come. */
	std::vector<uint8_t> msg(sizeof(req) + canonical.size());

	memcpy(msg.data(), &req, sizeof(req));
	memcpy(msg.data() + sizeof(req), canonical.data(), canonical.size());
	return post(sock, msg.data(), msg.size());
}

void release(int sock, uint32_t key)
{
	struct pipe_sk_info si {};

	/* Clear `paired` first: while it is set every byte this socket sends
	 * goes to the daemon rather than to the server. */
	qc_bpf_update(g_info_fd, &sock, &si, 0);
	qc_bpf_delete(g_cpipes_fd, &key);
	pushDpipe(key);
}

} // namespace qcagent
