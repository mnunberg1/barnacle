/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
/*
 * defs.h - the structures every component shares.
 *
 * Three very different things include this: the KCLIENT eBPF program compiled
 * for the kernel, the UCLIENT agent Frida injects into each client process,
 * and the ordinary userspace daemon. It is the one place their view of the
 * world has to agree.
 *
 * --- where these actually live --------------------------------------------
 *
 * In a BPF arena, which is what makes the pointers below meaningful. An arena
 * is mapped at the same address in every process that attaches to it, so a
 * `struct stmt *` written by the daemon is the same pointer UCLIENT reads --
 * no offsets, no per-process base, no id-to-object lookup table.
 *
 * That is the whole reason the design can hold pointers at all. Verified
 * available on the target kernel by tests/test_caps.c (BPF_MAP_TYPE_ARENA,
 * mmapable) before anything was built on it.
 *
 * --- what is NOT here ------------------------------------------------------
 *
 * No socket 5-tuple, anywhere. Sockets are named by their index in the
 * SOCKMAP that holds them, and each socket carries its peer's index in its
 * own sk_storage. A 5-tuple would be a second, derived copy of an identity
 * the kernel already has: it has to be computed identically by BPF and by
 * userspace, which encode ports differently; it has no network-namespace
 * discriminator, so two containers can collide; and it can go stale against
 * the socket it claims to name.
 */

/* Included from BPF programs (which have these from vmlinux.h) and from
 * ordinary userspace. Pulling the types in directly makes it self-sufficient
 * in both rather than depending on include order. */
#ifndef __VMLINUX_H__
#include <linux/bpf.h>
#include <linux/types.h>
#endif

/*
 * Arena pointers.
 *
 * Inside a BPF program an arena pointer lives in address space 1, which is
 * how the verifier knows it may be dereferenced without a bounds check
 * against a map value. Userspace sees the same bytes through mmap, where it
 * is an ordinary pointer.
 */
#ifdef __bpf__
#define __arena __attribute__((address_space(1)))
#else
#define __arena
#endif

/*
 * Sizing. These are defaults compiled into the BPF object; the daemon
 * overrides either one at load time with bpf_map__set_max_entries() before
 * the maps are created, so a deployment can tune them without a rebuild.
 */

/* Concurrently hijacked connections. Bounds both SOCKMAPs and the freelist. */
#define QC_MAX_PIPES 4096

/* Distinct cacheable statements. This is an administrator-curated list, not
 * something that grows with traffic, so it is small by nature. */
#define QC_MAX_STMTS 1024

/* Longest statement text that can be matched. Statements longer than this are
 * simply not cacheable. */
#define QC_STMT_MAX 512

/* Largest response UCLIENT will serve from its own in-process copy. Bigger
 * ones are not un-cacheable, they just do not take the local fast path. */
#define QC_LOCAL_MAX 8192

/* Arena size, in pages. Holds statement text and cached response bodies. */
#define QC_ARENA_PAGES 4096 /* 16 MiB at 4K pages */

/*
 * Fixed virtual address the arena is mapped at, in every process.
 *
 * This is the property the whole pointer-based design rests on: if the arena
 * landed wherever each process happened to map it, a `struct stmt *` written
 * by the daemon would mean nothing to a client, and every field below would
 * have to become an offset with a per-process base added back. Pinning the
 * address makes a pointer just a pointer.
 */
#define QC_ARENA_VA (1ULL << 44)

/* Where the maps are pinned, so a process that did not create them can get a
 * descriptor. UCLIENT's loader opens these; the daemon creates them. */
#define QC_PIN_DIR "/sys/fs/bpf/qcache"

/* --- statements ---------------------------------------------------------- */

/*
 * Statements are keyed by their exact text, zero-padded to a fixed width.
 *
 * A hash of the full text rather than a prefix trie: matching is exact byte
 * equality, so a trie would buy nothing here, and a prefix match would be
 * actively wrong -- `WHERE id = 5` is a prefix of `WHERE id = 55`. A trie
 * becomes interesting only if normalized or parameterized matching arrives,
 * and that is a different feature.
 */
struct stmt_key {
	char text[QC_STMT_MAX];
};

struct stmt;

/*
 * NOTE ON THE ZERO VALUE. STMT_S_LOCAL is 0, so a freshly zeroed record reads
 * as "present locally" while pointing at nothing. The invariant that makes
 * that safe, and which every reader must honour:
 *
 *     a statement is a hit only if stmt_state == STMT_S_LOCAL AND
 *     stmt_data is non-NULL.
 *
 * Seeding relies on it: a statement from the list starts zeroed with no
 * payload, which reads as "not fetched yet" rather than as an empty hit.
 */
enum stmt_state {
	/* Present locally in the arena; the bytes are right there. */
	STMT_S_LOCAL = 0,
	/* Someone is already fetching it. Other clients wait rather than each
	 * starting a duplicate fetch of the same thing. */
	STMT_S_PENDING = 1,
	/* The cache is unusable for this statement. Pass through untouched
	 * until OPT_ERROR_TTL has elapsed. */
	STMT_S_ERROR = 2,
};

/*
 * One cacheable statement and whatever is currently known about it.
 *
 * stmt_data points at the cached response bytes in the arena. Keeping the
 * payload out of the control path is deliberate: the hijacked connection is a
 * notification and control channel, so a result set is never copied through a
 * socket that both sides can already see into.
 */
struct stmt {
	const char __arena *stmt_txt;
	__u64 stmt_len;
	__u64 stmt_ts; /* last updated, CLOCK_MONOTONIC ns */
	__u32 stmt_state;
	__u32 stmt_id; /* universal id, stable across processes */
	void __arena *stmt_data;
	__u64 stmt_data_len;
	__u32 stmt_ttl;
};

/*
 * Statement records live in the ARENA, and stmts_map holds pointers to them.
 *
 * They cannot live in the map directly: `struct dpipe` refers to a statement
 * by pointer, and a pointer to a map value is not something another process
 * can follow. Putting the records in the arena makes one representation work
 * for both.
 *
 * That rules out bpf_spin_lock, which is only valid inside a map value, hence
 * stmt_state moving by atomic load/store instead. It is enough: a reader that
 * observes STMT_S_LOCAL with an acquire load is guaranteed to see the payload
 * the writer released before it, and every transition is a single word.
 */
typedef __u64 stmt_ref; /* arena address of a struct stmt, 0 for none */

/* --- connections --------------------------------------------------------- */

enum conn_type {
	CONN_T_UNKNOWN = 0,
	CONN_T_CLEAR = 1,
	CONN_T_SSL = 2,
};

enum txn_state {
	TXN_S_UNKNOWN = 0,
	TXN_S_INACTIVE = 1,
	/* Caching is disabled outright while a transaction is open: reads
	 * inside one may see uncommitted data, and caching them would leak one
	 * session's view into others. */
	TXN_S_ACTIVE = 2,
};

/* A buffer being assembled in the arena. Neither send(2) nor recv(2)
 * necessarily carries a whole protocol message, so both directions have to be
 * accumulated until a decision can be made. */
struct mybuf {
	__u8 __arena *data;
	__u32 len;
	__u32 cap;
};

/*
 * Everything tracked for one client connection.
 *
 * conn_stmt is needed for more than the lookup: it is how the client knows
 * which statement it owes the cache a response for after a WRITE_THROUGH, and
 * what to replay if the daemon never answers.
 */
struct conn_info {
	__u32 conn_type; /* enum conn_type */
	__u32 txn_state; /* enum txn_state */
	struct stmt __arena *conn_stmt;
	__u32 dpipe_id; /* daemon-side sockmap key */
	__u32 cpipe_id; /* client-side sockmap key */
	struct mybuf __arena *request;
	__u64 last_ts;
};

/* --- pipes --------------------------------------------------------------- */

/*
 * Which socket this one is spliced to: an index into the OPPOSITE map. On a
 * client socket it names a dpipe in dpipe_map; on a dpipe it names a client
 * in cpipe_map.
 *
 * Which map that is comes from which program is running, and that is decided
 * at attach time rather than carried here. sk_msg fires only on sendmsg -- it
 * has no ingress invocation and no `op` field -- so the context cannot tell a
 * program which side it is on. Two maps with a program each is what supplies
 * that, statically.
 *
 * Held in sk_storage on the socket itself, so it cannot go stale relative to
 * the socket and is freed when the socket is. A released pipe cannot leave a
 * dangling pairing behind that would misdeliver a later write.
 */
struct pipe_sk_info {
	__u32 peer_key;
	__u32 paired; /* 0 while the socket is not hijacked */
};

/*
 * The daemon's side of one splice.
 *
 * cfd and sfd are the two ends of the daemon's own loopback connection, and
 * both are daemon-local descriptors -- the client never holds either. The
 * client only ever names this pipe by `key`.
 *
 * sfd is the end the daemon reads and writes, and it is therefore also the end
 * registered in dpipe_map. Those two facts are the same fact: sk_msg runs only
 * on sends from a socket the map holds, so the daemon's i/o end has to be the
 * registered one, and BPF_F_INGRESS delivers the client's writes into that
 * same socket's receive queue.
 *
 * cfd is never read or written. It exists solely to keep the connection
 * established, so that sfd stays a live socket with somewhere to send.
 *
 * Loopback TCP rather than socketpair(2), measured rather than assumed: sk_msg
 * is installed by replacing sk_prot->sendmsg, which tcp_bpf does and unix_bpf
 * does not. An AF_UNIX socket enters the map without complaint and then never
 * runs the program on send. See tests/test_xproc.c --socketpair.
 */
struct dpipe {
	__u32 key; /* index in dpipe_map, dpipes and the freelist */
	__u32 cfd; /* far end; held open only to keep the connection alive */
	__u32 sfd; /* the daemon's i/o end, and what dpipe_map holds */
	__u64 ts;  /* last activity, for the LRU sweep */
	struct stmt __arena *stmt;
	__u32 cpipe_key; /* the client's index in cpipe_map */
	__u32 in_use;
};

/* Bookkeeping for the pool. The client pops from the freelist, so both of
 * these are written from more than one process and move under atomics. */
struct dpipes_meta {
	__u32 serial;   /* next key to hand out; monotonic */
	__u32 num_free; /* live entries in dpipe_freelist */
};

/*
 * The capabilities a cached response is STORED under.
 *
 * A response is kept as one canonical encoding and regenerated for whoever
 * asks, rather than stored as whatever the capturing connection happened to
 * produce. Two connections that negotiated differently need different packet
 * counts for identical rows, so a stored blob has to be neutral about that or
 * it can only ever be replayed to a connection just like its source.
 */
/* CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS | CLIENT_DEPRECATE_EOF */
#define QC_CANONICAL_CAPS 0x01002200u

/* --- the mini-protocol --------------------------------------------------- */

/*
 * What a client sends the daemon over a spliced dpipe.
 *
 * The cache is reactive: nothing is fetched speculatively. A client asks
 * about a statement it is about to run, and hands back the answer it got if
 * there was not one already.
 */
enum qc_req_kind {
	QC_REQ_LOOKUP = 0, /* is this statement cached? */
	QC_REQ_STORE = 1,  /* here is the response; cache it */
};

/* Largest response a client may hand back. Big enough for real result sets,
 * small enough that a confused client cannot make the daemon allocate
 * arbitrarily. */
#define QC_STORE_MAX (4u * 1024 * 1024)

struct qc_req {
	__u32 kind; /* enum qc_req_kind */
	__u32 len;  /* bytes of payload following, QC_REQ_STORE only */
};

/*
 * Status codes the daemon writes into a dpipe, read by UCLIENT out of the
 * redirected socket.
 */
enum agent_status {
	/* The cache has it. The bytes are in the arena, reachable through the
	 * statement -- they do not follow on the socket. */
	AGENT_OK = 0x01,
	/* Miss. Read-through: the query goes to the server as normal and the
	 * client hands the response back, so the next caller hits. Nothing is
	 * ever fetched speculatively -- the cache only learns what someone
	 * actually asked for. (The name is the status code from
	 * architecture.txt; the mechanism is read-through.) */
	AGENT_WRITE_THROUGH = 0x00,
	/* Cache unreachable. Pass through untouched. */
	AGENT_CACHE_ERROR = 0xff,
};

/* Four bytes, as specified. What follows AGENT_OK is a reference into the
 * arena rather than the payload itself. */
struct agent_reply {
	__u8 status;
	__u8 _pad[3];
	__u32 stmt_id;
};

/* --- configuration slots ------------------------------------------------- */

#define QC_CFG_ENABLED 0
#define QC_CFG_PORT 1
#define QC_CFG_DAEMON_TGID 2
#define QC_CFG_ERROR_TTL 3
#define QC_CFG__N 4
