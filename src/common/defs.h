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
#define BNCL_MAX_PIPES 4096

/* Distinct cacheable statements. This is an administrator-curated list, not
 * something that grows with traffic, so it is small by nature. */
#define BNCL_MAX_STMTS 1024

/* Longest statement text that can be matched. Statements longer than this are
 * simply not cacheable. */
#define BNCL_STMT_MAX 512

/* Largest response UCLIENT will serve from its own in-process copy. Bigger
 * ones are not un-cacheable, they just do not take the local fast path. */
#define BNCL_LOCAL_MAX 8192

/* Arena size, in pages. Holds statement text and cached response bodies. */
#define BNCL_ARENA_PAGES 4096 /* 16 MiB at 4K pages */

/*
 * Fixed virtual address the arena is mapped at, in every process.
 *
 * This is the property the whole pointer-based design rests on: if the arena
 * landed wherever each process happened to map it, a `struct stmt *` written
 * by the daemon would mean nothing to a client, and every field below would
 * have to become an offset with a per-process base added back. Pinning the
 * address makes a pointer just a pointer.
 */
#define BNCL_ARENA_VA (1ULL << 44)

/*
 * The one thing at a known address in the arena: a lock, at the very front.
 *
 * The dpipe freelist is a BPF map, and taking a pipe off it is a
 * read-modify-write across three bpf(2) calls -- read the count, read the top
 * entry, write the count back. Every attached process does that, and bpf(2)
 * offers no compare-and-swap, so two clients can read the same count and walk
 * away holding the same pipe. Both then splice their own socket to it, the
 * second overwriting the first, and the daemon's answer to one query is
 * delivered into the other client's TLS session -- which it reads as a
 * corrupt record and drops the connection.
 *
 * That is not theoretical; it is what eight clients issuing one statement at
 * one instant reliably produced. The window is tiny per attempt, which is why
 * it stayed hidden while pipes were held for microseconds. Holding one for the
 * length of a query, as a client waiting behind someone else's fetch now does,
 * makes collisions ordinary.
 *
 * The arena is the natural home for the fix: it is already shared memory, and
 * already mapped at the same address in every process, so an ordinary atomic
 * works across all of them. architecture.txt anticipated exactly this ("simple
 * atomic counters + spinlocks should be sufficient").
 */
struct bncl_ctl {
    __u32 lock; /* 0 free, 1 held */
    __u32 _pad;
    __u64 taken_ns; /* CLOCK_MONOTONIC, for breaking an abandoned lock */

    /* --- the heap ---
     *
     * Offsets from the base of the arena, not pointers, so the control
     * block says the same thing however it is mapped. Everything the
     * allocator needs is here rather than in daemon memory, which keeps
     * the arena self-describing: a reader with the base address can walk
     * it without asking anyone.
     */
    __u32 heap;      /* first block */
    __u32 heap_end;  /* one past the last */
    __u32 free_head; /* first free block, 0 for none */
    __u32 retire;    /* first block waiting out its grace period */
    __u64 used;      /* bytes currently handed out, headers excluded */
};

/* Bytes at the front of the arena that allocation must not hand out. */
#define BNCL_CTL_BYTES 64

/* Where the maps are pinned, so a process that did not create them can get a
 * descriptor. UCLIENT's loader opens these; the daemon creates them. */
#define BNCL_PIN_DIR "/sys/fs/bpf/barnacle"

/*
 * Runtime state that is NOT in a BPF map: the daemon's pid file, its log, and
 * the control socket barnacle talks to. Ordinary files, because the thing
 * reading them is a Python CLI that must work on a host with no bpftool and
 * no libbpf.
 */
#define BNCL_RUN_DIR "/run/barnacle"
#define BNCL_CTL_SOCK BNCL_RUN_DIR "/daemon.sock"

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
    char text[BNCL_STMT_MAX];
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
    /* Someone is already fetching it. Other clients would wait rather than
     * each starting a duplicate fetch of the same thing.
     *
     * Declared, not used: nothing sets it today. The cache assumes instead
     * that a statement gets populated once and that clients converge on it
     * shortly after -- see architecture.txt III for what coordinating the
     * miss would involve. */
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

    /*
     * How many holders this record has, across every process.
     *
     * Published with 1: the statement table's own reference, dropped when
     * the administrator takes the statement out of the list. Every client
     * that is about to use the record adds one and drops it when done, so
     * a record cannot be reclaimed while somebody is reading the payload
     * it points at.
     *
     * Taking a reference is a compare-and-swap that REFUSES to go from 0
     * to 1, not a plain increment: zero means the record has been retired
     * and is waiting to be freed, and resurrecting it there would hand out
     * memory the daemon has already promised to reclaim.
     */
    __u32 stmt_refs;
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

#ifndef __bpf__
/*
 * Take a reference, or fail.
 *
 * A compare-and-swap loop rather than an increment, because the interesting
 * case is the one an increment gets wrong: a record whose count has already
 * reached zero is retired and waiting to be freed, and bringing it back to one
 * would hand out memory the daemon has promised to reclaim. Refusing at zero
 * is what makes "retired" mean retired.
 *
 * Defined here, once, because both the daemon and the injected agent take
 * references and a refcount protocol implemented twice is a refcount protocol
 * that will eventually disagree with itself.
 */
static inline int bncl_stmt_get(struct stmt *st) {
    __u32 cur = __atomic_load_n(&st->stmt_refs, __ATOMIC_ACQUIRE);

    while (cur != 0) {
        if (__atomic_compare_exchange_n(&st->stmt_refs, &cur, cur + 1, 0, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE)) {
            return 1;
        }
    }
    return 0;
}

/* Drop a reference. Returns non-zero if this was the last one, which makes
 * the caller responsible for retiring the record. */
static inline int bncl_stmt_put(struct stmt *st) {
    return __atomic_sub_fetch(&st->stmt_refs, 1, __ATOMIC_ACQ_REL) == 0;
}
#endif /* __bpf__ */

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
 *
 * `key` is the serial, and one serial names both halves: the client socket is
 * cpipe_map[key] and the daemon socket is dpipe_map[key]. dpipe[n] is spliced
 * to cpipe[n] and to nothing else, so a program that knows its own serial
 * knows its peer's without being told -- it redirects into the opposite map
 * at the same index. Both sides therefore store the same value here, and
 * there is no pairing table anywhere to disagree with.
 *
 * A descriptor is never a key. sk_storage is addressed by socket because that
 * is what the map type is -- data hanging off the socket, which is the only
 * place a program holding nothing but `msg->sk` can find out which serial it
 * is. Everything the serial then names is indexed by the serial.
 */
struct pipe_sk_info {
    __u32 key;    /* this socket is cpipe_map[key] or dpipe_map[key] */
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
#define BNCL_CANONICAL_CAPS 0x01002200u

/* --- the mini-protocol --------------------------------------------------- */

/*
 * What a client sends the daemon over a spliced dpipe.
 *
 * The cache is reactive: nothing is fetched speculatively. A client asks
 * about a statement it is about to run, and hands back the answer it got if
 * there was not one already.
 */
enum bncl_req_kind {
    BNCL_REQ_LOOKUP = 0, /* is this statement cached? */
    BNCL_REQ_STORE = 1,  /* here is the response; cache it */
};

/* Largest response a client may hand back. Big enough for real result sets,
 * small enough that a confused client cannot make the daemon allocate
 * arbitrarily. */
#define BNCL_STORE_MAX (4u * 1024 * 1024)

struct bncl_req {
    __u32 kind; /* enum bncl_req_kind */
    __u32 len;  /* bytes of payload following, BNCL_REQ_STORE only */
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

#define BNCL_CFG_ENABLED 0
#define BNCL_CFG_PORT 1
#define BNCL_CFG_DAEMON_TGID 2
#define BNCL_CFG_ERROR_TTL 3

/*
 * Whether attached agents should intercept at all.
 *
 * `barnacle detach-client` clears this, and every agent stops matching
 * statements within one poll interval. It exists as well as the per-process
 * revert because detach must take effect even for a process the injector
 * cannot reach a second time -- and because turning interception off is one
 * map write, while unhooking is a per-process operation that can fail.
 */
#define BNCL_CFG_CLIENT_ON 4

/*
 * Bumped by the daemon whenever the statement list is re-read.
 *
 * Agents hold their own copy of the list (matching happens in the client
 * process, on the client's thread, and must not involve a lookup), so a
 * reload has to reach them somehow. A counter they poll is the cheapest
 * thing that works: no signal to deliver, no socket to hold open, and an
 * agent that missed one bump still sees the value differ.
 */
#define BNCL_CFG_GENERATION 5

/*
 * Whether the LOCAL tier may answer. Set by default; cleared to make every
 * lookup go to Valkey.
 *
 * There are two tiers, and they are not the same kind of thing. Valkey is the
 * shared one -- one copy, visible to every host. The arena is a per-host copy
 * that each attached process has mapped, so a hit there is a memory read and
 * costs no round trip and no command. That is the fast path, and clearing
 * this switch gives it up on purpose.
 *
 * Reasons to give it up:
 *
 *   - the shared tier is then the only authority, so a key expired or deleted
 *     in Valkey takes effect at the next lookup rather than whenever the
 *     local copy happens to age out.
 *   - several hosts stay closer together, since none of them is answering
 *     from a copy the others cannot see.
 *   - and every hit becomes visible: MONITOR shows the traffic that a local
 *     hit, by construction, never generates.
 *
 * What it costs: a round trip on the hot path, and the cache stops working
 * entirely while Valkey is unreachable -- there is no longer a local copy to
 * fall back to. That degrades to passing queries through, which is safe, but
 * it is the whole cache rather than one tier.
 *
 * The arena is still how a response reaches the client, in both modes. This
 * governs whether a copy already sitting there may be TRUSTED, not whether it
 * is used: the daemon writes the freshly fetched bytes there and the client
 * reads them from there, because a result set is never copied through the
 * control path.
 */
#define BNCL_CFG_LOCAL_ON 6

#define BNCL_CFG__N 7
