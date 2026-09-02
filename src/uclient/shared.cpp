// SPDX-License-Identifier: GPL-2.0
#include "uclient/shared.h"

#include "common/defs.h"
#include "uclient/bpfsys.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#define PIN(name) BNCL_PIN_DIR "/" name

namespace bncl::agent {

/* The mirrored definitions in shared.h must match the real ones. This is the
 * one file that can see both. */
static_assert(sizeof(Reply) == sizeof(agent_reply),
              "bncl::agent::Reply has drifted from struct agent_reply");
static_assert(REPLY_OK == AGENT_OK && REPLY_WRITE_THROUGH == AGENT_WRITE_THROUGH &&
                  REPLY_CACHE_ERROR == static_cast<uint8_t>(AGENT_CACHE_ERROR),
              "bncl::agent reply statuses have drifted from enum agent_status");
static_assert(CANONICAL_CAPS == BNCL_CANONICAL_CAPS,
              "bncl::agent::CANONICAL_CAPS has drifted from BNCL_CANONICAL_CAPS");

namespace {

class FDS {
public:
    uint8_t *arena = nullptr;
    int stmts_fd = -1;
    int dpipes_fd = -1;
    int freelist_fd = -1;
    int meta_fd = -1;
    int cpipes_fd = -1;
    int info_fd = -1;
    int cfg_fd = -1;

    void closeAll()
    {
        for (int *p :
             {&stmts_fd, &dpipes_fd, &freelist_fd, &meta_fd, &cpipes_fd, &info_fd, &cfg_fd}) {
            if (*p >= 0) {
                close(*p);
                *p = -1;
            }
        }
    }
};

FDS fds;

/*
 * Post bytes to the daemon over the spliced socket.
 *
 * A short write is treated as failure rather than retried. This runs on the
 * application's thread inside a TLS call: looping until the kernel accepts
 * the rest is exactly the block we must not introduce. The requests here are
 * a few bytes, or a response the socket buffer has room for; if one does not
 * fit, the statement simply does not get cached this time.
 *
 * MSG_NOSIGNAL, and this is not a detail. send(2) to a socket whose peer has
 * closed raises SIGPIPE, and the default disposition is to kill the process
 * -- which here is somebody else's application, on its own thread, for a
 * reason it has no way to understand. That happens for real: stopping the
 * daemon closes every dpipe, and an agent that has not yet noticed writes
 * into one. Ignoring the signal process-wide would be the wrong fix, because
 * the disposition belongs to the application and not to us; suppressing it
 * per call does not touch it.
 */
bool post(int fd, const void *buf, size_t n)
{
    ssize_t w = send(fd, buf, n, MSG_NOSIGNAL);

    return w == static_cast<ssize_t>(n);
}

/*
 * The freelist lock: see struct bncl_ctl in common/defs.h for why it exists.
 *
 * A spinlock rather than a lock-free stack because the critical section is
 * three bpf(2) calls -- a few microseconds -- and because a lock-free version
 * needs a compare-and-swap on the freelist head, which means moving the head
 * out of the BPF map that holds it. This buys the same correctness for a
 * fraction of the change.
 *
 * Bounded, and it gives up rather than waiting. The cost of failing is that
 * one query goes to the server, which is what would have happened anyway; the
 * cost of waiting forever is an application thread hung inside SSL_write for a
 * cache. Nothing here is ever allowed to be worse than not caching.
 */
bncl_ctl *ctl()
{
    return reinterpret_cast<bncl_ctl *>(static_cast<uintptr_t>(BNCL_ARENA_VA));
}

stmt *stmtFromRef(stmt_ref ref)
{
    return reinterpret_cast<stmt *>(static_cast<uintptr_t>(ref));
}

bool lockPipes()
{
    bncl_ctl *c = ctl();

    if (!fds.arena) {
        return false;
    }

    /* Roughly a millisecond of spinning at worst, against a section held
     * for microseconds by at most one client at a time. */
    for (int i = 0; i < 4096; i++) {
        uint32_t free_slot = 0;

        if (__atomic_compare_exchange_n(&c->lock, &free_slot, 1u, false, __ATOMIC_ACQUIRE,
                                        __ATOMIC_RELAXED)) {
            timespec ts{};

            clock_gettime(CLOCK_MONOTONIC, &ts);
            /* Stamped so the daemon can tell a held lock from an
             * abandoned one. Written after the lock is ours, which
             * is the only time it can be written safely. */
            __atomic_store_n(&c->taken_ns,
                             static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
                                 static_cast<uint64_t>(ts.tv_nsec),
                             __ATOMIC_RELAXED);
            return true;
        }
        sched_yield();
    }
    return false;
}

void unlockPipes()
{
    __atomic_store_n(&ctl()->lock, 0u, __ATOMIC_RELEASE);
}

/* Take a dpipe off the freelist. Losing the race is normal and means the
 * query goes to the server as it otherwise would. Call with the lock held. */
bool popDpipe(uint32_t &key)
{
    dpipes_meta meta{};
    uint32_t zero = 0, slot;

    if (bncl_bpf_lookup(fds.meta_fd, &zero, &meta) || meta.num_free == 0) {
        return false;
    }
    slot = meta.num_free - 1;
    if (bncl_bpf_lookup(fds.freelist_fd, &slot, &key)) {
        return false;
    }
    meta.num_free = slot;
    return bncl_bpf_update(fds.meta_fd, &zero, &meta, 0) == 0;
}

void pushDpipe(uint32_t key)
{
    dpipes_meta meta{};
    uint32_t zero = 0;

    if (bncl_bpf_lookup(fds.meta_fd, &zero, &meta)) {
        return;
    }

    uint32_t slot = meta.num_free;

    /* The key must be visible in the slot before num_free admits the slot
     * exists, or another client could pop an index not yet written. */
    if (bncl_bpf_update(fds.freelist_fd, &slot, &key, 0)) {
        return;
    }
    meta.num_free = slot + 1;
    bncl_bpf_update(fds.meta_fd, &zero, &meta, 0);
}

} // namespace

bool daemonAlive()
{
    return access(PIN("cfg"), F_OK) == 0;
}

bool openShared()
{
    /* Whatever a previous attach left open. Re-attaching after the daemon
     * was restarted has to end up on the NEW maps, and these descriptors
     * name the old ones. */
    fds.closeAll();

    int fd = bncl_bpf_obj_get(PIN("arena"));

    if (fd < 0) {
        fprintf(stderr, "agent: no arena pin (daemon not running?)\n");
        return false;
    }

    /* MAP_FIXED: the arena must land where the daemon put it, or the
     * pointers stored inside it mean nothing here. A different address
     * would appear to work and then hand out garbage, so fail loudly. */
    auto *const arena_addr = reinterpret_cast<void *>(static_cast<uintptr_t>(BNCL_ARENA_VA));
    void *p = mmap(arena_addr, static_cast<size_t>(BNCL_ARENA_PAGES) * 4096, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_FIXED, fd, 0);

    if (p != arena_addr) {
        fprintf(stderr, "agent: arena did not map at the shared address\n");
        return false;
    }
    fds.arena = static_cast<uint8_t *>(p);
    /* The mapping keeps the map alive; the descriptor has done its job.
     * It matters now that this function can run more than once. */
    close(fd);

    fds.stmts_fd = bncl_bpf_obj_get(PIN("stmts_map"));
    fds.dpipes_fd = bncl_bpf_obj_get(PIN("dpipes"));
    fds.freelist_fd = bncl_bpf_obj_get(PIN("dpipe_freelist"));
    fds.meta_fd = bncl_bpf_obj_get(PIN("dpipes_meta_map"));
    fds.cpipes_fd = bncl_bpf_obj_get(PIN("cpipe_map"));
    fds.info_fd = bncl_bpf_obj_get(PIN("pipe_sk_info_map"));

    /* Not in the check below: an older daemon has no cfg pin, and the
     * agent works without it -- it just never hears about a detach or a
     * reload. Failing to attach over that would be worse. */
    fds.cfg_fd = bncl_bpf_obj_get(PIN("cfg"));

    if (fds.stmts_fd < 0 || fds.dpipes_fd < 0 || fds.freelist_fd < 0 || fds.meta_fd < 0 ||
        fds.cpipes_fd < 0 || fds.info_fd < 0) {
        fprintf(stderr, "agent: daemon maps missing under %s\n", BNCL_PIN_DIR);
        return false;
    }
    return true;
}

bool cfgRead(Switches &out)
{
    static const uint32_t slots[] = {BNCL_CFG_CLIENT_ON, BNCL_CFG_GENERATION, BNCL_CFG_LOCAL_ON};
    uint32_t vals[3] = {0, 0, 0};

    if (fds.cfg_fd < 0) {
        return false;
    }
    for (int i = 0; i < 3; i++) {
        uint32_t slot = slots[i];

        if (bncl_bpf_lookup(fds.cfg_fd, &slot, &vals[i])) {
            return false;
        }
    }
    out.client_on = vals[0];
    out.generation = vals[1];
    out.local_on = vals[2];
    return true;
}

bool lookupPayload(const std::string &sql, std::vector<uint8_t> &out, uint32_t &id)
{
    stmt_key k{};
    stmt_ref ref = 0;

    if (!fds.arena || sql.size() > BNCL_STMT_MAX - 1) {
        return false;
    }
    memcpy(k.text, sql.data(), sql.size());
    if (bncl_bpf_lookup(fds.stmts_fd, &k, &ref) || !ref) {
        return false;
    }

    auto st = stmtFromRef(ref);

    /*
     * Hold a reference for as long as the payload is being read.
     *
     * Without it the daemon could retire this record, and the bytes it
     * points at, between the check below and the copy at the bottom. The
     * take fails if the record has already been retired, which reads as a
     * miss -- correct, since a retired statement is one nobody should be
     * served from any more.
     */
    if (!bncl_stmt_get(st)) {
        return false;
    }

    /* STMT_S_LOCAL is the zero value, so state alone cannot say "present";
     * the payload pointer is what does. Acquire, to pair with the daemon's
     * release store: seeing LOCAL must mean the bytes are already there. */
    if (__atomic_load_n(&st->stmt_state, __ATOMIC_ACQUIRE) != STMT_S_LOCAL || !st->stmt_data ||
        !st->stmt_data_len) {
        bncl_stmt_put(st);
        return false;
    }

    if (st->stmt_ttl && st->stmt_ts) {
        timespec ts{};

        clock_gettime(CLOCK_MONOTONIC, &ts);

        auto now =
            static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);

        if (now > st->stmt_ts && (now - st->stmt_ts) / 1000000000ull > st->stmt_ttl) {
            bncl_stmt_put(st);
            return false;
        }
    }

    auto p = static_cast<const uint8_t *>(st->stmt_data);

    out.assign(p, p + st->stmt_data_len);
    id = st->stmt_id;
    bncl_stmt_put(st);
    return true;
}

bool acquire(const std::string &sql, int sock, uint32_t &key)
{
    stmt_key k{};
    stmt_ref ref = 0;

    if (!fds.arena || sql.size() > BNCL_STMT_MAX - 1) {
        return false;
    }

    /* Only statements the administrator listed have a record to point at. */
    memcpy(k.text, sql.data(), sql.size());
    if (bncl_bpf_lookup(fds.stmts_fd, &k, &ref) || !ref) {
        return false;
    }
    /*
     * The lock covers the pop AND the write that claims the pipe.
     *
     * Not just the pop: two clients that came away with the same key would
     * both write their own statement and generation here, and the second
     * would erase the first. Claiming the pipe is part of taking it.
     */
    if (!lockPipes()) {
        return false; /* contended past patience; the query goes out */
    }
    if (!popDpipe(key)) {
        unlockPipes();
        return false;
    }

    dpipe rec{};

    if (bncl_bpf_lookup(fds.dpipes_fd, &key, &rec)) {
        pushDpipe(key);
        unlockPipes();
        return false;
    }

    /*
     * Hold a reference until release(). The pipe keeps a pointer to this
     * record and the daemon follows it, so it has to outlive the request
     * whatever the administrator does to the statement list meanwhile.
     */
    if (!bncl_stmt_get(stmtFromRef(ref))) {
        pushDpipe(key);
        unlockPipes();
        return false;
    }

    /* Point the pipe at the statement. This is what lets the request carry
     * nothing but a key: everything else hangs off the pipe. */
    rec.stmt = stmtFromRef(ref);
    rec.in_use = 1;
    bncl_bpf_update(fds.dpipes_fd, &key, &rec, 0);
    unlockPipes();

    /* Hijack our own socket. Both calls take a plain fd because we own it;
     * the daemon could not do this for us even if it wanted to. */
    pipe_sk_info si{};

    si.key = key;
    si.paired = 1;
    if (bncl_bpf_update(fds.cpipes_fd, &key, &sock, 0) ||
        bncl_bpf_update(fds.info_fd, &sock, &si, 0)) {
        if (lockPipes()) {
            pushDpipe(key);
            unlockPipes();
        }
        return false;
    }
    return true;
}

bool askLookup(int sock)
{
    bncl_req req{};

    req.kind = BNCL_REQ_LOOKUP;
    req.len = 0;
    return post(sock, &req, sizeof(req));
}

bool askStore(int sock, const std::vector<uint8_t> &canonical)
{
    bncl_req req{};

    if (canonical.empty() || canonical.size() > BNCL_STORE_MAX) {
        return false;
    }
    req.kind = BNCL_REQ_STORE;
    req.len = static_cast<uint32_t>(canonical.size());

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
    pipe_sk_info si{};
    dpipe rec{};

    /* Clear `paired` first: while it is set every byte this socket sends
     * goes to the daemon rather than to the server. */
    bncl_bpf_update(fds.info_fd, &sock, &si, 0);
    bncl_bpf_delete(fds.cpipes_fd, &key);

    /*
     * Give back the reference acquire() took.
     *
     * The record is not retired here even if this was the last reference:
     * the daemon owns the heap, and a client that started freeing shared
     * memory would make the allocator multi-writer for no benefit. The
     * daemon picks it up on its next pass.
     */
    if (bncl_bpf_lookup(fds.dpipes_fd, &key, &rec) == 0 && rec.stmt) {
        bncl_stmt_put(rec.stmt);
    }

    /*
     * Under the lock, for the same reason the pop is: the push writes the
     * slot and then the count, and a concurrent pop reading the count
     * between those two writes takes a slot that has not been filled in.
     *
     * If the lock cannot be had, the pipe is not returned. That leaks one
     * pipe out of the pool, which costs a little concurrency, and is the
     * right way to lose: pushing without the lock could hand the same pipe
     * to two clients, and one connection receiving another's rows is not a
     * degradation, it is a wrong answer.
     */
    if (lockPipes()) {
        pushDpipe(key);
        unlockPipes();
    }
}

} // namespace bncl::agent
