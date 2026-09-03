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
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
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

int sockOf(void *ssl) {
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
    bncl::RequestTracker req;
    bncl::ResponseTracker resp;

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
    bncl::mysql_proto::MessageReader rd;
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

uint64_t nowNs() {
    timespec ts{};

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

std::mutex lock_s;
std::map<void *, Conn> conns_s;
/* Only sockets currently spliced. Kept separate so the read hook can reject
 * an uninteresting fd with one lookup and no locking of the SSL map. */
std::map<int, Conn *> spliced_s;
bncl::StmtList list_s;
std::string list_path_s;
bool ready_s;

/*
 * Whether this agent is interceping at all, and which version of the list it
 * holds. Both mirror slots the daemon owns.
 *
 * on_s false is a complete pass-through: the hooks still run, still parse, and
 * still keep the protocol trackers aligned -- they simply match nothing. That
 * is what makes `barnacle detach-client` safe to issue at any moment, and what
 * makes re-attaching cheap.
 */
bool on_s = true;
uint32_t gen_s;
uint64_t next_poll_ns_s;

/*
 * Whether the local tier may answer, from this end.
 *
 * The agent's version of that question is its own shortcut: it only asks the
 * daemon about a statement the arena already holds a payload for, because if
 * the arena has nothing then neither has this host, and letting the query run
 * captures the answer for next time. That shortcut IS the local tier. With it
 * cleared the agent asks every time and lets the daemon go to Valkey -- which
 * is the point, and which also means a statement another host cached is
 * served here on its first execution rather than its second.
 */
bool local_s = true;

/*
 * Set once the daemon's pins have gone, and never cleared by polling.
 *
 * A daemon that comes back makes new maps; the descriptors this agent is
 * holding name the old ones, which still exist and will still be readable
 * forever. So "the pins are back" is not a reason to start intercepting
 * again -- only being injected again is, because that is what reopens them.
 */
bool daemon_gone_s;

/*
 * How often the agent looks at those slots.
 *
 * A bpf(2) lookup per SSL_write would put a syscall on the application's hot
 * path for a value that only changes when an administrator types a command.
 * A quarter second is imperceptible to whoever ran barnacle and invisible to
 * the application.
 */
constexpr uint64_t CFG_POLL_NS = 250ull * 1000 * 1000;

struct {
    unsigned long writes, matched, served, passthrough, txn_skip, published;
    unsigned long asked, pool_empty, resent, timeouts;
} stat_s;

Conn &connFor(void *ssl) {
    Conn &c = conns_s[ssl];

    if (!c.started) {
        /* Capabilities are not known without watching the handshake,
         * which happens before we attach to a live process. Assume the
         * modern set; extractQuery only needs QUERY_ATTRIBUTES to be
         * right, and a wrong guess means a miss, never a wrong hit. */
        c.req.begin(bncl::mysql_proto::CLIENT_PROTOCOL_41 | bncl::mysql_proto::CLIENT_TRANSACTIONS);
        c.started = true;
    }
    return c;
}

/*
 * Pick up the daemon's switches, at most once per CFG_POLL_NS.
 *
 * Called with lock_s held, from the write hook -- which is the only place
 * that consults either value, and the only place that reads list_s.
 */
void refreshLocked() {
    uint64_t now = nowNs();
    bncl::agent::Switches sw{};

    if (now < next_poll_ns_s) {
        return;
    }
    next_poll_ns_s = now + CFG_POLL_NS;

    /*
     * The daemon first. Its maps outlive it -- we are holding descriptors
     * to them -- so without this check everything still looks fine: the
     * statement table still answers, a dpipe can still be taken, and the
     * request goes to nobody. The application would get every cached
     * statement back a hundred milliseconds late, once the wait times out
     * and the query is sent for real.
     */
    if (!bncl::agent::daemonAlive()) {
        if (!daemon_gone_s) {
            fprintf(stderr, "agent: the daemon has gone; passing "
                            "everything through\n");
            daemon_gone_s = true;
        }
        on_s = false;
        return;
    }
    if (daemon_gone_s) {
        return; /* wait to be attached again, on the new maps */
    }

    /* Unreadable means the daemon is gone or was built without these
     * slots. Keep whatever we last saw rather than guessing: guessing off
     * would silently stop caching, and guessing on would keep asking a
     * daemon that is not there. */
    if (!bncl::agent::cfgRead(sw)) {
        return;
    }
    on_s = sw.client_on != 0;
    local_s = sw.local_on != 0;

    if (sw.generation == gen_s) {
        return;
    }

    bncl::StmtList fresh;
    std::string err;

    /* The generation is taken either way. A list file we cannot read is a
     * configuration error to report once, not on every write from here on. */
    gen_s = sw.generation;
    if (!fresh.load(list_path_s, err)) {
        fprintf(stderr, "agent: %s\n", err.c_str());
        return;
    }
    list_s = fresh;
    fprintf(stderr, "agent: reloaded %zu statement(s), generation %u\n", list_s.size(),
            sw.generation);
}

/* --- the write side ------------------------------------------------------ */

/* Returns true if the write was handled -- i.e. suppressed because we can
 * answer it. False means "let the real function run", which is always safe. */
bool handleWrite(void *ssl, int sock, const void *buf, size_t num) {
    std::lock_guard<std::mutex> lk(lock_s);
    Conn &c = connFor(ssl);
    std::string sql;

    stat_s.writes++;
    refreshLocked();

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
                                  : (bncl::mysql_proto::CLIENT_PROTOCOL_41 |
                                     bncl::mysql_proto::CLIENT_TRANSACTIONS));

        if (!on_s) {
            /* Detached. Everything above still runs -- the trackers
             * have to stay aligned with the stream in case we are
             * attached again -- but nothing is matched, so nothing
             * is intercepted and every query goes to the server. */
            continue;
        }
        if (!list_s.contains(sql)) {
            continue;
        }
        stat_s.matched++;

        if (c.in_txn) {
            /* Caching is bypassed outright while a transaction is
             * open, per the caveat this whole design exists under.
             * Not captured either: the rows may reflect
             * uncommitted state private to this session. */
            stat_s.txn_skip++;
            continue;
        }

        /*
         * Is it worth asking the daemon at all?
         *
         * Only if the arena already holds a payload for this statement:
         * if it does not, neither does this host, so letting the query
         * run and capturing the answer is both faster than a round trip
         * that would say the same thing, and what fills the cache in
         * the first place. That test IS the local tier from this end,
         * which is why the switch skips it -- with the local tier
         * bypassed the daemon is asked every time, so that it can go to
         * Valkey.
         *
         * The lookup is only a test; the bytes it returns are
         * discarded. What is served comes out of the arena in settle(),
         * after the daemon has confirmed the payload is current.
         */
        if (local_s) {
            std::vector<uint8_t> canon;
            uint32_t id = 0;

            if (!bncl::agent::lookupPayload(sql, canon, id)) {
                /* Read-through. Let the query run and capture
                 * what comes back, so the next caller hits. */
                c.pending = sql;
                c.captured.clear();
                c.rd.reset();
                c.capturing = true;
                continue;
            }
        }

        /* Ask the daemon. Take a dpipe, splice this connection to it,
         * post the request, and return -- the reply lands on the
         * client's own socket, which is the one it was going to wait on
         * anyway. Nothing here waits, because this is the application's
         * thread inside SSL_write. */
        if (!bncl::agent::acquire(sql, sock, c.dpipe)) {
            stat_s.pool_empty++;
            continue; /* pool exhausted: let the query through */
        }
        if (!bncl::agent::askLookup(sock)) {
            bncl::agent::release(sock, c.dpipe);
            continue;
        }

        c.awaiting = true;
        c.status = 0xFFFF;
        c.deadline_ns = nowNs() + AGENT_TIMEOUT_NS;
        c.sock = sock;
        c.pending = sql;
        c.query.assign((const uint8_t *)buf, (const uint8_t *)buf + num);
        spliced_s[sock] = &c;
        stat_s.asked++;
        return true; /* suppress: the query is the daemon's problem now */
    }
    while (c.req.next(sql));

    stat_s.passthrough++;
    return false;
}

/* --- the read side ------------------------------------------------------- */

/* Hand over as much of the owed response as this call has room for. Returns 0
 * when there is nothing owed, meaning the real SSL_read should run. */
size_t drainLocked(Conn &c, void *buf, size_t cap) {
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

size_t drain(void *ssl, void *buf, size_t cap) {
    std::lock_guard<std::mutex> lk(lock_s);
    auto it = conns_s.find(ssl);

    if (it == conns_s.end()) {
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
bool inferCaps(const std::vector<uint8_t> &resp, uint32_t &out) {
    const uint32_t base =
        bncl::mysql_proto::CLIENT_PROTOCOL_41 | bncl::mysql_proto::CLIENT_TRANSACTIONS;
    bncl::mysql_proto::ResultSet plain, deprecated;
    bool ok_plain = bncl::mysql_proto::parseResultSet(resp.data(), resp.size(), base, plain);
    bool ok_dep = bncl::mysql_proto::parseResultSet(
        resp.data(), resp.size(), base | bncl::mysql_proto::CLIENT_DEPRECATE_EOF, deprecated);

    /* Both can "succeed" on the same bytes: without DEPRECATE_EOF there is
     * an extra EOF packet between the definitions and the rows, and a
     * DEPRECATE_EOF parse mistakes it for the terminator -- stopping early
     * and reporting zero rows. Whichever reading consumes more rows is the
     * real one. */
    if (ok_plain && ok_dep) {
        if (plain.rows.size() >= deprecated.rows.size()) {
            out = base;
        }
        else {
            out = base | bncl::mysql_proto::CLIENT_DEPRECATE_EOF;
        }
        return true;
    }
    if (ok_plain) {
        out = base;
        return true;
    }
    if (ok_dep) {
        out = base | bncl::mysql_proto::CLIENT_DEPRECATE_EOF;
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
void observe(void *ssl, int sock, const void *buf, size_t n) {
    std::lock_guard<std::mutex> lk(lock_s);
    Conn &c = connFor(ssl);
    bncl::mysql_proto::Message m;

    c.sock = sock;
    c.rd.append((const uint8_t *)buf, n);
    if (c.capturing) {
        c.captured.insert(c.captured.end(), (const uint8_t *)buf, (const uint8_t *)buf + n);
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
            bncl::mysql_proto::ResultSet rs;

            if (!bncl::mysql_proto::parseResultSet(whole.data(), whole.size(), c.caps, rs)) {
                continue;
            }

            std::vector<uint8_t> canon =
                bncl::mysql_proto::encodeResultSet(rs, bncl::agent::CANONICAL_CAPS, 1);

            /* Read-through: hand the response to the daemon so the
             * next caller hits. Needs its own dpipe -- the one used
             * for the lookup went back on the freelist when the
             * verdict arrived.
             *
             * Best effort, deliberately. This posts and returns;
             * the daemon parses and stores on its own thread. A
             * query issued in the moment before that finishes sees
             * no payload and reads through again, which costs a
             * round trip and stores the same rows twice. Waiting
             * for the store to land would fix that by blocking the
             * application inside SSL_read, which is the one thing
             * this design will not do. The cache is allowed to be
             * slightly behind; it is not allowed to be in the way.
             */
            uint32_t key = 0;

            if (bncl::agent::acquire(c.pending, c.sock, key)) {
                if (bncl::agent::askStore(c.sock, canon)) {
                    stat_s.published++;
                }
                bncl::agent::release(c.sock, key);
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
bool takeReply(Conn *c, int fd) {
    bncl::agent::Reply r{};
    pollfd pfd = {fd, POLLIN, 0};
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
size_t settle(void *ssl, Conn &c, void *buf, size_t cap) {
    if (!c.awaiting) {
        return 0;
    }
    if (c.status == 0xFFFF) {
        takeReply(&c, c.sock);
    }
    if (c.status == 0xFFFF) {
        /* Out of time. Fall through to the passthrough path below,
         * which releases the pipe and sends the query for real. */
        stat_s.timeouts++;
    }

    int sock = c.sock;
    uint32_t key = c.dpipe;

    c.awaiting = false;
    spliced_s.erase(sock);

    /* Give the connection back before anything else: while it is spliced
     * every byte it sends goes to the daemon rather than the server. */
    bncl::agent::release(sock, key);

    if (c.status == bncl::agent::REPLY_OK && c.caps_known) {
        std::vector<uint8_t> canon;
        uint32_t id = 0;
        bncl::mysql_proto::ResultSet rs;

        if (bncl::agent::lookupPayload(c.pending, canon, id) &&
            bncl::mysql_proto::parseResultSet(canon.data(), canon.size(),
                                              bncl::agent::CANONICAL_CAPS, rs)) {
            /* Stored canonically, re-framed for THIS connection.
             * Replaying the stored bytes would only work for a
             * connection that negotiated identically and stood at
             * the same sequence id. */
            c.owed = bncl::mysql_proto::encodeResultSet(rs, c.caps, (uint8_t)(c.last_seq + 1));
            c.owed_off = 0;
            c.pending.clear();
            stat_s.served++;
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
        stat_s.resent++;
        /* Capture what comes back, so the next caller hits. */
        c.captured.clear();
        c.rd.reset();
        c.capturing = true;
    }
    return 0;
}

/* --- replacements -------------------------------------------------------- */

int rep_SSL_write(void *ssl, const void *buf, int num) {
    if (num > 0 && handleWrite(ssl, sockOf(ssl), buf, (size_t)num)) {
        return num; /* the caller believes every byte was sent */
    }
    return real_SSL_write(ssl, buf, num);
}

int rep_SSL_write_ex(void *ssl, const void *buf, size_t num, size_t *written) {
    if (num > 0 && handleWrite(ssl, sockOf(ssl), buf, num)) {
        if (written) {
            *written = num;
        }
        return 1;
    }
    return real_SSL_write_ex(ssl, buf, num, written);
}

int rep_SSL_read(void *ssl, void *buf, int num) {
    if (num > 0) {
        {
            std::lock_guard<std::mutex> lk(lock_s);
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

int rep_SSL_read_ex(void *ssl, void *buf, size_t num, size_t *readbytes) {
    if (num > 0) {
        {
            std::lock_guard<std::mutex> lk(lock_s);
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
gpointer resolve(const char *sym) {
    static const char *mods[] = {"libssl.so.3", "libssl.so", NULL};

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

/*
 * The entry points we replaced, so they can be put back.
 *
 * gum_interceptor_revert() takes the address of the function that was
 * replaced, and resolve() is not guaranteed to return the same answer later
 * -- the module it found the symbol in may have been unloaded, or a second
 * one loaded over it. So the address is remembered at hook time.
 */
struct Hooked {
    gpointer target;
    const char *sym;
};

GumInterceptor *ic_s;
Hooked hooks_s[8];
int nhooks_s;
bool hooked_s;

void hook(GumInterceptor *ic, const char *sym, gpointer repl, gpointer *orig) {
    gpointer target = resolve(sym);

    if (!target) {
        fprintf(stderr, "agent: %s not found\n", sym);
        return;
    }
    if (gum_interceptor_replace(ic, target, repl, NULL, orig) != 0) {
        fprintf(stderr, "agent: cannot replace %s\n", sym);
        return;
    }
    if (nhooks_s < (int)(sizeof(hooks_s) / sizeof(hooks_s[0]))) {
        hooks_s[nhooks_s].target = target;
        hooks_s[nhooks_s].sym = sym;
        nhooks_s++;
    }
    fprintf(stderr, "agent: hooked %s\n", sym);
}

/*
 * Put every entry point back. This is what `barnacle detach-client` reaches.
 *
 * The library itself stays mapped. Unloading it would free the trampolines
 * the process may be executing at that instant, and there is no way to know
 * it is not -- which is the one failure mode a detach must not have. Reverting
 * costs a few pages of resident memory and leaves nothing of ours running.
 */
void unhookAll() {
    if (!hooked_s || !ic_s) {
        fprintf(stderr, "agent: not attached in pid %d\n", getpid());
        return;
    }

    /* Stop taking on new work first, then wait for what is already in
     * flight. A connection that has suppressed its query is waiting for
     * the daemon's answer to come back through OUR read hook; removing
     * that hook first strands the application on a query it never sent.
     */
    on_s = false;
    for (int i = 0; i < 100; i++) {
        bool busy = false;

        {
            std::lock_guard<std::mutex> lk(lock_s);

            for (const auto &kv : conns_s) {
                if (kv.second.awaiting || kv.second.owed_off < kv.second.owed.size()) {
                    busy = true;
                    break;
                }
            }
        }
        if (!busy) {
            break;
        }
        usleep(5000); /* up to half a second in total */
    }

    gum_interceptor_begin_transaction(ic_s);
    for (int i = 0; i < nhooks_s; i++) {
        gum_interceptor_revert(ic_s, hooks_s[i].target);
    }
    gum_interceptor_end_transaction(ic_s);

    fprintf(stderr, "agent: detached from pid %d, %d hook(s) reverted\n", getpid(), nhooks_s);
    nhooks_s = 0;
    hooked_s = false;
}

} // namespace

/*
 * Frida's entrypoint, called every time the library is injected.
 *
 * The signature matters. `stay_resident` must be set, or Frida unloads this
 * object as soon as the function returns -- taking the hooks with it and
 * leaving the target running patched trampolines into freed memory. It is
 * NOT also a constructor: declaring both makes it run twice.
 *
 * --- injected more than once ----------------------------------------------
 *
 * Injecting again into a process that already has the agent runs this
 * function again in the SAME loaded library, which is how barnacle reaches an
 * agent it has no other channel to. `data` says what for:
 *
 *   "detach"     put the entry points back; stop being in the way.
 *   anything else  the path to the statement list -- attach, or re-arm after
 *                  a detach.
 *
 * There is no third mechanism for this. The daemon's cfg slots reach every
 * agent at once and are what make a detach take effect immediately, but they
 * cannot unhook anything: only code running inside the target can do that,
 * and injection is the only way to get code running there.
 */
extern "C" void bncl_agent_init(const gchar *data, gboolean *stay_resident, gpointer user_data) {
    static bool gum_started;
    std::string arg = data && *data ? data : "";
    std::string err;

    (void)user_data;
    if (stay_resident) {
        *stay_resident = TRUE;
    }

    if (arg == "detach") {
        unhookAll();
        return;
    }

    const char *list = !arg.empty() ? arg.c_str() : getenv("BARNACLE_LIST");

    list_path_s = list && *list ? list : "demo/config/cache.list";

    {
        bncl::StmtList fresh;

        if (!fresh.load(list_path_s, err)) {
            fprintf(stderr, "agent: %s\n", err.c_str());
            return;
        }

        /* Under the lock: on a re-arm the hooks are live and another
         * thread may be matching against this list right now. */
        std::lock_guard<std::mutex> lk(lock_s);

        list_s = fresh;
    }

    if (!ready_s) {
        fprintf(stderr, "agent: loading into pid %d\n", getpid());
    }
    /* Every time, not only the first. A daemon restart leaves this agent
     * holding descriptors for maps nobody is serving, and reopening the
     * pins is the whole substance of re-attaching to a new one. */
    if (!bncl::agent::openShared()) {
        return;
    }
    ready_s = true;
    daemon_gone_s = false;

    /* Whatever a previous detach left behind, an explicit attach means on.
     * The next poll re-reads the daemon's view a quarter second later. */
    on_s = true;
    next_poll_ns_s = 0;

    /* Take the generation now. The list was just read from the file, so it
     * IS current -- without this the first poll sees a difference that
     * does not exist and reads the same file again. */
    {
        bncl::agent::Switches sw{};

        if (bncl::agent::cfgRead(sw)) {
            gen_s = sw.generation;
            local_s = sw.local_on != 0;
        }
    }

    if (!gum_started) {
        gum_init_embedded();
        ic_s = gum_interceptor_obtain();
        gum_started = true;
    }

    if (hooked_s) {
        fprintf(stderr, "agent: re-armed in pid %d, %zu statement(s)\n", getpid(), list_s.size());
        return;
    }

    gum_interceptor_begin_transaction(ic_s);
    hook(ic_s, "SSL_write", (gpointer)rep_SSL_write, (gpointer *)&real_SSL_write);
    hook(ic_s, "SSL_write_ex", (gpointer)rep_SSL_write_ex, (gpointer *)&real_SSL_write_ex);
    hook(ic_s, "SSL_read", (gpointer)rep_SSL_read, (gpointer *)&real_SSL_read);
    hook(ic_s, "SSL_read_ex", (gpointer)rep_SSL_read_ex, (gpointer *)&real_SSL_read_ex);
    gum_interceptor_end_transaction(ic_s);
    hooked_s = nhooks_s > 0;

    /* Looked up, never replaced: the splice is registered against the
     * socket, and only the SSL object knows which one that is. */
    real_SSL_get_fd = (int (*)(const void *))resolve("SSL_get_fd");
    if (!real_SSL_get_fd) {
        fprintf(stderr, "agent: SSL_get_fd not found; nothing can be "
                        "spliced\n");
    }

    fprintf(stderr, "agent: ready, %zu statement(s)\n", list_s.size());
}

extern "C" __attribute__((destructor)) void bncl_agent_fini(void) {
    fprintf(stderr,
            "agent: writes=%lu matched=%lu asked=%lu served=%lu resent=%lu\n"
            "agent: published=%lu timeouts=%lu pool_empty=%lu txn_skip=%lu\n",
            stat_s.writes, stat_s.matched, stat_s.asked, stat_s.served, stat_s.resent,
            stat_s.published, stat_s.timeouts, stat_s.pool_empty, stat_s.txn_skip);
}
