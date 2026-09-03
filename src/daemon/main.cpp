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
#include "common/defs.h"
#include "common/mysql/resultset.h"
#include "common/stmtlist.h"
#include "common/valkey.h"
#include "daemon/arena.h"
#include "daemon/dpipes.h"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "kclient.skel.h"

namespace {

volatile sig_atomic_t exiting_s;

uint64_t now_ns() {
    timespec ts{};

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
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
bool expired(const stmt *st, uint64_t now) {
    if (!st->stmt_ttl) {
        return false; /* ttl 0 means "do not expire" */
    }
    if (!st->stmt_ts) {
        return true;
    }
    return now - st->stmt_ts > static_cast<uint64_t>(st->stmt_ttl) * 1000000000ull;
}

stmt_ref stmtToRef(stmt *rec) {
    return static_cast<stmt_ref>(reinterpret_cast<uintptr_t>(rec));
}

void on_signal(int) {
    exiting_s = 1;
}

struct Options {
    std::string stmt_list;
    std::string valkey_host = "valkey";
    uint16_t valkey_port = 6379;
    uint16_t mysql_port = 3306;
    uint32_t pipes = 64;
    uint32_t max_stmts = BNCL_MAX_STMTS;
    uint32_t max_pipes = BNCL_MAX_PIPES;
    int ttl = 60;
    int error_ttl = 30;
    std::string ctl_path = BNCL_CTL_SOCK;
    /* False bypasses the arena tier: every lookup goes to Valkey. See
     * BNCL_CFG_LOCAL_ON in common/defs.h for what that trades away. */
    bool local_on = true;
    bool verbose = false;
};

/*
 * What the daemon has done since it started.
 *
 * Kept here rather than derived from the logs because `barnacle status` has
 * to answer "is this thing working" without anyone having run it with -v.
 */
struct Counters {
    unsigned long hits = 0;
    unsigned long misses = 0;
    unsigned long errors = 0;
    unsigned long stores = 0;
    unsigned long refused = 0;
    unsigned long reloads = 0;
    unsigned long lockbreaks = 0;
};

class Daemon {
public:
    explicit Daemon(const Options &o) : opt(o) {
    }

    bool start();
    void run();
    void stop();

private:
    bool attachSplices();
    bool loadStatements();
    void serve(int fd);
    void reply(int fd, uint8_t status, uint32_t stmt_id);
    bool store(uint32_t key, const std::vector<uint8_t> &body);
    void *keep(stmt *st, const std::vector<uint8_t> &body);
    void retireStmt(stmt *st, uint64_t now);
    void collectOrphans(uint64_t now);
    bool readExactly(int fd, void *buf, size_t n);

    /* --- the control surface, for barnacle --- */
    bool openControl();
    void control(int fd);
    void stats(std::string &out);
    void cfgSet(uint32_t slot, uint32_t val);
    void breakStaleLock(uint64_t now);
    uint32_t cfgGet(uint32_t slot);

    Options opt;
    kclient_bpf *skel = nullptr;
    bncl::daemon::Arena arena;
    bncl::daemon::Pool pool;
    bncl::StmtList list;
    bncl::Valkey valkey;
    std::unordered_map<int, uint32_t> key_of_fd;

    /* Statements already published, by text. A reload reuses these records
     * rather than making new ones: a client may be holding a pointer to
     * one, and it may hold a payload worth keeping. */
    std::unordered_map<std::string, stmt *> known;
    uint32_t next_id = 1;

    /* Records taken out of the list while a client still held one. They
     * are unreachable -- the map key is gone -- but not yet dead. */
    std::vector<stmt *> orphans;

    Counters cnt;
    /* Mirrors BNCL_CFG_LOCAL_ON, which `LOCAL on|off` moves at runtime. Held
     * here as well because serve() consults it on every lookup, and that is
     * not a place to put a bpf(2) syscall for a value an administrator
     * changes by typing a command. */
    bool local_on = true;
    time_t started = 0;
    int epfd = -1;
    int ctl_fd = -1;
    bool loaded = false;
    bool c2d_on = false, d2c_on = false;
};

bool Daemon::attachSplices() {
    /* One attach per side. Which map a program is attached to is how it
     * knows its direction -- sk_msg has no way to tell from the context. */
    if (bpf_prog_attach(bpf_program__fd(skel->progs.splice_c2d), bpf_map__fd(skel->maps.cpipe_map),
                        BPF_SK_MSG_VERDICT, 0)) {
        fprintf(stderr, "daemon: attach client->dpipe failed: %s\n", strerror(errno));
        return false;
    }
    c2d_on = true;

    if (bpf_prog_attach(bpf_program__fd(skel->progs.splice_d2c), bpf_map__fd(skel->maps.dpipe_map),
                        BPF_SK_MSG_VERDICT, 0)) {
        fprintf(stderr, "daemon: attach dpipe->client failed: %s\n", strerror(errno));
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
 *
 * --- and re-publish it, on reload -----------------------------------------
 *
 * This runs again for every `barnacle reload-config`, so it has to be
 * idempotent in a specific way: a statement that was already in the list
 * keeps the RECORD it had. Allocating a fresh one would silently throw away
 * its cached payload, and worse, a client that is mid-request holds a pointer
 * to the old record and would be answered about a statement nothing is
 * publishing any more.
 *
 * A statement removed from the list has its map key deleted, which is what
 * makes it uncacheable. The record itself stays in the arena -- the arena is
 * a bump allocator with no free -- but nothing can reach it again.
 */
bool Daemon::loadStatements() {
    bncl::StmtList fresh;
    std::string err;

    if (opt.stmt_list.empty()) {
        fprintf(stderr, "daemon: no statement list given; nothing will be "
                        "intercepted\n");
        return true;
    }
    if (!fresh.load(opt.stmt_list, err)) {
        fprintf(stderr, "daemon: %s\n", err.c_str());
        return false;
    }

    int fd = bpf_map__fd(skel->maps.stmts_map);
    std::unordered_map<std::string, stmt *> next;

    for (const std::string &sql : fresh.all()) {
        stmt_key key{};
        stmt *rec;
        stmt_ref ref;

        if (sql.size() > BNCL_STMT_MAX - 1) {
            fprintf(stderr,
                    "daemon: statement too long to cache (%zu > %d), "
                    "skipping: %.60s...\n",
                    sql.size(), BNCL_STMT_MAX - 1, sql.c_str());
            continue;
        }

        auto it = known.find(sql);

        if (it != known.end()) {
            rec = it->second;
            rec->stmt_ttl = static_cast<uint32_t>(opt.ttl);
        }
        else {
            auto *txt = static_cast<char *>(arena.put(sql.c_str(), sql.size() + 1));

            rec = static_cast<stmt *>(arena.alloc(sizeof(*rec)));
            if (!txt || !rec) {
                fprintf(stderr, "daemon: arena exhausted seeding statements\n");
                return false;
            }

            /* Zeroed, so stmt_data is NULL. That is what marks it
             * unfetched: STMT_S_LOCAL is the zero value, so state
             * alone cannot say "nothing here" -- the payload
             * pointer does. */
            memset(rec, 0, sizeof(*rec));
            /* The list's own reference. Dropped when the
             * administrator takes the statement out again. */
            rec->stmt_refs = 1;
            rec->stmt_txt = txt;
            rec->stmt_len = sql.size();
            rec->stmt_id = next_id++;
            rec->stmt_ttl = static_cast<uint32_t>(opt.ttl);
        }

        memcpy(key.text, sql.data(), sql.size());
        ref = stmtToRef(rec);
        if (bpf_map_update_elem(fd, &key, &ref, BPF_ANY)) {
            fprintf(stderr, "daemon: cannot publish statement: %s\n", strerror(errno));
            return false;
        }
        next[sql] = rec;
    }

    /*
     * Statements that left the list stop being cacheable.
     *
     * The map key goes first, so no client can newly find the record, and
     * only then is the list's reference dropped. Doing it the other way
     * round would leave a window where a lookup could resolve a record
     * that is already being reclaimed.
     *
     * If that was the last reference the record is retired rather than
     * freed: a client that resolved the pointer a moment ago may be about
     * to read it. If it was not, whoever holds the remaining reference
     * retires it when they drop it.
     */
    uint64_t now = now_ns();

    for (const auto &kv : known) {
        stmt_key key{};

        if (next.count(kv.first)) {
            continue;
        }
        memcpy(key.text, kv.first.data(), kv.first.size());
        bpf_map_delete_elem(fd, &key);
        if (bncl_stmt_put(kv.second)) {
            retireStmt(kv.second, now);
        }
        else {
            /* A client is still using it. It will drop its
             * reference when its request finishes; nobody but the
             * daemon may touch the heap, so the record waits here
             * to be collected on a later tick. */
            orphans.push_back(kv.second);
        }
    }

    known.swap(next);
    list = fresh;
    fprintf(stderr, "daemon: %zu statement(s) from %s\n", list.size(), opt.stmt_list.c_str());
    return true;
}

/*
 * The control socket barnacle talks to.
 *
 * A Unix socket rather than signals: `barnacle status` needs an answer back,
 * not just an effect, and the alternative -- the daemon writing a stats file
 * on a timer -- reports whatever was true at the last tick. It also gives
 * reload a definite success or failure, which SIGHUP cannot.
 *
 * Nothing here is a network service. It is an AF_UNIX socket in a directory
 * only root can write, carrying four verbs.
 */
bool Daemon::openControl() {
    sockaddr_un sa{};
    size_t slash;

    if (opt.ctl_path.empty()) {
        return true; /* explicitly disabled */
    }
    if (opt.ctl_path.size() >= sizeof(sa.sun_path)) {
        fprintf(stderr, "daemon: control path too long: %s\n", opt.ctl_path.c_str());
        return false;
    }

    slash = opt.ctl_path.rfind('/');
    if (slash != std::string::npos && slash > 0) {
        mkdir(opt.ctl_path.substr(0, slash).c_str(), 0755);
    }

    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, opt.ctl_path.c_str(), opt.ctl_path.size());

    /*
     * A leftover socket file from a daemon that was killed looks exactly
     * like a live one. Tell them apart by connecting: if someone answers,
     * a daemon is already running and this one must not take the pins out
     * from under it. If nobody does, the file is stale and can go.
     */
    {
        int probe = socket(AF_UNIX, SOCK_STREAM, 0);

        if (probe >= 0) {
            bool live = connect(probe, (sockaddr *)&sa, sizeof(sa)) == 0;

            ::close(probe);
            if (live) {
                fprintf(stderr,
                        "daemon: another daemon is already "
                        "listening on %s\n",
                        opt.ctl_path.c_str());
                return false;
            }
        }
    }
    unlink(opt.ctl_path.c_str());

    ctl_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctl_fd < 0) {
        fprintf(stderr, "daemon: control socket: %s\n", strerror(errno));
        return false;
    }
    if (bind(ctl_fd, (sockaddr *)&sa, sizeof(sa)) || listen(ctl_fd, 8)) {
        fprintf(stderr, "daemon: cannot listen on %s: %s\n", opt.ctl_path.c_str(), strerror(errno));
        return false;
    }
    return true;
}

void Daemon::cfgSet(uint32_t slot, uint32_t val) {
    bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &slot, &val, BPF_ANY);
}

uint32_t Daemon::cfgGet(uint32_t slot) {
    uint32_t v = 0;

    bpf_map_lookup_elem(bpf_map__fd(skel->maps.cfg), &slot, &v);
    return v;
}

/*
 * The `status` report, as plain `key value` lines.
 *
 * Text rather than JSON because the only consumer is a Python CLI that prints
 * it, and a line-per-fact format survives a field being added without either
 * side needing to agree on a schema first.
 */
void Daemon::stats(std::string &out) {
    uint64_t now = now_ns();
    size_t cached = 0;
    char buf[512];
    long keys = -1;

    unsigned long refs = 0;

    for (const auto &kv : known) {
        const stmt *st = kv.second;

        if (st->stmt_data && !expired(st, now)) {
            cached++;
        }
        /* Summed, not per-record: what matters is whether they are all still
         * held. A total below the statement count means something has taken
         * a record's last reference while it was still published, which is a
         * bug -- clients only ever put back what they got. */
        refs += __atomic_load_n(&st->stmt_refs, __ATOMIC_ACQUIRE);
    }
    if (valkey.healthy() || valkey.connect(opt.valkey_host, opt.valkey_port)) {
        valkey.dbsize(keys);
    }

    snprintf(buf, sizeof(buf),
             "pid %d\n"
             "uptime %ld\n"
             "statements %zu\n"
             "cached %zu\n"
             "refs %lu\n"
             "pipes %zu\n"
             "pipes_free %u\n"
             "hits %lu\n"
             "misses %lu\n"
             "errors %lu\n"
             "stores %lu\n"
             "refused %lu\n"
             "lockbreaks %lu\n"
             "reloads %lu\n"
             "generation %u\n"
             "client_on %u\n"
             "local_on %d\n"
             "ttl %d\n"
             "valkey %s:%u\n"
             "valkey_ok %d\n"
             "valkey_keys %ld\n"
             "arena_used %zu\n"
             "arena_cap %zu\n"
             "arena_retired %zu\n"
             "list %s\n",
             getpid(), (long)(time(nullptr) - started), list.size(), cached, refs, pool.size(),
             pool.freeCount(), cnt.hits, cnt.misses, cnt.errors, cnt.stores, cnt.refused,
             cnt.lockbreaks, cnt.reloads, cfgGet(BNCL_CFG_GENERATION), cfgGet(BNCL_CFG_CLIENT_ON),
             local_on ? 1 : 0, opt.ttl, opt.valkey_host.c_str(), (unsigned)opt.valkey_port,
             valkey.healthy() ? 1 : 0, keys, arena.used(), arena.capacity(), arena.retired(),
             opt.stmt_list.c_str());
    out = buf;
}

/*
 * Serve one control connection: one command, one answer, close.
 *
 * Handled inline rather than added to the epoll set. These connections are a
 * CLI asking one question; keeping them out of the loop's state means a
 * control client that goes away mid-sentence cannot leave anything behind.
 */
void Daemon::control(int fd) {
    char buf[256];
    std::string reply;
    ssize_t n;

    n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        ::close(fd);
        return;
    }
    buf[n] = 0;

    std::string cmd(buf);

    while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r')) {
        cmd.pop_back();
    }

    if (cmd == "PING") {
        reply = "ok\n";
    }
    else if (cmd == "STATS") {
        stats(reply);
    }
    else if (cmd == "RELOAD") {
        if (loadStatements()) {
            cnt.reloads++;
            /* Bumped AFTER the map is republished: an agent that
             * sees the new generation must find the new statements
             * already there. */
            cfgSet(BNCL_CFG_GENERATION, cfgGet(BNCL_CFG_GENERATION) + 1);
            reply = "ok " + std::to_string(list.size()) + " statement(s)\n";
        }
        else {
            reply = "error cannot reload " + opt.stmt_list + "\n";
        }
    }
    else if (cmd == "CLIENT on" || cmd == "CLIENT off") {
        cfgSet(BNCL_CFG_CLIENT_ON, cmd == "CLIENT on" ? 1 : 0);
        reply = "ok\n";
    }
    else if (cmd == "LOCAL on" || cmd == "LOCAL off") {
        local_on = cmd == "LOCAL on";
        /* Both ends have to agree, or the client stops asking about
         * statements the daemon would now happily fetch. */
        cfgSet(BNCL_CFG_LOCAL_ON, local_on ? 1 : 0);
        reply = "ok\n";
    }
    else {
        reply = "error unknown command\n";
    }

    (void)!write(fd, reply.data(), reply.size());
    ::close(fd);
}

bool Daemon::start() {
    LIBBPF_OPTS(bpf_object_open_opts, oo, .pin_root_path = BNCL_PIN_DIR);

    /*
     * Before anything touches the pins.
     *
     * openControl() is also how we find out another daemon is already
     * running, and that has to be settled first: the pinned maps outlive
     * whoever made them, so a second daemon that got as far as loading
     * would reuse the live one's maps and then, on the way out, unpin
     * them from under it.
     */
    if (!openControl()) {
        return false;
    }

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
        fprintf(stderr,
                "daemon: BPF load failed: %s (need root?)\n"
                "        \"parameter mismatch\" on a pinned map means %s holds\n"
                "        pins from a build with different map shapes; remove it.\n",
                strerror(errno), BNCL_PIN_DIR);
        return false;
    }
    loaded = true;

    {
        __u32 k, v;

        k = BNCL_CFG_ENABLED;
        v = 1;
        bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);
        k = BNCL_CFG_PORT;
        v = opt.mysql_port;
        bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);
        k = BNCL_CFG_ERROR_TTL;
        v = (__u32)opt.error_ttl;
        bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);

        /* Agents intercept by default. `barnacle detach-client` clears
         * this; a freshly started daemon is a fresh start. */
        k = BNCL_CFG_CLIENT_ON;
        v = 1;
        bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);

        /* Non-zero, so an agent that starts up already holding 0 sees
         * a difference and loads the list rather than assuming it is
         * current. */
        k = BNCL_CFG_GENERATION;
        v = 1;
        bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);

        /* Published as well as held locally: the agent needs it too.
         * Its own shortcut -- do not ask the daemon about a statement
         * the arena has nothing for -- is exactly the local tier, seen
         * from the other end. */
        local_on = opt.local_on;
        k = BNCL_CFG_LOCAL_ON;
        v = local_on ? 1 : 0;
        bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);
    }

    if (!arena.open(bpf_map__fd(skel->maps.arena))) {
        return false;
    }

    /* Nothing to initialise here: Arena::open() lays the control block out,
     * lock and heap together. Zeroing it again -- which this used to do, back
     * when the lock was all it held -- wipes the free list the allocator was
     * just given and every allocation fails. */
    if (!attachSplices()) {
        return false;
    }
    if (!loadStatements()) {
        return false;
    }

    bncl::daemon::PoolMaps pm;

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
        const auto *p = pool.byKey(i);
        epoll_event ev{};

        ev.events = EPOLLIN;
        ev.data.fd = p->sfd;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, p->sfd, &ev)) {
            fprintf(stderr, "daemon: epoll_ctl failed: %s\n", strerror(errno));
            return false;
        }
        key_of_fd[p->sfd] = p->key;
    }

    if (ctl_fd >= 0) {
        epoll_event ev{};

        ev.events = EPOLLIN;
        ev.data.fd = ctl_fd;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, ctl_fd, &ev)) {
            fprintf(stderr, "daemon: epoll_ctl(control) failed: %s\n", strerror(errno));
            return false;
        }
    }

    valkey.connect(opt.valkey_host, opt.valkey_port);
    if (!valkey.healthy()) {
        fprintf(stderr,
                "daemon: warning -- Valkey %s:%u unreachable; every lookup "
                "will report CACHE_ERROR\n",
                opt.valkey_host.c_str(), (unsigned)opt.valkey_port);
    }

    started = time(nullptr);
    fprintf(stderr,
            "daemon: ready -- %u pipes, %u stmt slots, arena %zu KiB at %#llx,\n"
            "        pins under %s, cache %s:%u, mysql port %u\n"
            "        control %s, local tier %s\n",
            opt.pipes, opt.max_stmts, arena.capacity() / 1024, (unsigned long long)BNCL_ARENA_VA,
            BNCL_PIN_DIR, opt.valkey_host.c_str(), (unsigned)opt.valkey_port,
            (unsigned)opt.mysql_port, opt.ctl_path.empty() ? "(none)" : opt.ctl_path.c_str(),
            local_on ? "on" : "bypassed");
    return true;
}

void Daemon::reply(int sfd, uint8_t status, uint32_t stmt_id) {
    agent_reply r{};

    r.status = status;
    r.stmt_id = stmt_id;

    /* On sfd, which is the socket dpipe_map holds -- that is what lets
     * sk_msg see this send at all. The redirect puts these four bytes in
     * the client's receive queue, which is what wakes it. On AGENT_OK the
     * payload is already in the arena. */
    if (write(sfd, &r, sizeof(r)) != (ssize_t)sizeof(r)) {
        fprintf(stderr, "daemon: short reply on fd %d: %s\n", sfd, strerror(errno));
    }
}

bool Daemon::readExactly(int fd, void *buf, size_t n) {
    auto *p = static_cast<uint8_t *>(buf);
    size_t got = 0;

    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);

        if (r <= 0) {
            return false;
        }
        got += static_cast<size_t>(r);
    }
    return true;
}

/*
 * Take a response a client observed and put it in the cache.
 *
 * The bytes arrive already canonicalised -- the client parsed what the server
 * sent and re-encoded it under BNCL_CANONICAL_CAPS -- so what is stored no
 * longer carries the framing decisions of the connection it came from. It
 * goes to Valkey for other machines and into the arena for this one.
 */
bool Daemon::store(uint32_t key, const std::vector<uint8_t> &body) {
    dpipe rec{};

    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.dpipes), &key, &rec) || !rec.stmt) {
        return false;
    }

    auto *st = rec.stmt;
    std::string sql(st->stmt_txt ? st->stmt_txt : "", static_cast<size_t>(st->stmt_len));

    if (sql.empty() || body.empty()) {
        return false;
    }

    /* Refuse anything that does not parse as a result set. A client should
     * not be able to poison the cache with bytes nobody can replay, and
     * the check is cheap next to the fetch that produced them. */
    bncl::mysql_proto::ResultSet rs;

    if (!bncl::mysql_proto::parseResultSet(body.data(), body.size(), BNCL_CANONICAL_CAPS, rs)) {
        fprintf(stderr, "daemon: refusing unparseable response for %.40s\n", sql.c_str());
        cnt.refused++;
        return false;
    }
    if (rs.status & bncl::mysql_proto::SERVER_STATUS_IN_TRANS) {
        /* Produced inside a transaction: may reflect uncommitted state
         * private to that session. */
        cnt.refused++;
        return false;
    }

    if (valkey.healthy() || valkey.connect(opt.valkey_host, opt.valkey_port)) {
        valkey.setex("bncl:" + sql, body, opt.ttl);
    }

    /* Bytes into the arena first, then the record that points at them: a
     * reader that sees a payload must be able to trust it is there. */
    void *p = keep(st, body);

    if (!p) {
        return false;
    }

    timespec ts{};

    clock_gettime(CLOCK_MONOTONIC, &ts);
    st->stmt_data = p;
    st->stmt_data_len = body.size();
    st->stmt_ttl = static_cast<uint32_t>(opt.ttl);
    st->stmt_ts =
        static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
    __atomic_store_n(&st->stmt_state, STMT_S_LOCAL, __ATOMIC_RELEASE);
    cnt.stores++;

    if (opt.verbose) {
        fprintf(stderr, "daemon: STORE %zu bytes, %zu row(s)  %.40s\n", body.size(), rs.rows.size(),
                sql.c_str());
    }

    return true;
}

/*
 * Put a payload in the arena for a statement, reusing what is there when the
 * bytes are identical.
 *
 * Only an optimisation in the normal case, where a statement is fetched once
 * per TTL. It matters with the local tier bypassed, where EVERY lookup fetches
 * and would otherwise allocate: the arena is a bump allocator that wraps, so
 * that turns into a continuous churn which evicts other statements' payloads
 * long before their TTL and makes the wrap counter meaningless as a signal
 * that the arena is too small.
 *
 * Identical bytes only. Overwriting a chunk in place with DIFFERENT bytes
 * would be visible to a client reading it right now, and a half-old result set
 * is worse than any amount of churn. When the data really has changed, this
 * allocates, and the ordering rule -- payload written before the record that
 * points at it -- is what keeps that safe.
 */
/*
 * Give a dead statement record, and the payload it owns, back to the heap.
 *
 * Retired rather than freed: both may be under a client's eye at this
 * instant, and the grace period is what covers the gap between a client
 * resolving a pointer and taking its reference on what it found.
 */
/*
 * Retire records whose last client has finally let go.
 *
 * Only the daemon writes the heap, so a client that drops the last reference
 * cannot retire the record itself; it just leaves the count at zero and moves
 * on. This is the other half of that, run on the idle tick.
 */
void Daemon::collectOrphans(uint64_t now) {
    size_t keep = 0;

    for (size_t i = 0; i < orphans.size(); i++) {
        stmt *st = orphans[i];

        if (__atomic_load_n(&st->stmt_refs, __ATOMIC_ACQUIRE) == 0) {
            retireStmt(st, now);
        }
        else {
            orphans[keep++] = st;
        }
    }
    orphans.resize(keep);
}

void Daemon::retireStmt(stmt *st, uint64_t now) {
    if (st->stmt_data) {
        arena.retire(st->stmt_data, now);
        st->stmt_data = 0;
        st->stmt_data_len = 0;
    }
    if (st->stmt_txt) {
        arena.retire(const_cast<char *>(st->stmt_txt), now);
        st->stmt_txt = 0;
    }
    arena.retire(st, now);
}

void *Daemon::keep(stmt *st, const std::vector<uint8_t> &body) {
    if (st->stmt_data && st->stmt_data_len == body.size() &&
        memcmp(st->stmt_data, body.data(), body.size()) == 0) {
        return st->stmt_data;
    }

    void *p = arena.put(body.data(), body.size());

    /*
     * The old payload is dead the moment the record stops pointing at it,
     * but a client may be copying it out right now -- so it is retired,
     * not freed. Only after the new one is safely allocated: failing
     * here must leave the record exactly as it was.
     */
    if (p && st->stmt_data) {
        arena.retire(st->stmt_data, now_ns());
    }
    return p;
}

/*
 * Free the pipe-freelist lock if whoever took it never gave it back.
 *
 * A client holds it for three bpf(2) calls. If it is still held a second
 * later, the process that took it died in that window -- injected code lives
 * inside applications, and applications are killed at arbitrary moments. Left
 * alone, every attached client would fail to take a pipe from then on and the
 * cache would quietly stop working.
 *
 * The daemon breaks it rather than the clients, because a client cannot tell
 * a dead holder from a live one: a pid means nothing across the PID
 * namespaces they may be in, while elapsed time means the same to everyone.
 */
void Daemon::breakStaleLock(uint64_t now) {
    bncl_ctl *c = arena.ctl();

    if (!c || !__atomic_load_n(&c->lock, __ATOMIC_ACQUIRE)) {
        return;
    }

    uint64_t taken = __atomic_load_n(&c->taken_ns, __ATOMIC_RELAXED);

    if (!taken || now < taken || now - taken < 1000000000ull) {
        return;
    }
    __atomic_store_n(&c->lock, 0u, __ATOMIC_RELEASE);
    cnt.lockbreaks++;
    fprintf(stderr,
            "daemon: freed the pipe lock, held %llums -- a client "
            "died holding it\n",
            (unsigned long long)((now - taken) / 1000000ull));
}

void Daemon::serve(int fd) {
    bncl_req req{};

    if (!readExactly(fd, &req, sizeof(req))) {
        return;
    }

    auto it = key_of_fd.find(fd);

    if (it == key_of_fd.end()) {
        return;
    }

    uint32_t key = it->second;

    if (req.kind == BNCL_REQ_STORE) {
        std::vector<uint8_t> body(req.len);

        if (req.len == 0 || req.len > BNCL_STORE_MAX || !readExactly(fd, body.data(), req.len)) {
            return;
        }
        store(key, body);
        /* No reply: the client is not waiting. It already has the
         * answer -- that is where these bytes came from.
         *
         * And no release. The client owns that, per architecture.txt:
         * it pops the freelist, so it puts the key back. Releasing here
         * too pushes the same key onto the freelist twice, and two
         * clients then splice different connections to one dpipe.
         */
        return;
    }
    dpipe rec{};

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
        bncl::daemon::Pipe *p = pool.byKey(key);
        pipe_sk_info ci{};

        ci.key = key; /* dpipe[key] is spliced to cpipe[key] */
        ci.paired = 1;
        /* On sfd: the socket we are about to send from, and the one
         * sk_msg will consult. */
        if (!p ||
            bpf_map_update_elem(bpf_map__fd(skel->maps.pipe_sk_info_map), &p->sfd, &ci, BPF_ANY)) {
            fprintf(stderr, "daemon: cannot splice dpipe %u back: %s\n", key, strerror(errno));
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
        /* The client releases on seeing this status; doing it here as
         * well would put the key on the freelist twice. */
        cnt.errors++;
        reply(fd, AGENT_CACHE_ERROR, 0);
        return;
    }

    auto *st = rec.stmt;
    uint64_t now = now_ns();
    uint8_t status;

    /* A hit needs all four: the local tier has to be allowed to answer at
     * all, and then the right state, an actual payload, and one that has
     * not aged out. STMT_S_LOCAL is the zero value, so state alone would
     * call every unseeded record a hit. */
    if (local_on && st->stmt_state == STMT_S_LOCAL && st->stmt_data && !expired(st, now)) {
        status = AGENT_OK;
    }
    else if (!valkey.healthy() && !valkey.connect(opt.valkey_host, opt.valkey_port)) {
        status = AGENT_CACHE_ERROR;
    }
    else {
        std::string sql(st->stmt_txt ? st->stmt_txt : "", static_cast<size_t>(st->stmt_len));
        std::vector<uint8_t> payload;

        if (!sql.empty() && valkey.get("bncl:" + sql, payload) && !payload.empty()) {
            /* Bytes into the arena FIRST, then the record that
             * points at them. A reader that sees STMT_S_LOCAL must
             * be able to trust the payload is already there. */
            void *p = keep(st, payload);

            if (p) {
                st->stmt_data = p;
                st->stmt_data_len = payload.size();
                st->stmt_ttl = static_cast<uint32_t>(opt.ttl);
                st->stmt_ts = now;
                __atomic_store_n(&st->stmt_state, STMT_S_LOCAL, __ATOMIC_RELEASE);
                status = AGENT_OK;
            }
            else {
                status = AGENT_CACHE_ERROR;
            }
        }
        else {
            /* Nothing upstream either. Drop the stale local copy so
             * the next request re-fetches rather than serving bytes
             * we have just been told are gone. */
            st->stmt_data = 0;
            st->stmt_data_len = 0;
            st->stmt_ts = 0;

            status = AGENT_WRITE_THROUGH;
        }
    }

    if (status == AGENT_OK) {
        cnt.hits++;
    }
    else if (status == AGENT_WRITE_THROUGH) {
        cnt.misses++;
    }
    else {
        cnt.errors++;
    }

    if (opt.verbose) {
        const char *what = status == AGENT_OK              ? "HIT"
                           : status == AGENT_WRITE_THROUGH ? "MISS"
                                                           : "ERROR";

        fprintf(stderr, "daemon: %-5s dpipe=%u stmt=%u\n", what, key, st->stmt_id);
    }

    reply(fd, status, st->stmt_id);

    /* The client releases the dpipe, not us. architecture.txt puts that on
     * the client, and releasing here as well would push the same key onto
     * the freelist twice -- handing one pipe to two connections. */
}

void Daemon::run() {
    std::vector<epoll_event> events(64);

    while (!exiting_s) {
        int n = epoll_wait(epfd, events.data(), (int)events.size(), 500);

        /* What the idle tick is for: a client that died holding the
         * freelist lock leaves nothing else to notice it, and retired
         * memory needs somebody to come back and free it once its
         * grace period has passed. */
        uint64_t tick = now_ns();

        breakStaleLock(tick);
        collectOrphans(tick);
        arena.reclaim(tick);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == ctl_fd) {
                int c = accept(ctl_fd, nullptr, nullptr);

                if (c >= 0) {
                    control(c);
                }
                continue;
            }
            serve(fd);
        }
    }
}

void Daemon::stop() {
    pool.shutdown();
    if (ctl_fd >= 0) {
        ::close(ctl_fd);
        unlink(opt.ctl_path.c_str());
    }
    if (epfd >= 0) {
        ::close(epfd);
    }
    if (c2d_on && skel) {
        bpf_prog_detach2(bpf_program__fd(skel->progs.splice_c2d), bpf_map__fd(skel->maps.cpipe_map),
                         BPF_SK_MSG_VERDICT);
    }
    if (d2c_on && skel) {
        bpf_prog_detach2(bpf_program__fd(skel->progs.splice_d2c), bpf_map__fd(skel->maps.dpipe_map),
                         BPF_SK_MSG_VERDICT);
    }
    arena.close();

    /*
     * Take the pins with us.
     *
     * They would otherwise outlive the process, and an agent injected
     * afterwards would open a complete-looking set of maps belonging to a
     * daemon that is not there -- so every intercepted query would wait
     * out the client's timeout instead of simply not being intercepted.
     * It also means a rebuild that changes a map's shape can just be
     * restarted, rather than failing to reuse pins from the old one.
     *
     * Only when we got as far as loading, so a daemon that bailed out
     * early never removes a running one's pins.
     */
    if (loaded && skel) {
        bpf_object__unpin_maps(skel->obj, BNCL_PIN_DIR);
        rmdir(BNCL_PIN_DIR);
    }
    if (skel) {
        kclient_bpf__destroy(skel);
    }
}

void usage(const char *prog) {
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
            "  -s PATH   control socket (default %s, empty to disable)\n"
            "  -R        bypass the local tier: send every lookup to Valkey\n"
            "  -v        verbose\n",
            prog, BNCL_MAX_STMTS, BNCL_MAX_PIPES, BNCL_CTL_SOCK);
}

} // namespace

int main(int argc, char **argv) {
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
        }
        else if (a == "-H") {
            opt.valkey_host = next();
        }
        else if (a == "-P") {
            opt.valkey_port = static_cast<uint16_t>(atoi(next()));
        }
        else if (a == "-m") {
            opt.mysql_port = static_cast<uint16_t>(atoi(next()));
        }
        else if (a == "-n") {
            opt.pipes = static_cast<uint32_t>(atoi(next()));
        }
        else if (a == "-S") {
            opt.max_stmts = static_cast<uint32_t>(atoi(next()));
        }
        else if (a == "-C") {
            opt.max_pipes = static_cast<uint32_t>(atoi(next()));
        }
        else if (a == "-t") {
            opt.ttl = atoi(next());
        }
        else if (a == "-e") {
            opt.error_ttl = atoi(next());
        }
        else if (a == "-s") {
            opt.ctl_path = next();
        }
        else if (a == "-R") {
            opt.local_on = false;
        }
        else if (a == "-v") {
            opt.verbose = true;
        }
        else {
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
