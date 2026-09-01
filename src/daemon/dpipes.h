// SPDX-License-Identifier: GPL-2.0
#pragma once
/*
 * dpipes.h - the dpipe pool.
 *
 * A dpipe is a loopback TCP connection the daemon makes to itself and holds
 * both ends of. The daemon writes the mini-protocol into it, and KCLIENT's
 * sk_msg program redirects those bytes into the spliced client socket's
 * receive queue rather than letting them travel to the other end.
 *
 * Loopback TCP rather than socketpair(2), measured rather than assumed: sk_msg
 * is installed by replacing sk_prot->sendmsg, which tcp_bpf does and unix_bpf
 * does not, so an AF_UNIX socket enters the map without complaint and then
 * silently never runs the program on send. See tests/test_xproc.c
 * --socketpair.
 *
 * --- who does i/o on which end -------------------------------------------
 *
 * The daemon reads and writes sfd, which is also the end registered in
 * dpipe_map -- one fact, not two. sk_msg runs only on sends from a socket the
 * map holds, so the daemon's i/o end must be the registered one, and
 * BPF_F_INGRESS delivers the client's writes into that same socket. cfd is
 * never touched; it only keeps the connection established.
 *
 * --- the pool is published, not private -----------------------------------
 *
 * The daemon builds the pipes, but the CLIENT takes one: it pops an index off
 * dpipe_freelist and decrements dpipes_meta.num_free. So the free list lives
 * in a shared map rather than in daemon memory, and both sides move num_free
 * atomically. A client that loses the race simply passes its query through --
 * exhaustion must never block anyone.
 */

#include "common/defs.h"

#include <cstddef>
#include <cstdint>
#include <vector>

/* Namespace is `bncld`, not `bncl::daemon` or `daemon`: <unistd.h> declares
 * daemon(int, int), and a namespace of that name collides with it. */
namespace bncld
{

struct Pipe {
    uint32_t key = 0; /* index in dpipe_map, dpipes and the freelist */
    int sfd = -1;     /* the daemon's i/o end; this is what dpipe_map holds */
    int cfd = -1;     /* far end, held open only to keep the connection up */
};

/* The map descriptors the pool needs. Grouped so the daemon can hand them
 * over in one go rather than as five positional arguments. */
struct PoolMaps {
    int dpipe_map = -1;
    int dpipes = -1;
    int freelist = -1;
    int meta = -1;
    int info = -1;
};

class Pool
{
public:
    /* Build `count` pipes, register each in dpipe_map, write its record to
     * dpipes, and publish its key on the freelist. */
    bool init(const PoolMaps &m, size_t count);
    void shutdown();

    size_t size() const
    {
        return pipes.size();
    }

    /* The pipe behind a key, or nullptr. The daemon needs this to turn the
     * key a client published back into something it can write to. */
    Pipe *byKey(uint32_t key);

    /* Every sfd, for the daemon's epoll set. */
    std::vector<int> fds() const;

    /* Put a key back on the freelist and clear its splice. Called when a
     * request finishes; leaving it spliced would redirect a later,
     * unrelated write into a client that has moved on. */
    bool release(uint32_t key);

    /* How many keys are currently on the freelist. */
    uint32_t freeCount() const;

private:
    bool makePipe(Pipe &p);
    bool publish(const Pipe &p);

    PoolMaps maps;
    std::vector<Pipe> pipes;
    int listen_fd = -1;
};

} // namespace bncld
