// SPDX-License-Identifier: GPL-2.0
#include "daemon/dpipes.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>

namespace bncld
{

bool Pool::makePipe(Pipe &p)
{
    struct sockaddr_in addr{};
    socklen_t alen = sizeof(addr);
    int cfd, sfd;

    if (getsockname(listen_fd, (struct sockaddr *)&addr, &alen)) {
        return false;
    }

    cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) {
        return false;
    }
    if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr))) {
        ::close(cfd);
        return false;
    }
    sfd = accept(listen_fd, nullptr, nullptr);
    if (sfd < 0) {
        ::close(cfd);
        return false;
    }

    /* Mini-protocol writes are four bytes and latency-critical. Nagle would
     * batch them and defeat the entire point of the fast path. */
    int one = 1;

    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    p.cfd = cfd;
    p.sfd = sfd;
    return true;
}

bool Pool::publish(const Pipe &p)
{
    struct dpipe rec{};

    /* Register the socket first, then describe it, then advertise it. A
     * client that sees the key on the freelist must find both the socket
     * and the record already there. */
    if (bpf_map_update_elem(maps.dpipe_map, &p.key, &p.sfd, BPF_ANY)) {
        fprintf(stderr, "pool: dpipe_map[%u] failed: %s\n", p.key, strerror(errno));
        return false;
    }

    rec.key = p.key;
    rec.cfd = (uint32_t)p.cfd;
    rec.sfd = (uint32_t)p.sfd;
    if (bpf_map_update_elem(maps.dpipes, &p.key, &rec, BPF_ANY)) {
        fprintf(stderr, "pool: dpipes[%u] failed: %s\n", p.key, strerror(errno));
        return false;
    }

    return release(p.key);
}

bool Pool::init(const PoolMaps &m, size_t count)
{
    struct sockaddr_in addr{};
    struct dpipes_meta meta{};
    uint32_t zero = 0;

    maps = m;

    /* One shared listener for every pipe: the pipes are all connections to
     * this same address, so there is no reason to bind one per pipe. */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        return false;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* any free port */
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(listen_fd, 64)) {
        fprintf(stderr, "pool: listener failed: %s\n", strerror(errno));
        return false;
    }

    /* Start from an empty freelist: whatever a previous run left pinned
     * refers to descriptors that died with it. */
    if (bpf_map_update_elem(maps.meta, &zero, &meta, BPF_ANY)) {
        fprintf(stderr, "pool: meta reset failed: %s\n", strerror(errno));
        return false;
    }

    pipes.resize(count);
    for (size_t i = 0; i < count; i++) {
        Pipe &p = pipes[i];

        p.key = (uint32_t)i;
        if (!makePipe(p)) {
            fprintf(stderr, "pool: could not build pipe %zu: %s\n", i, strerror(errno));
            return false;
        }
        if (!publish(p)) {
            return false;
        }
    }

    /* serial is where the NEXT key would come from. Pipes are preallocated
     * here, so it starts past the last one. */
    meta.serial = (uint32_t)count;
    meta.num_free = (uint32_t)count;
    if (bpf_map_update_elem(maps.meta, &zero, &meta, BPF_ANY)) {
        return false;
    }
    return true;
}

bool Pool::release(uint32_t key)
{
    struct dpipes_meta meta{};
    uint32_t zero = 0;

    if (bpf_map_lookup_elem(maps.meta, &zero, &meta)) {
        return false;
    }
    /*
     * Refuse to push a key that is already on the freelist.
     *
     * The client owns the release (architecture.txt), so nothing here
     * should ever be releasing a live pipe -- this exists so that a
     * mistake about that corrupts nothing. Pushing a key twice makes it
     * pop twice, and two clients then splice different connections to one
     * dpipe, which is a data-crossing bug rather than a lost request.
     *
     * A full freelist means every pipe is already free, so any release is
     * a duplicate; below that, look for the key itself. The scan is over
     * num_free entries on a path that runs once per statement, against a
     * pool of a few thousand.
     */
    if (meta.num_free >= pipes.size() && !pipes.empty()) {
        return true;
    }
    for (uint32_t i = 0; i < meta.num_free; i++) {
        uint32_t have = 0;

        if (bpf_map_lookup_elem(maps.freelist, &i, &have) == 0 && have == key) {
            return true;
        }
    }

    uint32_t slot = meta.num_free;

    if (bpf_map_update_elem(maps.freelist, &slot, &key, BPF_ANY)) {
        return false;
    }

    /* The key has to be visible in the slot before num_free admits the slot
     * exists, or a client could pop an index that has not been written. */
    meta.num_free = slot + 1;
    return bpf_map_update_elem(maps.meta, &zero, &meta, BPF_ANY) == 0;
}

uint32_t Pool::freeCount() const
{
    struct dpipes_meta meta{};
    uint32_t zero = 0;

    if (bpf_map_lookup_elem(maps.meta, &zero, &meta)) {
        return 0;
    }
    return meta.num_free;
}

Pipe *Pool::byKey(uint32_t key)
{
    if (key >= pipes.size()) {
        return nullptr;
    }
    return &pipes[key];
}

std::vector<int> Pool::fds() const
{
    std::vector<int> out;

    out.reserve(pipes.size());
    for (const Pipe &p : pipes) {
        out.push_back(p.cfd);
    }
    return out;
}

void Pool::shutdown()
{
    for (Pipe &p : pipes) {
        if (p.cfd >= 0) {
            ::close(p.cfd);
        }
        if (p.sfd >= 0) {
            ::close(p.sfd);
        }
    }
    pipes.clear();
    if (listen_fd >= 0) {
        ::close(listen_fd);
        listen_fd = -1;
    }
}

} // namespace bncld
