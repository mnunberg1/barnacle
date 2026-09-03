// SPDX-License-Identifier: GPL-2.0
#pragma once
/*
 * valkey.h - a deliberately tiny, binary-safe Valkey/Redis client.
 *
 * Only what the cache needs: GET, SETEX, and a liveness PING. Cached MySQL
 * responses are raw protocol bytes containing NULs, so every path here is
 * length-delimited rather than NUL-terminated.
 *
 * Hand-rolled rather than pulled in as a dependency because this code is
 * loaded into arbitrary client processes via LD_PRELOAD. Anything linked here
 * ends up in the address space of every traced application, so the smaller
 * and more predictable the better -- a full client library would bring
 * allocators, threads and signal handlers along with it.
 *
 * Failure is always non-fatal: a cache that cannot be reached must degrade to
 * "no caching", never to a broken application.
 */
#include <cstdint>
#include <string>
#include <vector>

namespace bncl {

class Valkey {
public:
    ~Valkey();

    /* Lazily connects on first use. Returns false if unreachable; the
     * caller is expected to carry on without a cache. */
    bool connect(const std::string &host, uint16_t port);

    bool get(const std::string &key, std::vector<uint8_t> &out);
    bool setex(const std::string &key, const std::vector<uint8_t> &val, int ttl_secs);

    /* How many keys the server holds. Only `barnacle status` wants this --
     * "how many caches are saved" is a question about the shared tier, and
     * the daemon's own count answers only for this host. */
    bool dbsize(long &out);

    bool healthy() const {
        return fd_ >= 0;
    }

    /* Drop the connection; the next call reconnects. Used when the
     * protocol desynchronizes, which is safer than trying to resync. */
    void disconnect();

private:
    bool sendCommand(const std::vector<std::string> &args);
    bool readLine(std::string &line);
    bool readExactly(size_t n, std::vector<uint8_t> &out);

    int fd_ = -1;
    std::string host_;
    uint16_t port_ = 0;
    std::string inbuf_;
};

} // namespace bncl
