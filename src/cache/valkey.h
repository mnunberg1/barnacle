// SPDX-License-Identifier: GPL-2.0
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
#ifndef VALKEY_EBPF_CACHE_VALKEY_H
#define VALKEY_EBPF_CACHE_VALKEY_H

#include <cstdint>
#include <string>
#include <vector>

namespace cache {

class Valkey {
public:
	~Valkey();

	/* Lazily connects on first use. Returns false if unreachable; the
	 * caller is expected to carry on without a cache. */
	bool connect(const std::string &host, uint16_t port);

	bool get(const std::string &key, std::vector<uint8_t> &out);
	bool setex(const std::string &key, const std::vector<uint8_t> &val, int ttl_secs);

	bool healthy() const
	{
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

} // namespace cache

#endif /* VALKEY_EBPF_CACHE_VALKEY_H */
