// SPDX-License-Identifier: GPL-2.0
#include "valkey.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace bncl {
namespace {

/* The cache's own socket operations must call straight into libc. If they
 * went through the interposed read()/recv() in preload.cpp, a cache lookup
 * performed while a connection is "armed" would be handed the EINTR meant for
 * the traced application -- and the cache would appear to be permanently
 * broken. These pointers are resolved once, directly against libc. */
ssize_t (*raw_read)(int, void *, size_t);
ssize_t (*raw_write)(int, const void *, size_t);

void initRaw() {
    if (raw_read) {
        return;
    }
    /* dlsym(RTLD_NEXT) is not usable here: this translation unit is part
     * of the preload object itself, so RTLD_NEXT skips past us to libc,
     * which is exactly what we want -- but only if the symbol was
     * interposed. Using dlvsym-free plain lookups keeps it simple. */
    raw_read = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
    raw_write = (ssize_t (*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
}

} // namespace

Valkey::~Valkey() {
    disconnect();
}

void Valkey::disconnect() {
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    inbuf_.clear();
}

bool Valkey::connect(const std::string &host, uint16_t port) {
    addrinfo hints{};
    addrinfo *res = nullptr;
    char portstr[16];

    initRaw();
    if (fd_ >= 0) {
        return true;
    }
    host_ = host;
    port_ = port;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    if (getaddrinfo(host.c_str(), portstr, &hints, &res) != 0 || !res) {
        return false;
    }
    fd_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd_ < 0) {
        freeaddrinfo(res);
        return false;
    }
    if (::connect(fd_, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd_);
        fd_ = -1;
        freeaddrinfo(res);
        return false;
    }
    freeaddrinfo(res);

    /* Cache lookups are small and latency-critical; batching them would
     * defeat the purpose. */
    int one = 1;

    setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return true;
}

bool Valkey::sendCommand(const std::vector<std::string> &args) {
    std::string out = "*" + std::to_string(args.size()) + "\r\n";

    for (const auto &a : args) {
        out += "$" + std::to_string(a.size()) + "\r\n";
        out += a;
        out += "\r\n";
    }

    size_t off = 0;

    while (off < out.size()) {
        ssize_t n = raw_write(fd_, out.data() + off, out.size() - off);

        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            disconnect();
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

bool Valkey::readLine(std::string &line) {
    for (;;) {
        size_t nl = inbuf_.find("\r\n");

        if (nl != std::string::npos) {
            line = inbuf_.substr(0, nl);
            inbuf_.erase(0, nl + 2);
            return true;
        }

        char tmp[4096];
        ssize_t n = raw_read(fd_, tmp, sizeof(tmp));

        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            disconnect();
            return false;
        }
        inbuf_.append(tmp, (size_t)n);
    }
}

bool Valkey::readExactly(size_t want, std::vector<uint8_t> &out) {
    while (inbuf_.size() < want) {
        char tmp[8192];
        ssize_t n = raw_read(fd_, tmp, sizeof(tmp));

        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            disconnect();
            return false;
        }
        inbuf_.append(tmp, (size_t)n);
    }
    out.assign(inbuf_.begin(), inbuf_.begin() + (long)want);
    inbuf_.erase(0, want);
    return true;
}

bool Valkey::get(const std::string &key, std::vector<uint8_t> &out) {
    std::string line;

    if (fd_ < 0 && !connect(host_, port_)) {
        return false;
    }
    if (!sendCommand({"GET", key})) {
        return false;
    }
    if (!readLine(line) || line.empty()) {
        return false;
    }

    if (line[0] == '$') {
        long n = strtol(line.c_str() + 1, nullptr, 10);

        if (n < 0) {
            return false; /* nil: cache miss */
        }
        std::vector<uint8_t> body;

        if (!readExactly((size_t)n + 2, body)) { /* value + CRLF */
            return false;
        }
        body.resize((size_t)n);
        out = std::move(body);
        return true;
    }
    /* Anything else (error, unexpected type) means desync or a server
     * error; drop the connection rather than attempt to resynchronize. */
    if (line[0] == '-') {
        return false;
    }
    disconnect();
    return false;
}

bool Valkey::dbsize(long &out) {
    std::string line;

    if (fd_ < 0 && !connect(host_, port_)) {
        return false;
    }
    if (!sendCommand({"DBSIZE"})) {
        return false;
    }
    if (!readLine(line) || line.size() < 2 || line[0] != ':') {
        return false;
    }
    out = strtol(line.c_str() + 1, nullptr, 10);
    return true;
}

bool Valkey::setex(const std::string &key, const std::vector<uint8_t> &val, int ttl_secs) {
    std::string line;
    std::string body((const char *)val.data(), val.size());

    if (fd_ < 0 && !connect(host_, port_)) {
        return false;
    }
    if (ttl_secs <= 0) {
        ttl_secs = 1;
    }
    if (!sendCommand({"SETEX", key, std::to_string(ttl_secs), body})) {
        return false;
    }
    if (!readLine(line)) {
        return false;
    }
    return !line.empty() && line[0] == '+';
}

} // namespace bncl
