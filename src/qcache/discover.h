// SPDX-License-Identifier: GPL-2.0
/*
 * discover.h - find candidate processes, then work out whether they can
 * actually be attached to.
 *
 * Discovery runs on the host and looks straight at /proc. With the host PID
 * namespace, processes inside containers are visible there like any other --
 * a container is a cgroup and some namespaces, not a separate process table.
 * So there is no need to talk to Docker, and nothing breaks under containerd,
 * podman, or a bare host.
 *
 * Finding a process is the easy half. The useful half is deciding whether
 * attaching would actually work, because several things have to line up and
 * each one has bitten this project already:
 *
 *   - a TLS library has to be mapped, and it has to be OpenSSL. Go and Java
 *     do TLS in-process with no libssl to hook at all.
 *   - the symbols matter, not just the library. The mysql CLI calls
 *     SSL_read/SSL_write while CPython's _ssl calls only the _ex variants, so
 *     a probe hooking one family silently misses the other.
 *   - libssl is often dlopen'd late, so a process can be a valid target while
 *     not yet having it mapped.
 *   - and there has to be an actual connection to the database, or there is
 *     nothing to cache.
 *
 * Reporting all of that is the difference between "attached, nothing
 * happened" and knowing why.
 */
#ifndef VALKEY_EBPF_QCACHE_DISCOVER_H
#define VALKEY_EBPF_QCACHE_DISCOVER_H

#include "config.h"

#include <cstdint>
#include <string>
#include <vector>

namespace qcache {

enum class TlsKind {
	None,     /* no TLS library mapped (yet) */
	OpenSSL,  /* libssl -- supported */
	GnuTLS,   /* mapped but unsupported */
	NSS,      /* mapped but unsupported */
	Unknown,
};

const char *tlsKindName(TlsKind k);

/* Why a process cannot be attached to, when it cannot. */
enum class Verdict {
	Attachable,
	NoTlsLibrary,     /* nothing mapped; may just not have connected yet */
	UnsupportedTls,   /* GnuTLS/NSS/etc -- out of scope */
	NoSslSymbols,     /* libssl mapped but stripped, or statically linked */
	NoDatabaseConn,   /* attachable, but not talking to the database */
	AlreadyAttached,
};

const char *verdictName(Verdict v);

struct Process {
	int pid = 0;
	std::string comm;
	std::string cmdline;
	std::string container;     /* id or name, empty when on the host */
	std::string container_kind; /* docker, podman, containerd, host */

	/* True when a container filter was applied but this process's
	 * container could not be determined -- which happens for our own
	 * container's processes when qcache runs inside a cgroup namespace
	 * instead of on the host. Reported rather than silently matched. */
	bool container_unattributable = false;

	/* Filled in by analyse(). */
	TlsKind tls = TlsKind::None;
	std::string libssl_path;   /* as seen from the host, via /proc/<pid>/root */
	bool has_classic_syms = false; /* SSL_read / SSL_write */
	bool has_ex_syms = false;      /* SSL_read_ex / SSL_write_ex */
	int db_connections = 0;        /* established sockets to the target port */
	Verdict verdict = Verdict::NoTlsLibrary;

	const Target *target = nullptr;
};

/* Enumerate /proc and return processes matching any configured target. */
std::vector<Process> discover(const Config &cfg, std::string &err);

/* Inspect one process: what TLS library it has mapped, which symbol families
 * that library exports, and whether it holds connections to the target port.
 * Sets `verdict`. */
void analyse(Process &p);

/* Human-readable one-line summary, for the report. */
std::string describe(const Process &p);

} // namespace qcache

#endif /* VALKEY_EBPF_QCACHE_DISCOVER_H */
