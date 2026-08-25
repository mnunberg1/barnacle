// SPDX-License-Identifier: GPL-2.0
/*
 * config.h - what to look for, and what to do when it is found.
 *
 * The entry point runs on the host and has to decide, out of every process on
 * the machine, which ones are worth attaching to. That decision is
 * configuration rather than code: which program, in which containers, talking
 * to which database.
 *
 * Format is deliberately plain `key = value` in `[section]` blocks -- no YAML
 * or JSON dependency for something this small, and it stays readable in a
 * diff.
 *
 *   [target shop-app]
 *   comm       = python3
 *   cmdline    = workload.py
 *   container  = vebpf-bpf
 *   mysql_port = 3306
 *   statements = config/cache.list
 *   ttl        = 60
 */
#ifndef VALKEY_EBPF_QCACHE_CONFIG_H
#define VALKEY_EBPF_QCACHE_CONFIG_H

#include <cstdint>
#include <string>
#include <vector>

namespace qcache {

/* One class of process worth caching for. Every matcher is optional; an empty
 * matcher means "do not filter on this". A target with no matchers at all is
 * rejected at parse time rather than silently matching every process on the
 * host. */
struct Target {
	std::string name;

	/* Substring matches against /proc/<pid>/comm and the cmdline. */
	std::string comm;
	std::string cmdline;

	/* Container name or id prefix, matched against what is recoverable
	 * from /proc/<pid>/cgroup. Empty means any container, and also the
	 * host itself. */
	std::string container;

	uint16_t mysql_port = 3306;
	std::string statements; /* file listing cacheable statements */
	int ttl = 60;

	bool matchesNothing() const
	{
		return comm.empty() && cmdline.empty() && container.empty();
	}
};

struct Config {
	std::vector<Target> targets;

	/* Where the agent listens, and where the cache lives. */
	std::string control_path = "/tmp/qcache.sock";
	std::string valkey_host = "valkey";
	uint16_t valkey_port = 6379;

	/* Host path to libssl inside the target. Resolved per-process at
	 * analysis time; this is only the fallback. */
	std::string libssl_hint = "libssl.so.3";

	static bool load(const std::string &path, Config &out, std::string &err);
};

} // namespace qcache

#endif /* VALKEY_EBPF_QCACHE_CONFIG_H */
