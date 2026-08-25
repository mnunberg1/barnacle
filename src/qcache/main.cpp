// SPDX-License-Identifier: GPL-2.0
/*
 * main.cpp - qcache, the entry point.
 *
 * Runs on the host, finds the programs named in a config file wherever they
 * happen to be running -- including inside containers -- works out whether
 * each can actually be attached to, and reports or acts on the answer.
 *
 * The three components it drives:
 *
 *   kclient   kernel eBPF. sockops classifier plus the sk_msg redirect that
 *             delivers the agent's replies into a client's socket receive
 *             queue, which is what wakes a client parked in epoll_wait().
 *   agent     userspace daemon. Owns the agent_pipe pool, the cache, and the
 *             mini-protocol.
 *   uclient   bpftime probes injected into each target process, hooking the
 *             TLS library's read/write entry points on the plaintext side.
 *
 * Why discovery is a first-class step rather than a `--pid` flag: attaching
 * is only useful when several things line up, and each of them has silently
 * broken this project at some point. The library has to be OpenSSL, because
 * Go and Java do TLS in-process with nothing to hook. The right symbol family
 * has to be present, because the mysql CLI uses SSL_read/SSL_write while
 * CPython uses only the _ex variants. libssl is often dlopen'd late, so a
 * valid target can look empty until it first connects. And there has to be a
 * live database connection or there is nothing to cache. Saying which of
 * those failed is the difference between a useful tool and one that attaches
 * successfully and does nothing.
 *
 *   qcache list     what matches, and whether it is attachable
 *   qcache analyze  the same with detail on why
 *   qcache attach   attach uclient to everything attachable
 *   qcache run      attach, then run the agent in the foreground
 */
#include "config.h"
#include "discover.h"

#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace qcache;

namespace {

volatile sig_atomic_t g_exiting;

void on_signal(int)
{
	g_exiting = 1;
}

void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-c CONFIG] <command>\n"
		"\n"
		"commands:\n"
		"  list      processes matching the config, and their verdicts\n"
		"  analyze   as above, with the reasoning for each verdict\n"
		"  attach    attach uclient to every attachable process\n"
		"  run       attach, then run the agent in the foreground\n"
		"\n"
		"options:\n"
		"  -c PATH   config file (default config/qcache.conf)\n"
		"  -n        dry run: report what would happen, change nothing\n"
		"  -v        verbose\n"
		"\n"
		"Runs on the host. Container processes are visible through /proc\n"
		"like any others, so no container runtime is required.\n",
		prog);
}

void printHeader()
{
	printf("%-7s %-14s %-16s %-8s %-12s %-7s %s\n", "PID", "COMM", "WHERE", "TLS",
	       "SYMBOLS", "CONNS", "VERDICT");
	printf("%-7s %-14s %-16s %-8s %-12s %-7s %s\n", "-------", "--------------",
	       "----------------", "--------", "------------", "-------",
	       "----------");
}

/* Explain a verdict in terms of what to do about it. A bare enum name is not
 * actionable; these are the four things that actually go wrong. */
void explain(const Process &p)
{
	switch (p.verdict) {
	case Verdict::Attachable:
		printf("      ready: %s, %d connection(s) to port %u\n",
		       p.libssl_path.c_str(), p.db_connections,
		       p.target ? p.target->mysql_port : 0);
		break;
	case Verdict::NoTlsLibrary:
		printf("      no TLS library mapped yet. Usually means the process has\n"
		       "      not opened a connection -- libssl is normally dlopen'd on\n"
		       "      first use. Re-run once it has connected.\n");
		break;
	case Verdict::UnsupportedTls:
		printf("      uses %s (%s), which has no OpenSSL entry points to hook.\n"
		       "      Go and Java do TLS in-process and are out of scope.\n",
		       tlsKindName(p.tls), p.libssl_path.c_str());
		break;
	case Verdict::NoSslSymbols:
		printf("      %s is mapped but exports neither SSL_read/SSL_write nor\n"
		       "      the _ex variants -- likely stripped or statically linked.\n",
		       p.libssl_path.c_str());
		break;
	case Verdict::NoDatabaseConn:
		printf("      attachable, but no established connection to port %u.\n"
		       "      Nothing to cache until it talks to the database.\n",
		       p.target ? p.target->mysql_port : 0);
		break;
	case Verdict::AlreadyAttached:
		printf("      uclient is already attached.\n");
		break;
	}
}

/* Shell out to `bpftime attach <pid>`.
 *
 * A subprocess rather than a library call because bpftime's injection has to
 * happen from a separate process image -- it maps its agent into the target,
 * and doing that from inside our own address space is not the supported path.
 */
bool attachOne(const Process &p, bool dry_run, bool verbose)
{
	if (dry_run) {
		printf("      [dry-run] would attach uclient to pid %d\n", p.pid);
		return true;
	}

	pid_t child = fork();

	if (child < 0) {
		fprintf(stderr, "      fork failed: %s\n", strerror(errno));
		return false;
	}
	if (child == 0) {
		char pidbuf[32];

		snprintf(pidbuf, sizeof(pidbuf), "%d", p.pid);
		if (!verbose) {
			int devnull = open("/dev/null", O_WRONLY);

			if (devnull >= 0) {
				dup2(devnull, STDOUT_FILENO);
				dup2(devnull, STDERR_FILENO);
			}
		}
		execlp("bpftime", "bpftime", "attach", pidbuf, (char *)nullptr);
		_exit(127);
	}

	int status = 0;

	waitpid(child, &status, 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("      attached uclient to pid %d\n", p.pid);
		return true;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
		fprintf(stderr, "      bpftime not on PATH (try /root/.bpftime)\n");
	} else {
		fprintf(stderr, "      attach failed for pid %d\n", p.pid);
	}
	return false;
}

} // namespace

int main(int argc, char **argv)
{
	std::string cfg_path = "config/qcache.conf";
	bool dry_run = false, verbose = false;
	std::string cmd;

	for (int i = 1; i < argc; i++) {
		std::string a = argv[i];

		if (a == "-c" && i + 1 < argc) {
			cfg_path = argv[++i];
		} else if (a == "-n") {
			dry_run = true;
		} else if (a == "-v") {
			verbose = true;
		} else if (a == "-h" || a == "--help") {
			usage(argv[0]);
			return 0;
		} else if (a[0] != '-') {
			cmd = a;
		} else {
			usage(argv[0]);
			return 1;
		}
	}
	if (cmd.empty()) {
		usage(argv[0]);
		return 1;
	}

	Config cfg;
	std::string err;

	if (!Config::load(cfg_path, cfg, err)) {
		fprintf(stderr, "qcache: %s\n", err.c_str());
		return 1;
	}
	if (verbose) {
		fprintf(stderr, "qcache: %zu target(s) from %s\n", cfg.targets.size(),
			cfg_path.c_str());
	}

	std::vector<Process> found = discover(cfg, err);

	if (!err.empty()) {
		fprintf(stderr, "qcache: %s\n", err.c_str());
		return 1;
	}
	for (auto &p : found) {
		analyse(p);
	}

	if (found.empty()) {
		printf("No processes matched. Targets configured:\n");
		for (const auto &t : cfg.targets) {
			printf("  %-12s comm=%-10s cmdline=%-20s container=%s\n",
			       t.name.c_str(), t.comm.empty() ? "*" : t.comm.c_str(),
			       t.cmdline.empty() ? "*" : t.cmdline.c_str(),
			       t.container.empty() ? "*" : t.container.c_str());
		}
		return 0;
	}

	if (cmd == "list" || cmd == "analyze") {
		printHeader();
		for (const auto &p : found) {
			printf("%s\n", describe(p).c_str());
			if (cmd == "analyze") {
				explain(p);
			}
		}
		return 0;
	}

	if (cmd == "attach" || cmd == "run") {
		int ok = 0, skipped = 0;

		printHeader();
		for (const auto &p : found) {
			printf("%s\n", describe(p).c_str());
			if (p.verdict != Verdict::Attachable) {
				explain(p);
				skipped++;
				continue;
			}
			if (attachOne(p, dry_run, verbose)) {
				ok++;
			}
		}
		printf("\n%d attached, %d skipped\n", ok, skipped);

		if (cmd == "run") {
			if (ok == 0) {
				fprintf(stderr,
					"qcache: nothing attached; not starting the agent\n");
				return 1;
			}
			signal(SIGINT, on_signal);
			signal(SIGTERM, on_signal);
			printf("\nagent would run here (control %s, cache %s:%u)\n",
			       cfg.control_path.c_str(), cfg.valkey_host.c_str(),
			       (unsigned)cfg.valkey_port);
			while (!g_exiting) {
				sleep(1);
			}
		}
		return 0;
	}

	usage(argv[0]);
	return 1;
}
