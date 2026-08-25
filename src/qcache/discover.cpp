// SPDX-License-Identifier: GPL-2.0
#include "discover.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <map>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace qcache {
namespace {

std::string readFile(const std::string &path, size_t limit = 65536)
{
	std::ifstream in(path, std::ios::binary);
	std::string out;

	if (!in) {
		return out;
	}
	out.resize(limit);
	in.read(out.data(), (std::streamsize)limit);
	out.resize((size_t)in.gcount());
	return out;
}

std::string trim(const std::string &s)
{
	size_t a = s.find_first_not_of(" \t\r\n");
	size_t b = s.find_last_not_of(" \t\r\n");

	return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

/* cmdline is NUL-separated; join it so substring matching behaves the way a
 * person writing the config would expect. */
std::string readCmdline(int pid)
{
	std::string raw = readFile("/proc/" + std::to_string(pid) + "/cmdline");

	for (auto &c : raw) {
		if (c == '\0') {
			c = ' ';
		}
	}
	return trim(raw);
}

/* Recover container identity from the cgroup path.
 *
 * There is no portable API for this, and deliberately no dependency on a
 * container runtime -- the shapes below cover Docker, containerd and podman
 * under both cgroup v1 and v2:
 *
 *   0::/docker/<64-hex>
 *   0::/system.slice/docker-<64-hex>.scope
 *   0::/kubepods/.../<64-hex>
 *   0::/                              (host)
 */
void readContainer(int pid, std::string &id, std::string &kind)
{
	std::string cg = readFile("/proc/" + std::to_string(pid) + "/cgroup");
	std::istringstream iss(cg);
	std::string line;

	id.clear();
	kind = "host";

	while (std::getline(iss, line)) {
		size_t last = line.find_last_of('/');

		if (last == std::string::npos) {
			continue;
		}
		std::string leaf = line.substr(last + 1);

		if (leaf.empty()) {
			continue;
		}
		if (leaf.rfind("docker-", 0) == 0) {
			leaf = leaf.substr(7);
			kind = "docker";
		} else if (leaf.rfind("crio-", 0) == 0) {
			leaf = leaf.substr(5);
			kind = "cri-o";
		} else if (leaf.rfind("libpod-", 0) == 0) {
			leaf = leaf.substr(7);
			kind = "podman";
		}
		size_t dot = leaf.find(".scope");

		if (dot != std::string::npos) {
			leaf = leaf.substr(0, dot);
		}

		/* A container id is a long hex string; anything else is a
		 * systemd slice or the host root. */
		bool hex = leaf.size() >= 12 &&
			   leaf.find_first_not_of("0123456789abcdefABCDEF") ==
				   std::string::npos;

		if (hex) {
			id = leaf.substr(0, 12); /* short id, as docker shows it */
			if (kind == "host") {
				kind = "container";
			}
			return;
		}
	}
}

/* Are we ourselves inside a cgroup namespace?
 *
 * If so, our own container's processes report a cgroup of just "/" -- the
 * namespace root -- and there is no container id to recover. Processes in
 * OTHER containers are still attributable, because their paths surface as
 * "/../<id>". This is a hard limitation of looking from the inside, not a
 * parsing bug, and qcache is meant to run on the host precisely to avoid it.
 */
bool inCgroupNamespace()
{
	char self[64] = {}, init[64] = {};

	if (readlink("/proc/self/ns/cgroup", self, sizeof(self) - 1) <= 0) {
		return false;
	}
	if (readlink("/proc/1/ns/cgroup", init, sizeof(init) - 1) <= 0) {
		return false;
	}
	return std::strcmp(self, init) != 0;
}

bool containsCI(const std::string &hay, const std::string &needle)
{
	if (needle.empty()) {
		return true;
	}
	auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(),
			       [](char a, char b) {
				       return std::tolower((unsigned char)a) ==
					      std::tolower((unsigned char)b);
			       });

	return it != hay.end();
}

/* Map a container id to its human name, so config can say `vebpf-bpf` rather
 * than a hex string. Read from the runtime's own state files -- still no
 * dependency on the runtime being installed or running. */
const std::map<std::string, std::string> &containerNames()
{
	static std::map<std::string, std::string> cache;
	static bool loaded;

	if (loaded) {
		return cache;
	}
	loaded = true;

	/* Docker keeps one directory per container; the config file inside
	 * carries the name. Best-effort: unreadable means we fall back to
	 * matching on the id. */
	const char *roots[] = { "/var/lib/docker/containers",
				"/host/var/lib/docker/containers" };

	for (const char *root : roots) {
		DIR *d = opendir(root);

		if (!d) {
			continue;
		}
		struct dirent *e;

		while ((e = readdir(d)) != nullptr) {
			if (e->d_name[0] == '.') {
				continue;
			}
			std::string id(e->d_name);
			std::string cfg =
				std::string(root) + "/" + id + "/config.v2.json";
			std::string body = readFile(cfg, 8192);
			size_t k = body.find("\"Name\":\"");

			if (k == std::string::npos) {
				continue;
			}
			size_t start = k + 8;
			size_t end = body.find('"', start);

			if (end == std::string::npos) {
				continue;
			}
			std::string name = body.substr(start, end - start);

			if (!name.empty() && name[0] == '/') {
				name = name.substr(1);
			}
			cache[id.substr(0, 12)] = name;
		}
		closedir(d);
		if (!cache.empty()) {
			break;
		}
	}
	return cache;
}

/* Which TLS library, if any, is mapped into the process right now.
 *
 * "Right now" matters: libssl is frequently dlopen'd on first use, so a
 * perfectly valid target reports None until it has opened a connection. That
 * is reported as its own verdict rather than treated as unsupported. */
TlsKind detectTls(int pid, std::string &path)
{
	std::string maps = readFile("/proc/" + std::to_string(pid) + "/maps", 1 << 20);
	std::istringstream iss(maps);
	std::string line;
	TlsKind found = TlsKind::None;

	while (std::getline(iss, line)) {
		size_t sp = line.find_last_of(' ');

		if (sp == std::string::npos) {
			continue;
		}
		std::string file = trim(line.substr(sp + 1));

		if (file.empty() || file[0] != '/') {
			continue;
		}
		if (file.find("libssl.so") != std::string::npos) {
			path = file;
			return TlsKind::OpenSSL; /* supported: stop here */
		}
		if (file.find("libgnutls.so") != std::string::npos) {
			path = file;
			found = TlsKind::GnuTLS;
		} else if (file.find("libnss3.so") != std::string::npos ||
			   file.find("libssl3.so") != std::string::npos) {
			path = file;
			found = TlsKind::NSS;
		}
	}
	return found;
}

/* Which SSL entry-point families the mapped library exports.
 *
 * Both must be checked. The mysql CLI imports SSL_read/SSL_write; CPython's
 * _ssl imports only SSL_read_ex/SSL_write_ex. A probe covering one family
 * attaches cleanly to a process using the other and then never fires -- which
 * looks identical to "the cache does not work".
 *
 * The library is read through /proc/<pid>/root so a path that only exists
 * inside the container still resolves from the host.
 */
void detectSymbols(Process &p)
{
	if (p.libssl_path.empty()) {
		return;
	}
	std::string host_path =
		"/proc/" + std::to_string(p.pid) + "/root" + p.libssl_path;
	std::string blob = readFile(host_path, 8u << 20);

	if (blob.empty()) {
		return;
	}
	/* A plain scan of the file's bytes for the symbol names. Crude next to
	 * parsing .dynsym, but it needs no ELF library, works for both ELF
	 * classes, and only ever answers a yes/no question. */
	auto has = [&](const char *sym) {
		return blob.find(sym) != std::string::npos;
	};

	p.has_classic_syms = has("SSL_read") && has("SSL_write");
	p.has_ex_syms = has("SSL_read_ex") && has("SSL_write_ex");
}

/* Count established TCP connections from this process to the target port.
 *
 * Sockets are matched by inode: /proc/<pid>/fd gives the process's socket
 * inodes, /proc/<pid>/net/tcp lists connections in its network namespace.
 * Reading the per-process net/tcp rather than the host's is what makes this
 * correct for containers, which usually have their own namespace.
 */
int countDbConnections(int pid, uint16_t port)
{
	std::string fddir = "/proc/" + std::to_string(pid) + "/fd";
	DIR *d = opendir(fddir.c_str());
	std::vector<unsigned long> inodes;

	if (!d) {
		return 0;
	}
	struct dirent *e;

	while ((e = readdir(d)) != nullptr) {
		char buf[256];
		std::string link = fddir + "/" + e->d_name;
		ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);

		if (n <= 0) {
			continue;
		}
		buf[n] = '\0';
		unsigned long ino = 0;

		if (sscanf(buf, "socket:[%lu]", &ino) == 1) {
			inodes.push_back(ino);
		}
	}
	closedir(d);
	if (inodes.empty()) {
		return 0;
	}

	int count = 0;

	for (const char *which : { "/net/tcp", "/net/tcp6" }) {
		std::string tcp =
			readFile("/proc/" + std::to_string(pid) + which, 1 << 20);
		std::istringstream iss(tcp);
		std::string line;

		std::getline(iss, line); /* header */
		while (std::getline(iss, line)) {
			char local[128] = {}, rem[128] = {};
			unsigned st = 0;
			unsigned long ino = 0;

			/* sl local rem st ... inode */
			if (sscanf(line.c_str(),
				    "%*d: %127s %127s %X %*x:%*x %*x:%*x %*x %*d %*d %lu",
				    local, rem, &st, &ino) != 4) {
				continue;
			}
			if (st != 0x01) { /* TCP_ESTABLISHED */
				continue;
			}
			const char *colon = strrchr(rem, ':');

			if (!colon) {
				continue;
			}
			unsigned rport = (unsigned)strtoul(colon + 1, nullptr, 16);

			if (rport != port) {
				continue;
			}
			if (std::find(inodes.begin(), inodes.end(), ino) !=
			    inodes.end()) {
				count++;
			}
		}
	}
	return count;
}

} // namespace

const char *tlsKindName(TlsKind k)
{
	switch (k) {
	case TlsKind::None:
		return "none";
	case TlsKind::OpenSSL:
		return "openssl";
	case TlsKind::GnuTLS:
		return "gnutls";
	case TlsKind::NSS:
		return "nss";
	default:
		return "unknown";
	}
}

const char *verdictName(Verdict v)
{
	switch (v) {
	case Verdict::Attachable:
		return "ATTACHABLE";
	case Verdict::NoTlsLibrary:
		return "NO-TLS-YET";
	case Verdict::UnsupportedTls:
		return "UNSUPPORTED-TLS";
	case Verdict::NoSslSymbols:
		return "NO-SYMBOLS";
	case Verdict::NoDatabaseConn:
		return "NO-DB-CONN";
	case Verdict::AlreadyAttached:
		return "ATTACHED";
	default:
		return "?";
	}
}

void analyse(Process &p)
{
	p.tls = detectTls(p.pid, p.libssl_path);

	if (p.tls == TlsKind::OpenSSL) {
		detectSymbols(p);
	}
	if (p.target) {
		p.db_connections = countDbConnections(p.pid, p.target->mysql_port);
	}

	switch (p.tls) {
	case TlsKind::None:
		/* Not a failure: libssl is usually dlopen'd on first use, so
		 * this often just means "has not connected yet". */
		p.verdict = Verdict::NoTlsLibrary;
		return;
	case TlsKind::GnuTLS:
	case TlsKind::NSS:
	case TlsKind::Unknown:
		p.verdict = Verdict::UnsupportedTls;
		return;
	case TlsKind::OpenSSL:
		break;
	}

	if (!p.has_classic_syms && !p.has_ex_syms) {
		p.verdict = Verdict::NoSslSymbols;
		return;
	}
	if (p.db_connections == 0) {
		p.verdict = Verdict::NoDatabaseConn;
		return;
	}
	p.verdict = Verdict::Attachable;
}

std::vector<Process> discover(const Config &cfg, std::string &err)
{
	std::vector<Process> out;
	DIR *proc = opendir("/proc");

	if (!proc) {
		err = "cannot read /proc -- run on the host, with privileges";
		return out;
	}

	const auto &names = containerNames();
	const bool namespaced = inCgroupNamespace();
	struct dirent *e;

	while ((e = readdir(proc)) != nullptr) {
		if (e->d_name[0] < '0' || e->d_name[0] > '9') {
			continue;
		}
		int pid = atoi(e->d_name);

		if (pid <= 1 || pid == getpid()) {
			continue;
		}

		Process p;

		p.pid = pid;
		p.comm = trim(readFile("/proc/" + std::to_string(pid) + "/comm", 256));
		if (p.comm.empty()) {
			continue; /* exited between readdir and read */
		}
		p.cmdline = readCmdline(pid);
		readContainer(pid, p.container, p.container_kind);

		std::string cname;
		auto it = names.find(p.container);

		if (it != names.end()) {
			cname = it->second;
		}

		for (const auto &t : cfg.targets) {
			if (!containsCI(p.comm, t.comm)) {
				continue;
			}
			if (!containsCI(p.cmdline, t.cmdline)) {
				continue;
			}
			if (!t.container.empty()) {
				bool attributable = !p.container.empty();

				if (attributable) {
					/* Match the human name or the id prefix,
					 * whichever the config used. */
					if (!containsCI(cname, t.container) &&
					    !containsCI(p.container, t.container)) {
						continue;
					}
				} else if (!namespaced) {
					/* Genuinely on the host and not in any
					 * container: the filter excludes it. */
					continue;
				}
				/* Otherwise attribution is unavailable rather
				 * than negative -- we are looking from inside a
				 * cgroup namespace. Match, and flag it, rather
				 * than silently dropping a real target. */
				if (!attributable) {
					p.container_unattributable = true;
				}
			}
			p.target = &t;
			break;
		}
		if (!p.target) {
			continue;
		}
		if (!cname.empty()) {
			p.container = cname;
		}
		out.push_back(std::move(p));
	}
	closedir(proc);
	return out;
}

std::string describe(const Process &p)
{
	char buf[512];
	std::string where = p.container.empty() ? "host" : p.container;
	std::string syms;

	if (p.has_classic_syms && p.has_ex_syms) {
		syms = "classic+ex";
	} else if (p.has_ex_syms) {
		syms = "ex-only";
	} else if (p.has_classic_syms) {
		syms = "classic-only";
	} else {
		syms = "-";
	}

	snprintf(buf, sizeof(buf), "%-7d %-14.14s %-16.16s %-8s %-12s %2d conn  %s",
		 p.pid, p.comm.c_str(), where.c_str(), tlsKindName(p.tls), syms.c_str(),
		 p.db_connections, verdictName(p.verdict));
	return buf;
}

} // namespace qcache
