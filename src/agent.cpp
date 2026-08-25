// SPDX-License-Identifier: GPL-2.0
/*
 * agent - load mysql_reroute.bpf.o, keep its reroute list in sync
 * with a plain text file, and stream correlated request/response JSONL.
 *
 * This is the "main logic" half of the reroute mechanism, living outside the
 * kernel on purpose: everything that can be a normal userspace decision
 * (which statements are reroutable, how to log them, how to react) lives
 * here. The BPF program only ever does what MUST happen synchronously in
 * the kernel: looking a statement up in the reroute list before it reaches
 * mysqld and mutating it in place.
 *
 * Every matched statement is reported here (kind="request"), regardless of
 * reroute-list membership -- `rerouted` on each event says whether *this*
 * occurrence was actually mutated. "Place the original query somewhere in
 * my own code" means this stream: the "sql" field is the full original
 * statement, captured before any mutation, ready to be translated (e.g. via
 * translator/sql2search.py) and executed against Valkey.
 *
 * sockmap-based, not tracepoint-based: see bpf/mysql_reroute.bpf.c's header
 * comment for why. Three BPF programs need explicit, non-skeleton-generic
 * attachment here as a result -- classify() (SEC("sockops")) attaches to a
 * cgroup, and handle_msg()/handle_skb() attach to the sock_hash map itself
 * -- so this file does that by hand instead of calling the usual
 * mysql_reroute_bpf__attach(skel) one-liner.
 */
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>

#include "mysql_reroute.h"
#include "mysql_reroute.skel.h"

namespace {

struct Env {
	pid_t pid = 0;
	const char *comm = nullptr;
	unsigned int min_query_len = 1;
	unsigned int port = 3306;
	std::string cgroup_path = "/sys/fs/cgroup";
	bool verbose = false;
	std::string reroute_file = "config/reroute.list";
} g_env;

volatile sig_atomic_t g_exiting = 0;
volatile sig_atomic_t g_reload_requested = 0;

/* Currently-loaded raw statement texts, kept so a reload can diff against
 * what is already in the BPF map instead of clearing and rebuilding it. */
std::set<std::string> g_loaded;

void on_signal(int sig)
{
	if (sig == SIGHUP) {
		g_reload_requested = 1;
	} else {
		g_exiting = 1;
	}
}

int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !g_env.verbose) {
		return 0;
	}
	return vfprintf(stderr, fmt, args);
}

void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"\n"
		"Load mysql_reroute.bpf.o, reroute statements listed in a file to a\n"
		"harmless no-op before mysqld sees them, and print correlated\n"
		"request/response JSONL on stdout for every matched statement.\n"
		"\n"
		"  -f, --reroute-file PATH  statement list (default: config/reroute.list)\n"
		"  -p, --pid PID            only trace this process id\n"
		"  -c, --comm NAME          only report events whose comm matches NAME\n"
		"  -m, --min-len N          ignore statements shorter than N bytes\n"
		"  -P, --port N             only classify connections to this remote port "
		"(default: 3306)\n"
		"  -g, --cgroup PATH        cgroup v2 path to attach the sockops classifier to "
		"(default: /sys/fs/cgroup)\n"
		"  -v, --verbose            verbose libbpf output on stderr\n"
		"  -h, --help               this text\n"
		"\n"
		"SIGHUP reloads the reroute file without restarting.\n",
		prog);
}

void parse_args(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		std::string a = argv[i];
		auto next = [&](const char *flag) -> const char * {
			if (i + 1 >= argc) {
				fprintf(stderr, "agent: %s needs an argument\n", flag);
				exit(1);
			}
			return argv[++i];
		};

		if (a == "-f" || a == "--reroute-file") {
			g_env.reroute_file = next(a.c_str());
		} else if (a == "-p" || a == "--pid") {
			g_env.pid = atoi(next(a.c_str()));
		} else if (a == "-c" || a == "--comm") {
			g_env.comm = next(a.c_str());
		} else if (a == "-m" || a == "--min-len") {
			g_env.min_query_len = strtoul(next(a.c_str()), nullptr, 10);
		} else if (a == "-P" || a == "--port") {
			g_env.port = strtoul(next(a.c_str()), nullptr, 10);
		} else if (a == "-g" || a == "--cgroup") {
			g_env.cgroup_path = next(a.c_str());
		} else if (a == "-v" || a == "--verbose") {
			g_env.verbose = true;
		} else if (a == "-h" || a == "--help") {
			usage(argv[0]);
			exit(0);
		} else {
			fprintf(stderr, "agent: unknown argument %s\n", a.c_str());
			usage(argv[0]);
			exit(1);
		}
	}
}

/* Must mirror the BPF side's clamp exactly: zero-filled key, at most
 * MAX_QUERY_LEN-1 bytes of real content. Anything captured longer than that
 * is marked truncated and never reaches the reroute-list lookup at all, so
 * a file entry longer than that could never match -- rejected up front
 * instead of silently never firing. */
bool build_key(const std::string &text, reroute_key &key)
{
	if (text.size() > MAX_QUERY_LEN - 1) {
		return false;
	}
	std::memset(&key, 0, sizeof(key));
	std::memcpy(key.query, text.data(), text.size());
	return true;
}

bool load_reroute_file(const std::string &path, std::vector<std::string> &out)
{
	std::ifstream in(path);
	if (!in) {
		fprintf(stderr, "agent: cannot open %s: %s\n", path.c_str(),
			strerror(errno));
		return false;
	}
	std::string line;
	while (std::getline(in, line)) {
		while (!line.empty() && (line.back() == '\r'))
			line.pop_back();
		if (line.empty() || line[0] == '#') {
			continue;
		}
		out.push_back(line);
	}
	return true;
}

/* Diff the file against what is currently in the map and apply only the
 * delta, so a reload does not create a window where the list is empty. */
void sync_reroute_list(int map_fd, bool first_load)
{
	std::vector<std::string> lines;
	if (!load_reroute_file(g_env.reroute_file, lines)) {
		if (first_load) {
			exit(1);
		}
		fprintf(stderr, "agent: keeping the previous reroute list\n");
		return;
	}

	std::set<std::string> next;
	int rejected = 0;
	for (const auto &text : lines) {
		if (text.size() > MAX_QUERY_LEN - 1) {
			fprintf(stderr,
				"agent: entry too long (%zu bytes > %d), skipped: %.60s...\n",
				text.size(), MAX_QUERY_LEN - 1, text.c_str());
			rejected++;
			continue;
		}
		next.insert(text);
	}

	int removed = 0, added = 0;
	reroute_key key;
	for (const auto &text : g_loaded) {
		if (next.count(text)) {
			continue;
		}
		build_key(text, key); /* already validated when it was loaded */
		bpf_map_delete_elem(map_fd, &key);
		removed++;
	}
	for (const auto &text : next) {
		if (g_loaded.count(text)) {
			continue;
		}
		build_key(text, key); /* always fits: next was already filtered above */
		__u64 zero = 0;
		bpf_map_update_elem(map_fd, &key, &zero, BPF_ANY);
		added++;
	}

	g_loaded.swap(next);

	std::string msg = "agent: reroute list " +
			   std::string(first_load ? "loaded" : "reloaded") + ": " +
			   std::to_string(g_loaded.size()) + " active (+" +
			   std::to_string(added) + " -" + std::to_string(removed) + ")";
	if (rejected) {
		msg += " [" + std::to_string(rejected) + " rejected]";
	}
	msg += " from " + g_env.reroute_file + "\n";
	fprintf(stderr, "%s", msg.c_str());
}

/* Collapse whitespace so a captured multi-line statement prints as one
 * readable line, same convention translator/bridge.py's JSONL already uses. */
size_t squash_ws(char *buf, size_t len)
{
	size_t w = 0;
	bool in_ws = false;

	for (size_t r = 0; r < len; r++) {
		if (std::isspace((unsigned char)buf[r])) {
			in_ws = true;
			continue;
		}
		if (in_ws && w) {
			buf[w++] = ' ';
		}
		in_ws = false;
		buf[w++] = buf[r];
	}
	return w;
}

void json_escape(std::string &out, const char *s, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		switch (c) {
		case '"': out += "\\\""; break;
		case '\\': out += "\\\\"; break;
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		default:
			if (c < 0x20 || c == 0x7f) {
				char buf8[8];
				snprintf(buf8, sizeof(buf8), "\\u%04x", c);
				out += buf8;
			} else {
				out += (char)c;
			}
		}
	}
}

/* Response bytes are the MySQL binary protocol, not text -- hex, not
 * json_escape, is the honest way to print them. */
void hex_encode(std::string &out, const char *data, size_t len)
{
	static const char *hex = "0123456789abcdef";
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)data[i];
		out += hex[(c >> 4) & 0xf];
		out += hex[c & 0xf];
	}
}

int handle_corr_event(void *, void *data, size_t data_sz)
{
	const auto *ce = static_cast<const corr_event *>(data);
	if (data_sz < sizeof(*ce)) {
		fprintf(stderr, "agent: short event (%zu bytes)\n", data_sz);
		return 0;
	}
	if (g_env.comm && strncmp(ce->comm, g_env.comm, TASK_COMM_LEN) != 0) {
		return 0;
	}

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	char hdr[320];
	snprintf(hdr, sizeof(hdr),
		 "{\"wall\":%lld.%06ld,\"ts_ns\":%llu,\"req_ts_ns\":%llu,\"pid\":%u,"
		 "\"tid\":%u,\"sport\":%u,\"dport\":%u,\"kind\":\"%s\",\"rerouted\":%s,"
		 "\"truncated\":%s,\"len\":%u,\"comm\":\"",
		 (long long)ts.tv_sec, ts.tv_nsec / 1000, (unsigned long long)ce->ts_ns,
		 (unsigned long long)ce->req_ts_ns, ce->pid, ce->tid, ce->sport, ce->dport,
		 ce->kind == CORR_REQUEST ? "request" : "response",
		 ce->rerouted ? "true" : "false", ce->truncated ? "true" : "false", ce->len);

	std::string out;
	out.reserve(sizeof(hdr) + MAX_QUERY_LEN * 2);
	out += hdr;
	json_escape(out, ce->comm, strnlen(ce->comm, TASK_COMM_LEN));
	out += "\",";

	size_t dlen = ce->data_len <= sizeof(ce->data) ? ce->data_len : sizeof(ce->data);
	if (ce->kind == CORR_REQUEST) {
		char qbuf[MAX_QUERY_LEN];
		std::memcpy(qbuf, ce->data, dlen);
		size_t squashed = squash_ws(qbuf, dlen);
		out += "\"sql\":\"";
		json_escape(out, qbuf, squashed);
		out += "\"}";
	} else {
		out += "\"response_hex\":\"";
		hex_encode(out, ce->data, dlen);
		out += "\"}";
	}

	std::fwrite(out.data(), 1, out.size(), stdout);
	std::fputc('\n', stdout);
	std::fflush(stdout);
	return 0;
}

} // namespace

int main(int argc, char **argv)
{
	parse_args(argc, argv);

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGHUP, on_signal);

	mysql_reroute_bpf *skel = mysql_reroute_bpf__open();
	if (!skel) {
		fprintf(stderr, "agent: failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->targ_pid = g_env.pid;
	skel->rodata->min_query_len = g_env.min_query_len;
	skel->rodata->targ_port = g_env.port;

	/* handle_msg/handle_skb attach to the sock_hash map itself, not to a
	 * tracepoint or a cgroup -- expected_attach_type has to be set before
	 * load so the verifier applies BPF_SK_MSG_VERDICT/BPF_SK_SKB_VERDICT
	 * semantics, since the SEC("sk_msg")/SEC("sk_skb") tags alone only
	 * pin down the program *type*, not which of that type's several
	 * attach flavors this is. */
	bpf_program__set_expected_attach_type(skel->progs.handle_msg, BPF_SK_MSG_VERDICT);
	bpf_program__set_expected_attach_type(skel->progs.handle_skb, BPF_SK_SKB_VERDICT);

	int err = mysql_reroute_bpf__load(skel);
	if (err) {
		fprintf(stderr, "agent: failed to load BPF object: %d (%s)\n", err,
			strerror(-err));
		mysql_reroute_bpf__destroy(skel);
		return 1;
	}

	sync_reroute_list(bpf_map__fd(skel->maps.reroute_list), true);

	/* None of classify()/handle_msg()/handle_skb() support the generic
	 * skeleton auto-attach (there is no single tracepoint-style implicit
	 * attach point for a cgroup-attached or map-attached program), so
	 * each is attached by hand here instead of calling
	 * mysql_reroute_bpf__attach(skel). */
	int cgroup_fd = open(g_env.cgroup_path.c_str(), O_RDONLY);
	if (cgroup_fd < 0) {
		fprintf(stderr, "agent: cannot open cgroup path %s: %s\n",
			g_env.cgroup_path.c_str(), strerror(errno));
		mysql_reroute_bpf__destroy(skel);
		return 1;
	}

	struct bpf_link *cgroup_link = bpf_program__attach_cgroup(skel->progs.classify, cgroup_fd);
	if (!cgroup_link) {
		fprintf(stderr, "agent: failed to attach sockops classifier to cgroup %s: %s\n",
			g_env.cgroup_path.c_str(), strerror(errno));
		close(cgroup_fd);
		mysql_reroute_bpf__destroy(skel);
		return 1;
	}

	int sockhash_fd = bpf_map__fd(skel->maps.sock_hash);
	err = bpf_prog_attach(bpf_program__fd(skel->progs.handle_msg), sockhash_fd,
			       BPF_SK_MSG_VERDICT, 0);
	if (err) {
		fprintf(stderr, "agent: failed to attach sk_msg program: %d (%s)\n", err,
			strerror(-err));
		bpf_link__destroy(cgroup_link);
		close(cgroup_fd);
		mysql_reroute_bpf__destroy(skel);
		return 1;
	}
	err = bpf_prog_attach(bpf_program__fd(skel->progs.handle_skb), sockhash_fd,
			       BPF_SK_SKB_VERDICT, 0);
	if (err) {
		fprintf(stderr, "agent: failed to attach sk_skb program: %d (%s)\n", err,
			strerror(-err));
		bpf_link__destroy(cgroup_link);
		close(cgroup_fd);
		mysql_reroute_bpf__destroy(skel);
		return 1;
	}

	ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.corr_events),
					    handle_corr_event, nullptr, nullptr);
	if (!rb) {
		fprintf(stderr, "agent: failed to create ring buffer\n");
		bpf_link__destroy(cgroup_link);
		close(cgroup_fd);
		mysql_reroute_bpf__destroy(skel);
		return 1;
	}

	fprintf(stderr,
		"agent: attached, streaming JSONL for matched statements on stdout "
		"(SIGHUP to reload %s, Ctrl-C to stop)\n",
		g_env.reroute_file.c_str());

	while (!g_exiting) {
		if (g_reload_requested) {
			g_reload_requested = 0;
			sync_reroute_list(bpf_map__fd(skel->maps.reroute_list), false);
		}
		err = ring_buffer__poll(rb, 200 /* ms */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "agent: poll failed: %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
	bpf_link__destroy(cgroup_link);
	close(cgroup_fd);
	mysql_reroute_bpf__destroy(skel);
	return 0;
}
