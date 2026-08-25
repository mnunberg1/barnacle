// SPDX-License-Identifier: GPL-2.0
/*
 * main.cpp - the DAEMON.
 *
 * Owns the agent_pipe pool, the KCLIENT BPF programs, and the cache. Clients
 * never talk to Valkey themselves; they ask the daemon, and the answer comes
 * back through a redirected socket.
 *
 * Flow for one intercepted statement:
 *
 *   1. UCLIENT sends {client sock_key, statement} on the control socket.
 *      This is the ch_assign notification from the design. It is a unix
 *      socket rather than a BPF ringbuffer because a ringbuf can only be
 *      written from a BPF program, and UCLIENT is ordinary userspace; the
 *      message is the same either way, and this becomes a real ringbuf if
 *      UCLIENT moves to bpftime.
 *
 *   2. The daemon takes a pipe off the free list and pairs it to that client,
 *      which is what makes KCLIENT redirect this pipe's writes into that
 *      client's receive queue.
 *
 *   3. It resolves the statement and writes the four-byte mini-protocol reply
 *      into the pipe:
 *
 *        AGENT_OK             cache hit; length + payload follow
 *        AGENT_WRITE_THROUGH  miss; the client sends the query itself and
 *                             hands the response back to be stored
 *        AGENT_CACHE_ERROR    cache unreachable; pass through untouched
 *
 *   4. The pipe is released as soon as the write completes. The redirect
 *      happens at sendmsg time, so by then the bytes are already sitting in
 *      the client's receive queue -- there is nothing left to wait for, and
 *      holding the pairing longer would risk a later write landing in a
 *      client that has moved on.
 */
#include "../cache/valkey.h"
#include "pipes.h"

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "kclient.skel.h"

using namespace qcd;

namespace {

volatile sig_atomic_t g_exiting;

void on_signal(int)
{
	g_exiting = 1;
}

struct Options {
	std::string control_path = "/tmp/qcache.sock";
	std::string valkey_host = "valkey";
	uint16_t valkey_port = 6379;
	uint16_t mysql_port = 3306;
	size_t pipes = 32;
	int ttl = 60;
	bool verbose = false;
};

/* Request from UCLIENT. Fixed header then the statement text. */
struct __attribute__((packed)) ControlRequest {
	sock_key client;
	uint32_t query_len;
};

/* Reply on the control socket. The actual response payload does NOT come
 * back this way -- it goes through the pipe, so that it lands in the client's
 * socket and wakes an event loop. This only tells UCLIENT what to expect. */
struct __attribute__((packed)) ControlReply {
	uint8_t status;   /* enum agent_status */
	uint8_t _pad[3];
	uint32_t length;  /* bytes delivered via the pipe, AGENT_OK only */
};

bool readExactly(int fd, void *buf, size_t n)
{
	uint8_t *p = (uint8_t *)buf;
	size_t got = 0;

	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);

		if (r == 0) {
			return false;
		}
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		got += (size_t)r;
	}
	return true;
}

bool writeExactly(int fd, const void *buf, size_t n)
{
	const uint8_t *p = (const uint8_t *)buf;
	size_t sent = 0;

	while (sent < n) {
		ssize_t w = write(fd, p + sent, n - sent);

		if (w <= 0) {
			if (w < 0 && errno == EINTR) {
				continue;
			}
			return false;
		}
		sent += (size_t)w;
	}
	return true;
}

std::string cacheKey(const std::string &sql)
{
	return "qc:" + sql;
}

class Daemon {
public:
	explicit Daemon(const Options &o) : opt_(o)
	{
	}

	bool start();
	void run();
	void stop();

private:
	void serveClient(int cfd);
	void handleRequest(int cfd, const sock_key &client, const std::string &sql);

	Options opt_;
	struct kclient_bpf *skel_ = nullptr;
	PipePool pool_;
	cache::Valkey valkey_;
	int control_fd_ = -1;
	bool sk_msg_attached_ = false;
};

bool Daemon::start()
{
	struct sockaddr_un addr {};

	skel_ = kclient_bpf__open();
	if (!skel_) {
		fprintf(stderr, "daemon: cannot open BPF skeleton\n");
		return false;
	}
	if (kclient_bpf__load(skel_)) {
		fprintf(stderr, "daemon: BPF load failed: %s (need root?)\n",
			strerror(errno));
		return false;
	}

	{
		__u32 k, v;

		k = KCLIENT_CFG_ENABLED;
		v = 1;
		bpf_map_update_elem(bpf_map__fd(skel_->maps.cfg), &k, &v, BPF_ANY);
		k = KCLIENT_CFG_PORT;
		v = opt_.mysql_port;
		bpf_map_update_elem(bpf_map__fd(skel_->maps.cfg), &k, &v, BPF_ANY);
	}

	/* sk_msg is what performs the redirect; without it a pipe write just
	 * goes to its own peer and no client is ever woken. */
	if (bpf_prog_attach(bpf_program__fd(skel_->progs.redirect),
			     bpf_map__fd(skel_->maps.sock_map), BPF_SK_MSG_VERDICT, 0)) {
		fprintf(stderr, "daemon: sk_msg attach failed: %s\n", strerror(errno));
		return false;
	}
	sk_msg_attached_ = true;

	if (!pool_.init(bpf_map__fd(skel_->maps.sock_map),
			 bpf_map__fd(skel_->maps.pipe_pairs), opt_.pipes)) {
		fprintf(stderr, "daemon: pipe pool init failed\n");
		return false;
	}

	valkey_.connect(opt_.valkey_host, opt_.valkey_port);
	if (!valkey_.healthy()) {
		fprintf(stderr, "daemon: warning -- Valkey %s:%u unreachable; every "
				"lookup will report CACHE_ERROR\n",
			opt_.valkey_host.c_str(), (unsigned)opt_.valkey_port);
	}

	unlink(opt_.control_path.c_str());
	control_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
	if (control_fd_ < 0) {
		return false;
	}
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", opt_.control_path.c_str());
	if (bind(control_fd_, (struct sockaddr *)&addr, sizeof(addr)) ||
	    listen(control_fd_, 64)) {
		fprintf(stderr, "daemon: cannot bind %s: %s\n", opt_.control_path.c_str(),
			strerror(errno));
		return false;
	}
	/* Clients run as whatever user the application runs as. */
	chmod(opt_.control_path.c_str(), 0666);

	fprintf(stderr,
		"daemon: ready -- %zu pipes, control %s, cache %s:%u, mysql port %u\n",
		pool_.size(), opt_.control_path.c_str(), opt_.valkey_host.c_str(),
		(unsigned)opt_.valkey_port, (unsigned)opt_.mysql_port);
	return true;
}

void Daemon::handleRequest(int cfd, const sock_key &client, const std::string &sql)
{
	ControlReply reply {};
	std::vector<uint8_t> payload;
	bool have = false;

	if (valkey_.healthy() || valkey_.connect(opt_.valkey_host, opt_.valkey_port)) {
		have = valkey_.get(cacheKey(sql), payload);
	}

	AgentPipe *pipe = pool_.acquire(client);

	if (!pipe) {
		/* Pool exhausted. Report an error rather than stalling: the
		 * client falls back to querying normally, which is slow but
		 * correct. */
		reply.status = AGENT_CACHE_ERROR;
		reply.length = 0;
		writeExactly(cfd, &reply, sizeof(reply));
		if (opt_.verbose) {
			fprintf(stderr, "daemon: pool exhausted for: %s\n", sql.c_str());
		}
		return;
	}

	agent_reply hdr {};

	if (have && !payload.empty()) {
		hdr.status = AGENT_OK;
		hdr.length = (uint32_t)payload.size();
	} else if (!valkey_.healthy()) {
		hdr.status = AGENT_CACHE_ERROR;
	} else {
		hdr.status = AGENT_WRITE_THROUGH;
	}

	/* Into the pipe, not the control socket. This is the whole point: the
	 * redirect puts these bytes in the client's receive queue, so a client
	 * parked in epoll_wait() becomes readable and wakes. */
	bool ok = writeExactly(pipe->local_fd, &hdr, sizeof(hdr));

	if (ok && hdr.status == AGENT_OK) {
		ok = writeExactly(pipe->local_fd, payload.data(), payload.size());
	}

	/* Safe to release immediately: the redirect happened during the write,
	 * so the bytes are already queued on the client side. */
	pool_.release(pipe);

	reply.status = ok ? hdr.status : (uint8_t)AGENT_CACHE_ERROR;
	reply.length = ok ? hdr.length : 0;
	writeExactly(cfd, &reply, sizeof(reply));

	if (opt_.verbose) {
		const char *what = reply.status == AGENT_OK	     ? "HIT"
				   : reply.status == AGENT_WRITE_THROUGH ? "MISS"
									 : "ERROR";

		fprintf(stderr, "daemon: %-5s pipe=%u %s\n", what, pipe->key,
			sql.c_str());
	}
}

void Daemon::serveClient(int cfd)
{
	for (;;) {
		ControlRequest req {};

		if (!readExactly(cfd, &req, sizeof(req))) {
			break;
		}
		if (req.query_len == 0 || req.query_len > (1u << 20)) {
			break;
		}
		std::string sql(req.query_len, '\0');

		if (!readExactly(cfd, sql.data(), req.query_len)) {
			break;
		}

		/* A store, not a lookup: the client fetched the response itself
		 * after a WRITE_THROUGH and is handing it back. Signalled by a
		 * zeroed client key. */
		sock_key zero {};

		if (memcmp(&req.client, &zero, sizeof(zero)) == 0) {
			uint32_t blob_len = 0;

			if (!readExactly(cfd, &blob_len, sizeof(blob_len))) {
				break;
			}
			std::vector<uint8_t> blob(blob_len);

			if (blob_len && !readExactly(cfd, blob.data(), blob_len)) {
				break;
			}
			if (blob_len) {
				valkey_.setex(cacheKey(sql), blob, opt_.ttl);
				if (opt_.verbose) {
					fprintf(stderr,
						"daemon: STORE %zu bytes ttl=%ds %s\n",
						blob.size(), opt_.ttl, sql.c_str());
				}
			}
			ControlReply ack {};

			ack.status = AGENT_OK;
			writeExactly(cfd, &ack, sizeof(ack));
			continue;
		}

		handleRequest(cfd, req.client, sql);
	}
	close(cfd);
}

void Daemon::run()
{
	while (!g_exiting) {
		int cfd = accept(control_fd_, nullptr, nullptr);

		if (cfd < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		serveClient(cfd);
	}
}

void Daemon::stop()
{
	pool_.shutdown();
	if (control_fd_ >= 0) {
		close(control_fd_);
		unlink(opt_.control_path.c_str());
	}
	if (sk_msg_attached_ && skel_) {
		bpf_prog_detach2(bpf_program__fd(skel_->progs.redirect),
				  bpf_map__fd(skel_->maps.sock_map), BPF_SK_MSG_VERDICT);
	}
	if (skel_) {
		kclient_bpf__destroy(skel_);
	}
}

void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"  -s PATH   control socket (default /tmp/qcache.sock)\n"
		"  -H HOST   valkey host (default valkey)\n"
		"  -P PORT   valkey port (default 6379)\n"
		"  -m PORT   mysql port to classify (default 3306)\n"
		"  -n N      agent_pipe pool size (default 32)\n"
		"  -t SECS   cache TTL (default 60)\n"
		"  -v        verbose\n",
		prog);
}

} // namespace

int main(int argc, char **argv)
{
	Options opt;

	for (int i = 1; i < argc; i++) {
		std::string a = argv[i];
		auto next = [&]() -> const char * {
			if (i + 1 >= argc) {
				usage(argv[0]);
				exit(1);
			}
			return argv[++i];
		};

		if (a == "-s") {
			opt.control_path = next();
		} else if (a == "-H") {
			opt.valkey_host = next();
		} else if (a == "-P") {
			opt.valkey_port = (uint16_t)atoi(next());
		} else if (a == "-m") {
			opt.mysql_port = (uint16_t)atoi(next());
		} else if (a == "-n") {
			opt.pipes = (size_t)atoi(next());
		} else if (a == "-t") {
			opt.ttl = atoi(next());
		} else if (a == "-v") {
			opt.verbose = true;
		} else {
			usage(argv[0]);
			return 1;
		}
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	Daemon d(opt);

	if (!d.start()) {
		d.stop();
		return 1;
	}
	d.run();
	d.stop();
	fprintf(stderr, "daemon: exiting\n");
	return 0;
}
