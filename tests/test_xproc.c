// SPDX-License-Identifier: GPL-2.0
/*
 * test_xproc.c - splice a client socket in ANOTHER process to a daemon dpipe.
 *
 * Everything downstream of the redirect assumes this works, and nothing had
 * ever checked. tests/test_pipes.cpp registers its sockets from its own
 * process, which sidesteps the only hard part: in the real topology the
 * client socket belongs to the application, not the daemon.
 *
 * --- who registers what, and why no kernel program is needed ---------------
 *
 * A SOCKMAP value is a file descriptor, resolved in the CALLING process's
 * table. That cuts both ways: the daemon cannot register the application's
 * socket, but the application can, because it owns the fd. So each side
 * registers its own:
 *
 *   child   inserts its DB socket into cpipe_map[CPIPE_KEY] and sets
 *           its own sk_storage to point at DPIPE_KEY
 *   parent  inserts its dpipe into dpipe_map[DPIPE_KEY] and sets that
 *           socket's sk_storage to point at CPIPE_KEY
 *
 * Neither needs a sockops program, a cgroup attach, or a 5-tuple. The maps
 * are reached through bpffs pins, which is how UCLIENT's loader will reach
 * them in production too.
 *
 * Both directions are exercised, because architecture.txt requires it: the
 * hijacked connection carries daemon->client replies AND client->daemon
 * control traffic.
 *
 * Modes:
 *   (default)      two processes; the real question
 *   --in-proc      one process, as a control. If this passes and the default
 *                  fails, the fault is in crossing the process boundary
 *                  rather than in the redirect itself.
 *   --socketpair   build the dpipe from socketpair(2) rather than loopback
 *                  TCP. architecture.txt asks for socketpair; sk_msg is
 *                  invoked from the TCP sendmsg path and AF_UNIX never
 *                  replaces sendmsg, so this is expected to fail. Included so
 *                  the answer is measured rather than argued.
 *
 * Run inside the bpf container as root:
 *   ./build/test_xproc [--in-proc] [--socketpair]
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common/defs.h"
#include "kclient.skel.h"

/* libbpf pins these itself on load, because the maps are declared
 * LIBBPF_PIN_BY_NAME and we hand it QC_PIN_DIR as the pin root. The child
 * opens them by path, exactly as UCLIENT's loader will. */
#define PIN_CPIPES QC_PIN_DIR "/cpipe_map"
#define PIN_INFO QC_PIN_DIR "/pipe_sk_info_map"

/* Fixed indices. In production these come from dpipes_meta.serial and the
 * freelist; the test needs only that both sides agree. */
#define DPIPE_KEY 1
#define CPIPE_KEY 1

#define WAIT_MS 3000
#define BODY "REDIRECT-PROVES-IT"
#define REVERSE "CLIENT-TO-DAEMON"

struct child_report {
	int n;
	char buf[256];
};

/* Splice a socket we own: put it in its map, then record which index in the
 * opposite map it is paired with. Both calls work on a plain fd because we
 * own it -- which is the entire reason no kernel program is involved. */
static int splice(int sockmap_fd, __u32 key, int info_fd, __u32 peer_key, int fd)
{
	struct pipe_sk_info info = { .peer_key = peer_key, .paired = 1 };

	if (bpf_map_update_elem(sockmap_fd, &key, &fd, BPF_ANY)) {
		fprintf(stderr, "sockmap insert failed: %s\n", strerror(errno));
		return -1;
	}
	if (bpf_map_update_elem(info_fd, &fd, &info, BPF_ANY)) {
		fprintf(stderr, "sk_storage set failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int read_all(int fd, void *buf, size_t n, int timeout_ms)
{
	unsigned char *p = buf;
	size_t got = 0;

	while (got < n) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };

		if (poll(&pfd, 1, timeout_ms) <= 0) {
			return -1;
		}

		ssize_t k = read(fd, p + got, n - got);

		if (k <= 0) {
			return -1;
		}
		got += (size_t)k;
	}
	return 0;
}

static int write_all(int fd, const void *buf, size_t n)
{
	const unsigned char *p = buf;
	size_t sent = 0;

	while (sent < n) {
		ssize_t k = write(fd, p + sent, n - sent);

		if (k <= 0) {
			return -1;
		}
		sent += (size_t)k;
	}
	return 0;
}

/* --- the child ------------------------------------------------------------
 *
 * Stands in for the application. It reaches the maps the way UCLIENT's loader
 * will -- through the bpffs pins -- and registers its own socket.
 */
static int run_child(int port, int rfd, int wfd)
{
	struct sockaddr_in addr = {};
	struct child_report rep = {};
	struct epoll_event ev = {}, out = {};
	int cpipes, info, fd, epfd;
	char go;

	cpipes = bpf_obj_get(PIN_CPIPES);
	info = bpf_obj_get(PIN_INFO);
	if (cpipes < 0 || info < 0) {
		fprintf(stderr, "child: cannot open pins: %s\n", strerror(errno));
		return 1;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return 1;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons((uint16_t)port);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		fprintf(stderr, "child: connect failed: %s\n", strerror(errno));
		return 1;
	}

	/* Hijack our own socket: from here its remote end is the dpipe, not
	 * the server we just connected to. */
	if (splice(cpipes, CPIPE_KEY, info, DPIPE_KEY, fd)) {
		return 1;
	}
	if (write_all(wfd, "r", 1)) {
		return 1;
	}

	/* Park, exactly like an event-loop driver awaiting a response. Nothing
	 * was sent to this socket; only the redirect can make it readable. */
	epfd = epoll_create1(0);
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);

	if (epoll_wait(epfd, &out, 1, WAIT_MS) > 0) {
		rep.n = (int)read(fd, rep.buf, sizeof(rep.buf));
	} else {
		rep.n = -1;
	}
	if (write_all(wfd, &rep, sizeof(rep))) {
		return 1;
	}

	/* Reverse leg: this write should land on the dpipe rather than on the
	 * server the socket is nominally connected to. */
	if (read_all(rfd, &go, 1, WAIT_MS)) {
		return 1;
	}
	if (write_all(fd, REVERSE, strlen(REVERSE))) {
		return 1;
	}

	poll(NULL, 0, 200); /* let the parent drain before we close */
	close(fd);
	close(epfd);
	return 0;
}

/* --- socket construction -------------------------------------------------- */

static int start_listener(int *out_port)
{
	struct sockaddr_in addr = {};
	socklen_t alen = sizeof(addr);
	int lfd = socket(AF_INET, SOCK_STREAM, 0);

	if (lfd < 0) {
		return -1;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) || listen(lfd, 8)) {
		close(lfd);
		return -1;
	}
	if (getsockname(lfd, (struct sockaddr *)&addr, &alen)) {
		close(lfd);
		return -1;
	}
	*out_port = ntohs(addr.sin_port);
	return lfd;
}

/* Loopback TCP, matching what the daemon's dpipe pool does. */
static int make_tcp_pipe(int *a, int *b, int *l)
{
	struct sockaddr_in addr = {};
	socklen_t alen = sizeof(addr);
	int lfd, cfd, sfd, unused_port = 0;

	lfd = start_listener(&unused_port);
	if (lfd < 0) {
		return -1;
	}
	if (getsockname(lfd, (struct sockaddr *)&addr, &alen)) {
		close(lfd);
		return -1;
	}
	cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (cfd < 0) {
		close(lfd);
		return -1;
	}
	if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr))) {
		close(cfd);
		close(lfd);
		return -1;
	}
	sfd = accept(lfd, NULL, NULL);
	if (sfd < 0) {
		close(cfd);
		close(lfd);
		return -1;
	}
	*a = cfd;
	*b = sfd;
	*l = lfd;
	return 0;
}

int main(int argc, char **argv)
{
	struct kclient_bpf *skel = NULL;
	int in_proc = 0, use_socketpair = 0;
	int listen_fd = -1, accepted = -1, port = 0;
	int dp_a = -1, dp_b = -1, dp_l = -1;
	int cl_a = -1, cl_b = -1, cl_l = -1;
	int c2p[2] = { -1, -1 }, p2c[2] = { -1, -1 };
	int cpipes_fd, info_fd, dpipes_fd;
	int c2d_on = 0, d2c_on = 0, pinned = 0;
	struct child_report rep = {};
	unsigned char msg[sizeof(struct agent_reply) + sizeof(BODY) - 1];
	struct agent_reply hdr = {};
	pid_t child = -1;
	char rbuf[128], ready;
	int rc = 1, i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--in-proc") == 0) {
			in_proc = 1;
		} else if (strcmp(argv[i], "--socketpair") == 0) {
			use_socketpair = 1;
		} else if (strcmp(argv[i], "--child") == 0 && i + 3 < argc) {
			return run_child(atoi(argv[i + 1]), atoi(argv[i + 2]),
					 atoi(argv[i + 3]));
		} else {
			fprintf(stderr, "usage: %s [--in-proc] [--socketpair]\n", argv[0]);
			return 1;
		}
	}

	{
		LIBBPF_OPTS(bpf_object_open_opts, oo, .pin_root_path = QC_PIN_DIR);

		mkdir(QC_PIN_DIR, 0700);
		skel = kclient_bpf__open_opts(&oo);
	}
	if (!skel) {
		fprintf(stderr, "open skeleton failed\n");
		return 1;
	}
	if (kclient_bpf__load(skel)) {
		fprintf(stderr, "SKIP: BPF load failed: %s (need root?)\n",
			strerror(errno));
		kclient_bpf__destroy(skel);
		return 77;
	}

	cpipes_fd = bpf_map__fd(skel->maps.cpipe_map);
	info_fd = bpf_map__fd(skel->maps.pipe_sk_info_map);
	dpipes_fd = bpf_map__fd(skel->maps.dpipe_map);

	{
		__u32 k = QC_CFG_ENABLED, v = 1;

		bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);
	}

	/* One attach per side: which map a program is attached to is how it
	 * knows its direction. */
	if (bpf_prog_attach(bpf_program__fd(skel->progs.splice_c2d), cpipes_fd,
			    BPF_SK_MSG_VERDICT, 0)) {
		fprintf(stderr, "attach client->dpipe failed: %s\n", strerror(errno));
		goto out;
	}
	c2d_on = 1;
	if (bpf_prog_attach(bpf_program__fd(skel->progs.splice_d2c), dpipes_fd,
			    BPF_SK_MSG_VERDICT, 0)) {
		fprintf(stderr, "attach dpipe->client failed: %s\n", strerror(errno));
		goto out;
	}
	d2c_on = 1;

	listen_fd = start_listener(&port);
	if (listen_fd < 0) {
		fprintf(stderr, "listener failed: %s\n", strerror(errno));
		goto out;
	}

	/* The daemon's end of the splice. */
	if (use_socketpair) {
		int sv[2];

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
			fprintf(stderr, "socketpair failed: %s\n", strerror(errno));
			goto out;
		}
		dp_a = sv[0];
		dp_b = sv[1];
		fprintf(stderr,
			"note: --socketpair, so the dpipe is AF_UNIX. sk_msg runs\n"
			"      from the TCP sendmsg path; unix_bpf never replaces\n"
			"      sendmsg, so the redirect is not expected to fire.\n");
	} else if (make_tcp_pipe(&dp_a, &dp_b, &dp_l)) {
		fprintf(stderr, "dpipe failed: %s\n", strerror(errno));
		goto out;
	}
	if (splice(dpipes_fd, DPIPE_KEY, info_fd, CPIPE_KEY, dp_a)) {
		if (use_socketpair) {
			printf("RESULT: sock_map would not take the AF_UNIX socket.\n"
			       "        socketpair(2) cannot back a dpipe.\n");
		}
		goto out;
	}

	if (in_proc) {
		if (make_tcp_pipe(&cl_a, &cl_b, &cl_l)) {
			fprintf(stderr, "client pair failed: %s\n", strerror(errno));
			goto out;
		}
		if (splice(cpipes_fd, CPIPE_KEY, info_fd, DPIPE_KEY, cl_a)) {
			goto out;
		}
	} else {
		/* The maps are already pinned under QC_PIN_DIR by libbpf; the
		 * child reaches them by path, exactly as UCLIENT's loader will.
		 * Nothing is inherited. */
		if (access(PIN_CPIPES, F_OK) || access(PIN_INFO, F_OK)) {
			fprintf(stderr,
				"SKIP: maps were not pinned under %s\n"
				"      (is /sys/fs/bpf mounted in this container?)\n",
				QC_PIN_DIR);
			rc = 77;
			goto out;
		}
		pinned = 1;

		if (pipe(c2p) || pipe(p2c)) {
			fprintf(stderr, "pipe failed: %s\n", strerror(errno));
			goto out;
		}
		child = fork();
		if (child < 0) {
			fprintf(stderr, "fork failed: %s\n", strerror(errno));
			goto out;
		}
		if (child == 0) {
			char sport[16], srfd[16], swfd[16];

			close(c2p[0]);
			close(p2c[1]);
			snprintf(sport, sizeof(sport), "%d", port);
			snprintf(srfd, sizeof(srfd), "%d", p2c[0]);
			snprintf(swfd, sizeof(swfd), "%d", c2p[1]);
			/* execve, not just fork: the descriptor table must be
			 * genuinely the child's own, with nothing inherited
			 * that could make this pass for the wrong reason. */
			execl("/proc/self/exe", argv[0], "--child", sport, srfd, swfd,
			      (char *)NULL);
			_exit(127);
		}
		close(c2p[1]);
		c2p[1] = -1;
		close(p2c[0]);
		p2c[0] = -1;

		if (read_all(c2p[0], &ready, 1, WAIT_MS)) {
			fprintf(stderr, "FAIL: child never registered its socket\n");
			goto out;
		}
		accepted = accept(listen_fd, NULL, NULL);
	}

	/* A real AGENT_OK carries only the 4-byte header -- the response bytes
	 * live in the arena. The trailing BODY here is a transport probe: it
	 * shows a multi-byte write survives the splice intact, which a bare
	 * 4-byte header would not demonstrate. */
	hdr.status = AGENT_OK;
	hdr.stmt_id = 42;
	memcpy(msg, &hdr, sizeof(hdr));
	memcpy(msg + sizeof(hdr), BODY, sizeof(BODY) - 1);

	if (write_all(dp_a, msg, sizeof(msg))) {
		fprintf(stderr, "write to dpipe failed: %s\n", strerror(errno));
		goto out;
	}

	if (in_proc) {
		struct epoll_event ev = {}, out_ev = {};
		int epfd = epoll_create1(0);

		ev.events = EPOLLIN;
		ev.data.fd = cl_a;
		epoll_ctl(epfd, EPOLL_CTL_ADD, cl_a, &ev);
		if (epoll_wait(epfd, &out_ev, 1, WAIT_MS) > 0) {
			rep.n = (int)read(cl_a, rep.buf, sizeof(rep.buf));
		} else {
			rep.n = -1;
		}
		close(epfd);
	} else if (read_all(c2p[0], &rep, sizeof(rep), WAIT_MS * 2)) {
		/* Outwait the child deliberately: when the redirect does not
		 * fire it spends the full WAIT_MS in epoll before it can report
		 * the miss, and racing it would turn a clean negative into "no
		 * answer at all". */
		fprintf(stderr, "FAIL: child never reported a result\n");
		goto out;
	}

	if (rep.n <= 0) {
		if (use_socketpair) {
			printf("RESULT: socketpair(2) cannot back a dpipe.\n"
			       "        The map accepted the AF_UNIX socket, but no\n"
			       "        sk_msg program ran on its send, so nothing was\n"
			       "        redirected. sk_msg is installed by replacing\n"
			       "        sk_prot->sendmsg, which tcp_bpf does and\n"
			       "        unix_bpf does not.\n"
			       "        architecture.txt lines 199/254 need loopback TCP.\n");
			goto out;
		}
		fprintf(stderr,
			"FAIL: the client fd never became readable.\n"
			"      %s\n",
			in_proc ? "Even the in-process control failed, so the fault is\n"
				  "      in the redirect itself."
				: "Re-run with --in-proc to tell a cross-process problem\n"
				  "      apart from a broken redirect.");
		goto out;
	}
	if (rep.n != (int)sizeof(msg) || memcmp(rep.buf, msg, sizeof(msg)) != 0) {
		fprintf(stderr, "FAIL: woke up, but got %d bytes and expected %d\n",
			rep.n, (int)sizeof(msg));
		goto out;
	}

	printf("PASS (daemon -> client): %d bytes reached %s socket and woke\n"
	       "      epoll_wait().\n",
	       rep.n, in_proc ? "an in-process" : "another process's");

	if (in_proc) {
		printf("SKIP (client -> daemon): needs a second process.\n");
		rc = 0;
		goto out;
	}

	if (write_all(p2c[1], "g", 1)) {
		fprintf(stderr, "could not signal child\n");
		goto out;
	}
	{
		struct pollfd pfd = { .fd = dp_a, .events = POLLIN };

		if (poll(&pfd, 1, WAIT_MS) <= 0) {
			fprintf(stderr,
				"FAIL: the client's write never arrived on the dpipe.\n"
				"      architecture.txt line 278 requires both\n"
				"      directions; only daemon -> client works.\n");
			goto out;
		}
	}
	i = (int)read(dp_a, rbuf, sizeof(rbuf));
	if (i != (int)strlen(REVERSE) || memcmp(rbuf, REVERSE, strlen(REVERSE)) != 0) {
		fprintf(stderr, "FAIL: reverse leg delivered %d unexpected bytes\n", i);
		goto out;
	}

	printf("PASS (client -> daemon): %d bytes written by the child arrived on\n"
	       "      the dpipe instead of the server it thought it was talking to.\n",
	       i);
	rc = 0;

out:
	if (child > 0) {
		int st;

		waitpid(child, &st, 0);
	}
	if (pinned) {
		/* Leave no pins behind: a stale one would be silently reused by
		 * the next run and carry its state with it. */
		unlink(PIN_CPIPES);
		unlink(PIN_INFO);
	}
	if (c2d_on) {
		bpf_prog_detach2(bpf_program__fd(skel->progs.splice_c2d), cpipes_fd,
				 BPF_SK_MSG_VERDICT);
	}
	if (d2c_on) {
		bpf_prog_detach2(bpf_program__fd(skel->progs.splice_d2c), dpipes_fd,
				 BPF_SK_MSG_VERDICT);
	}
	if (c2p[0] >= 0) {
		close(c2p[0]);
	}
	if (c2p[1] >= 0) {
		close(c2p[1]);
	}
	if (p2c[0] >= 0) {
		close(p2c[0]);
	}
	if (p2c[1] >= 0) {
		close(p2c[1]);
	}
	if (dp_a >= 0) {
		close(dp_a);
	}
	if (dp_b >= 0) {
		close(dp_b);
	}
	if (dp_l >= 0) {
		close(dp_l);
	}
	if (cl_a >= 0) {
		close(cl_a);
	}
	if (cl_b >= 0) {
		close(cl_b);
	}
	if (cl_l >= 0) {
		close(cl_l);
	}
	if (accepted >= 0) {
		close(accepted);
	}
	if (listen_fd >= 0) {
		close(listen_fd);
	}
	kclient_bpf__destroy(skel);
	return rc;
}
