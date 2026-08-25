// SPDX-License-Identifier: GPL-2.0
/*
 * redirect_test.c - does the KCLIENT redirect actually wake an epoll client?
 *
 * This is the assumption the entire architecture rests on, and the one I
 * previously skipped past. It is tested in isolation, before the daemon and
 * UCLIENT are built on top of it.
 *
 * Setup mirrors the real topology:
 *
 *   "client" socket   stands in for the application's MySQL connection.
 *                     Parked in epoll_wait(), exactly like an event-loop
 *                     driver waiting for a response.
 *   "pipe" socket     stands in for an agent_pipe owned by the daemon.
 *
 * Both go into sock_map, a pipe_pairs entry points pipe -> client, and the
 * test writes into the pipe end. If the sk_msg redirect works, those bytes
 * arrive in the CLIENT socket's receive queue, epoll fires, and we read them
 * back. If it does not, epoll times out -- which is precisely how an async
 * client would hang in production.
 *
 * Run inside the bpf container as root:
 *   ./build/redirect_test
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../src/kclient/kclient.h"
#include "kclient.skel.h"

static int connect_pair(int *client_fd, int *server_fd, int *listen_fd)
{
	struct sockaddr_in addr = {};
	socklen_t alen = sizeof(addr);
	int lfd, cfd, sfd;

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		return -1;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) || listen(lfd, 4)) {
		close(lfd);
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

	*client_fd = cfd;
	*server_fd = sfd;
	*listen_fd = lfd;
	return 0;
}

/* Build the sock_key for a socket exactly as the BPF side builds it.
 *
 * The port encoding is the classic sockmap trap. In BPF, sk_msg_md.local_port
 * is the port as a HOST-order u32, and the idiom is bpf_htonl(local_port);
 * remote_port is already stored in that same htonl'd form. So both key fields
 * hold htonl(port_number) -- for 3306 that is 0xEA0C0000.
 *
 * A sockaddr_in's sin_port is a 16-bit network-order value, which
 * zero-extends to 0x0000EA0C instead. Using it directly produces a key that
 * silently never matches, and the redirect quietly does nothing.
 */
static int key_of(int fd, struct sock_key *k)
{
	struct sockaddr_in local = {}, remote = {};
	socklen_t l = sizeof(local), r = sizeof(remote);

	if (getsockname(fd, (struct sockaddr *)&local, &l)) {
		return -1;
	}
	if (getpeername(fd, (struct sockaddr *)&remote, &r)) {
		return -1;
	}
	memset(k, 0, sizeof(*k));
	k->sip = local.sin_addr.s_addr;
	k->dip = remote.sin_addr.s_addr;
	k->sport = htonl(ntohs(local.sin_port));
	k->dport = htonl(ntohs(remote.sin_port));
	k->family = AF_INET;
	return 0;
}

int main(void)
{
	struct kclient_bpf *skel;
	int cfd = -1, sfd = -1, lfd = -1;
	int pipe_a = -1, pipe_b = -1, pipe_l = -1;
	struct sock_key client_key, pipe_key;
	int err, epfd, rc = 1;
	struct epoll_event ev, out;
	char buf[128];
	const char *payload = "\x01\x00\x00\x00MINI";
	size_t payload_len = 8;

	skel = kclient_bpf__open();
	if (!skel) {
		fprintf(stderr, "open skeleton failed\n");
		return 1;
	}
	if (kclient_bpf__load(skel)) {
		fprintf(stderr, "load failed: %s\n", strerror(errno));
		goto out;
	}

	/* Enable, and set a port that will not match, so classify() only picks
	 * up the loopback sockets this test creates. */
	{
		__u32 k = KCLIENT_CFG_ENABLED, v = 1;

		bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);
		k = KCLIENT_CFG_PORT;
		v = 3306;
		bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);
	}

	/* Attach sk_msg to the sockmap. The sockops program is not needed
	 * here: this test registers its sockets from userspace directly, which
	 * is exactly what the daemon does for its own pipes. */
	err = bpf_prog_attach(bpf_program__fd(skel->progs.redirect),
			       bpf_map__fd(skel->maps.sock_map), BPF_SK_MSG_VERDICT, 0);
	if (err) {
		fprintf(stderr, "attach sk_msg failed: %s\n", strerror(errno));
		goto out;
	}

	if (connect_pair(&cfd, &sfd, &lfd)) {
		fprintf(stderr, "client pair failed: %s\n", strerror(errno));
		goto out;
	}
	if (connect_pair(&pipe_a, &pipe_b, &pipe_l)) {
		fprintf(stderr, "pipe pair failed: %s\n", strerror(errno));
		goto out;
	}

	if (key_of(cfd, &client_key) || key_of(pipe_a, &pipe_key)) {
		fprintf(stderr, "key_of failed\n");
		goto out;
	}

	/* Register both sockets, then pair pipe -> client. */
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.sock_map), &client_key, &cfd,
				 BPF_ANY)) {
		fprintf(stderr, "register client failed: %s\n", strerror(errno));
		goto out;
	}
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.sock_map), &pipe_key, &pipe_a,
				 BPF_ANY)) {
		fprintf(stderr, "register pipe failed: %s\n", strerror(errno));
		goto out;
	}
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.pipe_pairs), &pipe_key,
				 &client_key, BPF_ANY)) {
		fprintf(stderr, "pairing failed: %s\n", strerror(errno));
		goto out;
	}

	/* The client parks in epoll, like an event-loop driver awaiting a
	 * response. Nothing has been sent to it; only the redirect can wake
	 * this up. */
	epfd = epoll_create1(0);
	ev.events = EPOLLIN;
	ev.data.fd = cfd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev);

	if (write(pipe_a, payload, payload_len) != (ssize_t)payload_len) {
		fprintf(stderr, "write to pipe failed: %s\n", strerror(errno));
		goto out;
	}

	err = epoll_wait(epfd, &out, 1, 2000);
	if (err <= 0) {
		fprintf(stderr,
			"FAIL: epoll timed out -- the client fd never became "
			"readable.\n"
			"      This is exactly how an async client hangs when the\n"
			"      redirect is missing.\n");
		goto out;
	}

	err = (int)read(cfd, buf, sizeof(buf));
	if (err != (int)payload_len || memcmp(buf, payload, payload_len) != 0) {
		fprintf(stderr, "FAIL: woke up but got %d unexpected bytes\n", err);
		goto out;
	}

	printf("PASS: %d bytes written to the agent_pipe arrived in the client\n"
	       "      socket's receive queue and woke epoll_wait().\n",
	       err);
	rc = 0;

out:
	if (cfd >= 0) {
		close(cfd);
	}
	if (sfd >= 0) {
		close(sfd);
	}
	if (lfd >= 0) {
		close(lfd);
	}
	if (pipe_a >= 0) {
		close(pipe_a);
	}
	if (pipe_b >= 0) {
		close(pipe_b);
	}
	if (pipe_l >= 0) {
		close(pipe_l);
	}
	kclient_bpf__destroy(skel);
	return rc;
}
