// SPDX-License-Identifier: GPL-2.0
/*
 * test_pipes.cpp - the agent_pipe pool against the real KCLIENT redirect.
 *
 * Goes further than spike/redirect_test.c: that proved a hand-built pair
 * could redirect, this proves the pooled implementation does -- acquire a
 * pipe, write the mini-protocol, see it wake an epoll client, release, and
 * confirm the pairing is gone so a released pipe cannot leak into a client
 * that is no longer waiting.
 *
 * Needs root and a kernel with sockmap support; skipped elsewhere.
 */
#include "pipes.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "kclient.skel.h"

using namespace qcd;

static int g_fail;

#define CHECK(cond, msg)                                                          \
	do {                                                                      \
		if (!(cond)) {                                                    \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,   \
				msg);                                             \
			g_fail++;                                                 \
		}                                                                 \
	} while (0)

/* A stand-in for an application's MySQL connection: connected, and parked in
 * epoll waiting for a response that will only ever arrive via redirect. */
struct FakeClient {
	int fd = -1, peer = -1, listen = -1;

	bool start()
	{
		struct sockaddr_in addr {};
		socklen_t alen = sizeof(addr);

		listen = socket(AF_INET, SOCK_STREAM, 0);
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(listen, (struct sockaddr *)&addr, sizeof(addr)) ||
		    ::listen(listen, 4) ||
		    getsockname(listen, (struct sockaddr *)&addr, &alen)) {
			return false;
		}
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
			return false;
		}
		peer = accept(listen, nullptr, nullptr);
		return peer >= 0;
	}

	void stop()
	{
		for (int *f : { &fd, &peer, &listen }) {
			if (*f >= 0) {
				close(*f);
				*f = -1;
			}
		}
	}
};

int main()
{
	struct kclient_bpf *skel = kclient_bpf__open();

	if (!skel || kclient_bpf__load(skel)) {
		fprintf(stderr, "SKIP: cannot load kclient BPF (need root?): %s\n",
			strerror(errno));
		return 77; /* skip */
	}

	__u32 k = KCLIENT_CFG_ENABLED, v = 1;

	bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &k, &v, BPF_ANY);

	if (bpf_prog_attach(bpf_program__fd(skel->progs.redirect),
			     bpf_map__fd(skel->maps.sock_map), BPF_SK_MSG_VERDICT, 0)) {
		fprintf(stderr, "SKIP: sk_msg attach failed: %s\n", strerror(errno));
		kclient_bpf__destroy(skel);
		return 77;
	}

	PipePool pool;

	CHECK(pool.init(bpf_map__fd(skel->maps.sock_map),
			 bpf_map__fd(skel->maps.pipe_pairs), 4),
	      "pool init");
	CHECK(pool.size() == 4, "pool size");
	CHECK(pool.freeCount() == 4, "all pipes free initially");

	FakeClient client;

	CHECK(client.start(), "fake client connected");

	sock_key ckey {};

	CHECK(sockKeyOf(client.fd, ckey), "client sock_key");
	CHECK(bpf_map_update_elem(bpf_map__fd(skel->maps.sock_map), &ckey, &client.fd,
				   BPF_ANY) == 0,
	      "client registered in sockmap");

	AgentPipe *p = pool.acquire(ckey);

	CHECK(p != nullptr, "acquired a pipe");
	CHECK(pool.freeCount() == 3, "free count dropped");

	if (p) {
		/* The daemon's reply: a four-byte header, then payload. */
		agent_reply hdr {};
		const char *body = "RESPONSE-BYTES";

		hdr.status = AGENT_OK;
		hdr.length = (uint32_t)strlen(body);

		std::vector<uint8_t> msg;

		msg.insert(msg.end(), (uint8_t *)&hdr, (uint8_t *)&hdr + sizeof(hdr));
		msg.insert(msg.end(), body, body + strlen(body));

		int epfd = epoll_create1(0);
		struct epoll_event ev {}, out {};

		ev.events = EPOLLIN;
		ev.data.fd = client.fd;
		epoll_ctl(epfd, EPOLL_CTL_ADD, client.fd, &ev);

		ssize_t n = write(p->local_fd, msg.data(), msg.size());

		CHECK(n == (ssize_t)msg.size(), "wrote mini-protocol into pipe");

		/* The assertion that matters: the client was never sent
		 * anything directly, so only the redirect can wake this. */
		int ready = epoll_wait(epfd, &out, 1, 2000);

		CHECK(ready == 1, "redirect woke the client's epoll");

		if (ready == 1) {
			uint8_t buf[128];
			ssize_t got = read(client.fd, buf, sizeof(buf));

			CHECK(got == (ssize_t)msg.size(), "client read full message");
			CHECK(buf[0] == AGENT_OK, "status byte survived");
			CHECK(memcmp(buf + sizeof(hdr), body, strlen(body)) == 0,
			      "payload survived");
		}
		close(epfd);

		pool.release(p);
		CHECK(pool.freeCount() == 4, "pipe returned to free list");

		/* A released pipe must no longer be paired, or its next write
		 * would land in a client that has moved on. */
		sock_key probe {};
		CHECK(bpf_map_lookup_elem(bpf_map__fd(skel->maps.pipe_pairs), &p->skey,
					   &probe) != 0,
		      "pairing removed on release");
	}

	/* Exhaustion must be reported, not blocked on: the caller falls back to
	 * sending the query normally. */
	{
		std::vector<AgentPipe *> held;

		for (int i = 0; i < 8; i++) {
			AgentPipe *q = pool.acquire(ckey);

			if (!q) {
				break;
			}
			held.push_back(q);
		}
		CHECK(held.size() == 4, "acquired exactly the pool size");
		CHECK(pool.acquire(ckey) == nullptr, "exhaustion returns null");
		for (auto *q : held) {
			pool.release(q);
		}
		CHECK(pool.freeCount() == 4, "all pipes returned");
	}

	pool.shutdown();
	client.stop();
	kclient_bpf__destroy(skel);

	printf("%s\n", g_fail == 0 ? "pipe pool: PASS" : "pipe pool: FAIL");
	return g_fail == 0 ? 0 : 1;
}
