// SPDX-License-Identifier: GPL-2.0
/*
 * kclient.bpf.c - KCLIENT: socket classification and redirect.
 *
 * Two programs, one job between them: get the daemon's mini-protocol bytes
 * into the client's socket receive queue.
 *
 *   classify()   sock_ops. At ACTIVE_ESTABLISHED_CB, adds outbound
 *                connections to the target port into sock_map. A socket must
 *                be in the map before anything can be redirected to it.
 *
 *   redirect()   sk_msg. Runs on every send from a socket in the map. If the
 *                sender is an agent_pipe (it has an entry in pipe_pairs),
 *                the bytes are redirected into the paired client socket's
 *                INGRESS queue instead of going out on the pipe's own wire.
 *                Everything else passes through untouched.
 *
 * The BPF_F_INGRESS flag is the whole point. Redirecting to a socket's
 * ingress makes those bytes appear as if they had arrived from the network:
 * the fd becomes readable, epoll fires, and a client sitting in epoll_wait()
 * wakes up and calls read(). UCLIENT then consumes the mini-protocol from
 * that read and returns EINTR so the bytes never reach the TLS record layer.
 *
 * This is the piece that makes the design work for non-blocking clients.
 * Injecting a cached response at SSL_read alone is sufficient only for a
 * blocking client that calls SSL_read on its own; an event-loop client never
 * gets that far, because nothing ever makes its socket readable.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "kclient.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

/* Client sockets and agent_pipe sockets both live here. Membership is what
 * routes a socket's traffic through the sk_msg program at all. */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 4096);
	__type(key, struct sock_key);
	__type(value, __u32);
} sock_map SEC(".maps");

/* pipe sock_key -> client sock_key.
 *
 * Populated by the daemon when it hands a pipe to a waiting client, and
 * removed when the pipe goes back on the free list. Its presence is also how
 * redirect() tells a pipe socket from a client socket. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sock_key);
	__type(value, struct sock_key);
} pipe_pairs SEC(".maps");

/* Runtime configuration, written by the daemon before attach. An array
 * rather than .rodata so the daemon can flip the enable flag and change the
 * target port without reloading. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, KCLIENT_CFG__N);
	__type(key, __u32);
	__type(value, __u32);
} cfg SEC(".maps");

static __always_inline __u32 cfg_get(__u32 slot)
{
	__u32 *v = bpf_map_lookup_elem(&cfg, &slot);

	return v ? *v : 0;
}

static __always_inline void key_from_ops(struct bpf_sock_ops *ops, struct sock_key *k)
{
	k->sip = ops->local_ip4;
	k->dip = ops->remote_ip4;
	k->sport = bpf_htonl(ops->local_port); /* local_port is host order */
	k->dport = ops->remote_port;           /* remote_port already network order */
	k->family = ops->family;
}

static __always_inline void key_from_msg(struct sk_msg_md *msg, struct sock_key *k)
{
	k->sip = msg->local_ip4;
	k->dip = msg->remote_ip4;
	k->sport = bpf_htonl(msg->local_port);
	k->dport = msg->remote_port;
	k->family = msg->family;
}

SEC("sockops")
int classify(struct bpf_sock_ops *ops)
{
	struct sock_key key = {};
	__u32 port;

	if (!cfg_get(KCLIENT_CFG_ENABLED)) {
		return 0;
	}
	if (ops->family != AF_INET) {
		return 0;
	}

	/* Both directions are registered. ACTIVE is the application connecting
	 * out to MySQL; PASSIVE is the daemon accepting its own pipe
	 * connection, which must also be in the map for redirect() to see its
	 * sends. */
	if (ops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
	    ops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		return 0;
	}

	port = cfg_get(KCLIENT_CFG_PORT);

	/* Register anything talking to the MySQL port, plus loopback traffic,
	 * which is how the daemon's own pipe pair shows up. Registering a
	 * socket is harmless on its own -- nothing is redirected until a
	 * pipe_pairs entry exists for it. */
	if (port && bpf_ntohl(ops->remote_port) != port &&
	    bpf_htonl(ops->local_port) != bpf_htonl(port)) {
		__u32 lo = bpf_ntohl(ops->local_ip4);

		/* 127.0.0.0/8 */
		if ((lo >> 24) != 127) {
			return 0;
		}
	}

	key_from_ops(ops, &key);
	bpf_sock_hash_update(ops, &sock_map, &key, BPF_ANY);
	return 0;
}

SEC("sk_msg")
int redirect(struct sk_msg_md *msg)
{
	struct sock_key self = {};
	struct sock_key *peer;

	if (!cfg_get(KCLIENT_CFG_ENABLED)) {
		return SK_PASS;
	}
	if (msg->family != AF_INET) {
		return SK_PASS;
	}

	key_from_msg(msg, &self);

	/* Only agent_pipes have a pairing. A client socket sending its own
	 * traffic to MySQL finds nothing here and passes straight through --
	 * we never interfere with real queries on the wire. */
	peer = bpf_map_lookup_elem(&pipe_pairs, &self);
	if (!peer) {
		return SK_PASS;
	}

	/* BPF_F_INGRESS: deliver into the client socket's RECEIVE queue, so
	 * the bytes look like they arrived from the network and the fd becomes
	 * readable. Without the flag they would be sent out of the client
	 * socket towards mysqld, which is the opposite of what we want. */
	return bpf_msg_redirect_hash(msg, &sock_map, peer, BPF_F_INGRESS);
}
