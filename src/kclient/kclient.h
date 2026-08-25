/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kclient.h - shared between the KCLIENT eBPF program, the DAEMON, and
 * UCLIENT.
 *
 * KCLIENT's whole job is the socket redirect. When the daemon writes the
 * mini-protocol into an agent_pipe, those bytes have to land in the *client's*
 * socket receive queue -- not the daemon's peer. That is what makes the
 * client's fd readable, which is what wakes a client parked in epoll_wait().
 *
 * Without it a suppressed query leaves an event-loop client waiting forever
 * for readability that never comes, because the query was never sent and the
 * server will never answer. Injecting at SSL_read alone only works for a
 * blocking client that calls SSL_read of its own accord.
 */
#ifndef VALKEY_EBPF_KCLIENT_H
#define VALKEY_EBPF_KCLIENT_H

/* Included from two very different places: BPF programs (which already have
 * these from vmlinux.h) and ordinary userspace. Pulling the types in directly
 * makes it self-sufficient in both, rather than depending on include order.
 * vmlinux.h defines them itself, hence the guard. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* Identifies one TCP connection. Available identically from sock_ops (at
 * connect time) and sk_msg (on send), which is what lets the two halves
 * agree on which socket is which. IPv4 only for now.
 *
 * Byte-order convention follows the common sockmap idiom: remote_port is
 * already network order, local_port is host order and needs bpf_htonl().
 */
struct sock_key {
	__u32 sip;
	__u32 dip;
	__u32 sport;
	__u32 dport;
	__u32 family;
};

/* Published on the ch_assign ringbuffer when UCLIENT takes a pipe out of the
 * free list, telling the daemon which pipe now has a client waiting on it. */
struct ch_assign_msg {
	__u32 pipe_key;   /* which agent_pipe was assigned */
	__u32 _pad;
	__u64 request_id; /* correlates the daemon's reply with the waiter */
};

/* Mini-protocol status codes, written by the daemon into the pipe and read
 * by UCLIENT out of the redirected socket. Four bytes, then any payload. */
enum agent_status {
	AGENT_OK = 0x01,          /* cache hit; length + payload follow */
	AGENT_WRITE_THROUGH = 0x00, /* miss; client must fetch and store */
	AGENT_CACHE_ERROR = 0xff, /* cache unreachable; pass through */
};

/* Header the daemon writes into the pipe. Kept to four bytes as specified;
 * AGENT_OK is followed by `length` bytes of MySQL response. */
struct agent_reply {
	__u8 status;
	__u8 _pad[3];
	__u32 length; /* payload bytes following, AGENT_OK only */
};

#define KCLIENT_CFG_ENABLED 0
#define KCLIENT_CFG_PORT 1
#define KCLIENT_CFG_DAEMON_TGID 2
#define KCLIENT_CFG__N 3

#endif /* VALKEY_EBPF_KCLIENT_H */
