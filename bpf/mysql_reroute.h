/* Shared definitions between bpf/mysql_reroute.bpf.c and its userspace
 * loader (src/agent.cpp). Builds on proto.h's struct sock_key and adds the
 * reroute-specific pieces: what to overwrite a matched statement with, and
 * how a request correlates with its response.
 *
 * No restore_state/read_args here anymore (an earlier, tracepoint-based
 * version of this file had both): sk_msg mutates the kernel's own already-
 * copied sendmsg buffer, never the caller's own memory, so there is nothing
 * to restore; and sk_skb sees response bytes directly as they arrive on the
 * socket, with no need to stash a userspace buffer pointer ahead of time the
 * way correlating against a read()/recvfrom() syscall's own arguments did.
 */
#ifndef __MYSQL_REROUTE_H
#define __MYSQL_REROUTE_H

#include "proto.h"

/* Replacement text for a rerouted statement. The comment marker comes AFTER
 * the real statement on purpose: `SELECT 0` actually executes and returns a
 * harmless one-row result, and `-- ` swallows whatever padding follows so
 * the in-memory buffer's length -- which we cannot change, see below --
 * still matches the original. Putting `--` first would comment out
 * "SELECT 0" too and turn the statement into an empty query (MySQL error
 * 1065), which is a valid design choice if you want rerouted queries to
 * surface as an error instead -- just swap the order if that's what you want.
 */
#define REROUTE_TEXT "SELECT 0-- "
#define REROUTE_TEXT_LEN (sizeof(REROUTE_TEXT) - 1) /* 11, excludes the NUL */

/* Reroute-list key: the exact query text, zero-padded to MAX_QUERY_LEN.
 * Exact byte match against the assembled, CLIENT_QUERY_ATTRIBUTES-stripped
 * statement text -- no whitespace normalization. */
struct reroute_key {
	char query[MAX_QUERY_LEN];
};

/* One outstanding request per connection, used to correlate the response
 * arriving later on the same socket. MySQL's classic protocol is
 * synchronous -- no pipelining -- so a single slot per sock_key is exact,
 * not an approximation. */
struct pending_req {
	__u64 req_ts_ns; /* also serves as the correlation id */
	__u8 rerouted;
	__u8 _pad[7];
};

enum corr_kind {
	CORR_REQUEST = 0,
	CORR_RESPONSE = 1,
};

struct corr_event {
	__u64 ts_ns;
	__u64 req_ts_ns; /* correlation id: matches the request's ts_ns */
	/* REQUEST: the writing process, read via bpf_get_current_pid_tgid()
	 * from inside the synchronous sendmsg() syscall path -- accurate.
	 * RESPONSE: whatever process happened to be executing when the skb
	 * was processed on the receive path, which is not necessarily (and
	 * often is not) the application that will eventually call read() --
	 * sk_skb runs asynchronously with respect to the reading app. Best-
	 * effort only; do not rely on it for response events. */
	__u32 pid;
	__u32 tid;
	__u32 sport; /* client-side ephemeral port, host byte order */
	__u32 dport; /* server port, host byte order */
	__u32 len;      /* request: payload_len. response: bytes seen on the skb */
	__u32 data_len; /* valid bytes in data[]; always <= sizeof(data) */
	__u8 kind;      /* enum corr_kind */
	__u8 rerouted;
	__u8 truncated;
	__u8 _pad;
	char comm[TASK_COMM_LEN];
	/* CORR_REQUEST: the full original statement, zero-padded, captured
	 * before any reroute mutation -- the channel meant for "hand the query
	 * to my own code". CORR_RESPONSE: a short preview of the raw response
	 * bytes (binary protocol, not text). */
	char data[MAX_QUERY_LEN];
};

#endif /* __MYSQL_REROUTE_H */
