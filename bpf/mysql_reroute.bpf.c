// SPDX-License-Identifier: GPL-2.0
/*
 * mysql_reroute.bpf.c - reroute specific statements to a harmless no-op
 * before they reach mysqld, correlate the outcome, using BPF sockmap
 * instead of directly hooking write()/send()/sendto()/read()/recvfrom().
 *
 * --- why sockmap instead of tracepoints on send/recv --------------------
 *
 * An earlier version of this file hooked sys_enter_write/sys_enter_sendto
 * directly, mutated the statement in the calling process's own userspace
 * buffer via bpf_probe_write_user(), and had to save+restore those bytes at
 * sys_exit so the caller's own memory looked untouched afterward. It also
 * had to hand-roll reassembly of a statement split across multiple write()
 * calls, since each write() independently and immediately committed its
 * bytes to the wire regardless of what our BPF program decided.
 *
 * sockmap replaces both of those mechanisms with ones the kernel already
 * provides, more robustly, for exactly this purpose:
 *
 * 1. sk_msg programs (see handle_msg() below) run on the kernel's own
 *    already-copied sendmsg buffer -- by the time our program sees it, the
 *    data has left the caller's userspace memory. Mutating it here can
 *    never be observed by the calling process's own buffer, by
 *    construction. There is nothing to restore.
 * 2. bpf_msg_cork_bytes() tells the kernel to hold a message back --
 *    genuinely not forward it to mysqld at all -- until a target byte
 *    count has accumulated across possibly-many sendmsg()/write() calls on
 *    that socket. This means the old "some real query text was already
 *    committed to the wire in an earlier write()" hazard cannot occur, and
 *    there is no separate per-connection reassembly map to maintain --
 *    msg->size already reflects everything corked so far on every
 *    (re-)invocation.
 *
 *    Mutation itself, though, is deliberately *not* attempted on a
 *    statement that needed corking to complete -- only fully observed and
 *    reported. try_reroute()'s mutation combines bpf_msg_pop_data() (to
 *    shrink the message down to REROUTE_TEXT's length, see its own comment
 *    for why this project can do that now and couldn't with
 *    bpf_probe_write_user()) with a follow-up rewrite of the packet's
 *    length header. For a single-write statement this verifies and works
 *    correctly. For a statement that spanned multiple write() calls before
 *    corking released it, the identical code was confirmed empirically (via
 *    bpf_trace_printk() tracing plus a tcpdump capture) to make the kernel
 *    silently drop the message instead of forwarding the mutated result --
 *    not corrupt it, not delay it, just lose it, hanging both the client
 *    and mysqld waiting on each other. This codebase does not have a
 *    kernel-internals explanation for that behavior, only the observation;
 *    the honest response is to not attempt it, tracked by the `corking` map
 *    and handle_msg()'s `was_corked` gate below.
 *
 * A sock_ops program (classify() below) decides, once per connection, which
 * sockets are worth this treatment at all -- matched on remote port, at
 * connect() time, on the client side (BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) --
 * and adds them to a BPF_MAP_TYPE_SOCKHASH. Once a socket is in that map,
 * the kernel installs a ULP that routes write()/send()/sendto()/sendmsg()
 * on it uniformly through the attached sk_msg program (one hook covers all
 * of those syscalls) and its receives through the attached sk_skb program.
 *
 * The response side (handle_skb() below) observes bytes directly as they
 * arrive on the socket -- it does not need to correlate against a
 * read()/recvfrom() syscall's own buffer pointer the way the tracepoint
 * version's entry/exit dance did, since sk_skb sees the data itself, not a
 * copy destined for a particular userspace buffer.
 *
 * CLIENT_QUERY_ATTRIBUTES handling (parse_query_offset() below) is
 * unchanged from the tracepoint-based version: still a content heuristic,
 * still necessary, still applied the same way once we have the header.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "mysql_reroute.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 targ_pid = 0;    /* 0 = all processes */
const volatile __u32 targ_port = 3306; /* MySQL's default port */
const volatile __u32 min_query_len = 1;

/* Sockets classify() has matched. Membership in this map is what actually
 * routes a socket's traffic through handle_msg()/handle_skb() below -- see
 * BPF_MAP_TYPE_SOCKMAP's documentation for the ULP-installation mechanics. */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 1024);
	__type(key, struct sock_key);
	__type(value, __u32);
} sock_hash SEC(".maps");

/* Statements to neuter, keyed on their exact assembled query text. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct reroute_key);
	__type(value, __u64); /* membership marker */
} reroute_list SEC(".maps");

/* One outstanding request per connection, for response correlation. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct sock_key);
	__type(value, struct pending_req);
} pending_reqs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} corr_events SEC(".maps");

/* Scratch for building the zero-padded reroute_list lookup key: a
 * struct reroute_key is MAX_QUERY_LEN bytes, too large for the plain BPF
 * stack (512-byte budget) once other locals are counted. Same reasoning as
 * every percpu scratch map elsewhere in this project's history. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct reroute_key);
} key_scratch SEC(".maps");

/* Marks a connection whose currently-accumulating statement needed at least
 * one round of bpf_msg_cork_bytes() to complete. Read and cleared on every
 * handle_msg() invocation, re-armed by both its cork_bytes() call sites --
 * see the mutation-gating comment in handle_msg() for why this matters:
 * mutating a corked (multi-invocation) statement was found to make the
 * kernel silently drop it instead of forwarding the result. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct sock_key);
	__type(value, __u8);
} corking SEC(".maps");

/* sk_msg/sk_skb programs cannot call bpf_get_current_comm() -- it is not on
 * the helper allowlist for those program types (verified by trying: "program
 * of this type cannot use helper bpf_get_current_comm"), unlike tracepoint
 * programs where it just works. bpf_get_current_task_btf() returns a
 * verifier-trusted BTF-typed pointer that direct struct field reads and
 * bpf_probe_read_kernel_str() both remain valid over, and is on the
 * allowlist for both program types here. */
static __always_inline void read_comm(char *dst, __u32 len)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (task) {
		bpf_probe_read_kernel_str(dst, len, task->comm);
	} else {
		__builtin_memset(dst, 0, len);
	}
}

/* `have >= BASE_HEADER_LEN + QUERY_ATTR_LEN` alone is not enough to let the
 * verifier accept hdrbuf[BASE_HEADER_LEN]/hdrbuf[BASE_HEADER_LEN+1] (both
 * compile-time-constant offsets): that comparison is against `have`, a
 * runtime scalar, and proving `data + have <= data_end` at the pull_data
 * call site does not transfer onto *this* pointer's own verifier-tracked
 * readable range the way a direct `data + CONST <= data_end` comparison
 * does. Repeating the check in that specific constant-offset shape (against
 * data_end, not have) is what actually lets the verifier narrow hdrbuf's
 * range enough to accept the two accesses below. */
static __always_inline __u32 parse_query_offset(const char *hdrbuf, const void *data_end,
						  __u32 have)
{
	if (have >= BASE_HEADER_LEN + QUERY_ATTR_LEN &&
	    (void *)(hdrbuf + MAX_HEADER_LEN) <= data_end &&
	    hdrbuf[BASE_HEADER_LEN] == 0x00 && hdrbuf[BASE_HEADER_LEN + 1] == 0x01) {
		return BASE_HEADER_LEN + QUERY_ATTR_LEN;
	}
	return BASE_HEADER_LEN;
}

/* Classify a newly-established outbound (client-side) connection: if its
 * remote port matches targ_port, add it to sock_hash so its traffic gets
 * routed through handle_msg()/handle_skb() below. Fires once per
 * connection, not per message -- this is where the port-based filter this
 * project didn't previously need lives now: the tracepoint-based version
 * filtered every socket's traffic by wire-content heuristics alone, but
 * sockmap requires opting sockets in before any content can be inspected
 * at all. */
SEC("sockops")
int classify(struct bpf_sock_ops *skops)
{
	struct sock_key key;

	if (skops->family != AF_INET) {
		return 0;
	}
	if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
		return 0;
	}
	if (targ_pid) {
		__u64 id = bpf_get_current_pid_tgid();

		if ((__u32)(id >> 32) != targ_pid) {
			return 0;
		}
	}
	/* remote_port is already network byte order; local_port is host byte
	 * order and needs converting to match, matching common sockmap
	 * example convention (see proto.h's struct sock_key comment). */
	if (bpf_ntohl(skops->remote_port) != targ_port) {
		return 0;
	}

	key.sip = skops->local_ip4;
	key.dip = skops->remote_ip4;
	key.sport = bpf_htonl(skops->local_port);
	key.dport = skops->remote_port;
	key.family = skops->family;

	bpf_sock_hash_update(skops, &sock_hash, &key, BPF_NOEXIST);
	return 0;
}

static __always_inline void sock_key_from_msg(const struct sk_msg_md *msg, struct sock_key *key)
{
	key->sip = msg->local_ip4;
	key->dip = msg->remote_ip4;
	key->sport = bpf_htonl(msg->local_port);
	key->dport = msg->remote_port;
	key->family = msg->family;
}

static __always_inline void sock_key_from_skb(const struct __sk_buff *skb, struct sock_key *key)
{
	key->sip = skb->local_ip4;
	key->dip = skb->remote_ip4;
	key->sport = bpf_htonl(skb->local_port);
	key->dport = skb->remote_port;
	key->family = skb->family;
}

/* `snapshot` is the original query text (already captured into key_scratch
 * by handle_msg() before try_reroute() got a chance to mutate anything) --
 * always a full, fixed-size copy for the same reason apply_reroute()'s old
 * padding write used one: constant size, no runtime-bounded loop, no
 * verifier fight. */
static __always_inline void emit_request(const struct sock_key *skey, __u32 payload_len,
					  const struct reroute_key *snapshot, __u32 qlen,
					  bool truncated, bool rerouted)
{
	struct corr_event *ce;
	struct pending_req preq;

	preq.req_ts_ns = bpf_ktime_get_ns();
	preq.rerouted = rerouted ? 1 : 0;
	__builtin_memset(preq._pad, 0, sizeof(preq._pad));
	bpf_map_update_elem(&pending_reqs, skey, &preq, BPF_ANY);

	ce = bpf_ringbuf_reserve(&corr_events, sizeof(*ce), 0);
	if (!ce) {
		return;
	}
	ce->ts_ns = preq.req_ts_ns;
	ce->req_ts_ns = preq.req_ts_ns;
	ce->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	ce->tid = (__u32)bpf_get_current_pid_tgid();
	ce->sport = bpf_ntohl(skey->sport);
	ce->dport = bpf_ntohl(skey->dport);
	ce->len = payload_len;
	ce->data_len = qlen;
	ce->kind = CORR_REQUEST;
	ce->rerouted = rerouted ? 1 : 0;
	ce->truncated = truncated ? 1 : 0;
	ce->_pad = 0;
	read_comm(ce->comm, sizeof(ce->comm));
	__builtin_memcpy(ce->data, snapshot->query, sizeof(ce->data));
	bpf_ringbuf_submit(ce, 0);
}

/* Look up the reroute list against the snapshot handle_msg() already
 * captured into key_scratch, and if matched, overwrite the statement text
 * in place with REROUTE_TEXT. By the time this runs, cork already
 * guarantees the entire statement is present and nothing has been
 * transmitted yet, so there is no partial-write safety check needed here
 * the way the tracepoint-based version's `have_before <= qoff` check was. */
static __always_inline bool try_reroute(struct sk_msg_md *msg, const struct reroute_key *snapshot,
					 __u32 qoff, __u32 qlen)
{
	char *data;
	__u32 new_payload_len;

	if (qlen < REROUTE_TEXT_LEN) {
		return false;
	}

	if (!bpf_map_lookup_elem(&reroute_list, snapshot)) {
		return false;
	}

	/* sockmap can actually resize a message -- bpf_probe_write_user()
	 * mutating a syscall's own buffer in place never could, which is why
	 * an earlier version of this mechanism had to pad same-length with
	 * spaces instead. Drop the extra bytes outright: bpf_msg_pop_data()
	 * is a helper call, and helper arguments may be runtime values (only
	 * *direct* in-place access to msg data requires a compile-time-
	 * constant offset/length to verify -- see the memcpy below, and the
	 * dead end this replaced). */
	if (qlen > REROUTE_TEXT_LEN) {
		if (bpf_msg_pop_data(msg, qoff + REROUTE_TEXT_LEN, qlen - REROUTE_TEXT_LEN, 0) !=
		    0) {
			return false;
		}
	}

	/* Write REROUTE_TEXT as a single compile-time-constant-sized copy
	 * (always exactly REROUTE_TEXT_LEN bytes, same content every time)
	 * rather than a runtime-bounded loop. Direct in-place writes into msg
	 * data only verify when the access offset/length are compile-time
	 * constants: a `data + N <= data_end` check for a *runtime* N narrows
	 * a temporary sum register the check computes, not `data` itself, so
	 * a later runtime-indexed `data[i]` loop does not verify even though
	 * the check logically covers it -- confirmed empirically ("invalid
	 * access to packet ... r=0") for exactly that pattern while building
	 * this. A single fixed-size __builtin_memcpy has no such problem, the
	 * same way it didn't for the old bpf_probe_write_user-based mutation
	 * elsewhere in this project's history. */
	if (bpf_msg_pull_data(msg, qoff, qoff + REROUTE_TEXT_LEN, 0) != 0) {
		return false;
	}
	data = msg->data;
	if ((void *)(data + REROUTE_TEXT_LEN) > msg->data_end) {
		return false;
	}
	__builtin_memcpy(data, REROUTE_TEXT, REROUTE_TEXT_LEN);

	/* The packet's own 3-byte length header now overstates the payload:
	 * fix it up to match the shorter statement. new_payload_len counts
	 * the command byte, any CLIENT_QUERY_ATTRIBUTES prefix bytes still
	 * intact before qoff, and REROUTE_TEXT_LEN -- the same accounting
	 * `payload_len`/`want` used for the original statement, just with
	 * REROUTE_TEXT_LEN standing in for the original query length. */
	new_payload_len = (qoff - BASE_HEADER_LEN) + 1 + REROUTE_TEXT_LEN;
	if (bpf_msg_pull_data(msg, 0, BASE_HEADER_LEN, 0) != 0) {
		return false;
	}
	data = msg->data;
	if ((void *)(data + BASE_HEADER_LEN) > msg->data_end) {
		return false;
	}
	data[0] = (char)(new_payload_len & 0xff);
	data[1] = (char)((new_payload_len >> 8) & 0xff);
	data[2] = (char)((new_payload_len >> 16) & 0xff);

	return true;
}

/* sk_msg runs synchronously inside the writing process's own sendmsg()-
 * family syscall (write(), send(), sendto(), sendmsg() all funnel through
 * the same tcp_bpf-installed hook once the socket is in sock_hash), so
 * bpf_get_current_pid_tgid() here is the actual client process -- unlike
 * handle_skb() below. */
SEC("sk_msg")
int handle_msg(struct sk_msg_md *msg)
{
	struct sock_key skey;
	struct reroute_key *snapshot;
	__u8 hdr[BASE_HEADER_LEN];
	char *data;
	__u32 payload_len, want, have, qoff, qlen, target, zero = 0, one = 1;
	bool truncated, rerouted, was_corked;

	sock_key_from_msg(msg, &skey);

	/* Whether *this* statement needed corking at any earlier invocation --
	 * see the mutation-gating comment below for why this matters. Checked
	 * and cleared unconditionally on every invocation (harmless no-op via
	 * bpf_map_delete_elem() if absent), then re-armed by both
	 * bpf_msg_cork_bytes() call sites below before they return early, so
	 * it correctly survives however many rounds of corking a statement
	 * actually needs. */
	was_corked = bpf_map_lookup_elem(&corking, &skey) != NULL;
	bpf_map_delete_elem(&corking, &skey);

	if (msg->size < BASE_HEADER_LEN) {
		bpf_msg_cork_bytes(msg, BASE_HEADER_LEN);
		bpf_map_update_elem(&corking, &skey, &one, BPF_ANY);
		return SK_PASS;
	}

	if (bpf_msg_pull_data(msg, 0, BASE_HEADER_LEN, 0) != 0) {
		return SK_PASS;
	}
	data = msg->data;
	if ((void *)(data + BASE_HEADER_LEN) > msg->data_end) {
		return SK_PASS;
	}
	__builtin_memcpy(hdr, data, BASE_HEADER_LEN);

	if (hdr[3] != 0 || hdr[4] != COM_QUERY) {
		/* Not the start of a COM_QUERY -- nothing to track. No
		 * corking-marker leak either: it was already unconditionally
		 * cleared above. */
		return SK_PASS;
	}

	payload_len = (__u32)hdr[0] | ((__u32)hdr[1] << 8) | ((__u32)hdr[2] << 16);
	want = payload_len + 4;
	if (want < BASE_HEADER_LEN + min_query_len) {
		return SK_PASS;
	}

	truncated = want > MAX_QUERY_LEN - 1;
	if (!truncated && msg->size < want) {
		/* Don't have the whole statement yet. Cork holds the entire
		 * message back in the kernel until `want` bytes are queued,
		 * however many more write()/send() calls that takes -- but see
		 * the mutation-gating comment below: corking is only safe for
		 * *observation*, not for the mutation this function may
		 * otherwise perform. */
		bpf_msg_cork_bytes(msg, want);
		bpf_map_update_elem(&corking, &skey, &one, BPF_ANY);
		return SK_PASS;
	}

	/* Truncated (over MAX_QUERY_LEN): never going to match a reroute-list
	 * entry or need mutation, so act on whatever has arrived so far
	 * rather than waiting for a statement we already know is too long to
	 * route -- avoids corking for a potentially huge `want`. */
	target = truncated ? msg->size : want;
	have = target > MAX_QUERY_LEN - 1 ? MAX_QUERY_LEN - 1 : target;
	have &= MAX_QUERY_LEN - 1;

	if (bpf_msg_pull_data(msg, 0, have, 0) != 0) {
		return SK_PASS;
	}
	data = msg->data;
	if ((void *)(data + have) > msg->data_end) {
		return SK_PASS;
	}

	qoff = parse_query_offset(data, msg->data_end, have);
	qlen = have > qoff ? have - qoff : 0;
	qlen &= MAX_QUERY_LEN - 1;

	/* Snapshot the original query text *before* try_reroute() gets a
	 * chance to mutate anything: try_reroute()'s mutation (via
	 * bpf_msg_pop_data()) shrinks the message, which invalidates any
	 * pulled data pointer and would make a later attempt to re-pull the
	 * original (larger) `have` bytes fail outright -- confirmed
	 * empirically: emit_request() silently never ran for a rerouted
	 * statement before this snapshot was introduced, since the post-
	 * mutation re-pull always failed. Captured once here and reused by
	 * both try_reroute() (as its reroute_list lookup key) and
	 * emit_request() (as the "original statement" it reports), so there
	 * is exactly one copy, not two independently-timed ones. */
	snapshot = bpf_map_lookup_elem(&key_scratch, &zero);
	if (!snapshot) {
		return SK_PASS;
	}
	__builtin_memset(snapshot->query, 0, sizeof(snapshot->query));
	if (qlen) {
		bpf_probe_read_kernel(snapshot->query, qlen, data + qoff);
	}

	/* Mutation is scoped to the single-invocation fast path only:
	 * try_reroute()'s mutation combines bpf_msg_pop_data() (to shrink the
	 * message) with a follow-up direct write to the packet's length
	 * header. For a statement that needed corking to complete -- i.e.
	 * spans more than one underlying write()/send() call -- that
	 * combination was confirmed empirically (verifier accepted it, the
	 * BPF program ran and reported success, but a wire capture showed the
	 * connection then went completely silent: not corrupted, not
	 * delayed, just never transmitted at all) to make the kernel silently
	 * drop the message instead of forwarding the mutated result. A
	 * single-write statement -- the common case -- is unaffected; this
	 * codebase does not currently have an explanation for the corked
	 * case rooted in kernel internals rather than empirical observation,
	 * so the honest fix is to not attempt it: a corked statement is still
	 * fully observed and reported (this is what `was_corked` gates, nowhere
	 * else), just never mutated. */
	rerouted = !truncated && !was_corked && try_reroute(msg, snapshot, qoff, qlen);

	emit_request(&skey, payload_len, snapshot, qlen, truncated, rerouted);

	return SK_PASS;
}

/* sk_skb (BPF_SK_SKB_VERDICT) runs on the receive path as data arrives on
 * the socket -- not inside the reading application's own read()/recvfrom()
 * call, which may happen on a different thread or long afterward. pid/tid
 * reported from here are therefore best-effort only (see corr_event's
 * comment in mysql_reroute.h); the correlation key is the connection's own
 * sock_key, which is accurate. Always returns SK_PASS: this program only
 * ever observes, never redirects. */
SEC("sk_skb")
int handle_skb(struct __sk_buff *skb)
{
	struct sock_key skey;
	struct pending_req *preq;
	struct corr_event *ce;
	__u32 plen;

	sock_key_from_skb(skb, &skey);

	preq = bpf_map_lookup_elem(&pending_reqs, &skey);
	if (!preq) {
		return SK_PASS;
	}

	ce = bpf_ringbuf_reserve(&corr_events, sizeof(*ce), 0);
	if (!ce) {
		bpf_map_delete_elem(&pending_reqs, &skey);
		return SK_PASS;
	}

	plen = skb->len;
	ce->truncated = 0;
	if (plen > 127) {
		plen = 127;
		ce->truncated = 1;
	}
	plen &= MAX_QUERY_LEN - 1;

	ce->ts_ns = bpf_ktime_get_ns();
	ce->req_ts_ns = preq->req_ts_ns;
	ce->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	ce->tid = (__u32)bpf_get_current_pid_tgid();
	ce->sport = bpf_ntohl(skey.sport);
	ce->dport = bpf_ntohl(skey.dport);
	ce->len = skb->len;
	ce->data_len = plen;
	ce->kind = CORR_RESPONSE;
	ce->rerouted = preq->rerouted;
	ce->_pad = 0;
	read_comm(ce->comm, sizeof(ce->comm));

	__builtin_memset(ce->data, 0, sizeof(ce->data));
	if (plen) {
		bpf_skb_load_bytes(skb, 0, ce->data, plen);
	}

	bpf_ringbuf_submit(ce, 0);
	bpf_map_delete_elem(&pending_reqs, &skey);
	return SK_PASS;
}
