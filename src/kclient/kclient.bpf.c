// SPDX-License-Identifier: GPL-2.0
/*
 * kclient.bpf.c - KCLIENT: the socket splice.
 *
 * KCLIENT is deliberately small. Everything that needs to parse a protocol,
 * assemble a buffer, or know what a statement means lives in UCLIENT, where
 * there is real application context and no verifier. What is left here is the
 * one thing only the kernel can do: move bytes between two sockets that
 * belong to different processes.
 *
 * --- what a splice is -----------------------------------------------------
 *
 * A hijacked MySQL connection has its remote end replaced by a dpipe the
 * daemon holds. While spliced, that socket carries no MySQL traffic at all --
 * it is a control and notification channel between the client and the daemon,
 * and the response payload itself never travels over it. It lives in the
 * arena, which both sides can already see.
 *
 * Using the client's own socket for this, rather than some side channel, is
 * what makes the wakeup work. The client is already waiting on that fd. A
 * blocking client is in recv(); an event-loop client is in epoll_wait(). Both
 * wake for exactly the same reason a real server response would wake them,
 * and neither needs to know anything happened.
 *
 * --- how a socket names its peer ------------------------------------------
 *
 * Both maps are SOCKMAPs indexed by a plain __u32, and each socket carries
 * its pairing in its own sk_storage. So the redirect never names a socket
 * from outside: it asks the socket it is already running on which index to
 * deliver to.
 *
 * There is no 5-tuple anywhere, on purpose. A 5-tuple is a second, derived
 * copy of an identity the kernel already holds -- it must be computed
 * identically by BPF and userspace, which encode ports differently; it has no
 * netns discriminator, so two containers collide; and it can go stale against
 * the socket it names.
 *
 * --- why there are two programs -------------------------------------------
 *
 * BPF_SK_MSG_VERDICT attaches per-map, and a socket runs the program of the
 * map it belongs to. A cpipe must redirect into dpipe_map and a dpipe into
 * cpipe_map, so they cannot be one program. Attaching only one is a
 * silent no-op in the other direction.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "common/defs.h"

char LICENSE[] SEC("license") = "GPL";

/* --- the splice maps ------------------------------------------------------
 *
 * Pinned by name so the other side can reach them. The daemon creates them;
 * UCLIENT's loader opens the pins, because the client process registers its
 * own socket -- it owns that descriptor and the daemon does not.
 */

/*
 * Two maps, one per side, and that separation is what carries direction.
 *
 * They exist rather than routing on ingress and egress of a single map
 * because ingress and egress are not symmetrical in capability: routing on
 * egress is the easier side. Concretely, sk_msg fires only on sendmsg -- no
 * ingress invocation, and sk_msg_md carries no `op` field the way sock_ops
 * does -- so a program cannot ask the context which side it is on. What it
 * can know is which map it was attached to.
 *
 * The receive side is not equivalent. An sk_skb stream verdict can redirect,
 * but it cannot call bpf_sk_storage_get or bpf_sk_fullsock at all: both are
 * refused by program type before the arguments are even checked. It would
 * have to identify the socket by cookie and carry the pairing in a separate
 * hash.
 *
 * Since the target of bpf_msg_redirect_map is a compile-time reference
 * anyway, encoding the side in the attach costs nothing and needs no runtime
 * state.
 */

/* Daemon-side dpipe sockets, keyed by dpipes_meta.serial. */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, QC_MAX_PIPES);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpipe_map SEC(".maps");

/* Hijacked client DB sockets. */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, QC_MAX_PIPES);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cpipe_map SEC(".maps");

/* Which index in the opposite map this socket is spliced to. Attached to the
 * socket, so it is freed with it and can never outlive what it points at. */
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct pipe_sk_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} pipe_sk_info_map SEC(".maps");

/* --- the pool ------------------------------------------------------------
 *
 * The daemon builds dpipes and publishes them here; the client pops one when
 * it decides to intercept a statement. Both sides write, so num_free moves
 * under an atomic and a pop that loses the race simply passes the query
 * through -- exhaustion must never block a client.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, QC_MAX_PIPES);
	__type(key, __u32);
	__type(value, __u32); /* index into dpipe_map */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpipe_freelist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dpipes_meta);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpipes_meta_map SEC(".maps");

/* The dpipe records themselves, indexed the same way as dpipe_map.
 *
 * Mostly daemon-side data -- the two descriptors mean nothing to anyone else
 * -- but the client writes `stmt` when it takes a pipe, which is how the
 * daemon learns what to resolve without the message carrying anything but a
 * key. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, QC_MAX_PIPES);
	__type(key, __u32);
	__type(value, struct dpipe);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpipes SEC(".maps");

/* --- the arena -----------------------------------------------------------
 *
 * Statement text and cached response bodies live here. Mapped at the same
 * fixed address in every process, so the pointers in struct stmt are
 * meaningful everywhere rather than only to whoever wrote them.
 *
 * This is also what keeps result sets off the wire: a client reads a cached
 * response straight out of the arena instead of having it copied through the
 * control socket.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, QC_ARENA_PAGES);
	__ulong(map_extra, QC_ARENA_VA);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} arena SEC(".maps");

/* --- the statement table -------------------------------------------------
 *
 * Every cacheable statement, keyed by exact text. Shared by the daemon and,
 * through the pin, by anything else that needs to see cache state.
 *
 * stmt_data points into the arena, so a cached response is never copied
 * through a socket: the client reads the bytes where they already are.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, QC_MAX_STMTS);
	__type(key, struct stmt_key);
	__type(value, stmt_ref); /* arena address; the record itself is there */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} stmts_map SEC(".maps");

/* Runtime configuration. An array rather than .rodata so the daemon can flip
 * the enable flag and change the target port without reloading. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, QC_CFG__N);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cfg SEC(".maps");

static __always_inline __u32 cfg_get(__u32 slot)
{
	__u32 *v = bpf_map_lookup_elem(&cfg, &slot);

	return v ? *v : 0;
}

/*
 * Client -> daemon. Attached to cpipe_map.
 *
 * A socket with no pairing is not hijacked and passes straight through --
 * that check is the only thing between this program and every socket in the
 * map, so it comes first and fails closed.
 *
 * BPF_F_INGRESS delivers into the dpipe's RECEIVE queue, which is the end the
 * daemon reads.
 */
SEC("sk_msg")
int splice_c2d(struct sk_msg_md *msg)
{
	struct pipe_sk_info *info;

	if (!cfg_get(QC_CFG_ENABLED)) {
		return SK_PASS;
	}
	if (!msg->sk) {
		return SK_PASS;
	}
	info = bpf_sk_storage_get(&pipe_sk_info_map, msg->sk, NULL, 0);
	if (!info || !info->paired) {
		return SK_PASS;
	}
	return bpf_msg_redirect_map(msg, &dpipe_map, info->peer_key, BPF_F_INGRESS);
}

/*
 * Daemon -> client. Attached to dpipe_map.
 *
 * This is the direction that wakes a client parked in epoll_wait():
 * BPF_F_INGRESS puts the bytes in the client socket's receive queue, so they
 * look like they arrived from the network. Without the flag they would go out
 * of the client's own wire toward the database, which is precisely what must
 * not happen.
 */
SEC("sk_msg")
int splice_d2c(struct sk_msg_md *msg)
{
	struct pipe_sk_info *info;

	if (!cfg_get(QC_CFG_ENABLED)) {
		return SK_PASS;
	}
	if (!msg->sk) {
		return SK_PASS;
	}
	info = bpf_sk_storage_get(&pipe_sk_info_map, msg->sk, NULL, 0);
	if (!info || !info->paired) {
		return SK_PASS;
	}
	return bpf_msg_redirect_map(msg, &cpipe_map, info->peer_key,
				    BPF_F_INGRESS);
}
