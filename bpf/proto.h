/* Shared definitions between the BPF program(s) and their userspace loaders. */
#ifndef __PROTO_H
#define __PROTO_H

/* Must stay a power of two: the BPF side masks copy/accumulate lengths
 * against it so the verifier can prove variable-size reads/writes stay
 * inside a MAX_QUERY_LEN-sized buffer. */
#define MAX_QUERY_LEN 512
#define TASK_COMM_LEN 16

/* MySQL client/server protocol command bytes we care about. */
#define COM_QUERY 0x03
#define COM_STMT_PREPARE 0x16

/* A COM_QUERY packet is normally:
 *   byte 0..2  payload length, seq (4 bytes header total)
 *   byte 4     command (0x03)
 *   byte 5..   query text
 *
 * MySQL 8.0.26+'s CLIENT_QUERY_ATTRIBUTES capability inserts two more bytes
 * here when negotiated -- lenenc-int param_count and param_set_count, each a
 * single byte (0x00, 0x01) in the overwhelmingly common zero-bound-
 * parameters case -- shifting the query text to byte 7. Whether a given
 * connection negotiated this is not something we track (that would mean
 * following the connection from its opening handshake); instead this is a
 * content heuristic: real SQL text never legitimately begins with a NUL
 * byte, so seeing {0x00, 0x01} immediately after the command byte is taken
 * as this prefix and skipped. MAX_HEADER_LEN is the upper bound across both
 * shapes, used to decide whether a reroute mutation is still safe (see
 * mysql_reroute.bpf.c): if more than this many bytes of a packet were
 * already sent in an earlier write() call, some real query text must have
 * gone out already, and mutating a later call can no longer take it back.
 */
#define BASE_HEADER_LEN 5
#define QUERY_ATTR_LEN 2
#define MAX_HEADER_LEN (BASE_HEADER_LEN + QUERY_ATTR_LEN)

/* Identifies a TCP connection for both sockmap membership (the SOCKHASH key)
 * and request/response correlation (the pending_reqs key). This is the
 * *kernel's own* socket identity, available identically from sock_ops (at
 * connect time), sk_msg (on send), and sk_skb (on receive) program context --
 * unlike a (pid_tgid, fd) pair, it needs no separate bookkeeping to stay
 * valid across those three different hook points, and isn't vulnerable to fd
 * reuse. IPv4 only, matching the rest of this project's demo scope. Field
 * naming/byte-order convention (sport/dport, local_port host order requiring
 * bpf_htonl(), remote_port already network order) matches common sockmap
 * example code so it's recognizable, not just internal consistency. */
struct sock_key {
	__u32 sip;
	__u32 dip;
	__u32 sport;
	__u32 dport;
	__u32 family;
};

#endif /* __PROTO_H */
