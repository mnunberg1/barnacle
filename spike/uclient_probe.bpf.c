// SPDX-License-Identifier: GPL-2.0
/*
 * uclient_probe.bpf.c - UCLIENT under bpftime, attached to a LIVE process.
 *
 * LD_PRELOAD cannot attach to a process that is already running; it only
 * takes effect if the variable was set before exec. bpftime patches function
 * entry points by address at runtime, so `bpftime attach <PID>` works against
 * an application that is already up and serving traffic. That is the
 * deployment model this project needs.
 *
 * --- why every probe here is an ENTRY filter, and there are no uretprobes --
 *
 * bpf_override_return() only works when the program was attached with
 * BPF_TYPE_UPROBE_OVERRIDE. That attach type installs a Frida *replacement*
 * whose handler sets the thread-local override callback, runs this program as
 * a filter, and then either returns our value or calls the real function.
 *
 * A plain uprobe goes through Frida's ordinary enter/leave listeners, which
 * never set that callback -- calling bpf_override_return() from one throws
 * std::invalid_argument and aborts the target process. Learned the hard way:
 * it killed a running client mid-query.
 *
 * A uretprobe cannot override either, for the same reason. That rules out the
 * obvious "capture the buffer at entry, fill it at return" shape -- but it
 * turns out not to matter, because at SSL_read ENTRY we already have both the
 * destination buffer and its size as arguments. So the read filter fills the
 * caller's buffer and overrides the return directly, and the real SSL_read
 * never runs at all.
 *
 * Args come from pt_regs via PT_REGS_PARM*, and the signature is the plain
 * `struct pt_regs *ctx` form used by bpftime's own working examples rather
 * than the BPF_UPROBE() macro.
 */
#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_PAYLOAD 512
#define COM_QUERY 0x03

struct config {
	__u32 query_len;
	__u32 reply_len;
	char query[MAX_PAYLOAD];
	char reply[MAX_PAYLOAD];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} cfg SEC(".maps");

enum stat_slot {
	STAT_WRITE_SEEN = 0,
	STAT_WRITE_SUPPRESSED = 1,
	STAT_READ_INJECTED = 2,
	STAT__N = 3,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, STAT__N);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* Set when a write was suppressed, so the next read on that thread knows it
 * owes the caller a fabricated response. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64); /* pid_tgid */
	__type(value, __u64);
} armed SEC(".maps");

/* A 512-byte local blows the BPF stack budget outright. Per-CPU scratch is
 * the established way around it. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} scratch SEC(".maps");

static __always_inline void bump(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);

	if (v) {
		__sync_fetch_and_add(v, 1);
	}
}

/* Is this buffer a COM_QUERY whose text matches the configured statement? */
static __always_inline int matches(const void *buf, __u64 num)
{
	__u32 zero = 0;
	struct config *c = bpf_map_lookup_elem(&cfg, &zero);
	struct config *tmp = bpf_map_lookup_elem(&scratch, &zero);
	char *local;
	__u32 qlen;

	if (!c || !tmp) {
		return 0;
	}
	qlen = c->query_len;
	if (qlen == 0 || qlen > MAX_PAYLOAD - 8) {
		return 0;
	}
	/* 4-byte header + command byte + text */
	if (num != (__u64)qlen + 5) {
		return 0;
	}
	local = tmp->query;
	if (bpf_probe_read_user(local, (qlen + 5) & (MAX_PAYLOAD - 1), buf) != 0) {
		return 0;
	}
	if (local[4] != COM_QUERY) {
		return 0;
	}
	for (__u32 i = 0; i < MAX_PAYLOAD - 8; i++) {
		if (i >= qlen) {
			break;
		}
		if (local[5 + i] != c->query[i]) {
			return 0;
		}
	}
	return 1;
}

/* --- write side: suppress a matching query ------------------------------- */

SEC("uprobe/libssl.so.3:SSL_write")
int filter_ssl_write(struct pt_regs *ctx)
{
	const void *buf = (const void *)PT_REGS_PARM2(ctx);
	__u64 num = (__u64)PT_REGS_PARM3(ctx);
	__u64 id = bpf_get_current_pid_tgid();
	__u64 one = 1;

	if ((__s64)num <= 0) {
		return 0;
	}
	bump(STAT_WRITE_SEEN);
	if (!matches(buf, num)) {
		return 0;
	}

	/* Tell the caller every byte was sent. The real SSL_write never runs,
	 * so the query does not reach the server. */
	bpf_map_update_elem(&armed, &id, &one, BPF_ANY);
	bump(STAT_WRITE_SUPPRESSED);
	bpf_override_return(ctx, num);
	return 0;
}

/* CPython's _ssl imports only the _ex variants; the mysql CLI imports only
 * the classic pair. Both families must be covered or entire classes of client
 * are silently missed. The _ex forms return 1/0 and report the count through
 * an out-parameter, so that pointer has to be written too. */
SEC("uprobe/libssl.so.3:SSL_write_ex")
int filter_ssl_write_ex(struct pt_regs *ctx)
{
	const void *buf = (const void *)PT_REGS_PARM2(ctx);
	__u64 num = (__u64)PT_REGS_PARM3(ctx);
	__u64 *written = (__u64 *)PT_REGS_PARM4(ctx);
	__u64 id = bpf_get_current_pid_tgid();
	__u64 one = 1;

	if (num == 0) {
		return 0;
	}
	bump(STAT_WRITE_SEEN);
	if (!matches(buf, num)) {
		return 0;
	}

	if (written) {
		bpf_probe_write_user(written, &num, sizeof(num));
	}
	bpf_map_update_elem(&armed, &id, &one, BPF_ANY);
	bump(STAT_WRITE_SUPPRESSED);
	bpf_override_return(ctx, 1); /* 1 == success */
	return 0;
}

/* --- read side: hand back the response ----------------------------------- */

SEC("uprobe/libssl.so.3:SSL_read")
int filter_ssl_read(struct pt_regs *ctx)
{
	void *buf = (void *)PT_REGS_PARM2(ctx);
	__u64 cap = (__u64)PT_REGS_PARM3(ctx);
	__u64 id = bpf_get_current_pid_tgid();
	__u32 zero = 0;
	struct config *c;
	__u32 n;

	if (!bpf_map_lookup_elem(&armed, &id)) {
		return 0;
	}
	c = bpf_map_lookup_elem(&cfg, &zero);
	if (!c) {
		return 0;
	}
	n = c->reply_len;
	if (n == 0 || n > MAX_PAYLOAD || (__u64)n > cap) {
		return 0;
	}
	if (bpf_probe_write_user(buf, c->reply, n) != 0) {
		return 0;
	}
	bpf_map_delete_elem(&armed, &id);
	bump(STAT_READ_INJECTED);
	bpf_override_return(ctx, n);
	return 0;
}

SEC("uprobe/libssl.so.3:SSL_read_ex")
int filter_ssl_read_ex(struct pt_regs *ctx)
{
	void *buf = (void *)PT_REGS_PARM2(ctx);
	__u64 cap = (__u64)PT_REGS_PARM3(ctx);
	__u64 *readbytes = (__u64 *)PT_REGS_PARM4(ctx);
	__u64 id = bpf_get_current_pid_tgid();
	__u32 zero = 0;
	struct config *c;
	__u64 n64;
	__u32 n;

	if (!bpf_map_lookup_elem(&armed, &id)) {
		return 0;
	}
	c = bpf_map_lookup_elem(&cfg, &zero);
	if (!c) {
		return 0;
	}
	n = c->reply_len;
	if (n == 0 || n > MAX_PAYLOAD || (__u64)n > cap) {
		return 0;
	}
	if (bpf_probe_write_user(buf, c->reply, n) != 0) {
		return 0;
	}
	n64 = n;
	if (readbytes) {
		bpf_probe_write_user(readbytes, &n64, sizeof(n64));
	}
	bpf_map_delete_elem(&armed, &id);
	bump(STAT_READ_INJECTED);
	bpf_override_return(ctx, 1);
	return 0;
}
