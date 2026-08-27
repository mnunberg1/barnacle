// SPDX-License-Identifier: GPL-2.0
/*
 * test_caps.c - which kernel features are actually available here.
 *
 * Nothing is attached and no socket is touched. Programs are loaded and maps
 * are created, then immediately closed, so this is safe to run anywhere with
 * enough privilege to call bpf(2).
 *
 * It exists because architecture.txt commits to several features whose
 * availability we have never checked on the kernel this actually runs on --
 * Docker Desktop's LinuxKit VM, not a distro kernel. Finding out from a
 * two-second probe is cheaper than finding out from a redesign:
 *
 *   BPF arenas         the memory model. Every shared structure is supposed
 *                      to live in one, with real pointers valid in every
 *                      process. Linux 6.9+.
 *   bpf_timer          the LRU sweeper that unsticks dead dpipes.
 *   sk_storage         pipe_sk_info_map, which hangs per-socket state off the
 *                      client's own socket.
 *   msg_redirect_map   dpipe_map is an index-keyed SOCKMAP, so the redirect
 *                      needs the array form, not just the hash form the
 *                      current code uses.
 *
 * Three tiers are reported. REQUIRED is what the code in this tree already
 * depends on; a missing one is a hard failure. DESIGN is what architecture.txt
 * assumes but nothing implements yet; a missing one means the design needs
 * revisiting, and is reported loudly without failing the build. The rest is
 * informational -- worth knowing, nothing depends on it.
 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

/* Spelled numerically rather than by name: an older uapi header will not have
 * the enumerator at all, and a header that cannot name the thing we are
 * probing for is exactly the case this test is here to detect. */
#define MAP_TYPE_ARENA 33

enum tier {
	TIER_REQUIRED, /* current code depends on it */
	TIER_DESIGN,   /* architecture.txt depends on it */
	TIER_INFO,     /* neither, but worth knowing */
};

static int n_required_missing;
static int n_design_missing;

static const char *tier_name(enum tier t)
{
	switch (t) {
	case TIER_REQUIRED:
		return "REQUIRED";
	case TIER_DESIGN:
		return "DESIGN  ";
	default:
		return "info    ";
	}
}

static void report(const char *what, int ok, enum tier tier)
{
	printf("  %-8s %-34s %s\n", tier_name(tier), what, ok ? "yes" : "NO");

	if (ok) {
		return;
	}
	if (tier == TIER_REQUIRED) {
		n_required_missing++;
	} else if (tier == TIER_DESIGN) {
		n_design_missing++;
	}
}

static void probe_prog(const char *what, enum bpf_prog_type type, enum tier tier)
{
	report(what, libbpf_probe_bpf_prog_type(type, NULL) == 1, tier);
}

static void probe_map(const char *what, enum bpf_map_type type, enum tier tier)
{
	report(what, libbpf_probe_bpf_map_type(type, NULL) == 1, tier);
}

static void probe_helper(const char *what, enum bpf_prog_type type, enum bpf_func_id id,
			 enum tier tier)
{
	report(what, libbpf_probe_bpf_helper(type, id, NULL) == 1, tier);
}

/* Arenas do not go through libbpf_probe_bpf_map_type cleanly: they take no
 * key or value, size themselves in pages, and must be mmapable. Create one
 * directly instead. */
static void probe_arena(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE);
	int fd = bpf_map_create((enum bpf_map_type)MAP_TYPE_ARENA, "probe_arena", 0, 0,
				1 /* page */, &opts);

	report("BPF_MAP_TYPE_ARENA (mmapable)", fd >= 0, TIER_DESIGN);
	if (fd >= 0) {
		close(fd);
	}
}

/* A SOCKMAP keyed by a u32 index, which is the shape dpipe_map needs -- the
 * current sock_map is a SOCKHASH keyed by a 5-tuple. Worth probing separately
 * because the redirect helper differs between the two. */
static void probe_sockmap_array(void)
{
	int fd = bpf_map_create(BPF_MAP_TYPE_SOCKMAP, "probe_dpipes", sizeof(__u32),
				sizeof(__u32), 8, NULL);

	report("SOCKMAP, u32-keyed (dpipe_map)", fd >= 0, TIER_DESIGN);
	if (fd >= 0) {
		close(fd);
	}
}

int main(void)
{
	struct utsname u;

	if (uname(&u) == 0) {
		printf("kernel: %s %s (%s)\n\n", u.sysname, u.release, u.machine);
	} else {
		printf("kernel: unknown\n\n");
	}

	/* Quieten libbpf: a probe that fails is a result, not an error, and
	 * the verifier log for a deliberately-rejected program is noise. */
	libbpf_set_print(NULL);

	printf("program types:\n");
	probe_prog("BPF_PROG_TYPE_SOCK_OPS", BPF_PROG_TYPE_SOCK_OPS, TIER_REQUIRED);
	probe_prog("BPF_PROG_TYPE_SK_MSG", BPF_PROG_TYPE_SK_MSG, TIER_REQUIRED);
	probe_prog("BPF_PROG_TYPE_SK_SKB", BPF_PROG_TYPE_SK_SKB, TIER_INFO);

	printf("\nmap types:\n");
	probe_map("BPF_MAP_TYPE_SOCKHASH", BPF_MAP_TYPE_SOCKHASH, TIER_REQUIRED);
	probe_map("BPF_MAP_TYPE_SOCKMAP", BPF_MAP_TYPE_SOCKMAP, TIER_REQUIRED);
	probe_map("BPF_MAP_TYPE_RINGBUF", BPF_MAP_TYPE_RINGBUF, TIER_INFO);
	probe_map("BPF_MAP_TYPE_SK_STORAGE", BPF_MAP_TYPE_SK_STORAGE, TIER_DESIGN);
	probe_sockmap_array();
	probe_arena();

	printf("\nsk_msg helpers:\n");
	probe_helper("bpf_msg_redirect_hash", BPF_PROG_TYPE_SK_MSG,
		     BPF_FUNC_msg_redirect_hash, TIER_REQUIRED);
	probe_helper("bpf_msg_redirect_map", BPF_PROG_TYPE_SK_MSG,
		     BPF_FUNC_msg_redirect_map, TIER_DESIGN);
	probe_helper("bpf_sk_storage_get", BPF_PROG_TYPE_SK_MSG, BPF_FUNC_sk_storage_get,
		     TIER_DESIGN);
	/* If this is available the dpipe pool can collapse to a single daemon
	 * socket: prefix each reply with its target key, pop it in the
	 * verdict program, redirect on what is left. */
	probe_helper("bpf_msg_pop_data", BPF_PROG_TYPE_SK_MSG, BPF_FUNC_msg_pop_data,
		     TIER_INFO);

	/* The receive side. sk_skb can redirect, but it cannot consult
	 * sk_storage -- so anything routed on recv has to find its target some
	 * other way. These are the candidates. */
	printf("\nsk_skb helpers (the recv side):\n");
	probe_helper("bpf_sk_redirect_map", BPF_PROG_TYPE_SK_SKB,
		     BPF_FUNC_sk_redirect_map, TIER_INFO);
	probe_helper("bpf_sk_storage_get  [expect NO]", BPF_PROG_TYPE_SK_SKB,
		     BPF_FUNC_sk_storage_get, TIER_INFO);
	probe_helper("bpf_get_socket_cookie", BPF_PROG_TYPE_SK_SKB,
		     BPF_FUNC_get_socket_cookie, TIER_INFO);
	probe_helper("bpf_skb_pull_data", BPF_PROG_TYPE_SK_SKB, BPF_FUNC_skb_pull_data,
		     TIER_INFO);

	printf("\nsockops helpers:\n");
	probe_helper("bpf_sock_hash_update", BPF_PROG_TYPE_SOCK_OPS,
		     BPF_FUNC_sock_hash_update, TIER_REQUIRED);
	probe_helper("bpf_sock_map_update", BPF_PROG_TYPE_SOCK_OPS,
		     BPF_FUNC_sock_map_update, TIER_DESIGN);
	/* The missing netns discriminator for sock_key. Available here does
	 * not make it usable -- the daemon reads /proc and gets an inode, not
	 * a cookie -- but it settles half the question. */
	probe_helper("bpf_get_netns_cookie", BPF_PROG_TYPE_SOCK_OPS,
		     BPF_FUNC_get_netns_cookie, TIER_INFO);

	printf("\ntimers:\n");
	probe_helper("bpf_timer_init (sched_cls)", BPF_PROG_TYPE_SCHED_CLS,
		     BPF_FUNC_timer_init, TIER_DESIGN);

	printf("\n");
	if (n_design_missing > 0) {
		printf("NOTE: %d feature(s) architecture.txt assumes are unavailable.\n"
		       "      Nothing depends on them yet, so this is not a failure --\n"
		       "      but the design needs revisiting before it does.\n\n",
		       n_design_missing);
	}
	if (n_required_missing > 0) {
		printf("FAIL: %d feature(s) the current code depends on are missing.\n",
		       n_required_missing);
		return 1;
	}
	printf("PASS: everything the current code depends on is available.\n");
	return 0;
}
