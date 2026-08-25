// SPDX-License-Identifier: GPL-2.0
/*
 * uclient_loader.c - loads the UCLIENT probe under bpftime.
 *
 * Run as:  bpftime load ./uclient_loader "<statement>" <reply-file>
 *
 * bpftime's syscall-server intercepts the BPF syscalls this makes and keeps
 * the programs and maps in shared memory. A separate `bpftime attach <PID>`
 * then injects the agent into an ALREADY-RUNNING process, which picks the
 * programs up from that shared memory and patches SSL_read/SSL_write in
 * place.
 *
 * That is the property LD_PRELOAD cannot provide: it only takes effect if the
 * environment variable was set before exec, so it can never attach to a
 * process that is already up and serving traffic.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "attach_override.h"
#include "uclient_probe.skel.h"

/* Where libssl lives. bpf_prog_attach_uprobe_with_override() resolves the
 * symbol out of this file rather than taking a SEC() string. */
#ifndef LIBSSL_PATH
#define LIBSSL_PATH "/usr/lib/aarch64-linux-gnu/libssl.so.3"
#endif

#define MAX_PAYLOAD 512

struct config {
	__u32 query_len;
	__u32 reply_len;
	char query[MAX_PAYLOAD];
	char reply[MAX_PAYLOAD];
};

static volatile sig_atomic_t exiting;

static void on_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

int main(int argc, char **argv)
{
	struct uclient_probe_bpf *skel;
	struct config cfg = {};
	__u32 zero = 0;
	FILE *f;
	size_t n;

	if (argc < 3) {
		fprintf(stderr,
			"usage: bpftime load %s \"<statement>\" <reply-file>\n",
			argv[0]);
		return 1;
	}

	n = strlen(argv[1]);
	if (n == 0 || n > MAX_PAYLOAD - 8) {
		fprintf(stderr, "statement length out of range\n");
		return 1;
	}
	cfg.query_len = (__u32)n;
	memcpy(cfg.query, argv[1], n);

	f = fopen(argv[2], "rb");
	if (!f) {
		fprintf(stderr, "cannot open %s: %s\n", argv[2], strerror(errno));
		return 1;
	}
	n = fread(cfg.reply, 1, MAX_PAYLOAD, f);
	fclose(f);
	if (n == 0) {
		fprintf(stderr, "%s is empty\n", argv[2]);
		return 1;
	}
	cfg.reply_len = (__u32)n;

	skel = uclient_probe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "open_and_load failed: %s\n", strerror(errno));
		return 1;
	}

	if (bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &zero, &cfg, BPF_ANY)) {
		fprintf(stderr, "cfg update failed: %s\n", strerror(errno));
		uclient_probe_bpf__destroy(skel);
		return 1;
	}

	/* NOT uclient_probe_bpf__attach(): the generic attach installs plain
	 * uprobes, and bpf_override_return() from one of those throws and
	 * aborts the target process. BPF_TYPE_UPROBE_OVERRIDE installs a Frida
	 * replacement whose handler sets the override callback and runs the
	 * program as a filter -- which is what makes suppression and injection
	 * possible at all. */
	struct {
		struct bpf_program *prog;
		const char *sym;
	} filters[] = {
		{ skel->progs.filter_ssl_write, "SSL_write" },
		{ skel->progs.filter_ssl_write_ex, "SSL_write_ex" },
		{ skel->progs.filter_ssl_read, "SSL_read" },
		{ skel->progs.filter_ssl_read_ex, "SSL_read_ex" },
	};

	for (size_t i = 0; i < sizeof(filters) / sizeof(filters[0]); i++) {
		if (bpf_prog_attach_uprobe_with_override(
			    bpf_program__fd(filters[i].prog), LIBSSL_PATH,
			    filters[i].sym)) {
			fprintf(stderr, "attach %s failed: %s\n", filters[i].sym,
				strerror(errno));
			uclient_probe_bpf__destroy(skel);
			return 1;
		}
		fprintf(stderr, "uclient: override-attached %s\n", filters[i].sym);
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	fprintf(stderr,
		"uclient: loaded. statement=%u bytes, reply=%u bytes.\n"
		"uclient: now run:  bpftime attach <PID>\n",
		cfg.query_len, cfg.reply_len);

	while (!exiting) {
		__u64 seen = 0, suppressed = 0, injected = 0;
		__u32 k;

		k = 0;
		bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &k, &seen);
		k = 1;
		bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &k, &suppressed);
		k = 2;
		bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &k, &injected);

		fprintf(stderr, "uclient: writes_seen=%llu suppressed=%llu injected=%llu\n",
			(unsigned long long)seen, (unsigned long long)suppressed,
			(unsigned long long)injected);
		sleep(1);
	}

	uclient_probe_bpf__destroy(skel);
	return 0;
}
