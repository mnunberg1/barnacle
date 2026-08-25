#pragma once
/*
 * Stand-in for the skeleton generated from src/uclient/uclient.bpf.c.
 *
 * HAND-MAINTAINED; must mirror that file's maps and programs.
 *
 * Note there is no uclient_bpf__attach() declared. That is deliberate: the
 * generic skeleton attach installs plain uprobes, and bpf_override_return()
 * from one of those aborts the target process. The loader must use
 * bpf_prog_attach_uprobe_with_override() instead -- see attach_override.h.
 */
#ifndef VALKEY_QCACHE_SHIM_UCLIENT_SKEL_H
#define VALKEY_QCACHE_SHIM_UCLIENT_SKEL_H

#include "bpf/libbpf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct uclient_bpf__maps {
	struct bpf_map *cfg;     /* statement to match, reply to inject */
	struct bpf_map *stats;   /* writes seen / suppressed / injected */
	struct bpf_map *armed;   /* pid_tgid -> owes a fabricated response */
	struct bpf_map *scratch; /* per-CPU compare buffer */
};

struct uclient_bpf__progs {
	struct bpf_program *filter_ssl_write;
	struct bpf_program *filter_ssl_write_ex;
	struct bpf_program *filter_ssl_read;
	struct bpf_program *filter_ssl_read_ex;
};

struct uclient_bpf {
	struct bpf_object *obj;
	struct uclient_bpf__maps maps;
	struct uclient_bpf__progs progs;
};

struct uclient_bpf *uclient_bpf__open(void);
int uclient_bpf__load(struct uclient_bpf *obj);
struct uclient_bpf *uclient_bpf__open_and_load(void);
void uclient_bpf__destroy(struct uclient_bpf *obj);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_QCACHE_SHIM_UCLIENT_SKEL_H */
