#pragma once
/*
 * IDE-indexing stub for the *generated* mysql_reroute.skel.h. The real one
 * is produced by `bpftool gen skeleton` from the compiled
 * bpf/mysql_reroute.bpf.o (see Makefile / CMakeLists.txt) -- there is
 * nothing to generate on a non-Linux host, so this stub only mirrors the
 * struct shape and function signatures src/agent.cpp actually
 * references, enough for clangd to type-check it. Declarations only, no
 * bodies; see bpf/bpf_helpers.h in this directory for why.
 */
#ifndef VALKEY_EBPF_MYSQL_REROUTE_SKEL_STUB_H
#define VALKEY_EBPF_MYSQL_REROUTE_SKEL_STUB_H

#include "linux_types_stub.h"
#include "bpf/libbpf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mysql_reroute_bpf__rodata {
	__u32 targ_pid;
	__u32 targ_port;
	__u32 min_query_len;
};

struct mysql_reroute_bpf__maps {
	struct bpf_map *corr_events;
	struct bpf_map *reroute_list;
	struct bpf_map *sock_hash;
};

/* classify()/handle_msg()/handle_skb() all need explicit, non-skeleton-
 * generic attachment (see agent.cpp's own comment) -- there is no
 * mysql_reroute_bpf__attach() to declare here anymore. */
struct mysql_reroute_bpf__progs {
	struct bpf_program *classify;
	struct bpf_program *handle_msg;
	struct bpf_program *handle_skb;
};

struct mysql_reroute_bpf {
	struct mysql_reroute_bpf__maps maps;
	struct mysql_reroute_bpf__progs progs;
	struct mysql_reroute_bpf__rodata *rodata;
};

struct mysql_reroute_bpf *mysql_reroute_bpf__open(void);
int mysql_reroute_bpf__load(struct mysql_reroute_bpf *obj);
void mysql_reroute_bpf__destroy(struct mysql_reroute_bpf *obj);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_EBPF_MYSQL_REROUTE_SKEL_STUB_H */
