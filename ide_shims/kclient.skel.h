#pragma once
/*
 * Stand-in for the skeleton `bpftool gen skeleton build/kclient.bpf.o`
 * generates. The real one embeds the compiled BPF bytecode as a byte array;
 * there is nothing to compile from off Linux.
 *
 * HAND-MAINTAINED. The maps and programs below must mirror
 * src/kclient/kclient.bpf.c exactly -- adding one there and not here means
 * the agent stops parsing in the editor.
 */
#ifndef VALKEY_QCACHE_SHIM_KCLIENT_SKEL_H
#define VALKEY_QCACHE_SHIM_KCLIENT_SKEL_H

#include "bpf/libbpf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct kclient_bpf__maps {
	struct bpf_map *sock_map;   /* SOCKHASH: clients and agent_pipes */
	struct bpf_map *pipe_pairs; /* pipe sock_key -> client sock_key */
	struct bpf_map *cfg;        /* enable flag, target port */
};

struct kclient_bpf__progs {
	struct bpf_program *classify; /* sockops */
	struct bpf_program *redirect; /* sk_msg */
};

struct kclient_bpf {
	struct bpf_object *obj;
	struct kclient_bpf__maps maps;
	struct kclient_bpf__progs progs;
};

struct kclient_bpf *kclient_bpf__open(void);
int kclient_bpf__load(struct kclient_bpf *obj);
struct kclient_bpf *kclient_bpf__open_and_load(void);
int kclient_bpf__attach(struct kclient_bpf *obj);
void kclient_bpf__destroy(struct kclient_bpf *obj);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_QCACHE_SHIM_KCLIENT_SKEL_H */
