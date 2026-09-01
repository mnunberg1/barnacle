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
#ifndef BNCL_SHIM_KCLIENT_SKEL_H
#define BNCL_SHIM_KCLIENT_SKEL_H

#include "bpf/libbpf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct kclient_bpf__maps {
        struct bpf_map *dpipe_map;       /* SOCKMAP: daemon-side dpipes */
        struct bpf_map *cpipe_map; /* SOCKMAP: hijacked client sockets */
        struct bpf_map *pipe_sk_info_map;  /* SK_STORAGE: peer index, opposite map */
        struct bpf_map *dpipe_freelist;  /* ARRAY: available dpipe indices */
        struct bpf_map *dpipes_meta_map; /* ARRAY[1]: serial, num_free */
        struct bpf_map *dpipes;          /* ARRAY: the dpipe records */
        struct bpf_map *arena;           /* ARENA: stmt text and payloads */
        struct bpf_map *stmts_map;       /* HASH: stmt_key -> stmt_ref */
        struct bpf_map *cfg;             /* enable flag, target port, TTLs */
};

struct kclient_bpf__progs {
        /* Which map each is attached to is how it knows its direction; sk_msg
         * cannot tell from the context. */
        struct bpf_program *splice_c2d; /* sk_msg, on cpipe_map */
        struct bpf_program *splice_d2c; /* sk_msg, on dpipe_map */
};

struct kclient_bpf {
        struct bpf_object *obj;
        struct kclient_bpf__maps maps;
        struct kclient_bpf__progs progs;
};

struct kclient_bpf *kclient_bpf__open(void);
/* The opts form is what sets pin_root_path, which is how the maps land under
 * BNCL_PIN_DIR instead of bpffs's root. */
struct kclient_bpf *kclient_bpf__open_opts(const struct bpf_object_open_opts *opts);
int kclient_bpf__load(struct kclient_bpf *obj);
struct kclient_bpf *kclient_bpf__open_and_load(void);
int kclient_bpf__attach(struct kclient_bpf *obj);
void kclient_bpf__destroy(struct kclient_bpf *obj);

#ifdef __cplusplus
}
#endif

#endif /* BNCL_SHIM_KCLIENT_SKEL_H */
