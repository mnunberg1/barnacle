#pragma once
/*
 * IDE-indexing stub. The BPF programs include the real bpf_tracing.h
 * conventionally but does not name anything from it. bpf/mysql_reroute.bpf.c
 * does, though: BPF_UPROBE/BPF_URETPROBE, replicated here closely enough for
 * clangd to parse call sites (the real macro also captures `ctx` and derives
 * argument types from `struct pt_regs`; this stub just needs matching
 * *signatures*, not the real PT_REGS_PARMn extraction). See bpf_helpers.h in
 * this directory for why this tree exists at all.
 */
#ifndef VALKEY_EBPF_BPF_TRACING_STUB_H
#define VALKEY_EBPF_BPF_TRACING_STUB_H

struct pt_regs; /* opaque; the stub helpers below never dereference it */

#define BPF_UPROBE(name, args...) name(struct pt_regs *ctx, ##args)
#define BPF_URETPROBE(name, args...) name(struct pt_regs *ctx, ##args)

#endif /* VALKEY_EBPF_BPF_TRACING_STUB_H */
