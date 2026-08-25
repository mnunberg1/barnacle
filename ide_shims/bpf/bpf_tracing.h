#pragma once
/*
 * Stand-in for libbpf's bpf/bpf_tracing.h: argument access for uprobes.
 *
 * On a real target PT_REGS_PARM* expand to architecture-specific register
 * reads out of pt_regs -- x0..x4 on arm64, rdi/rsi/rdx/rcx/r8 on x86_64.
 * There is no meaningful stand-in for that off-target, so these are declared
 * as functions returning an integer wide enough to hold a pointer. Call sites
 * type-check; the values are fiction.
 */
#ifndef VALKEY_QCACHE_SHIM_BPF_TRACING_H
#define VALKEY_QCACHE_SHIM_BPF_TRACING_H

#include "../vmlinux.h"

#ifdef __cplusplus
extern "C" {
#endif

__u64 __shim_pt_regs_param(const struct pt_regs *ctx, int n);

#define PT_REGS_PARM1(ctx) __shim_pt_regs_param((ctx), 1)
#define PT_REGS_PARM2(ctx) __shim_pt_regs_param((ctx), 2)
#define PT_REGS_PARM3(ctx) __shim_pt_regs_param((ctx), 3)
#define PT_REGS_PARM4(ctx) __shim_pt_regs_param((ctx), 4)
#define PT_REGS_PARM5(ctx) __shim_pt_regs_param((ctx), 5)
#define PT_REGS_RC(ctx)    __shim_pt_regs_param((ctx), 0)
#define PT_REGS_IP(ctx)    __shim_pt_regs_param((ctx), 0)

/*
 * The real BPF_UPROBE/BPF_URETPROBE macros generate a wrapper that unpacks
 * pt_regs into named arguments. This project does not use them -- the probes
 * take `struct pt_regs *ctx` directly and call PT_REGS_PARM* by hand, because
 * bpftime's own working examples do it that way and the macro form did not
 * fire. Kept only so the names resolve if someone reaches for them.
 */
#define BPF_UPROBE(name, args...) name(struct pt_regs *ctx)
#define BPF_URETPROBE(name, args...) name(struct pt_regs *ctx)
#define BPF_KPROBE(name, args...) name(struct pt_regs *ctx)

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_QCACHE_SHIM_BPF_TRACING_H */
