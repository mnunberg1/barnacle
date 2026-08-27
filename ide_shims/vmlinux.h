#pragma once
/*
 * Stand-in for vmlinux.h, which `bpftool btf dump file /sys/kernel/btf/vmlinux
 * format c` generates from the *running kernel's* BTF at build time. There is
 * no kernel to dump on a workstation, so only the handful of types this
 * project names are declared here.
 *
 * Structs are truncated to the fields the code actually reads. The real ones
 * carry many more, and offsets here mean nothing -- these exist so an editor
 * can resolve `ops->remote_port` and `msg->data_end`, not to describe kernel
 * memory layout.
 */
#ifndef VALKEY_QCACHE_SHIM_VMLINUX_H
#define VALKEY_QCACHE_SHIM_VMLINUX_H

/* The real generated vmlinux.h defines this; headers shared with userspace
 * test it to avoid pulling in <linux/types.h> on top of these typedefs. */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t __u8;
typedef int8_t __s8;
typedef uint16_t __u16;
typedef int16_t __s16;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef uint64_t __u64;
typedef int64_t __s64;

typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

/* sock_ops context. `local_port` is host byte order while `remote_port` is
 * network order -- the asymmetry is real, and is why the code calls
 * bpf_htonl() on one and not the other. */
struct bpf_sock_ops {
	__u32 op;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_port;
	__u32 local_port;
};

/* sk_msg context. data/data_end bracket the readable window, which only
 * covers what bpf_msg_pull_data() has pulled in. */
struct bpf_sock;

struct sk_msg_md {
	void *data;
	void *data_end;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_port;
	__u32 local_port;
	__u32 size;
	/* The socket this message is being sent on. Reaching sk_storage
	 * through it is how a socket names its own splice peer, rather than
	 * being looked up by a key computed from outside. */
	struct bpf_sock *sk;
};

/* One word in the real thing too. Embedded in a map value to serialise
 * writers; the verifier enforces the locking rules around it. */
struct bpf_spin_lock {
	__u32 val;
};

struct __sk_buff {
	__u32 len;
	__u32 data;
	__u32 data_end;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_port;
	__u32 local_port;
};

/* Opaque here. The uclient probes only ever pass it to PT_REGS_PARM*(). */
struct pt_regs;

struct task_struct {
	char comm[16];
};

enum sk_action {
	SK_DROP = 0,
	SK_PASS = 1,
};

/* Real UAPI values. */
enum {
	BPF_SOCK_OPS_VOID = 0,
	BPF_SOCK_OPS_TIMEOUT_INIT = 1,
	BPF_SOCK_OPS_RWND_INIT = 2,
	BPF_SOCK_OPS_TCP_CONNECT_CB = 3,
	BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB = 4,
	BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB = 5,
};

#endif /* VALKEY_QCACHE_SHIM_VMLINUX_H */
