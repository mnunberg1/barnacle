#pragma once
/*
 * Stand-in for the real vmlinux.h, which `bpftool btf dump` generates from
 * the *target kernel's own BTF* at build time (see Makefile / CMakeLists.txt)
 * -- there is nothing to generate that from on a non-Linux host. Only the
 * handful of types the BPF programs here actually name are declared here.
 * IDE-indexing stub only; see linux_types_stub.h.
 */
#ifndef VALKEY_EBPF_VMLINUX_STUB_H
#define VALKEY_EBPF_VMLINUX_STUB_H

#include "linux_types_stub.h"

struct trace_event_raw_sys_enter {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long id;
	unsigned long args[6];
};

struct trace_event_raw_sys_exit {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long id;
	long ret;
};

/* Only the fields mysql_reroute.bpf.c actually reads are declared below;
 * the real structs (generated from the target kernel's own BTF) have many
 * more. */

struct bpf_sock_ops {
	__u32 op;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_port;
	__u32 local_port;
};

struct sk_msg_md {
	void *data;
	void *data_end;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_port;
	__u32 local_port;
	__u32 size;
};

/* __sk_buff's data/data_end are __u32 (not pointers) in the real kernel
 * struct -- this program reads skb->len/remote_ip4/etc directly and uses
 * bpf_skb_load_bytes() rather than dereferencing data/data_end itself, so
 * that distinction does not matter here. */
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

struct task_struct {
	char comm[16];
};

enum sk_action {
	SK_DROP = 0,
	SK_PASS = 1,
};

/* Real value from the kernel's bpf_sock_ops_cb_flags-adjacent enum
 * (BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB); only the one this program's
 * classify() actually checks against is declared. */
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 4

#endif /* VALKEY_EBPF_VMLINUX_STUB_H */
