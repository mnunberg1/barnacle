#pragma once
/*
 * IDE-indexing stub for libbpf's bpf/bpf_endian.h. Not a functional
 * implementation: declared, never defined, enough for clangd to type-check
 * call sites without a link step. See bpf_helpers.h in this directory for
 * why.
 */
#ifndef VALKEY_EBPF_BPF_ENDIAN_STUB_H
#define VALKEY_EBPF_BPF_ENDIAN_STUB_H

#include "../linux_types_stub.h"

#ifdef __cplusplus
extern "C" {
#endif

__u32 bpf_ntohl(__u32 x);
__u32 bpf_htonl(__u32 x);
__u16 bpf_ntohs(__u16 x);
__u16 bpf_htons(__u16 x);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_EBPF_BPF_ENDIAN_STUB_H */
