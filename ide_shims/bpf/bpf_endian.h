#pragma once
/*
 * Stand-in for libbpf's bpf/bpf_endian.h.
 *
 * Worth knowing when reading the sockmap code: these operate on 32-bit
 * quantities, so bpf_htonl(3306) is 0xEA0C0000 -- NOT the 0x0000EA0C you get
 * from a 16-bit sockaddr_in::sin_port. Mixing the two produces sock_keys that
 * never match and a redirect that silently does nothing.
 */
#ifndef VALKEY_QCACHE_SHIM_BPF_ENDIAN_H
#define VALKEY_QCACHE_SHIM_BPF_ENDIAN_H

#include "../vmlinux.h"

#ifdef __cplusplus
extern "C" {
#endif

__u16 bpf_htons(__u16 x);
__u16 bpf_ntohs(__u16 x);
__u32 bpf_htonl(__u32 x);
__u32 bpf_ntohl(__u32 x);

#ifdef __cplusplus
}
#endif

#endif /* VALKEY_QCACHE_SHIM_BPF_ENDIAN_H */
