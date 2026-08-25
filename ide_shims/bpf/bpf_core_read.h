#pragma once
/*
 * Stand-in for libbpf's bpf/bpf_core_read.h (CO-RE relocated field access).
 * Not currently used by this project -- present so an include resolves rather
 * than failing to parse if one is added.
 */
#ifndef VALKEY_QCACHE_SHIM_BPF_CORE_READ_H
#define VALKEY_QCACHE_SHIM_BPF_CORE_READ_H

#include "../vmlinux.h"

#define BPF_CORE_READ(src, a...) ((typeof((src)->a)){ 0 })
#define BPF_CORE_READ_INTO(dst, src, a...) (void)0
#define bpf_core_field_exists(field) 1

#endif /* VALKEY_QCACHE_SHIM_BPF_CORE_READ_H */
