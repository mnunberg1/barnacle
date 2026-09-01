#pragma once
/*
 * Stand-in for Linux's <linux/types.h>: the fixed-width kernel typedefs that
 * headers shared between BPF and userspace rely on.
 */
#ifndef BNCL_SHIM_LINUX_TYPES_H
#define BNCL_SHIM_LINUX_TYPES_H

#include <stdint.h>

typedef uint8_t __u8;
typedef int8_t __s8;
typedef uint16_t __u16;
typedef int16_t __s16;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef uint64_t __u64;
typedef int64_t __s64;

#endif /* BNCL_SHIM_LINUX_TYPES_H */
