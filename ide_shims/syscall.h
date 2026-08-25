#pragma once
/*
 * Stand-in for Linux's <syscall.h>.
 *
 * Deliberately does NOT declare syscall() itself: <unistd.h> already provides
 * it on both platforms, and the signatures differ (macOS uses `int syscall(int,
 * ...)`), so redeclaring here is a guaranteed conflict. Only the syscall
 * numbers are supplied -- the part macOS genuinely lacks.
 */
#ifndef VALKEY_QCACHE_SHIM_SYSCALL_H
#define VALKEY_QCACHE_SHIM_SYSCALL_H

#include <unistd.h>

/* Real Linux numbers, for parsing only -- meaningless on any other kernel. */
#ifndef SYS_bpf
#define SYS_bpf 321
#endif
#ifndef SYS_perf_event_open
#define SYS_perf_event_open 298
#endif

/* The __NR_ spelling is what kernel-adjacent code actually uses. */
#ifndef __NR_bpf
#define __NR_bpf SYS_bpf
#endif
#ifndef __NR_perf_event_open
#define __NR_perf_event_open SYS_perf_event_open
#endif

#endif /* VALKEY_QCACHE_SHIM_SYSCALL_H */
