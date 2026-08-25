#pragma once
/*
 * Stand-in for Linux's <linux/perf_event.h>. Only the pieces the
 * override-attach path touches: bpftime encodes its attach type in a
 * perf_event_attr, reusing the uprobe plumbing.
 */
#ifndef VALKEY_QCACHE_SHIM_LINUX_PERF_EVENT_H
#define VALKEY_QCACHE_SHIM_LINUX_PERF_EVENT_H

#include <stdint.h>

#define PERF_FLAG_FD_NO_GROUP (1UL << 0)
#define PERF_FLAG_FD_OUTPUT (1UL << 1)
#define PERF_FLAG_PID_CGROUP (1UL << 2)
#define PERF_FLAG_FD_CLOEXEC (1UL << 3)

struct perf_event_attr {
	uint32_t type;
	uint32_t size;
	uint64_t config;
	union {
		uint64_t sample_period;
		uint64_t sample_freq;
	};
	uint64_t sample_type;
	uint64_t read_format;
	uint64_t flags;
	union {
		uint32_t wakeup_events;
		uint32_t wakeup_watermark;
	};
	uint32_t bp_type;
	union {
		uint64_t bp_addr;
		uint64_t kprobe_func;
		uint64_t uprobe_path;
		uint64_t config1;
	};
	union {
		uint64_t bp_len;
		uint64_t kprobe_addr;
		uint64_t probe_offset;
		uint64_t config2;
	};
};

#endif /* VALKEY_QCACHE_SHIM_LINUX_PERF_EVENT_H */
