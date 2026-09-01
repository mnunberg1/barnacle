// SPDX-License-Identifier: GPL-2.0
#include "uclient/bpfsys.h"

#include <linux/bpf.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* glibc has no wrapper for bpf(2). */
static long bpf(int cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int bncl_bpf_obj_get(const char *path)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(unsigned long)path;
    return (int)bpf(BPF_OBJ_GET, &attr);
}

int bncl_bpf_lookup(int fd, const void *key, void *value)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = (uint64_t)(unsigned long)key;
    attr.value = (uint64_t)(unsigned long)value;
    return bpf(BPF_MAP_LOOKUP_ELEM, &attr) == 0 ? 0 : -1;
}

int bncl_bpf_update(int fd, const void *key, const void *value, uint64_t flags)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = (uint64_t)(unsigned long)key;
    attr.value = (uint64_t)(unsigned long)value;
    attr.flags = flags;
    return bpf(BPF_MAP_UPDATE_ELEM, &attr) == 0 ? 0 : -1;
}

int bncl_bpf_delete(int fd, const void *key)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = (uint64_t)(unsigned long)key;
    return bpf(BPF_MAP_DELETE_ELEM, &attr) == 0 ? 0 : -1;
}
