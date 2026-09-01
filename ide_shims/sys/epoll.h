#pragma once
/*
 * Parse-only stand-in for Linux's <sys/epoll.h>.
 *
 * macOS has kqueue, with a different model entirely -- this is not a port and
 * nothing here waits on anything. It exists so the redirect and pipe-pool
 * tests, whose whole point is that a client parked in epoll_wait() gets woken
 * by the sk_msg redirect, can be read and navigated in an editor. They only
 * ever run on Linux.
 */
#ifndef BNCL_SHIM_SYS_EPOLL_H
#define BNCL_SHIM_SYS_EPOLL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EPOLLIN 0x001
#define EPOLLOUT 0x004
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLET (1u << 31)

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef union epoll_data {
        void *ptr;
        int fd;
        uint32_t u32;
        uint64_t u64;
} epoll_data_t;

struct epoll_event {
        uint32_t events;
        epoll_data_t data;
};

int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

#ifdef __cplusplus
}
#endif

#endif /* BNCL_SHIM_SYS_EPOLL_H */
