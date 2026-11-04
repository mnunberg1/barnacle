Design considerations:

Agent is assumed to run under a restricted environment, meaning it is unable to invoke
privileged system calls, and cannot create or even access files, meaning no assumed
mounts.

The design spec (in architecture.txt and security.md) should be followed as closely as
possible.

Error Scenarios:

Potentially unhandled, but need to be handled are the following error scenarios.
It should be noted that in each of these scenarios, the client application must
continue to function, and must not block. Furthermore, the connection to MySQL
must not be modified or terminated - i.e. if the agent or daemon fail, this
must never be reflected in the client.


The main failure scenario is the daemon being unavailable.

- Unavailable before remapping is simpler, we simply don't remap
- Unavailable during remapping is the more difficult path, since the connection can be closed
    mid-stream
- When reattaching, we need to know how to handle maps and so on.


Assume the following scenario:

C is the client socket, A is the MySQL server remote, and B is the Valkey
daemon remote. Normally, C is connected to A, but when a statement in the
list is detected, a splice is requested and A is now routed to B.

Now, in the event that B is disconnected or hangs during the splice, we must
know what happens to C. Generally, C would be waiting for a response from
B.

One way of solving this is a poll timeout, but this only solves part of
the problem: what if there is data that was sent by the client over the
spliced socket, and the daemon crashed in-situ? obviously the data
cannot be forwarded to MySQL, so simply unmapping it is insufficient.


Another problem is one of the client crashing: Let's say C crashes while
it holds a splice. How does the daemon or subsystem know that this splice
is no longer active? Remember that there are actually *two* splices
internally, one that redirects C->B, and one that redirects B->C

Thus, if any end of the pairing is disconnected, then the other end
needs to be disconnected as well, and the pairing undone.

This can be done by using a unified socket info structure that is accessible
via the bpf functions, the daemon, and the agent.

The ACK response for a SPLICE command should also contain a pointer to
the actual `dpipe` structure.

When the client is performing I/O on the socket (using poll(2)) it must check
before and after what the state of the dpipe::status (we'll change this from
an in_use boolean to a set of status codes)

// available
DPIPE_STATUS_FREE = 1

// lease active
DPIPE_STATUS_BUSY = 2

// we'll explain these two reap statuses soon
DPIPE_STATUS_REAP_C = 3
DPIPE_STATUS_REAP_D = 4

The client program is waiting on I/O on socket C. When/if B closes, the
following must happen:

1) C must be woken up so that it doesn't hang
2) Client must be notified that C's splice is now broken
3) C must be unspliced

The question is, how is C unspliced (removed from the mapping)? the error
itself is reported via the `dpipe` structure, but once the splice is done
then the error information is gone.

We must add an explicit release or unsplice command that is invoked by
the client. Once the client invokes this command, the dpipe is no longer
accessible by it, and the daemon (or internal bpf subsystem) processes
it for destruction.

Because the client doesn't need an ACK, we can just submit the dpipe key
to an unsplice queue: bncl_queue_unsplice

The message is simply: { dpipe->key }

Before submitting, we do a CAS on dpipe->status, ensuring that it's BUSY OR REAP_D,
and transitioning it to REAP_C

We change dpipe::is_paired to dpipe::status:

struct dpipe {
    __u32 key; /* index in dpipe_map, dpipes and the freelist */
    __u32 cfd; /* far end; held open only to keep the connection alive */
    __u32 sfd; /* the daemon's i/o end, and what dpipe_map holds */
    __u64 ts;  /* last activity, for the LRU sweep */
    struct stmt __arena *stmt;
    __u32 status; /* DPIPE_STATUS_xxx */
};

then, ringbuffers/queues (the ordering doesn't matter.. really)

- bncl_queue_reap_client
- bncl_queue_reap_daemon

The actual mechanism of unsplicing is done via a new cgroup/setsockopt program,
we'll call it setsockopt(sock, SOL_BNCL, BNCL_CTL_UNSPLICE) for example.

This function will do these things before returning:

- Remove the client-side (e.g. socket C's) SKINFO so that it effectively no longer exists
- Transition state to REAP_C (from BUSY or REAP_D)
- Pushes the dpipe key into the queue (maybe with some more metadata TBD)


Let's demonstrate some scenarios
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

NORMAL
======

Client: BNCL_CTL_SPLICE(FD=100)
Server: BNCL_CTL_SPLICE_OK(DPIPE=0xFDD)
Client: write(fd=100, {stmt=whatever})
Server: read(fd=100,....)
Server: write(fd=100, {rows=xxxxx})

Client: poll(fd=100,...)
Client: POLLIN(fd=100)
Client: dpipe=0xfdd->status == BUSY (ok)
Client: read(fd=100,....) = N
Client: dpipe=0xfdd->status == BUSY (ok)

Client: setsockopt(fd=100, SOL_BNCL, BNCL_CTL_UNSPLICE, key=dpipe->key);

SERVER CRASH
============

Client: BNCL_CTL_SPLICE(FD=100)
Server: BNCL_CTL_SPLICE_OK(DPIPE=0xFDD)
Client: write(fd=100, {stmt=whatever})
Server: read(fd=100,....)
Server: write(fd=100, {rows=xxxxx})
[server crash]

bpf: sock_ops detects crash (TODO: What state transition is this)
    maybe instead of sock_ops, it's actually a callback invoked when the process exits?? tbd

bpf: marks dpipe->status = REAP_D (but only if status == BUSY)
    (if status == FREE -- this shouldn't happen, this callback shouldn't fire)
    (if status == REAP_C -- we can ignore this, REAP_C takes precedence anyway, and means
    that the socket will be collected by the reaper thread)

bpf: dpipe goes into bncl_queue_reap_server (i.e. server side crashed)

note: it's always safe to dereference dpipe from the server-side (i.e. socket B)
    because the dpipe is attached to it for its entire lifetime

[server restart]

Server: go through queue_reap_server, for each item, sending a single byte to wake up client
    -- but only send those bytes if the state is still REAP_D -- if the client end already
    signalled a close (i.e. REAP_C), then it means the client has released the dpipe and
    is no longer using it or awaiting I/O on it, and has submitted it to the REAP_C queue

Client: poll(..., {fd=100) = POLLIN
    client receives notification about a readable socket, and inspects the state
    if state == REAP_D, it drains the queue and releases it
    Note that it should NEVER receive a status of REAP_C, because this is something
    only the client itself can set.

Client: setsockopt(fd=100, SOL_BNCL, BNCL_CTL_UNSPLICE, key=dpipe->key);
    this unsplices C immediately, and

CLIENT CRASH
============

Client: BNCL_CTL_SPLICE(FD=100)
Server: BNCL_CTL_SPLICE_OK(DPIPE=0xFDD)
Client: write(fd=100, {stmt=whatever})
Server: read(fd=100,....)
Server: write(fd=100, {rows=xxxxx})

[client crash]

bpf: sock_ops detect crash -- I guess here we can just do a simple state transition into
    dpipe->status = REAP_C

Infrastructure Assumptions:

1) Daemon will always be available/restart through some watchdog process,
i.e. there is a reaper process.

2) Agent has context of full original statement, can retry the operation if necessary

3) BPF structures are pinned (at least at the container housing the daemon).
    With respect to the client-side containers, they do not access BPF structures
    at all, except by means of SCM_RIGHTS transfer (i.e. the arena)

4) We don't care about any data sent between C and B in the case of an error.. it's all
    restartable anyway

5) Daemon has control over the freelist, and in fact, a central assumption is that


RECONNECTING
============

Agents can reconnect to a crashed daemon (and therefore retain the control channel)
by using a new queue -- this queue is established at the point of initial connection,
when the control channel is established. Its sole purpose is to allow the
reestablishment of the control channel (used for splicing).

The name of this special queue is:

`bncl_agent_reconn_queue`

The reconnect procedure is:

1) Agent re-creates the socketpair
2) Agent places socketpair fds in `bncl_ctrl_g.sock` (per security.md)
3) Agent writes the daemon-bound FD and the value of bncl_ctrl_g.dpid as
    input into the queue. It also begins listening on the agent-side of
    the newly-created socketpair
4) As the daemon consumes the queue, it looks at the provided PID, calling
    pidfd_openfd(dpid, fd, etc)

5) Finally, it responds with a `CONTROL_RECONNECT(0x03)` signalling that
    the AGENT is now connected to the daemon once more.

Note that there is no need to reestablish bpf structures and arenas,
because the AGENT already has handles to them.