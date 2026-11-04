# Privilege separation between Agent and Daemon

## Overview

The goal of Barnacle is to make the installation and configuration as simple and as
turnkey as possible, putting the burden and onus of configuration on the system
administrator, and eliminating any application/client-side changes.

Barnacle is divided into two main components: one that runs on the outer scope,
at the host, bare metal, or supervisor/privileged level called the **daemon**.

The other is the **Agent**, which is injected by a privileged process
_into_ the client application, and runs with the latter's context and permissions.


## Daemon Privileges

This is what we know about the daemon so far:

- being able to view/analyze all inferior PIDs on other processes
- being able to inject into the process, this requires at least one of:
  - modifying via `LD_PRELOAD`:
    - copying binary over to container and/or bind-mounting a volume containing the binary
    - modifying the command line arguments to allow for injection
  - live modification/hot patching
    - using `ptrace(2)` to attach to an existing binary
    - write pages into binary's address space
    - mark pages as executable (`mprotect(2)`, `PROT_EXEC`)
    - modify executable pages (`mprotect(2)`, `PROT_WRITE`)
- being able to inject/install BPF programs

## Current Landscape

The AGENT does not run in a separate container, but rather WITHIN the
intercepted/injected binary. It must have a way to communicate efficiently with
the daemon. There are several privileged operations which are currently done
via an agent-side invocation of `bpf(2)`, both involve modifying/manipulating
a socket map. These `bpf(2)` system calls may require modifying (elevating)
the privelges of the agent, something which we must avoid doing.

## Goals

### Verify required permissions

Verify required permissions for the Agent. At the most basic level, the agent
must be able to read the Barnacle configuration (so it requires at least read-
only access to some shared state), as a way to relate or correlate SQL statements
to the `stmts_map`.

The Agent must also be able to request that the daemon temporarily splice a
MySQL socket over to a daemon-provided `dpipe`.

### Extend Agent Control Flow

Rather than opening the shared BPF objects themselves, the Agent will
'receive' them from the privileged daemon container.

#### Control Section

We introduce a new concept called the Control Section. This is a segment
of machine code injected into the Agent that provides the agent-side
mechanics of establishing a bidirectional communication channel between
Daemon and Agent.

```
extern int bncl_agent_channel[2]; // = {0}; // 0 is agent-side, 1 is daemon-side 

void bncl_agent_channel_init() {
    static int ctlfd = -1;
    if (ctlfd != == -1) {
        assert(0 && "this wasn't supposed to be called twice");
    }
    // ....
    if (0 != socketpair(AF_UNIX, SOCK_STREAM, 0, bncl_agent_channel) {
        assert(0 && "couldn't establish channel!");
    }
}
```

The control section is injected into the target client application, and then
invokes `socketpair(2)` creating a pair of UNIX sockets. The Control Section
agent keeps one end of the sockets, and the injector (daemon) takes a handle
from the other end, using pidfd_getfd.

Once `bncl_agent_channel_init()` completes, we can read the public
bncl_agent_channel symbol, which contains the other end of our FD,
and then call pidfd_getfd on that (e.g. the remote `channel[1]`)

```
void bncl_agent_channel_bootstrap() {
    struct msghdr msg = {0};
    // ....
    // todo: set up timeout code etc
    if (recvmsg(bncl_agent_channel[0], &msg, 0) < 0) {
        // ....
        assert(0 && "couldn't receive message from socket!");
    }
}   
```

Once the daemon and the agent both have their own ends of the control channel
the daemon sends over the handles of the relevant BPF maps and arenas using
`SCM_RIGHTS` (via `bncl_agent_channel_bootstrap`),
with the agent receiving these maps. This eliminates the map
needing to be shared via filesystem .

You should handle the exact call sequencing, since this involves
passing data on a socket between two processes.

The exact call sequence is TBD.

#### Splice Handling via SOCKMAP

Splices can no longer be done using BPF map operations within the agent, since
those require `CAP_BPF` permissions, which we are now unwilling to grant.

Instead, we will use the control channel established by the Control Section:
The Agent will request the Daemon to splice one of its sockets.

1. *Agent* sends a `SPLICE_SOCK(0x01)` message over the *Control Socket*
   (established via the *Control Section* above), including the MySQL
   (i.e. victim socket) as the payload for an `SCM_RIGHTS` cmsg.
2. *Daemon* receives this message, and internally splices it to one of the
    available *Daemon Pipes*.
3. *Agent* then proceeds to communicate on the spliced socket via the mini-protocol
   established in the architecture.txt file
4. *Daemon* un-splices the socket after sending a response (regardless of the response)


#### Optional `LD_PRELOAD` Mode

Instead of forcing `ptrace(2)` for the Control Section and binary injection
we should also offer a more conventional path using `LD_PRELOAD`, accessible
BPF maps, and an accessible UNIX socket path.

1. Our `libbnclagent.so` must be accessible from a mounted directory within
   the client container
2. A UNIX socket, `bncl.sock` must also be accessible from a mounted directory
   within the client container

This provides an alternative that doesn't require ptrace(2)