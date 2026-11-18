# BARNACLE

The goal of this project is to provide a transparent injectable
caching layer that can accelerate query times for administrator-selected
queries.

The cache should require little-to-no configuration on the
administration/platform end, and *zero* configuration on the application
or user.


## Operational Overview

From a high level, this caching layer intercepts database queries, and
checks if a query conforms to a specific set of criteria and can/should
be redirected to the caching layer. For queries that do meet the criteria,
the system them processes it through the caching pipeline, and for all
other queries, the system leaves them alone to be processed as usual.

It is important to note that this decision happens at the point of origin
of the query, rather than some common gateway. **BARNACLE IS NOT A PROXY**,
meaning it does not force all query traffic through an added choke-point.

All of the filtering and processing of queries happens as part of
a dynamically linked executable object known as the **Agent**. Queries
that *do* require caching are sent through a centralized server known
as the **Daemon**, which does act like a proxy, but only for queries
that are specifically selected as such.

### Some Terminology

#### Client

The *client* is a sealed, black-box application written by a user. We do not
know anything about the client except for the fact that it issues MySQL queries
through TCP connections that it creates (or receives).

The client is always an executable binary. In cases where the client code is an
interpreter and the user's business logic is written in a scripting language
(e.g. Python), the actual _execution_ still occurs at the _binary_ or _machine
code_ level.

#### Agent

The *agent* is part of the Barnacle codebase, and compiles down to binary form
and is attached at runtime to the *client* binary executable and is executed
in its context. From the perspective of the kernel, processor, and memory, the
Agent is fused on to the Client. Of course, because the Client is sealed, the
Agent must make runtime decisions and heuristics on how to interact with the
Client.

#### Origin Server

This terminology is borrowed from the HTTP RFCs (and other RFCs) and refers to
the remote end of a client's MySQL connection. It is the authoritative origin
of the data.

#### Daemon

This is the Barnacle Server component, and it runs in its own context, not
within the context of the client. It serves as a coordinator and communicated
with the *agent*.


#### KAgent (previously KClient)

This is the Barnacle component that is executed in the kernel space. It lacks
an application context and is quite restricted in what it can do. It is a vital
component of the Barnacle infrastructure, since it allows us to emulate the
Origin Server in a fairly transparent way, and share various structures between
the daemon and the agents.

#### UAgent (previously UClient)

This is the non-BPF, non-privileged portion of the client. I think we will
simply refer to it as *agent*

#### DPipe

The DPipe, or Daemon Pipe, represents a _temporary_ connection between the agent
and the daemon. The DPipe is spliced and spoofed into an origin server

#### Control Socket

Refers to a permanent and open control channel between agent and daemon

#### BPF Arena/Shared Memory

Refers to shared memory accessible by all components:
Agent, UAgent, Daemon, and KAgent

This is a block of memory and is intended to contain control information rather
than heavier data (though it may contain that as well!)

## Connection Model

Most modern database servers use TLS as a standard option, which influences
the connection model of Barnacle. Intercepting and *reading* TLS traffic
is non-trivial (but possible), but writing TLS-encrypted packets (e.g.
as a cache _response_) is entirely impossible without knowing the server's
private key.

Therefore, any solution overriding/intercepting TLS-based communication must
operate on a level where the traffic is not _yet_ encrypted, allowing 
modification of the packet before it hits the encryption stack (or preventing
it from being encrypted and sent in the first place). 

We chose **not** to intercept traffic at the network level, since this would
make Barnacle a _proxy_, and would also require Barnacle to know the connection
parameters of the remote database instance (e.g. username, password, host, port
and so on -- which is not required currently).

## Implementation

### Socket/Connection Tracing and Tracking


#### Tracking Streams

Each database protocol must have its own implementation; we'll start
with MySQL because it's a well-known synchronous protocol.

For starters, we must determine if the outbound connection is plain-text
or SSL; we must do this using heuristics because a TLS-enabled MySQL
connection starts out as a plain-text connection that is later upgraded
to TLS.

Even though we do not decrypt traffic, we must still know where in the
call-stack to analyze query analysis. If the connection is plain text
then we simply analyze `send`/`recv` (and their `read`/`write` analogues).
However, if the connection is encrypted then it is already too late by
the time `send`/`recv` is seen -- in this case, our agent must break
at `SSL_read`/`SSL_write` (and their `_ex` analogues)

In the case of MySQL, this heuristic is fairly straight-forward since
its protocol does not support pipelining or multiplexing. Therefore,
we can guarantee that a `send` after a `recv` (or vice versa) is
the beginning of a new L7 message.

```c++
enum class LastIOOp {
    Unknown = 0, // default
    Send,
    Recv
};

using Last = LastIOOP;
```

```
!![agent attach]
last_op = Last::Unknown;

> [outgoing data]; last_op==Last::Unknown, change to last_op=Last::Send
> [more outgoing]; last_op=Last::Send, keep last_op=Last::Send

< [incoming data]; last_op=Last::Recv
at this point, we know that the last part of outgoing data is the end
of a request packet, because the last op is not unknown and is not
recv, so we begin parsing from the incoming data.
```


We cannot assume that every call to `send(2)` contains a fully formed
packet, nor can we assume that every call to `recv(2)` receives a
fully formed response. We need to buffer the packet until we can make a
decision.

***

This is the object that the agent associates with a file descriptor. It handles
parsing and state management. This is not a comprehensive definition, but merely
the fields needed for parsing.


```c++
class OConn {
public:
    enum ParseStatus {
        // Packet parsed ok, buf contains the full request, query contains the
        // SQL statement itself. If the statement should not be intercepted
        // (or if it needs to be relayed to the origin), then the contents of
        // the passed `buf` should be sent to the origin
        OK = 0,
        
        // More data needed
        NEED_MORE,
        
        // Packet parsing error.. should not be returned in normal operation
        PARSE_ERR,
        
        // SQL (server-side) error, i.e. response is not data. The response can
        // be passed to the application, but should not be relayed to any cache
        // and should not be parsed for data. Only received on feedResponse
        SQL_ERR,
        
        // Client requests to upgrade connection to TLS. Send the attached
        // buffer and monitor the socket on SSL_write/SSL_read functions
        // This is only received on feedRequest
        TLS_UPGRADE,
    };

    // feeds the outgoing request to the parser, in the case of ok,
    // the `query` contains the offset and size of the SQL query that
    // can be used for further processing.
    // in the case of NEED_MORE, the call must be repeated again with
    // the same buffer (it doesn't need to be the same pointer, but the first
    // byte needs to be the same as the previous call).
    //
    // If TLS_UPGRADE is returned, then the buffered packet should be relayed
    // to its destination (presumably ::feedRequest() is called here within the
    // context of send()).
    // The agent should send the buffer (_within_ the existing send() call) and
    // this parser itself should shift to SSL parsing mode.
    //
    ParseStatus feedRequest(std::string_view buf, std::string_view& query);

    // feeds the incoming response to the parser, in the case of ok,
    // the `result` contains the offset and size of the responded
    // rows. In the case of an error, sqlError contains the server-side error
    ParseStatus feedResponseCaching(std::string_view buf, std::string_view& result, int& sqlError);
    
    // Just feeds the response without parsing the row data. This is simply
    // to maintain state.
    ParseStatus feedResponse(std::string_view buf);
    

    // This function will determine whether a packet needs to be intercepted
    // analyzing the buffered request. If it returns false, it means that normal
    // program flow should continue. If it returns true, it means that the query
    // has been redirected elsewhere.
    //
    // This function should also enable non-TLS recv() by manipulating the
    // flags in FDTracker, but keep track of the previous state when the
    // intercept is complete.
    bool interceptBegin();
    bool isIntercepting() const;
    // continue interception control flow.
    bool interceptContinue();

private:
    LastIOOp lastOp = LastIOOp::Unknown;
    
    struct ProtocolParseInfo {
        //  .... fields for parsing and maintaining protocol state.
        // no buffer here.
    } protostate;
   
    // example field only, this is the database name the connection is using.
    char* dbName;
    
    using Buffer = std::vector<char>;
    Buffer wbuf, rbuf;
};
```

The API is shown as an example in C++, but it could be rewritten in C were it
required to be deployed within the kernel-level BPF rather than in userspace.


#### Tracking File Descriptors

In the previous section we discussed how to trace or analyze an individual
connection, but this does not tell us how to associate connection metadata
with its connection. Because we are a Barnacle agent, we *latch on* to
existing connections, and must find ways to properly establish and remove
metadata from file descriptors.


```c++
enum BNCL_FDIgnore {
    BNCL_FDIGNORE_NONE =    0x00, // New socket
    BNCL_FDIGNORE_SYS =     0x01, // Ignore send/recv
    BNCL_FDIGNORE_TLS =     0x02, // Ignore SSL_write/SSL_read
    BNCL_FDIGNORE_ALL =     (BNCL_FDIGNORE_SYS|BNCL_FDIGNORE_TLS)
};

struct ClientFDInfo {
    uint32_t oconn_idx : 24;
    uint8_t ignored
};
```

```c++
struct BNCL_FDTable {
    ClientFDInfo *fds; // indexed by file descriptor
    OConn*[] oconns; // index to OConn objects, indexed by FDInfo::oconn_idx
};
```

```c++
class FDTracker {
public:
    static const size_t TRACK_LIMIT = 500000; // example
    
    // Special value returned if the ignore flags match
    static const OConn *Ignored = (OConn*)0xdeadbeef;
    
    // Return the OConn for the given FD, with the given flags.
    // the flags indicate the context of the request; if the context is
    // in the ignore list, then ::Ignored is returned, otherwise the
    // current OConn is potentially allocated and returned.
    //
    // The FDInfo is returned as an out parameter (always), and its flags
    // can be manipulated
    OConn *get(int fd, int myflags, ClientFDInfo*& fdinfo);
    
    // Instructs the tracker to clear and/or reset the Ignored flag and the
    // associated OConn. This should only happen during connect() and close()
    // calls.
    void reset(int fd);
    
    // Instructs the tracker to ignore the socket for all operations
    void ignore(int fd);

private:
    BNCL_FDTable fd_table;
};
```

Note that the implementation is not confined to C++. It could be C, e.g.

```c++
BNCL_OConn* bncl_fdtrack_get(FDTrackCtx*, int, int, ClientFDInfo**);
// etc..
```

`tracker->reset()` must be called when a file descriptor is closed. Closes
can happen either implicitly (via `close()`) or explicitly, via various
forms of `dup` calls. When a socket is traced in its initial `socket()` call,
its entry should be reset/cleared, or ignored (if it's not to the correct
host/port that the agent should monitor)

##### Forked processes

When a process forks, the child process inherits all the parent's file
descriptors. Normally, either the child or the parent takes over the file, and
they don't both write to it, so the fd can be tracked from either the
parent or the child, whichever one actually performs I/O on it.


#### Socket Tracing Walkthrough

There are two scenarios, but both are covered by the same state transition
mechanism. The first scenario is tracing a newly connected socket, in which
case the state of the stream is known from the first `connect` call. The
second scenario is attaching to a stream whose state is not known. In the
second scenario

1. syscall `connect(2)` is intercepted
   ```c++
   int connect_wrapper(int fd, struct sockaddr *saddr, socklen_t addrlen) {
       if (!bncl_cfg_check_addr(saddr, addreln)) {
           // socket should NOT be traced
           tracker->ignore(fd); // or
           // bncl_fdtrack_ignore(tracker, fd);
       }
       return connect_real(fd, saddr, addrlen);
   }
   ```
2. When syscalls are invoked on the socket:
   ```c++
    ssize_t send_wrapper(int fd, const void* buf, size_t length, int flags) {   
       // check the state of the socket ....
       
       ClientFDInfo* ptr = nullptr;
       auto conn = tracker->get(fd, BNCL_FDIGNORE_SYS);
       
       if (conn = FDTracker::Ignored) {
           // ignored, nothing to do here..
           return send_real(fd, buf, length, flags);
       }
       
       // now we need to actually get our state
       std::string_view svbuf(buf, length);
       std::string_view query;
   
       auto rv = conn->feedRequest(buf, query);
   
       switch (rv) {
       case OConn::OK: {
           // see how we feed/relay this packet over to the origin:
           if (!conn->interceptBegin()) {
               return send(fd, buf, length, flags);
           }
           return length;
       }
       case OConn::NEED_MODE: {
           conn->sendbuf(svbuf); // append to internal buffer
           return length;
       }
       case OConn::TLS_UPGRADE: {
           // 1) ignore sysio
           // 2) assume that SSL_write/SSL_read will be used
           // 3) relay the connection
           ptr->ignored |= BNCL_FDIGNORE_SYS;
           conn->tlsUpgraded();
           return send(fd, buf, length, flags);
       }
       }
   }
   ```
3. When SSL_write is invoked:

   ```c++
   int SSL_write_wrapper(SSL *ctx, const void *buf, int num) {
      // check the state of the socket
       ClientFDInfo* ptr = nullptr;
       // find the FD first. The FD will always be at some offset
       // of the SSL_ctx, though maybe it makes more sense
       // to trace the SSL_ctx? but SSL_ctx can't be indexed in a simple array
       auto fd = SSL_get_fd(ctx);
       auto conn = tracker->get(fd, BNCL_FDIGNORE_TLS, ptr);
       if (conn = FDTracker::Ignored) {
           // ignored, nothing to do here..
           return SSL_write_real(ctx, buf, length, flags);
       }
       // now we need to actually get our state
       // note: if we've gotten to here, we must also disable the SYS flag
       // on the connection, because the invocation of this function is PROOF
       // that fd is not a plain text connection
       ptr->ignore |= BNCL_FDIGNORE_SYS;
       
       std::string_view svbuf(buf, length);
       std::string_view query;
       
       auto rv = conn->feedRequest(buf, query);
       
       switch (rv) {
       case OConn::OK: {
           if (!conn->interceptBegin()) {
               return SSL_write_real(fd, buf)
           }
           return num;
       }
       case OConn::NEED_MORE: {
           // etc.. this switch statement is basically the same in SSL and
           // non-SSL variants, except that we can't upgrade from
           // SSL
       }
       }
   }
   ```

4. Read (plain or regular) are simply fed into the parser as before:
    ```c++

  ssize_t recv_wrapper(int fd, void
    ```
5. When socket is closed:
   ```c++
   int close_wrapper(int fd)    {
       tracker->reset(fd);
       return close_real(fd);
   }
   ```
   `reset` has the effect of deallocating any parser internals (or scheduling
    them for destruction since we might need to do lazy cleanup)


#### TLS vs Plain Text tracing and processing

TLS tracing must be done in the callstack of the client
(subject to the specific TLS/SSL implementation).
Clear text, however, must be done at the syscall level, but in order to
operate and intercept syscall invocations, BPF or frida-gum is insufficient. We
must use something like `bpftime` which executes BPF functions _within_
userspace and contains the correct implementation that can override syscall
sites.


## Cache handling

In the event that a query is encountered (after the request itself has been
fully parsed), the normal control flow of the client application is interrupted
and the agent-specific code and I/O handlers take over for a period of time.

The agent will, if it can, fetch the database result from the cache, and return
the result to the client, as if it had come directly from the MySQL server
itself.

#### Simulating the Origin Server Response

Interrupting the program flow is quite complex when we aren't _sure_ of the
response path. Consider the following sequence of events:

1. Business logic determines an SQL query must be issued
2. Client application issues SQL query using high-level SQL library
3. SQL library forms a request packet
4. SQL library then invokes I/O function (e.g. `send()` or `SSL_write()`)
    > ^^^^ this step is where we trace outgoing packets
5. At this point, the client will, as potentially part of a different callstack,
   read and/or wait for activity on the server's socket. It will either call
   `recv()` on the server's socket, or, more likely, it will add it to a
    `poll()`-like interface and ignore the request until the socket is marked
   as readable.

For us to properly handle the SQL request, it is insufficient to simply
intercept stage #4 (the outgoing request), because this does not give us a way
to simulate the response to the server.

In order to overcome this, we _temporarily_ override the socket connection at
the BPF (kernel) level, so that we can signal both to the agent and to the
application when a response is ready from the cache _without_ blocking the main
application.

#### Cache States

When the agent makes a cache request, one of three states are possible

1. Response data is in the **LOCAL** cache and can be returned instantly
2. Response data is in the **REMOTE** cache and needs to be fetched
3. Response data is not present, and needs to be **READ-THROUGH** from the DB

> The **local** cache represents the cache that is local to the host running
> the agent; it is present somewhere in the filesystem or resident memory and
> does not need to be fetched over a socket.

From the perspective of the agent, it doesn't matter if the data is present
locally or remotely, because it needs to be returned via network anyway
(see the discussion above for the reasoning).

If the response is _not_ cached then it needs to be (re-)generated from the
origin server (i.e. the MySQL server). Care must be taken to ensure that only
_one_ client connection re-generates this (in case multiple clients are
concurrently executing the same query). The exact flow is discussed more in
depth in the dpipe section

## States, Data Structures and Components

This outlines the core components to be used in our application; these
are outlined in no particular order.

We touched upon this in the _terminology_ section, but here it's more prudent
to outline the layout of the components.

* Agent -- this is divided into client-specific bookeeping and
  components that interact with the daemon or kernel:
  * Client-Only 
    * MySQL Parsing (understanding protocol state)
    * Buffer Handling/Management
    * Client-origin FD tracking
  * Bootstrapping code that interacts with *daemon*
  * *DPipe* acquisition and release
* KAgent
  * Passing data to/from dpipe (proxying); SOCKMAP
  * DPipe reaping in case of Agent/Client death

### Statement

```c++

struct Statement {
    // the "text" of the statement. in the future this could be something
    // more expansive, but it should uniquely identify this statement
    const char *stmt_name;
    
    // universal numeric ID
    uint32_t stmt_id;
    
    // When the statement last changed state
    uint32_t mtime;
    
    enum State {
        // default state, there is no cache for this statement
        Uncached = 0,
        
        // exists in cache
        Cached,
        
        // is being fetched by a read-through operation from a client
        Pending,
        
        // there is an error for this statement
        Error
    };
    
    State state = Uncached;
    
    // the implementation can be a simple vector, char, or whatever. We're
    // leaving this open for the event where the contents are more structured
    RowData *data;    
};

class RowData {
public:
    // e.g.
    iterator getData(size_t from, size_t to, uint64_t rowMask);
};
```

The statement map is simply where statements can be found, and are based on
the configuration rules.

```c++
class StatementMap {
public:
    std::vector<Statement*> by_id;
    std::unordered_map<std::string,Statement*> statements;
    // each statement is independently allocated.. of course
};
```

Statement data and the map lives in the Arena, since it is shared among agents
and the daemon.


### Agent-Side DPipe information

This object represents the agent-side ownership of a DPipe. This structure
is used whenever the parser detects a statement that is cachable.

```c++
// A state object per statement and dpipe
class AgentStmtState {
    // the statement
    Statement *stmt;
    
    // The DPipe ID acquired from the daemon, this ID must be released
    // when the statment operation is completed.
    uint32_t dpipe_id;
    enum State {
        Init = 0,
        CacheFetch, // fetching from cache
        OriginReadThrough, // reading from origin, relay back to server
    };
};
```

### DPipe

A DPipe is the bpf/daemon-side connection.
The agent and BPF subsystems will *splice* the MySQL client connection so that
packets intended for the Origin Server are redirected to the DPipe, and that
packets originating from the DPipe go to the client connection *as if* they had
originated from the origin server.

This allows clients to utilize whatever existing I/O infrastructure they had
in place, since the redirection happens at the kernel layer and not the client
layer, it doesn't matter if synchronous or asynchronous non-blocking I/O is
used.

The DPipe structure goes into shared memory, despite some of its fields only
making sense in specific contexts. It is needed in case a daemon crashes, so
that its successor process has a way to understand/track/clean up state
rather than leaving existing agent connections hanging.


```c++
struct DPipe {
    // daemon end, the daemon reads to and writes from this
    int daemon_fd;
    
    // inactive fd, because I/O is actually redirected at the kernel level
    int client_fd;
    
    
    // the original FD passed via SCM_RIGHTS, to the daemon. This is used for
    // splicing and unsplicing
    int spliced_fd;
    
    // we'll speak more about this field later on.
    uint32_t state;
};
```

The map of DPipes

```c++
#define DPIPE_MAX 4096 // or whatever

// List of DPipes
DPipe bncl_dpipes[DPIPE_MAX];
```

There is the DPipe freelist, which needs to persist between Daemon instances
and should be in the BPF arena

```c++
struct bncl_dpipe_freelist {
    // list of IDs, IDs is an index into the daemon-side DPipe array.
    // when allocating a dpipe, the daemon checks here first. this is initially
    // populated with all the IDs, and then indexes are popped as they are
    // allocated to agent requests, and are placed back as they are released
    // by the agents.
    uint32_t ids[DPIPE_MAX];
    
    uint32_t num; // number of FDs currently in the freelist
};
```


### BPF Structures

This section documents BPF maps which must exist in order for the various
BPF programs to function. They exist in this section because their design
is dictated by the strictures of BPF rather than the more intuitive nature
of the other structures.

#### Splicing

BPF cannot actually "splice" a socket. What it can do is take individual packets
and change their egress path, meaning it can monitor a socket (let's call it
`A`) and instead of it going to the other end of `A`, the installed hook
actually redirects to socket `B`. But this must be done explicitly and for
each message. So while from a higher level it seems as if the socket is spliced,
what is actually happens is less glamorous; an injected function simply captures
data going from one place and shoves it in another place.

The sequence is thus, for Agent-Daemon:

1. Agent sends packet, destined for MySQL on spliced socket `A`
2. BPF Function captures packet, callback is called
3. Callback looks at the metadata for the spliced socket `A`
4. Metadata for `A` says it should go to Daemon's socket `C`
5. BPF function tells BPF subsystem that this specific packet should go to `C`

The exact same sequence is required for Daemon -> Agent, e.g.

1. Daemon responds to agent over spliced socket `C`
2. Remote end of `C` is actually never shared with Agent. Agent must read data
   via spliced socket `A`.
3. BPF must check associated metadata with `C`
4. Metadata for `C` says it should go to Agent's socket `A`
5. BPF function tells BPF subsystem that this specific packet should go to `A`


##### Sockmaps

Note that `key` here is the associated DPipe ID

```c++
#define BNCL_SOCKMAP(name) \
    struct { \
        __uint(type, BPF_MAP_TYPE_SOCKMAP); \
        __uint(max_entries, DPIPE_MAX); \
        __type(key, __u32); \
        __type(value, __u32); \
    } name SEC(".maps");

BNCL_SOCKMAP(bncl_smap_daemon);
BNCL_SOCKMAP(bncl_smap_agent);
```

The structure that is used as a value for `BPF_MAP_TYPE_SK_STORAGE`. We don't
need individual daemon and agent versions because they are keyed by the
sockets themselves.

```c++
// we use a struct even though there's only a single 32-bit field to allow for
// future expansion without changing/breaking too much code
struct bncl_skinfo {
    // this is the dpipe id, which is actually an array index into `bncl_dpipes`
    __u32 dpipe_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct bncl_skinfo);
} bncl_map_skinfo SEC(".maps");
```

## Sockets and Flows

### Control Socket

### Splicing and Allocation

#### Design Consideration and Rationale

Barnacle is a decentralized and somewhat non-cooperative system, meaning that
its components are not synchronized with other components. The Barnacle Agent
has little knowledge about the internal state of the client process to which it
is attached, and the client process knows nothing about the Barnacle attached
to it.

This clarification becomes apparent and necessary in fault scenarios. A fault
in Barnacle should not cause a fault in the client application, but the client
application has _no way_ of inspecting a fault in Barnacle, which means it is
of the utmost importance that Barnacle preemptively and proactively detect any
internal fault, and at the very least, unblock the client application and ensure
its smooth operation, since one of the guarantees Barnacle provides users is
transparency: the client application should _never_ notice its presence, neither
in speed nor in stability.

The primary failure scenario for Barnacle is a fault within the daemon _while_
the client's socket is spliced. In this case, the agent doesn't know that the
daemon is stuck -- and yet the origin server is still operational, and the
client is still able to retrieve the (slower) response from it.

Therefore we must have a way to un-stick the client application even when the
daemon malfunctions.

DPipe Status:

```c++
struct DPipe {
    // ....
    enum State {
        // Nobody is using this DPipe
        Free = 0,
        // Leased out to an Agent
        Busy = 1,

        // These are two special status that will be explained later!
        ReapClient = 3,
        ReapDaemon = 4
    };
};
```

#### Splicing Command

These are the parameters for a splice command and response over the control
channel. The agent should issue this request when it discovers a cachable
SQL query.

##### Request

- **Channel**: Control Channel
- **Command**: `SPLICE(0x01)`
- **Data**: MySQL Origin Server socket, passed via `SCM_RIGHTS`

##### Response

- **Status**: `OK(0x00)`
- **Data**: DPipe ID

##### Semantics

Once the socket is splice, the agent owns the returned DPipe ID and must release
it using the release protocol

> NOTE: The release process is *not* done over the control socket, but through
> a special `setsockopt` invocation.

##### Using the socket

Now when the agent (or client) does I/O on the socket, it will be done against
the DPipe object rather than the MySQL server. There is a special mini-protocol
established that is used for data and cache management.


##### Cache Implementation

The Daemon should use Valkey as its backing store. We can abstract and/or
specify the specific implementation regarding key and value.

It should use libvalkey for communication, utilizing an asynchronous event
loop library like libuv, libev, or libevent, or using a native idiomatic C++
I/O library.

The valkey implementation should use the query statement
(i.e. `Statement::stmt_name`) statement to inspect) as the key and the row set
(either encoded in protocol, or as a simple TLV format) as the value.

> TODO: Determine the final format, but in the initial version, I leave the
> encoding format up to the LLM.


##### Checks before splicing

Here is an example implementation of sending the splice command. This does not
show how the splice command itself is constructed, but demonstrates some of the
logic and checks mentioned elsewhere in this document.


```c++
bool Agent::splice(OConn& oc) {
    if (!bncl_ctrl_g.enabled) {
        return false; // disabled...
    }
    
    // do we have a valid socket?
    ensureControlSocket();
    
    requestSpliceCommand(oc);
}
```

##### Data Protocol

###### Requesting Cache

- **Channel**: DPipe
- **Command**: `CACHE_GET(0x02)`
- **Data**: Statement ID
- **Options**: `wait_pending=<seconds>`

`wait_pending` is used when retrieving a query that is pending, in this case
`NOT_FOUND` is not returned immediately, but the daemon waits in the background
up to `<seconds>` for the rowset of this statement to be populated.

Note that `wait_pending` should only be used during a cache retry, because it
will just cause a delay in a common cache-miss case, where a single thread is
requesting the value and no other thread is requesting it.
Therefore, it should not be used during the initial request. 

To properly implement `wait_pending`, we need a global queue at the daemon-level

```c++
class AgentConn; // represents an agent connection..
class StatementCacheWaitQueue {
public:
    // adds a waiter connection. this connection waits until deadline
    void addWaiter(uint32_t stmt_id, AgentConn* conn, uint32_t deadline);
    
    // notify the subsystem that information for a statement is now available
    void popWaiters(uint32_t stmt_id, std::vector<AgenTConn*>& conns);
    
    // when an agent connection dies, we need to remove it from the wait list
    void clearConn(AgentConn *conn);
    
    uint32_t getDeadline(); // for setting a timer, the earliest possible time
    
    // return all connections that expire at 'now' or earlier, the connections
    // are also removed from the queue
    void popExpired(uint32_t now, std::vector<AgentConn*>& conns);
private:
    // we need to index things by:
    
    // 1) soonest expiry time (for handling timed-out requests)
    // 2) agent connections (for clearing killed agents)
    // 3) statement ids (for handling newly-received row data)
};
```

When `wait_pending` is specified, the daemon invokes
`queue->addWaiter(stmt_id, conn, time()+wait_pending)`

The daemon should have a timer incorporated into its event loop, and it should
fire no later than `queue->getDeadline()`. When the timer elapses, the
`queue->popExpired(now, expired_clients)` function is invoked, clearing the
expired clients.

When a statement's data is received via `CACHE_PUT` then
`queue->popWaiters(id, waiting_clients)` is invoked, which will bring those
clients back in to play and have the daemon send the results on their respective
connections.

###### Cache Response

Status can be one of:

- `NOT_FOUND(0x00)`:
    The cache does not have the value, and the client needs to fetch the result
    and send it to the cache (using the `CACHE_SET(0x03)` command)
    > todo: we can also write the result directly to a shared memory segment 
    > or use a ringbuffer to send (and presumably copy) the response data

- `CACHE_RESULT(0x01)`:
    The local cache has the data; the exact number of bytes will follow. Note that
    the agent must still separately unsplice the socket

- `CACHE_ERROR(0xff)`:
    There was an error reaching the cache server, or something else is malformed.
    Don't try to cache this response.


###### Reading-Through the Cache

In the event that the DPipe controls `NOT_FOUND`, it means that one client must
fetch the actual result set, and THEN upload the data back to the cache. This
should be done through a `CACHE_SET` command which uploads the row data for a
given statement ID.

> TODO: Currently this goes over the control channel, but it should ideally
> save the data to some shared memory area, and pass only the fd of the saved
> data, which the daemon can then use to store into valkey itself.

- **Channel**: Control
- **Command**: `CACHE_PUT`
- **Data**: <row data>
- **Options**: `error=xxx`

If `error` is set, then it means there is an SQL error from this statement
and instead of caching the rows, it should return an error for future queries.


###### Electing a Cache Reader

Because multiple clients may be trying to execute the same query, we should
on the one hand try to reduce a scenario where _all_ clients request it at
once, but also avoid a single failure point in case the client responsible
for fetching the response dies or hangs for some reason.

In order to satisfy both conditions, we do the following:

1. `CAS(Statement::state, Uncached, Pending)`. This swaps the status from
    uncached to pending, but only if the previous state was already uncached.
2. If the state is _already_ pending and the `time() - mtime` is greater than
    some configured interval, it means the leader is taking too long, and that
    mtime should be atomically swapped out to the current time
3. If the state is _already_ pending and `time() - mtime` is within the
    allowable interval, then DPipe allocation should take place, and the
    agent should issue a request for the cache, using the `wait_pending` option

What follows are several scenarios:

1. Client succeeds and sends a `CACHE_PUT`, all other waiting clients are
    unblocked at the server level with the correct response (received via the
    `CACHE_PUT`)
2. Client times out, all other waiting clients receive a `NOT_FOUND` message,
    and then another client is elected at random to fetch the response.
3. Client returns error, and all other waiting clients also retrieve the error
    from the `CACHE_PUT` command.


### DPipe Implementation

When the daemon starts up, it populates the `bncl_dpipes` array with `DPipe`
structures. Note that at this point, it does not need to create the sockets,
and it is sufficient to set `daemon_fd` and `client_fd` to the value `-1`.

It also populates the `bncl_dpipe_freelist` to contain all of the indexes of
`0..DPIPE_MAX-1`

> Note: There is probably a way to dynamically scale the number of DPipes
> allowed, `DPIPE_MAX` is used as a placeholder to allow a more readable
> definition within this document.

The ID of each `DPipe` is implicitly its index within the `bncl_dpipes` array.
DPipes are owned by the daemon by default, unless leased out to an agent.

To allocate a DPipe, the client sends a `SPLICE` command over the control
channel and receives a DPipe ID as a response. Here's what the daemon does:

1. Atomically pops the tail ID from the dpipe freelist
2. Changes the status of the DPipe to DPipe::State::Busy
3. Places the DPipe ID into the per-agent register, this register is used by
   the daemon to clean up data when an agent disappears


##### `sk_msg` Implementation

`sk_msg` is the program type used in BPF for our "spliced socket". As outlined
above in the _Splicing_ section, we rely on two `SOCKMAP` maps which contain
the spliced pairs, the _DPipe_ and the _Client_ sockets.

***

**DPipe -> Client `sk_msg`**:

1. Check own `SK_STORAGE` lookup
2. The value of `SK_STORAGE` is the key in the `smap_agent`
3. Check if SK_STORAGE value is -1, drop -- otherwise redirect


**Client -> DPipe `sk_msg`**:

1. Check own `SK_STORAGE` lookup
2. The value can be set to `-1` or be NULL,in the case of it being unspliced
   and waiting for garbage collection. In that case, it returns `SK_PASS`
3. Call redirect so that it goes to the DPipe specified under that key

#### Reap Queues & DPipe Releases


Reap queues solve the problem of being unable to perform certain operations in
BPF handlers themselves:

###### Client Reap Queue

elements cannot be removed from `SOCKMAP` within a BPF program. It must be done
from within userspace. Therefore, when we perform an 'unsplice' operation via
`setsockopt`, the actual unsplicing, i.e. the removal of the sockets from the
maps must be done from the daemon. Trying to manipulate the sockmap from
`setsockopt` will result in an error.

To release a dpipe, the agent invokes a `setsockopt(2)` call with a custom
level and arguments (TODO: look at this in more detail).

- **Channel**: `setsockopt`
- **Command**: `BNCL_CTL_UNSPLICE`
- **Data**: DPipe ID

Implementation:

```c++

#define BNCL_REAP_QUEUE(qname, ...) \
    struct qname ## _msg { \
        __VA_ARGS__; \
    }; \
    struct { \
        __uint(type, BPF_MAP_TYPE_RINGBUF); \
        __uint(max_entries, 256 * 1024); /* 256 KB */ \
    } qname SEC(".maps")


BNCL_REAP_QUEUE(bncl_reapq_client, __u32 dpipe_id);


// tries to unsplice this socket, if it's spliced
void bncl_close_agent_sock(struct bpf_sock* sk) {
    struct bncl_skinfo skinfo = bpf_sk_storage_get(&bncl_map_skinfo, sk, 0, 0);
    // todo: in real code, skinfo is a pointer type, but the underlying struct
    // is 64 bits wide, so we can just store it as a __u64 and then use accessor
    // functions to access the individual fields, but we're keeping it simple
    // here.

    if (BNCL_SKINFO_EMPTY(skinfo)) {
        // nothing here! it's not a tracked socket, bail and return..
    }

    struct bncl_reapq_client_msg msg{
        .dpipe_id = skinfo.dpipe_id,
    };

    // remove from client, i.e. "unsplice"
    bpf_sk_storage_delete(&bncl_map_skinfo, sk);

    // write to the ringbuffer to remove the client from the map altogether
    bpf_ringbuf_output(&bncl_reapq_client, &msg, sizeof msg, 0);

    // llm: handle return values
}

SEC ("cgroup/setsockopt")
int bncl_setsockopt(struct bpf_sockopt* ctx) {
    struct bpf_sock* sk = ctx->sk;
    if (!sk || ctx->level != SOL_BNCL || ctx->optname != SO_BNCL_UNSPLICE) {
        // llm: handle error conditions and default cases
    }
    bncl_close_agent_sock(sk);
}


//  now, the daemon handling the reap queue
void ClientReapQueue::handle_message(bncl_client_reqpq_msg* msg) {
    // todo: synchronization -- we don't want to conflict with an existing
    // SPLICE command..
    // 1) Get the relevant DPipe. Since the state is not yet Free, we are
    //      guaranteed that it hasn't been reassigned.
    DPipe* dp = &bncl_dpipes[msg->dpipe_id];

    // remove the smap pairing.. -- this removes it from the sockmap.
    // note that this is a safe operation -- because this DPipe has exclusive
    // ownership over the smap_agent as well, so in the worst case, the socket
    // is reassigned and the slot is empty.
    bpf_map_delete_elem(bncl_smap_agent, &msg->dpipe_id);


    // Note that we don't need to modify sk_storage -- which was already removed
    // during the unsplice operation

    close(dp->spliced);
    dp->spliced = -1;
    dp->state = DPipe::Free;
}

```

The basic flow is:

1. Remove `SK_STORAGE` from client socket. This way the next time `sk_msg` is
    invoked for this client, it passes through the normal path (e.g. to the
    origin server)
2. Send a message with the dpipe ID into the client reap
    queue.

The client can be re-paired with another DPipe while it remains open and inside
the client reap queue. In this case, it is assigned the new dpipe's `smap_agent`
slot, and its old slot (i.e. the previous `smap_agent[dpipe_id]`) is deleted.


###### Daemon Reap Queue

The daemon reap queue contains a list of active DPipes that were paired when a
previous instance of the daemon crashed. When the new daemon (promptly) starts
up, any previously connected agents must be un-stuck, and the only way to do
this is putting things in their receive queue -- which is waiting on input from
the daemon.

The crash handler will go through all active DPipes and set their state to
`DPipe::ReapDaemon`; `sk_msg` programs will check for this and refuse to
pass messages. Likewise, the agent I/O functions will check the dpipe state
and if `dpipe->state == ReapDeaemon`, it should immediately release the DPipe
via the the `UNSPLICE` socket option.

But the real point of this queue is for the daemon to send bytes of data on
this queue so that clients waiting on read-ready get unstuck.

```c++

// example handler of daemon reapq handler
BNCL_REAP_QUEUE(bncl_reapq_daemon, __u32 dpipe_id);

void DaemonReapQueue::handle_message(struct bncl_reapq_daemon_msg* msg) {
    // find the DPipe
    DPipe* dp = &bncl_dpipes[msg->dpipe_id];
    if (dpipe->state != DPipe::ReapDaemon) {
        // then this is being released by the client.. ignore and return
        return;
    }

    // ensure that this dpipe is wired to its slot in smap_daemon
    // this depends on whether DPipes are created up-front with their
    // socketpair invocation, or if file descriptors are allocated on
    // demand. But it's irrelevant for this function
    ensure_dpipe_connected(dp);

    // now write some data on the socket    
    write_dummy_bytes(dp->daemon, dummy, dummylen);
}


// example I/O function of e.g. OConn::interceptContinue()
bool OConn::interceptContinue() {
    DPipe* dp = getDpipe(); // class member, assuming..

    // invoke the actual recv first

    auto rv = recv(getFileDes(), ....);

    if (dp->state == DPipe::Busy) {
        // read data as normal, handle logic flow..
    }
    else if (dp->state == DPipe::ReapDaemon) {
        // release this DPipe right now
        setsockopt(getFileDes(), SOL_BNCL, SO_BNCL_UNSPLICE, &dp->dpipe_id, 4);

        // state transitions 
    }
}
```

#### Crash Scenarios

Part of the purpose of queues is to allow orderly flow of operations when either
an agent or a daemon crashes. By having state be part of the BPF Arena rather
than application-local memory, we enable deterministic behavior that's
data-driven.


##### Client/Agent Crash

If a client or agent crashes, the daemon needs a way to know that any DPipes
being used by the agent's sockets are now free. This requires us to hook on
to close events in the Agent's process.

```c++
SEC("fentry/inet_release")
int BPF_PROG(on_inet_release, struct socket *sock) {
    if (!sock) {
        // no socket..
        return 0;
    }
    // checks if it has sk_storage and then unsplices it..
    bncl_close_agent_sock(sock);
}
```

##### Daemon Crash

If a daemon crashes, we need to mark it as unusable to the Agent (via changing
the state). Because we create these sockets, we can install a sockops program
on them to observe them when they crash. This allows us to quickly send data
back to the client to 'wake up' the potentially stuck sockets, notifying them
of the error (via dpipe->status)

```c++

struct bncl_daemon_dpinfo
{
    __u32 dpipe_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct bncl_daemon_dpinfo);
} bncl_map_dpinfo SEC(".maps");



SEC("sockops")
int monitor_daemon_close(struct bpf_sock_ops *skops)
{
    if (!skops->sk)
    {
        // no socket..
        return 0;
    }
    if (skops->op != BPF_SOCK_OPS_STATE_CB || skops->args[1] != BPF_TCP_CLOSE)
    {
        // normal handling
        return 0;
    }
    
    // otherwise, CAS the socket's state..
    struct bncl_daemon_dpinfo dpi = bpf_sk_storage_get(&bncl_map_dpinfo, skops->sk, 0, 0);
    if (!dpi)
    {
        // i.e. no ID found?? just pass.. it's not our socket, somehow..
    }
    
    DPipe *dp = &bncl_dpipes[dpi.dpipe_id];
    
    // switch state atomically from busy to ReapDaemon -- state can also be
    // ReapClient, which implies ReapDaemon, and will be picked up during the
    // next instantiation of the daemon.
    old_st = CAS(&dp->state, DPipe::Busy, DPipe::ReapDaemon);
    if (old_st != DPipe::Busy)
    {
        // so it's not a stuck client, we don't need to put it inside the queue
        // return ....
    }
    
    bncl_reqpq_daemon_msg msg { dpi.dpipe_id };
    bpf_ringbuf_output(&bncl_reapq_daemon, &msg, sizeof msg, 0);
    
    // fill in the blanks..
}
```

#### Examples

##### Normal Flow

Shows the typical lifecycle of allocating a DPipe, using it for data
transmission, and then releasing it.

```
# Sent the command for splicing
Client: SPLICE(SCM_RIGHTS, {fd=100}))

# Server responds with dpipe to release. Client fd=100 is bound
# to dpipe 0xfdd
Server: SPLICE({status=OK, dpipe=0xFDD})

# Client requests cache for statement
Client: send(fd=100, {cmd=CACHE_GET, stmt=SELECT...})
Server: recv(dpipe=0xfdd, {cmd=...)

# server checks valkey cache and responds with data
Server: send(dpipe=0xfdd, {status=OK, rows=xxxxx})

# meanwhile, the client is waiting for the response 
Client: poll(fd=100,...) => POLLIN(fd=100)

# fd=100 becomes ready, intercepted recv_wrapper (see above) is active
Client: recv(fd=100, buf, nbuf, MSG_NOWAIT) // read loop

# Client checks the state of the DPipe, if it's not Busy (i.e. not
# assigned to us, then the data is garbage and the client should restart
# the query state machine.

DPipe *dp = &bncl_dpipes[0xfdd];
if (dp->status != DPipe::Busy) {
    release_dpipe();
    restart_query();
} else {
    process_row_data(buf, nbuf);
}

# finally the client 
Client: setsockopt(fd=100, SOL_BNCL, BNCL_CTL_UNSPLICE, dpipe=0xfdd);
```

##### Server/Daemon Crash

In this scenario, the agent leases a DPipe, but the server crashes while the
client is holding the lease.

We demonstrate the crash handlers and daemon reaping workflow.

```
Client: SPLICE(SCM_RIGHTS, {fd=100})
Server: SPLICE({status=OK, dpipe=0xfdd})
Client: send(fd=100, {cmd=CACHE_GET, stmt=whatever})
Server: recv(dpipe=0xfdd, {cmd=xxx})
Server: send(dpipe=0xfdd, {...}) // partial data
Client: poll(fd=100) // waiting for more server data

[** BOOM ** SERVER CRASH **]

Kernel: monitor_daemon_close(sk) {
    daemon_dpinfo = bpf_sk_storage_get(&bncl_map_dpinfo, sk, 0, 0)
    
    // bncl_dpipes is part of global BPF memory
    DPipe *dp = &bncl_dpipes[daemon_dpinfo.dpipe_id];
    
    old = atomic_compare_and_swap(&dp->status, DPipe::Busy, DPipe::ReapDaemon);
    if (old == DPipe::Busy) {
        // submit into the queue
        bpf_ringbuf_output(&bncl_reapq_daemon, msg={dpipe_id=daemon_dpinfo.dpipe_id});
    } else {
        // if status == DPipe::Free then no cleanup is required
        // if status == DPipe::ReapClient then the client is no longer
        // waiting for us
    }
}
 
[ Watchdog/Cron/Admin Process restarts the daemon]

Server: Iterate through items in bncl_reapq_daemon, calling
    DaemonReapQueue::handle_message(). This function sends a single byte to
    wake up the attached client -- but only if the state is still ReapDaemon.
    If the client already signalled a close (i.e. state is ReapClient or Free),
    then it means the client has released the dpipe and is no longer using it
    or awaiting I/O on it, and has submitted it to bncl_reapq_client

Server: send(dpipe=0xfdd, &c, 1, ...)

# Client waits for read-readiness on the socket:
    client receives notification about a readable socket, and inspects the state
    if state == ReapDaemon, it ignores the read buffer and advances the state
    to ReapClient. Note that it is impossible for a client to receive a socket
    in a state of ReapClient, because ReapClient itself is only ever set by the
    client relase handler.

Client: poll(...) = POLLIN(fd=100)
Client: {
    DPipe *dp = getDPipe(fd);
    if (dp->state == DPipe::ReapDaemon) {
        setsockopt(fd=100, SOL_BNCL, BNCL_CTL_UNSPLICE, key=dpipe_id);
        // This unsplices the socket immediately (at least in effect, by
        // allowing normal traffic to resume
    }

```

##### Client/Agent Crash


```
Client: SPLICE(SCM_RIGHTS, {fd=100})
Server: SPLICE({status=OK, dpipe=0xfdd})
Client: send(fd=100, {cmd=CACHE_GET, stmt=whatever})
Server: recv(dpipe=0xfdd, {cmd=xxxxx})
Server: send(dpipe=0xfdd, {rows=xxxxx})

[** BOOM ** CLIENT CRASH **]

Kernel: fentry/inet_release is called, which calls into bncl_close_agent_sock()
    which scans the skinfo and then does the UNSPLICE command just as the client
    would have. The state is set to ReapClient, and the daemon never knows
    the difference.
```


#### Infrastructure Assumptions and Directives

1. Daemon will always be available/restart through some watchdog process,
    i.e. there is a reaper process. Without a watchdog ensuring the reap queues
    are indeed reaped, clients can become stuck and/or DPipes can become
    exhausted.

2. Agent *must* have a way to repeat the original statement until all the rows
    have been delivered up to the client application. Otherwise, we have no way
    to retry the operation if there is a daemon crash while holding a DPipe

3. BPF structures are universally accessible by the daemon, kernel, and agent.
    We will explain in a different section how these are made available

4. Synchronization -- there must be a way to synchronize operations on a
    single DPipe, because we may end up in a scenario where both client and
    server are trying to modify its state. In theory, things like atomic
    compare-and-swap operations should be sufficient.

5. We don't care about any data sent between client and daemon in the case of 
    an error: it's all restartable anyway.

6. Only the daemon is able to create DPipe leases and manage the DPipe freelist.


## Shared Arena Contents

In addition to the BPF map, there is also a shared memory segment that is
available to all components of the Barnacle system, and contains the following:

- Configuration
- Statement Configuration
- Statement State (i.e. data, timestamp, and so on)
- DPipe Array (the actual DPipe object)
- DPipe Freelist
- Daemon State (TBD)

## Bootstrapping

Here we clarify how an agent connects with the daemon in the first place. As
specified in the beginning, the agent is *injected* into the client application.

The outline of bootstrapping uses a push-and-pull model:

1. The daemon pushes the injectable code (the agent) into the client
2. The agent creates an fd and publishes the fd in a specified memory location
3. The daemon reads the memory location and connects to the published fd



##### Agent structure and initial bootstrap

- **Command**: `CONTROL_HELLO(0x01)`
- **Channel**: Control
- **Data**:
    - Various BPF file descriptors
    - Agent ID (only if this cannot be passed with the initial injection function
      TODO: -- check if we can set the Agent ID at establishment time rather than
      through this protocol???)


```c++
struct bncl_ipc_ctrl {
    // Holds local and remote ends of the socket.
    // TODO: the local end doesn't need to be here, because it doesn't
    // need to be visible by the daemon process.
    int sock[2];
    
    // Used as a way to externally enable / disable 
    int enabled = 1;
};

extern struct bncl_ipc_ctrl bncl_ctrl_g = {{-1,-1}, 1};

#define BNCL_CTRL_SOCK_AGENT 0
#define BNCL_CTRL_SOCK_DAEMON 1

struct {
    int agent_id = -1;
} bncl_agent_info;

struct CtrlSockMgr {
    enum Type {
        Agent = BNCL_CTRL_SOCK_AGENT, Daemon = BNCL_CTRL_SOCK_DAEMON
    };
    static int agent() { return bncl_ctrl_g[Agent]; }
    static int daemon() { return bncl_ctrl_g[Daemon]; }
    static void close(Type type) {
        close(bncl_ctrl_g.sock[type]);
        bncl_ctrl_g.sock[type] = -1;
    }
    
    int create() {
        return socketpair(AF_UNIX, SOCK_STREAM, bncl_ctrl_g.sock);
    }
};

// It is initialized like so:
void bncl_agent_channel_init(int agent_id) {
    bncl_agent_info.agent_id = agent_id;
    
    // ....
    if (0 != CtrlSockMgr::create()) {
        assert(0 && "couldn't establish channel!");
    }
    
    // then agent sends the hello command. The command can be sent even before
    // 
    send(CtrlSockMgr::agent(), buf={HELLO(0x01)};);
    
    // Note that this function must return if we are invoking this synchronously
    // -- the agent must read the daemon response, but we do this in a different
    // thread of control
    spawn_hello_reader();
}

```

The control section is injected into the target client application, and then
invokes `bncl_agent_channel_init()` which itself creates a pair of
UNIX sockets and issues the initial HELLO command. It then spawns another
thread which awaits and reads the server's response.

The Control Section agent keeps one end of the sockets, and the
injector (daemon) takes a handle from the other end, using pidfd_getfd.

> Note, in the actual implementation, agent_channel_init() might be called
> through a general wrapper function, e.g. agent_init() in case other
> initialization needs to take place.


Implementation of the wait thread

```c++
static pthread_t bncl_hello_reader_thread;
void *bncl_hello_reader() {
    struct msghdr msg;
    // read message from server
    recvmsg(CtrlSockMgr::agent(), msg, ...);
    
    // extract the fds passed via SCM_RIGHTS (see daemon impl for the format)
    extract_fds_from_msg(msg);
    
    // if we don't close this, then the control channel might remain open while
    // the daemon crashes. if the control channel remains open, we end up
    // hanging and not being able to reconnect to the new daemon.
    CtrlSockMgr::close(CtrlSockMgr::Daemon);
}

void spawn_hello_reader() {
    pthread_create(...&bncl_hello_reader_thread, bncl_hello_reader);
}
```


##### Daemon Hello Response

The daemon polls and probes the address of `bncl_ctrl_g` in the client binary
until it contains a non-`-1` value for `sock`, and then attempts to connect to
it. Once connected, it sends a hello message to the client:


This is the implementation of the response handler
```c++

enum class BPFMapTypes : uint32_t {
    Arena = 0, // shared memory space
    ReconnectQueue = 1, // for reconnections..
    // there may be more..
};

class HelloResponse {
public:
    HelloResponse() {
    }
    void addFD(BPFMapTypes type, int fd) {
        // append type to fdtypes
        m_fdtypes.append((uint32_t)type);

        // update iov
        m_iov.iov_base = (void*)m_fdtypes.data();
        m_iov.iov_len = sizeof(uint32_t) * m_fdtypes.size();

        // change the message header buffer to ensure there's enough space:
        auto new_size = CMSG_SPACE(m_fdtypes.size() * sizeof(int));
        
        m_hdrbuf.resize(CMSG_SPACE(m_fd), new_size);
        m_msg.msg_control = m_hdrbuf.data();
        m_msg.msg_controllen = m_hdrbuf.size();
        
        // now append the FD
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&m_msg);
        const char* begin = CMSG_DATA(cmsg);
        auto head = begin + ((m_fdtypes.size()-1) * sizeof(int));
        memcpy(head, (void*)&fd, sizeof(int));
        
        cmsg->cmsg_len = CMSG_LEN(m_fdtypes.size() * sizeof(int));
    }
    
    const struct msghdr* msg() const {
        return m_msg;
    }
    
private:
    struct msghdr m_msg = {0};
    struct iovec m_iov;
    
    // message header buffer
    std::vector<char> m_hdrbuf;
    
    // message payload
    std::vector<uint32_t> m_fdtypes;
};

void Daemon::negotiateAgent(pid_t agent_pid) {
    int pidfd = pidfd_open(agent_pid, 0); // check errors etc
    
    // find the offset of the symbol using /proc/${agent_pid}/maps
    // or similar -- i.e. based on the loaded address of the .so
    // and the offset of its bncl_ctrl_g symbol
    uintptr_t ctl_g_addr = find_ctl_offset(agent_pid);
    
    int ctlfds[2] = {-1,-1};
    struct iovec local_iov, remote_iov;
    local_iov.iov_base = ctlfds;
    local_iov.iov_len = sizeof(ctlfds);
    
    remote_iov = local_iov;
    remote_iov.iov_base = ctl_g_addr;
    
    // loop while we don't have an FD..
    // in real code we'd use a timeout to ensure we don't block indefinitely
    // in the case of error
    while (ctlfds[DAEMON_FD_INDEX /* i.e. = 1 */] == -1) {
        int rv = process_vm_readv(agent_pid, local_iov, remote_iov);
        // check rv...
        if (rv == sizeof(ctlfds)) {
            // ERROR!!
        } else {
            break;
        }
    }
    
    // At this point, we also set the agent's task storage
    
    // Once we have an FD, we setup the msghdr and cmsghdr to send over
    // the SCM_RIGHTS object alongside other data
    
    // the type and number of BPF file descriptors (and other file descriptors)
    // send in this initial mesage are specified elsewhere, and not within scope
    // of this document.
    
    // first, pidfd_getfd
    agent_fd = pidfd_getfd(agent_pid, ctlfds[1]);

    FDSender resp;
    resp.addFD(BPFMapTypes::Arena, arena_fd);
    resp.addFD(BPFMapTypes::ReconnectQueue, reconn_queue_fd);
    resp.setAgentId(agent_pid);
    
    // does the encoding and so on.
    sendResp(agent_fd, resp);
    
    // once done, the agent_fd is monitored for future requests
}

#define BNCL_AGENT_INIT_FUNC "bncl_agent_channel_init"
#define BNCL_AGENT_SOCKPAIR_SYM bncl_ipc_ctrl

void Daemon::attachToClient(pid_t pid) {
    auto agentBlob = getAgentBlob();
    auto rv = attachAgent(pid,
        agentBlob, // todo: is this a path? fd? blob?
        BNCL_AGENT_INIT_FUNC, // name of function
        pid /* as an argument to the the init function */);
    if (!rv) {
        // handle error...
    }
    negotiateAgent(pid); // 
}
```

### Reconnection

When a daemon crashes, its control connection crashes too, and clients lose the
ability to request new splices or perform other data plane operations. In order
to allow client recovery when a new daemon arises, it notifies the new dameon
(via a queue) of the desire to establish a new communication channel.

The name of this queue is `bncl_agent_reconn_queue`

```c++
struct bncl_agent_reconn_queue_msg {
    // This is the agent ID as passed during the initial bootstrap phase. It
    // never changes throguhout the life of the client process.
    int agent_id;

    // The daemon-end of the socketpair(2) call, used to avoid probing the
    // memory space again
    int pipe_fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096); // only one per agent!
} bncl_agent_reconn_queue SEC(".maps");
```

Here are the steps in detail:

1) Agent re-creates the control channel pipes via `socketpair(2)`
2) Agent places socketpair fds in `bncl_ctrl_g.sock[]`
3) Agent writes the message to `reconn_queue`, the message contains the
   agent ID and the pipe FD.
4) Agent writes a `RECONNECT(0x03)` message to its end of the pipe. There is no
   body to this message. Since this message is small, it is safe to write
   without blocking.
5) Agent begins listening on the agent-side of the socket pair.
6) Daemon consumes the queue message, using the message fields as parameters
   for `pidfd_getfd(msg.agent_id, msg.pipe_fd)`
7) Daemon responds with a `OK(0x01)` message indicating that the agent is now
   reconnected to the control channel. Sockets may be spliced through it once
   again.

Note that the various BPF maps do _not_ need to be reestablished because they
are owned in the _kernel_ and not inside the _userspace_ Daemon process.

Here is an example of the reconnection process

```c++

void Agent::reconnect() {
    CtrlSockMgr::close(CtrlSockMgr::Agent);
    CtrlSockMgr::close(CtrlSockMgr::Daemon);
    
    int rv = CtrlSockMgr::create();
    // check RV
    
    bncl_agent_reconn_queue_msg msg {
        bncl_agent_id,
        CtrlSockMgr::daemon()
    };
    bpf_ringbuf_output(&bncl_agent_reconn_queue, &msg, sizeof msg, 0);
    
    // write the message to our end:
    send(CtrlSockMgr::agent(), {cmd=RECONNECT});
    
    // at this point, the agent now listens
    // NOTE: this is pseudo-code, the implementation should use a time-bounded
    // waiting mechanism to ensure it never hangs
    nr = recv(CtrlSockMgr::agent(), {status=OK});
    CtrlSockMgr::close(CtrlSockMgr::Daemon);
    
    // once this is done, we have no more work to do on the agent end..
}
```

```c++
void Daemon::handleReconnect(const bncl_agent_reconn_queue_msg& msg) {
    auto pidfd = pidfd_open(msg.agent_id);
    auto dfd = pidfd_getfd(pidfd, msg.pipe_fd);
    recv(dfd, {....}); // we don't actually care what this message says, for now
    send(dfd, {status=OK}); // respond ok
    
    // dfd is now monitored for further control messages as part of the regular
    // program flow.
}
```

### Fork Handling and PID Mapping

When a process forks, its file descriptors (sockets and all) remain in-tact,
but this won't work for us -- the control socket is used to splice connections
and if this socket is shared, we end up with multiple clients sending messages
at the same time and not receiving the proper responses and DPipe IDs. In short,
every agent-client-pid must have its own reliable and synchronized mode of
communication with the daemon.

In order to solve this, we must treat child processes as independent objects
receiving their own agent ID, distinct from their parents' agent ID.

When daemon attaches the barnacle on a PID, it sets the agent ID in the
`BPF_MAP_TYPE_TASK_STORAGE` which is associated with the process.

```c++
struct bncl_proc_agentid_info {
    int dummy;
};

// this is the task-specific storage associating an agent id with a process
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct bncl_proc_agentid_info);
} bncl_proc_agentid_map SEC(".maps");

// this map associates the agent id with the PID. This is not exported to
// the agent, and is used only by kernel functions and by the daemon process.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // agentid
    __type(value, __u32);  // global PID
} bncl_agentid_pid_map SEC(".maps");
```

Future calls to `fork()` for this process are intercepted (either via a BPF-level
trace, or via a `pthread_atfork()` handler, TBD).

The fork handler does the following in the child:

1. Set `bncl_proc_agentid_map[child]` to an empty value (e.g. -1)
2. Close the sockets in `bncl_ctrl_g.sock[]` and sets them to `-1`

Next time the child process tries to get the control socket, it will realize
it doesn't exist and will try a reconnect, acquiring an agent ID, using the
following:

```c++
// we need this socketpair anyway..
socketpair(AF_UNIX, SOCK_STREAM, bncl_ctrl_g.sock);

// this generates an agent id for the given process..
uint32_t agent_id = -1;
getsockopt(bncl_ctrl_g.sock[0], SOL_BNCL, SO_BNCL_AGENTID, &agent_id);
bncl_set_agent_id(agent_id);
```

```c++
// fexit -- or whatever
int bncl_getsockopt(struct bpf_sockopt* ctx) {
    if (ctx->level != SOL_BNCL || ctx->optname != SO_BNCL_AGENTID) {
        // forward to normal handling
    }
    if (!bncl_proc_agentid_map[self]) {
        // if there is nothing stored in task storage then this
        // process is not authorized to get an agentid. we don't know how this
        // would be called, but we bail here..
    }
    
    // ignore the socket, generate the agentid
    if (bncl_proc_agentid_map[self] != -1) {
        // not a placeholder and not 0
        return bncl_proc_agentid_map[self];
    } else {
        // 
        agentid = ++bncl_agentid_serial;
        bncl_proc_agentid_map[self] = agentid;
        bncl_agentid_pid_map[agentid] = global_pid();
        // write it in the PID map as well..
    }
    *ctx->optval = agentid;
    return 0;
}
```

When a process exits, a hook should check if it has task storage, and if it
does, get its agent id and delete it from the `agentid_pid_map`


#### Agent ID and PID Mapping


In earlier versions of this document, we said that the agent ID would be the
global PID as visible from the daemon process, but this is in fact a security
risk -- as we would be leaking details that the process would normally not know
about itself. Instead, we use an abstraction, an agent ID, which is a
monotonically increasing counter, that maps to the daemon-visible process ID
inside a BPF map that is *not* exported to the agent.


## Timeouts and Error Handling

Every instance of the agent waiting for the daemon introduces a potential
for a stuck client. Therefore, none of these operations should be unbounded by
time.

Further discussion is needed on the model of enforcing these timeouts. BPF
mechanisms exist for creating timers, but timers are only useful if they can
un-stick hung clients, and hung clients can only be unstuck by sending I/O
on their sockets, something that BPF does not directly allow, but can be done
indirectly using a userspace helper.

Is this enough? I don't know. The whole point of making a BPF timer in the first
place is to sidestep the possibility of a hung userspace helper, and if we're
forced to use userspace helpers, then we might as well make the timers
themselves completely within the daemon.

The topic of timeouts also leads to configuration options

## Monitoring and Interception

Barnacle only monitors a subset of network connections. Obviously, not _all_
connections are for SQL databases, so we rely on the administrator to tell us
which ports, or which host:port destinations are to be monitored.

It may also be possible to do this heuristically, through another set of BPF
functions and a helper process -- traffic can be monitored for a period and,
using the send/recv break algorithm we described above, determine which socket
streams can be parsed as MySQL protocol messages.

The common case however, is to use 2 or 3 filtering parameters:

**process**, **port**, and **host**

The process is the process name, exposed either via `procfs` for already-running
processes, or via `exec(2)` for newly-created ones. The process name can be
specified as a path to a binary and/or matching a regular expression.

The host and port options filter which outbound hosts and which outbound ports
should be monitored for MySQL connections.

While heuristics are possible, for the time being it is not implemented, and
the process+port options should be mandatory.

The daemon should **continually** monitor procfs for newly spawned processes, so
that it can attach to them, if needed. At any given point in time, _all_
processes that match the expression or parameters should be tracked by the
daemon. I do not know the ideal way to do this, whether it should be done by
continually polling procfs, or using some kind of notification mechanism via
BPF, this is a TODO.

## Configuration Options

Barnacle is designed to be zero-config, but it should be configurable and
tunable in case the defaults are insufficient.

The config file format is ini-style, organized into different sections, though
this can change if we find another format to be more amenable.

#### Interception Options

- **Section**: `[hijack]`

##### `intercept_port`

- Internal name: `BNCL_CFG_INTERCEPT_PORT`
- Meaning: only intercept sockets connected to this destination port
- Default: 3306

##### `intercept_host`

- Internal name: `BNCL_CFG_INTERCEPT_HOST`
- Meaning: only intercept sockets connected to this destination host
- Default: <none>

##### `intercept_cli_re`

- Internal name: `BNCL_CFG_INTERCEPT_CLI_RE`
- Meaning: only intercept processes matching this command line. Uses POSIX RE
- Default: <none> (also, required)

#### Valkey Options

- **Section**: `[valkey]`

These options are required for the cache, and tells the daemon how to connect
to Valkey

##### `valkey_uri`

- Internal name: `BNCL_CFG_VALKEY_URI`
- Meaning: `scheme://user:password@host:port` connection string for valkey.
  `scheme` can either be `valkey` or `valkeys` for plain or TLS connections.
- Default: `localhost:6379`

##### `valkey_db`

- Internal name: `BNCL_CFG_VALKEY_DBNUM`
- Meaning: the Valkey database to use (e.g. 0, 1, 2)
- Default: `0`


#### Connection Tracking Options

- **Section**: `[connections]`

These options control how Barnacle traces and interprets connections between
the client and origin server. These options can be tuned to improve performance
or fix bugs.

The default setting employs heuristics to figure out the 'right' mode, but these
heuristics require analyzing a small amount of traffic flowing between Client
and Origin Server. That small traffic may contain queries that could have
otherwise been cached.

##### `no_txns`

- Internal name: `BNCL_CFG_NO_TXNS`
- Meaning: application never issues transactions, so don't track them
- Default: `false`

By default we assume that transactions are performed and don't get items from
cache unless we are certain (via a protocol message) that no transactions
are being performed. Often times this means needing to track the reply from
the server, costing an extra query that could have gone through the cache.

##### `trans_proto`

- Internal name: `BNCL_CFG_TRANS_PROTO`
- Meaning: What transport protocol is used between client and origin server.
  Possible values are:
  - `tls`: SSL/TLS is always used, no need to analyze plain `send` or `recv`
  - `plain`: plain/clear (i.e. non-TLS) is always used, no need to override
    `SSL_*`: functions
  - `auto`: Automatically detect the type of transport being used
- Default: `auto`. You can change the value in order to save some network bytes


##### `track_new`

- Internal name: `BNCL_CFG_TRACK_NEW`
- Meaning: Only track new connections from their point of `connect(2)`. Don't
    analyze untracked connections from their `send` or `recv` calls unless 
    they had previously been tagged and assigned their relevant `SK_STORAGE`
    structures at connection.
- Default: `false`. Connections are tracked greedily by default.


#### Resource Usage Options

- **Section**: `[resources]`

##### `dpipes_max`

- Internal Name: `BNCL_CFG_DPIPE_MAX`
- Meaning: Maximum number of DPipes allocated. This limits the number of
  simultaneous queries that can go to the cache
- Default: TBD

##### `dpipe_splice_timeout`

- Internal Name: `BNCL_CFG_DPIPE_SPLICE_TMO`
- Meaning: How long to wait on the control socket for a splice request before
  giving up
- Default: 100ms

##### `dpipe_cache_get_timeout`

- Internal Name: `BNCL_CFG_DPIPE_CACHE_GET_TMO`
- Meaning: How long to wait for Barnacle to retrieve the rows from the cache
- Default: 1s

##### `cache_readthru_timeout`

- Internal Name: `BNCL_CFG_CACHE_READTHRU_TMO`
- Meaning: How long to wait for the elected cache read-thru agent to return
  with rows before electing another reader.
- Default: `dpipe_cache_get_timeout * 2`


## `LD_PRELOAD` and Filesystem Mode

While the more flexible deployment mode of Barnacle is simply to attach an agent
to a client process via `ptrace` and binary injection, this requires the ability
to rewrite the binary in memory at runtime. Though this is perfectly safe and
the rewrites are visible within the codebase, it may not be acceptable to some
deployments, and may at times conflict with other tools that perform their own
rewrites, and/or malfunction if debuggers are being used.

The `LD_PRELOAD` provides a different mode of deployment. Rather than rewriting
code at runtime, the Barnacle is deployed pre-loaded as a part of the client
application itself.

In this mode, the daemon does not use `pidfd_getfd`, but rather publishes a
Unix socket in a filesystem. This unix socket exists at a fixed path specified
by the administrator, and must be accessible by both the `bncld` container
and the client container. This may involve modifying command line arguments,
mount points, and so on, violating Barnacle's zero-config guarantee, so you're
on your own here 😉

In this mode, the client connects to the published UNIX socket, and the server
listens on it.

## Controller Process & Deployment

This section describes the tools used to deploy and manage barnacle:

- `bncld` is the server/daemon process
- `bncl_watchdog` is a lightweight watchdog process that restarts `bncdl` 
- `bncl_agent.so` is the barnacle agent
- `barnacle` is the front-end and controller
- `bncl.conf` is the config file

### `barnacle`

This is the front-end and entry point for managing all Barnacle systems. It
can be implemented in Python, though maybe we should write this in a language
like Golang (so it actually compiles?).

It communicates with `bncld` using an admin protocol, which is not the same
as the control protocol that exists between agent and server.

The admin protocol is over an admin socket -- this admin socket being either
Unix or TCP (i.e. local or remote). TODO: figure out an ideal default location
for such a control socket.

##### `up`

Start the server. Has no effect if the server is already started.

Options:

- `--monitor=<on|off>`: attach to and monitor processes that match
  the configuration
  - Default: `on`. If disabled, then the server won't do much, but it's useful
    for tests and so on.

##### `down`

Stops the server. Has no effect if the server is already down


##### `reload`

Reloads the configuration


##### `monitor <on|off>`

Turn monitoring on or off. This does not affect existing processes that have
had a barnacle agent attached to them

##### `attach [pid]`

Attach agent. Without a PID argument, scans all processes (as a one-off) and
attaches the barnacle to all matching PIDs. If a PID is specified, then the
agent is deployed to this PID.

##### `detach [pid]`

Deactivates agent for all running processes, or for a specific process. This
works by modifying the `enabled` field in the per-agent configuration for all
active agents.



V. Memory/Process Model

All structures I've outlined here so far are universal to all processes. This can be
accomplished using BPF arenas and other BPF types that are mapped using BPF arenas.

One thing that remains to be determined is synchronization models, but simple atomic
counters + spinlocks should be sufficient here, since there is no real heavy
processing or blocking.

~~~~~~
Configuration options:

OPT_NO_TXNS:
    assume there are no transactions

OPT_TRACK_NEW:
    only track new connections (seen via connect()), don't try to monitor/diagnose existing connections
    this simplifies the logic somewhat, at the expense of having little effect if the client was recently
    attached.

~~~~~~

Possible scenarios/flows. We will assume OPT_TRACK_NEW here.

kprobe on connect(2)
see if the socket connects to a port of interest; if so, mark it, and if not, mark it as irrelevant
we don't do anything until protocol etc is negotiated. We also trace SSL_connect and/or SSL_send.
If those calls are in the call stack, we mark the socket as SSL, but only check the call stack
as long as the connection type is unknown

TODO: Most efficient way to tag/mark a socket in userspace?

query request/response is normal; we only monitor the query response to see if a txn is active or not.
if there is no txn flag in the response, we can know definitively that there is no txn active locally.

we don't need to buffer the entire response.. just maintain state so we can parse the stream.

When we encounter a request that DOES match our criteria, we must:

1) save the request query text itself (in userspace)
2) grab an available agent_pipe, remove it from the free list, assign the connection,
   and so on.

3) wakeup_daemon(key) is called.. see above for possible implementations.

now, on the CLIENT:

    - mark the socket's state (on the client end) as communicating with the agent.
     while in this mode, the bpf program does not reroute up the stack, but waits
     for a response from the userspace daemon. During this point, we also must
     capture raw recv/read events, EVEN if ssl is active

    - set up a timer in the client, to protect against malfunctioning agent.. if
     the agent is not responsive within a certain time frame (let's say 100ms)
     then we simply release the dpipe handle, and relay the original
     request buffer to the server, and continue as if nothing ever happened. In order
     for the timer to work, we probably need to do some kind of garbage collection

    - await the status code from DAEMON (see daemon flow for details)

on the DAEMON:

    - read the key from ch_assign; look at the internal statement structure and
      determine caching state.

    - there are three possible states, indicated by status codes:
        - 0xff: CACHE ERROR. For some reason, the cache is unreachable; this statement or this server
                should be ignored for OPT_ERROR_TTL time and the response should flow as normal
        - 0x01: OK. The local cache has the data; the exact number of bytes will follow,
                after which the socket should be unmapped.

        In the interest of simplicity, the response is 4 bytes, followed by whatever payload, etc
