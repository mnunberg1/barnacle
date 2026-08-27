Goals:

The goal of this project is to provide a transparent injectable cache that
can accelerate query times for administrator-selected queries.

This cache would require almost no configuration other than the list of
queries to cache, and the cache ttl.

Operation:

The operation is dependent largely on the kind of input protocol employed; but
as a general rule, our transparent cache intercepts the query at some layer,
checks to see if it's a cacheable query, whether it exists in the cache,
retrieves the response, and relays it to the client.

For queries that are not in the cache list, the client continues to function
as normal.

Connection Model:

Most outbound database connections use TLS of some sort. Outbound TLS packets
are somewhat cumbersome to decrypt, and inbound TLS packets are impossible to
tamper with (this is by design), so any solution overriding/intercepting
TLS-based communication must either replace the TLS stack entirely OR must
short-circuit the TLS stack so that a protocol packet is never encrypted.

Short-circuiting the stack is preferred since eliminates having to
make dedicated outbound connections, which itself would require the host
to know the location of the destination server, in addition to having its
own route to it (which is not a given!)

Caveats:

cannot be static; even if we observe a cachable query, we must NOT
employ caching when a transaction is active, as it may compromise
application and state integrity.

There may be more


Implementation:

I. Socket Tracing

Each database protocol must have its own implementation; we'll start
with MySQL because it's a well known synchronous protocol.

For starters, we must determine if the outbound connection is plain-text
or SSL; we can do this using heuristics -- we begin at the send/recv layer
and find a boundary, i.e. a recv after a send or a send after a recv.

Because MySQL does not support pipelining or multiplexing, we can
guarantee that a send after a recv (or vice versa) is the beginning of
a new L7 message. If this message decodes properly as MySQL then it's
plain text; otherwise we assume it's TLS and move over to more expensive
handling via SSL_read/SSL_write, or equivalent entry points.

So we have essentially two modes; plain text (where we intercept at send/recv)
or TLS mode (where we intercept at SSL_write/SSL_read). Even in plain
text mode, we must monitor for the point at which the connection is
upgraded to TLS. Plain text can morph into TLS, but TLS can never be
downgraded to text.

Now, we will need to check/trace the state of every single seen connection
monitoring for the following:

Type: [SSL|PLAIN|UNKNOWN]
Txn: [YES|NO|UNKNOWN]
Mode: [WAIT|PASSTHROUGH]
Last: <timestamp>

If type or txn are unknown, then we enter heuristic mode. For TXN, the server
responds with a certain flag, SERVER_STATUS_IN_TRANS, if a transaction is
active.

Mode is how we are processing the socket's I/O, explained in the next section

Sockets are to be traced until they are close(2)'d or shutdown(2)

II. Packet tracing/assembly

We cannot assume that every call to send(2) contains a fully formed
packet, nor can we assume that every call to recv(2) receives a
fully formed response. We need to buffer the packet until we can make a
decision. On the write end, we need to see if the statement is one to be
filtered, and on the read end, we need to extract the fully formed response
(so maybe we can cache it??)

Because the MySQL protocol has a predictable send/recv flow, the moment
we detect a query that doesn't / shouldn't be cached, we simply allow that
query's response to be forwarded directly to the client without any
additional logic -- but only after one specific step. The server response
must be scanned/analyzed for any hint/implication of being in a
transaction -- in which case the entire cache mechanism is bypassed.

III. Cache handling

In the event that a query is encountered (after the request itself has been
fully parsed), our program must delegate handling to the userspace agent,
which is responsible from fetching the data from the cache. At this point,
the client application must be paused and wait for I/O, somehow.

Because there is no pending request, recv() should naturally hang; but at
some point, it will need to be written to with the response.

When it needs to retrieve data from the cache, three states are possible:

1. Response data is in the LOCAL cache and can be returned instantly
2. Response data is in the REMOTE cache and needs to be fetched
3. Response data is not present, and needs to be re-generated from the DB

If the response data is in the LOCAL cache, the BPF program can simply return the
local cache.

If the response data is in the REMOTE cache, the BPF program will need to
instruct the userspace daemon to fetch results from the cache. During this
fetch period, any requests for this query will need to BLOCK until the
result is returned.

If the response data is not in the REMOTE cache, then exactly ONE client
application will fetch the data and response. The rest of the client
applications that are executing this query will need to BLOCK until
the result is delivered. When the response arrives from the server,
it should be written into the CACHE by the userspace daemon agent.

IV. States, data structures, components, and so on

This outlines the core components to be used in our application; these
are outlined in no particular order

- Client [client]

This is the component that executes within the program. The client component
is divided into two components, the UCLIENT (userspace client) and KCLIENT
(kernel/eBPF client)

The UCLIENT contains most of the parsing and state handling logic, since it
is only here that we can fully parse the socket, aggregate buffers, and have
true local application context.

The KCLIENT contains the low-level code that performs the socket redirect,
and perhaps some other functionality. We will keep most things in the
userspace level because we're keeping track of local parse/buffer context
and most likely, TLS/SSL, which is impossible to do at the kernel level

[TODO: check if/how kTLS can be employed]

- Statement Map [stmts_map]

This is the global map shared by all clients and the userspace agent; it
is a map (actually, a prefix trie) of statements to a stmt structure;

struct stmt {
    const char *stmt_txt; // statement text
    size_t stmt_len; // size of statement text
    uint64_t stmt_ts; // last updated
    enum stmt_state stmt_state; // status of the statement
    void *stmt_data; // data of the statement;
    uint32_t stmt_id; // universal id
    // some kind of rwlock equivalent for synchronization
};

enum stmt_state {
    STMT_S_LOCAL, // statement is present locally, return immediately with buffer context [but see below]
    STMT_S_PENDING, // statement is pending result. client must wait on result
    STMT_S_ERROR // cache has an error, pass-through
};

- Socket Structure [conn_info]

We referenced this before, but it's

Type: [SSL|PLAIN|UNKNOWN]
Txn: [YES|NO|UNKNOWN]
Mode: [WAIT|PASSTHROUGH]
Last: <timestamp>

struct conn_info {
    enum conn_type conn_type;   // CONN_T_SSL - CONN_T_CLEAR - CONN_T_UNKNOWN
    enum txn_state txn_state;   // TXN_S_ACTIVE - TXN_S_INACTIVE - TXN_S_UNKNOWN
    struct stmt* conn_stmt;     // if non-NULL, last statement sent on this connection (that matches)
    struct mybuf* request; // parsed request, only valid in conjunction with conn_stmt
    __u32 dpipe_id; // daemon (target)-side sockmap key
    __u32 cpipe_id; // client (source)-side sockmap key
};


conn_stmt is needed both for refcounting, and also for cases where the client must initially
populate the cache -- where the client needs to send the response again, and other instances
where the request must be relayed to the actual scenario.


struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    // ...
} dpipe_map;

DPIPE_MAP is populated by the DAEMON, and contains the client-side end of
a socketpair(2) call. It is READ/CONSUMED by CLIENT. dpipe_freelist acts
as a list of available (unused) dpipes

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(value, __u32); // daemon-side file descriptors
    // ...
} dpipe_freelist;

DPIPE_FREELIST contains indexes or keys into dpipe_map, showing containing
lists of available dpipes. Client reads and pops items from here.

struct {
    __u32 serial;
    __u32 num_free;
} dpipes_meta;

Bookkeeping for dpipes

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    // ...
} cpipe_map;

cpipe_map contains the client-side mapping of original DB connection
sockets; the client control flow uses these sockets instead of the original
DB connection (but the fd remains the same).

struct pipe_sk_info {
    __u32 dpipe_key; // key into dpipe_map, needed for redirect
    // ... nothing else
};

> NOTE:

dpipe_map and cpipe_map exist (rather than just route on ingress and egress) because ingress
and egress are not symmetrical in capability, it's easier to route on egress (i.e. outgoing 
data).

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __type(value, struct pipe_sk_info);
    // ...
} pipe_sk_info_map;

this map is stored client-side, and tells us which client-side sockets are mapped
to which dpipes

struct dpipe {
    __u32 cfd; // fd of "remote" end (i.e. where the client does i/o)
    __u32 sfd; // fd of "local" end (i.e. where the daemon does i/o)
    __u32 key; // key in map
    __u64 ts; // last active
    struct bpf_list_node lru_node; // for gc/purging/etc
    struct stmt* stmt; // the statement being handled by this pipe
};

Daemon-side data for dpipe

- Socket implementation -

The DAEMON establishes new connections to itself via socketpair(2); and populates
the corresponding dpipe struct with the relevant fds. it then registers the connection
(using dpipe::cfd!!) to dpipe_map. the key is determined via dpipes.meta_serial which is
monotonic

KCLIENT will pop dpipe_freelist[dpipes_meta.num_free-1], decrement num_free, and so on
the value of the popped element is an index into dpipe_map, and is the key for the daemon-level
socket. It also needs to update the stmt field in the struct dpipe

To actually make the dpipe useful, it needs to be connected to an equivalent cpipe; a client-side
pipe. Client-side pipes represent the connection of the client to the daemon, but are never
actually treated as separate fds in client applications, but as redirect targets for an
existing (hijacked) MySQL connection.

The BPF redirect program runs on pipes in the CPIPE map, and then replaces its remote
end with those sockets in the DPIPE map.

It is important to note that the temporarily hijacked MySQL connection is not used
(at least in the initial, TLS-focused implementation) to transmit data, rather, the
daemon and the client use the socket as a control/data channel and as a notification
mechanism. Using the same socket avoids notification/wakeup issues (e.g. if we need
to get data from the cache, an i/o operation, how does the client know when the data
is available? what if the client is using non-blocking I/O).

For this purpose, traffic must be redirected in both ways.

KCLIENT (or UCLIENT) will need to release the connection at some point as well, when it is no
longer needed. There is no special step for this needed other than placing the
key back into the freelist and removing its own descriptor from cpipe_map
and pipe_sk_info_map


void wakeup_daemon(key);

This is a function rather than a data structure, because the underlying notification
mechanism can be implemented in a variety of ways. It is called from kclient or uclient
to notify the daemon that a statement (stmt) needs resolution. This can be done either
through:

1. Sending the key on a dedicated channel. Daemon reads the key information, and then
   starts watching/processing the socket

2. Sending a hello message on the newly redirected socket; but this requires the daemon
   to already be listening to read/write events for that socket, which could become
   expensive if there are many concurrent connections

3. Using a ringbuffer instead of a channel/socket. This works like #1, but using a BPF
   structure instead.


- Timeouts and error handling -

We should prepare for scenarios in which the daemon is unavailable or unresponsive,
and need a way in which the clients don't wait indefinitely for a response.

The basic premise is that the client, at any given point in time, is waiting for some
kind of I/O on the (DB) socket; so we need to 'unstick' the connection from waiting
in the case of e.g. a stuck daemon (closed daemons are easier, since we get a connection
close notification...)

We define the following:

1) LRU of [active] dpipe objects. This contains a list of all active dpipes; when i/o
   is performed on it, the LRU node is removed and placed in the front, etc. The LRU
   node contains the last-touch timestamp.

2) BPF program (scheduled via timer) which sweeps the LRU list, cleaning up (*see later)
   stuck connections, until it hits a dpipe which has its timestamp within the acceptable
   margin.

cleaning up involves draining any incoming I/O from the client and sending a final error
status on the client [CACHE_ERROR], and/or CLOSING the dpipe. This must be coordinated
with uclient, so that the close is intercepted and not propagated up to the user and the
DB socket can be restored transparently.


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
        - 0x00: WRITE THROUGH. The cache does not have the value, and the client needs to fetch the result
                and send it to the cache (somehow...) [todo: we can either write the result directly to a shared memory segment
                or use a ringbuffer to send (and presumably copy) the response data]
        - 0x01: OK. The local cache has the data; the exact number of bytes will follow,
                after which the socket should be unmapped.

        In the interest of simplicity, the response is 4 bytes, followed by whatever payload, etc