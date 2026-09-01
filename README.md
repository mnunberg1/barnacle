# Barnacle

A transparent query cache that attaches to a running program.

Barnacle aims to provide a turnkey query cache allowing system administrators
to quickly accelerate slow DB queries without explicitly configuring a cache or
maintaining more infrastructure. It attaches to processes that are already
running and know nothing about it, and detaches again without restarting them.

The name is the shape of the thing: it fastens onto something already moving,
travels with it, and comes off without leaving a mark. `bncl` is the internal
prefix -- macros, C symbols, namespaces and the components other than the
command line itself, which is just `barnacle`.

The only configuration required is:

1. Location of the cache
2. How to identify outbound DB connections
3. Which queries to optimize

There are two cache tiers: Valkey, which every host shares, and a per-host
copy in a BPF arena that each attached process has mapped, so a hit there
costs no round trip. `local_cache = off` gives the local tier up and sends
every lookup to Valkey, which is slower but makes the shared copy the only
authority.

Strictly speaking, however, all except #1 can be inferred through heuristics

## Setup and building

There is ONE daemon that does need to run, although it is entirely self-contained,
not requiring any ports or permissions. It simply serves to coordinate and schedule
cache notification [...]

One dependency is frida-gum, which for the time being does the heavy lifting of
binary injection and patching at a few points in the program. This is needed in
order to intercept I/O of applications using OpenSSL without having to run a full-
blown man-in-the-middle proxy. Instead, we intercept calls to the SSL functions
themselves, and determine whether or not they involve caching or not.

## Components

| | what it is | language |
|---|---|---|
| `barnacle` | entry point. Owns the daemon's lifecycle, finds target processes via `/proc`, decides whether each can be hooked, injects the agent, and reports status. | Python |
| `bncl-daemon` | the userspace daemon. Owns the dpipe pool, the arena and the cache; answers lookups and stores; carries a control socket. | C++ |
| `libbnclagent.so` | the agent injected into each client process. Hooks the TLS library's read/write entry points. | C++ |
| `bncl-inject` | injects the above into a running process, via frida-gum. | C++ |
| `kclient.bpf.o` | the only eBPF: two `sk_msg` programs that splice a client socket to the daemon. | C |

## The command line

```
barnacle start-server     start the daemon
barnacle stop-server      stop it
barnacle attach-client    attach the agent to the configured programs
barnacle detach-client    undo every attachment
barnacle reload-config    re-read the config; tell the daemon and the agents
barnacle status           what is running, and what it has done

barnacle list             which processes match, and their verdicts
barnacle analyze          as above, with the reasoning for each verdict
```

The daemon and the agents are reached differently because they are different
kinds of thing. The daemon is one long-lived process with a Unix control
socket, so start, stop, reload and status are a request and an answer. The
agents are code running inside somebody else's process with no thread of their
own, so they are reached by injection -- to hook, or to put every entry point
back -- and by two values in a BPF map that they poll, which is how a detach
or a new statement list reaches every attached process at once.

Nothing in barnacle needs libbpf or bpftool: every effect on a BPF map goes
through the daemon, which already has them. That is what lets it run on a host
with no toolchain.

## Running the demo

A docker-compose stack in `demo/`: MySQL with five genuinely slow queries,
Valkey, a sealed client application in its own container, and a barnacle host
with supervisor access to the client and nothing else.

```bash
docker compose -f demo/docker-compose.yml up -d --build
docker compose -f demo/docker-compose.yml exec ctl make
demo/terminals.sh
```

That opens four windows -- what reaches MySQL, what reaches Valkey, the
client's own log, and a shell on the barnacle host. In the last one:

```bash
./build/barnacle -c demo/config/barnacle.conf start-server
./build/barnacle -c demo/config/barnacle.conf attach-client
```

The client's latency histogram collapses into its fastest bucket, its
"over 500ms" count goes to zero, and the MySQL window stops moving -- without
the client being restarted or reconfigured, or knowing anything happened.

See [demo/README.md](demo/README.md) for what each window shows, how the
latency is arranged, what `reload-config` and `detach-client` do, and the two
client settings (TLS and autocommit) that will otherwise stop it working
silently.
