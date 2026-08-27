# Valkey Query Cache

This project aims to provide a turnkey query cache allowing system administrators
to quickly accelerate slow DB queries without explicitly configuring a cache or
maintaining more infrastructure.

The only configuration required is:

1. Location of the cache
2. How to identify outbound DB connections
3. Which queries to optimize

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
| `qc-barnacle` | entry point. Finds target processes via `/proc`, decides whether each can be hooked, injects the agent. | Python |
| `qc-daemon` | the userspace daemon. Owns the dpipe pool, the arena and the cache; answers lookups and stores. | C++ |
| `libqcagent.so` | the agent injected into each client process. Hooks the TLS library's read/write entry points. | C++ |
| `qc-inject` | injects the above into a running process, via frida-gum. | C++ |
| `kclient.bpf.o` | the only eBPF: two `sk_msg` programs that splice a client socket to the daemon. | C |

## Running the demo

A docker-compose stack with MySQL, Valkey and a build container is in `demo/`.
It shows an already-running client getting faster without being restarted, and
— via `demo/mysql-tail.sh`, which follows MySQL's general query log — shows the
database going quiet as the cache takes over.

```bash
docker compose -f demo/docker-compose.yml up -d
docker compose -f demo/docker-compose.yml exec bpf make
```

Then, in three terminals:

```bash
docker compose -f demo/docker-compose.yml exec bpf ./build/qc-daemon -l demo/config/cache.list -v
```

```bash
demo/mysql-tail.sh
```

```bash
docker compose -f demo/docker-compose.yml exec bpf python3 demo/workload.py --slow-only
docker compose -f demo/docker-compose.yml exec bpf ./build/qc-barnacle -c demo/config/barnacle.conf attach
```

The workload's queries drop from ~4s to ~0.001s, and the tail stops moving.
See [demo/README.md](demo/README.md) for what each step does, what the output
should look like, and the two client settings (TLS and autocommit) that will
otherwise stop it working silently.
