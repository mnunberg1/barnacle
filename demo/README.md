# Demo environment

A self-contained docker-compose stack for exercising the query cache
end-to-end: a MySQL 8.4 server seeded with a small `shop` dataset, a Valkey
instance, and a privileged `bpf` container with the toolchain needed to build
and run the project.

## Layout

- `docker-compose.yml` — the three services: `mysql`, `valkey`, `bpf`
- `docker/Dockerfile` — the `bpf` container's image (clang/llvm/libbpf/bpftool
  plus MySQL and Valkey clients)
- `seed_mysql.sql` — schema and demo data, loaded automatically the first
  time the `mysql` container starts
- `workload.py` — a stand-in client that issues a steady stream of queries
  against the demo dataset, some deliberately slow
- `config/qcache.conf`, `config/cache.list` — a qcache config pinned to this
  compose stack's container names and ports

All commands below are run from the repository root.

## Bring the stack up

```bash
docker compose -f demo/docker-compose.yml up -d
```

This starts `mysql` (host port 13306), `valkey` (host port 16379), and `bpf`
(idles on `sleep infinity` until you `exec` into it). The `bpf` container
mounts the whole repository at `/workspace`, so it builds and runs against
the same source tree you're editing.

## Build

```bash
docker compose -f demo/docker-compose.yml exec bpf make
```

`make check` runs the tests that need no kernel or root; `make test` also
runs the privileged ones (kernel feature probes, cross-process sockmap
redirect). See the
[Makefile](../Makefile) for details.

## Run the demo workload

```bash
docker compose -f demo/docker-compose.yml exec bpf python3 demo/workload.py
```

The `bpf` container already has `MYSQL_HOST`/`MYSQL_PORT`/`VALKEY_HOST`/etc.
set to point at the compose services, so `workload.py` needs no flags. It
prints each query it issues, how long it took, and the shape of the result.

## Run the daemon and UCLIENT

The daemon owns the shared state: it loads KCLIENT, creates the maps and the
arena, builds the dpipe pool, and seeds the statement table from the list.

```bash
docker compose -f demo/docker-compose.yml exec bpf ./build/agent -l demo/config/cache.list -v
```

UCLIENT is a shared library that Frida injects into a client process that is
already running and serving. Nothing is preloaded and the client is not
restarted -- that is the whole point of injecting rather than `LD_PRELOAD`:

```bash
docker compose -f demo/docker-compose.yml exec bpf ./build/qcinject <PID>
```

The agent picks up the same statement list through the daemon's pinned maps,
so it needs no list of its own. It prints its counters on exit (`writes`,
`matched`, `asked`, `served`, `resent`, `published`, `timeouts`), which is the
quickest way to see whether statements are being recognised and answered.

The injected library must match the target's glibc. The agent links
libstdc++ statically, but a build against a newer glibc than the target
container's will fail to load -- see the note in the [Makefile](../Makefile).

## Run qcache against the demo

With the workload running in one shell, discover and attach to it from
another:

```bash
docker compose -f demo/docker-compose.yml exec bpf ./build/qcache -c demo/config/qcache.conf list
docker compose -f demo/docker-compose.yml exec bpf ./build/qcache -c demo/config/qcache.conf analyze
docker compose -f demo/docker-compose.yml exec bpf ./build/qcache -c demo/config/qcache.conf run
```

`list`/`analyze` report what qcache sees and, for `analyze`, why a process is
or isn't attachable. `run` attaches and runs the agent in the foreground.

## Tear down

```bash
docker compose -f demo/docker-compose.yml down -v
```

The `-v` also drops the MySQL data volume, so the next `up` reseeds from
`seed_mysql.sql`.

## Using your own config instead of the demo's

`demo/config/` is pinned to this compose stack and checked into the repo as
part of the demo. For a real deployment, copy the templates at the
repository root instead and point qcache at your own processes/containers:

```bash
cp config/qcache.conf.example config/qcache.conf
cp config/cache.list.example config/cache.list
```

`config/qcache.conf` and `config/cache.list` are gitignored, since what to
attach to and which queries to cache is specific to each deployment.
