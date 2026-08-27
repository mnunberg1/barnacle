# Demo environment

A self-contained docker-compose stack for exercising the query cache
end-to-end: a MySQL 8.4 server seeded with a small `shop` dataset, a Valkey
instance, and a privileged `bpf` container with the toolchain needed to build
and run the project.

The point of the demo is to show a running, unmodified process getting faster
without being restarted or reconfigured — and to show that the speedup is real
by watching the database go quiet.

## Layout

- `docker-compose.yml` — the three services: `mysql`, `valkey`, `bpf`
- `docker/Dockerfile` — the `bpf` container's image (clang/llvm/libbpf/bpftool
  plus MySQL and Valkey clients)
- `seed_mysql.sql` — schema and demo data, loaded automatically the first time
  the `mysql` container starts
- `workload.py` — a stand-in client that issues a steady stream of queries,
  some deliberately slow. It knows nothing about the cache.
- `mysql-tail.sh` — shows every statement that actually reaches mysqld
- `config/barnacle.conf`, `config/cache.list` — a barnacle config pinned to
  this stack's container names and ports

All commands are run from the repository root.

## The short version

Five commands, in three terminals. Details for each are below.

```bash
docker compose -f demo/docker-compose.yml up -d
docker compose -f demo/docker-compose.yml exec bpf make
```

```bash
# terminal 1 — the daemon
docker compose -f demo/docker-compose.yml exec bpf ./build/qc-daemon -l demo/config/cache.list -v
```

```bash
# terminal 2 — what reaches the database
demo/mysql-tail.sh
```

```bash
# terminal 3 — the application, then attach to it
docker compose -f demo/docker-compose.yml exec bpf python3 demo/workload.py --slow-only
docker compose -f demo/docker-compose.yml exec bpf ./build/qc-barnacle -c demo/config/barnacle.conf attach
```

## Bring the stack up

```bash
docker compose -f demo/docker-compose.yml up -d
```

This starts `mysql` (host port 13306), `valkey` (host port 16379), and `bpf`
(idles on `sleep infinity` until you `exec` into it). The `bpf` container
mounts the whole repository at `/workspace`, so it builds and runs against the
same source tree you are editing.

## Build

```bash
docker compose -f demo/docker-compose.yml exec bpf make
```

`make check` runs the tests that need no kernel or root; `make test` also runs
the privileged ones (kernel feature probes, cross-process sockmap redirect).

## 1. Start the daemon

The daemon owns everything shared: it loads KCLIENT, creates the maps and the
arena, builds the dpipe pool, and seeds the statement table from the list.
Nothing else works until it is running — it is what creates the pins the agent
later opens.

```bash
docker compose -f demo/docker-compose.yml exec bpf \
    ./build/qc-daemon -l demo/config/cache.list -v
```

With `-v` it logs a line per `STORE` and `HIT`, which is the daemon's own view
of the same events the other two terminals show from outside.

## 2. Watch what reaches the database

```bash
demo/mysql-tail.sh
```

This runs on the host (it talks to the `mysql` container over `docker exec`)
and follows MySQL's general query log, which records every statement the
server is asked to run.

It is the honest half of the demo. A client-side timing number cannot
distinguish a cache hit from a query that simply ran fast; this shows a hit as
an **absence** — the application gets its rows and nothing arrives here.

Turn the log back off when you are finished:

```bash
demo/mysql-tail.sh --off
```

## 3. Run the workload

```bash
docker compose -f demo/docker-compose.yml exec bpf python3 demo/workload.py --slow-only
```

`--slow-only` restricts it to the two statements in `config/cache.list`. The
default mixed feed is more realistic but much harder to read, since the fast
queries dominate the output and none of them are cacheable.

Each of those statements ends in `SLEEP(1.5)` or `SLEEP(2)`, standing in for
the kind of slow query a real application would have — an unindexed scan, a
slow join — without needing a large dataset to reproduce it. Expect ~4s per
query, and a matching line in terminal 2 for every one.

The `bpf` container already has `MYSQL_HOST`/`MYSQL_PORT`/`VALKEY_HOST` set to
point at the compose services, so no flags are needed.

## 4. Attach, without restarting anything

Leave the workload running. In a third terminal:

```bash
docker compose -f demo/docker-compose.yml exec bpf \
    ./build/qc-barnacle -c demo/config/barnacle.conf list
docker compose -f demo/docker-compose.yml exec bpf \
    ./build/qc-barnacle -c demo/config/barnacle.conf attach
```

`list` reports what barnacle found and whether each process can be hooked;
`analyze` adds the reasoning when something cannot; `attach` injects the agent
into everything attachable. `run` attaches and then runs the daemon in the
foreground, if you would rather not keep terminal 1 open.

## What you should see

The workload does not restart, reconnect, or notice anything. Its timings drop
from seconds to microseconds, and terminal 2 stops moving:

```
# terminal 3, workload.py
workload:  4.513s  3 row(s) x 8 col(s)   SELECT * FROM products WHERE category = 'safety' ...
workload:  4.019s  2 row(s) x 6 col(s)   SELECT * FROM orders WHERE customer = 'wayne ...
        <-- attached here
workload:  4.507s  3 row(s) x 8 col(s)   SELECT * FROM products WHERE category = 'safety' ...   read-through
workload:  4.005s  2 row(s) x 6 col(s)   SELECT * FROM orders WHERE customer = 'wayne ...       read-through
workload:  0.001s  3 row(s) x 8 col(s)   SELECT * FROM products WHERE category = 'safety' ...
workload:  0.000s  2 row(s) x 6 col(s)   SELECT * FROM orders WHERE customer = 'wayne ...
workload:  0.001s  3 row(s) x 8 col(s)   SELECT * FROM products WHERE category = 'safety' ...
```

```
# terminal 2, mysql-tail.sh
16:07:19.412  conn=213699 Query    SELECT * FROM orders WHERE customer = 'wayne industries' ...
16:07:23.834  conn=213699 Query    SELECT * FROM orders WHERE customer = 'wayne industries' ...
16:07:28.163  conn=213699 Query    SELECT * FROM products WHERE category = 'safety' ...
        <-- nothing further, while the workload keeps querying
```

The two queries that still reach the database immediately after attaching are
the read-through: the cache is reactive and learns only statements someone
actually ran, so the first execution of each is served by the server and
captured on the way back. Everything after that is served without the server
being contacted at all.

The daemon's own log agrees, and is a good cross-check:

```
daemon: STORE 367 bytes, 6 row(s)  SELECT * FROM products WHERE category = 'safety' ...
daemon: HIT   dpipe=63 stmt=1
```

The agent prints its counters when the process exits — `writes`, `matched`,
`asked`, `served`, `published`, `timeouts`, `pool_empty`, `txn_skip` — which is
the quickest way to see whether statements are being recognised.

## Two things that will silently stop it working

Both are properties of the client, not bugs in the cache, and both look
identical from outside: the agent attaches, reports `ready`, and then nothing
happens. `workload.py` sets both correctly, with a comment saying why.

- **The connection must use TLS.** The cache intercepts inside the TLS
  library, above the encryption, so a plaintext connection has no
  `SSL_read`/`SSL_write` to hook and is invisible to it. MySQLdb does not
  request TLS by default; the workload passes `ssl_mode="REQUIRED"`. Check
  with `SHOW STATUS LIKE 'Ssl_cipher'` — an empty value means plaintext.
- **Autocommit must be on.** MySQLdb defaults it off, which means every
  statement runs inside an open transaction, and the cache deliberately
  bypasses those: the rows may reflect uncommitted state private to that
  session. `SET autocommit=0` in the tail output is the giveaway.

## Statements are matched byte for byte

`config/cache.list` is an exact match against the statement text on the wire —
no normalisation, no parameter extraction. A statement that differs by one
space is a different statement. This is why the demo's list is written to
match `workload.py`'s `QUERY_TEMPLATES` exactly.

## Tear down

```bash
docker compose -f demo/docker-compose.yml down -v
```

The `-v` also drops the MySQL data volume, so the next `up` reseeds from
`seed_mysql.sql`.

## Using your own config instead of the demo's

`demo/config/` is pinned to this stack and checked in as part of the demo. For
a real deployment, copy the templates at the repository root and point
barnacle at your own processes:

```bash
cp config/barnacle.conf.example config/barnacle.conf
cp config/cache.list.example config/cache.list
```

Both are gitignored, since what to attach to and which queries to cache is
specific to each deployment.

Barnacle is meant to run on the **host**, where `/proc` shows every process
including those inside containers, and where their cgroups identify which
container each belongs to. Running it inside the `bpf` container — as the demo
does, for convenience — works, but that container has its own cgroup
namespace, so no container can be identified and the `container` filter cannot
be applied. Barnacle says so rather than silently ignoring it, and shows `?`
in the `WHERE` column.
