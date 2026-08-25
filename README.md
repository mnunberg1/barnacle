# valkey-ebpf

Boilerplate for capturing live MySQL queries with eBPF and answering them from
Valkey Search instead.

An eBPF program hooks the syscalls a MySQL client uses to send a command packet,
recognises `COM_QUERY` on the wire, and streams the statement text to userspace.
A translator turns simple `SELECT ... WHERE ...` statements into `FT.SEARCH`
calls and (optionally) runs them.

```
 mysql client ──write(2)──► mysqld
       │
       │ tracepoint/syscalls/sys_enter_{write,sendto}
       ▼
 mysql_reroute.bpf.o ──ringbuf──► build/agent ──JSONL──► bridge.py ──► Valkey
```

The three pieces are deliberately separate processes: only the tiny C loader
needs privileges, and the translator can be developed and tested with no kernel
and no server involved.

## Layout

| Path | What it is |
| --- | --- |
| `bpf/mysql_reroute.bpf.c` | active eBPF program: uprobes `mysql_real_query` in a client library, can reroute statements and correlates entry/return |
| `src/agent.cpp` | libbpf loader for the reroute/correlate path; keeps `config/reroute.list` in sync with a BPF map, prints correlated request/response JSONL |
| `config/reroute.list` | plain-text reroute list the agent reads directly, one exact statement per line |
| `config/reroute.json` | structured reroute list `app/dashboard.py` manages (adds TTL/added-at metadata); derives `reroute.list` |
| `app/workload.py` | stand-in application generating demo traffic, using a client library the agent can actually observe |
| `app/dashboard.py` | Flask backend: launches the agent, aggregates latency by statement, serves the triage UI |
| `app/static/index.html` | the triage UI itself (single-file HTML/CSS/JS, no build step) |
| `translator/sql2search.py` | SQL tokenizer, parser and FT.SEARCH renderer |
| `translator/schema.json` | table → index mapping and column types (drives both the translator and the mirror) |
| `translator/bridge.py` | reads the agent JSONL, translates, optionally executes |
| `translator/test_sql2search.py` | unit tests (no kernel, no server) |
| `demo/mirror.py` | copies the MySQL tables into Valkey hashes and builds the indexes |
| `demo/verify.py` | runs each SELECT on both engines and diffs the primary keys |
| `demo/run_demo.sh` | the whole pipeline against live traffic |
| `CMakeLists.txt`, `include/bpf_stub/` | IDE support only (CLion/VS Code/clangd); see "IDE support" below |

## Quick start

```bash
docker compose up -d
```

```bash
docker compose exec bpf make
```

```bash
docker compose exec bpf demo/run_demo.sh
```

`run_demo.sh` mirrors the data, starts the agent, then issues real queries
against the real MySQL server. Each captured statement is printed alongside the
`FT.SEARCH` it became and the rows Valkey returned.

To watch your own traffic instead, run the pipeline and use the client yourself:

```bash
docker compose exec bpf sh -c './build/agent | translator/bridge.py --execute'
```

```bash
docker compose exec bpf mysql -h mysql -u app -papppw --skip-ssl shop
```

Translate without any of the tracing machinery:

```bash
docker compose exec bpf translator/sql2search.py "SELECT name FROM products WHERE price < 30"
```

## Does the translation actually agree with MySQL?

`demo/verify.py` runs each statement against both engines and compares the set
of primary keys returned:

```bash
docker compose exec bpf python3 demo/verify.py
```

Current result on the demo dataset: **14 matching, 2 differing-as-warned, 0
unexpectedly differing.** The two divergences are `LIKE` against a `TEXT`
column, and the translator flags them before they happen — see "Where the
mapping is not equivalent" below.

## What translates

| SQL | FT.SEARCH |
| --- | --- |
| `category = 'tools'` (TAG) | `@category:{tools}` |
| `name = 'Cordless Drill'` (TEXT) | `@name:"Cordless Drill"` |
| `price = 30` (NUMERIC) | `@price:[30 30]` |
| `price > 30` | `@price:[(30 +inf]` |
| `price BETWEEN 10 AND 20` | `@price:[10 20]` |
| `brand IN ('acme','globex')` | `@brand:{acme\|globex}` |
| `sku LIKE 'SKU-00%'` (TAG) | `@sku:{SKU\-00*}` |
| `category != 'tools'` | `-@category:{tools}` |
| `a AND b` / `a OR b` / `NOT a` | `a b` / `a \| b` / `-a` |
| `ORDER BY price DESC` | `SORTBY price DESC` |
| `LIMIT 10, 5` | `LIMIT 10 5` |
| `SELECT sku, price` | `RETURN 2 sku price` |
| `SELECT COUNT(*)` | `LIMIT 0 0` (the reply's total) |

Joins, subqueries, `GROUP BY`, `HAVING`, `DISTINCT` and expressions are
**rejected with a reason** rather than approximated. A wrong translation is
worse than a refused one, and in a tracing pipeline you will always see traffic
that is out of scope — `bridge.py` skips it and carries on.

## Where the mapping is not equivalent

Two things are worth knowing before trusting this on real data.

**`LIKE` on a TEXT column is not the same predicate.** SQL anchors `LIKE 'Ham%'`
to the start of the whole column value; a TEXT index is tokenized, so
`@name:Ham*` matches a token anywhere in the field. On the demo data MySQL
returns nothing for `name LIKE 'Ham%'` while Valkey returns "Claw Hammer" and
"Ball Peen Hammer". The translator emits a warning saying exactly this. For
whole-value prefix matching, declare the column `TAG` — `sku LIKE 'SKU-00%'`
agrees with MySQL exactly.

**A TAG field is a list, not a scalar.** `FT.CREATE` splits TAG values on a
separator that defaults to `,`, so a column containing `o'brien, inc.` would
index as two separate tags and never match as a whole. Because this project
mirrors *scalar* SQL columns, `schema.json` defaults TAG columns to `\u0001`
instead, and `mirror.py` and the translator agree on that. Set `"separator":
","` explicitly on columns that really do hold a delimited list; the translator
warns when a literal contains the separator in force.

Also note `=` on a TEXT column becomes a tokenized, case-insensitive phrase
match, not a byte-exact comparison.

## Dialect differences

`valkey-search` and RediSearch do not accept the same query language. These
were measured against `valkey/valkey-bundle`, not assumed:

| | valkey-search | RediSearch |
| --- | --- | --- |
| match-all | no `*` token | `*` |
| `@field:(a \| b)` | rejected | accepted |
| `ismissing(@field)` | not implemented | available |
| `WEIGHT` other than 1.0 | rejected by `FT.CREATE` | accepted |

The translator defaults to `--dialect valkey`. With no `WHERE` clause it
substitutes an unbounded range over a NUMERIC column (`@price:[-inf +inf]`) and
warns, because there is no match-all token; that skips documents where the
column is absent. `--dialect redis` emits `*` and enables `IS NULL`.

## How capture works

The eBPF program attaches to `sys_enter_write` and `sys_enter_sendto` and reads
the outgoing buffer. A MySQL command packet is:

```
byte 0..2   payload length, little endian
byte 3      sequence id (0 for a new command)
byte 4      command byte (0x03 COM_QUERY, 0x16 COM_STMT_PREPARE)
byte 5..    statement text (see below -- not always exactly byte 5)
```

Requiring `seq == 0`, a known command byte, and a self-consistent
`payload_len` is specific enough that the program does not need to know which
file descriptors are MySQL sockets, and it works with any client library.
Nothing here depends on MySQL's symbols or version — unlike a uprobe on a
server-internal function, which breaks whenever the server is rebuilt.

Two things make this more robust than "read 5 bytes and go":

**`CLIENT_QUERY_ATTRIBUTES`.** MySQL 8.0.26+'s query-attributes capability
inserts two more bytes here when a client negotiates it (confirmed with
`mysql-connector-python`) — two lenenc-int fields, each a single byte in the
common zero-bound-parameters case — shifting the query text to byte 7
instead of byte 5. This isn't tracked via the connection's actual capability
negotiation (that would mean following a connection from its opening
handshake); it's a content heuristic instead: real SQL text never
legitimately starts with a NUL byte, so seeing `{0x00, 0x01}` right after the
command byte is taken as this prefix and skipped.

**Statements split across multiple `write()`/`sendto()` calls.** A statement
is not required to arrive in one syscall. Partial packets are accumulated
per connection (keyed by thread + fd) until the declared `payload_len` is
satisfied — the *header* is still assumed to arrive intact in the first call
of a new command, but the text portion can continue across later calls, and
`"spans_writes": true` marks a statement that needed this. This was
validated directly: a hand-crafted packet split across two real `send()`
calls captures with byte-for-byte correct text.

Statements longer than 511 bytes are truncated and marked `"truncated": true`.
A connection whose partial assembly never completes (the client errors out
mid-write) leaks its tracking entry — bounded by the map's `max_entries`, a
known, low-impact gap.

**TLS defeats this**, by design: the payload is encrypted before it reaches
`write(2)`. The compose file enables `mysql_native_password` and the demo
clients pass `--skip-ssl` so there is plaintext to match on. Tracing real
TLS traffic needs uprobes on the TLS library instead — see
[Established patterns for TLS interception](#established-patterns-for-tls-interception-not-implemented-here)
below for what that would actually involve.

Known gap: `sendmsg`/`writev` are not hooked (add another tracepoint if your
client uses them).

## Rerouting specific statements (agent)

`agent` (backed by `bpf/mysql_reroute.bpf.c`) actively intercepts specific statements
before they reach mysqld, restores the caller's own buffer afterward, and
correlates the outcome:

```
                      ┌─ in config/reroute.list? ──no──► leave the packet alone
mysql client ──write()┤
                      └─ yes, and safe to mutate ──► overwrite the buffer in
                                place with `SELECT 0-- ...`, save the
                                original bytes for restoration
                                                    │
sys_exit_write/sendto ─── same syscall's own exit ──┘── write the saved
                                                         original bytes back
                                                         (kernel already
                                                         consumed the mutated
                                                         version by now)
```

### Wire-level, not a client-library uprobe

An earlier version of this mechanism uprobed `mysql_real_query()` in
libmysqlclient/libmariadb directly — plaintext by construction, immune to
wire framing and TLS. It was abandoned for a concrete reason: it only sees
processes that dynamically link that library and call through its
text-protocol API. Pure reimplementations of the wire protocol with no such
library in the loop at all — PyMySQL, `mysql-connector-python`'s default
"pure" mode, Go's `go-sql-driver/mysql` — are very likely the *majority* of
real-world Python (and much other) MySQL traffic, precisely because avoiding
a `libmysqlclient` build dependency is a genuine, widely-felt convenience.
A uprobe-only mechanism would have had *worse* real-world coverage than the
wire-level one, despite being more robust for the narrower slice it did
cover. So `agent` reuses the same wire-level, universal
capture (the `CLIENT_QUERY_ATTRIBUTES`-aware, reassembly-aware machinery
described above) instead, and gets the robustness some other way — see
below.

### Running it

```bash
docker compose exec bpf ./build/agent
```

With a `config/reroute.list` entry matching exactly:

```bash
docker compose exec bpf python3 -c "
import MySQLdb
conn = MySQLdb.connect(host='mysql', user='app', passwd='apppw', db='shop')
cur = conn.cursor()
cur.execute(\"SELECT * FROM products WHERE stock = 0\")
print(cur.fetchall())  # ((0,),) -- mysqld actually ran SELECT 0
"
```

`agent` prints the original text and the correlated response:

```json
{"kind":"request","req_ts_ns":...,"comm":"python3","rerouted":true,"spans_writes":false,"sql":"SELECT * FROM products WHERE stock = 0"}
{"kind":"response","req_ts_ns":...,"comm":"python3","rerouted":true,"response_hex":"010000010117..."}
```

`req_ts_ns` is the correlation key — a request event's `req_ts_ns` equals its
own `ts_ns`; the response event correlated to it carries the same value, and
`(response.ts_ns − req_ts_ns) / 1e6` is the latency in milliseconds. Send
`SIGHUP` to reload `config/reroute.list` without restarting:

```bash
kill -HUP $(docker compose exec -T bpf pgrep -x agent)
```

**Correlation is broader than mutation.** Every matched statement gets a
request/response pair reported, regardless of reroute-list membership — that
is what lets a consumer answer "which queries are slow right now" before
anyone has decided to reroute anything (see `app/dashboard.py` below). The
`rerouted` flag on each event says whether *this* occurrence was actually
mutated. Only the mutation itself is gated on list membership, matching
"check the reroute list; if the query is not in it, exit."

### The buffer is restored after the syscall completes

The mutation happens at `sys_enter_write`/`sys_enter_sendto` — the only
point where the caller's outgoing bytes can still be changed before the
kernel reads them for transmission. But the intent is not for the *calling
application* to ever see `SELECT 0` in memory it still owns (e.g. if it logs
the query it believes it just sent). So the original bytes are saved before
being overwritten, and at `sys_exit_write`/`sys_exit_sendto` — once the
kernel has already consumed the mutated version for transmission — they are
written back. By exit time the wire transmission is already committed;
restoring afterward only changes what the caller's own memory contains going
forward, invisibly. This was validated directly: a Python client's own
in-memory copy of the query string is provably unaffected by the wire-level
mutation.

### Mutation safety with reassembly

A statement whose *header* arrived in an earlier `write()` call but whose
*text* is entirely contained in the call that completes it can still be
safely rerouted — nothing but header bytes went out before now, and those
don't need to change. A statement whose text was already partly sent in an
earlier, already-committed `write()` call cannot be safely rerouted at all —
there is no way to un-send those bytes. This is checked on every completed
assembly; when unsafe, mutation is skipped, but the statement is still
correctly observed and reported. Both cases were validated directly with
hand-split packets: a
split that only separates the header from the text still reroutes
correctly; a split that cuts partway through the text correctly declines to
mutate and lets the real query execute.

Design points worth knowing before relying on this:

- **The replacement is `SELECT 0-- <padding>`, not `-- SELECT 0<padding>`.**
  Putting the comment marker first would swallow "SELECT 0" too and turn the
  statement into an empty query (MySQL error 1065) — putting it after means
  `SELECT 0` genuinely executes and returns a harmless one-row result. Swap
  the order in `REROUTE_TEXT` (`bpf/mysql_reroute.h`) if you'd rather
  rerouted queries surface as an error to the client instead.
- **Same-length replacement only, by necessity.** There is no supported way
  to change what a syscall's arguments are from a tracepoint — only the
  memory they point to — so the replacement is padded with spaces (harmless
  inside a `--` comment) to exactly the original length. A statement shorter
  than `"SELECT 0-- "` (11 bytes) cannot be rerouted and is left untouched.
- **Exact byte match, no normalization**, same caveat as the translator's TAG
  matching: `config/reroute.list` entries must match the literal statement
  text on the wire, incidental whitespace differences included. Copy entries
  from the agent's own `"sql"` output (or `app/dashboard.py`'s UI) if
  unsure of the exact text a client sends.
- **Correlation key is `(thread, fd)`**, not a real connection identity (a
  `struct sock *`-based key via a kprobe on `tcp_sendmsg`/`tcp_recvmsg` would
  survive fd reuse more robustly, at the cost of walking kernel-internal
  structures across kernel versions).
- **One outstanding request per connection.** MySQL's classic protocol is
  synchronous — no pipelining — so a single pending-request slot per
  connection is sufficient. A response that spans multiple `read()`/
  `recvfrom()` calls only correlates its first chunk.
- **The response side captures a preview, not a parsed result.** Up to 127
  bytes of the raw MySQL protocol response are hex-dumped (it is binary
  protocol framing, not text). Reassembling and decoding a full result set
  is out of scope here.

### Established patterns for TLS interception (not implemented here)

`agent` sees nothing once a connection
uses TLS — the payload is ciphertext before it reaches `write(2)`. The
established technique for recovering plaintext despite TLS is uprobing the
TLS library's own encrypt/decrypt entry points — `SSL_write`/`SSL_read` for
OpenSSL, `gnutls_record_send` for GnuTLS — capturing the buffer argument at
entry (`SSL_write`) or after return once it's populated (`SSL_read`, where
the buffer is empty at entry). [Pixie](https://blog.px.dev/ebpf-openssl-tracing/)
uses exactly this for its protocol tracing, correlating entry and return via
a map keyed by thread id, the same shape this project's own request/response
correlation already uses. The important part for a project like this one:
**Python's own `ssl` module is a thin wrapper over OpenSSL**, so a
`libssl.so` uprobe would recover plaintext from *pure-Python* drivers using
TLS too, not just compiled ones — unlike the client-library-uprobe approach
this project tried and set aside above, which only ever covered native
clients. Adding this would be a genuinely separate, third capture path
layered on top of the two here, not implemented in this project.

Sources:
- [eBPF TLS tracing: The Past, Present and Future — Pixie Labs](https://blog.px.dev/ebpf-tls-tracing-past-present-future/)
- [Debugging with eBPF Part 3: Tracing SSL/TLS connections — Pixie Labs](https://blog.px.dev/ebpf-openssl-tracing/)

## Triage UI: workload.py + dashboard.py

`app/workload.py` is a stand-in application — a loop issuing a mix of cheap
and (via `SLEEP()`) deliberately slow queries against the demo database,
unaware it is being observed. `app/dashboard.py` launches `agent` as
a subprocess, aggregates its JSONL by exact statement text (count, avg/max/
last latency), and serves a small web UI: a table of observed statements
sorted slowest-first, an "Add" button per row with a TTL picker, and the
current reroute list with a live countdown and a hit counter.

```bash
docker compose exec bpf python3 app/workload.py &
docker compose exec bpf python3 app/dashboard.py
```

Then open `http://localhost:18080`. Clicking "Add" writes the entry into
`config/reroute.json` (the structured, persistent source of truth — statement
text, when it was added, its TTL), regenerates `config/reroute.list` from it,
and signals `agent` to reload — the same file-plus-SIGHUP mechanism
described above, just driven from the UI instead of by hand. A background
sweep every 2 seconds expires entries whose TTL has elapsed and regenerates
the list again. **Usage statistics are not tracked per-entry by the BPF
layer** — `hit_count` in the UI is computed by `app/dashboard.py` itself,
counting `"rerouted": true` events per exact statement text as they stream
by; no changes to `agent` or the BPF program were needed for that.

`config/reroute.list` becomes a *generated* file once the dashboard is
running: hand-editing it will be silently overwritten on the next add/
remove/expiry sweep. Manage entries through the UI, or stop the dashboard
first if you want to edit the file directly.

## Requirements

The BPF side needs a kernel with BTF (`/sys/kernel/btf/vmlinux`) and ring buffer
support (5.8+). `vmlinux.h` is generated at build time from the running
kernel's own BTF, so the same source builds anywhere CO-RE works.

The `bpf` container is `privileged` with `pid: host` — it needs to load
programs, read kernel BTF, and see processes in the other containers. It is
built on Debian trixie rather than Ubuntu 24.04 because Ubuntu has no `bpftool`
binary package on arm64.

Verified on Docker Desktop for macOS on Apple Silicon (LinuxKit kernel 6.12,
aarch64). `agent` additionally needs `libmariadb-dev` (for `app/
workload.py`'s `mysqlclient` build) and a target `libmariadb.so`/
`libmysqlclient.so` to actually uprobe — both already set up by
`docker/Dockerfile` and `docker-compose.yml` for this project's containers.

## IDE support (CMakeLists.txt)

`CMakeLists.txt` exists purely so an IDE (CLion, VS Code + clangd) can index
this code with working autocomplete — it is not a build system replacement;
`docker compose exec bpf make` remains the only supported way to actually
build and run this project. eBPF does not exist outside Linux, so on a
non-Linux host (macOS, Windows) it configures IDE-only stub targets against
`include/bpf_stub/` — stand-ins for `vmlinux.h`, the real libbpf headers, and
the two `bpftool`-generated `*.skel.h` files, none of which exist without a
real Linux + libbpf toolchain. `cmake --build` is not expected to produce a
working binary on such a host; the point is only that opening this project
in an editor does not show a wall of false-positive errors while you read or
edit the code. On an actual Linux host with the container's toolchain
installed, the same `CMakeLists.txt` drives a real build instead, mirroring
the Makefile.

## Tests

```bash
docker compose exec bpf make check
```
