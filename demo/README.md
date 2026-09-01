# Demo environment

Four containers and four terminal windows. A MySQL server where some queries
are genuinely slow, a Valkey instance, a client application that knows nothing
about any of this, and a barnacle host with supervisor access to the client
and nothing else.

The point is to watch an already-running, unmodified process get faster --
and to be able to check that the speedup is real rather than a number the
client made up, by watching the database go quiet at the same moment.

## Layout

- `docker-compose.yml` — the four services: `mysql`, `valkey`, `client`, `ctl`
- `up.sh` / `down.sh` — start and stop the whole thing
- `terminals.sh` — opens the four windows to watch it in
- `client/app.py`, `client/Dockerfile` — the application and its own image
- `ctl/Dockerfile` — the controller's image (clang/llvm/libbpf/bpftool, frida,
  and the MySQL and Valkey clients)
- `seed_mysql.sql` — schema, data, and the views that make five queries slow
- `mysql-tail.sh` — every statement that actually reaches mysqld
- `netem.sh` — optional network-level latency in front of MySQL
- `config/cache.list` — the queries to cache. Ships **empty**; filling it in is
  the demo
- `config/slow-queries.list` — the five slow statements, ready to paste in
- `config/barnacle.conf` — pinned to this stack

All commands are run from the repository root.

## Who is allowed to do what

| | is | can |
|---|---|---|
| `bncl-mysql` | the database | nothing else |
| `bncl-valkey` | the cache | nothing else |
| `bncl-client` | a sealed application | talk to MySQL |
| `bncl-ctl` | the controller | supervise the client; talk to Valkey |

The controller is where the daemon runs and where you type `barnacle`. It runs
in the host PID namespace and is privileged, so it can
see the client's processes, ptrace one, and write into its filesystem through
`/proc/<pid>/root`. It has no such relationship with MySQL or Valkey: it talks
to Valkey as an ordinary client and never talks to MySQL at all.

The client gets `/sys/fs/bpf` and `CAP_BPF`, and nothing else from this
project — no volume from this repository, no build output, no statement list.
Those two are not conveniences: the agent runs *inside* the client process,
with the client's credentials, and has to be able to open the maps the daemon
pinned. Barnacle puts the agent and the statement list inside the container at
attach time.

## Bring it up

```bash
demo/up.sh
```

That is four containers started, barnacle built inside the controller, the
daemon started, and the agent attached to the client that is already running.
It is not a working cache yet — **nothing is cached**, because the cache list
ships empty. That is the starting position, and filling the list in is the
demo.

`demo/up.sh --rebuild` forces a docker image rebuild; `--no-attach` leaves the
client alone so you can watch it be slow first and attach by hand.

If you would rather type it out — and it is worth doing once, since the script
is only bookkeeping:

```bash
docker compose -f demo/docker-compose.yml up -d --wait
```

```bash
docker compose -f demo/docker-compose.yml exec ctl make
```

```bash
docker compose -f demo/docker-compose.yml exec ctl barnacle start-server
```

```bash
docker compose -f demo/docker-compose.yml exec ctl barnacle attach-client
```

The client starts querying the moment its container does, and keeps going;
nothing below ever restarts it.

### A note on docker compose

`docker-compose.yml` is a list of the four containers and how they are wired
together. Three commands cover everything this demo needs:

- `docker compose -f demo/docker-compose.yml up -d` — start them all
- `docker compose -f demo/docker-compose.yml exec ctl CMD` — run `CMD` inside
  the controller. This is how every `barnacle` command below is issued.
- `docker compose -f demo/docker-compose.yml down` — stop and remove them

The file pins its project name to `barnacle`, so those work from any
directory. Inside the controller, `build/` is on `PATH` and `BARNACLE_CONF`
points at this demo's config, which is why the commands are `barnacle status`
rather than `./build/barnacle -c demo/config/barnacle.conf status`.

## A short tmux guide

The four windows are tmux panes. If you have not used tmux, this is all you
need for this demo — it is a terminal that can split itself into panes and
keep running when you close the window.

Install it if you have not got it:

```bash
brew install tmux
```

`demo/terminals.sh` creates the session and drops you into it. Once you are
inside, every tmux command starts with a **prefix key**, which is `ctrl-b` by
default: press and release `ctrl-b`, then press the next key.

| | |
|---|---|
| `ctrl-b` then `o` | move to the next pane |
| `ctrl-b` then arrow key | move to the pane in that direction |
| `ctrl-b` then `z` | zoom the current pane to full screen; again to unzoom |
| `ctrl-b` then `[` | scroll back. Arrows/PageUp to move, `q` to stop |
| `ctrl-b` then `d` | detach — leaves everything running |
| `ctrl-b` then `?` | list every binding |

`z` is the one worth remembering: four panes on a laptop screen are cramped,
and zooming the client display to read it, then unzooming to see the MySQL
window go quiet, is most of what watching this demo consists of. The client
pane is also the only one that takes input — `+` and `-` change how often it
repaints, and ctrl-c there detaches that pane rather than stopping the
client.

Detaching is the other one. `ctrl-b d` leaves the session running in the
background with everything still going, and you get back with:

```bash
demo/terminals.sh
```

To end it, close each pane with `exit` or `ctrl-d`, or kill the session
outright:

```bash
tmux kill-session -t barnacle
```

That stops the log-watching commands. It does not stop the demo — the
containers, the daemon and the client are unaffected, since none of them run
inside tmux.

## Open the four windows

```bash
demo/terminals.sh
```

Native Terminal windows on macOS, a tmux session elsewhere, and
`--print` if you would rather open them yourself:

1. **MySQL** — `demo/mysql-tail.sh`, the general query log: every statement
   the server was asked to run.
2. **Valkey** — `valkey-cli monitor`: every command the daemon sends the cache.
3. **Client** — `docker attach --sig-proxy=false bncl-client`: a live latency
   display, repainted once a second. `attach` rather than `logs -f` so that
   keystrokes reach it; `--sig-proxy=false` so ctrl-c detaches the pane
   instead of killing the container.
4. **Control** — a shell on the controller, where `barnacle` is typed.

Four windows because the interesting thing is a relationship between them.
When the cache takes over, window 3 gets faster, window 1 goes quiet, and
window 2 starts moving — and no one of those three facts means much without
the other two.

## The client

Twenty statements, issued at random, forever. Fifteen return immediately; five
take somewhere between half a second and three seconds, and no two executions
take the same time. It reports every query over 500ms as it happens, and a
latency histogram every five seconds:

```
  SLOW   1.86s   3 row(s) x 8 col(s)  SELECT * FROM inventory_report WHERE category = 'safety'
client  5s window  21 queries   4 over 500ms
     <1ms │██████████████████████████████████████████████   12
    <10ms │██████████████                                    4
   <100ms │                                                  .
   <500ms │                                                  .
      <1s │███                                               1
      <2s │██████                                            2
      2s+ │███                                               1
          │ p50 771us   p90 1.40s   max 1.86s

   4.00s ┤▃ ▆▄▁▅▆▆▄▆  ▅ ▆▂▃
   894ms ┤█▇████████▇ █ ███
   200ms ┤███████████ █ ███
    45ms ┤███████████ █ ███
    10ms ┤███████████ █ ███
     2ms ┤███████████▅█▆███▅▄▄▄▃▄▅
         └────────────────────────
         p90 per 5s window, newest right
```

A histogram rather than an average, because the average hides the shape and
the shape is the story: a clump down at a millisecond and a smear across one
to three seconds. An average moving from 0.4s to 0.001s says the same thing in
a way nobody can watch happening.

The chart underneath is p90 per window over the last five minutes, newest on
the right — that tail flattening along the bottom row is the cache being
attached. Two decisions in it are worth knowing:

- **p90, not the median.** Fifteen of the twenty statements are fast whether
  or not the cache is running, so the median sits at a millisecond in both
  worlds and would draw a flat line straight through the most interesting
  event in the demo. p90 lives inside the slow five.
- **A fixed axis, not one that autoscales.** An axis that rescales redraws the
  past whenever a new extreme arrives, so a bar that was head-height a moment
  ago is knee-height now and nothing can be compared with anything. Half a
  millisecond to four seconds covers a cache hit at one end and the slowest
  query the demo can produce at the other.

Rows are coloured by the latency they represent rather than by the data, so a
bar reaching into the red means slow regardless of what else is on screen.

Bars are coloured by latency, so the whole block goes from red to green as the
cache takes hold. `NO_COLOR=1` or `--no-color` turns that off. Colour is on by
default and not autodetected: without a terminal on the other end, `isatty()`
would disable it exactly where it is wanted.

### It is repainted, not reprinted

The frame is redrawn in place once a second — the cursor goes back up over the
previous one and overwrites it. At 1Hz an appending log would be twenty lines
a second scrolling past; repainting means the display sits still and changes,
which is the only way a graph is worth having.

That is also why slow queries appear *inside* the frame rather than scrolling
past it, and why there are always exactly three lines of them, blank when
there is nothing to show. A frame that changed height would leave the tail of
the previous one stranded on screen.

| | |
|---|---|
| `+` | repaint twice as often, down to 0.1s |
| `-` | half as often, up to 10s |
| `r` | back to the default |

The keys need a keyboard behind the process, which is why the demo attaches to
the client rather than following its log — `docker logs -f` is a one-way
stream, which is the whole reason the client container is given a tty. Without
one the display still runs, just at whatever `--interval` (or `$BNCL_REDRAW`)
said.

The histogram's window stays five seconds wide however often the frame is
drawn, so the bars keep enough samples to have a shape; `--window` changes it.
`--plain` appends each frame instead of repainting, which is what you want for
`docker logs` without `-f`, or for piping to a file, where cursor movement is
noise rather than a display.

That is the whole instrument panel, and it is deliberately not enough to tell
a cache hit from a fast query. The only thing the application can observe is
how long the database took.

### Where the slowness comes from

In the server, as a property of the objects being queried. The five slow
statements select from views that cross-join a one-row derived table
containing `SLEEP(0.5 + RAND() * 2.5)` — see the end of `seed_mysql.sql`. The
derived table is materialised once per query, so the cost is paid once
regardless of how many rows come back.

The delay is **random** rather than fixed. A flat 1.5 seconds makes an
unrealistically tidy picture: every slow query costs exactly the same, the
histogram is a single spike, and the average never moves. Real slow queries
scatter — plan changes, buffer pool hits and misses, lock waits — and a cache
has to look good against a distribution, not against one number.

`SLEEP()` in a `WHERE` clause is not the same thing: there it runs per row, so
`... AND SLEEP(1.5) = 0` over three rows takes four and a half seconds. Nor is
`tc netem`, which shapes an interface and delays every packet identically — it
can make the whole database feel remote but cannot make five statements slow
and fifteen fast. `demo/netem.sh` adds that anyway, as a baseline RTT, because
it changes what a cache hit is worth:

```bash
demo/netem.sh on 20ms
```

Putting the latency in the server rather than in the query text also keeps the
client honest. Its statements read like ordinary reporting queries, with
nothing in the text announcing which ones are expensive — which is what the
queries a real administrator puts in a cache list look like.

## Find the slow queries

Everything from here is typed in window 4, the controller's shell.

Window 3 is the client's own log. It reports every query that took longer than
500ms, and a rolling average every five seconds. With nothing cached, five
statements keep showing up:

```
client: SLOW   1.511s   4 row(s) x 4 col(s)  SELECT * FROM brand_rollup
client: SLOW   1.505s   4 row(s) x 3 col(s)  SELECT * FROM customer_spend
client:   5.0s window   avg  0.566s   worst  1.511s     8 queries, 3 over 500ms
client: SLOW   1.505s   3 row(s) x 6 col(s)  SELECT * FROM order_history WHERE status = 'shipped'
client: SLOW   1.509s   3 row(s) x 8 col(s)  SELECT * FROM inventory_report WHERE category = 'safety'
```

That is the list an administrator would arrive at. `barnacle status` agrees
that nothing is being done about it yet:

```
statements    0 configured, 0 cached locally  [demo/config/cache.list]
clients       1 attached
              pid 1343    python3
```

## Cache them

Add those five statements to the cache list and tell barnacle to re-read it.
They are already written out in `demo/config/slow-queries.list`, so you do not
have to transcribe them — and transcribing is exactly what you must not do,
since matching is byte for byte.

```bash
docker compose -f demo/docker-compose.yml exec ctl sh -c 'cat demo/config/slow-queries.list >> demo/config/cache.list'
```

```bash
docker compose -f demo/docker-compose.yml exec ctl barnacle reload-config
```

```
daemon reloaded: 5 statement(s)
generation 2; 1 attached client(s) will pick it up within a quarter second
```

Append from **inside** the controller, as above, rather than editing the file
on your machine. Both work in the end, but a bind-mounted directory can take a
moment to show a host-side write to the container, and a `reload-config` that
wins that race reads the old file and reports `0 statement(s)`. Barnacle says
so when it happens; run it again and it will pick the edit up.

Nothing restarted: not the daemon, not the client, not the agent inside it.
The daemon re-seeded its statement table and bumped a counter that every
attached agent polls.

## What you should see

The client does not restart, reconnect, or notice anything — it has been
running since before the daemon existed. Each of the five slow statements runs
against the server once more — the cache is reactive and
learns only statements someone actually ran — and after that they are served
without the server being contacted at all:

```
# window 3, the client
client: SLOW   1.510s   4 row(s) x 4 col(s)  SELECT * FROM brand_rollup
client:   5.0s window   avg  0.324s   worst  1.512s    14 queries, 3 over 500ms
        <-- reload-config here
client: SLOW   1.509s   4 row(s) x 3 col(s)  SELECT * FROM customer_spend      read-through
client: SLOW   1.505s   3 row(s) x 4 col(s)  SELECT * FROM category_margin     read-through
client:   5.0s window   avg  0.001s   worst  0.002s    33 queries, 0 over 500ms
client:   5.0s window   avg  0.001s   worst  0.002s    35 queries, 0 over 500ms
```

The average falls from a few hundred milliseconds to one, and the "over 500ms"
count goes to zero. Meanwhile window 1 stops showing the five slow statements
entirely, which is the honest half of the demo: a client-side timing number
cannot distinguish a cache hit from a query that ran fast, and this shows a
hit as an **absence**.

`status` agrees:

```
statements    5 configured, 5 cached locally
lookups       18 total: 18 hit, 0 miss, 0 error
stores        5 accepted, 0 refused
clients       1 attached
              pid 21587   python3
```

### What window 2 shows, and what it does not

`SETEX` as each statement is captured, and `GET` when a response has to come
back from Valkey. What it does **not** show is a steady stream during the fast
period — and that is the design, not a fault. There are two tiers: the shared
one in Valkey and a local one in the BPF arena that every attached process has
mapped. A hit served from the arena is a memory read, so no command is sent to
anybody.

Valkey traffic is therefore what you see when the cache is being *populated*
or *revalidated*: once at capture, and again for each statement as its 60
second TTL expires. Leave the window up for a minute and it keeps moving —
each of those is also a `SLOW` line in window 3 and a statement in window 1,
which is the TTL doing its job.

The other time it moves is with a second attached client, or a second host:
that is what the shared tier is for.

### Making every hit go to Valkey

The local tier can be given up on purpose. Uncomment `local_cache = off` in
`demo/config/barnacle.conf` and apply it:

```bash
docker compose -f demo/docker-compose.yml exec ctl barnacle reload-config
```

```
daemon reloaded: 5 statement(s)
local tier bypassed -- every lookup now goes to Valkey
```

Window 2 now shows a `GET` for every cached query the client issues, and
window 3 stays at a millisecond — a Valkey round trip on this network is
nothing next to a second and a half. `status` says which mode it is in:

```
local tier    BYPASSED -- every lookup goes to Valkey
arena         10 KiB of 16384 KiB used, 0 wrap(s)
```

It is not only a way to make the demo louder. With the local tier bypassed the
shared copy is the only authority, so a key expired or deleted in Valkey takes
effect at the next lookup rather than whenever each host's copy happens to age
out, and several hosts stay closer together because none of them is answering
from something the others cannot see. Try it:

```bash
docker exec bncl-valkey valkey-cli flushall
```

With the local tier on, the client keeps being served for up to a TTL. With it
bypassed, the next execution of each statement goes to MySQL and appears in
window 1 immediately.

What it costs is a round trip on the hot path, and the cache stops working
entirely while Valkey is unreachable — there is no longer a local copy to fall
back on. That degrades to passing queries through, which is safe, but it is
the whole cache rather than one tier.

The arena is still how a response gets to the client in both modes: the daemon
writes the bytes it fetched there and the client reads them from there, since
a result set is never copied through the control path. What the switch governs
is whether a copy already sitting there may be *trusted*. The daemon reuses
the chunk when the bytes have not changed, which is why `arena used` barely
moves under a few hundred bypassed lookups — worth watching, because a bump
allocator that wrapped once per lookup would evict other statements long
before their TTL.

## How reload-config reaches a running client

Two things have to move when the list changes, and they move differently
because they live in different places.

The daemon holds the statement table in a BPF map and re-seeds it from the
file — keeping the record for every statement that is still listed, so nothing
already cached is thrown away by a reload that only added something.

Each agent holds its **own** copy of the list, because matching happens on the
application's thread inside `SSL_write` and cannot involve a lookup. So
barnacle writes the new file into each attached process's filesystem, through
`/proc/<pid>/root`, and then the daemon bumps a generation counter that every
agent polls. The file lands before the counter moves, so an agent that notices
the change always finds the new list already there.

Removing a statement works the same way: take it out, reload, and it stops
being cacheable at the next poll. The statement's cached response is dropped
from the map, though it stays in Valkey until its TTL expires.

## Detach, and stop

```bash
docker compose -f demo/docker-compose.yml exec ctl barnacle detach-client
```

Every hooked entry point is put back, and the client's timings return to what
they were. The library stays mapped: unloading it would free trampolines the
process might be executing at that instant.

Detach also clears a flag in a BPF map that every agent polls, which is the
half that cannot fail — it reaches processes the injector cannot get back
into, and it takes effect whether or not unhooking worked.

```bash
docker compose -f demo/docker-compose.yml exec ctl barnacle stop-server
```

```
stopping daemon (pid 21633)
daemon stopped; 1 client(s) still attached and now passing everything through
```

Stopping the daemon while clients are attached is the case worth trying, since
it is the one that could go badly. The application keeps running and goes back
to querying MySQL:

```
agent: the daemon has gone; passing everything through
client: SLOW   1.513s   3 row(s) x 4 col(s)  SELECT * FROM category_margin
```

An agent notices because the daemon removes its pins on the way out. It cannot
notice any other way: a BPF map outlives every pin and every process that made
it, for as long as one descriptor stays open — and the agent is holding those
descriptors, so a dead daemon otherwise leaves it with a complete, readable,
permanently unanswered set of maps.

Start the daemon again and attach again, and it all comes back. The agent
reopens the pins on each attach, which is what makes it land on the new
daemon's maps rather than the old one's.

## Two things that will silently stop it working

Both are properties of the client, not bugs in the cache, and both look
identical from outside: the agent attaches, reports `ready`, and then nothing
happens. `client/app.py` sets both correctly, with a comment saying why.

- **The connection must use TLS.** The cache intercepts inside the TLS
  library, above the encryption, so a plaintext connection has no
  `SSL_read`/`SSL_write` to hook and is invisible to it. MySQLdb does not
  request TLS by default; the client passes `ssl_mode="REQUIRED"`. Check with
  `SHOW STATUS LIKE 'Ssl_cipher'` — an empty value means plaintext.
- **Autocommit must be on.** MySQLdb defaults it off, which means every
  statement runs inside an open transaction, and the cache deliberately
  bypasses those: the rows may reflect uncommitted state private to that
  session. `SET autocommit=0` in the tail output is the giveaway.

## Statements are matched byte for byte

`config/cache.list` is an exact match against the statement text on the wire —
no normalisation, no parameter extraction. A statement that differs by one
space is a different statement. This is why the demo's list is written to
match `client/app.py`'s query lists exactly, and why a test
(`tests/test_request.cpp`) checks that every statement in the list is one the
client actually issues.

## Tear down

```bash
demo/down.sh
```

That stops the daemon before removing the containers, which matters: `compose
down` signals the container's PID 1 (`sleep infinity`), not the daemon, so the
daemon is killed without running its shutdown path. `/sys/fs/bpf` is bind
mounted from the host, and the daemon is what removes its pins from it — left
behind, they keep the maps alive with nobody serving them. `down.sh` cleans
them up either way.

- `demo/down.sh --stop` keeps the containers, for a fast restart
- `demo/down.sh --wipe` also drops MySQL's data, so the next `up.sh` reseeds
  from `seed_mysql.sql` — including the views

Running the demo leaves `demo/config/cache.list` with the five statements you
added. `git checkout demo/config/cache.list` puts it back to empty for the
next run.

The compose file pins its project name to `barnacle`, so these commands
work from any directory. Compose would otherwise derive the project from the
directory holding the file (`demo`), and a command run from elsewhere would
quietly address a different stack than the one that is up.

## Using your own config instead of the demo's

`demo/config/` is pinned to this stack and checked in as part of the demo. For
a real deployment, copy the templates at the repository root:

```bash
cp config/barnacle.conf.example config/barnacle.conf
cp config/cache.list.example config/cache.list
```

Both are gitignored, since what to attach to and which queries to cache is
specific to each deployment.

Barnacle is meant to run on the **host**, where `/proc` shows every process
including those inside containers, and where their cgroups identify which
container each belongs to. Running it inside the controller — as the demo
does, so that the barnacle host is itself a container you can look inside —
works, but that container has its own cgroup namespace, so no container can be
identified and the `container` filter cannot be applied. Barnacle says so
rather than silently ignoring it, and shows `?` in the `WHERE` column.
