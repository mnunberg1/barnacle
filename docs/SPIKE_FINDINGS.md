# Phase 1 Spike — Findings

**Verdict: the architecture holds. All three assumptions validated end-to-end
against a real MySQL server over a real TLS connection.**

Run `make -C spike` inside the `bpf` container to reproduce; see
`ssl_intercept.c` for the mechanism and the exact commands.

## What was tested

The transparent cache depends on three things being true. None were proven
before this spike, and if any had failed the design would have needed
rethinking — so they were tested before anything was built on them.

`LD_PRELOAD` was used rather than bpftime deliberately. Whether a function
*can* be hooked was never in doubt (Frida-gum hooks strictly more than
`LD_PRELOAD` can). The open question was whether **OpenSSL and real MySQL
clients behave correctly** when we do these things — and that is identical
under either mechanism.

| # | Assumption | Result |
|---|---|---|
| 1 | A query can be suppressed at `SSL_write`; the client believes it was sent | ✅ |
| 2 | `read()`/`recv()` can return `EINTR`; OpenSSL treats it as retryable, not fatal | ✅ |
| 3 | `SSL_read`'s output buffer *and* return value can be overridden | ✅ |

## The decisive experiment

Capture the response to query **A**, then have the client ask query **B** and
inject A's response. If the client shows A's data, it cannot have come from
the server.

- Baseline over TLS: `A → SKU-004`, `B → SKU-001, SKU-002, SKU-007`
- With the shim, asking **B** returned **`SKU-004`**

The query was suppressed, `read()` returned `EINTR`, the real `SSL_read`
returned `-1`, and 87 bytes were injected. The client rendered the result set
correctly and exited cleanly.

## Session survival — the result that actually matters

A single injection proves the mechanism; it does not prove the design is
usable. Long-lived pooled connections mean the session must survive.

Sequence: real query → injected query → real query

```
live-1 : Cordless Drill      <- real
TARGET : SKU-004             <- injected
live-2 : 10                  <- real
```

The TLS session was undamaged and immediately usable. `EINTR` did not
poison OpenSSL's state machine, which was the specific risk.

Verified identically for both the `mysql` CLI and Python/PyMySQL.

## Findings that change the design

### 1. Two OpenSSL entry-point families must be hooked, not one

- `mysql` CLI imports `SSL_read` / `SSL_write`
- CPython's `_ssl` imports **only** `SSL_read_ex` / `SSL_write_ex`

Hooking one family silently misses entire classes of client — notably every
Python driver, which is the motivating use case. The `_ex` forms differ in
signature: they return 1/0 for success/failure and report the byte count via
an out-parameter.

**Action:** UCLIENT hooks a minimum of four symbols. Worth auditing other
drivers (Go, JDBC, PHP) for further variants before declaring coverage.

### 2. TLS libraries can arrive late, via `dlopen`

Resolving `SSL_*` eagerly at attach time yields `NULL` for a Python process,
because the first intercepted call happens during interpreter startup — long
before `import ssl` loads `_ssl.so`. Caching those `NULL`s segfaults on the
first real call. (This spike hit exactly that.)

**Action:** UCLIENT must be able to attach to `libssl` *when it appears*, not
only at process start.

### 3. Python loads `libssl` into a private namespace

`_ssl.so` is `dlopen`ed with `RTLD_LOCAL`, so `libssl.so.3` lands in a scope
that `RTLD_NEXT` does not search. Interposition still works — calls bind
against the global scope first — but reaching the *genuine* function behind
the hook needs `dlopen(..., RTLD_NOLOAD)`.

This is an `LD_PRELOAD`-specific limitation. **bpftime/Frida-gum patch by
address rather than through the dynamic linker, so the real implementation is
not subject to it** — this case gets easier, not harder.

### 4. Verbatim replay worked, which is informative for E2

The captured 87 bytes were replayed byte-for-byte and accepted. MySQL resets
the packet sequence id per command, so a response captured and replayed at the
same point in the command cycle lines up without renumbering.

This does **not** retire E1/E2 — renumbering is still required when replaying
onto a connection whose counter sits elsewhere, and capability-dependent
framing (`CLIENT_DEPRECATE_EOF` especially) still differs across connections.
But it does suggest raw-blob caching is viable *between connections that
negotiated identical capabilities*, which is the common case within one
application.

### 5. bpftime builds and runs on aarch64

Its CI is x86_64-only (`linux/amd64` explicitly), which was a live risk given
this host and container are both arm64. In practice:

- builds clean with LLVM 18 on Debian trixie / aarch64
- the `malloc` uprobe example **runs**, so Frida-gum binary rewriting works
- counts crossed process boundaries via shared maps, so inter-process shm maps
  work

Kernel↔userspace map sharing is still unproven and remains a Phase 3/4 risk.

## Residual risks

- **`EINTR` handling is client-dependent.** Validated for the `mysql` CLI and
  PyMySQL. Go, JDBC and PHP drivers have not been tested and some code treats
  `EINTR` as fatal. This is load-bearing for the whole TLS path.
- **bpftime remains research-grade**, and kernel-map interop — the piece this
  design needs for KCLIENT↔UCLIENT — is its least-exercised path.
- **Only OpenSSL is covered.** GnuTLS, NSS, Go's `crypto/tls` and JSSE have
  entirely different (or absent) entry points.
