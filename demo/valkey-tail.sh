#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# valkey-tail.sh - watch what the cache is actually asked to do.
#
# `valkey-cli monitor` shows every command the server receives, which is the
# right source and the wrong signal-to-noise ratio for a demo:
#
#   - the compose healthcheck runs `valkey-cli ping` every five seconds, and
#     `barnacle status` runs DBSIZE, so most lines are bookkeeping nobody is
#     watching for.
#   - a SETEX carries the cached response inline. A stored result set is a
#     few hundred bytes of MySQL wire protocol, escaped, on one line -- over
#     1600 characters in practice. It wraps, it scrolls the pane, and it says
#     nothing a person can read.
#   - the timestamp is a unix epoch with microseconds, which cannot be
#     eyeballed against the MySQL window.
#
# So this keeps the commands that are about the cache, prints a clock, and
# says `<payload>` where the blob was. The keys lose their `bncl:` prefix,
# which every one of them has.
#
# Usage:
#   demo/valkey-tail.sh              cache commands only
#   demo/valkey-tail.sh -a           everything, unfiltered and unformatted
#   demo/valkey-tail.sh --off        (nothing to turn off; MONITOR is read-only)
#
# Formatting is done in python rather than awk, unlike demo/mysql-tail.sh:
# turning an epoch into a local clock needs strftime(), which gawk has and the
# awk on a macOS host does not.

set -u

CONTAINER="${VALKEY_CONTAINER:-bncl-valkey}"
ALL=0

for arg in "$@"; do
    case "$arg" in
    -a | --all) ALL=1 ;;
    --off)
        echo "valkey-tail: MONITOR only reads; there is nothing to turn off."
        exit 0
        ;;
    -h | --help)
        sed -n '3,30p' "$0" | sed 's/^# \?//'
        exit 0
        ;;
    *)
        echo "unknown option: $arg" >&2
        exit 2
        ;;
    esac
done

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    echo "valkey-tail: no container named '$CONTAINER'." >&2
    echo "             Bring the demo up first, or set VALKEY_CONTAINER." >&2
    exit 1
fi

echo "watching $CONTAINER -- every command below reached the cache."
echo "a hit served from this host's arena sends nothing and will not appear."
echo "ctrl-c to stop.  -a for the unfiltered stream."
echo

if [ "$ALL" = 1 ]; then
    exec docker exec -i "$CONTAINER" valkey-cli monitor
fi

docker exec -i "$CONTAINER" valkey-cli monitor 2>/dev/null | python3 -u -c '
import re
import sys
import time

# Commands that are somebody keeping house, not the cache doing its job. The
# healthcheck pings; barnacle status calls DBSIZE; valkey-cli itself opens with
# COMMAND DOCS and HELLO.
NOISE = {
    "ping", "dbsize", "command", "hello", "auth", "select", "info",
    "client", "config", "subscribe", "psubscribe", "replconf",
}

LINE = re.compile(r"^([0-9]+)\.([0-9]+) \[[0-9]+ [^]]+\] (.*)$")
# Quoted arguments, honouring backslash escapes so a value containing \" does
# not end the token early.
ARG = re.compile(r"\"((?:[^\"\\]|\\.)*)\"")

for raw in sys.stdin:
    m = LINE.match(raw.rstrip("\n"))
    if not m:
        continue  # the leading OK from valkey-cli, and anything unparsed

    args = ARG.findall(m.group(3))
    if not args:
        continue
    cmd = args[0].upper()
    if cmd.lower() in NOISE:
        continue

    when = time.strftime("%H:%M:%S", time.localtime(int(m.group(1))))
    when += "." + m.group(2)[:3]

    key = args[1] if len(args) > 1 else ""
    if key.startswith("bncl:"):
        key = key[5:]

    extra = ""
    if cmd == "SETEX" and len(args) >= 4:
        extra = "   ttl %ss   <payload>" % args[2]
    elif len(args) > 2:
        # Anything else: show the remaining arguments, but never a blob.
        rest = [a if len(a) <= 24 else "<payload>" for a in args[2:]]
        extra = "   " + " ".join(rest)

    print("%s  %-7s %s%s" % (when, cmd, key, extra))
'
