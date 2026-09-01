#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# up.sh - get the demo to its starting position, in one command.
#
# The starting position is NOT a working cache. It is four containers running,
# the client issuing queries, five of them slow, and nothing cached -- because
# the demo is what happens next: you read the client's log, see which queries
# are slow, add those to the cache list, and reload. Bringing that about is
# five commands of docker-compose bookkeeping, which is all this is.
#
#   1. start the four containers, wait for them to be healthy
#   2. build barnacle inside the controller
#   3. start the daemon
#   4. attach the agent to the client that is already running
#
# Everything here can be typed by hand, and demo/README.md walks through it
# that way. This is for the second and subsequent times.
#
# Usage:
#   demo/up.sh                 bring it up and attach
#   demo/up.sh --no-attach     leave the client unattached
#   demo/up.sh --rebuild       force a docker image rebuild first
#
# Then: demo/terminals.sh opens the four windows to watch it in.
#       demo/down.sh shuts it all down cleanly.

set -u

cd "$(dirname "$0")/.." || exit 1

COMPOSE="docker compose -f demo/docker-compose.yml"
CTL="docker exec -w /workspace bncl-ctl"
ATTACH=1
BUILD_ARGS=""

for arg in "$@"; do
        case "$arg" in
        --no-attach) ATTACH=0 ;;
        --rebuild) BUILD_ARGS="--build" ;;
        -h | --help)
                sed -n '3,26p' "$0" | sed 's/^# \?//'
                exit 0
                ;;
        *)
                echo "unknown option: $arg" >&2
                exit 2
                ;;
        esac
done

say() { printf '\n== %s\n' "$1"; }

say "starting containers"
# --wait blocks until every service with a healthcheck reports healthy, which
# is what makes the build step below safe to run immediately.
$COMPOSE up -d --wait $BUILD_ARGS || exit 1

say "building"
$CTL make || exit 1

say "starting the daemon"
$CTL barnacle start-server || exit 1

if [ "$ATTACH" = 1 ]; then
        say "attaching to the client"
        $CTL barnacle attach-client 2>&1 | tail -3 || exit 1
fi

cat <<'EOF'

== ready

Nothing is cached yet, on purpose: the cache list starts empty. The client is
running and five of its twenty queries take between half a second and
three seconds each.

  1. watch it            demo/terminals.sh
                         (or just: docker logs -f bncl-client)

  2. see which are slow  the client reports every query over 500ms

  3. cache them          docker compose -f demo/docker-compose.yml exec ctl sh -c \
                             'cat demo/config/slow-queries.list >> demo/config/cache.list'
                         docker compose -f demo/docker-compose.yml exec ctl \
                             barnacle reload-config

  4. watch it get faster the client's average falls to a millisecond, and the
                         MySQL window goes quiet

  5. put it back         docker compose -f demo/docker-compose.yml exec ctl \
                             barnacle detach-client

Shut down:  demo/down.sh
EOF
