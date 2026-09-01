#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# down.sh - shut the demo down cleanly.
#
# `docker compose down` on its own is very nearly enough. The one thing it
# does not do is stop the daemon: compose signals the container's PID 1, which
# is `sleep infinity`, while the daemon is a process started alongside it. It
# gets killed without ever running its shutdown path.
#
# That matters because /sys/fs/bpf is bind-mounted from the host. The daemon
# removes its pins on a clean exit; killed outright, it leaves them behind --
# and a pinned map stays alive with no process holding it, so the next daemon
# would find a complete-looking set of maps belonging to nobody.
#
# So: stop the daemon first, then the containers.
#
# Usage:
#   demo/down.sh              stop and remove the containers
#   demo/down.sh --keep-data  leave MySQL's volume alone (default is to keep)
#   demo/down.sh --wipe       also drop MySQL's data, so the next up reseeds
#   demo/down.sh --stop       just stop them, keep them for a fast restart

set -u

cd "$(dirname "$0")/.." || exit 1

COMPOSE="docker compose -f demo/docker-compose.yml"
MODE=down

for arg in "$@"; do
        case "$arg" in
        --wipe) MODE=wipe ;;
        --stop) MODE=stop ;;
        --keep-data) MODE=down ;;
        -h | --help)
                sed -n '3,23p' "$0" | sed 's/^# \?//'
                exit 0
                ;;
        *)
                echo "unknown option: $arg" >&2
                exit 2
                ;;
        esac
done

if docker inspect bncl-ctl >/dev/null 2>&1; then
        echo "== stopping the daemon"
        docker exec -w /workspace bncl-ctl barnacle stop-server 2>/dev/null ||
                echo "   (it was not running)"
        # Belt and braces: if the daemon was killed in some earlier run, its pins
        # are still there and nothing else will remove them.
        docker exec bncl-ctl rm -rf /sys/fs/bpf/barnacle 2>/dev/null
fi

case "$MODE" in
stop)
        echo "== stopping containers (keeping them)"
        $COMPOSE stop
        echo
        echo "Start again with: $COMPOSE start   (or demo/up.sh)"
        ;;
down)
        echo "== removing containers"
        $COMPOSE down
        echo
        echo "MySQL's data volume was kept. demo/down.sh --wipe drops it too."
        ;;
wipe)
        echo "== removing containers and MySQL's data"
        $COMPOSE down -v
        echo
        echo "The next demo/up.sh will reseed from demo/seed_mysql.sql."
        ;;
esac
