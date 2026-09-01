#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# mysql-tail.sh - watch what actually reaches the database.
#
# The whole claim of this project is that a cached statement never reaches
# mysqld. That is not something a client-side timing number can prove on its
# own -- a fast response could just be a fast query. This watches the server
# from the other side, so a hit is visible as an ABSENCE: the client gets its
# rows and nothing arrives here.
#
# Uses MySQL's general query log, which records every statement the server is
# asked to run. The demo stack turns it on in docker-compose.yml, so it is
# already running before this script starts and nothing is missed. If it is
# off -- against a server this stack did not configure -- this enables it at
# runtime, which needs no restart.
#
# The general log is a debugging tool, not something to leave on in
# production: it writes a line per statement and grows without bound. The demo
# enables it because this stack exists to be watched.
#
# Usage:
#   demo/mysql-tail.sh              follow queries as they arrive
#   demo/mysql-tail.sh -a           include Connect/Quit, not just queries
#   demo/mysql-tail.sh --off        turn the log off and exit
#
# Run it in a second terminal, then run the workload in the first.

set -u

CONTAINER="${MYSQL_CONTAINER:-bncl-mysql}"
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-rootpw}"
LOGFILE=/var/lib/mysql/general.log

ALL=0
OFF=0
for arg in "$@"; do
        case "$arg" in
        -a | --all) ALL=1 ;;
        --off) OFF=1 ;;
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

sql() {
        docker exec -i "$CONTAINER" mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -N -e "$1" 2>/dev/null
}

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
        echo "mysql-tail: no container named '$CONTAINER'." >&2
        echo "            Bring the demo up first, or set MYSQL_CONTAINER." >&2
        exit 1
fi

if [ "$OFF" = 1 ]; then
        sql "SET GLOBAL general_log = 'OFF';"
        echo "general log off"
        exit 0
fi

# Normally already on, from the flags in docker-compose.yml. Enable it only if
# it is not, so the common case touches no server state at all -- and point it
# at a predictable path, since the default is named after the container's
# hostname and changes whenever the container is recreated.
if [ "$(sql 'SELECT @@general_log;')" != "1" ]; then
        echo "general log was off; enabling it for this session"
        sql "SET GLOBAL general_log_file = '$LOGFILE'; SET GLOBAL general_log = 'ON';"
        if [ "$(sql 'SELECT @@general_log;')" != "1" ]; then
                echo "mysql-tail: could not enable the general log." >&2
                exit 1
        fi
else
        LOGFILE="$(sql 'SELECT @@general_log_file;')"
fi

echo "watching $CONTAINER:$LOGFILE -- every statement below REACHED the server."
echo "a cached statement will not appear at all. ctrl-c to stop."
echo "(the demo stack leaves this log on; 'mysql-tail.sh --off' stops it)"
echo

# -n0: start at the end, so only traffic from now on is shown.
#
# Each log line is: timestamp<TAB>connection-id<TAB>command<TAB>argument.
# Reformat to something readable and drop the server's own bookkeeping --
# the version probe every client sends on connect, and the log's header.
docker exec -i "$CONTAINER" tail -n0 -F "$LOGFILE" 2>/dev/null |
        awk -v all="$ALL" '
        /^[0-9]{4}-/ {
                ts = substr($1, 12, 12)
                id = $2
                cmd = $3
                arg = ""
                if (NF > 3) {
                        arg = substr($0, index($0, $4))
                }
                if (cmd == "Query" && arg ~ /^select @@version_comment/) { next }
                # Bookkeeping from this script itself, not application traffic.
                if (cmd == "Query" && arg ~ /general_log/) { next }
                if (cmd != "Query" && all == 0) { next }
                printf "%s  conn=%-6s %-8s %s\n", ts, id, cmd, arg
                fflush()
                next
        }
        # A statement can span lines; show continuations indented under it.
        all == 1 || prev_was_query { printf "                        %s\n", $0; fflush() }
        '
