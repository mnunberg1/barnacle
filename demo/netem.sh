#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# netem.sh - add a baseline network delay in front of MySQL.
#
# The demo's real latency is server-side and per-statement: five of the
# client's twenty queries hit views that take between half a second and three
# seconds to produce
# (see the end of demo/seed_mysql.sql). This is the other kind, and it is
# worth being clear about why it is a separate thing rather than the mechanism.
#
# `tc qdisc ... netem delay` shapes an interface. It delays every packet the
# same way, so it can make the whole database feel remote -- which is
# realistic, since a production MySQL is rarely on the same host -- but it
# cannot make five statements slow and fifteen fast. Those are different
# properties and they need different tricks.
#
# It is still worth having, because it changes what a cache hit is worth: with
# a few milliseconds of RTT, even the fifteen "instantaneous" queries cost a
# round trip, and the ones served from the local arena do not.
#
# Applied from a helper container sharing MySQL's network namespace, so the
# mysql image needs neither iproute2 nor NET_ADMIN.
#
# Usage:
#   demo/netem.sh on [DELAY]      default 2ms; try 20ms for "another region"
#   demo/netem.sh off
#   demo/netem.sh show

set -u

CONTAINER="${MYSQL_CONTAINER:-bncl-mysql}"
IFACE="${NETEM_IFACE:-eth0}"
ACTION="${1:-show}"
DELAY="${2:-2ms}"

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
        echo "netem: no container named '$CONTAINER'; bring the demo up first." >&2
        exit 1
fi

# The controller's image already has iproute2, and it is already built.
# Borrowing it avoids pulling a second image just to run one command.
IMAGE="$(docker inspect bncl-ctl --format '{{.Config.Image}}' 2>/dev/null)"
if [ -z "$IMAGE" ]; then
        echo "netem: the controller is not up; its image is what carries tc." >&2
        exit 1
fi

tc_in_ns() {
        docker run --rm \
                --network "container:$CONTAINER" \
                --cap-add NET_ADMIN \
                "$IMAGE" tc "$@"
}

case "$ACTION" in
on)
        # `replace` rather than `add`, so running this twice changes the delay
        # instead of failing with "file exists".
        tc_in_ns qdisc replace dev "$IFACE" root netem delay "$DELAY" || exit 1
        echo "netem: every packet to and from $CONTAINER now delayed $DELAY"
        echo "       the fifteen fast queries will each cost about one round trip"
        ;;
off)
        tc_in_ns qdisc del dev "$IFACE" root 2>/dev/null
        echo "netem: delay removed from $CONTAINER"
        ;;
show)
        tc_in_ns qdisc show dev "$IFACE"
        ;;
*)
        sed -n '3,26p' "$0" | sed 's/^# \?//'
        exit 2
        ;;
esac
