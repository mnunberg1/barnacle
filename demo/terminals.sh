#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# terminals.sh - open the four panes the demo is meant to be watched in.
#
#   1. MySQL          every statement that actually reaches the server
#   2. Valkey         MONITOR: every command the daemon sends the cache
#   3. Client         the application's own log: a latency histogram
#   4. Control        a shell on the controller, for `barnacle ...`
#
# Four panes rather than one window because the interesting thing is a
# relationship between them. When the cache takes over, pane 3 gets faster,
# pane 1 goes quiet, and pane 2 starts moving -- and none of those three facts
# means much without the other two. A single interleaved log would show the
# same events and hide the shape.
#
# tmux, on every platform. Driving a terminal emulator through AppleScript
# worked, but only on macOS, only for Terminal.app, and it put the four
# windows wherever the window manager felt like: everything tmux does properly
# and portably. `ctrl-b z` zooms a pane to full screen, which is what makes
# four panes on a laptop readable -- see the tmux section of demo/README.md.
#
# Usage:
#   demo/terminals.sh              create the session, or reattach to it
#   demo/terminals.sh --print      just print the four commands
#   demo/terminals.sh --kill       tear the session down
#
# The stack must already be up: this starts nothing, so a pane that dies takes
# nothing with it.

set -u

cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"

COMPOSE="docker compose -f demo/docker-compose.yml"
SESSION=barnacle

TITLE1="MySQL - what reaches the server"
CMD1="demo/mysql-tail.sh"

TITLE2="Valkey - what reaches the cache"
CMD2="demo/valkey-tail.sh"

TITLE3="Client - latency, live  (+/- repaint rate)"
# attach rather than `logs -f`, so keystrokes reach the client and +/- can
# change how often its display repaints. --sig-proxy=false is what makes that
# safe: ctrl-c detaches this pane instead of killing the container.
CMD3="docker attach --sig-proxy=false bncl-client"

TITLE4="Control - the controller"
CMD4="$COMPOSE exec ctl bash"

MODE=attach
for arg in "$@"; do
    case "$arg" in
    --print) MODE=print ;;
    --kill) MODE=kill ;;
    -h | --help)
        sed -n '3,29p' "$0" | sed 's/^# \?//'
        exit 0
        ;;
    *)
        echo "unknown option: $arg" >&2
        exit 2
        ;;
    esac
done

if [ "$MODE" = print ]; then
    echo "Run each of these in its own terminal, from $ROOT:"
    echo
    printf '  # %s\n  %s\n\n' "$TITLE1" "$CMD1"
    printf '  # %s\n  %s\n\n' "$TITLE2" "$CMD2"
    printf '  # %s\n  %s\n\n' "$TITLE3" "$CMD3"
    printf '  # %s\n  %s\n\n' "$TITLE4" "$CMD4"
    exit 0
fi

if ! command -v tmux >/dev/null 2>&1; then
    echo "terminals: tmux is not installed." >&2
    echo "           brew install tmux   (or your package manager)" >&2
    echo "           demo/terminals.sh --print lists the four commands." >&2
    exit 1
fi

if [ "$MODE" = kill ]; then
    tmux kill-session -t "$SESSION" 2>/dev/null &&
        echo "killed the '$SESSION' session. The demo itself is untouched." ||
        echo "no '$SESSION' session to kill."
    exit 0
fi

if ! docker inspect bncl-client >/dev/null 2>&1; then
    echo "terminals: the demo stack is not up." >&2
    echo "           demo/up.sh" >&2
    exit 1
fi

if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "reattaching to the '$SESSION' session."
else
    # One window, four panes, tiled: they have to be visible at the same time
    # to be worth anything. Each pane runs its command directly, so a pane
    # whose command exits closes rather than sitting there looking live.
    #
    # Created at a generous size rather than the default 80x24. A detached
    # session keeps whatever size it was made at, and tmux refuses a split
    # that would leave a pane below its minimum -- so at the default the third
    # and fourth panes silently fail to appear. Attaching resizes to the real
    # terminal anyway.
    #
    # Panes are addressed by the id each split reports, not by index. Indices
    # renumber as panes are added, so an index captured before the next split
    # is a different pane afterwards -- which is how the titles came to be on
    # the wrong panes the first time.
    p1=$(tmux new-session -d -s "$SESSION" -n demo -x 220 -y 60 -c "$ROOT" \
        -P -F '#{pane_id}' "$CMD1")
    p2=$(tmux split-window -t "$p1" -h -c "$ROOT" -P -F '#{pane_id}' "$CMD2")
    p3=$(tmux split-window -t "$p1" -v -c "$ROOT" -P -F '#{pane_id}' "$CMD3")
    p4=$(tmux split-window -t "$p2" -v -c "$ROOT" -P -F '#{pane_id}' "$CMD4")

    tmux select-layout -t "$SESSION":demo tiled

    # A label under each pane saying what it is and which keys reach it.
    #
    # Window-scoped, not global: `set-option -g` would change the border in
    # every tmux window this user has open, which is not ours to do.
    #
    # pane-border-format is a format string re-evaluated per pane, so
    # #{pane_index} is always the number `C-b q` will flash up on that pane --
    # unlike a number baked into the title, which goes stale the moment the
    # layout changes.
    tmux set-window-option -t "$SESSION":demo pane-border-status bottom
    tmux set-window-option -t "$SESSION":demo pane-border-format \
        " #{pane_index}  #{pane_title}   |   focus: C-b q #{pane_index}   |   scroll: C-b [   |   zoom: C-b z "

    tmux select-pane -t "$p1" -T "$TITLE1"
    tmux select-pane -t "$p2" -T "$TITLE2"
    tmux select-pane -t "$p3" -T "$TITLE3"
    tmux select-pane -t "$p4" -T "$TITLE4"

    # Land on the control pane: it is the only one anybody types into.
    tmux select-pane -t "$p4"
fi

if [ -n "${TMUX:-}" ]; then
    tmux switch-client -t "$SESSION"
else
    tmux attach -t "$SESSION"
fi
