#!/usr/bin/env python3
"""app.py - the demo's client application.

A sealed program, in its own container, that knows nothing about the cache.
It opens one connection to MySQL and issues queries from a fixed repertoire,
at random, forever. There is no cache-aware code here and no hook for one:
everything the cache does to this process is done from outside it, to a
process that is already running.

What it reports is what an operator would actually have:

  - every query slower than 500ms, as it happens
  - a latency histogram every 5 seconds, plus a trend of recent windows

That is the whole instrument panel. It cannot tell a cache hit from a query
that simply ran fast, which is the point -- the only thing it can observe is
how long the database took, and after the cache is attached that number falls
without a single line of this file changing.

A histogram rather than an average because an average hides the shape, and the
shape is the story: before the cache, a clump down at a millisecond and a
smear across one to three seconds; after it, everything collapses into the
first bucket. An average moving from 0.4s to 0.001s says the same thing in a
way nobody can see happening.

Twenty statements: fifteen return immediately, five take somewhere between half
a second and three. The slow ones are slow because of what they query, not how
-- see the views at the end of demo/seed_mysql.sql. Nothing in their text says
"slow", and no two executions take the same time.
"""

from __future__ import annotations

import argparse
import collections
import math
import os
import random
import select
import sys
import termios
import time
import tty

import MySQLdb
from MySQLdb import Error as MySQLError
from MySQLdb import InterfaceError, OperationalError

# --- the repertoire -------------------------------------------------------
#
# Written out one per line and matched byte for byte by the cache list, so the
# text here and the text in demo/config/cache.list have to agree exactly. That
# is a property of the cache, not of this file: matching is exact bytes, with
# no normalisation and no parameter extraction.

FAST = [
    "SELECT * FROM products WHERE category = 'tools'",
    "SELECT * FROM products WHERE category = 'safety'",
    "SELECT * FROM products WHERE brand = 'acme'",
    "SELECT * FROM products WHERE brand = 'globex'",
    "SELECT name, price FROM products WHERE stock = 0",
    "SELECT sku, price FROM products WHERE price < 30",
    "SELECT sku, name FROM products WHERE rating >= 4.5",
    "SELECT sku, stock FROM products WHERE stock < 50",
    "SELECT COUNT(*) FROM products",
    "SELECT * FROM orders WHERE status = 'shipped'",
    "SELECT * FROM orders WHERE status = 'pending'",
    "SELECT * FROM orders WHERE customer = 'wayne industries'",
    "SELECT id, total FROM orders WHERE total > 100",
    "SELECT customer, qty FROM orders WHERE qty >= 5",
    "SELECT COUNT(*) FROM orders",
]

# One and a half seconds each, in the server. Ordinary-looking reporting
# queries against views that are expensive to produce.
SLOW = [
    "SELECT * FROM inventory_report WHERE category = 'safety'",
    "SELECT * FROM order_history WHERE status = 'shipped'",
    "SELECT * FROM brand_rollup",
    "SELECT * FROM customer_spend",
    "SELECT * FROM category_margin",
]

QUERIES = FAST + SLOW

# Anything above this is called out as it happens. Half a second is the point
# at which a person waiting on a page notices.
SLOW_MS = 500

# The histogram covers a sliding window this wide...
WINDOW_SECS = 5.0

# ...and the whole frame is repainted this often. A second is fast enough that
# the change is something you watch happen rather than something you notice
# afterwards, and the window stays five seconds wide so the bars still have
# enough samples in them to have a shape.
#
# Repainted, not reprinted: at 1Hz an appending log would be twenty lines a
# second scrolling past. The frame is drawn once and then overwritten in place
# with cursor movement, so it sits still and changes. That needs a terminal on
# the other end -- `docker logs -f`, which is how the demo watches it. Piping
# to a file, or `docker logs` without -f, wants --plain instead.
REDRAW_SECS = 1.0

# Slow queries are shown inside the frame rather than scrolling past it: with
# the frame being repainted, anything printed between repaints would land in
# the middle of it. The most recent few are the useful ones anyway.
SLOW_KEEP = 3


def say(msg):
    """One line, one write.

    print() emits the text and the newline separately, which is invisible
    until something else writes to the same descriptor between them -- and a
    histogram torn in half by a SLOW line is worse than either on its own.
    """
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def make_arg_parser(**kwargs) -> argparse.ArgumentParser:
    if sys.version_info >= (3, 14):
        kwargs["color"] = False
    return argparse.ArgumentParser(**kwargs)


def connect(args):
    return MySQLdb.connect(
        host=args.host,
        port=args.port,
        user=args.user,
        passwd=args.password,
        db=args.db,
        connect_timeout=5,
        # The cache intercepts inside the TLS library, above the encryption --
        # so a plaintext connection has no SSL_read/SSL_write to hook and is
        # invisible to it. MySQLdb does not request TLS by default, so without
        # this the agent attaches, reports "ready", and then never sees a
        # single query. Encrypted connections are the normal case in
        # production, which is exactly why intercepting there is the point.
        ssl_mode="REQUIRED",
        # MySQLdb defaults to autocommit OFF, which means every statement runs
        # inside an open transaction -- and the cache deliberately bypasses
        # those, since the rows may reflect uncommitted state private to this
        # session. Without this the demo attaches successfully and then never
        # caches anything, which looks like a bug in the cache rather than a
        # property of the client. A real read-mostly app would set this too.
        autocommit=True,
    )


# --- the display ----------------------------------------------------------
#
# Log-spaced buckets, because the interesting range spans four orders of
# magnitude: a cache hit is under a millisecond and a miss is seconds. Linear
# buckets would put every hit in the first one and say nothing about the
# difference between 0.2ms and 0.9ms, which is exactly where the cache lives.
#
# Upper bound in seconds, and the label to print for it.
BUCKETS = [
    (0.001, "<1ms"),
    (0.010, "<10ms"),
    (0.100, "<100ms"),
    (0.500, "<500ms"),
    (1.000, "<1s"),
    (2.000, "<2s"),
    (float("inf"), "2s+"),
]

BAR_WIDTH = 46

# Eighths, for partial rows in the trend graph. Sub-character resolution is
# what lets six rows cover four decades without the bars looking quantised.
SPARK = " ▁▂▃▄▅▆▇█"

# The trend graph: how tall, how many columns wide, and the fixed range of its
# log y-axis.
#
# Fixed, not autoscaled to what has been seen. An axis that rescales redraws
# the past every time a new extreme arrives, so the bar that was head-height a
# moment ago is knee-height now and nothing can be compared with anything.
# Half a millisecond to four seconds covers a cache hit at one end and the
# slowest query the demo can produce at the other.
GRAPH_H = 6
GRAPH_W = 60  # one column per repaint
GRAPH_LO = 0.0005
GRAPH_HI = 4.0

# How far the interval can be pushed with +/-, and the step between stops.
RATE_MIN = 0.1
RATE_MAX = 10.0

# Colour by how bad the latency is, so the histogram goes from red to green as
# the cache takes over -- visible from across a room, which an average is not.
GREEN, YELLOW, RED, DIM, BOLD, OFF = (
    "\033[32m", "\033[33m", "\033[31m", "\033[2m", "\033[1m", "\033[0m")

# Move the cursor up N lines, and clear a line where it stands. This is the
# whole of the in-place repaint: go back to where the frame started, then
# overwrite every line of it.
UP = "\033[%dA"
CLEAR = "\033[2K"


def bucket_colour(i):
    if i <= 2:
        return GREEN
    if i <= 4:
        return YELLOW
    return RED


def latency_colour(secs):
    """The band a duration falls in.

    Shared by the histogram's rows and the trend graph's, so a height in one
    means the same thing as a height in the other.
    """
    if secs < 0.100:
        return GREEN
    if secs < 0.500:
        return YELLOW
    return RED


def dur(secs):
    """A duration a person can read at a glance."""
    if secs < 0.001:
        return "%.0fus" % (secs * 1e6)
    if secs < 1:
        return "%.0fms" % (secs * 1e3)
    return "%.2fs" % secs


class Window:
    """Query timings over a sliding window, and the frame drawn from them."""

    def __init__(self, colour=True, window=WINDOW_SECS):
        self.colour = colour
        self.window = window
        self.samples = collections.deque()  # (monotonic, seconds)
        self.slow = collections.deque(maxlen=SLOW_KEEP)
        self.trend = []

    def add(self, now, elapsed, note=None):
        self.samples.append((now, elapsed))
        if note:
            self.slow.append(note)

    def prune(self, now):
        """Drop what has aged out of the window.

        A sliding window rather than a bucket that empties on every repaint:
        at one repaint a second a bucket would hold a handful of samples and
        the histogram would jump around from noise. The window stays five
        seconds wide however often it is drawn.
        """
        cutoff = now - self.window
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def paint(self, text, code):
        return "%s%s%s" % (code, text, OFF) if self.colour else text

    def percentile(self, pct):
        """Nearest-rank. Sorted per call: a window holds tens of samples."""
        if not self.samples:
            return 0.0
        ordered = sorted(t for _, t in self.samples)
        k = int(round((pct / 100.0) * (len(ordered) - 1)))
        return ordered[k]

    def tick(self):
        """Take one trend sample. Called once per repaint."""
        self.trend.append(self.percentile(90) if self.samples else 0.0)
        del self.trend[:-GRAPH_W]

    def render(self, rate, live):
        """The frame, as a list of lines."""
        times = [t for _, t in self.samples]
        n = len(times)

        hint = "+/- rate" if live else "--interval"
        head = self.paint("%.0fs window  %s repaint  [%s]"
                          % (self.window, dur(rate), hint), DIM)

        if not n:
            out = ["client  %s  %s" % (head, self.paint("no queries", DIM))]
            out += [""] * (GRAPH_H + 10)
            return out

        counts = [0] * len(BUCKETS)
        for t in times:
            for i, (hi, _) in enumerate(BUCKETS):
                if t < hi:
                    counts[i] += 1
                    break
        top = max(counts)
        slow = sum(1 for t in times if t * 1000 >= SLOW_MS)

        out = ["client  %s  %s queries%s"
               % (head, self.paint(str(n), BOLD),
                  "" if not slow
                  else self.paint("   %d over %dms" % (slow, SLOW_MS), RED))]

        for i, (_, label) in enumerate(BUCKETS):
            filled = 0 if not top else int(round(BAR_WIDTH * counts[i] / top))
            out.append("  %7s %s%s%s %s"
                       % (label, self.paint("│", DIM),
                          self.paint("█" * filled, bucket_colour(i)),
                          " " * (BAR_WIDTH - filled),
                          self.paint("%4d" % counts[i] if counts[i] else "   .",
                                     DIM)))

        out.append("  %7s %s %s"
                   % ("", self.paint("│", DIM),
                      self.paint("p50 %s   p90 %s   max %s"
                                 % (dur(self.percentile(50)),
                                    dur(self.percentile(90)),
                                    dur(max(times))), DIM)))
        out.append("")
        out += self.graph()
        out.append("")

        # A fixed number of slow-query lines, blank when there are none, so
        # the frame is always the same height. A frame that changed height
        # would leave the tail of the last one on screen after a repaint.
        for i in range(SLOW_KEEP):
            out.append(self.slow[i] if i < len(self.slow) else "")
        return out

    def graph(self):
        """The trend, as a bar chart over time rather than one line.

        Each column is one repaint's p90 over the window; newest on the right.
        Height is log-scaled, because the range that matters spans four
        decades and a linear axis would draw every cached column as zero --
        which is exactly the half of the picture worth seeing.

        Rows are coloured by the latency they represent, not by the data, so a
        bar reaching into the red rows means slow no matter what else is on
        screen. Cached, the chart is a green line along the bottom.
        """
        pts = self.trend[-GRAPH_W:]
        lo = math.log10(GRAPH_LO)
        span = math.log10(GRAPH_HI) - lo

        eighths = []
        for v in pts:
            if v <= 0:
                eighths.append(0)
                continue
            frac = (math.log10(min(max(v, GRAPH_LO), GRAPH_HI)) - lo) / span
            eighths.append(int(round(frac * GRAPH_H * 8)))

        out = []
        for row in range(GRAPH_H - 1, -1, -1):
            cells = []
            for e in eighths:
                have = e - row * 8
                cells.append(SPARK[8] if have >= 8
                             else (" " if have <= 0 else SPARK[have]))
            # The latency at the top of this row is what the row means.
            at = 10 ** (lo + ((row + 1) / GRAPH_H) * span)
            out.append("  %6s %s%s%s"
                       % (dur(at), self.paint("┤", DIM),
                          self.paint("".join(cells), latency_colour(at)),
                          " " * (GRAPH_W - len(cells))))

        out.append("  %6s %s%s" % ("", self.paint("└" + "─" * len(pts), DIM),
                                   " " * (GRAPH_W - len(pts))))
        out.append("  %6s %s" % ("", self.paint(
            "p90 per repaint, newest right", DIM)))
        return out


class Frame:
    """Draws the report, in place if it can.

    Repainting means going back up over the previous frame and overwriting it,
    which needs the lines to still be where they were left. Anything else
    printing in between breaks that, so everything the client has to say goes
    through here -- and if something does print out of band, dirty() makes the
    next frame start fresh lower down rather than eating whatever it was.
    """

    def __init__(self, redraw=True):
        self.redraw = redraw
        self.height = 0

    def dirty(self):
        self.height = 0

    def draw(self, lines):
        buf = []
        if self.redraw and self.height:
            buf.append(UP % self.height)
        for ln in lines:
            buf.append((CLEAR if self.redraw else "") + ln + "\n")
        sys.stdout.write("".join(buf))
        sys.stdout.flush()
        self.height = len(lines)


class Keys:
    """Single keypresses from the terminal, if there is one.

    There usually is not: the client's stdin is whatever docker gave it, and
    `docker logs -f` is a one-way stream with no keyboard behind it. So this
    turns itself off unless stdin is a tty, and the interval stays whatever
    --interval said. Run the container with a tty and attach to it and the
    keys start working, with no change here -- see demo/README.md.
    """

    def __init__(self):
        self.fd = None
        self.saved = None
        try:
            if sys.stdin.isatty():
                self.fd = sys.stdin.fileno()
                self.saved = termios.tcgetattr(self.fd)
                tty.setcbreak(self.fd)
        except (OSError, ValueError, termios.error):
            self.fd = None

    @property
    def live(self):
        return self.fd is not None

    def pending(self):
        """Whatever has been typed since last time. Never blocks."""
        if self.fd is None:
            return ""
        out = []
        while select.select([self.fd], [], [], 0)[0]:
            ch = os.read(self.fd, 1)
            if not ch:
                break
            out.append(ch.decode("utf-8", "replace"))
        return "".join(out)

    def restore(self):
        if self.fd is not None and self.saved is not None:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.saved)


def apply_keys(typed, rate):
    """+ faster, - slower, r back to the default. Doubling per press, because
    the useful range is 0.1s to 10s and stepping linearly would take a hundred
    presses to cross it."""
    for ch in typed:
        if ch in "+=":
            rate = max(RATE_MIN, rate / 2.0)
        elif ch in "-_":
            rate = min(RATE_MAX, rate * 2.0)
        elif ch in "rR":
            rate = REDRAW_SECS
    return rate


def run(args) -> int:
    conn = None
    win = Window(colour=args.colour, window=args.window)
    frame = Frame(redraw=args.redraw)
    keys = Keys()
    rate = args.interval
    issued = 0
    next_draw = time.monotonic()

    try:
        while True:
            if args.count and issued >= args.count:
                win.prune(time.monotonic())
                win.tick()
                frame.draw(win.render(rate, keys.live))
                return 0

            try:
                if conn is None:
                    conn = connect(args)
                    frame.dirty()
                    say("client: connected to %s:%d/%s -- %d statements, %d of "
                        "them slow" % (args.host, args.port, args.db,
                                       len(QUERIES), len(SLOW)))

                sql = random.choice(QUERIES)
                start = time.monotonic()
                cur = conn.cursor()
                cur.execute(sql)
                rows = cur.fetchall()
                elapsed = time.monotonic() - start
                ncols = len(cur.description) if cur.description else 0
                cur.close()

                issued += 1
                note = None
                if elapsed * 1000 >= SLOW_MS:
                    note = ("  %s %s  %2d row(s) x %d col(s)  %s"
                            % (win.paint("SLOW", RED),
                               win.paint("%7s" % dur(elapsed), BOLD),
                               len(rows), ncols, sql[:52]))
                win.add(time.monotonic(), elapsed, note)

            except MySQLError as exc:
                frame.dirty()
                print("client: query failed: %s" % (exc,), file=sys.stderr,
                      flush=True)
                # Only a connection-level failure is worth reconnecting for. A
                # statement the server rejected -- a missing table, a syntax
                # error -- leaves a perfectly good connection, and throwing it
                # away would turn one bad query into a reconnect loop that
                # hides what actually went wrong.
                if isinstance(exc, (OperationalError, InterfaceError)):
                    try:
                        if conn:
                            conn.close()
                    except MySQLError:
                        pass
                    conn = None
                    time.sleep(1)
            except KeyboardInterrupt:
                return 0

            rate = apply_keys(keys.pending(), rate)

            now = time.monotonic()
            if now >= next_draw:
                win.prune(now)
                win.tick()
                frame.draw(win.render(rate, keys.live))
                # Advanced rather than reset to now, so the cadence holds
                # instead of drifting by however long the last query took. If
                # the rate just changed, or a slow query overran several
                # intervals, restart from here rather than firing repeatedly
                # to catch up.
                next_draw += rate
                if next_draw <= now:
                    next_draw = now + rate

            time.sleep(random.uniform(args.min_interval, args.max_interval))
    finally:
        keys.restore()


def main() -> int:
    ap = make_arg_parser(description=__doc__)
    ap.add_argument("--host", default=os.environ.get("MYSQL_HOST", "mysql"))
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("MYSQL_PORT", "3306")))
    ap.add_argument("--user", default=os.environ.get("MYSQL_USER", "app"))
    ap.add_argument("--password",
                    default=os.environ.get("MYSQL_PASSWORD", "apppw"))
    ap.add_argument("--db", default=os.environ.get("MYSQL_DB", "shop"))
    ap.add_argument("--min-interval", type=float, default=0.05,
                    help="seconds, min gap between queries")
    ap.add_argument("--max-interval", type=float, default=0.25,
                    help="seconds, max gap between queries")
    ap.add_argument("--interval", type=float,
                    default=float(os.environ.get("BNCL_REDRAW", REDRAW_SECS)),
                    metavar="SECS",
                    help="how often the frame is repainted (default: "
                         "%(default)s, or $BNCL_REDRAW). Adjustable at "
                         "runtime with +/- when stdin is a terminal")
    ap.add_argument("--window", type=float, default=WINDOW_SECS,
                    metavar="SECS",
                    help="how wide the histogram's sliding window is "
                         "(default: %(default)s)")
    ap.add_argument("--plain", dest="redraw", action="store_false",
                    help="append each frame instead of repainting in place. "
                         "For piping to a file, or `docker logs` without -f, "
                         "where cursor movement is noise rather than a display")
    ap.add_argument("--no-color", "--no-colour", dest="colour",
                    action="store_false",
                    help="plain output. Colour is on by default: without a "
                         "tty, autodetection would turn it off exactly where "
                         "it is wanted")
    ap.add_argument("-n", "--count", type=int, default=0, metavar="N",
                    help="stop after N queries (default: run until killed)")
    args = ap.parse_args()
    if os.environ.get("NO_COLOR"):
        args.colour = False
    args.interval = min(RATE_MAX, max(RATE_MIN, args.interval))
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
