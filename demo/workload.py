#!/usr/bin/env python3
"""workload.py - a stand-in application, unaware it is being observed.

Issues a steady stream of queries against the demo `shop` database.

The choice of driver no longer affects visibility: the cache hooks the TLS
library every client shares rather than any particular driver's internals, so
pure-Python drivers and C extensions are observed alike.

Most queries are cheap lookups against the tiny demo dataset. A few are
deliberately expensive via SLEEP(), standing in for the kind of slow query a
real app would have (an unindexed scan, a slow join) without needing a large
dataset to reproduce reliably. All templates return the same column shape
whether they are the fast or slow variant, so results can be fetched
generically -- and a cached answer keeps that shape too, since the daemon
stores the result set and regenerates the packets rather than replaying
whatever bytes it captured. A hit is meant to be indistinguishable from a
miss apart from how long it took, which is what this script measures.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

import MySQLdb
from MySQLdb import Error as MySQLError

# Weighted so slow queries show up often enough to be interesting quickly
# without dominating the feed.
QUERY_TEMPLATES = [
	(3, "SELECT * FROM products WHERE category = 'tools'"),
	(3, "SELECT name, price FROM products WHERE stock = 0"),
	(3, "SELECT * FROM products WHERE brand = 'acme'"),
	(3, "SELECT * FROM orders WHERE status = 'shipped'"),
	(3, "SELECT sku, price FROM products WHERE price < 30"),
	(2, "SELECT * FROM orders WHERE customer = 'wayne industries'"),
	# Slow: a real app might have an unindexed scan or a slow join here.
	# SLEEP() reproduces "this is slow" deterministically on a 10-row table.
	(1, "SELECT * FROM products WHERE category = 'safety' AND SLEEP(1.5) = 0"),
	(1, "SELECT * FROM orders WHERE customer = 'wayne industries' AND SLEEP(2) = 0"),
]


def make_arg_parser(**kwargs) -> argparse.ArgumentParser:
	if sys.version_info >= (3, 14):
		kwargs["color"] = False
	return argparse.ArgumentParser(**kwargs)


# The two slow statements, by index into QUERY_TEMPLATES. `--slow-only` runs
# just these: a mixed feed makes the cache hard to SEE, because the fast
# queries dominate the output and none of them are cacheable anyway.
SLOW = [i for i, (_, q) in enumerate(QUERY_TEMPLATES) if "SLEEP(" in q]


def pick_query(slow_only: bool = False) -> str:
	if slow_only:
		return QUERY_TEMPLATES[random.choice(SLOW)][1]
	weights = [w for w, _ in QUERY_TEMPLATES]
	return random.choices([q for _, q in QUERY_TEMPLATES], weights=weights, k=1)[0]


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


def run(args) -> int:
	conn = None
	issued = 0
	while True:
		if args.count and issued >= args.count:
			return 0
		try:
			if conn is None:
				conn = connect(args)
				print(f"workload: connected to {args.host}:{args.port}/{args.db}", flush=True)

			sql = pick_query(args.slow_only)
			start = time.monotonic()
			cur = conn.cursor()
			cur.execute(sql)
			rows = cur.fetchall()
			elapsed = time.monotonic() - start
			ncols = len(cur.description) if cur.description else 0
			cur.close()

			issued += 1
			shape = f"{len(rows)} row(s) x {ncols} col(s)"
			print(f"workload: {elapsed:6.3f}s  {shape:22s}  {sql}", flush=True)

		except MySQLError as exc:
			print(f"workload: query failed: {exc}", file=sys.stderr, flush=True)
			try:
				if conn:
					conn.close()
			except MySQLError:
				pass
			conn = None
			time.sleep(1)
			continue
		except KeyboardInterrupt:
			return 0

		time.sleep(random.uniform(args.min_interval, args.max_interval))


def main() -> int:
	ap = make_arg_parser(description=__doc__)
	ap.add_argument("--host", default=os.environ.get("MYSQL_HOST", "mysql"))
	ap.add_argument("--port", type=int, default=int(os.environ.get("MYSQL_PORT", "3306")))
	ap.add_argument("--user", default=os.environ.get("MYSQL_USER", "app"))
	ap.add_argument("--password", default=os.environ.get("MYSQL_PASSWORD", "apppw"))
	ap.add_argument("--db", default=os.environ.get("MYSQL_DB", "shop"))
	ap.add_argument("--min-interval", type=float, default=0.3, help="seconds, min gap between queries")
	ap.add_argument("--max-interval", type=float, default=1.0, help="seconds, max gap between queries")
	ap.add_argument("--slow-only", action="store_true",
	                help="issue only the slow (cacheable) statements, so the "
	                     "difference a cache makes is obvious")
	ap.add_argument("-n", "--count", type=int, default=0, metavar="N",
	                help="stop after N queries (default: run until interrupted)")
	args = ap.parse_args()
	return run(args)


if __name__ == "__main__":
	sys.exit(main())
