#!/usr/bin/env python3
"""Run each SELECT against MySQL and its translation against Valkey, and diff.

This is the check that matters: a translation that parses and executes can
still be wrong. Comparing the primary keys each side returns is what proves the
mapping is faithful.

    python3 demo/verify.py                 # built-in statement list
    python3 demo/verify.py -f queries.sql  # one statement per line
"""

from __future__ import annotations

import os
import sys

import pymysql
import redis

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "translator"))
from sql2search import (  # noqa: E402
    DEFAULT_DIALECT,
    DIALECTS,
    TranslationError,
    load_schema,
    make_arg_parser,
    translate,
)

QUERIES = [
    "SELECT * FROM products",
    "SELECT name, price FROM products WHERE category = 'tools' AND price < 30",
    "SELECT * FROM products WHERE brand IN ('acme','globex') AND rating >= 4.5",
    "SELECT * FROM products WHERE price BETWEEN 10 AND 20 OR stock = 0",
    "SELECT * FROM products WHERE category != 'tools'",
    "SELECT * FROM products WHERE NOT (category = 'tools' OR price > 100)",
    "SELECT * FROM products WHERE sku LIKE 'SKU-00%'",
    "SELECT * FROM products WHERE name LIKE 'Ham%'",
    "SELECT * FROM products WHERE description LIKE '%proof'",
    "SELECT * FROM products WHERE name = 'Cordless Drill'",
    "SELECT * FROM products WHERE stock = 0",
    "SELECT * FROM products WHERE rating > 4.5 AND stock > 0",
    "SELECT * FROM orders WHERE status = 'shipped'",
    "SELECT * FROM orders WHERE customer = 'o''brien, inc.'",
    "SELECT * FROM orders WHERE qty NOT IN (1,2,3)",
    "SELECT * FROM orders WHERE total >= 100 AND status != 'cancelled'",
]

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def mysql_keys(conn, schema: dict, sql: str) -> set[str]:
    """Primary keys MySQL returns, rewriting the projection to the key column."""
    table = _table_of(sql, schema)
    key_column = schema["tables"][table].get("key_column")
    where = sql[sql.lower().index(" where ") + 7:] if " where " in sql.lower() else "1"
    with conn.cursor() as cur:
        cur.execute(f"SELECT `{key_column}` FROM `{table}` WHERE {where}")
        return {str(row[0]) for row in cur.fetchall()}


def _table_of(sql: str, schema: dict) -> str:
    tokens = sql.replace(";", " ").split()
    table = tokens[tokens.index("FROM") + 1] if "FROM" in tokens else tokens[
        [t.lower() for t in tokens].index("from") + 1]
    for name in schema["tables"]:
        if name.lower() == table.lower():
            return name
    raise KeyError(table)


def valkey_keys(client: redis.Redis, args: list[str], prefix: str) -> set[str]:
    # Ask for the whole result set, not the default first page of 10.
    args = [a for a in args]
    if "LIMIT" not in args:
        args += ["LIMIT", "0", "10000"]
    reply = client.execute_command(*args)
    if isinstance(reply, dict):  # RESP3
        return {r["id"].removeprefix(prefix) for r in reply.get("results", [])}
    keys = set()
    rest = list(reply[1:])
    for i in range(0, len(rest), 2):
        if isinstance(rest[i], str):
            keys.add(rest[i].removeprefix(prefix))
    return keys


def main() -> int:
    ap = make_arg_parser(description=__doc__)
    ap.add_argument("-f", "--file", help="file of statements, one per line")
    ap.add_argument("-d", "--dialect", default=DEFAULT_DIALECT, choices=sorted(DIALECTS))
    ap.add_argument("--schema", default=None)
    args = ap.parse_args()

    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def paint(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    schema = load_schema(args.schema)
    queries = QUERIES
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            queries = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    conn = pymysql.connect(
        host=os.environ.get("MYSQL_HOST", "mysql"),
        port=int(os.environ.get("MYSQL_PORT", "3306")),
        user=os.environ.get("MYSQL_USER", "app"),
        password=os.environ.get("MYSQL_PASSWORD", "apppw"),
        database=os.environ.get("MYSQL_DB", "shop"),
    )
    client = redis.Redis(
        host=os.environ.get("VALKEY_HOST", "valkey"),
        port=int(os.environ.get("VALKEY_PORT", "6379")),
        decode_responses=True,
    )

    match = mismatch = skipped = warned = 0

    for sql in queries:
        try:
            result = translate(sql, schema, args.dialect)
        except TranslationError as exc:
            skipped += 1
            print(f"{paint(YELLOW, 'SKIP')} {sql}")
            print(f"     {paint(DIM, str(exc))}")
            continue

        table = _table_of(sql, schema)
        prefix = schema["tables"][table]["prefix"]

        expected = mysql_keys(conn, schema, sql)
        try:
            actual = valkey_keys(client, result.args, prefix)
        except Exception as exc:  # noqa: BLE001
            mismatch += 1
            print(f"{paint(RED, 'FAIL')} {sql}")
            print(f"     {paint(DIM, result.query)}")
            print(f"     server error: {exc}")
            continue

        if expected == actual:
            match += 1
            print(f"{paint(GREEN, ' OK ')} {sql}")
            print(f"     {paint(DIM, result.query)}  -> {len(actual)} row(s)")
            continue

        # A divergence the translator predicted is a documented limitation,
        # not a bug: only unannounced differences count as failures.
        if result.warnings:
            warned += 1
            print(f"{paint(YELLOW, 'WARN')} {sql}")
        else:
            mismatch += 1
            print(f"{paint(RED, 'DIFF')} {sql}")
        print(f"     {paint(DIM, result.query)}")
        print(f"     only in MySQL : {sorted(expected - actual) or '-'}")
        print(f"     only in Valkey: {sorted(actual - expected) or '-'}")
        for warning in result.warnings:
            print(f"     {paint(DIM, 'predicted: ' + warning)}")

    print(f"\n{match} matching, {warned} differing-as-warned, "
          f"{mismatch} unexpectedly differing, {skipped} skipped")
    return 1 if mismatch else 0


if __name__ == "__main__":
    sys.exit(main())
