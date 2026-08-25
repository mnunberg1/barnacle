#!/usr/bin/env python3
"""Mirror the MySQL demo tables into Valkey hashes and build the search indexes.

Both sides are driven by translator/schema.json, so the indexes always match
what the translator assumes when it renders a query.
"""

from __future__ import annotations

import os
import sys

import pymysql
import redis

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "translator"))
from sql2search import DEFAULT_TAG_SEPARATOR, load_schema, make_arg_parser  # noqa: E402


def build_index(client: redis.Redis, table: str, spec: dict) -> None:
    index = spec["index"]
    prefix = spec["prefix"]

    try:
        client.execute_command("FT.DROPINDEX", index)
    except redis.ResponseError:
        pass  # first run

    args = ["FT.CREATE", index, "ON", "HASH", "PREFIX", "1", prefix, "SCHEMA"]
    for column, column_spec in spec["columns"].items():
        ctype = str(column_spec.get("type", "TAG")).upper()
        args += [column, ctype]
        if ctype == "TAG":
            # Must agree with what the translator assumes when it escapes a
            # literal, or values containing ',' index as several tags.
            args += ["SEPARATOR", column_spec.get("separator", DEFAULT_TAG_SEPARATOR)]
        if ctype == "NUMERIC" and column_spec.get("sortable"):
            args.append("SORTABLE")
        if ctype == "TEXT" and column_spec.get("suffix_trie"):
            args.append("WITHSUFFIXTRIE")
        # No WEIGHT clause here on purpose: valkey-search rejects any value
        # other than 1.0, unlike RediSearch.

    client.execute_command(*args)
    print(f"created index {index} over {prefix}*")


def load_rows(mysql_conn, client: redis.Redis, table: str, spec: dict) -> int:
    columns = list(spec["columns"])
    key_column = spec.get("key_column") or columns[0]
    prefix = spec["prefix"]

    with mysql_conn.cursor() as cur:
        cur.execute("SELECT {} FROM `{}`".format(
            ", ".join(f"`{c}`" for c in columns), table))
        rows = cur.fetchall()

    pipe = client.pipeline()
    for row in rows:
        record = dict(zip(columns, row))
        # DECIMAL comes back as Decimal; hashes are byte strings either way.
        mapping = {k: ("" if v is None else str(v)) for k, v in record.items()}
        pipe.hset(f"{prefix}{record[key_column]}", mapping=mapping)
    pipe.execute()
    return len(rows)


def main() -> int:
    ap = make_arg_parser(description=__doc__)
    ap.add_argument("--schema", default=None)
    args = ap.parse_args()

    schema = load_schema(args.schema)

    mysql_conn = pymysql.connect(
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

    for table, spec in schema["tables"].items():
        build_index(client, table, spec)
        count = load_rows(mysql_conn, client, table, spec)
        print(f"mirrored {count} rows from {table} into {spec['prefix']}*")

    return 0


if __name__ == "__main__":
    sys.exit(main())
