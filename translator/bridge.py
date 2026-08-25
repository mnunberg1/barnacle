#!/usr/bin/env python3
"""Read agent JSONL on stdin, translate each statement, optionally run it.

    build/agent | translator/bridge.py --execute

Statements that cannot be translated are reported and skipped -- in a tracing
pipeline you will always see traffic that is out of scope (SET, SHOW, BEGIN,
information_schema chatter), and that is not an error condition.
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sql2search import (  # noqa: E402
    DEFAULT_DIALECT,
    DIALECTS,
    TranslationError,
    load_schema,
    make_arg_parser,
    translate,
)

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"


class Palette:
    """Colors, unless stdout is a pipe or NO_COLOR is set."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.enabled else text


def main() -> int:
    ap = make_arg_parser(description=__doc__)
    ap.add_argument("-s", "--schema", default=None, help="path to schema.json")
    ap.add_argument("-e", "--execute", action="store_true",
                    help="run the translated query against Valkey and show results")
    ap.add_argument("-j", "--json", action="store_true",
                    help="emit one JSON object per statement instead of a report")
    ap.add_argument("--quiet-errors", action="store_true",
                    help="do not report statements that cannot be translated")
    ap.add_argument("-d", "--dialect", default=DEFAULT_DIALECT, choices=sorted(DIALECTS),
                    help=f"target query dialect (default: {DEFAULT_DIALECT})")
    ap.add_argument("--host", default=os.environ.get("VALKEY_HOST", "valkey"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("VALKEY_PORT", "6379")))
    args = ap.parse_args()

    color = Palette(sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
    schema = load_schema(args.schema)

    client = None
    if args.execute:
        import redis  # imported lazily so the pure-translation path needs no deps

        client = redis.Redis(host=args.host, port=args.port, decode_responses=True)
        client.ping()

    translated = skipped = 0

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            print(f"bridge: not JSON: {line[:120]}", file=sys.stderr)
            continue

        sql = event.get("sql", "")
        if not sql:
            continue

        record: dict = {
            "sql": sql,
            "pid": event.get("pid"),
            "comm": event.get("comm"),
            "command": event.get("command"),
        }

        try:
            result = translate(sql, schema, args.dialect)
        except TranslationError as exc:
            skipped += 1
            record["error"] = str(exc)
            if args.json:
                print(json.dumps(record), flush=True)
            elif not args.quiet_errors:
                print(f"{color(DIM, '· skip')} {sql}", flush=True)
                print(f"        {color(RED, str(exc))}", flush=True)
            continue

        translated += 1
        record.update(result.to_dict())

        if client is not None:
            try:
                reply = client.execute_command(*result.args)
                record["result"] = _summarize(reply)
            except Exception as exc:  # noqa: BLE001 - surface whatever the server said
                record["execute_error"] = str(exc)

        if args.json:
            print(json.dumps(record, default=str), flush=True)
            continue

        stamp = time.strftime("%H:%M:%S")
        who = f"{event.get('comm', '?')}[{event.get('pid', '?')}]"
        print(f"{color(DIM, stamp)} {color(BOLD, who)}", flush=True)
        print(f"  {color(DIM, 'MySQL ')} {sql}", flush=True)
        print(f"  {color(GREEN, 'Valkey')} {result.command}", flush=True)
        for warning in result.warnings:
            print(f"  {color(YELLOW, 'note  ')} {warning}", flush=True)
        if "execute_error" in record:
            print(f"  {color(RED, 'error ')} {record['execute_error']}", flush=True)
        elif "result" in record:
            total = record["result"]["total"]
            print(f"  {color(DIM, 'result')} {total} match(es)", flush=True)
            for doc in record["result"]["docs"][:5]:
                print(f"           {doc}", flush=True)
        print(flush=True)

    print(f"bridge: {translated} translated, {skipped} skipped", file=sys.stderr)
    return 0


def _summarize(reply) -> dict:
    """FT.SEARCH replies as [total, key1, [f, v, ...], key2, [...], ...]."""
    if isinstance(reply, dict):  # RESP3 servers reply with a map
        results = reply.get("results", [])
        return {
            "total": reply.get("total_results", len(results)),
            "docs": [
                {"key": r.get("id"), **(r.get("extra_attributes") or {})} for r in results
            ],
        }

    if not isinstance(reply, (list, tuple)) or not reply:
        return {"total": 0, "docs": []}

    total = reply[0]
    docs = []
    rest = list(reply[1:])
    for i in range(0, len(rest), 2):
        key = rest[i]
        fields = rest[i + 1] if i + 1 < len(rest) else []
        if isinstance(fields, (list, tuple)):
            pairs = dict(zip(fields[0::2], fields[1::2]))
        else:
            pairs = {}
        docs.append({"key": key, **pairs})
    return {"total": total, "docs": docs}


if __name__ == "__main__":
    sys.exit(main())
