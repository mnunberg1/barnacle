#!/usr/bin/env python3
"""Translate simple MySQL SELECT statements into Valkey Search FT.SEARCH calls.

Scope, stated up front: this handles single-table ``SELECT ... FROM t WHERE ...``
with the predicate forms that map cleanly onto the FT.SEARCH query language.
Joins, subqueries, aggregation and expressions are rejected with a clear reason
rather than mistranslated -- a wrong query is worse than a refused one.

The mapping is type-driven, so a schema (see schema.json) is required:

    TAG      col = 'v'        ->  @col:{v}
    TEXT     col = 'v'        ->  @col:("v")
    NUMERIC  col = 5          ->  @col:[5 5]
             col > 5          ->  @col:[(5 +inf]
             col BETWEEN a b  ->  @col:[a b]
    AND/OR/NOT               ->  space / | / -

Usable as a library (``translate``) or a CLI:

    ./sql2search.py "SELECT name FROM products WHERE price < 30"
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

DEFAULT_SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.json")


class TranslationError(Exception):
    """Raised when a statement cannot be faithfully expressed as FT.SEARCH."""


# --------------------------------------------------------------------------
# Tokenizer
# --------------------------------------------------------------------------

KEYWORDS = {
    "select", "from", "where", "and", "or", "not", "in", "is", "null",
    "like", "between", "order", "by", "asc", "desc", "limit", "offset",
    "as", "distinct", "count", "join", "inner", "left", "right", "outer",
    "group", "having", "union", "on", "true", "false",
}

_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<comment>--[^\n]*|\#[^\n]*|/\*.*?\*/)
    | (?P<bq>`(?:[^`]|``)*`)
    | (?P<sq>'(?:[^'\\]|\\.|'')*')
    | (?P<dq>"(?:[^"\\]|\\.|"")*")
    | (?P<num>\d+\.\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?|\d+(?:[eE][+-]?\d+)?)
    | (?P<param>\?|%s)
    | (?P<op><=|>=|<>|!=|=|<|>)
    | (?P<punct>[(),.*;+-])
    | (?P<ident>[A-Za-z_][A-Za-z0-9_$]*)
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass
class Token:
    kind: str  # ident | keyword | string | number | op | punct | param
    value: str
    pos: int

    def is_kw(self, *names: str) -> bool:
        return self.kind == "keyword" and self.value in names


def _unquote_string(raw: str) -> str:
    quote = raw[0]
    body = raw[1:-1]
    body = body.replace(quote * 2, quote)
    # MySQL backslash escapes (NO_BACKSLASH_ESCAPES off, the default).
    return re.sub(
        r"\\(.)",
        lambda m: {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\"}.get(
            m.group(1), m.group(1)
        ),
        body,
    )


def tokenize(sql: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(sql):
        m = _TOKEN_RE.match(sql, pos)
        if not m:
            raise TranslationError(f"unexpected character {sql[pos]!r} at offset {pos}")
        pos = m.end()
        kind = m.lastgroup
        text = m.group()
        if kind in ("ws", "comment"):
            continue
        if kind == "ident":
            low = text.lower()
            tokens.append(Token("keyword" if low in KEYWORDS else "ident", low if low in KEYWORDS else text, m.start()))
        elif kind == "bq":
            tokens.append(Token("ident", text[1:-1].replace("``", "`"), m.start()))
        elif kind in ("sq", "dq"):
            # MySQL's default sql_mode treats "..." as a string, not an identifier.
            tokens.append(Token("string", _unquote_string(text), m.start()))
        elif kind == "num":
            tokens.append(Token("number", text, m.start()))
        elif kind == "param":
            tokens.append(Token("param", text, m.start()))
        else:
            tokens.append(Token(kind, text, m.start()))
    return tokens


# --------------------------------------------------------------------------
# AST
# --------------------------------------------------------------------------


@dataclass
class Literal:
    value: Any
    is_string: bool


@dataclass
class Comparison:
    column: str
    op: str
    value: Literal


@dataclass
class Between:
    column: str
    low: Literal
    high: Literal
    negated: bool = False


@dataclass
class InList:
    column: str
    values: list[Literal]
    negated: bool = False


@dataclass
class Like:
    column: str
    pattern: str
    negated: bool = False


@dataclass
class IsNull:
    column: str
    negated: bool = False


@dataclass
class BoolOp:
    op: str  # "and" | "or"
    operands: list[Any]


@dataclass
class NotOp:
    operand: Any


@dataclass
class Select:
    columns: list[str]  # empty means "*"
    count_star: bool
    table: str
    where: Any | None
    order_by: list[tuple[str, str]]
    limit: int | None
    offset: int


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------


class Parser:
    def __init__(self, tokens: Sequence[Token]) -> None:
        self.tokens = list(tokens)
        self.i = 0

    # -- token helpers ----------------------------------------------------
    def peek(self, ahead: int = 0) -> Token | None:
        idx = self.i + ahead
        return self.tokens[idx] if idx < len(self.tokens) else None

    def next(self) -> Token:
        tok = self.peek()
        if tok is None:
            raise TranslationError("unexpected end of statement")
        self.i += 1
        return tok

    def accept_kw(self, *names: str) -> bool:
        tok = self.peek()
        if tok and tok.is_kw(*names):
            self.i += 1
            return True
        return False

    def expect_kw(self, *names: str) -> Token:
        tok = self.peek()
        if not tok or not tok.is_kw(*names):
            got = tok.value if tok else "end of statement"
            raise TranslationError(f"expected {' or '.join(names).upper()}, got {got!r}")
        return self.next()

    def accept_punct(self, ch: str) -> bool:
        tok = self.peek()
        if tok and tok.kind == "punct" and tok.value == ch:
            self.i += 1
            return True
        return False

    def expect_punct(self, ch: str) -> None:
        if not self.accept_punct(ch):
            tok = self.peek()
            got = tok.value if tok else "end of statement"
            raise TranslationError(f"expected {ch!r}, got {got!r}")

    # -- grammar ----------------------------------------------------------
    def parse_select(self) -> Select:
        self.expect_kw("select")
        if self.accept_kw("distinct"):
            raise TranslationError("SELECT DISTINCT has no FT.SEARCH equivalent")

        columns, count_star = self._parse_select_list()

        self.expect_kw("from")
        table = self._parse_name()
        if self.accept_punct("."):  # db.table
            table = self._parse_name()

        tok = self.peek()
        if tok and tok.is_kw("join", "inner", "left", "right", "outer", "union"):
            raise TranslationError("joins and set operations are not supported")
        if tok and tok.kind == "ident":
            raise TranslationError("table aliases are not supported")

        where = None
        if self.accept_kw("where"):
            where = self.parse_expr()

        if self.accept_kw("group"):
            raise TranslationError("GROUP BY is not supported (see FT.AGGREGATE)")
        if self.accept_kw("having"):
            raise TranslationError("HAVING is not supported (see FT.AGGREGATE)")

        order_by: list[tuple[str, str]] = []
        if self.accept_kw("order"):
            self.expect_kw("by")
            while True:
                col = self._parse_name()
                direction = "ASC"
                if self.accept_kw("desc"):
                    direction = "DESC"
                else:
                    self.accept_kw("asc")
                order_by.append((col, direction))
                if not self.accept_punct(","):
                    break

        limit: int | None = None
        offset = 0
        if self.accept_kw("limit"):
            first = self._parse_integer()
            if self.accept_punct(","):  # LIMIT offset, count
                offset, limit = first, self._parse_integer()
            else:
                limit = first
                if self.accept_kw("offset"):
                    offset = self._parse_integer()

        self.accept_punct(";")
        if self.peek() is not None:
            raise TranslationError(f"trailing input at {self.peek().value!r}")

        return Select(columns, count_star, table, where, order_by, limit, offset)

    def _parse_select_list(self) -> tuple[list[str], bool]:
        if self.accept_punct("*"):
            return [], False

        tok = self.peek()
        if tok and tok.is_kw("count"):
            self.next()
            self.expect_punct("(")
            if not self.accept_punct("*"):
                self._parse_name()
            self.expect_punct(")")
            if self.peek() and self.peek().is_kw("as"):
                self.next()
                self._parse_name()
            return [], True

        columns: list[str] = []
        while True:
            columns.append(self._parse_name())
            if self.accept_kw("as"):
                self._parse_name()  # alias, dropped: FT.SEARCH cannot rename
            if not self.accept_punct(","):
                break
        return columns, False

    def parse_expr(self) -> Any:
        return self._parse_or()

    def _parse_or(self) -> Any:
        operands = [self._parse_and()]
        while self.accept_kw("or"):
            operands.append(self._parse_and())
        return operands[0] if len(operands) == 1 else BoolOp("or", operands)

    def _parse_and(self) -> Any:
        operands = [self._parse_not()]
        while self.accept_kw("and"):
            operands.append(self._parse_not())
        return operands[0] if len(operands) == 1 else BoolOp("and", operands)

    def _parse_not(self) -> Any:
        if self.accept_kw("not"):
            return NotOp(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        if self.accept_punct("("):
            inner = self.parse_expr()
            self.expect_punct(")")
            return inner
        return self._parse_predicate()

    def _parse_predicate(self) -> Any:
        column = self._parse_name()
        if self.accept_punct("."):  # table.column
            column = self._parse_name()

        negated = self.accept_kw("not")

        tok = self.peek()
        if tok is None:
            raise TranslationError(f"incomplete predicate on column {column!r}")

        if tok.is_kw("between"):
            self.next()
            low = self._parse_literal()
            self.expect_kw("and")
            high = self._parse_literal()
            return Between(column, low, high, negated)

        if tok.is_kw("in"):
            self.next()
            self.expect_punct("(")
            values = [self._parse_literal()]
            while self.accept_punct(","):
                values.append(self._parse_literal())
            self.expect_punct(")")
            return InList(column, values, negated)

        if tok.is_kw("like"):
            self.next()
            pattern = self._parse_literal()
            if not pattern.is_string:
                raise TranslationError("LIKE pattern must be a string literal")
            return Like(column, str(pattern.value), negated)

        if tok.is_kw("is"):
            self.next()
            is_negated = self.accept_kw("not")
            self.expect_kw("null")
            return IsNull(column, is_negated)

        if negated:
            raise TranslationError(f"NOT is not valid before {tok.value!r}")

        if tok.kind == "op":
            op = self.next().value
            return Comparison(column, op, self._parse_literal())

        raise TranslationError(f"unsupported predicate near {tok.value!r}")

    def _parse_name(self) -> str:
        tok = self.next()
        if tok.kind != "ident":
            raise TranslationError(f"expected a column or table name, got {tok.value!r}")
        return tok.value

    def _parse_integer(self) -> int:
        tok = self.next()
        if tok.kind == "param":
            raise TranslationError("placeholder in LIMIT: run the tracer against the "
                                   "executed statement, not the prepared one")
        if tok.kind != "number" or "." in tok.value:
            raise TranslationError(f"expected an integer, got {tok.value!r}")
        return int(tok.value)

    def _parse_literal(self) -> Literal:
        negate = False
        tok = self.next()
        if tok.kind == "punct" and tok.value in "+-":
            negate = tok.value == "-"
            tok = self.next()
        if tok.kind == "string":
            return Literal(tok.value, True)
        if tok.kind == "number":
            num = float(tok.value) if ("." in tok.value or "e" in tok.value.lower()) else int(tok.value)
            return Literal(-num if negate else num, False)
        if tok.is_kw("null"):
            return Literal(None, False)
        if tok.is_kw("true", "false"):
            return Literal(1 if tok.value == "true" else 0, False)
        if tok.kind == "param":
            raise TranslationError(
                "statement still contains a placeholder (%s/?); trace the executed "
                "COM_QUERY rather than the COM_STMT_PREPARE"
            )
        raise TranslationError(f"expected a literal value, got {tok.value!r}")


# --------------------------------------------------------------------------
# Rendering to the FT.SEARCH query language
# --------------------------------------------------------------------------

# --- dialects -------------------------------------------------------------
#
# valkey-search and RediSearch accept overlapping but not identical query
# languages. These flags are not guesses: they were measured against
# valkey/valkey-bundle (see README, "Dialect differences").


@dataclass(frozen=True)
class Dialect:
    name: str
    #: query text that matches every document, or None if the server has none
    match_all: str | None
    #: whether `@field:(a | b)` is accepted as a grouping inside a field
    field_parens: bool
    #: whether ismissing(@field) exists
    ismissing: bool


DIALECTS = {
    # Measured against valkey-search: `*` is rejected outright, and a
    # parenthesised group directly after `@field:` is a syntax error.
    "valkey": Dialect("valkey", match_all=None, field_parens=False, ismissing=False),
    "redis": Dialect("redis", match_all="*", field_parens=True, ismissing=True),
}
DEFAULT_DIALECT = "valkey"


# A TAG field is a *list*, split on its separator. Mirroring a scalar SQL
# column means the value must never be split, so the default separator here is
# a control character rather than FT.CREATE's own default of ','  -- otherwise
# a value like "o'brien, inc." silently indexes as two tags. Override per
# column with "separator" in schema.json for genuinely delimited columns.
DEFAULT_TAG_SEPARATOR = "\x01"

# RediSearch/valkey-search treat these as syntax inside a query, so any that
# appear in a literal value have to be backslash-escaped.
_TAG_SPECIAL = set(",.<>{}[]\"':;!@#$%^&*()-+=~/\\| \t\n")


def escape_tag(value: str) -> str:
    return "".join("\\" + c if c in _TAG_SPECIAL else c for c in value)


def escape_text(value: str) -> str:
    """Escape a value going inside a "quoted phrase"."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def escape_text_token(value: str) -> str:
    """Escape a bare (unquoted) term, e.g. the stem of a prefix wildcard."""
    return "".join("\\" + c if c in _TAG_SPECIAL else c for c in value)


def format_number(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    # A quoted number in SQL ('30') still compares numerically in MySQL.
    try:
        return str(int(str(value)))
    except ValueError:
        return repr(float(str(value)))


@dataclass
class Translation:
    index: str
    query: str
    args: list[str]
    warnings: list[str] = field(default_factory=list)

    @property
    def command(self) -> str:
        return " ".join(_shell_quote(a) for a in self.args)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "query": self.query,
            "args": self.args,
            "command": self.command,
            "warnings": self.warnings,
        }


def _shell_quote(arg: str) -> str:
    if arg and not re.search(r"[\s\"'|(){}\[\]$`\\*]", arg):
        return arg
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Renderer:
    def __init__(self, table: str, table_schema: dict[str, Any],
                 dialect: Dialect | None = None) -> None:
        self.table = table
        self.schema = table_schema
        self.columns: dict[str, dict[str, Any]] = table_schema.get("columns", {})
        self.dialect = dialect or DIALECTS[DEFAULT_DIALECT]
        self.warnings: list[str] = []

    def match_all(self) -> str:
        """Query matching every document in the index."""
        if self.dialect.match_all:
            return self.dialect.match_all

        # valkey-search has no match-all token, but an unbounded range over any
        # NUMERIC field is equivalent for rows where that field is present.
        for name, spec in self.columns.items():
            if str(spec.get("type", "TAG")).upper() == "NUMERIC":
                self.warnings.append(
                    f"the {self.dialect.name} dialect has no match-all token; using "
                    f"the unbounded range @{name}:[-inf +inf], which skips documents "
                    f"where {name} is absent"
                )
                return f"@{name}:[-inf +inf]"

        raise TranslationError(
            f"a WHERE clause is required: the {self.dialect.name} dialect has no "
            f"match-all token and {self.table!r} has no NUMERIC column to range over"
        )

    def column_type(self, column: str) -> str:
        # MySQL identifiers are case-insensitive for column names in practice.
        for name, spec in self.columns.items():
            if name.lower() == column.lower():
                return str(spec.get("type", "TAG")).upper()
        raise TranslationError(
            f"column {column!r} is not indexed on {self.table!r} "
            f"(known: {', '.join(sorted(self.columns)) or 'none'})"
        )

    def canonical(self, column: str) -> str:
        for name in self.columns:
            if name.lower() == column.lower():
                return name
        return column

    def column_spec(self, column: str) -> dict[str, Any]:
        for name, spec in self.columns.items():
            if name.lower() == column.lower():
                return spec
        return {}

    def tag_value(self, column: str, value: str) -> str:
        """Escape a TAG literal, warning if it would have been split on index."""
        separator = self.column_spec(column).get("separator", DEFAULT_TAG_SEPARATOR)
        if separator and separator in value:
            self.warnings.append(
                f"value {value!r} contains the TAG separator {separator!r} for "
                f"{self.canonical(column)!r}, so it was indexed as multiple tags "
                f"and this equality test cannot match the whole value"
            )
        return escape_tag(value)

    # -- node dispatch ----------------------------------------------------
    def render(self, node: Any) -> str:
        if isinstance(node, BoolOp):
            parts = [self.render(child) for child in node.operands]
            joiner = " " if node.op == "and" else " | "
            return "(" + joiner.join(parts) + ")"
        if isinstance(node, NotOp):
            return "-" + self.render(node.operand)
        if isinstance(node, Comparison):
            return self._render_comparison(node)
        if isinstance(node, Between):
            return self._render_between(node)
        if isinstance(node, InList):
            return self._render_in(node)
        if isinstance(node, Like):
            return self._render_like(node)
        if isinstance(node, IsNull):
            return self._render_is_null(node)
        raise TranslationError(f"internal: cannot render {type(node).__name__}")

    def _render_comparison(self, node: Comparison) -> str:
        col = self.canonical(node.column)
        ctype = self.column_type(node.column)
        op = node.op
        val = node.value

        if val.value is None:
            raise TranslationError(
                f"{col} {op} NULL is never true in SQL; use IS NULL / IS NOT NULL"
            )

        if ctype == "NUMERIC":
            num = format_number(val.value)
            if op == "=":
                return f"@{col}:[{num} {num}]"
            if op in ("!=", "<>"):
                return f"-@{col}:[{num} {num}]"
            if op == ">":
                return f"@{col}:[({num} +inf]"
            if op == ">=":
                return f"@{col}:[{num} +inf]"
            if op == "<":
                return f"@{col}:[-inf ({num}]"
            if op == "<=":
                return f"@{col}:[-inf {num}]"

        if ctype == "TAG":
            if op not in ("=", "!=", "<>"):
                raise TranslationError(
                    f"{op} on TAG column {col!r} has no FT.SEARCH equivalent; "
                    "declare it NUMERIC for range queries"
                )
            rendered = f"@{col}:{{{self.tag_value(col, str(val.value))}}}"
            return rendered if op == "=" else "-" + rendered

        if ctype == "TEXT":
            if op not in ("=", "!=", "<>"):
                raise TranslationError(f"{op} on TEXT column {col!r} is not supported")
            self.warnings.append(
                f"{col} is a TEXT field: '=' becomes a phrase match, which is "
                "tokenized and case-insensitive, not a byte-exact comparison"
            )
            rendered = f'@{col}:"{escape_text(str(val.value))}"'
            return rendered if op == "=" else "-" + rendered

        raise TranslationError(f"unknown index type {ctype!r} for column {col!r}")

    def _render_between(self, node: Between) -> str:
        col = self.canonical(node.column)
        if self.column_type(node.column) != "NUMERIC":
            raise TranslationError(f"BETWEEN requires a NUMERIC column, {col!r} is not")
        rendered = f"@{col}:[{format_number(node.low.value)} {format_number(node.high.value)}]"
        return "-" + rendered if node.negated else rendered

    def _render_in(self, node: InList) -> str:
        col = self.canonical(node.column)
        ctype = self.column_type(node.column)

        if ctype == "TAG":
            # No spaces around '|': inside tag braces a space is part of the
            # tag value, not a separator.
            joined = "|".join(self.tag_value(col, str(v.value)) for v in node.values)
            rendered = f"@{col}:{{{joined}}}"
        elif ctype == "NUMERIC":
            parts = [f"@{col}:[{format_number(v.value)} {format_number(v.value)}]"
                     for v in node.values]
            rendered = "(" + " | ".join(parts) + ")"
        else:  # TEXT
            # Repeat the field per term rather than @col:(a | b): valkey-search
            # rejects a parenthesised group directly after the field name.
            joined = " | ".join(f'@{col}:"{escape_text(str(v.value))}"' for v in node.values)
            rendered = f"({joined})"
        return "-" + rendered if node.negated else rendered

    def _render_like(self, node: Like) -> str:
        col = self.canonical(node.column)
        ctype = self.column_type(node.column)
        if ctype == "NUMERIC":
            raise TranslationError(f"LIKE on NUMERIC column {col!r} is not supported")

        pattern = node.pattern
        if "_" in pattern:
            raise TranslationError(
                "LIKE '_' (single-character wildcard) has no FT.SEARCH equivalent"
            )
        body = pattern.strip("%")
        if "%" in body:
            raise TranslationError(
                "LIKE with an interior '%' is not supported; only prefix, suffix "
                "and infix patterns map onto FT.SEARCH wildcards"
            )
        if not body:
            raise TranslationError("LIKE '%' matches everything; drop the predicate")

        leading = pattern.startswith("%")
        trailing = pattern.endswith("%")
        if not leading and not trailing:
            # No wildcard at all: LIKE degenerates to equality.
            return self._render_comparison(
                Comparison(col, "!=" if node.negated else "=", Literal(body, True))
            )

        if ctype == "TEXT" and re.search(r"\s", body):
            # A TEXT field is tokenized, so '%rust proof%' would become the two
            # independent terms '*rust' and 'proof*' -- not a substring match.
            raise TranslationError(
                f"LIKE wildcard over multiple words ({pattern!r}) cannot be "
                f"expressed against TEXT column {col!r}: wildcards apply per token"
            )

        if ctype == "TEXT":
            # Worth stating loudly: this is the one mapping in the whole
            # translator that is not semantically equivalent. SQL LIKE anchors
            # against the entire column value; a TEXT index is tokenized, so
            # the wildcard applies to each token independently. 'Ham%' finds
            # "Hammer" but also "Claw Hammer", which MySQL would not return.
            self.warnings.append(
                f"LIKE on TEXT column {col!r} matches per token, not against the "
                f"whole value: MySQL anchors {pattern!r} to the start/end of the "
                f"string, the index matches any token. Use a TAG column for "
                f"whole-value prefix matching."
            )

        # Wildcards are query syntax, so they go outside the escaped literal.
        stem = escape_tag(body) if ctype == "TAG" else escape_text_token(body)
        term = f"{'*' if leading else ''}{stem}{'*' if trailing else ''}"
        if leading:
            kind = "infix" if trailing else "suffix"
            self.warnings.append(
                f"{kind} match on {col!r} needs the field created WITHSUFFIXTRIE; "
                f"without it the server rejects the query"
            )

        # A wildcard term is never quoted -- inside quotes the '*' is literal.
        rendered = f"@{col}:{{{term}}}" if ctype == "TAG" else f"@{col}:{term}"
        return "-" + rendered if node.negated else rendered

    def _render_is_null(self, node: IsNull) -> str:
        col = self.canonical(node.column)
        self.column_type(node.column)
        if not self.dialect.ismissing:
            raise TranslationError(
                f"IS NULL on {col!r} needs ismissing(), which the "
                f"{self.dialect.name} dialect does not implement"
            )
        self.warnings.append(
            f"IS NULL on {col!r} maps to ismissing(@{col}), which requires the "
            "field to be declared INDEXMISSING"
        )
        rendered = f"ismissing(@{col})"
        return "-" + rendered if node.negated else rendered


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def load_schema(path: str | None = None) -> dict[str, Any]:
    with open(path or DEFAULT_SCHEMA, "r", encoding="utf-8") as fh:
        return json.load(fh)


def translate(sql: str, schema: dict[str, Any] | None = None,
              dialect: str | Dialect = DEFAULT_DIALECT) -> Translation:
    """Translate one MySQL SELECT into an FT.SEARCH invocation."""
    schema = schema if schema is not None else load_schema()
    tables = schema.get("tables", {})

    if isinstance(dialect, str):
        try:
            dialect = DIALECTS[dialect]
        except KeyError:
            raise TranslationError(
                f"unknown dialect {dialect!r} (known: {', '.join(sorted(DIALECTS))})"
            ) from None

    stmt = Parser(tokenize(sql)).parse_select()

    table_schema = None
    for name, spec in tables.items():
        if name.lower() == stmt.table.lower():
            table_schema = spec
            break
    if table_schema is None:
        raise TranslationError(
            f"no index mapping for table {stmt.table!r} "
            f"(known: {', '.join(sorted(tables)) or 'none'})"
        )

    index = table_schema.get("index") or f"idx:{stmt.table}"
    renderer = Renderer(stmt.table, table_schema, dialect)

    if stmt.where is None:
        query = renderer.match_all()
    else:
        query = renderer.render(stmt.where)
        # Strip one redundant layer of parens for readability.
        if query.startswith("(") and query.endswith(")") and _balanced(query[1:-1]):
            query = query[1:-1]

    args: list[str] = ["FT.SEARCH", index, query]

    if stmt.count_star:
        # FT.SEARCH always returns the total as the first reply element, so a
        # zero-sized page is exactly COUNT(*).
        args += ["LIMIT", "0", "0"]
    else:
        if stmt.columns:
            missing = [c for c in stmt.columns if not _known(renderer, c)]
            if missing:
                renderer.warnings.append(
                    "returning non-indexed column(s) " + ", ".join(missing) +
                    ": RETURN reads them from the hash, so they must exist on the key"
                )
            args += ["RETURN", str(len(stmt.columns))] + [renderer.canonical(c) for c in stmt.columns]

        for sort_col, _ in stmt.order_by:
            renderer.column_type(sort_col)  # validates the column is indexed
        if len(stmt.order_by) > 1:
            renderer.warnings.append(
                "FT.SEARCH SORTBY takes a single field; only the first ORDER BY "
                "term is applied"
            )
        if stmt.order_by:
            col, direction = stmt.order_by[0]
            args += ["SORTBY", renderer.canonical(col), direction]

        if stmt.limit is not None:
            args += ["LIMIT", str(stmt.offset), str(stmt.limit)]
        elif stmt.offset:
            args += ["LIMIT", str(stmt.offset), "10"]

    return Translation(index=index, query=query, args=args, warnings=renderer.warnings)


def _known(renderer: Renderer, column: str) -> bool:
    try:
        renderer.column_type(column)
        return True
    except TranslationError:
        return False


def _balanced(text: str) -> bool:
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def make_arg_parser(**kwargs: Any) -> argparse.ArgumentParser:
    """ArgumentParser with colorized help disabled, on versions that have it.

    Python 3.14 turns help colorization on by default; 3.12 (what the container
    ships) does not accept the keyword at all.
    """
    if sys.version_info >= (3, 14):
        kwargs["color"] = False
    return argparse.ArgumentParser(**kwargs)


def main(argv: Iterable[str] | None = None) -> int:
    ap = make_arg_parser(
        description="Translate a MySQL SELECT into a Valkey Search FT.SEARCH command."
    )
    ap.add_argument("sql", nargs="*", help="SQL statement (reads stdin if omitted)")
    ap.add_argument("-s", "--schema", default=None, help="path to schema.json")
    ap.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("-d", "--dialect", default=DEFAULT_DIALECT, choices=sorted(DIALECTS),
                    help=f"target query dialect (default: {DEFAULT_DIALECT})")
    args = ap.parse_args(list(argv) if argv is not None else None)

    statements = [" ".join(args.sql)] if args.sql else [
        line for line in (l.strip() for l in sys.stdin) if line
    ]
    schema = load_schema(args.schema)

    rc = 0
    for sql in statements:
        try:
            result = translate(sql, schema, args.dialect)
        except TranslationError as exc:
            rc = 1
            if args.json:
                print(json.dumps({"sql": sql, "error": str(exc)}))
            else:
                print(f"SQL   : {sql}\nERROR : {exc}\n", file=sys.stderr)
            continue

        if args.json:
            payload = result.to_dict()
            payload["sql"] = sql
            print(json.dumps(payload))
        else:
            print(f"SQL   : {sql}")
            print(f"VALKEY: {result.command}")
            for warning in result.warnings:
                print(f"  note: {warning}")
            print()
    return rc


if __name__ == "__main__":
    sys.exit(main())
