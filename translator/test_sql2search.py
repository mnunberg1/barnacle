#!/usr/bin/env python3
"""Unit tests for the SQL -> FT.SEARCH translator.

These need neither a kernel nor a server: run them with `make check`.
The end-to-end check that the queries return the same rows MySQL returns
lives in demo/verify.py.
"""

import unittest

from sql2search import (
    DEFAULT_TAG_SEPARATOR,
    TranslationError,
    tokenize,
    translate,
)

SCHEMA = {
    "tables": {
        "products": {
            "index": "idx:products",
            "prefix": "product:",
            "key_column": "sku",
            "columns": {
                "sku": {"type": "TAG"},
                "name": {"type": "TEXT", "suffix_trie": True},
                "category": {"type": "TAG"},
                "tags": {"type": "TAG", "separator": ","},
                "price": {"type": "NUMERIC", "sortable": True},
                "stock": {"type": "NUMERIC"},
            },
        },
        "tagonly": {
            "index": "idx:tagonly",
            "prefix": "t:",
            "key_column": "id",
            "columns": {"id": {"type": "TAG"}},
        },
    }
}


def q(sql, dialect="valkey"):
    return translate(sql, SCHEMA, dialect).query


def args(sql, dialect="valkey"):
    return translate(sql, SCHEMA, dialect).args


class TestTokenizer(unittest.TestCase):
    def test_strips_comments(self):
        kinds = [t.value for t in tokenize("SELECT /* hi */ a -- tail\nFROM t")]
        self.assertEqual(kinds, ["select", "a", "from", "t"])

    def test_doubled_quote_escape(self):
        (tok,) = [t for t in tokenize("'o''brien'")]
        self.assertEqual(tok.value, "o'brien")

    def test_backtick_identifier(self):
        (tok,) = [t for t in tokenize("`order`")]
        self.assertEqual((tok.kind, tok.value), ("ident", "order"))


class TestPredicates(unittest.TestCase):
    def test_tag_equality(self):
        self.assertEqual(q("SELECT * FROM products WHERE category = 'tools'"),
                         "@category:{tools}")

    def test_tag_inequality_is_bare_negation(self):
        self.assertEqual(q("SELECT * FROM products WHERE category != 'tools'"),
                         "-@category:{tools}")

    def test_numeric_ranges(self):
        cases = {
            "price = 10": "@price:[10 10]",
            "price > 10": "@price:[(10 +inf]",
            "price >= 10": "@price:[10 +inf]",
            "price < 10": "@price:[-inf (10]",
            "price <= 10": "@price:[-inf 10]",
            "price <> 10": "-@price:[10 10]",
            "price BETWEEN 5 AND 10": "@price:[5 10]",
        }
        for where, expected in cases.items():
            with self.subTest(where=where):
                self.assertEqual(q(f"SELECT * FROM products WHERE {where}"), expected)

    def test_negative_number(self):
        self.assertEqual(q("SELECT * FROM products WHERE price > -5"),
                         "@price:[(-5 +inf]")

    def test_in_list(self):
        self.assertEqual(q("SELECT * FROM products WHERE category IN ('a','b')"),
                         "@category:{a|b}")
        # The redundant outer paren is stripped when it wraps the whole query.
        self.assertEqual(q("SELECT * FROM products WHERE price IN (1,2)"),
                         "@price:[1 1] | @price:[2 2]")
        self.assertEqual(
            q("SELECT * FROM products WHERE price IN (1,2) AND stock = 3"),
            "(@price:[1 1] | @price:[2 2]) @stock:[3 3]",
        )

    def test_not_in(self):
        self.assertEqual(q("SELECT * FROM products WHERE category NOT IN ('a')"),
                         "-@category:{a}")

    def test_text_equality_is_a_phrase(self):
        self.assertEqual(q("SELECT * FROM products WHERE name = 'Cordless Drill'"),
                         '@name:"Cordless Drill"')

    def test_tag_prefix_like(self):
        self.assertEqual(q("SELECT * FROM products WHERE sku LIKE 'SKU-00%'"),
                         "@sku:{SKU\\-00*}")

    def test_text_prefix_like_is_unquoted(self):
        self.assertEqual(q("SELECT * FROM products WHERE name LIKE 'Ham%'"),
                         "@name:Ham*")

    def test_like_without_wildcard_is_equality(self):
        self.assertEqual(q("SELECT * FROM products WHERE category LIKE 'tools'"),
                         "@category:{tools}")


class TestBooleanStructure(unittest.TestCase):
    def test_and_or_precedence(self):
        # AND binds tighter than OR, so this is (a AND b) OR c.
        self.assertEqual(
            q("SELECT * FROM products WHERE category = 'a' AND price = 1 OR stock = 2"),
            "(@category:{a} @price:[1 1]) | @stock:[2 2]",
        )

    def test_explicit_grouping(self):
        self.assertEqual(
            q("SELECT * FROM products WHERE category = 'a' AND (price = 1 OR stock = 2)"),
            "@category:{a} (@price:[1 1] | @stock:[2 2])",
        )

    def test_not_group(self):
        self.assertEqual(
            q("SELECT * FROM products WHERE NOT (category = 'a' OR price > 1)"),
            "-(@category:{a} | @price:[(1 +inf])",
        )


class TestEscaping(unittest.TestCase):
    def test_tag_specials_escaped(self):
        self.assertEqual(q("SELECT * FROM products WHERE category = 'a,b c'"),
                         "@category:{a\\,b\\ c}")

    def test_separator_in_value_warns(self):
        # 'tags' declares SEPARATOR ',' so a comma really does split it.
        result = translate("SELECT * FROM products WHERE tags = 'a,b'", SCHEMA)
        self.assertTrue(any("separator" in w for w in result.warnings), result.warnings)

    def test_default_separator_does_not_warn_on_comma(self):
        result = translate("SELECT * FROM products WHERE category = 'a,b'", SCHEMA)
        self.assertNotIn(",", DEFAULT_TAG_SEPARATOR)
        self.assertFalse([w for w in result.warnings if "separator" in w])


class TestClauses(unittest.TestCase):
    def test_projection_becomes_return(self):
        self.assertEqual(
            args("SELECT sku, price FROM products WHERE stock = 1")[3:],
            ["RETURN", "2", "sku", "price"],
        )

    def test_count_star_uses_zero_page(self):
        self.assertEqual(
            args("SELECT COUNT(*) FROM products WHERE stock = 1")[3:],
            ["LIMIT", "0", "0"],
        )

    def test_order_by_and_limit(self):
        self.assertEqual(
            args("SELECT * FROM products WHERE stock = 1 ORDER BY price DESC LIMIT 5")[3:],
            ["SORTBY", "price", "DESC", "LIMIT", "0", "5"],
        )

    def test_limit_offset_forms_agree(self):
        tail = ["LIMIT", "10", "5"]
        self.assertEqual(args("SELECT * FROM products WHERE stock = 1 LIMIT 10, 5")[3:], tail)
        self.assertEqual(
            args("SELECT * FROM products WHERE stock = 1 LIMIT 5 OFFSET 10")[3:], tail)


class TestDialects(unittest.TestCase):
    def test_valkey_has_no_match_all_token(self):
        # Falls back to an unbounded numeric range, and says so.
        result = translate("SELECT * FROM products", SCHEMA, "valkey")
        self.assertEqual(result.query, "@price:[-inf +inf]")
        self.assertTrue(any("match-all" in w for w in result.warnings))

    def test_redis_uses_star(self):
        self.assertEqual(q("SELECT * FROM products", "redis"), "*")

    def test_no_numeric_column_to_range_over(self):
        with self.assertRaisesRegex(TranslationError, "WHERE clause is required"):
            translate("SELECT * FROM tagonly", SCHEMA, "valkey")

    def test_is_null_only_on_redis(self):
        self.assertEqual(q("SELECT * FROM products WHERE name IS NULL", "redis"),
                         "ismissing(@name)")
        with self.assertRaisesRegex(TranslationError, "ismissing"):
            translate("SELECT * FROM products WHERE name IS NULL", SCHEMA, "valkey")


class TestRejections(unittest.TestCase):
    def assertRejected(self, sql, pattern):
        with self.assertRaisesRegex(TranslationError, pattern):
            translate(sql, SCHEMA)

    def test_unknown_table(self):
        self.assertRejected("SELECT * FROM nope WHERE a = 1", "no index mapping")

    def test_unknown_column(self):
        self.assertRejected("SELECT * FROM products WHERE nope = 1", "not indexed")

    def test_join_rejected(self):
        self.assertRejected(
            "SELECT * FROM products JOIN orders ON products.sku = orders.sku",
            "joins",
        )

    def test_group_by_rejected(self):
        self.assertRejected("SELECT * FROM products GROUP BY category", "GROUP BY")

    def test_range_on_tag_rejected(self):
        self.assertRejected("SELECT * FROM products WHERE category > 'a'", "no FT.SEARCH")

    def test_like_underscore_rejected(self):
        self.assertRejected("SELECT * FROM products WHERE sku LIKE 'a_b'", "single-char")

    def test_multiword_wildcard_on_text_rejected(self):
        self.assertRejected(
            "SELECT * FROM products WHERE name LIKE '%rust proof%'", "multiple words")

    def test_placeholder_rejected(self):
        self.assertRejected("SELECT * FROM products WHERE category = ?", "placeholder")

    def test_compare_to_null_rejected(self):
        self.assertRejected("SELECT * FROM products WHERE category = NULL", "IS NULL")

    def test_not_a_select(self):
        self.assertRejected("UPDATE products SET price = 1", "expected SELECT")


class TestWarnings(unittest.TestCase):
    def test_text_like_warns_about_token_semantics(self):
        result = translate("SELECT * FROM products WHERE name LIKE 'Ham%'", SCHEMA)
        self.assertTrue(any("per token" in w for w in result.warnings), result.warnings)

    def test_suffix_like_warns_about_suffix_trie(self):
        result = translate("SELECT * FROM products WHERE name LIKE '%mer'", SCHEMA)
        self.assertTrue(any("WITHSUFFIXTRIE" in w for w in result.warnings))

    def test_multiple_order_by_warns(self):
        result = translate(
            "SELECT * FROM products WHERE stock = 1 ORDER BY price, stock", SCHEMA)
        self.assertTrue(any("single field" in w for w in result.warnings))


if __name__ == "__main__":
    unittest.main()
