"""Phase 8 T8.1: mutation operators, semantics validator, migration 8."""

import pytest

from fuzzlab.core import migrations
from fuzzlab.core.store import Store
from fuzzlab.mutation.operators import (ANY, apply_chain, default_operators)
from fuzzlab.mutation.semantics import (SemanticsValidator, canonicalize,
                                        sqlglot_available)

SQLI = "1 union select password from users"


# --- migration 8 -------------------------------------------------------------
def test_migration_8_adds_payload_variant(tmp_path):
    with Store(tmp_path / "u.db") as store:
        assert store.schema_version() == max(v for v, _ in migrations.MIGRATIONS) >= 8
        cols = {r["name"] for r in store.conn.execute("PRAGMA table_info(payload_variant)")}
        assert {"base_payload", "variant", "operators", "bypassed_rule",
                "semantics_ok", "coverage_gain"} <= cols


# --- operator applicability --------------------------------------------------
def test_default_operators_filter_by_class():
    ids_sql = {op.id for op in default_operators("sql-injection")}
    ids_xss = {op.id for op in default_operators("xss")}
    assert {"url-encode", "ws-alt", "sql-comment", "case-toggle", "sql-equivalent"} <= ids_sql
    assert "sql-comment" not in ids_xss and "sql-equivalent" not in ids_xss
    assert "case-toggle" in ids_xss and "url-encode" in ids_xss   # url-encode is ANY


# --- surface operators preserve semantics ------------------------------------
def test_every_surface_variant_preserves_semantics():
    v = SemanticsValidator()
    for op in default_operators("sql-injection"):
        for variant in op.apply(SQLI):
            assert variant != SQLI                                # actually changed
            assert v.preserves(SQLI, variant, "sql-injection", trusted=not op.surface)


def test_url_encode_roundtrips():
    import urllib.parse
    (enc,) = next(o for o in default_operators() if o.id == "url-encode").apply(SQLI)
    assert enc != SQLI and urllib.parse.unquote(enc) == SQLI


def test_whitespace_and_comment_are_evasive_but_equivalent():
    ws = next(o for o in default_operators("sql-injection") if o.id == "ws-alt")
    variants = ws.apply(SQLI)
    assert any("/**/" in x for x in variants) and any("%09" in x for x in variants)
    v = SemanticsValidator()
    assert all(canonicalize(x) == canonicalize(SQLI) for x in variants)
    assert all(v.preserves(SQLI, x, "sql-injection") for x in variants)


def test_apply_no_op_returns_empty():
    ws = next(o for o in default_operators("sql-injection") if o.id == "ws-alt")
    assert ws.apply("nospaceshere") == []                          # nothing to change


# --- vetted-equivalent operator (trusted by provenance) ----------------------
def test_sql_equivalent_needs_trusted_provenance():
    base = "1 or 1=1"
    eq = next(o for o in default_operators("sql-injection") if o.id == "sql-equivalent")
    variants = eq.apply(base)
    assert variants and all(x != base for x in variants)
    v = SemanticsValidator()
    for x in variants:
        # a tautology swap is NOT canonical-equal, so it is accepted only as trusted
        assert v.preserves(base, x, "sql-injection", trusted=True)
    assert not v.preserves(base, "1 or 1=1 -- x", "sql-injection")  # not vetted → refused


# --- the validator refutes meaning changes -----------------------------------
def test_validator_rejects_meaning_change():
    v = SemanticsValidator()
    assert not v.preserves("id=1", "id=2", "sql-injection")
    assert not v.preserves("cat=dogs", "cat=cats", "xss")


def test_canonicalize_normalizes_surface_variation():
    assert canonicalize("UNION/**/SELECT  1") == canonicalize("union select 1")
    assert canonicalize("%2f..%2f") == canonicalize("/../")        # url-decoded


def test_case_toggle_preserved_for_xss():
    v = SemanticsValidator()
    (upper, _alt) = next(o for o in default_operators("xss")
                         if o.id == "case-toggle").apply("<svg onload=x>")
    assert v.preserves("<svg onload=x>", upper, "xss")


# --- deterministic chains ----------------------------------------------------
def test_apply_chain_is_deterministic_and_preserving():
    ops = default_operators("sql-injection")
    a = apply_chain(SQLI, ops)
    b = apply_chain(SQLI, ops)
    assert a == b and a != SQLI
    assert canonicalize(a) == canonicalize(SQLI)                   # surface-only chain


# --- AST path (on-host: needs a working sqlglot) -----------------------------
@pytest.mark.skipif(not sqlglot_available(), reason="sqlglot unavailable/broken")
def test_ast_equivalence_when_sqlglot_present():
    v = SemanticsValidator(use_ast=True)
    assert v.use_ast is True
    assert v.preserves("SELECT 1 UNION SELECT 2", "SELECT 1 UNION/**/SELECT 2",
                       "sql-injection")


# --- BUG-0027 regression: AST must never override canonicalize -------------
# (fail-open direction) An AST-decisive verdict must never launder an unvetted
# `--` comment injection into "meaning preserving", since sqlglot discards
# comments as trivia and cannot tell a vetted /* */ insertion from an
# arbitrary trailing comment that would truncate the rest of a real query.
def test_ast_never_approves_an_unvetted_line_comment_injection():
    v = SemanticsValidator()
    assert not v.preserves("1 or 1=1", "1 or 1=1 -- x", "sql-injection")
    assert not v.preserves("id=1 and 2=2", "id=1 and 2=2 --", "sql-injection")


# (fail-closed direction) Canonicalize's case-insensitive comparison must
# decide case-toggle variants before AST ever gets a say, since sqlglot's tree
# equality is sensitive to identifier/keyword case even though SQL keywords
# and unquoted identifiers are case-insensitive.
def test_ast_never_rejects_a_case_toggle_canonicalize_already_accepts():
    v = SemanticsValidator()
    assert v.preserves("1 union select password from users",
                       "1 UNION SELECT PASSWORD FROM USERS", "sql-injection")
    assert v.preserves("1 union select password from users",
                       "1 uNiOn SeLeCt pAsSwOrD fRoM uSeRs", "sql-injection")
