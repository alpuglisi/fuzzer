"""Regression coverage for `build_sql_db.py`'s indicator catalog: guards the
invariant `build_sql_db.py`'s own comment states but nothing previously
enforced — "indicator_type MUST match a handler key in fetcher.py's RULES
registry, or the rule silently never runs." `audit_page()` already degrades
gracefully at runtime (an unmatched indicator_type lands in its `unhandled`
set rather than crashing), but nothing caught a drift between the two
registries turning into silently narrowed rule coverage. No prior coverage
existed for this module.
"""
import sqlite3

from fuzzlab.tools.build_sql_db import INDICATORS, build_indicator_database
from fuzzlab.tools.fetcher import RULES

_REFERENCES_ROOT = "references"


def test_every_indicator_type_has_a_rule_handler():
    indicator_types = {t for _, t, _, _, _ in INDICATORS}
    assert indicator_types == set(RULES.keys()), (
        "indicator_type <-> RULES key mismatch: "
        f"indicators without a rule={indicator_types - set(RULES.keys())}, "
        f"rules without an indicator={set(RULES.keys()) - indicator_types}"
    )


def test_every_reference_category_directory_exists():
    import os
    references = {r for _, _, _, _, r in INDICATORS}
    missing = {r for r in references if not os.path.isdir(os.path.join(_REFERENCES_ROOT, r))}
    assert not missing, f"references/ missing category dirs: {missing}"


def test_indicator_types_and_categories_are_non_empty_strings():
    for category, indicator_type, description, example, reference in INDICATORS:
        assert category and indicator_type and description and example and reference


def test_build_indicator_database_writes_every_indicator(tmp_path):
    db = str(tmp_path / "indicators.db")
    build_indicator_database(db)
    conn = sqlite3.connect(db)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM indicators")
    assert cursor.fetchone()[0] == len(INDICATORS)
    cursor.execute("SELECT indicator_type, reference FROM indicators")
    rows = set(cursor.fetchall())
    assert rows == {(t, r) for _, t, _, _, r in INDICATORS}
    conn.close()


def test_build_indicator_database_is_idempotent(tmp_path):
    db = str(tmp_path / "indicators.db")
    build_indicator_database(db)
    build_indicator_database(db)                  # re-running must not duplicate rows
    conn = sqlite3.connect(db)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM indicators")
    assert cursor.fetchone()[0] == len(INDICATORS)
    conn.close()
