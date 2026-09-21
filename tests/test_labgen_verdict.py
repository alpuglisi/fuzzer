"""Tests for the versioned, snapshot-tested verdict() function (T-LAB0.1).

Follows this repo's existing golden-file convention (see
tests/test_features_golden.py): a fixed safety matrix + a fixed set of
(pipeline, sink_context) pairs must always produce the recorded verdicts. A
bare diff here is a red flag, not something to "fix" by updating the golden
file without understanding why it moved. Set FUZZLAB_REGEN_GOLDEN=1 to
regenerate after a deliberate, understood safety-matrix change.
"""

import json
import os
from pathlib import Path

import pytest

from fuzzlab.labgen.schema import Pipeline, SinkContext
from fuzzlab.labgen.verdict import (
    Effect,
    MatrixEntry,
    SafetyMatrix,
    SafetyMatrixError,
    load_safety_matrix,
    verdict,
)

GOLDEN = Path(__file__).parent / "golden" / "labgen_verdict_v1.json"
REAL_MATRIX_PATH = "lab/safety_matrix.yaml"


def _matrix_v1() -> SafetyMatrix:
    entries = {
        ("raw_concat", "sql_string_literal"): MatrixEntry("raw_concat", "sql_string_literal", Effect.NO_EFFECT),
        ("param_bind", "sql_string_literal"): MatrixEntry(
            "param_bind", "sql_string_literal", Effect.NEUTRALISES, neutralizes=("sql_syntax_break",)
        ),
        ("strip_quotes_naive", "sql_string_literal"): MatrixEntry(
            "strip_quotes_naive", "sql_string_literal", Effect.PARTIAL, neutralizes=("sql_syntax_break",)
        ),
        ("verbose_error_leak", "sql_string_literal"): MatrixEntry(
            "verbose_error_leak", "sql_string_literal", Effect.INTRODUCES, introduces=("error_based_disclosure",)
        ),
        ("reflect_raw_after_bind", "sql_string_literal"): MatrixEntry(
            "reflect_raw_after_bind", "sql_string_literal", Effect.INTRODUCES, introduces=("sql_syntax_break",)
        ),
        ("html_entity_escape", "html_body"): MatrixEntry(
            "html_entity_escape", "html_body", Effect.NEUTRALISES, neutralizes=("html_tag_break",)
        ),
        ("html_entity_escape", "html_attribute_unquoted"): MatrixEntry(
            "html_entity_escape", "html_attribute_unquoted", Effect.PARTIAL, neutralizes=("html_tag_break",)
        ),
    }
    return SafetyMatrix(version=1, entries=entries)


SQL_CTX = SinkContext(family="sql_string_literal", required_neutralizations=("sql_syntax_break",))
HTML_BODY_CTX = SinkContext(family="html_body", required_neutralizations=("html_tag_break",))
HTML_ATTR_UNQUOTED_CTX = SinkContext(family="html_attribute_unquoted", required_neutralizations=("html_tag_break",))


# --- Behavioral tests (fast, readable failure -> exact semantics) ---------


def test_no_transform_is_vulnerable():
    v = verdict(Pipeline([]), SQL_CTX, _matrix_v1())
    assert v.verdict == "VULNERABLE"
    assert v.difficulty is not None


def test_full_neutralisation_is_secure_with_no_difficulty():
    v = verdict(Pipeline(["param_bind"]), SQL_CTX, _matrix_v1())
    assert v.verdict == "SECURE"
    assert v.difficulty is None
    assert v.missing == ()


def test_partial_neutralisation_stays_vulnerable_never_a_third_value():
    """The D20 binary-verdict decision: partial neutralization is
    VULNERABLE-but-harder (a difficulty tier), never a third verdict."""
    v = verdict(Pipeline(["strip_quotes_naive"]), SQL_CTX, _matrix_v1())
    assert v.verdict in ("VULNERABLE", "SECURE")  # binary domain
    assert v.verdict == "VULNERABLE"
    assert v.difficulty is not None


def test_partial_is_harder_than_no_transform():
    baseline = verdict(Pipeline([]), SQL_CTX, _matrix_v1())
    partial = verdict(Pipeline(["strip_quotes_naive"]), SQL_CTX, _matrix_v1())
    tiers = ("trivial", "easy", "medium", "hard", "very_hard")
    assert tiers.index(partial.difficulty) >= tiers.index(baseline.difficulty)


def test_introduces_can_turn_a_secure_pipeline_vulnerable():
    v = verdict(Pipeline(["param_bind", "verbose_error_leak"]), SQL_CTX, _matrix_v1())
    assert v.verdict == "VULNERABLE"
    assert "error_based_disclosure" in v.missing


def test_escaping_context_mismatch_is_vulnerable_but_harder():
    """Same op (html_entity_escape), two sink families: fully sufficient in
    an HTML body, only partial in an unquoted attribute — the CR-LAB-0001
    'escaping-context-mismatch XSS' shape."""
    secure = verdict(Pipeline(["html_entity_escape"]), HTML_BODY_CTX, _matrix_v1())
    mismatched = verdict(Pipeline(["html_entity_escape"]), HTML_ATTR_UNQUOTED_CTX, _matrix_v1())
    assert secure.verdict == "SECURE"
    assert mismatched.verdict == "VULNERABLE"


def test_unknown_op_context_pair_raises_rather_than_silently_defaulting():
    with pytest.raises(SafetyMatrixError):
        verdict(Pipeline(["nonexistent_op"]), SQL_CTX, _matrix_v1())


def test_verdict_is_pure_and_order_independent_of_call_count():
    m = _matrix_v1()
    p = Pipeline(["strip_quotes_naive"])
    first = verdict(p, SQL_CTX, m)
    second = verdict(p, SQL_CTX, m)
    assert first == second


def test_pipeline_order_matters():
    """Neutralizing a concern and then reintroducing it (a defense applied
    before a later leak) ends VULNERABLE; reintroducing it and then
    neutralizing (the defense applied last) ends SECURE — same two ops,
    reversed order, different verdicts."""
    m = _matrix_v1()
    bind_then_leak = verdict(Pipeline(["param_bind", "reflect_raw_after_bind"]), SQL_CTX, m)
    leak_then_bind = verdict(Pipeline(["reflect_raw_after_bind", "param_bind"]), SQL_CTX, m)
    assert bind_then_leak.verdict == "VULNERABLE"
    assert leak_then_bind.verdict == "SECURE"


def test_matrix_version_is_carried_onto_the_verdict():
    v = verdict(Pipeline(["param_bind"]), SQL_CTX, _matrix_v1())
    assert v.safety_matrix_version == 1


# --- Snapshot test (golden file) ------------------------------------------


def _snapshot_cases():
    return {
        "no_transform_sql": (Pipeline([]), SQL_CTX),
        "param_bind_sql": (Pipeline(["param_bind"]), SQL_CTX),
        "strip_quotes_naive_sql": (Pipeline(["strip_quotes_naive"]), SQL_CTX),
        "param_bind_then_verbose_error_leak": (Pipeline(["param_bind", "verbose_error_leak"]), SQL_CTX),
        "html_entity_escape_body": (Pipeline(["html_entity_escape"]), HTML_BODY_CTX),
        "html_entity_escape_unquoted_attr": (Pipeline(["html_entity_escape"]), HTML_ATTR_UNQUOTED_CTX),
    }


def _compute_snapshot():
    matrix = _matrix_v1()
    return {name: verdict(p, ctx, matrix).to_dict() for name, (p, ctx) in _snapshot_cases().items()}


def test_verdict_matches_snapshot():
    computed = _compute_snapshot()
    if os.environ.get("FUZZLAB_REGEN_GOLDEN") == "1" or not GOLDEN.exists():
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(computed, indent=2, sort_keys=True) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert computed == expected


# --- Loader tests against the real lab/safety_matrix.yaml -----------------


def test_load_real_safety_matrix():
    matrix = load_safety_matrix(REAL_MATRIX_PATH)
    assert matrix.version == 1
    entry = matrix.lookup("param_bind", "sql_string_literal")
    assert entry.effect is Effect.NEUTRALISES


def test_real_matrix_reproduces_documented_partial_case():
    matrix = load_safety_matrix(REAL_MATRIX_PATH)
    ctx = SinkContext(family="html_attribute_unquoted", required_neutralizations=("html_tag_break",))
    v = verdict(Pipeline(["html_entity_escape"]), ctx, matrix)
    assert v.verdict == "VULNERABLE"
    assert v.difficulty is not None


def test_missing_safety_matrix_file_raises_actionable_error(tmp_path):
    with pytest.raises(SafetyMatrixError):
        load_safety_matrix(tmp_path / "nope.yaml")


def test_duplicate_matrix_entry_rejected(tmp_path):
    import yaml

    bad = {
        "version": 1,
        "entries": [
            {"op": "a", "sink_family": "b", "effect": "no_effect"},
            {"op": "a", "sink_family": "b", "effect": "no_effect"},
        ],
    }
    p = tmp_path / "matrix.yaml"
    p.write_text(yaml.safe_dump(bad))
    with pytest.raises(SafetyMatrixError):
        load_safety_matrix(p)
