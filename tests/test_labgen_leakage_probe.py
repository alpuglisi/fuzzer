"""Tests for the T-LAB0.11 leakage-probe reference implementation.

Reference: `docs/LAB_PHASE_0_PLAN.md` T-LAB0.11,
`docs/components/01-target-lab/requirements.md` FR-LAB-8.
This is a reference implementation only (not wired into any build gate); the
tests here verify the mechanism itself against synthetic fixtures, per the
task brief: one corpus that should clearly leak, one that should not.
"""

from __future__ import annotations

import random

import pytest

pytest.importorskip("sklearn", reason="leakage probe requires scikit-learn")

from fuzzlab.labgen.leakage_probe import (
    FEATURE_ALLOWLIST,
    PER_CLASS_FEATURE_EXCLUSIONS,
    probe_leakage,
)


def _make_cell(label, rule_id, **features):
    return {"label": label, "rule_id": rule_id, "features": features}


def _leaky_corpus(n=120, n_rules=12, seed=0):
    """Status code is deterministically correlated with the label -> should leak."""
    rng = random.Random(seed)
    cells = []
    for i in range(n):
        rule = f"rule{i % n_rules}"
        label = "sqli_error" if i % 2 == 0 else "secure"
        status = 500 if label == "sqli_error" else 200
        cells.append(
            _make_cell(
                label,
                rule,
                status_code=status,
                response_length=100 + rng.randint(0, 20),
                header_count=8,
                latency_ms=20 + rng.randint(0, 5),
                param_name_length=5,
                path_depth=2,
                content_type="text/html",
            )
        )
    return cells


def _clean_corpus(n=120, n_rules=12, seed=1):
    """Features are independent of the label -> should not leak."""
    rng = random.Random(seed)
    cells = []
    for i in range(n):
        rule = f"rule{i % n_rules}"
        label = "sqli_error" if i % 2 == 0 else "secure"
        cells.append(
            _make_cell(
                label,
                rule,
                status_code=rng.choice([200, 404, 500]),
                response_length=rng.randint(50, 500),
                header_count=rng.randint(5, 12),
                latency_ms=rng.randint(10, 100),
                param_name_length=rng.randint(3, 10),
                path_depth=rng.randint(1, 5),
                content_type=rng.choice(["text/html", "application/json"]),
            )
        )
    return cells


def test_feature_allowlist_is_closed_and_payload_free():
    # Explicitly assert the allowlist is exactly the closed set from the plan,
    # never anything payload- or body-derived (no "payload", "body", etc.).
    assert set(FEATURE_ALLOWLIST) == {
        "status_code",
        "response_length",
        "header_count",
        "latency_ms",
        "param_name_length",
        "path_depth",
        "content_type",
    }
    forbidden_substrings = ("payload", "body", "injection", "sql")
    for name in FEATURE_ALLOWLIST:
        for bad in forbidden_substrings:
            assert bad not in name.lower()


def test_leaky_corpus_flagged_above_null_threshold():
    cells = _leaky_corpus()
    result = probe_leakage(cells, n_splits=3, n_permutations=40, random_state=0)
    assert result.leaks is True
    assert result.observed_auc > result.null_threshold
    # A near-perfect deterministic correlation should produce a near-perfect AUC.
    assert result.observed_auc > 0.9
    assert result.exclusion_count == 0  # no excluded classes present


def test_clean_corpus_not_flagged():
    cells = _clean_corpus()
    result = probe_leakage(cells, n_splits=3, n_permutations=40, random_state=0)
    assert result.leaks is False
    assert result.observed_auc <= result.null_threshold
    assert result.exclusion_count == 0


def test_grouping_by_generating_rule_id_is_enforced():
    # Every cell from the same rule carries the exact same feature vector,
    # so a random (non-grouped) split would let identical rows leak across
    # train/test and inflate AUC to ~1.0. With proper StratifiedGroupKFold
    # grouping, an otherwise-uninformative-per-rule signal must not leak
    # trivially just because duplicates exist within a rule.
    cells = []
    for rule_idx in range(10):
        rule = f"rule{rule_idx}"
        label = "sqli_error" if rule_idx % 2 == 0 else "secure"
        # 10 near-identical cells per rule (only response_length jitters).
        for j in range(10):
            cells.append(
                _make_cell(
                    label,
                    rule,
                    status_code=200,
                    response_length=300 + j,
                    header_count=8,
                    latency_ms=25,
                    param_name_length=6,
                    path_depth=2,
                    content_type="text/html",
                )
            )
    result = probe_leakage(cells, n_splits=5, n_permutations=30, random_state=0)
    # n_groups must equal the number of distinct rules, not the number of cells.
    assert result.n_groups == 10
    assert result.n_samples == 100


def test_per_class_exclusion_applied_and_reported():
    cells = _clean_corpus(n=80, n_rules=10, seed=2)
    # Swap in a class with a registered exclusion (time-based blind SQLi).
    for cell in cells[:20]:
        cell["label"] = "sqli_blind_time"
    result = probe_leakage(cells, n_splits=3, n_permutations=20, random_state=0)
    assert "latency_ms" not in result.features_used
    assert result.exclusion_count == 1
    cls, feature, justification = result.exclusions_applied[0]
    assert cls == "sqli_blind_time"
    assert feature == "latency_ms"
    assert justification  # a written one-line justification is present


def test_per_class_exclusions_have_written_justifications():
    # Guards the "never a quiet loophole" requirement: every registered
    # exclusion must carry a non-empty, single-line justification.
    for cls, exclusions in PER_CLASS_FEATURE_EXCLUSIONS.items():
        for feature, justification in exclusions.items():
            assert feature in FEATURE_ALLOWLIST
            assert isinstance(justification, str) and justification.strip()
            assert "\n" not in justification.strip()


def test_rejects_feature_outside_closed_allowlist():
    cells = _clean_corpus(n=20, n_rules=5)
    cells[0]["features"]["raw_payload"] = "' OR 1=1--"
    with pytest.raises(ValueError, match="closed allowlist"):
        probe_leakage(cells, n_splits=3, n_permutations=5)


def test_rejects_too_few_label_classes():
    cells = [
        _make_cell(
            "secure",
            f"rule{i}",
            status_code=200,
            response_length=100,
            header_count=8,
            latency_ms=20,
            param_name_length=5,
            path_depth=2,
            content_type="text/html",
        )
        for i in range(10)
    ]
    with pytest.raises(ValueError, match="two distinct label classes"):
        probe_leakage(cells, n_splits=3, n_permutations=5)


def test_missing_group_key_rejected():
    cells = _clean_corpus(n=10, n_rules=3)
    del cells[0]["rule_id"]
    with pytest.raises(ValueError, match="group key"):
        probe_leakage(cells, n_splits=3, n_permutations=5)
