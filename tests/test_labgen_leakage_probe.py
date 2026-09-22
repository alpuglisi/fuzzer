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
    DEFAULT_CLASS_THRESHOLD,
    FEATURE_ALLOWLIST,
    MIN_CELLS_FOR_GATE,
    MIN_CELLS_PER_CLASS_FOR_GATE,
    MIN_GROUPS_FOR_GATE,
    PER_CLASS_AUC_THRESHOLDS,
    PER_CLASS_FEATURE_EXCLUSIONS,
    PROVISIONAL_THRESHOLD_BAND,
    THRESHOLD_STATUSES,
    ClassThreshold,
    InsufficientCorpusError,
    MetadataLeakageError,
    class_threshold,
    format_leakage_report,
    insufficiency_reason,
    probe_leakage,
    run_leakage_gate,
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


# ---------------------------------------------------------------------------
# Per-class thresholds + the build gate (lane L-P1.3,
# docs/LAB_IMPLEMENTATION_PLAN.md SS2.3).
#
# Every corpus below is one of this module's own existing fixtures
# (`_leaky_corpus` / `_clean_corpus`), per this lane's scope discipline: reuse
# the probe's fixtures rather than re-authoring a parallel set.
# ---------------------------------------------------------------------------

GATE_KWARGS = {"n_splits": 3, "n_permutations": 40, "random_state": 0}


def test_every_shipped_per_class_threshold_is_provisional_and_inside_the_plans_band():
    # SS2.3 is explicit that Phase 1's values are PROVISIONAL, seeded from the
    # report's band. Both properties are asserted against the module's own
    # source-of-truth constants rather than literals (PA-0001).
    low, high = PROVISIONAL_THRESHOLD_BAND
    shipped = list(PER_CLASS_AUC_THRESHOLDS.values()) + [DEFAULT_CLASS_THRESHOLD]
    assert shipped, "the registry must not be empty"
    for threshold in shipped:
        assert threshold.status == "provisional"
        assert threshold.status in THRESHOLD_STATUSES
        assert low <= threshold.auc_threshold <= high
        assert threshold.justification.strip()


def test_class_threshold_falls_back_to_the_documented_default():
    assert class_threshold("sqli") is PER_CLASS_AUC_THRESHOLDS["sqli"]
    assert class_threshold("a_class_nobody_has_registered") is DEFAULT_CLASS_THRESHOLD


def test_class_threshold_rejects_an_unknown_status_and_an_impossible_auc():
    with pytest.raises(ValueError, match="status must be one of"):
        ClassThreshold(auc_threshold=0.58, status="calibrated-ish", justification="x")
    with pytest.raises(ValueError, match=r"must be in \[0.5, 1.0\]"):
        ClassThreshold(auc_threshold=0.2, status="provisional", justification="x")
    with pytest.raises(ValueError, match="non-empty written line"):
        ClassThreshold(auc_threshold=0.58, status="provisional", justification="   ")


def test_per_class_rows_are_reported_for_every_class():
    result = probe_leakage(_clean_corpus(), **GATE_KWARGS)
    assert {row.label for row in result.per_class} == {"sqli_error", "secure"}
    for row in result.per_class:
        assert row.n_samples == 60
        # Fail-closed: the effective line is the STRICTER of the two, so a
        # configured number can only tighten the gate, never disable it.
        assert row.effective_threshold == min(row.null_threshold, row.configured.auc_threshold)
        assert row.binding_line in {"permutation_null", "configured_threshold"}


def test_a_configured_threshold_can_only_ever_tighten_never_loosen(monkeypatch):
    """The loophole `PER_CLASS_FEATURE_EXCLUSIONS`'s own comment warns about: a
    per-class threshold must not be settable high enough to switch the gate off
    for that class. Setting one to the maximum must leave the verdict exactly as
    the permutation null alone decided it."""
    monkeypatch.setitem(
        PER_CLASS_AUC_THRESHOLDS,
        "sqli_error",
        ClassThreshold(auc_threshold=1.0, status="provisional", justification="test: maximally loose"),
    )
    result = probe_leakage(_leaky_corpus(), **GATE_KWARGS)
    row = next(r for r in result.per_class if r.label == "sqli_error")
    assert row.binding_line == "permutation_null"
    assert row.effective_threshold == row.null_threshold
    assert row.leaks is True  # still caught, despite a 1.0 configured threshold


def test_gate_passes_on_a_non_leaky_corpus_and_returns_a_report():
    report = run_leakage_gate(_clean_corpus(), **GATE_KWARGS)
    assert report.result.gate_passes is True
    assert report.result.leaks is False
    assert report.result.per_class_leaks is False
    assert report.report_text == format_leakage_report(report.result)


def test_gate_fails_loud_on_a_deliberately_leaky_corpus():
    # `_leaky_corpus` makes `status_code` trivially predict the class.
    with pytest.raises(MetadataLeakageError) as exc_info:
        run_leakage_gate(_leaky_corpus(), **GATE_KWARGS)
    message = str(exc_info.value)
    # Names EVERY violation, global and per-class, not just the first.
    assert "global metadata AUC" in message
    assert "class 'sqli_error'" in message
    assert "class 'secure'" in message


def test_gate_report_marks_each_threshold_provisional_or_calibrated():
    report = run_leakage_gate(_clean_corpus(), **GATE_KWARGS)
    text = report.report_text
    assert "PROVISIONAL" in text
    # Each class gets its own annotated line, plus the configured rationale.
    for label in ("sqli_error", "secure"):
        assert f"- {label}: AUC" in text
        assert PER_CLASS_AUC_THRESHOLDS[label].justification in text
    # And the report says, in words, which classes' verdicts rest on a number
    # nobody has calibrated yet -- the point of the SS2.3 requirement.
    if report.result.provisional_classes:
        assert "not one derived" in text
    else:
        assert "no verdict above currently rests on an uncalibrated" in text


def test_gate_skips_rather_than_fails_on_a_corpus_too_small_to_judge():
    tiny = _clean_corpus(n=MIN_CELLS_FOR_GATE - 1, n_rules=MIN_GROUPS_FOR_GATE + 2)
    reason = insufficiency_reason(tiny)
    assert reason is not None and str(MIN_CELLS_FOR_GATE) in reason
    with pytest.raises(InsufficientCorpusError, match="permutation null"):
        run_leakage_gate(tiny, **GATE_KWARGS)


def test_insufficiency_reason_names_each_distinct_shortfall():
    assert "empty" in insufficiency_reason([])

    one_class = [
        _make_cell("secure", f"rule{i}", **dict.fromkeys(FEATURE_ALLOWLIST, 1))
        for i in range(MIN_CELLS_FOR_GATE + 5)
    ]
    assert ">= 2" in insufficiency_reason(one_class)

    few_groups = _clean_corpus(n=MIN_CELLS_FOR_GATE + 10, n_rules=MIN_GROUPS_FOR_GATE - 1)
    assert "generating-rule group" in insufficiency_reason(few_groups)

    thin_class = _clean_corpus(n=MIN_CELLS_FOR_GATE + 10, n_rules=MIN_GROUPS_FOR_GATE + 2)
    for cell in thin_class[: len(thin_class) - (MIN_CELLS_PER_CLASS_FOR_GATE - 1)]:
        cell["label"] = "sqli_error"
    assert "fewer than" in insufficiency_reason(thin_class)

    # A big, well-grouped corpus whose in-scope feature never varies: no
    # variance means every AUC is chance by construction.
    flat = _clean_corpus(n=MIN_CELLS_FOR_GATE + 10, n_rules=MIN_GROUPS_FOR_GATE + 2)
    for cell in flat:
        cell["features"]["path_depth"] = 1
    assert "varies across this corpus" in insufficiency_reason(flat, feature_scope=("path_depth",))
    # ...while the same corpus with the full allowlist in scope is measurable.
    assert insufficiency_reason(flat) is None


def test_feature_scope_narrows_the_probe_and_can_never_widen_the_allowlist():
    cells = _clean_corpus()
    result = probe_leakage(cells, feature_scope=("path_depth", "status_code"), **GATE_KWARGS)
    # Allowlist order is preserved regardless of the order passed.
    assert result.features_used == ("status_code", "path_depth")

    with pytest.raises(ValueError, match="may only NARROW"):
        probe_leakage(cells, feature_scope=("status_code", "raw_payload"), **GATE_KWARGS)
    with pytest.raises(ValueError, match="at least one allowlisted feature"):
        probe_leakage(cells, feature_scope=(), **GATE_KWARGS)


def test_an_in_scope_feature_missing_from_a_cell_is_rejected_not_imputed():
    # PA-0006: a silently-imputed feature would be an input the real upstream
    # never produced. The probe must say so rather than guess.
    cells = _clean_corpus()
    del cells[3]["features"]["latency_ms"]
    with pytest.raises(ValueError, match="absent from at least one"):
        probe_leakage(cells, **GATE_KWARGS)
    # ...and narrowing the scope to what the corpus does carry is the fix.
    assert probe_leakage(cells, feature_scope=("status_code",), **GATE_KWARGS) is not None


def test_existing_global_leaks_field_keeps_its_meaning():
    # Backward compatibility: `leaks` stays the global-AUC-vs-global-null
    # verdict it always was; the per-class verdict is a separate field.
    result = probe_leakage(_clean_corpus(), **GATE_KWARGS)
    assert result.leaks == (result.observed_auc > result.null_threshold)
    assert result.gate_passes == (not (result.leaks or result.per_class_leaks))
