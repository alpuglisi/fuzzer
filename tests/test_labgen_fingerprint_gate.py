"""Offline tests for `fuzzlab.labgen.fingerprint_gate` (the CR-LAB-0001 §3
fingerprint-independence build gate). All tests use deterministic, hand-
constructed corpus metadata -- no randomness, so p-values are exact and
reproducible, and no real lab/manifest is involved (this gate is
schema-independent by design).

`scipy` (the `labgen-stats` extra) is a real, declared-but-optional
dependency this module imports lazily; the missing-dependency test simulates
its absence rather than skipping (scipy is installed in this dev
environment), so that branch is still exercised on every run.
"""

import sys

import pytest

from fuzzlab.labgen.fingerprint_gate import (
    ChiSquareResult,
    FingerprintGateReport,
    FingerprintIndependenceError,
    MissingStatsDependencyError,
    check_min_classes_per_stack,
    check_min_stacks_per_class,
    check_stack_class_independence,
    check_stack_verdict_independence,
    chi_square_independence,
    run_fingerprint_gate,
)


def _balanced_independent_corpus():
    """3 stacks x 3 classes x 2 verdicts, each combination repeated equally
    (10x) -- stack, class, and verdict are all constructed to be perfectly
    independent of one another, and every class/stack pair co-occurs."""
    stacks = ["flask", "express", "laravel"]
    classes = ["sql-injection", "command-injection", "ssti"]
    verdicts = ["vulnerable", "secure"]
    records = []
    for stack in stacks:
        for cls in classes:
            for verdict in verdicts:
                records.extend([{"stack": stack, "vuln_class": cls, "verdict": verdict}] * 10)
    return records


def _confounded_corpus():
    """Every flask cell is SSTI, every express cell is SQLi, every laravel
    cell is command-injection -- the exact leakage shape CR-LAB-0001 §3
    warns about ("every Flask cell is SSTI")."""
    mapping = {"flask": "ssti", "express": "sql-injection", "laravel": "command-injection"}
    records = []
    for stack, cls in mapping.items():
        records.extend([{"stack": stack, "vuln_class": cls, "verdict": "vulnerable"}] * 20)
    return records


def _skewed_but_covered_corpus():
    """2 stacks x 2 classes, every combination present (satisfies the
    coverage checks) but heavily skewed toward a diagonal -- demonstrates
    that coverage alone does not catch a strong statistical association;
    the chi-square check is still needed."""
    return (
        [{"stack": "flask", "vuln_class": "sql-injection"}] * 50
        + [{"stack": "flask", "vuln_class": "command-injection"}] * 5
        + [{"stack": "express", "vuln_class": "sql-injection"}] * 5
        + [{"stack": "express", "vuln_class": "command-injection"}] * 50
    )


# --- coverage checks ---------------------------------------------------------

def test_min_stacks_per_class_passes_on_balanced_corpus():
    check_min_stacks_per_class(_balanced_independent_corpus(), min_stacks_per_class=2)


def test_min_stacks_per_class_fails_naming_the_short_class():
    with pytest.raises(FingerprintIndependenceError) as exc_info:
        check_min_stacks_per_class(_confounded_corpus(), min_stacks_per_class=2)
    message = str(exc_info.value)
    assert "'ssti'" in message
    assert "'sql-injection'" in message
    assert "'command-injection'" in message
    assert "only 1 stack" in message


def test_min_classes_per_stack_fails_naming_the_short_stack():
    with pytest.raises(FingerprintIndependenceError) as exc_info:
        check_min_classes_per_stack(_confounded_corpus(), min_classes_per_stack=2)
    message = str(exc_info.value)
    assert "'flask'" in message
    assert "'express'" in message
    assert "'laravel'" in message


def test_expected_classes_flags_a_wholly_absent_class():
    records = [{"stack": "flask", "vuln_class": "sql-injection"}] * 4 + [
        {"stack": "express", "vuln_class": "sql-injection"}
    ] * 4
    with pytest.raises(FingerprintIndependenceError) as exc_info:
        check_min_stacks_per_class(records, min_stacks_per_class=2, expected_classes=["sql-injection", "ssti"])
    assert "'ssti'" in str(exc_info.value)
    assert "only 0 stack" in str(exc_info.value)


def test_expected_stacks_flags_a_wholly_absent_stack():
    records = [{"stack": "flask", "vuln_class": "sql-injection"}] * 4
    with pytest.raises(FingerprintIndependenceError) as exc_info:
        check_min_classes_per_stack(records, min_classes_per_stack=1, expected_stacks=["flask", "laravel"])
    assert "'laravel'" in str(exc_info.value)
    assert "only 0 class" in str(exc_info.value)


# --- chi-square independence --------------------------------------------------

def test_chi_square_independence_high_p_value_on_balanced_corpus():
    result = chi_square_independence(_balanced_independent_corpus(), "stack", "vuln_class")
    assert isinstance(result, ChiSquareResult)
    assert result.p_value == pytest.approx(1.0, abs=1e-9)
    assert result.statistic == pytest.approx(0.0, abs=1e-9)


def test_chi_square_independence_low_p_value_on_confounded_corpus():
    result = chi_square_independence(_confounded_corpus(), "stack", "vuln_class")
    assert result.p_value < 0.001


def test_check_stack_class_independence_passes_on_balanced_corpus():
    result = check_stack_class_independence(_balanced_independent_corpus(), alpha=0.05)
    assert result.p_value > 0.05


def test_check_stack_class_independence_fails_on_confounded_corpus():
    with pytest.raises(FingerprintIndependenceError) as exc_info:
        check_stack_class_independence(_confounded_corpus(), alpha=0.05)
    message = str(exc_info.value)
    assert "NOT independent" in message
    assert "chi2=" in message
    assert "p=" in message


def test_check_stack_verdict_independence_fails_on_a_skewed_verdict_corpus():
    records = (
        [{"stack": "flask", "verdict": "vulnerable"}] * 40
        + [{"stack": "flask", "verdict": "secure"}] * 2
        + [{"stack": "express", "verdict": "vulnerable"}] * 2
        + [{"stack": "express", "verdict": "secure"}] * 40
    )
    with pytest.raises(FingerprintIndependenceError) as exc_info:
        check_stack_verdict_independence(records, alpha=0.05)
    assert "stack and verdict are NOT independent" in str(exc_info.value)


def test_coverage_checks_pass_but_chi_square_still_catches_a_skewed_corpus():
    # The central point of having BOTH kinds of check: this corpus satisfies
    # every stack/class co-occurrence (coverage passes) but is still
    # strongly, statistically associated (chi-square must still catch it).
    corpus = _skewed_but_covered_corpus()
    check_min_stacks_per_class(corpus, min_stacks_per_class=2)
    check_min_classes_per_stack(corpus, min_classes_per_stack=2)
    with pytest.raises(FingerprintIndependenceError):
        check_stack_class_independence(corpus, alpha=0.05)


def test_degenerate_table_with_only_one_stack_raises_fingerprint_error():
    records = [{"stack": "flask", "vuln_class": "sql-injection"}] * 5 + [
        {"stack": "flask", "vuln_class": "ssti"}
    ] * 5
    with pytest.raises(FingerprintIndependenceError) as exc_info:
        chi_square_independence(records, "stack", "vuln_class")
    assert "need at least 2 distinct values" in str(exc_info.value)


def test_missing_scipy_raises_typed_error_not_raw_import_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "scipy.stats", None)
    with pytest.raises(MissingStatsDependencyError) as exc_info:
        chi_square_independence(_balanced_independent_corpus(), "stack", "vuln_class")
    assert "labgen-stats" in str(exc_info.value)


# --- run_fingerprint_gate (the build-gate entry point) -----------------------

def test_run_fingerprint_gate_passes_and_returns_a_report_on_a_good_corpus():
    report = run_fingerprint_gate(_balanced_independent_corpus())
    assert isinstance(report, FingerprintGateReport)
    assert set(report.stacks) == {"flask", "express", "laravel"}
    assert set(report.classes) == {"sql-injection", "command-injection", "ssti"}
    assert report.chi2_stack_class.p_value > 0.05
    assert report.chi2_stack_verdict is not None
    assert report.chi2_stack_verdict.p_value > 0.05


def test_run_fingerprint_gate_fails_loud_listing_every_violation():
    with pytest.raises(FingerprintIndependenceError) as exc_info:
        run_fingerprint_gate(_confounded_corpus())
    message = str(exc_info.value)
    # coverage violations for every class/stack, plus the chi-square failure
    assert "violation(s)" in message
    assert "'ssti'" in message
    assert "NOT independent" in message


def test_run_fingerprint_gate_rejects_an_empty_corpus():
    with pytest.raises(FingerprintIndependenceError):
        run_fingerprint_gate([])


def test_run_fingerprint_gate_skips_verdict_check_when_verdict_key_absent():
    records = [
        {"stack": s, "vuln_class": c}
        for s in ("flask", "express", "laravel")
        for c in ("sql-injection", "command-injection", "ssti")
        for _ in range(10)
    ]
    report = run_fingerprint_gate(records)
    assert report.chi2_stack_verdict is None


def test_run_fingerprint_gate_verdict_check_can_be_disabled_explicitly():
    corpus = _balanced_independent_corpus()
    report = run_fingerprint_gate(corpus, check_verdict_independence=False)
    assert report.chi2_stack_verdict is None
