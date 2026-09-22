"""Tests for the ground-truth label contract loader (T0.6)."""

import json

import pytest

from fuzzlab.labels import contract

GT_DIR = "lab/ground-truth"


def test_missing_ground_truth_dir_raises_actionable_error(tmp_path):
    with pytest.raises(contract.ContractError) as exc:
        contract.load(tmp_path / "lab" / "ground-truth")   # does not exist
    msg = str(exc.value)
    assert "ground-truth directory not found" in msg and "repo root" in msg


def test_loads_and_cross_checks_real_ground_truth():
    gt = contract.load(GT_DIR)
    # `L-P3.3c-CUT`: the target is the generated php_laravel lab, not the
    # retired hand-built `puppy-fort-factory/` app -- metadata only, the
    # cutover coverage gate does not diff on this field.
    assert gt.target == "php_laravel"
    # 8 vulnerable cases documented in VULNERABILITIES.md.
    assert len(gt.positives()) == 8
    assert gt.negatives()  # true negatives present for FP testing
    # Opaque case IDs: no vuln class leaks into the identifier.
    for case in gt.cases:
        for token in ("sql", "xss", "vuln"):
            assert token not in case.case_id.lower()


def test_expected_csv_matches_labels():
    gt = contract.load(GT_DIR)
    # A known positive and a known negative.
    p = gt.case_by_id("PFF-0001")
    assert p.expected_vulnerable and p.vuln_class == "sqli" and p.param == "id"
    n = gt.case_by_id("PFF-1001")
    assert not n.expected_vulnerable


def test_injection_points_include_client_only():
    gt = contract.load(GT_DIR)
    client_only = [pt for pt in gt.points if pt.client_only]
    # reviews.php#author and feedback.php?ref are client-side only.
    assert {pt.url for pt in client_only} == {"/reviews.php", "/feedback.php"}


def test_schema_rejects_bad_case(tmp_path):
    bad = {
        "version": 1, "target": "x",
        "cases": [{"case_id": "lower-0001", "url": "/x", "method": "GET",
                   "param": "p", "location": "query", "vuln_class": "sqli",
                   "sink_context": "sql", "expected_vulnerable": True,
                   "rendering": "server"}],
    }
    (tmp_path / "labels.json").write_text(json.dumps(bad))
    with pytest.raises(contract.ContractError):
        contract.load_labels(tmp_path)


def _minimal_case(**overrides):
    case = {
        "case_id": "PFF-9001", "url": "/x", "method": "GET", "param": "p",
        "location": "query", "vuln_class": "sqli", "sink_context": "sql",
        "expected_vulnerable": True, "rendering": "server",
    }
    case.update(overrides)
    return case


def test_per_case_stack_is_loaded_when_present(tmp_path):
    # Multi-stack ground truth (docs/LAB_IMPLEMENTATION_PLAN.md §4.4): `stack`
    # is inline, per-case metadata -- the same axis the fingerprint-
    # independence gate tests for independence from vuln_class.
    data = {"version": 1, "target": "x", "cases": [_minimal_case(stack="node_express")]}
    (tmp_path / "labels.json").write_text(json.dumps(data))
    (case,) = contract.load_labels(tmp_path)
    assert case.stack == "node_express"


def test_per_case_stack_is_optional_and_defaults_to_none(tmp_path):
    data = {"version": 1, "target": "x", "cases": [_minimal_case()]}
    (tmp_path / "labels.json").write_text(json.dumps(data))
    (case,) = contract.load_labels(tmp_path)
    assert case.stack is None


def test_empty_stack_string_is_rejected_by_the_schema(tmp_path):
    # Fail closed rather than record a meaningless stack name.
    data = {"version": 1, "target": "x", "cases": [_minimal_case(stack="")]}
    (tmp_path / "labels.json").write_text(json.dumps(data))
    with pytest.raises(contract.ContractError):
        contract.load_labels(tmp_path)


def test_real_ground_truth_still_loads_without_a_stack_field():
    # The hand-built PHP app's ground truth predates multi-stack and is not
    # backfilled here (its migration onto the generator is D20 §7.2 /
    # php_laravel's lane); the field must therefore stay optional.
    gt = contract.load(GT_DIR)
    assert all(c.stack is None for c in gt.cases)


def test_drift_between_labels_and_csv_is_caught(tmp_path):
    # Copy the real labels + points, but write a CSV with a flipped verdict.
    gt_src = contract.load(GT_DIR)
    import shutil
    for name in ("labels.json", "injection-points.json"):
        shutil.copy(f"{GT_DIR}/{name}", tmp_path / name)
    lines = ["case_id,url,method,param,location,category,expected_vulnerable"]
    for c in gt_src.cases:
        flipped = "false" if c.case_id == "PFF-0001" else str(c.expected_vulnerable).lower()
        lines.append(f"{c.case_id},{c.url},{c.method},{c.param},{c.location},{c.vuln_class},{flipped}")
    (tmp_path / "expectedresults.csv").write_text("\n".join(lines))
    with pytest.raises(contract.ContractError):
        contract.load(tmp_path)
