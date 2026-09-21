"""Tests for the regression/additive-only build gate (T-LAB0.9).

Mirrors ``tests/test_labgen_gates.py``'s own convention: exercise the gate
against the real ground truth (must pass unchanged, and against itself) and
against a deliberately shrunk/altered fixture (must fail loud).
"""

from __future__ import annotations

import shutil

import pytest

from fuzzlab.labels.contract import Case, GroundTruth
from fuzzlab.labgen.regression_gate import (
    PageChange,
    RegressionGateError,
    VerdictChange,
    assert_no_regression,
    check_no_regression,
    diff_ground_truth,
)

GT_DIR = "lab/ground-truth"


def _case(case_id: str, url: str = "/x.php", *, expected_vulnerable: bool = True, **kw) -> Case:
    defaults = dict(
        method="GET", param="p", location="query", vuln_class="sqli",
        sink_context="sql", rendering="server",
    )
    defaults.update(kw)
    return Case(case_id=case_id, url=url, expected_vulnerable=expected_vulnerable, **defaults)


def _gt(*cases: Case, target: str = "t") -> GroundTruth:
    return GroundTruth(target=target, cases=list(cases), points=[])


# --- Case extension (defaults + identity) ---------------------------------


def test_case_extension_fields_default_for_a_plain_single_location_case():
    c = _case("PFF-9001")
    assert c.primary_endpoint is None
    assert c.primary_role is None
    assert c.related_endpoints == ()
    assert c.flow_variant == "direct"


def test_case_extension_fields_can_be_set_explicitly():
    c = _case(
        "PFF-9002",
        primary_endpoint="/render.php",
        primary_role="sink",
        related_endpoints=({"endpoint": "/store.php", "role": "source"},),
        flow_variant="stored_second_order",
    )
    assert c.primary_endpoint == "/render.php"
    assert c.primary_role == "sink"
    assert c.related_endpoints == ({"endpoint": "/store.php", "role": "source"},)
    assert c.flow_variant == "stored_second_order"


def test_real_ground_truth_round_trips_through_schema_with_defaulted_extension_fields():
    # lab/ground-truth/labels.json predates these fields entirely -- loading
    # it must not raise, and every case must fall back to the single-location
    # defaults (schema tolerates the fields being entirely absent).
    from fuzzlab.labels import contract

    gt = contract.load(GT_DIR)
    assert gt.cases  # sanity: real data loaded
    for case in gt.cases:
        assert case.flow_variant == "direct"
        assert case.related_endpoints == ()


def test_schema_accepts_a_case_using_the_new_multi_location_fields(tmp_path):
    import json

    from fuzzlab.labels import contract

    data = {
        "version": 1, "target": "x",
        "cases": [{
            "case_id": "PFF-9003", "url": "/render.php", "method": "GET",
            "param": "bio", "location": "body", "vuln_class": "xss-stored",
            "sink_context": "html", "expected_vulnerable": True,
            "rendering": "server", "primary_endpoint": "/render.php",
            "primary_role": "sink",
            "related_endpoints": [{"endpoint": "/store.php", "role": "source"}],
            "flow_variant": "stored_second_order",
        }],
    }
    (tmp_path / "labels.json").write_text(json.dumps(data))
    [case] = contract.load_labels(tmp_path)
    assert case.flow_variant == "stored_second_order"
    assert case.related_endpoints == ({"endpoint": "/store.php", "role": "source"},)


def test_schema_rejects_an_unknown_flow_variant(tmp_path):
    import json

    from fuzzlab.labels import contract

    data = {
        "version": 1, "target": "x",
        "cases": [{
            "case_id": "PFF-9004", "url": "/x.php", "method": "GET",
            "param": "p", "location": "query", "vuln_class": "sqli",
            "sink_context": "sql", "expected_vulnerable": True,
            "rendering": "server", "flow_variant": "not-a-real-variant",
        }],
    }
    (tmp_path / "labels.json").write_text(json.dumps(data))
    with pytest.raises(contract.ContractError):
        contract.load_labels(tmp_path)


def test_load_expected_csv_still_works_with_the_four_new_trailing_columns():
    # PA/behavior confirmation named explicitly in the task: csv.DictReader
    # already tolerates unknown/extra columns; the real ground-truth CSV now
    # carries the four new columns and must still cross-check cleanly.
    from fuzzlab.labels import contract

    gt = contract.load(GT_DIR)
    p = gt.case_by_id("PFF-0001")
    assert p.expected_vulnerable


# --- Regression gate: diff logic ------------------------------------------


def test_diff_is_clean_when_candidate_equals_baseline():
    a = _case("PFF-0001")
    diff = diff_ground_truth(_gt(a), _gt(a))
    assert diff.is_clean
    assert diff.missing_case_ids == ()
    assert diff.changed_pages == ()
    assert diff.changed_verdicts == ()


def test_diff_allows_additive_new_cases():
    a = _case("PFF-0001")
    b = _case("PFF-0002", url="/y.php")
    diff = diff_ground_truth(_gt(a), _gt(a, b))
    assert diff.is_clean
    assert diff.added_case_ids == ("PFF-0002",)


def test_diff_flags_a_missing_case_id():
    a = _case("PFF-0001")
    b = _case("PFF-0002", url="/y.php")
    diff = diff_ground_truth(_gt(a, b), _gt(a))  # candidate dropped PFF-0002
    assert not diff.is_clean
    assert diff.missing_case_ids == ("PFF-0002",)


def test_diff_flags_a_changed_page():
    baseline = _case("PFF-0001", url="/product.php")
    candidate = _case("PFF-0001", url="/moved.php")
    diff = diff_ground_truth(_gt(baseline), _gt(candidate))
    assert not diff.is_clean
    assert diff.changed_pages == (PageChange("PFF-0001", "/product.php", "/moved.php"),)


def test_diff_flags_a_changed_verdict():
    baseline = _case("PFF-0001", expected_vulnerable=True)
    candidate = _case("PFF-0001", expected_vulnerable=False)
    diff = diff_ground_truth(_gt(baseline), _gt(candidate))
    assert not diff.is_clean
    assert diff.changed_verdicts == (VerdictChange("PFF-0001", True, False),)


# --- Regression gate: fail-loud assertion ----------------------------------


def test_assert_no_regression_passes_when_clean():
    a = _case("PFF-0001")
    assert_no_regression(_gt(a), _gt(a)).is_clean  # must not raise


def test_assert_no_regression_raises_and_names_every_violation():
    baseline = _gt(
        _case("PFF-0001", url="/a.php", expected_vulnerable=True),
        _case("PFF-0002", url="/b.php", expected_vulnerable=True),
    )
    candidate = _gt(
        _case("PFF-0001", url="/a-moved.php", expected_vulnerable=False),
        # PFF-0002 dropped entirely
    )
    with pytest.raises(RegressionGateError) as exc:
        assert_no_regression(baseline, candidate)
    msg = str(exc.value)
    assert "PFF-0001" in msg and "PFF-0002" in msg
    assert "page changed" in msg
    assert "verdict changed" in msg
    assert "missing case IDs" in msg


# --- Regression gate: directory-loading wiring -----------------------------


def test_check_no_regression_passes_for_the_real_ground_truth_against_itself():
    check_no_regression(GT_DIR, GT_DIR)  # must not raise


def test_check_no_regression_fails_on_a_deliberately_shrunk_fixture(tmp_path):
    # Copy the real ground truth, then drop one case from labels.json (and
    # its expectedresults.csv row) to simulate a generator run that silently
    # lost a case.
    for name in ("labels.json", "expectedresults.csv", "injection-points.json"):
        shutil.copy(f"{GT_DIR}/{name}", tmp_path / name)

    import json

    labels_path = tmp_path / "labels.json"
    data = json.loads(labels_path.read_text())
    dropped_id = data["cases"][0]["case_id"]
    data["cases"] = data["cases"][1:]
    labels_path.write_text(json.dumps(data))

    csv_path = tmp_path / "expectedresults.csv"
    lines = [ln for ln in csv_path.read_text().splitlines() if not ln.startswith(f"{dropped_id},")]
    csv_path.write_text("\n".join(lines) + "\n")

    with pytest.raises(RegressionGateError) as exc:
        check_no_regression(GT_DIR, tmp_path)
    assert dropped_id in str(exc.value)


def test_check_no_regression_fails_on_a_flipped_verdict_fixture(tmp_path):
    for name in ("labels.json", "expectedresults.csv", "injection-points.json"):
        shutil.copy(f"{GT_DIR}/{name}", tmp_path / name)

    import json

    labels_path = tmp_path / "labels.json"
    data = json.loads(labels_path.read_text())
    target_id = data["cases"][0]["case_id"]
    data["cases"][0]["expected_vulnerable"] = not data["cases"][0]["expected_vulnerable"]
    labels_path.write_text(json.dumps(data))

    csv_path = tmp_path / "expectedresults.csv"
    lines = csv_path.read_text().splitlines()
    new_lines = []
    for ln in lines:
        if ln.startswith(f"{target_id},"):
            fields = ln.split(",")
            fields[6] = "false" if fields[6].strip().lower() == "true" else "true"
            ln = ",".join(fields)
        new_lines.append(ln)
    csv_path.write_text("\n".join(new_lines) + "\n")

    with pytest.raises(RegressionGateError) as exc:
        check_no_regression(GT_DIR, tmp_path)
    assert target_id in str(exc.value)
    assert "verdict changed" in str(exc.value)


def test_check_no_regression_uses_injected_loader():
    calls: list = []

    def fake_loader(path):
        calls.append(str(path))
        a = _case("PFF-0001")
        return _gt(a)

    check_no_regression("baseline-dir", "candidate-dir", loader=fake_loader)
    assert calls == ["baseline-dir", "candidate-dir"]
