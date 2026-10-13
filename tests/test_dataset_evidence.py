"""Unreadable candidate evidence is quarantined and counted, never fabricated
(BUG-0107, FR-ML-24, PA-0108).

`"[]"` evidence crashed `build_dataset` (``'list' object has no attribute 'get'``) and
`"{not json"` became a fabricated negative row on endpoint ``/``.
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.core.evidence import display_evidence, parse_evidence
from fuzzlab.core.store import Store
from fuzzlab.ml.dataset import (DatasetEvidenceError, build_dataset, candidate_keys,
                                quarantine_refusal)
from fuzzlab.ml.train import train_and_score
from tests.test_ml_holdout_calibration import _seed
from tests.test_ml_train import _finding

BAD = ["[]", '"x"', "null", "{not json", "", json.dumps({"url": 1, "param": "q",
                                                         "category": "xss"}),
       json.dumps({"url": "/a", "param": "q", "category": "xss", "method": 7})]


@pytest.mark.parametrize("raw", BAD)
def test_unreadable_evidence_is_none_for_ml_and_empty_for_display(raw):
    assert parse_evidence(raw) is None
    shown = display_evidence(raw)                       # never raises, always a dict
    assert isinstance(shown, dict)
    assert shown == {} or raw.startswith("{")


def _bad_row(store, run_id, raw, status="rejected"):
    store.conn.execute("INSERT INTO candidate (run_id, rule, evidence, oracle_status) "
                       "VALUES (?,?,?,?)", (run_id, "xss", raw, status))
    store.conn.commit()


@pytest.mark.parametrize("raw", BAD)
def test_a_bad_row_is_quarantined_never_fabricated(tmp_path, raw):
    with Store(tmp_path / "s.db") as store:
        r = store.start_run("auto", "x")
        _bad_row(store, r, raw)
        ds = build_dataset(store, r, include_unlabelled=True)
        assert len(ds) == 0 and len(ds.quarantined) == 1 and ds.scope_total == 1
        assert candidate_keys(store, ds.quarantined)[0][0] == "\0quarantined"


def test_a_few_quarantined_rows_are_skipped_counted_and_recorded(tmp_path):
    from fuzzlab.ml.train import latest_classifier
    with Store(tmp_path / "s.db") as store:
        r = _seed(store)                                  # 80 candidates
        _bad_row(store, r, "[]")
        res = train_and_score(store, r, model_kind="logistic")
        assert res["quarantined_rows"] == 1
        assert latest_classifier(store, r).calibration["quarantined_rows"] == 1
        assert store.conn.execute("SELECT value FROM run_metrics WHERE run_id=? AND "
                                  "key='ml_quarantined_rows'", (r,)).fetchone()[0] == 1


def test_too_many_quarantined_rows_refuse(tmp_path):
    with Store(tmp_path / "s.db") as store:
        r = _seed(store, n=10)                            # 20 candidates
        for _ in range(3):
            _bad_row(store, r, "{not json")
        with pytest.raises(DatasetEvidenceError, match="unreadable evidence"):
            train_and_score(store, r, model_kind="logistic")


def test_a_possibly_lost_label_refuses(tmp_path):
    """A run with a quarantined row and a finding no readable candidate matches."""
    with Store(tmp_path / "s.db") as store:
        r = _seed(store)
        _bad_row(store, r, "[]")
        _finding(store, r, "/orphan.php", "id", "sqli")
        assert quarantine_refusal(build_dataset(store, r)) is not None
        with pytest.raises(DatasetEvidenceError, match="label may be lost"):
            train_and_score(store, r, model_kind="logistic")


def test_an_orphan_finding_without_quarantine_never_refuses(tmp_path):
    """S9: findings with no candidate are legitimate (blind SQLi, greybox, manual)."""
    with Store(tmp_path / "s.db") as store:
        r = _seed(store)
        _finding(store, r, "/orphan.php", "id", "sqli")
        assert quarantine_refusal(build_dataset(store, r)) is None
        assert train_and_score(store, r, model_kind="logistic")["rows"] > 0


def test_a_clean_store_never_trips_the_check(tmp_path, monkeypatch, capsys):
    """A's invariant: stores the real pipeline writes (the golden `fuzzlab auto`
    scenarios and an offline multi-target run) have no quarantined row and no refusal."""
    from fuzzlab.harness.multitarget import TargetSpec, run_targets
    from fuzzlab.labels import contract
    from tests.test_auto_plugins import CASES, _run
    from tests.test_multitarget import GT_DIR, AutoSender
    for name in sorted(CASES):
        d = tmp_path / name
        d.mkdir()
        _run(d, monkeypatch, capsys, *CASES[name],
             earlier=name != "budget_fallback_nolabels")
        with Store(d / "s.db") as store:
            ds = build_dataset(store, None, include_unlabelled=True)
            assert ds.quarantined == [] and quarantine_refusal(ds) is None, name
    gt = contract.load(GT_DIR)
    specs = [TargetSpec(n, u, ground_truth=gt, points_source="ground-truth")
             for n, u in (("a", "http://127.0.0.1:8080"), ("b", "http://127.0.0.1:9090"))]
    with Store(tmp_path / "m.db") as store:
        run_targets(specs, store, sender_for=lambda spec: AutoSender())
        ds = build_dataset(store, None, include_unlabelled=True)
        assert ds.scope_total > 0 and ds.quarantined == []
        assert quarantine_refusal(ds) is None


def test_the_cli_prints_the_quarantine_count(capsys):
    from fuzzlab.harness.auto_cli import _print_ml_extras
    _print_ml_extras({"quarantined_rows": 2}, 1)
    assert "2 candidate(s) with unreadable evidence skipped" in capsys.readouterr().out
