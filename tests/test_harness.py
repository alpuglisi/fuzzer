"""Tests for the integration harness: scoring math and store integration (T0.7)."""

from fuzzlab.core.store import Store
from fuzzlab.harness import integration
from fuzzlab.harness.scoring import Detection, score
from fuzzlab.labels import contract

GT_DIR = "lab/ground-truth"


def _gt():
    return contract.load(GT_DIR)


def test_perfect_run_passes():
    gt = _gt()
    detections = [
        Detection(c.url, c.method, c.param, c.vuln_class) for c in gt.positives()
    ]
    report = score(detections, gt)
    assert report.fn == 0 and report.fp == 0
    assert report.tp == len(gt.positives())
    assert report.tn == len(gt.negatives())
    assert report.recall == 1.0 and report.precision == 1.0
    assert report.mcc == 1.0
    assert report.all_positives_found


def test_missed_and_false_alarm():
    gt = _gt()
    positives = gt.positives()
    # Miss one positive; raise a false alarm on a known-secure parameter.
    detections = [Detection(c.url, c.method, c.param, c.vuln_class)
                  for c in positives[1:]]
    neg = gt.negatives()[0]
    detections.append(Detection(neg.url, neg.method, neg.param, "sqli"))
    report = score(detections, gt)
    assert report.fn == 1
    assert report.fp == 1
    assert positives[0].case_id in report.missed
    assert 0.0 < report.mcc < 1.0


def test_wrong_class_on_right_param_is_false_positive():
    gt = _gt()
    # PFF-0003 is XSS-reflected on search.php?q; claim SQLi-only detection there
    # plus the true SQLi. The XSS case is still missed, and no spurious credit.
    detections = [Detection("/search.php", "GET", "q", "sqli")]
    report = score(detections, gt)
    # search.php?q sqli is a real positive -> TP; the xss-reflected case -> FN.
    assert any(cid == "PFF-0002" for cid in report.matched)
    assert "PFF-0003" in report.missed


def test_detection_matching_no_case_counts_as_fp():
    gt = _gt()
    detections = [Detection("/nonexistent.php", "GET", "zzz", "sqli")]
    report = score(detections, gt)
    assert report.fp >= 1


def test_score_from_store_and_metrics(tmp_path):
    gt = _gt()
    with Store(tmp_path / "s.db") as store:
        assert store.schema_version() == 2  # migration 2 applied
        run_id = store.start_run("harness-test", "h")
        # Oracle writes confirmed findings for every positive case.
        for c in gt.positives():
            store.conn.execute(
                "INSERT INTO finding (run_id, case_id, vuln_class, label, url, method, param) "
                "VALUES (?,?,?,?,?,?,?)",
                (run_id, c.case_id, c.vuln_class, 1, c.url, c.method, c.param),
            )
        store.conn.commit()
        result = integration.assert_known_vulns(store, run_id, GT_DIR)
        assert result.passed
        metrics = dict(store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,)).fetchall())
        assert metrics["tp"] == len(gt.positives())
        assert metrics["fn"] == 0
