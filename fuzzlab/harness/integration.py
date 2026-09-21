"""Integration harness — automatic mode's assert-known-vulns run (T0.7).

Reads the confirmed findings a run wrote to the store, scores them against the
ground-truth contract, records the confusion-matrix metrics into ``run_metrics``,
and reports pass/fail. This is invoked from the launcher's *automatic* mode
(never on bring-up); the crawler/auditor/fuzzer orchestration is wired in as the
tools move onto the store (T0.8).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fuzzlab.harness.scoring import Detection, ScoreReport, score
from fuzzlab.labels import contract
from fuzzlab.labels.contract import GroundTruth


def detections_from_store(store, run_id: int) -> list[Detection]:
    """Collect confirmed findings for a run as scorable detections.

    Only the oracle writes ``finding`` rows (label=1), so this reads confirmed
    positives. Findings carry their own url/method/param (migration 2).
    """
    rows = store.conn.execute(
        "SELECT url, method, param, vuln_class FROM finding "
        "WHERE run_id=? AND label=1",
        (run_id,),
    ).fetchall()
    out = []
    for row in rows:
        if not (row["url"] and row["param"] and row["vuln_class"]):
            continue
        out.append(Detection(
            url=row["url"], method=row["method"] or "GET",
            param=row["param"], vuln_class=row["vuln_class"],
        ))
    return out


def record_metrics(store, run_id: int, report: ScoreReport) -> None:
    for key, value in report.as_dict().items():
        store.conn.execute(
            "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
            (run_id, key, float(value)),
        )
    store.conn.commit()


@dataclass
class HarnessResult:
    report: ScoreReport
    passed: bool

    def summary(self) -> str:
        d = self.report.as_dict()
        status = "PASS" if self.passed else "FAIL"
        line = (f"[{status}] TP={d['tp']} FP={d['fp']} TN={d['tn']} FN={d['fn']} "
                f"precision={d['precision']} recall={d['recall']} mcc={d['mcc']}")
        if self.report.missed:
            line += f"\n  missed: {', '.join(self.report.missed)}"
        if self.report.false_alarms:
            line += f"\n  false alarms: {', '.join(self.report.false_alarms)}"
        return line


def assert_known_vulns(store, run_id: int, ground_truth_dir: str | Path,
                       require_no_false_positives: bool = True) -> HarnessResult:
    """Score a run and decide pass/fail.

    Pass requires every known vulnerability found (no FN); by default it also
    requires no false positives on the secure controls.
    """
    gt: GroundTruth = contract.load(ground_truth_dir)
    detections = detections_from_store(store, run_id)
    report = score(detections, gt)
    record_metrics(store, run_id, report)
    passed = report.all_positives_found and (
        report.fp == 0 or not require_no_false_positives
    )
    return HarnessResult(report=report, passed=passed)
