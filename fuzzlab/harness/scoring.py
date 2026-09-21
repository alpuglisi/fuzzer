"""Score a tool run against the ground-truth contract.

Given the set of vulnerabilities a run *detected* and the ground truth it should
have found, compute the confusion matrix (TP/FP/TN/FN) and the metrics the
project reports (precision, recall, F1, and Matthews correlation — MCC — which
stays honest under class imbalance, per D10).

Matching is by case key ``(url, method, param, vuln_class)`` so a detection is
credited only when it names the right class on the right parameter — flagging
SQLi on an XSS-only parameter is a false positive, not a hit.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from fuzzlab.labels.contract import GroundTruth


@dataclass(frozen=True)
class Detection:
    url: str
    method: str
    param: str
    vuln_class: str

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.url, self.method, self.param, self.vuln_class)


@dataclass
class ScoreReport:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    matched: list[str] = None          # case_ids correctly detected (TP)
    missed: list[str] = None           # case_ids missed (FN)
    false_alarms: list[str] = None     # detection keys with no positive case (FP)

    def __post_init__(self):
        self.matched = self.matched or []
        self.missed = self.missed or []
        self.false_alarms = self.false_alarms or []

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def mcc(self) -> float:
        tp, tn, fp, fn = self.tp, self.tn, self.fp, self.fn
        denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        return (tp * tn - fp * fn) / denom if denom else 0.0

    @property
    def all_positives_found(self) -> bool:
        return self.fn == 0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4), "recall": round(self.recall, 4),
            "f1": round(self.f1, 4), "mcc": round(self.mcc, 4),
        }


def score(detections: list[Detection], ground_truth: GroundTruth) -> ScoreReport:
    """Confusion matrix of ``detections`` against the ground-truth cases.

    Each ground-truth case is one unit of scoring:
    - positive case detected      -> TP
    - positive case not detected  -> FN
    - negative case detected      -> FP (a false alarm on a safe parameter)
    - negative case not detected  -> TN
    A detection that matches no case at all is also an FP.
    """
    detected_keys = {d.key for d in detections}
    report = ScoreReport()
    case_keys = set()

    for case in ground_truth.cases:
        case_keys.add(case.key)
        hit = case.key in detected_keys
        if case.expected_vulnerable:
            if hit:
                report.tp += 1
                report.matched.append(case.case_id)
            else:
                report.fn += 1
                report.missed.append(case.case_id)
        else:
            if hit:
                report.fp += 1
                report.false_alarms.append(case.case_id)
            else:
                report.tn += 1

    # Detections that correspond to no known case are also false alarms.
    for det in detections:
        if det.key not in case_keys:
            report.fp += 1
            report.false_alarms.append(f"{det.url}:{det.param}:{det.vuln_class}")

    return report
