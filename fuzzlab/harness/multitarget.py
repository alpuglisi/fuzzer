"""Multi-target evaluation harness (Phase 10 T10.5, generalization/transfer).

Run the full toolkit against several targets — each its own base-url + ground-truth
contract — and compare the results, so we can show the toolkit **generalizes** rather
than overfitting the Puppy Fort Factory. Each target runs the ordinary `run_auto`
pipeline; the harness collects per-target scores and a transfer summary.

The network is injected via ``sender_for(spec) -> sender`` (a seam), so this is
offline-testable with fakes; the live transfer run against an external validation lab
(OWASP Juice Shop / WAVSEP, per D10) is the on-host T10.6 exit. The eventual second
target from the manifest generator (option C) plugs in here unchanged — it is just
another `TargetSpec`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from fuzzlab.harness.auto import run_auto


@dataclass
class TargetSpec:
    name: str
    base_url: str
    ground_truth: object | None = None      # a labels.contract.GroundTruth, or None
    points_source: str = "auto"
    selected_categories: list[str] | None = None
    mode: str = "automatic"


@dataclass
class TargetOutcome:
    name: str
    run_id: int
    findings: int
    report: object | None = None            # a scoring.ScoreReport, or None (unscored)

    @property
    def scored(self) -> bool:
        return self.report is not None

    def as_dict(self) -> dict:
        d = {"name": self.name, "run_id": self.run_id, "findings": self.findings,
             "scored": self.scored}
        if self.report is not None:
            d.update(self.report.as_dict())
        return d


# sender_for(spec) -> a sender the pipeline sends probes through
SenderFor = Callable[[TargetSpec], object]


def run_targets(specs: list[TargetSpec], store, sender_for: SenderFor, *,
                browser=None, scheduler=None, plugins=None) -> list[TargetOutcome]:
    """Run the pipeline against each target (one run per target) and collect outcomes."""
    outcomes: list[TargetOutcome] = []
    for spec in specs:
        host = urlparse(spec.base_url).netloc or spec.base_url
        run_id = store.start_run("multitarget", host)
        result = run_auto(base_url=spec.base_url, store=store, run_id=run_id,
                          sender=sender_for(spec), mode=spec.mode,
                          ground_truth=spec.ground_truth,
                          selected_categories=spec.selected_categories,
                          points_source=spec.points_source,
                          browser=browser, scheduler=scheduler, plugins=plugins)
        outcomes.append(TargetOutcome(name=spec.name, run_id=run_id,
                                      findings=result.findings, report=result.report))
    return outcomes


def transfer_summary(outcomes: list[TargetOutcome]) -> dict:
    """A deterministic transfer view: per-target metrics + macro averages + a verdict."""
    scored = [o for o in outcomes if o.report is not None]
    summary: dict = {
        "targets": len(outcomes),
        "per_target": [o.as_dict() for o in outcomes],
        "found_on": [o.name for o in outcomes if o.findings > 0],
    }
    if scored:
        summary["macro_precision"] = round(
            sum(o.report.precision for o in scored) / len(scored), 4)
        summary["macro_recall"] = round(
            sum(o.report.recall for o in scored) / len(scored), 4)
        # generalizes: finds real vulnerabilities (recall > 0) on >= 2 scored targets,
        # i.e. it isn't overfit to a single app.
        summary["generalizes"] = sum(1 for o in scored if o.report.recall > 0) >= 2
    return summary


def format_transfer(summary: dict) -> str:
    lines = [f"multi-target transfer over {summary['targets']} target(s)"]
    for t in summary["per_target"]:
        if t["scored"]:
            lines.append(f"  {t['name']}: tp={t['tp']} fp={t['fp']} fn={t['fn']} "
                         f"precision={t['precision']} recall={t['recall']} "
                         f"({t['findings']} finding(s))")
        else:
            lines.append(f"  {t['name']}: {t['findings']} finding(s) (unscored)")
    if "macro_recall" in summary:
        lines.append(f"  macro precision={summary['macro_precision']} "
                     f"recall={summary['macro_recall']}  "
                     f"generalizes={summary['generalizes']}")
    return "\n".join(lines)
