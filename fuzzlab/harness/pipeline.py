"""Automatic-mode pipeline: compose Phase 2 into one run (T2.8 integration).

Ties the pieces together for an automatic run:
1. **dedup** injection points to one page per DOM-skeleton template cluster (T2.6),
2. **fingerprint** the target from a baseline probe and record the `target` row (T2.5),
3. **audit** — evaluate the rules-as-data engine scoped to the run's categories,
   logging every evaluation incl. negatives (T2.3 / D14 / D15 via the RunPlan),
4. **confirm** each candidate with the deterministic oracle (sole finding-writer),
5. **score** against ground truth only when the plan is scored (D15 fail-safe:
   unscored runs report findings without TP/FP/FN),
6. **record** request-efficiency metrics.

This is library-level composition (fully testable with an injected sender). The
live crawler/auditor browser-fetch edits that feed it real pages/HTML are the
on-host last mile.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

from fuzzlab.audit import InjectionPoint, evaluate
from fuzzlab.core.dedup import TemplateClusterer
from fuzzlab.core.fingerprint import fingerprint
from fuzzlab.core.runmode import RunPlan
from fuzzlab.harness import integration
from fuzzlab.harness.scoring import ScoreReport, score
from fuzzlab.oracle import Candidate, Oracle, category_to_oracle_class


@dataclass
class PipelineResult:
    plan: RunPlan
    points_audited: int
    candidates: int
    negatives: int
    findings: int
    report: ScoreReport | None = None      # None when the run is unscored (D15)
    metrics: dict = field(default_factory=dict)


def _dedup(points: list[InjectionPoint], pages_html: dict[str, str]) -> list[InjectionPoint]:
    """Keep only points on a representative page per template cluster (T2.6)."""
    clusterer = TemplateClusterer()
    keep: set[str] = set()
    seen_clusters: set[str] = set()
    for url in dict.fromkeys(p.url for p in points):     # first-seen order
        cid = clusterer.cluster_id(pages_html.get(url, ""))
        if cid not in seen_clusters:
            seen_clusters.add(cid)
            keep.add(url)
    return [p for p in points if p.url in keep]


def run_pipeline(points: list[InjectionPoint], store, run_id: int, sender,
                 plan: RunPlan, ground_truth=None,
                 pages_html: dict[str, str] | None = None, budget=None,
                 browser=None, scheduler=None) -> PipelineResult:
    if pages_html:
        points = _dedup(points, pages_html)

    # Fingerprint from a baseline probe and record the target row (T2.5).
    if points:
        probe = sender.send(points[0].url, points[0].param, "1")
        fp = fingerprint(probe.headers, probe.text)
        origin = urlparse(points[0].url)
        store.conn.execute(
            "INSERT INTO target (run_id, base_url, dbms, framework, waf, fingerprint) "
            "VALUES (?,?,?,?,?,?)",
            (run_id, f"{origin.scheme}://{origin.netloc}", fp.dbms, fp.framework,
             fp.waf, json.dumps(fp.as_dict())),
        )
        store.conn.commit()

    # Audit: rules-as-data, scoped to the plan's categories (T2.3 / D14 / D15).
    counts = evaluate(points, store, run_id, categories=plan.categories)

    # Confirm each candidate with the oracle (sole finding-writer).
    oracle = Oracle(store=store, run_id=run_id, browser=browser, scheduler=scheduler)
    rows = store.conn.execute(
        "SELECT evidence FROM candidate WHERE run_id=?", (run_id,)).fetchall()
    for row in rows:
        ev = json.loads(row["evidence"])
        category = ev.get("category", "")
        if category_to_oracle_class(category) is None:
            continue                                     # no confirmer for this category yet
        oracle.confirm(Candidate(url=ev["url"], param=ev["param"],
                                 method=ev.get("method", "GET"),
                                 location=ev.get("location", "query"),
                                 category=category,
                                 store_url=ev.get("store_url"),
                                 store_param=ev.get("store_param")), sender)

    findings = store.conn.execute(
        "SELECT COUNT(*) c FROM finding WHERE run_id=?", (run_id,)).fetchone()["c"]

    report: ScoreReport | None = None
    if plan.scored and ground_truth is not None:
        report = score(integration.detections_from_store(store, run_id), ground_truth)
        integration.record_metrics(store, run_id, report)

    # Negative training examples come from two places: rules that evaluated but did
    # not fire, AND candidates the oracle nominated but did not confirm (fail-closed).
    rejected = max(0, counts["candidate"] - findings)
    negatives = counts["negative"] + rejected
    metrics = {"candidates": counts["candidate"], "negatives": negatives,
               "rule_negatives": counts["negative"], "oracle_rejected": rejected,
               "findings": findings, "scored": plan.scored}
    if budget is not None:
        used = budget.used()
        metrics["requests"] = used
        metrics["requests_per_finding"] = round(used / findings, 3) if findings else None
    for key, value in metrics.items():
        if isinstance(value, (int, float)):
            store.conn.execute(
                "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                (run_id, f"pipeline_{key}", float(value)))
    store.conn.commit()

    return PipelineResult(plan=plan, points_audited=len(points),
                          candidates=counts["candidate"], negatives=negatives,
                          findings=findings, report=report, metrics=metrics)
