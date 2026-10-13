"""Automatic-mode pipeline: compose Phase 2 into one run (T2.8 integration).

Ties the pieces together for an automatic run:
1. **dedup** injection points to one page per DOM-skeleton template cluster (T2.6),
2. **fingerprint** the target from a baseline probe and record the `target` row (T2.5),
3. **audit** — evaluate the rules-as-data engine scoped to the run's categories,
   logging every evaluation incl. negatives (T2.3 / D14 / D15 via the RunPlan),
4. **confirm** each candidate with the deterministic oracle (sole finding-writer) —
   or, with a ``confirm_budget``, only the first N distinct candidates in the order an
   injected ``prioritizer`` gives (active learning, CC-FUZZ-0048); every candidate's
   ``oracle_status`` records whether the oracle looked at it,
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
    plugin_outcomes: list = field(default_factory=list)   # `after_run` results (FR-PLUG-7)


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


# `candidate.oracle_status` values (migration 13).
CHECKED, SKIPPED_BUDGET, NO_CONFIRMER = "checked", "skipped_budget", "no_confirmer"


def _candidate_of(ev: dict) -> Candidate:
    return Candidate(url=ev["url"], param=ev["param"], method=ev.get("method", "GET"),
                     location=ev.get("location", "query"), category=ev.get("category", ""),
                     store_url=ev.get("store_url"), store_param=ev.get("store_param"),
                     content_type=ev.get("body_content_type"))


def _confirmation_key(ev: dict) -> tuple:
    """Rows that would send the oracle the identical confirmation (several rules firing
    on one point) share one key, one budget slot and one status."""
    return (ev.get("url"), ev.get("param"), ev.get("method", "GET"),
            ev.get("location", "query"), ev.get("category", ""))


def run_pipeline(points: list[InjectionPoint], store, run_id: int, sender,
                 plan: RunPlan, ground_truth=None,
                 pages_html: dict[str, str] | None = None, budget=None,
                 browser=None, oob=None, coverage=None, dbfault=None,
                 scheduler=None, plugins=None, confirm_budget: int | None = None,
                 prioritizer=None) -> PipelineResult:
    """``budget`` counts requests (``used()``); ``confirm_budget`` caps how many distinct
    candidates are sent to the oracle, in ``prioritizer(store, run_id, ids)`` order (an
    object with ``.order`` or ``None`` = no usable model → confirm everything)."""
    if confirm_budget is not None and confirm_budget < 1:
        raise ValueError(f"confirm_budget must be >= 1, got {confirm_budget}")
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
    counts = evaluate(points, store, run_id, categories=plan.categories, plugins=plugins)

    # Confirm each candidate with the oracle (sole finding-writer).
    oracle = Oracle(store=store, run_id=run_id, browser=browser, oob=oob,
                    coverage=coverage, dbfault=dbfault, scheduler=scheduler,
                    plugins=plugins)
    rows = store.conn.execute(
        "SELECT id, evidence FROM candidate WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
    keyed: dict[tuple, list[tuple[int, dict]]] = {}      # confirmable key -> its rows
    confirmable: list[tuple[tuple, int, dict]] = []      # (key, id, evidence), row order
    status: dict[int, str] = {}
    for row in rows:
        ev = json.loads(row["evidence"])
        if category_to_oracle_class(ev.get("category", "")) is None:
            status[row["id"]] = NO_CONFIRMER             # no confirmer for this category yet
            continue
        key = _confirmation_key(ev)
        keyed.setdefault(key, []).append((row["id"], ev))
        confirmable.append((key, row["id"], ev))

    budget_info: dict = {}
    selected: list[tuple] | None = None                  # None = confirm every row
    if confirm_budget is not None:
        first_id = {key: members[0][0] for key, members in keyed.items()}
        by_id = {cid: key for key, cid in first_id.items()}
        plan_order = prioritizer(store, run_id, list(first_id.values())) \
            if prioritizer is not None else None
        budget_info = {"confirm_budget": confirm_budget,
                       "confirm_budget_fallback": 1 if plan_order is None else 0}
        if plan_order is not None:
            ordered = list(dict.fromkeys(by_id[cid] for cid in plan_order.order
                                         if cid in by_id))
            listed = set(ordered)
            ordered += [k for k in keyed if k not in listed]   # never drop a key
            selected = ordered[:confirm_budget]
            budget_info.update(budget_method=plan_order.method,
                               budget_training_rows=plan_order.training_rows,
                               budget_training_positives=plan_order.training_positives,
                               budget_seed=getattr(plan_order, "seed", 0),
                               budget_model_sha256=getattr(plan_order, "model_sha256", None))
            budget_plugin = getattr(prioritizer, "plugin_name", None)
            if budget_plugin is not None:
                budget_info["budget_plugin"] = budget_plugin
            if getattr(plan_order, "error", None) is not None:
                # the prioritizer failed: the cap still holds, spent in row order
                budget_info.update(confirm_budget_error=1, budget_error=plan_order.error)

    confirmed_keys: set[tuple] = set()
    if selected is None:
        # Unbudgeted (or fallback): every row in its original order, exactly as before
        # (duplicates included) — order matters to a bandit scheduler.
        for key, cid, ev in confirmable:
            if oracle.confirm(_candidate_of(ev), sender) is not None:
                confirmed_keys.add(key)
            status[cid] = CHECKED
    else:
        chosen = set(selected)
        for key in selected:                             # one confirmation per key
            if oracle.confirm(_candidate_of(keyed[key][0][1]), sender) is not None:
                confirmed_keys.add(key)
        for key, members in keyed.items():
            for cid, _ev in members:
                status[cid] = CHECKED if key in chosen else SKIPPED_BUDGET
    store.conn.executemany("UPDATE candidate SET oracle_status=? WHERE id=?",
                           [(st, cid) for cid, st in status.items()])
    store.conn.commit()
    checked_keys = len(keyed) if selected is None else len(selected)

    findings = store.conn.execute(
        "SELECT COUNT(*) c FROM finding WHERE run_id=?", (run_id,)).fetchone()["c"]

    report: ScoreReport | None = None
    if plan.scored and ground_truth is not None:
        report = score(integration.detections_from_store(store, run_id), ground_truth)
        integration.record_metrics(store, run_id, report)

    # Negative training examples come from two places: rules that evaluated but did
    # not fire, AND candidates the oracle checked but did not confirm (fail-closed).
    # Counted per confirmation key; candidates the oracle never looked at (skipped by
    # the budget, or with no confirmer) are not rejections.
    rejected = checked_keys - len(confirmed_keys)
    negatives = counts["negative"] + rejected
    statuses = list(status.values())
    metrics = {"candidates": counts["candidate"], "negatives": negatives,
               "rule_negatives": counts["negative"], "oracle_rejected": rejected,
               "oracle_checked": statuses.count(CHECKED),
               "oracle_skipped": statuses.count(SKIPPED_BUDGET),
               "oracle_no_confirmer": statuses.count(NO_CONFIRMER),
               "oracle_checked_keys": checked_keys, "confirmable_keys": len(keyed),
               "findings": findings, "scored": plan.scored, **budget_info}
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
