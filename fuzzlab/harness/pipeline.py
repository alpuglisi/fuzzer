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
from fuzzlab.core import trace
from fuzzlab.core.dedup import TemplateClusterer
from fuzzlab.core.fingerprint import fingerprint
from fuzzlab.core.oracle_status import (CHECKED, INCONCLUSIVE,  # migration 13
                                         NO_CONFIRMER, PENDING, SKIPPED_BUDGET)
from fuzzlab.core.runmode import RunPlan
from fuzzlab.harness import integration
from fuzzlab.harness.scoring import ScoreReport, score
from fuzzlab.oracle import Candidate, Oracle, category_to_oracle_class
from fuzzlab.oracle.oracle import UNPLACEABLE
from fuzzlab.oracle.probe import HeaderPointsStopped, ProbeUnobserved


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
    # keys a confirmer could not decide within its cap (FR-FUZZ-45): url, param,
    # location, mechanism, families not started -- no values; never in the store row
    inconclusive: list = field(default_factory=list)


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


def _candidate_of(ev: dict) -> Candidate:
    # `sink_context` is omitted deliberately (BUG-0083, item 11): the auditor's value is a
    # coarse ground-truth label (`html`, `sql`, …), no confirmation strategy reads it
    # (an AST guard enforces that), and leaving it out keeps one confirmation per
    # `_confirmation_key` sound (BUG-0072). The bandit context facet is the location.
    return Candidate(url=ev["url"], param=ev["param"], method=ev.get("method", "GET"),
                     location=ev.get("location", "query"), category=ev.get("category", ""),
                     store_url=ev.get("store_url"), store_param=ev.get("store_param"),
                     store_method=ev.get("store_method", "POST"),
                     store_location=ev.get("store_location", "body"),
                     store_entries=(tuple(tuple(e) for e in ev["store_entries"])
                                    if ev.get("store_entries") else None),
                     content_type=ev.get("body_content_type"),
                     base_entries=(tuple(tuple(e) for e in ev["entries"])
                                   if ev.get("entries") else None),
                     base_value=ev.get("base_value"),
                     redirect_seed=ev.get("redirect_seed"))


def _origin_of(url: str) -> str | None:
    from fuzzlab.core.urls import canonical_origin
    return canonical_origin(url)


def _fingerprint_point(points: list[InjectionPoint]) -> InjectionPoint | None:
    """The point the baseline probe goes through: the first query point, else the
    first form-encoded body point; never a header, fragment or raw-body point."""
    for location in ("query", "body"):
        for p in points:
            if p.location == location and not p.body_content_type:
                return p
    return None


def _baseline(sender, point: InjectionPoint):
    """Send ``1`` at ``point``'s own location and method, with its siblings."""
    from fuzzlab.core.forms import FormEntries
    if point.base_entries:
        entries = FormEntries(tuple(e) for e in point.base_entries).replace(point.param, "1")
        return sender.send(point.url, point.param, "1", method=point.method,
                           location=point.location, entries=entries)
    if point.method == "GET" and point.location == "query":
        return sender.send(point.url, point.param, "1")
    return sender.send(point.url, point.param, "1", method=point.method,
                       location=point.location)


def _header_stop_reason(sender) -> str | None:
    """A breaker reason a sender (or the sender it wraps) recorded, if any."""
    seen = 0
    while sender is not None and seen < 10:
        reason = getattr(sender, "header_stop_reason", None)
        if isinstance(reason, str) and reason:
            return reason
        sender, seen = getattr(sender, "_inner", None), seen + 1
    return None


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
                 prioritizer=None, peer=None) -> PipelineResult:
    """``budget`` counts requests (``used()``); ``confirm_budget`` caps how many distinct
    candidates are sent to the oracle, in ``prioritizer(store, run_id, ids)`` order (an
    object with ``.order`` or ``None`` = no usable model → confirm everything)."""
    if confirm_budget is not None and confirm_budget < 1:
        raise ValueError(f"confirm_budget must be >= 1, got {confirm_budget}")
    if pages_html:
        points = _dedup(points, pages_html)

    # Fingerprint from a baseline probe and record the target row (T2.5). The probe
    # goes where its point says, siblings included (BUG-0115: it used to send any
    # point's parameter as a GET query); never through a header point.
    fp_point = _fingerprint_point(points)
    probe = None
    if fp_point is not None:
        try:
            with trace.role("baseline"):      # FR-FUZZ-60: the fingerprint baseline
                probe = _baseline(sender, fp_point)
        except ProbeUnobserved:
            # no response to the baseline (BUG-0147): an unprobed target row, as for
            # header points only; the candidates still run
            pass
    if probe is not None:
        fp = fingerprint(probe.headers, probe.text)
        origin = urlparse(fp_point.url)
        store.conn.execute(
            "INSERT INTO target (run_id, base_url, dbms, framework, waf, fingerprint) "
            "VALUES (?,?,?,?,?,?)",
            (run_id, f"{origin.scheme}://{origin.netloc}", fp.dbms, fp.framework,
             fp.waf, json.dumps(fp.as_dict())),
        )
        store.conn.commit()
    elif points:
        # no point a baseline may go through (header points only), or no response to it:
        # still one target row, unprobed -- ML's same-target training and holdout
        # origins key on it (BUG-0104)
        origin = urlparse((fp_point or points[0]).url)
        store.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)",
                           (run_id, f"{origin.scheme}://{origin.netloc}"))
        store.conn.commit()

    # Audit: rules-as-data, scoped to the plan's categories (T2.3 / D14 / D15).
    counts = evaluate(points, store, run_id, categories=plan.categories, plugins=plugins)

    # Confirm each candidate with the oracle (sole finding-writer).
    oracle = Oracle(store=store, run_id=run_id, browser=browser, oob=oob,
                    coverage=coverage, dbfault=dbfault, scheduler=scheduler,
                    plugins=plugins, peer=peer)
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
                               budget_model_sha256=getattr(plan_order, "model_sha256", None),
                               # the candidate feature version its model read (BUG-0069)
                               budget_feature_version=getattr(plan_order, "feature_version",
                                                              None))
            budget_plugin = getattr(prioritizer, "plugin_name", None)
            if budget_plugin is not None:
                budget_info["budget_plugin"] = budget_plugin
            if getattr(plan_order, "error", None) is not None:
                # the prioritizer failed: the cap still holds, spent in row order
                budget_info.update(confirm_budget_error=1, budget_error=plan_order.error)

    # Crash safety (BUG-0071): before any probe, every candidate gets a status that is
    # never read as a label — `no_confirmer` (already final) or `pending` (unlabelled
    # until the oracle reaches it) — so a crash mid-loop never leaves a NULL, which the
    # ML dataset would read as a confirmed negative.
    store.conn.executemany(
        "UPDATE candidate SET oracle_status=? WHERE id=?",
        [(status.get(row["id"], PENDING), row["id"]) for row in rows])
    store.conn.commit()

    confirmed_keys: set[tuple] = set()
    inconclusive_keys: set[tuple] = set()
    inconclusive_detail: list[dict] = []
    inconclusive_mechanism: dict[tuple, str] = {}        # key -> the undecided mechanism
    # Forms phase 2 (FR-FUZZ-43): once a sender stops header probing (the main session
    # was logged out right after one), every remaining header key is left unconfirmed:
    # its rows keep `pending` (unlabelled) and the reason goes to the metrics.
    stopped_keys: set[tuple] = set()
    breaker: list[str] = []

    tests = {"n": 0}

    def _confirm(key: tuple, ev: dict) -> None:
        if breaker and ev.get("location") == "header":
            stopped_keys.add(key)
            return
        candidate = _candidate_of(ev)
        # FR-FUZZ-60: one test per confirmation key; its sends, strategy outcomes and
        # finding carry its id (explicit correlation, never a time window)
        tests["n"] += 1
        test_id = f"t{tests['n']}"
        trace.emit("test.start", {
            "test": test_id, "url": trace.safe_ref(candidate.url),
            "origin": _origin_of(candidate.url), "method": candidate.method,
            "param": candidate.param, "location": candidate.location,
            "category": candidate.category, "rule": ev.get("rule_id"),
            "candidates": [cid for cid, _ev in keyed.get(key, [])]},
            key=f"test.start:{test_id}", scope=f"test:{test_id}")
        outcome, mechanism = "error", None
        try:
            with trace.test_scope(test_id):
                verdict, unsure = oracle.confirm_outcome(candidate, sender)
            outcome = ("confirmed" if verdict is not None else
                       "inconclusive" if unsure is not None else "not_confirmed")
            mechanism = (verdict or unsure).mechanism if (verdict or unsure) else None
        except HeaderPointsStopped as exc:
            outcome = "stopped"
            breaker.append(str(exc))
            stopped_keys.add(key)
            return
        finally:
            trace.emit("test.end", {"test": test_id, "outcome": outcome,
                                    "mechanism": mechanism},
                       key=f"test.end:{test_id}", scope=f"test:{test_id}")
        if verdict is not None:
            confirmed_keys.add(key)
        elif unsure is not None:                         # FR-FUZZ-45: never a negative
            inconclusive_keys.add(key)
            inconclusive_mechanism[key] = unsure.mechanism
            item = {"url": candidate.url, "param": candidate.param,
                    "location": candidate.location, "mechanism": unsure.mechanism,
                    "families_not_started": list(
                        unsure.evidence.get("families_not_started", []))}
            if unsure.mechanism == UNPLACEABLE:          # FR-FUZZ-47: why, no values
                item["reason"] = str(unsure.evidence.get("reason", ""))[:200]
            elif "not_observed" in unsure.evidence:      # BUG-0137: M6 saw no page
                item["reason"] = str(unsure.evidence["not_observed"])[:200]
            elif "unobserved" in unsure.evidence:        # BUG-0147: no response
                item["reason"] = str(unsure.evidence["unobserved"])[:200]
            inconclusive_detail.append(item)

    def _checked(key) -> str:
        return INCONCLUSIVE if key in inconclusive_keys else CHECKED

    try:
        if selected is None:
            # Unbudgeted (or fallback): one confirmation per key, on its first row, in
            # the original row order (order matters to a bandit scheduler). Later rows
            # of a key send the identical Candidate, so they are marked checked without
            # another probe (BUG-0072: they used to re-confirm and duplicate findings).
            confirmed_or_tried: set[tuple] = set()
            for key, cid, ev in confirmable:
                if key not in confirmed_or_tried:
                    confirmed_or_tried.add(key)
                    _confirm(key, ev)
                if key not in stopped_keys:
                    status[cid] = _checked(key)
        else:
            chosen = set(selected)
            for key in selected:                             # one confirmation per key
                _confirm(key, keyed[key][0][1])
                if key not in stopped_keys:
                    for cid, _ev in keyed[key]:
                        status[cid] = _checked(key)
            for key, members in keyed.items():
                if key in stopped_keys:
                    continue
                for cid, _ev in members:
                    status[cid] = _checked(key) if key in chosen else SKIPPED_BUDGET
    finally:
        # the statuses gathered so far, even when the loop raised (rows never reached
        # keep `pending`)
        store.conn.executemany("UPDATE candidate SET oracle_status=? WHERE id=?",
                               [(st, cid) for cid, st in status.items()])
        store.conn.commit()
    checked_keys = (len(keyed) if selected is None else len(selected)) - len(stopped_keys)

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
    rejected = checked_keys - len(confirmed_keys) - len(inconclusive_keys)
    negatives = counts["negative"] + rejected
    statuses = list(status.values())
    undecided: dict[str, int] = {}                       # mechanism -> inconclusive rows
    for key, members in keyed.items():
        if key in inconclusive_mechanism:
            n = sum(1 for cid, _ev in members if status.get(cid) == INCONCLUSIVE)
            if n:
                mech = inconclusive_mechanism[key]
                undecided[mech] = undecided.get(mech, 0) + n
    metrics = {"candidates": counts["candidate"], "negatives": negatives,
               "rule_negatives": counts["negative"], "oracle_rejected": rejected,
               "oracle_checked": statuses.count(CHECKED),
               "oracle_skipped": statuses.count(SKIPPED_BUDGET),
               "oracle_no_confirmer": statuses.count(NO_CONFIRMER),
               "oracle_inconclusive": statuses.count(INCONCLUSIVE),
               # of those, rows no mechanism could place (FR-FUZZ-47); the rest were
               # stopped by a cost cap (FR-FUZZ-45) or got no response (FR-FUZZ-50)
               "oracle_unplaceable": undecided.get(UNPLACEABLE, 0),
               "oracle_checked_keys": checked_keys, "confirmable_keys": len(keyed),
               "findings": findings, "scored": plan.scored, **budget_info}
    for mech, n in sorted(undecided.items()):            # which mechanism (run page)
        metrics[f"oracle_inconclusive_{mech}"] = n
    if counts.get("invalid_plugin_rules"):
        metrics["invalid_plugin_rules"] = counts["invalid_plugin_rules"]
    # PRG observation (FR-FUZZ-49): reported only when it did something, so a run with
    # no PRG redirect keeps exactly its earlier metrics (its follow-ups are already in
    # `requests`)
    metrics.update({k: n for k, n in oracle.prg_counts.items() if n})
    if not breaker:
        # a trip on the last header probe (or the main send after it) raises nothing:
        # read the reason the sender recorded (reviewer A)
        late = _header_stop_reason(sender)
        if late:
            metrics["header_breaker"] = late
    if breaker:
        # one entry per header point left unconfirmed, for `skipped_points`
        metrics["header_breaker"] = breaker[0]
        metrics["header_breaker_skipped"] = sorted(
            {(urlparse(k[0]).path or "/", k[2], k[1], breaker[0]) for k in stopped_keys})
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
                          findings=findings, report=report, metrics=metrics,
                          inconclusive=inconclusive_detail)
