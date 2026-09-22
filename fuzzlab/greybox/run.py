"""Live grey-box run: send correlated probes, read the side channel, shape reward.

This is the on-host "run" last mile for Phase 3 (T3.2–T3.7). The seam layer
(coverage frontier, shaped reward, DB-fault signal, deterministic reset, M10 decision)
is built and unit-tested with fakes elsewhere in this package; here we drive it with
the **live** sources against the instrumented lab:

1. For each injection point, send a small set of probes (a benign baseline plus SQLi /
   XSS payloads). Every request carries a fresh ``X-Fzl-Cov`` correlation id.
2. Read that request's executed application lines (`CoverageSource`) and DB-fault marker
   (`DbFaultSource`) back from the shim's per-request side channel, keyed by the id.
3. Fold them into a shaped, multi-tier ``attempt.reward`` (screening + coverage novelty +
   DB fault) and persist the grey-box columns on the attempt row.
4. Between stateful iterations, restore the DB to a baseline (`LabControl`) so novelty
   accounting and stored-payload cases stay reproducible.

The oracle remains the sole finding-writer; M10 here is **advisory** — we count where the
grey-box evidence *would* confirm (sink file executed, plus a DB fault for SQLi), record
it in ``run_metrics``, and leave folding it into ``Oracle.confirm`` as the deeper T3.6
step. Lab-only: the caller must pass ``--authorized`` at the CLI.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence
from urllib.parse import urlparse

from fuzzlab.core.store import MetricLogger
from fuzzlab.greybox.confirm import greybox_confirms
from fuzzlab.greybox.coverage import (CoverageFrontier, app_lines, encode_coverage)
from fuzzlab.greybox.recorder import record_attempt_signals
from fuzzlab.greybox.reward import GreyboxSignal, shaped_reward
from fuzzlab.mutation.catalog import record_variant
from fuzzlab.mutation.operators import default_operators
from fuzzlab.mutation.semantics import SemanticsValidator
from fuzzlab.oracle.probe import Probe

DEFAULT_APP_ROOT = "/var/www/html"
_SQL_ERR = re.compile(
    r"SQL syntax|mysqli|SQLSTATE|you have an error|unclosed quotation|"
    r"mysqli_sql_exception|Warning.*mysql", re.I)

# ProbeSpec.kind ("sqli"/"xss") -> the mutation engine's own class taxonomy
# ("sql-injection"/"xss", per fuzzlab/mutation/operators.py and DEFAULT_BASES).
_MUTATION_CLASS: dict[str, str] = {"sqli": "sql-injection", "xss": "xss"}

# Operators skipped when generating *live-sendable* variants: url-encode pre-encodes the
# payload as a Python string, but the probe transport (requests' `params=`/`data=`) then
# percent-encodes it again, so the app would only ever see the once-decoded, still-encoded
# text -- not a useful WAF-evasion probe here. mutate-run's live search (T8.4/T8.5) still
# uses it against a raw HTTP layer; this harness's correlated sender does not expose that.
_MUTATION_SKIP_OPS: frozenset[str] = frozenset({"url-encode"})


@dataclass(frozen=True)
class GreyboxPoint:
    """An injection point to probe, with an optional class hint for M10."""
    url: str
    param: str
    method: str = "GET"
    location: str = "query"
    vuln_class: str | None = None


@dataclass(frozen=True)
class ProbeSpec:
    """One payload to send at a point.

    ``base``/``operators`` are set only on mutation-engine-derived variants (T8.5
    wiring, `mutation_variant_probes`) -- they carry the provenance needed to write the
    variant back to `payload_variant` (`fuzzlab.mutation.catalog.record_variant`) if it
    turns out to be an "accepted" one (screening hit or new coverage) once probed.
    """
    family: str
    value: str
    kind: str                        # 'baseline' | 'sqli' | 'xss'
    base: str | None = None          # mutation variants only: the payload it was derived from
    operators: tuple[str, ...] = ()  # mutation variants only: the operator chain applied


# A compact, deterministic probe set: a benign baseline (normal code path), an
# error-based SQLi probe (provokes the DB syntax error branch -> db_fault + new code),
# a boolean SQLi probe, and a reflected-XSS canary. Small so the request cost stays low.
DEFAULT_PROBES: tuple[ProbeSpec, ...] = (
    ProbeSpec("baseline", "1", "baseline"),
    ProbeSpec("sqli-error", "'", "sqli"),
    ProbeSpec("sqli-boolean", "1' OR '1'='1' -- -", "sqli"),
    ProbeSpec("xss-reflect", "<fzlxss>", "xss"),
)

# Correlating sender contract (duck-typed):
#   send_correlated(url, param, value, *, method, location) -> (Probe, correlation_id)


class RequestsCorrelatingSender:
    """Live sender: plain ``requests`` with a fresh ``X-Fzl-Cov`` id per request.

    Coverage/DB-fault correlation only needs the id header; authentication is optional
    (the lab's SQLi/XSS endpoints are reachable anonymously). Pass ``cookie`` to probe
    an authenticated surface. ``id_factory`` is injectable for deterministic tests.
    """

    def __init__(self, *, header: str = "X-Fzl-Cov", timeout: float = 15.0,
                 cookie: str | None = None,
                 id_factory: Callable[[], str] | None = None, session=None):
        import requests
        self._requests = requests
        self._session = session or requests.Session()
        self._header = header
        self._timeout = timeout
        self._cookie = cookie
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)

    def send_correlated(self, url: str, param: str, value: str, *,
                        method: str = "GET", location: str = "query"):
        cid = self._id_factory()
        headers = {self._header: cid}
        if self._cookie:
            headers["Cookie"] = self._cookie
        kwargs = {"timeout": self._timeout, "headers": headers}
        if location == "body":
            kwargs["data"] = {param: value}
        else:
            kwargs["params"] = {param: value}
        start = time.perf_counter()
        try:
            r = self._session.request(method.upper(), url, **kwargs)
            probe = Probe(status=r.status_code, text=r.text,
                          elapsed=time.perf_counter() - start, headers=dict(r.headers))
        except self._requests.RequestException as exc:
            probe = Probe(status=0, text=f"<request-error: {exc}>",
                          elapsed=time.perf_counter() - start)
        return probe, cid


def _endpoint_file(url: str, app_root: str) -> str:
    """Map a point URL to the app file that serves it (…/login.php)."""
    path = urlparse(url).path or "/"
    base = path.rsplit("/", 1)[-1] or "index.php"
    return app_root.rstrip("/") + "/" + base


def _screening(spec: ProbeSpec, probe: Probe, baseline: Probe | None) -> float:
    """Coarse black-box hit signal in [0, 1] (the Phase 2 tier carried forward)."""
    text = probe.text or ""
    if spec.kind == "sqli":
        if probe.status >= 500 or _SQL_ERR.search(text):
            return 1.0
        if baseline is not None and abs(len(text) - len(baseline.text or "")) > 64:
            return 0.5                      # boolean divergence from the baseline body
        return 0.0
    if spec.kind == "xss":
        return 1.0 if spec.value in text else 0.0
    return 0.0


def _class_for(spec: ProbeSpec, point_class: str | None) -> str:
    if point_class:
        return point_class
    return "sqli" if spec.kind == "sqli" else "xss" if spec.kind == "xss" else ""


def _insert_attempt(store, run_id: int, family: str, features: dict,
                    reward: float) -> int:
    cur = store.conn.execute(
        "INSERT INTO attempt (run_id, payload_family, features_json, reward) "
        "VALUES (?,?,?,?)",
        (run_id, family, json.dumps(features, sort_keys=True), float(reward)),
    )
    store.conn.commit()
    return int(cur.lastrowid)


def _record_metric(store, run_id: int, key: str, value: float) -> None:
    store.conn.execute(
        "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
        (run_id, key, float(value)))
    store.conn.commit()


def mutation_variant_probes(base_specs: Iterable[ProbeSpec], *,
                            max_variants: int = 2,
                            validator: SemanticsValidator | None = None) -> list[ProbeSpec]:
    """Semantics-preserving mutation-engine variants of each sqli/xss base probe.

    T8.5 wiring: the mutation engine (`fuzzlab/mutation/operators.py`, T8.1) already
    generates meaning-preserving payload variants and the semantics validator
    (T8.1/NFR-MUT-semantics) already judges which are safe to send; this is what was
    missing -- turning those into extra :class:`ProbeSpec` entries the **main harness's**
    attempt loop (`run_greybox`, below) sends and records exactly like any other probe,
    rather than only through the standalone `mutate-run` CLI. Offline/local: it makes no
    network calls of its own, it just proposes candidates for the caller to send.

    At most ``max_variants`` operators are tried per base probe (one variant each), to
    keep the extra request cost per point small and bounded (NFR-MUT-bounded).
    """
    validator = validator or SemanticsValidator()
    out: list[ProbeSpec] = []
    for spec in base_specs:
        mutation_class = _MUTATION_CLASS.get(spec.kind)
        if mutation_class is None:
            continue
        ops = [op for op in default_operators(mutation_class)
               if op.id not in _MUTATION_SKIP_OPS][:max_variants]
        for op in ops:
            variants = op.apply(spec.value)
            if not variants:
                continue
            variant = variants[0]
            if not validator.preserves(spec.value, variant, mutation_class,
                                       trusted=not op.surface):
                continue
            out.append(ProbeSpec(family=f"mutation:{op.id}", value=variant, kind=spec.kind,
                                 base=spec.value, operators=(op.id,)))
    return out


def _record_accepted_variant(store, run_id: int, spec: ProbeSpec, mutation_class: str, *,
                             new_lines: int, allow_destructive: bool) -> int | None:
    """Write a mutation-derived probe back to `payload_variant` if it was "accepted":
    it produced a screening hit or reached new code when actually probed live. Goes
    through the same destructive gate as `mutate-run` (NFR-MUT-safe) -- refused variants
    are neither persisted nor (already) sent again."""
    return record_variant(
        store, run_id, spec.base, spec.value, list(spec.operators), mutation_class,
        semantics_ok=True, coverage_gain=float(new_lines),
        allow_destructive=allow_destructive)


def _record_coverage_metric(logger: MetricLogger, step: int, frontier: CoverageFrontier) -> None:
    """Emit the run-wide coverage frontier's current size to `metric_series`
    (B0's coverage-frontier emitter, CC-FUZZ-0021), keyed by attempt count so
    frontier growth over the run is visible at read time (LTTB downsampling
    per `docs/UI_IMPLEMENTATION_PLAN.md` R-05's `coverage/lines` example key).

    Purely additive alongside the existing `greybox_frontier_size` run_metrics
    total (`_record_metric`, below) -- it does not replace or alter that path,
    it just adds a per-step series `log_scalar` cannot express as a single
    end-of-run total. `logger` is buffered (`MetricLogger`); the caller flushes
    it once at the end of the run, same as `mutation_variant_probes` /
    `_record_accepted_variant` above slot into this same attempt loop for T8.5.
    """
    logger.log("coverage/lines", step, float(frontier.size))


def run_greybox(*, base_url: str, store, run_id: int,
                points: Sequence[GreyboxPoint], sender,
                coverage_source, dbfault_source, lab_control=None,
                reset_between: bool = False, app_root: str = DEFAULT_APP_ROOT,
                probes: Iterable[ProbeSpec] = DEFAULT_PROBES,
                settle: float = 0.0, logger=None,
                mutation_variants: bool = False, max_mutation_variants: int = 2,
                allow_destructive: bool = False) -> dict:
    """Drive the live grey-box run; return a summary dict.

    Writes one ``attempt`` row per (point, probe) with the shaped reward and the
    grey-box coverage / db_fault columns, plus grey-box ``run_metrics`` totals.

    ``mutation_variants`` (T8.5 wiring, opt-in): also probe each point's sqli/xss attacks
    with a bounded set of the mutation engine's semantics-preserving variants
    (`mutation_variant_probes`), through the exact same attempt/reward/coverage path as
    the built-in probes; a variant that turns out to hit or reach new code is written
    back to ``payload_variant`` (`fuzzlab.mutation.catalog.record_variant`), same as
    `mutate-run` does. Off by default -- it is additional live traffic, bounded by
    ``max_mutation_variants`` per attack probe.
    """
    probes = tuple(probes)
    include = (app_root.rstrip("/") + "/",)
    frontier = CoverageFrontier()          # run-wide exploration total only (a metric)
    coverage_metrics = MetricLogger(store, run_id, source="coverage")  # B0 coverage emitter
    summary = {"points": len(points), "attempts": 0, "db_faults": 0,
               "novel_lines": 0, "m10_would_confirm": 0, "max_reward": 0.0,
               "baseline_reward": 0.0, "newcode_reward": 0.0, "coverage_lines_seen": 0,
               "mutation_variants_probed": 0, "mutation_variants_recorded": 0}

    if lab_control is not None:
        lab_control.snapshot("baseline")

    for pt in points:
        # Send the benign baseline(s) first to establish this point's baseline coverage,
        # then diff each attack against it. Novelty for the reward is PER-POINT
        # differential (lines the attack reaches that the point's benign request did not),
        # NOT global-frontier consumption — otherwise the baseline, running first, eats
        # all the novelty and every attack shows novel=0 (BUG-0016).
        ordered = sorted(probes, key=lambda s: s.kind != "baseline")   # baselines first
        if mutation_variants:
            # Appended after the base probes (baseline already sorted first above), so
            # each variant's per-point baseline is already established when it runs.
            ordered = ordered + mutation_variant_probes(
                (s for s in ordered if s.kind != "baseline"),
                max_variants=max_mutation_variants)
        baseline_probe: Probe | None = None
        baseline_cov: set[tuple[str, int]] = set()
        for spec in ordered:
            probe, cid = sender.send_correlated(
                pt.url, pt.param, spec.value, method=pt.method, location=pt.location)
            if settle:
                time.sleep(settle)
            cov = app_lines(coverage_source.lines_for(cid), include_prefixes=include)
            cov_lines = {(f, ln) for f, lns in cov.items() for ln in lns}
            frontier.observe(cov)          # accumulate the run-wide exploration total
            fault = dbfault_source.fault_for(cid)
            if spec.kind == "baseline":
                if baseline_probe is None:
                    baseline_probe = probe
                baseline_cov |= cov_lines
                new_lines = 0              # the control reaches no code "beyond itself"
            else:
                new_lines = len(cov_lines - baseline_cov)   # attack vs its own baseline
            screening = _screening(spec, probe, baseline_probe)
            sink_covered = _endpoint_file(pt.url, app_root) in cov
            signal = GreyboxSignal(screening=screening, novel_lines=new_lines,
                                   db_fault=fault.faulted, sink_covered=sink_covered)
            reward = shaped_reward(signal)
            features = {
                "payload_family": spec.family,
                "payload_kind": spec.kind,
                "param": pt.param,
                "location": pt.location,
                "method": pt.method,
                "status": probe.status,
                "resp_len": len(probe.text or ""),
                "new_lines_vs_baseline": new_lines,
                "cov_lines": len(cov_lines),
                "sink_covered": sink_covered,
                "db_fault": fault.faulted,
                "screening": screening,
                "mutation_variant": spec.base is not None,
            }
            attempt_id = _insert_attempt(store, run_id, spec.family, features, reward)
            record_attempt_signals(
                store, attempt_id,
                coverage=encode_coverage(cov, novel=new_lines),
                db_fault=fault.faulted, reward=reward)

            summary["attempts"] += 1
            _record_coverage_metric(coverage_metrics, summary["attempts"], frontier)
            summary["coverage_lines_seen"] += len(cov_lines)
            summary["max_reward"] = max(summary["max_reward"], reward)
            if spec.kind == "baseline":
                summary["baseline_reward"] = max(summary["baseline_reward"], reward)
            elif new_lines > 0:
                summary["newcode_reward"] = max(summary["newcode_reward"], reward)
            if fault.faulted:
                summary["db_faults"] += 1
            if greybox_confirms(_class_for(spec, pt.vuln_class), signal):
                summary["m10_would_confirm"] += 1
            if spec.base is not None:            # mutation-engine-derived probe (T8.5)
                summary["mutation_variants_probed"] += 1
                if screening > 0 or new_lines > 0:      # "accepted": it did something
                    recorded_id = _record_accepted_variant(
                        store, run_id, spec, _MUTATION_CLASS[spec.kind],
                        new_lines=new_lines, allow_destructive=allow_destructive)
                    if recorded_id is not None:
                        summary["mutation_variants_recorded"] += 1
            if logger:
                logger.info("greybox attempt", extra={
                    "url": pt.url, "family": spec.family, "reward": reward,
                    "new_lines": new_lines, "db_fault": fault.faulted})

        if (reset_between and lab_control is not None
                and pt.method.upper() != "GET"):
            lab_control.reset("baseline")

    coverage_metrics.flush()               # B0 coverage emitter: commit any buffered rows
    summary["novel_lines"] = frontier.size
    _record_metric(store, run_id, "greybox_attempts", summary["attempts"])
    _record_metric(store, run_id, "greybox_db_faults", summary["db_faults"])
    _record_metric(store, run_id, "greybox_novel_lines", summary["novel_lines"])
    _record_metric(store, run_id, "greybox_coverage_lines_seen",
                   summary["coverage_lines_seen"])
    _record_metric(store, run_id, "greybox_m10_would_confirm",
                   summary["m10_would_confirm"])
    _record_metric(store, run_id, "greybox_frontier_size", frontier.size)
    if mutation_variants:
        _record_metric(store, run_id, "greybox_mutation_variants_probed",
                       summary["mutation_variants_probed"])
        _record_metric(store, run_id, "greybox_mutation_variants_recorded",
                       summary["mutation_variants_recorded"])
    return summary


def points_with_classes(ground_truth, base_url: str, browser_available: bool = False):
    """Ground-truth points as :class:`GreyboxPoint`, tagged with their vuln_class.

    Reuses the harness' point selection (`harness.auto.points_from_ground_truth`) and
    attaches each point's class from the contract's cases so M10 can be scored.
    """
    from fuzzlab.harness.auto import points_from_ground_truth
    base_points, skipped = points_from_ground_truth(
        ground_truth, base_url, browser_available=browser_available)
    base = base_url.rstrip("/")
    cls: dict[tuple[str, str, str], str] = {}
    for c in ground_truth.positives():
        path = c.url if c.url.startswith("/") else "/" + c.url
        cls[(base + path, c.method.upper(), c.param)] = c.vuln_class
    out = [GreyboxPoint(url=p.url, param=p.param, method=p.method, location=p.location,
                        vuln_class=cls.get((p.url, p.method.upper(), p.param)))
           for p in base_points]
    return out, skipped


def points_from_store(store, run_id: int, base_url: str) -> list[GreyboxPoint]:
    """Crawl-discovered points as :class:`GreyboxPoint` (class unknown -> None)."""
    from fuzzlab.harness.auto import injection_points_from_store
    return [GreyboxPoint(url=p.url, param=p.param, method=p.method, location=p.location)
            for p in injection_points_from_store(store, run_id, base_url)]
