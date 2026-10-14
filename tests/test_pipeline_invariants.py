"""Pipeline invariants of the oracle loop (BUG-0071, BUG-0072; PA-0072, PA-0073).

- **One confirmation per key, in every mode.** Duplicate rows of a confirmation key send
  the identical `Candidate`, so the oracle is asked once per key and a key yields at most
  one finding — unbudgeted, budgeted and budget-fallback alike (FR-FUZZ-32 amended).
- **Crash safety.** A run that dies mid-oracle-loop never leaves a candidate's
  `oracle_status` NULL (which the ML dataset reads as a labelled negative): reached rows
  are `checked`, unreached ones `pending` (unlabelled), no-confirmer rows final.
- **The bandit path takes content-typed probes** (BUG-0071's crash).
"""

from __future__ import annotations

import json
import random

import pytest

from fuzzlab.audit import InjectionPoint
from fuzzlab.core.oracle_status import PENDING, UNLABELLED
from fuzzlab.core.runmode import RunPlan
from fuzzlab.core.store import Store
from fuzzlab.harness.pipeline import run_pipeline
from fuzzlab.ml.active import Prioritized
from fuzzlab.ml.dataset import build_dataset
from fuzzlab.oracle import Oracle
from fuzzlab.oracle.probe import Probe
from tests.test_auto import AutoSender

BASE = "http://127.0.0.1:8080"
_PLAN = RunPlan(mode="manual", categories=["sql-injection", "xss"], scored=False,
                source="manual")


def _seed(store, run_id, rows):
    for page, param, category in rows:
        ev = json.dumps({"url": f"{BASE}/{page}", "param": param, "category": category,
                         "method": "GET", "location": "query"})
        store.conn.execute("INSERT INTO candidate (run_id, rule, evidence) VALUES (?,?,?)",
                           (run_id, "R", ev))
    store.conn.commit()


@pytest.fixture
def calls(monkeypatch):
    seen = []
    real = Oracle.confirm_outcome          # what the pipeline calls (FR-FUZZ-45)

    def recording(self, candidate, sender):
        seen.append((candidate.url, candidate.param, candidate.method, candidate.location,
                     candidate.category))
        return real(self, candidate, sender)
    monkeypatch.setattr(Oracle, "confirm_outcome", recording)
    return seen


# A, B, A, C, B: three keys, two duplicated; A (product) and C (blog_post) confirm as SQLi.
_ROWS = [("product.php", "id", "sql-injection"), ("search.php", "q", "sql-injection"),
         ("product.php", "id", "sql-injection"), ("blog_post.php", "id", "sql-injection"),
         ("search.php", "q", "sql-injection")]


def _ordered(s, r, ids):
    return Prioritized(order=list(ids), method="stub")


@pytest.mark.parametrize("mode,kw", [
    ("unbudgeted", {}),
    ("budgeted", {"confirm_budget": 99, "prioritizer": _ordered}),
    ("fallback", {"confirm_budget": 1, "prioritizer": lambda s, r, ids: None}),
])
def test_one_confirmation_and_at_most_one_finding_per_key(tmp_path, calls, mode, kw):
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        _seed(store, run_id, _ROWS)
        result = run_pipeline([], store, run_id, AutoSender(), _PLAN, **kw)
        keys = {(f"{BASE}/{p}", q, "GET", "query", c) for p, q, c in _ROWS}
        assert len(calls) == len(set(calls)) == len(keys)          # once per key
        findings = store.conn.execute(
            "SELECT url, param, method, vuln_class FROM finding WHERE run_id=?",
            (run_id,)).fetchall()
        assert len(findings) == len({tuple(f) for f in findings})  # no duplicate rows
        assert result.findings == len(findings) <= len(keys)
        assert result.findings == 2                                # product + blog_post
        assert result.metrics["oracle_checked"] == len(_ROWS)      # every row checked


class _Boom(RuntimeError):
    pass


def test_a_crash_mid_loop_leaves_reached_rows_checked_and_the_rest_pending(
        tmp_path, monkeypatch):
    real = Oracle.confirm_outcome
    n = {"calls": 0}

    def flaky(self, candidate, sender):
        n["calls"] += 1
        if n["calls"] == 2:
            raise _Boom("sender died")
        return real(self, candidate, sender)
    monkeypatch.setattr(Oracle, "confirm_outcome", flaky)
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        _seed(store, run_id, [("product.php", "id", "sql-injection"),   # reached
                              ("x.php", "p", "no-such-category"),       # no confirmer
                              ("search.php", "q", "sql-injection"),     # raises here
                              ("blog_post.php", "id", "sql-injection")])  # never reached
        with pytest.raises(_Boom):
            run_pipeline([], store, run_id, AutoSender(), _PLAN)
        statuses = [r["oracle_status"] for r in store.conn.execute(
            "SELECT oracle_status FROM candidate WHERE run_id=? ORDER BY id", (run_id,))]
        assert statuses == ["checked", "no_confirmer", PENDING, PENDING]
        assert PENDING in UNLABELLED
        ds = build_dataset(store, run_id)                 # only the reached row labels
        assert len(ds.ids) == 1 and ds.labelled == [True]
        everything = build_dataset(store, run_id, include_unlabelled=True)
        assert everything.labelled == [True, False, False, False]


def test_a_budgeted_crash_leaves_unreached_and_unchosen_rows_pending(tmp_path, monkeypatch):
    monkeypatch.setattr(Oracle, "confirm_outcome",
                        lambda self, c, s: (_ for _ in ()).throw(_Boom()))
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        _seed(store, run_id, _ROWS[:2])
        with pytest.raises(_Boom):
            run_pipeline([], store, run_id, AutoSender(), _PLAN, confirm_budget=1,
                         prioritizer=_ordered)
        assert {r["oracle_status"] for r in store.conn.execute(
            "SELECT oracle_status FROM candidate WHERE run_id=?", (run_id,))} == {PENDING}


class _JsonSqlSender:
    """A JSON API: SQL error on a quote in the raw body; records each content type."""

    def __init__(self):
        self.content_types = []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None):
        self.content_types.append(content_type)
        if "'" in value or '"' in value:
            return Probe(500, "You have an error in your SQL syntax", headers={})
        return Probe(200, "ok", headers={})


def test_a_bandit_run_confirms_a_json_body_point(tmp_path):
    from fuzzlab.oracle.strategies import default_strategies
    from fuzzlab.scheduler import ThompsonBandit, arm_priors
    bandit = ThompsonBandit(rng=random.Random(0), priors=arm_priors(default_strategies()),
                            cost_normalized=True, backoff=True)
    point = InjectionPoint(url=f"{BASE}/api/items", param="body", method="POST",
                           location="body", body_content_type="application/json")
    sender = _JsonSqlSender()
    plan = RunPlan(mode="manual", categories=["sql-injection"], scored=False,
                   source="manual")
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        result = run_pipeline([point], store, run_id, sender, plan, scheduler=bandit)
        assert result.candidates >= 1
        assert "application/json" in sender.content_types        # reached the sender
        assert {r["oracle_status"] for r in store.conn.execute(
            "SELECT oracle_status FROM candidate WHERE run_id=?", (run_id,))} == {"checked"}
