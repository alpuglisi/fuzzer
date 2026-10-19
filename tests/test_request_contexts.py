"""AU-REQID measurement, audit defect 8 (BUG-0530): distinct request contexts merge into
one test.

Each test drives the real code (the importer `store_adapter.import_spider`, the point
builder `harness.auto.injection_points_from_store`, `harness.pipeline.run_pipeline` on a
temporary real store, `ml.dataset.build_dataset`) and asserts what the request-context
identity of the draft (docs/components/07-fuzzing-harness-and-oracle/DRAFT-AU-REQID.md)
requires. Every test below fails on 8100959; each is pinned with a strict xfail until
CC-FUZZ-0106 lands (PA-0054(3)). A non-vacuity control beside each pipeline test passes
today: the oracle and the fake target confirm the context when it is reached.
"""

from __future__ import annotations

import html
import json

import pytest

from fuzzlab.audit import InjectionPoint
from fuzzlab.core.runmode import RunPlan
from fuzzlab.core.store import Store
from fuzzlab.harness.auto import STORED_DECIDER, injection_points_from_store
from fuzzlab.harness.pipeline import run_pipeline
from fuzzlab.oracle.browser import FakeBrowserExecutor
from fuzzlab.oracle.probe import Probe
from tests.test_forms_phase2 import _App, _rec
from tests.test_json_points import _req
from tests.test_json_points import _spider_db as _json_spider_db

BASE = "http://127.0.0.1:8080"
APP = "http://h/app/"

_XSS = RunPlan(mode="manual", categories=["xss"], scored=False, source="manual")
_SQLI = RunPlan(mode="manual", categories=["sql-injection"], scored=False,
                source="manual")

pin8 = pytest.mark.xfail(strict=True, reason="BUG-0530 (audit defect 8), measured on "
                         "8100959; fixed by CC-FUZZ-0106 (AU-REQID)")


def _import(tmp_path, *, pages=(), forms=(), requests=()):
    from fuzzlab.tools.store_adapter import import_spider
    _json_spider_db(tmp_path / "s.db", requests=requests, pages=pages, forms=forms)
    store = Store(tmp_path / "u.db")
    run = store.start_run("auto", "h")
    import_spider(tmp_path / "s.db", store, run)
    return store, run


def _points(tmp_path, **kw):
    store, run = _import(tmp_path, **kw)
    with store:
        return injection_points_from_store(store, run, APP, skipped=[])


def _contexts(points, name):
    return sorted((p.method, p.location, p.base_entries or ()) for p in points
                  if p.param == name)


# --- the point builder and the importer ------------------------------------------------
@pin8
def test_a_name_in_the_query_and_the_body_of_one_request_is_two_points(tmp_path):
    """The audit's reproduction: POST /api with ``q`` in its query and in its body. The
    builder's ``seen`` key ``(path, method, name)`` keeps the first row only."""
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        eid = store.conn.execute("INSERT INTO endpoint (run_id, url, method, source) "
                                 "VALUES (?,?,?,?)", (run, "/api", "POST", "form")
                                 ).lastrowid
        for location in ("query", "body"):
            store.conn.execute("INSERT INTO parameter (run_id, endpoint_id, name, "
                               "location, example) VALUES (?,?,?,?,?)",
                               (run, eid, "q", location, "1"))
        store.conn.commit()
        points = injection_points_from_store(store, run, BASE, skipped=[])
    assert sorted(p.location for p in points if p.param == "q") == ["body", "query"]


@pin8
def test_each_link_context_of_a_parameter_is_its_own_point(tmp_path):
    """Two crawled links give ``q`` two sibling sets; the importer keeps one parameter
    per (endpoint, name) and binds the first link's set only (FR-FUZZ-43's 'first
    crawled link wins')."""
    points = _points(tmp_path, pages=[APP + "l.php?op=safe&q=1",
                                      APP + "l.php?op=search&q=2"])
    assert _contexts(points, "q") == [
        ("GET", "query", (("op", "safe"), ("q", "1"))),
        ("GET", "query", (("op", "search"), ("q", "2")))]


@pin8
def test_each_captured_body_of_an_endpoint_is_its_own_context(tmp_path):
    """Two captured JSON requests to one endpoint, an operation selector apart: 'the
    first one's leaf wins a name' (FR-AUD-22) drops the second operation."""
    points = _points(tmp_path, requests=[
        _req(APP + "api/run", {"op": "safe", "q": "a"}, page=APP),
        _req(APP + "api/run", {"op": "search", "q": "b"}, page=APP)])
    ops = sorted({tuple(p): v for p, v in pt.base_entries}.get(("op",))
                 for pt in points if pt.param == "q")
    assert ops == ["safe", "search"]


@pin8
def test_a_form_body_and_a_json_body_of_one_endpoint_are_two_points(tmp_path):
    """A crawled form and a captured JSON request POST to one endpoint, both with
    ``q``: one parameter per (endpoint, name) drops the JSON leaf."""
    form = _rec("<form method=post action='/app/api/run'><input name=q>"
                "<input name=op value=x></form>")
    points = _points(tmp_path, forms=[form],
                     requests=[_req(APP + "api/run", {"q": "a", "op": "x"}, page=APP)])
    assert sorted(p.location for p in points if p.param == "q") == ["body", "json"]


@pin8
def test_a_post_actions_query_parameter_is_a_point(tmp_path):
    """A POST form keeps its action's query (`_import_forms`, reviewer A4), so the
    server reads ``q`` from the query too; it is never a point today."""
    form = _rec("<form method=post action='/app/api.php?q=1'><input name=q>"
                "<input name=t></form>")
    points = _points(tmp_path, forms=[form])
    assert ("POST", "query") in {(p.method, p.location) for p in points
                                 if p.param == "q"}


# --- the pipeline: one test per context -------------------------------------------------
def _op_gated_echo(req):
    """Reflects ``q`` raw only in the ``op=search`` context (another handler's sink),
    escaped otherwise."""
    q = req["query"].get("q", "")
    shown = q if req["query"].get("op") == "search" else html.escape(q)
    return Probe(200, f"<html><body><p>{shown}</p></body></html>",
                 headers={"Content-Type": "text/html"})


def _gated_points(*ops):
    return [InjectionPoint(url=BASE + "/s.php", param="q", method="GET", location="query",
                           base_entries=(("op", op), ("q", "1")), origin="crawl")
            for op in ops]


def test_control_the_search_context_alone_confirms(tmp_path):
    """Non-vacuity control (passes on 8100959): reached, the context confirms."""
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        result = run_pipeline(_gated_points("search"), store, run, _App(_op_gated_echo),
                              _XSS)
    assert result.findings == 1


@pin8
def test_the_pipeline_tests_a_context_that_only_its_siblings_reach(tmp_path):
    """`_confirmation_key` is (url, param, method, location, category): the two contexts
    are one key, the oracle is asked once (the ``op=safe`` row) and the ``op=search`` row
    is marked checked without a probe."""
    app = _App(_op_gated_echo)
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        result = run_pipeline(_gated_points("safe", "search"), store, run, app, _XSS)
    assert {r["query"].get("op") for r in app.requests} == {"safe", "search"}
    assert result.findings == 1


@pin8
def test_a_raw_body_and_a_form_field_of_one_url_are_two_tests(tmp_path, monkeypatch):
    """A whole raw JSON body and a form field named ``body`` at one URL: the key has no
    content type, so the oracle is asked for the first only (the baseline probe goes
    through the form point, so the oracle's own calls are what is recorded)."""
    from fuzzlab.oracle import Oracle
    seen = []
    real = Oracle.confirm_outcome

    def recording(self, candidate, sender):
        seen.append(candidate.content_type)
        return real(self, candidate, sender)
    monkeypatch.setattr(Oracle, "confirm_outcome", recording)

    class Recorder:
        def send(self, url, param, value, timing=False, method="GET", location="query",
                 content_type=None, entries=None, prg=False):
            return Probe(200, "<html>ok</html>")

    points = [InjectionPoint(url=BASE + "/api", param="body", method="POST",
                             location="body", body_content_type="application/json",
                             origin="ground-truth"),
              InjectionPoint(url=BASE + "/api", param="body", method="POST",
                             location="body", origin="crawl")]
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        run_pipeline(points, store, run, Recorder(), _SQLI)
    assert sorted(map(str, seen)) == ["None", "application/json"]


def _stored(store_path):
    return InjectionPoint(url=BASE + "/guestbook", param="comment", method="GET",
                          location="query", store_url=BASE + store_path,
                          store_param="comment", origin="ground-truth",
                          decided_by=STORED_DECIDER)


def _plants_at_b(req):
    return req.store is not None and req.store.url.endswith("/sign-b")


def test_control_the_second_store_alone_confirms(tmp_path):
    """Non-vacuity control (passes on 8100959)."""
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        result = run_pipeline([_stored("/sign-b")], store, run,
                              _App(lambda r: Probe(200, "<html>ok</html>")), _XSS,
                              browser=FakeBrowserExecutor(vulnerable=_plants_at_b))
    assert result.findings == 1


@pin8
def test_two_stored_cases_shown_on_one_page_each_plant_their_own_store(tmp_path):
    """Two store requests whose payload renders on one observe page: the key has no
    setup, so the second store request is never planted."""
    planted = []

    def vulnerable(req):
        planted.append(req.store.url if req.store else None)
        return _plants_at_b(req)

    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        result = run_pipeline([_stored("/sign-a"), _stored("/sign-b")], store, run,
                              _App(lambda r: Probe(200, "<html>ok</html>")), _XSS,
                              browser=FakeBrowserExecutor(vulnerable=vulnerable))
    assert {u.rsplit("/", 1)[-1] for u in planted if u} == {"sign-a", "sign-b"}
    assert result.findings == 1


# --- finding attribution: a label belongs to the context the oracle tested -------------
def _safe_gated_echo(req):
    """The mirror image: only the ``op=safe`` context reflects raw."""
    q = req["query"].get("q", "")
    shown = q if req["query"].get("op") == "safe" else html.escape(q)
    return Probe(200, f"<html><body><p>{shown}</p></body></html>",
                 headers={"Content-Type": "text/html"})


@pin8
def test_a_context_never_tested_is_never_labelled_by_anothers_finding(tmp_path):
    """The ``op=safe`` context confirms; the ``op=search`` rows were never sent, yet
    they are marked checked and the ML label join ((run, path, param, category,
    method), BUG-0075) labels them positive: a training label for a request no probe
    made."""
    from fuzzlab.ml.dataset import build_dataset
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        run_pipeline(_gated_points("safe", "search"), store, run, _App(_safe_gated_echo),
                     _XSS)
        ops = {r["id"]: dict(map(tuple, json.loads(r["evidence"])["entries"]))["op"]
               for r in store.conn.execute("SELECT id, evidence FROM candidate "
                                           "WHERE run_id=?", (run,))}
        ds = build_dataset(store, run)
    labels = {ops[cid]: y for cid, y in zip(ds.ids, ds.y)}
    assert labels == {"safe": 1, "search": 0}


# --- upstream: the crawler's own signatures (CRAWL; measured, not this item's scope) ---
def test_upstream_the_spider_keeps_one_form_per_action_method_and_names(tmp_path):
    """Measured for the sweep (passes on 8100959, documenting the upstream collapse):
    two forms at one action that differ only in a hidden operation value are one
    `discovered_forms` row (`StorageManager.record_form`'s signature)."""
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    first = sm.record_form(_rec("<form method=post action='/app/do.php'>"
                                "<input type=hidden name=op value=safe><input name=q>"
                                "</form>"))
    second = sm.record_form(_rec("<form method=post action='/app/do.php'>"
                                 "<input type=hidden name=op value=search><input name=q>"
                                 "</form>"))
    sm.close()
    assert (first, second) == (True, False)


def test_upstream_the_spider_keeps_one_request_per_method_path_and_keys(tmp_path):
    """Measured for the sweep (passes on 8100959): `record_request`'s signature is
    (method, url_key, body keys), so an operation selector in the query or in a body
    value is one row."""
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    got = [sm.record_request(APP, "POST", APP + f"api/run?op={op}", "application/json",
                             json.dumps({"op": op, "q": "x"}).encode(), "passive")
           for op in ("safe", "search")]
    sm.close()
    assert got == [None, "duplicate"]
