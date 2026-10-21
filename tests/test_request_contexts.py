"""Audit defect 8 (BUG-0530): distinct request contexts are never merged into one test.

Each test drives the real code (the importer `store_adapter.import_spider`, the point
builder `harness.auto.injection_points_from_store`, `harness.pipeline.run_pipeline` on a
temporary real store, `ml.dataset.build_dataset`). The measurement tests were parked at
9ac56f8 (DRAFT-AU-REQID8.md §1.1) and failed on 8100959; CC-FUZZ-0111, CC-AUD-0056,
CC-CORE-0073 and CC-ML-0501 make them pass. A non-vacuity control beside each pipeline
test shows the fake target and the oracle confirm a context once it is reached.

The guards at the end hold SP-57 (`core.reqctx`, PA-0530): every `Candidate` field is
classified, every identity field moves the context id and no excluded one does, and the
seed categories are the strategies that read the target's original value.
"""

from __future__ import annotations

import ast
import dataclasses
import html
import json
from pathlib import Path

import pytest

from fuzzlab.audit import InjectionPoint
from fuzzlab.core.runmode import RunPlan
from fuzzlab.core.store import Store
from fuzzlab.harness.auto import STORED_DECIDER, injection_points_from_store
from fuzzlab.harness.pipeline import run_pipeline
from fuzzlab.oracle.browser import FakeBrowserExecutor
from fuzzlab.oracle.probe import Candidate, Probe
from tests.test_forms_phase2 import _App, _rec
from tests.test_json_points import _req
from tests.test_json_points import _spider_db as _json_spider_db

BASE = "http://127.0.0.1:8080"
APP = "http://h/app/"

_XSS = RunPlan(mode="manual", categories=["xss"], scored=False, source="manual")
_SQLI = RunPlan(mode="manual", categories=["sql-injection"], scored=False,
                source="manual")


def _reqctx():
    """SP-57's owner, imported where used: each reproduction above the guards also runs
    (and fails on its own assertion) on a tree that predates it (PA-0541(2))."""
    from fuzzlab.core import reqctx
    return reqctx


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
def test_a_name_in_the_query_and_the_body_of_one_request_is_two_points(tmp_path):
    """The audit's reproduction: POST /api with ``q`` in its query and in its body. The
    builder's old ``seen`` key ``(path, method, name)`` kept the first row only."""
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


def test_each_link_context_of_a_parameter_is_its_own_point(tmp_path):
    """Two crawled links give ``q`` two sibling sets; the importer kept one parameter
    per (endpoint, name) and bound the first link's set only (FR-FUZZ-43's 'first
    crawled link wins')."""
    points = _points(tmp_path, pages=[APP + "l.php?op=safe&q=1",
                                      APP + "l.php?op=search&q=2"])
    assert _contexts(points, "q") == [
        ("GET", "query", (("op", "safe"), ("q", "1"))),
        ("GET", "query", (("op", "search"), ("q", "2")))]


def test_each_captured_body_of_an_endpoint_is_its_own_context(tmp_path):
    """Two captured JSON requests to one endpoint, an operation selector apart: 'the
    first one's leaf wins a name' (FR-AUD-22) dropped the second operation."""
    points = _points(tmp_path, requests=[
        _req(APP + "api/run", {"op": "safe", "q": "a"}, page=APP),
        _req(APP + "api/run", {"op": "search", "q": "b"}, page=APP)])
    ops = sorted({tuple(p): v for p, v in pt.base_entries}.get(("op",))
                 for pt in points if pt.param == "q")
    assert ops == ["safe", "search"]


def test_a_form_body_and_a_json_body_of_one_endpoint_are_two_points(tmp_path):
    """A crawled form and a captured JSON request POST to one endpoint, both with
    ``q``: one parameter per (endpoint, name) dropped the JSON leaf."""
    form = _rec("<form method=post action='/app/api/run'><input name=q>"
                "<input name=op value=x></form>")
    points = _points(tmp_path, forms=[form],
                     requests=[_req(APP + "api/run", {"q": "a", "op": "x"}, page=APP)])
    assert sorted(p.location for p in points if p.param == "q") == ["body", "json"]


@pytest.mark.xfail(strict=True, reason="a POST action's query parameter is not a point: "
                   "a query point on a request with a body needs a second entry list in "
                   "the Sender protocol (SP-20); owned by AU-REQID-POSTQ (DRAFT-AU-REQID8 "
                   "§11.3, BUG-0530 residual)")
def test_a_post_actions_query_parameter_is_a_point(tmp_path):
    """A POST form keeps its action's query (`_import_forms`, reviewer A4), so the
    server reads ``q`` from the query too; it is never a point today."""
    form = _rec("<form method=post action='/app/api.php?q=1'><input name=q>"
                "<input name=t></form>")
    points = _points(tmp_path, forms=[form])
    assert ("POST", "query") in {(p.method, p.location) for p in points
                                 if p.param == "q"}


def test_rows_of_one_request_context_are_one_point(tmp_path):
    """Non-vacuity of the builder's dedup: two rows that describe one wire request are
    one point; the same siblings in another order are another request."""
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        eid = store.conn.execute("INSERT INTO endpoint (run_id, url, method, source) "
                                 "VALUES (?,?,?,?)", (run, "/l.php", "GET", "link")
                                 ).lastrowid
        for entries in (["op", "safe"], ["q", "1"]), (["op", "safe"], ["q", "1"]), \
                (["q", "1"], ["op", "safe"]):
            fid = store.conn.execute("INSERT INTO form (run_id, endpoint_id, enctype, "
                                     "entries) VALUES (?,?,NULL,?)",
                                     (run, eid, json.dumps(entries))).lastrowid
            store.conn.execute("INSERT INTO parameter (run_id, endpoint_id, name, "
                               "location, example, form_id) VALUES (?,?,?,?,?,?)",
                               (run, eid, "q", "query", "1", fid))
        store.conn.commit()
        points = injection_points_from_store(store, run, BASE, skipped=[])
    assert [p.base_entries for p in points if p.param == "q"] == [
        (("op", "safe"), ("q", "1")), (("q", "1"), ("op", "safe"))]


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


def test_op_safe_and_op_search_have_distinct_confirmation_keys():
    """The brief's reproduction at the key itself: the old key was (url, param, method,
    location, category), equal for both."""
    keys = {_reqctx().confirmation_key({**_reqctx().point_evidence(p), "category": "xss"})
            for p in _gated_points("safe", "search")}
    assert len(keys) == 2


def test_control_the_search_context_alone_confirms(tmp_path):
    """Non-vacuity control (passes on 8100959): reached, the context confirms."""
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        result = run_pipeline(_gated_points("search"), store, run, _App(_op_gated_echo),
                              _XSS)
    assert result.findings == 1


def test_the_pipeline_tests_a_context_that_only_its_siblings_reach(tmp_path):
    """`_confirmation_key` was (url, param, method, location, category): the two contexts
    were one key, the oracle was asked once (the ``op=safe`` row) and the ``op=search``
    row was marked checked without a probe."""
    app = _App(_op_gated_echo)
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        result = run_pipeline(_gated_points("safe", "search"), store, run, app, _XSS)
    assert {r["query"].get("op") for r in app.requests} == {"safe", "search"}
    assert result.findings == 1


def test_rows_of_one_context_are_still_one_test(tmp_path, monkeypatch):
    """BUG-0072's invariant under the new key: rows of one context and category share
    one confirmation -- PA-0048's ground-truth duplicates, one point per
    ``sink_context``, give two candidate rows and one test."""
    from fuzzlab.oracle import Oracle
    calls = []
    real = Oracle.confirm_outcome

    def counting(self, candidate, sender):
        calls.append(candidate.context_key)
        return real(self, candidate, sender)
    monkeypatch.setattr(Oracle, "confirm_outcome", counting)
    points = [InjectionPoint(url=BASE + "/s.php", param="q", sink_context=s,
                             base_entries=(("op", "search"), ("q", "1")))
              for s in ("html", "attr")]
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        result = run_pipeline(points, store, run, _App(_op_gated_echo), _XSS)
        rows = store.conn.execute("SELECT COUNT(*) FROM candidate WHERE run_id=?",
                                  (run,)).fetchone()[0]
    assert rows == 2 and len(calls) == 1 and result.findings == 1


def test_a_raw_body_and_a_form_field_of_one_url_are_two_tests(tmp_path, monkeypatch):
    """A whole raw JSON body and a form field named ``body`` at one URL: the key had no
    content type, so the oracle was asked for the first only (the baseline probe goes
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


def test_two_stored_cases_shown_on_one_page_each_plant_their_own_store(tmp_path):
    """Two store requests whose payload renders on one observe page: the key had no
    setup, so the second store request was never planted."""
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


def test_a_context_never_tested_is_never_labelled_by_anothers_finding(tmp_path):
    """The ``op=safe`` context confirms; the ``op=search`` rows were tested and not
    confirmed. The old label join ((run, path, param, category, method), BUG-0075)
    labelled them positive: a training label for a request no confirming probe made."""
    from fuzzlab.ml.dataset import build_dataset
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        run_pipeline(_gated_points("safe", "search"), store, run, _App(_safe_gated_echo),
                     _XSS)
        ops = {r["id"]: dict(map(tuple, json.loads(r["evidence"])["entries"]))["op"]
               for r in store.conn.execute("SELECT id, evidence FROM candidate "
                                           "WHERE run_id=?", (run,))}
        (finding,) = [json.loads(r[0]) for r in store.conn.execute(
            "SELECT evidence FROM finding WHERE run_id=?", (run,))]
        ds = build_dataset(store, run)
    labels = {ops[cid]: y for cid, y in zip(ds.ids, ds.y)}
    assert labels == {"safe": 1, "search": 0}
    assert finding["context_id"].startswith(_reqctx().CONTEXT_PREFIX)


def test_a_finding_without_a_context_keeps_the_legacy_label_join(tmp_path):
    """A finding from before SP-57 (no ``context_key``) labels by (run, path, param,
    category, method), as before: old stores keep their labels."""
    from fuzzlab.ml.dataset import build_dataset
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("auto", "h")
        run_pipeline(_gated_points("safe"), store, run, _App(_safe_gated_echo), _XSS)
        store.conn.execute("UPDATE finding SET evidence='{}' WHERE run_id=?", (run,))
        store.conn.commit()
        ds = build_dataset(store, run)
    assert ds.y and set(ds.y) == {1}


# --- upstream: the crawler's own signatures (CRAWL; measured, not this item's scope) ---
_CRAWL_PIN = pytest.mark.xfail(strict=True, reason=(
    "the crawler's own dedup signature merges two request contexts before the store "
    "sees them (BUG-0530 residual, measured in DRAFT-AU-REQID8 §1.1); owned by CRAWL "
    "(a defect 9/10 item or a CRAWL follow-up)"))


@_CRAWL_PIN
def test_upstream_the_spider_keeps_both_forms_an_operation_value_apart(tmp_path):
    """Two forms at one action that differ only in a hidden operation value are one
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
    assert (first, second) == (True, True)


@_CRAWL_PIN
def test_upstream_the_spider_keeps_both_requests_an_operation_value_apart(tmp_path):
    """`record_request`'s signature is (method, url_key, body keys), so an operation
    selector in the query or in a body value is one row."""
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    got = [sm.record_request(APP, "POST", APP + f"api/run?op={op}", "application/json",
                             json.dumps({"op": op, "q": "x"}).encode(), "passive")
           for op in ("safe", "search")]
    sm.close()
    assert got == [None, None]


# --- SP-57's guards (PA-0530) ------------------------------------------------------------
def _ev(**over):
    ev = {"url": BASE + "/s.php?a=1", "param": "q", "method": "GET", "location": "query",
          "entries": [["op", "safe"], ["q", "1"]], "category": "xss"}
    ev.update(over)
    return {k: v for k, v in ev.items() if v is not None}


_STORE = dict(store_url=BASE + "/sign")
_BOUND = dict(bindings={"page": BASE + "/p", "fresh": ["op"]})
#: Each identity field: ``(the base evidence's own fields, a change that must move the
#: id)``.
_IDENTITY_CHANGES = {
    "origin": ({}, dict(url="http://127.0.0.1:9090/s.php?a=1")),
    "path": ({}, dict(url=BASE + "/t.php?a=1")),
    "query": ({}, dict(url=BASE + "/s.php?a=2")),
    "fragment": ({}, dict(url=BASE + "/s.php?a=1#/x")),
    "method": ({}, dict(method="POST")),
    "location": ({}, dict(location="body")),
    "target": ({}, dict(param="op")),
    "sibling value": ({}, dict(entries=[["op", "search"], ["q", "1"]])),
    "sibling name": ({}, dict(entries=[["mode", "safe"], ["q", "1"]])),
    "sibling order": ({}, dict(entries=[["q", "1"], ["op", "safe"]])),
    "placement": ({}, dict(entries=None)),
    "content type": (dict(location="body", entries=None),
                     dict(body_content_type="application/json")),
    "store url": ({}, _STORE),
    "store param": (_STORE, dict(store_param="other")),
    "store method": (_STORE, dict(store_method="PUT")),
    "store location": (_STORE, dict(store_location="json")),
    "store entries": (_STORE, dict(store_entries=[["a", "1"]])),
    "binding": ({}, _BOUND),
    "binding page": (_BOUND, dict(bindings={"page": BASE + "/form", "fresh": ["op"]})),
    "binding names": (_BOUND, dict(bindings={"page": BASE + "/p", "fresh": ["op2"]})),
    "refused": ({}, dict(replay_refusal="sibling x names a host outside the lab")),
    "identity": ({}, dict(identity_scope="alice")),
}
#: Fields that never move the id (they are not on the wire, or are the seed).
_NOT_IDENTITY = {
    "rule": dict(rule_id="R-OTHER"),
    "sink context": dict(sink_context="attr"),
    "decided by": dict(decided_by="xss-dom:browser-execution"),
    "category": dict(category="sql-injection"),
    "target's own value": dict(entries=[["op", "safe"], ["q", "2"]]),
    "base value": dict(base_value="127.0.0.1"),
    "redirect seed": dict(redirect_seed="http://h/"),
}


@pytest.mark.parametrize("field", sorted(_IDENTITY_CHANGES))
def test_every_identity_field_moves_the_context(field):
    own, change = _IDENTITY_CHANGES[field]
    base = _ev(**own)
    assert _reqctx().context_id(base) != _reqctx().context_id(_ev(**{**own, **change}))


@pytest.mark.parametrize("field", sorted(_NOT_IDENTITY))
def test_no_excluded_field_moves_the_context(field):
    assert _reqctx().context_id(_ev()) == _reqctx().context_id(_ev(**_NOT_IDENTITY[field]))


def test_a_seeded_category_keys_on_the_original_value_and_others_do_not():
    """The target's own value is the seed: two contexts that differ only in it are one
    test for xss and two for access-control, whose strategy replays it."""
    a, b = _ev(), _ev(entries=[["op", "safe"], ["q", "2"]])
    assert _reqctx().confirmation_key(a) == _reqctx().confirmation_key(b)
    ac = {"category": "access-control"}
    assert _reqctx().confirmation_key({**a, **ac}) != _reqctx().confirmation_key({**b, **ac})


def test_sink_context_duplicates_stay_one_test():
    """PA-0048's ground-truth duplicates (one point per sink_context) are one context."""
    points = [InjectionPoint(url=BASE + "/x", param="q", sink_context=s) for s in
              ("html", "attr")]
    assert len({_reqctx().point_key(p) for p in points}) == 1


def test_a_row_without_a_context_gets_the_same_one_on_read():
    """Compute on read (no migration): evidence written before SP-57 has no
    ``context_id``; its id, computed from the same fields, equals a stamped row's."""
    legacy = _ev()
    stamped = _reqctx().stamp(dict(legacy), None)
    assert "context_id" not in legacy
    assert _reqctx().context_id(legacy) == _reqctx().context_id(stamped) == stamped["context_id"]


def test_two_identities_never_share_a_context():
    assert _reqctx().context_id(_ev(identity_scope="alice")) != \
        _reqctx().context_id(_ev(identity_scope="bob"))


def test_a_points_key_equals_its_candidates_key():
    """The builder's key and the pipeline's are computed by the one owner from the same
    fields: a point's context id is its candidate's."""
    point = _gated_points("search")[0]
    ev = _reqctx().stamp({"rule_id": "R", "category": "xss", **_reqctx().point_evidence(point)},
                      None)
    assert _reqctx().point_key(point)[0] == _reqctx().context_id(json.loads(json.dumps(ev)))


def _unclassified(cls) -> set[str]:
    fields = {f.name for f in dataclasses.fields(cls)}
    return fields - set(_reqctx().CANDIDATE_FIELDS_IN_IDENTITY) \
        - set(_reqctx().CANDIDATE_FIELDS_EXCLUDED)


def test_every_candidate_field_is_in_the_identity_or_excluded():
    """PA-0530(2): a field a strategy or sender can read is in the request context or
    excluded with a reason, never neither (and never both)."""
    assert _unclassified(Candidate) == set()
    assert not set(_reqctx().CANDIDATE_FIELDS_IN_IDENTITY) & \
        set(_reqctx().CANDIDATE_FIELDS_EXCLUDED)


def test_the_field_guard_catches_a_synthetic_offender():
    @dataclasses.dataclass
    class Wider(Candidate):
        replay_token: str | None = None
    assert _unclassified(Wider) == {"replay_token"}


_STRATEGIES = Path(__file__).resolve().parent.parent / "fuzzlab/oracle/strategies.py"
#: Candidate fields holding (or derived from) the target's original value.
_SEED_FIELDS = frozenset({"base_entries", "base_value", "redirect_seed"})
#: Strategies that read one of them without sending the target's original value, why.
_SEED_EXEMPT = {
    "DomXssStrategy": "passes the siblings to the browser's binder, which replaces the "
                      "target's slot with the payload",
}


def _seed_readers(source: str) -> dict[str, str]:
    """``{class: category}`` of every class reading ``candidate.<seed field>``, with its
    category inherited through the module's own class bases."""
    tree = ast.parse(source)
    classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}

    def category(name: str) -> str | None:
        node = classes.get(name)
        if node is None:
            return None
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "category" for t in stmt.targets) \
                    and isinstance(stmt.value, ast.Constant):
                return stmt.value.value
        for base in node.bases:
            if isinstance(base, ast.Name) and (found := category(base.id)) is not None:
                return found
        return None

    out = {}
    for name, node in classes.items():
        if any(isinstance(n, ast.Attribute) and n.attr in _SEED_FIELDS
               and isinstance(n.value, ast.Name) and n.value.id == "candidate"
               for n in ast.walk(node)):
            out[name] = category(name)
    return out


def test_the_seed_categories_are_the_strategies_that_read_the_original_value():
    readers = _seed_readers(_STRATEGIES.read_text(encoding="utf-8"))
    assert readers, "the guard must see the strategies"
    want = {cat for cls, cat in readers.items() if cls not in _SEED_EXEMPT}
    assert want == set(_reqctx().SEED_CATEGORIES)
    assert set(_SEED_EXEMPT) <= set(readers)          # no stale exemption


def test_the_seed_guard_catches_a_synthetic_offender():
    src = ("class ConfirmationStrategy:\n    category = ''\n"
           "class Leaky(ConfirmationStrategy):\n    category = 'ssti'\n"
           "    def confirm(self, candidate, sender):\n"
           "        return candidate.base_value\n")
    assert _seed_readers(src) == {"Leaky": "ssti"}
