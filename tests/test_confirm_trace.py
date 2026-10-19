"""FR-FUZZ-62 (CC-FUZZ-0102, BUG-0520, PA-0520): the browser (M6) and out-of-band (M8)
confirmations record each step they perform.

BUG-0520: the diagrams said M6 "records its HTTP sends"; it recorded none. Its store
request and its page's requests reach the target through the Playwright driver and
Chromium, never a sender, and PA-0513's independent count had never run with a browser.
Now each M6 visit records its store, observe navigation, first refusal, ``load``,
sentinel, page counts and result, and each out-of-band wait records its callback or
its absence, correlated by test and strategy. Nothing they record changes what is sent
or any verdict (T7). Everything here is loopback (`tests.test_navigation_aborts._Site`,
a loopback app, `OobListener`); a real Chromium is needed for the M6 tests, and with
``FUZZLAB_REQUIRE_BROWSER=1`` its absence fails them.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
import threading
import types
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus, urlsplit

import pytest

from fuzzlab.core import trace
from fuzzlab.core.store import Store
from fuzzlab.oracle.browser import SENTINEL, ExecRequest, StoreStep
from fuzzlab.oracle.probe import Candidate, Probe, ProbeUnobserved, UnplaceableLocation
from fuzzlab.report import diagram
from tests.test_navigation_aborts import _chromium_or_skip, _Site

ROOT = Path(__file__).resolve().parents[1]
STRATEGY = "xss-dom:browser-execution"
SETTLE = 400
FIRE = f"<img src=x onerror=\"{SENTINEL}('tok')\">"
DOM_PAGE = ("<html><body><div id=o></div><script>document.getElementById('o')"
            ".innerHTML = new URLSearchParams(location.search).get('q') || ''"
            "</script></body></html>")
FRAG_PAGE = ("<html><body><div id=o></div><script>document.getElementById('o')"
             ".innerHTML = new URLSearchParams(location.hash.slice(1)).get('q') || ''"
             "</script></body></html>")


class _Raising(trace.TraceRecorder):
    """A recorder that fails on the two kinds this change adds (T7): their emits are
    contained; the run's other emits are not, and are outside this change."""

    def emit(self, kind, body, **kw):
        if kind in ("browser.step", "oob.wait"):
            raise RuntimeError("the trace failed")
        return super().emit(kind, body, **kw)


def _recorder(mode, store, run):
    return None if mode == "off" else (_Raising if mode == "raise" else
                                       trace.TraceRecorder)(store, run)


def _bodies(store, run, kinds=("browser.step", "oob.wait")):
    marks = ",".join("?" * len(kinds))
    return [(r["key"], r["seq"], r["t"], r["kind"], json.loads(r["body"]))
            for r in store.conn.execute(
                f"SELECT key, seq, t, kind, body FROM trace_event WHERE run_id=? AND "
                f"kind IN ({marks}) ORDER BY seq", (run, *kinds))]


@pytest.fixture
def site():
    s = _Site()
    s.pages["/dom"] = DOM_PAGE
    s.pages["/frag"] = FRAG_PAGE
    s.pages["/escaped"] = "<html><body><p>nothing runs</p></body></html>"
    # the sink runs 900 ms after `load` (the browser's own clock)
    s.pages["/slow"] = (f"<html><body><script>window.addEventListener('load', () => "
                        f"setTimeout(() => window.{SENTINEL}('tok'), 900))"
                        f"</script></body></html>")
    # the sink runs while the page is parsed; `load` waits for a 500 ms image
    s.pages["/parse"] = (f"<html><body><script>window.{SENTINEL}('tok')</script>"
                         f"<img src='/slowimg.png'></body></html>")
    s.delays["/slowimg.png"] = 0.5
    s.pages["/inline"] = ("<html><body><script>location.href = '/logout.php'</script>"
                          "<p>x</p></body></html>")
    s.pages["/early"] = ("<html><body><script>window.addEventListener('load', () => "
                         "location.href = '/logout.php')</script></body></html>")
    s.pages["/oos"] = ("<html><body><img src='http://127.0.0.2:9/x.png'><script>"
                       "try { new WebSocket('ws://127.0.0.2:9/ws') } catch (e) {}"
                       "</script></body></html>")
    s.pages["/sub"] = ("<html><body><img src='/img.png'><script>fetch('/api')</script>"
                       "</body></html>")
    s.pages["/subhop"] = "<html><body><img src='/imghop'></body></html>"
    s.pages["/landing"] = "<html><body>landed</body></html>"
    s.redirects["/imghop"] = "/img2.png"
    s.redirects["/hop"] = "/landing"
    s.redirects["/redir"] = "/logout.php"
    yield s
    s.close()


def _run_executor(req, settle):
    from tests._browser import skip_or_fail
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    ex = PlaywrightBrowserExecutor(timeout_ms=8000)
    ex.SETTLE_MS = settle
    try:
        return ("returned", ex.run(req, "tok").executed)
    except UnplaceableLocation as exc:
        if str(exc).startswith("browser unavailable"):
            skip_or_fail(f"chromium could not launch: {exc}")
        return ("raised", type(exc).__name__)


def _visit(tmp_path, site, req, *, mode="rec", settle=SETTLE, name="v"):
    """One real M6 visit inside test ``t1`` and the DOM strategy's scope."""
    site.log.clear()
    with Store(tmp_path / f"{name}-{mode}.db") as store:
        run = store.start_run("auto", "h")
        rec = _recorder(mode, store, run)
        with trace.recording(rec), trace.test_scope("t1"), \
                trace.strategy_scope(STRATEGY):
            outcome = _run_executor(req, settle)
            steps = trace.collected_steps()
        if rec is not None:
            rec.close()
        events = _bodies(store, run)
        seq = diagram.sequence(store.conn, run, "test:t1")
        mermaid = diagram.mermaid_sequence(seq)
    by = {}
    for _k, _s, _t, _kind, b in events:
        by.setdefault(b["step"], []).append(b)
    return {"outcome": outcome, "steps": steps, "events": events, "by": by,
            "server": list(site.log), "seq": seq, "mermaid": mermaid}


def _labels(v):
    return [s["label"] for s in v["seq"]["steps"]]


# --- T1 ---------------------------------------------------------------------------------
def test_an_m6_visit_records_each_step_where_it_happens(monkeypatch, tmp_path, site):
    _chromium_or_skip(monkeypatch)
    v = _visit(tmp_path, site, ExecRequest(url=site.base + "dom", param="q", value=FIRE))
    assert v["outcome"] == ("returned", True)
    names = [b["step"] for *_x, b in v["events"]]
    assert sorted(names) == ["end", "load", "navigate", "page", "sentinel"]
    assert names[-2:] == ["page", "end"]
    visits = {b["visit"] for *_x, b in v["events"]}
    assert len(visits) == 1
    for *_x, b in v["events"]:                  # each correlated by the context
        assert b["test"] == "t1" and b["strategy"] == STRATEGY
    assert [k for k, *_x in v["events"]] == v["steps"]       # the strategy cites them
    nav = v["by"]["navigate"][0]
    assert (nav["outcome"], nav["status"], nav["param"], nav["value_sent"]) == \
        ("response", 200, "q", True)
    assert nav["url"] == trace.safe_ref(site.base + "dom")
    assert nav["value_preview"] == FIRE
    assert v["by"]["load"][0]["outcome"] == "fired"
    assert v["by"]["end"][0]["outcome"] == "executed"
    assert v["by"]["page"][0]["answered"] == 2             # the page and its image
    # the order is judged by the page's own construction (the browser's clock), not by
    # the recorder: a sink 900 ms after `load`, and one during the parse, before it
    slow = _visit(tmp_path, site, ExecRequest(url=site.base + "slow", param="q",
                                              value="x"), settle=2500, name="slow")
    assert slow["outcome"] == ("returned", True)
    assert slow["by"]["sentinel"][0]["after_load_ms"] >= 800
    parse = _visit(tmp_path, site, ExecRequest(url=site.base + "parse", param="q",
                                               value="x"), name="parse")
    assert parse["outcome"] == ("returned", True)
    assert parse["by"]["sentinel"][0]["after_load_ms"] <= diagram.STAMP_RESOLUTION_MS


# --- T2 ---------------------------------------------------------------------------------
def test_a_sink_that_never_fires_ends_not_executed_with_its_window(monkeypatch, tmp_path,
                                                                   site):
    _chromium_or_skip(monkeypatch)
    v = _visit(tmp_path, site, ExecRequest(url=site.base + "escaped", param="q",
                                           value=FIRE))
    assert v["outcome"] == ("returned", False)
    assert "sentinel" not in v["by"]
    end = v["by"]["end"][0]
    assert end["outcome"] == "not_executed" and end["window_ms"] == SETTLE
    assert end["waited_ms"] >= SETTLE * 0.9
    labels = _labels(v)
    assert any(lb.startswith(f"the sentinel did not fire within {SETTLE} ms")
               for lb in labels)
    assert not any("payload executed" in lb or lb == "visit result: executed"
                   for lb in labels)
    assert "sentinel fired" not in v["mermaid"]


# --- T3 ---------------------------------------------------------------------------------
def test_refused_navigations_are_recorded_and_drawn_never_sent(monkeypatch, tmp_path,
                                                               site):
    _chromium_or_skip(monkeypatch)
    logout = trace.safe_ref(site.base + "logout.php")
    early = _visit(tmp_path, site, ExecRequest(url=site.base + "early", param="q",
                                               value="x"), name="early")
    (ref,) = early["by"]["refused"]
    assert (ref["url"], ref["detail"], ref["outcome"]) == (logout, "logout", "not_sent")
    assert early["by"]["end"][0]["outcome"] == "not_executed"
    assert not any("/logout.php" in p for _m, p in early["server"])
    blocked = [s for s in early["seq"]["steps"] if s.get("kind") == "blocked"]
    assert blocked and blocked[0]["type"] == "lost"
    assert blocked[0]["label"] == "refused by the guard, never sent: /logout.php (logout)"
    inline = _visit(tmp_path, site, ExecRequest(url=site.base + "inline", param="q",
                                                value="x"), name="inline")
    assert inline["outcome"] == ("raised", "NotObserved")
    assert inline["by"]["load"][0] == inline["by"]["load"][0] | {
        "outcome": "not_fired", "superseded": True}
    assert inline["by"]["refused"][0]["url"] == logout
    redir = _visit(tmp_path, site, ExecRequest(url=site.base + "redir", param="q",
                                               value="x"), name="redir")
    assert redir["outcome"] == ("raised", "NotObserved")
    assert redir["by"]["navigate"][0]["outcome"] == "error"
    assert redir["by"]["refused"][0]["url"] == logout and "load" not in redir["by"]
    assert redir["by"]["page"][0]["failed"] == 1           # `/redir` itself was sent
    oos = _visit(tmp_path, site, ExecRequest(url=site.base + "oos", param="q",
                                             value="x"), name="oos")
    page = oos["by"]["page"][0]
    assert (page["refused"], page["failed"]) == (2, 0)     # the image and the WebSocket
    assert oos["by"]["refused"][0]["detail"] == "out of scope"
    assert oos["by"]["refused"][0]["url"] in ("http://127.0.0.2:9/x.png",
                                              "ws://127.0.0.2:9/ws")


# --- T4 ---------------------------------------------------------------------------------
def test_a_page_that_never_loads_ends_not_observed(monkeypatch, tmp_path, site):
    _chromium_or_skip(monkeypatch)
    inline = _visit(tmp_path, site, ExecRequest(url=site.base + "inline", param="q",
                                                value="x"), name="inline")
    end = inline["by"]["end"][0]
    assert end["outcome"] == "not_observed" and end["waited_ms"] >= 0      # waited
    assert "did not finish loading" in end["detail"]
    assert any(lb.startswith("not observed: the page committed")
               for lb in _labels(inline))
    redir = _visit(tmp_path, site, ExecRequest(url=site.base + "redir", param="q",
                                               value="x"), name="redir")
    end = redir["by"]["end"][0]
    assert end["outcome"] == "not_observed" and "waited_ms" not in end    # no wait ran
    assert "sentinel" not in redir["by"] and "sentinel" not in inline["by"]


# --- T5 ---------------------------------------------------------------------------------
STORES = {
    "form": StoreStep(url="st", param="c", value="v", method="POST", location="body"),
    "json": StoreStep(url="api", param="content", value="v", method="POST",
                      location="json", entries=((("content",), "hi"), (("user",), "u"))),
    "query": StoreStep(url="st", param="c", value="v", method="GET", location="query"),
}


def _stored(site, kind):
    s = STORES[kind]
    return ExecRequest(url=site.base + "escaped", store=StoreStep(
        url=site.base + s.url, param=s.param, value=s.value, method=s.method,
        location=s.location, entries=s.entries))


def test_each_store_kind_records_its_request(monkeypatch, tmp_path, site):
    _chromium_or_skip(monkeypatch)
    for kind, method in (("form", "POST"), ("json", "POST"), ("query", "GET")):
        v = _visit(tmp_path, site, _stored(site, kind), name=kind)
        (store,) = v["by"]["store"]
        assert (store["outcome"], store["status"], store["method"], store["location"]) \
            == ("response", 200, method, STORES[kind].location), kind
        names = [b["step"] for *_x, b in v["events"]]
        assert names.index("store") < names.index("navigate")
        assert any(lb.startswith(f"[store] {method} /") for lb in _labels(v))
    # a fetch that returns no status (a test double): never drawn as a reply
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _fake_pw(monkeypatch)
    with Store(tmp_path / "double.db") as db:
        run = db.start_run("auto", "h")
        rec = trace.TraceRecorder(db, run)
        with trace.recording(rec), trace.test_scope("t1"), \
                trace.strategy_scope(STRATEGY):
            PlaywrightBrowserExecutor().run(_stored(site, "form"), "tok")
        rec.close()
        (store,) = [b for *_x, b in _bodies(db, run) if b["step"] == "store"]
        steps = diagram.sequence(db.conn, run, "test:t1")["steps"]
    assert store["outcome"] == "no_status" and "status" not in store
    drawn = [s for s in steps if "[store]" in s["label"]]
    after = steps[steps.index(drawn[0]) + 1]
    assert after["type"] == "note" and after["label"] == "request made; no status recorded"


# --- T6 ---------------------------------------------------------------------------------
def test_the_traced_browser_sends_match_what_the_server_received(monkeypatch, tmp_path,
                                                                 site):
    """The FR-FUZZ-62 equation: per visit, the server received the API store requests,
    plus what the page answered and failed (refusals never), plus the redirect hops the
    browser guard fetched itself -- the asserted, documented gap."""
    _chromium_or_skip(monkeypatch)
    cases = [("sub", ExecRequest(url=site.base + "sub", param="q", value="x"), 0),
             ("subhop", ExecRequest(url=site.base + "subhop", param="q", value="x"), 1),
             ("hop", ExecRequest(url=site.base + "hop", param="q", value="x"), 1),
             ("redir", ExecRequest(url=site.base + "redir", param="q", value="x"), 0),
             ("early", ExecRequest(url=site.base + "early", param="q", value="x"), 0),
             ("fragment", ExecRequest(url=site.base + "frag", param="q", value="x",
                                      location="fragment"), 0),
             ("form", _stored(site, "form"), 0), ("json", _stored(site, "json"), 0),
             ("query", _stored(site, "query"), 0)]
    for name, req, hops in cases:
        v = _visit(tmp_path, site, req, name=name)
        api = sum(1 for b in v["by"].get("store", [])
                  if b["location"] in ("body", "json") and b["outcome"] != "not_sent")
        (page,) = v["by"]["page"]
        assert len(v["server"]) == api + page["answered"] + page["failed"] + hops, \
            (name, v["server"], page)
    # the gap is the guard's own hop fetch: the landing reached the server twice
    hop = _visit(tmp_path, site, cases[2][1], name="hop2")
    assert [p for _m, p in hop["server"]].count("/landing") == 2
    assert hop["by"]["page"][0]["answered"] == 2


# --- T7 ---------------------------------------------------------------------------------
def _server(v):
    return Counter((m, p.split("?")[0]) for m, p in v["server"])


def test_tracing_changes_nothing_sent_and_no_verdict(monkeypatch, tmp_path, site,
                                                     auto_runs):
    """Each case with no recorder, with a recorder, and with a recorder that fails on
    the new kinds: the same requests reach the server, and the same results come back."""
    _chromium_or_skip(monkeypatch)
    cases = {"dom": ExecRequest(url=site.base + "dom", param="q", value=FIRE),
             "escaped": ExecRequest(url=site.base + "escaped", param="q", value=FIRE),
             "slow": ExecRequest(url=site.base + "slow", param="q", value="x"),
             "early": ExecRequest(url=site.base + "early", param="q", value="x"),
             "inline": ExecRequest(url=site.base + "inline", param="q", value="x"),
             "redir": ExecRequest(url=site.base + "redir", param="q", value="x"),
             "form": _stored(site, "form"),
             "header": ExecRequest(url=site.base + "escaped", param="q", value="x",
                                   location="header")}
    for name, req in cases.items():
        seen = {mode: _visit(tmp_path, site, req, mode=mode, settle=2500
                             if name == "slow" else SETTLE, name=name)
                for mode in ("off", "rec", "raise")}
        assert seen["off"]["outcome"] == seen["rec"]["outcome"] == \
            seen["raise"]["outcome"], name
        assert _server(seen["off"]) == _server(seen["rec"]) == _server(seen["raise"]), name
        assert seen["off"]["events"] == seen["raise"]["events"] == []
        assert seen["rec"]["events"]
    for strategy, delay in (("ssrf", 0.2), ("ssrf", None), ("cmdi", 0.2)):
        seen = {mode: _oob(tmp_path, strategy, delay, mode) for mode in
                ("off", "rec", "raise")}
        for key in ("verdict", "hits", "sent"):
            assert seen["off"][key] == seen["rec"][key] == seen["raise"][key], \
                (strategy, delay, key)
        assert seen["rec"]["waits"] and not seen["raise"]["waits"]
    off, rec, raising = auto_runs["off"], auto_runs["rec"], auto_runs["raise"]
    for key in ("verdicts", "findings", "statuses", "requests", "server", "hits"):
        assert off[key] == rec[key] == raising[key], key


# --- T8 ---------------------------------------------------------------------------------
JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
SECRETS = ("hunter2pw", "SESS0123456789abcdef", JWT, "FRAG0123456789abcdef",
           "PASSVALUE0123")


def _walk(value, key=None):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v, key)
    elif isinstance(value, str):
        yield key, value


def test_browser_and_oob_steps_withhold_every_token_shape(monkeypatch, tmp_path):
    """PA-0514(2), PA-0521: userinfo, a matrix parameter, a path token, a query-shaped
    fragment and a sensitive parameter's value never reach a step; a canary path is
    kept only under ``url`` (`scrub_event` passes a relative ``/cb/<token>`` under any
    other key)."""
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _fake_pw(monkeypatch)
    url = (f"http://user:hunter2pw@127.0.0.1:3000/a;jsessionid=SESS0123456789abcdef/"
           f"{JWT}/view#access_token=FRAG0123456789abcdef")
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        rec = trace.TraceRecorder(store, run)
        with trace.recording(rec), trace.test_scope("t1"), \
                trace.strategy_scope(STRATEGY):
            PlaywrightBrowserExecutor().run(ExecRequest(
                url=url, param="password", value="PASSVALUE0123", store=None), "tok")
            PlaywrightBrowserExecutor().run(ExecRequest(url=url, store=StoreStep(
                url=url, param="password", value="PASSVALUE0123")), "tok")
        rec.close()
        events = _bodies(store, run)
    blob = json.dumps([b for *_x, b in events])
    assert events and not [s for s in SECRETS if s in blob]
    assert all(b.get("value_preview") is None for *_x, b in events)
    oob = _oob(tmp_path, "ssrf", 0.05, "rec")
    assert oob["waits"]
    for *_x, b in oob["waits"]:
        for key, text in _walk(b):
            assert "/cb/" not in text or key == "url", (key, text)


# --- T9 ---------------------------------------------------------------------------------
DOUBLES = [
    ("tests.test_browser_scope",
     "test_the_m6_browser_is_launched_scoped_and_plants_without_redirects"),
    ("tests.test_destructive_urls",
     "test_the_m6_browser_aborts_destructive_subresources_but_loads_its_targets"),
    ("tests.test_json_points", "test_the_executor_places_a_fragment_inside_the_hash_route"),
    ("tests.test_m6_navigation_failures",
     "test_a_playwright_error_is_no_verdict_and_names_no_url"),
    ("tests.test_m6_navigation_failures", "test_any_other_error_is_not_swallowed"),
    ("tests.test_m6_navigation_failures",
     "test_a_driver_that_never_stops_cleanly_makes_the_browser_unavailable"),
    ("tests.test_m6_navigation_failures", "test_a_failed_driver_stop_keeps_the_result"),
]


@pytest.mark.parametrize("module,name", DOUBLES, ids=[n for _m, n in DOUBLES])
def test_the_fake_playwright_doubles_run_unchanged_under_a_recorder(
        tmp_path, module, name):
    """Every fake Playwright the executor's tests use (R4) runs unchanged under a
    recorder, and its visits are recorded."""
    import importlib
    fn = getattr(importlib.import_module(module), name)
    kwargs = {}
    with pytest.MonkeyPatch.context() as mp, Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        rec = trace.TraceRecorder(store, run)
        params = inspect.signature(fn).parameters
        if "monkeypatch" in params:
            kwargs["monkeypatch"] = mp
        if "tmp_path" in params:
            (tmp_path / "inner").mkdir()
            kwargs["tmp_path"] = tmp_path / "inner"
        with trace.recording(rec):
            fn(**kwargs)
        rec.close()
        events = _bodies(store, run)
    assert any(b["step"] == "end" for *_x, b in events)
    if name == "test_any_other_error_is_not_swallowed":
        assert [b["detail"] for *_x, b in events if b["step"] == "end"] == ["KeyError"]


def test_a_launch_failure_is_one_failed_launch_step(monkeypatch, tmp_path):
    """A browser or driver that cannot start: one ``launch`` step with its class only,
    and ``end`` ``unplaceable`` with the fixed phrase; then ``_unavailable``'s own
    phrase. The exception's text (the driver's first line) is never recorded."""
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    for where in ("launch", "enter"):
        _fake_pw(monkeypatch, **{f"{where}_error": RuntimeError(
            "boom /home/secret/chrome: cannot open shared object")})
        with Store(tmp_path / f"{where}.db") as store:
            run = store.start_run("auto", "h")
            rec = trace.TraceRecorder(store, run)
            ex = PlaywrightBrowserExecutor()
            with trace.recording(rec), trace.test_scope("t1"), \
                    trace.strategy_scope(STRATEGY):
                for _ in range(ex.MAX_LAUNCH_FAILURES + 1):
                    with pytest.raises(UnplaceableLocation):
                        ex.run(ExecRequest(url="http://127.0.0.1:3000/a", param="q",
                                           value="x"), "tok")
            rec.close()
            events = [b for *_x, b in _bodies(store, run)]
        launches = [b for b in events if b["step"] == "launch"]
        ends = [b["detail"] for b in events if b["step"] == "end"]
        assert [(b["outcome"], b["error"]) for b in launches] == \
            [("failed", "RuntimeError")] * ex.MAX_LAUNCH_FAILURES, where
        assert ends == ["browser unavailable (RuntimeError)"] * ex.MAX_LAUNCH_FAILURES \
            + ["browser unavailable for this run"], where
        assert "boom" not in json.dumps(events) and "secret" not in json.dumps(events)


def test_a_placement_refusal_ends_unplaceable_at_the_refusal(monkeypatch, tmp_path):
    """The executor's refusals before any browser starts return
    ``ExecObservation(False, …)`` as before; their visit records the request as not
    sent and ends ``unplaceable`` at the refusal, never "not executed" (which would be
    drawn "did not fire")."""
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _fake_pw(monkeypatch)
    url = "http://127.0.0.1:3000/a"
    refused = {"navigate": ExecRequest(url=url, param="q", value="x", location="header"),
               "store": ExecRequest(url=url, store=StoreStep(
                   url=url, param="c", value="x", method="DELETE"))}
    for step, req in refused.items():
        with Store(tmp_path / f"{step}.db") as store:
            run = store.start_run("auto", "h")
            rec = trace.TraceRecorder(store, run)
            with trace.recording(rec), trace.test_scope("t1"), \
                    trace.strategy_scope(STRATEGY):
                obs = PlaywrightBrowserExecutor().run(req, "tok")
            rec.close()
            events = [b for *_x, b in _bodies(store, run)]
            labels = [s["label"] for s in diagram.sequence(store.conn, run,
                                                           "test:t1")["steps"]]
        assert obs.executed is False and "unplaceable" in obs.detail     # unchanged
        assert [(b["step"], b["outcome"]) for b in events] == \
            [(step, "not_sent"), ("end", "unplaceable")]
        assert not any("did not fire" in lb for lb in labels)
        assert labels[-1].startswith("not placed: unplaceable")


def _fake_pw(monkeypatch, *, launch_error=None, enter_error=None):
    """A fake Playwright whose API request returns no response object."""
    import sys

    class Page:
        def on(self, *a):
            pass

        def once(self, *a):
            pass

        def goto(self, url, **kw):
            return None

        def wait_for_load_state(self, state, **kw):
            pass

        def wait_for_timeout(self, ms):
            pass

    class Context:
        request = types.SimpleNamespace(fetch=lambda *a, **k: None)
        pages: list = []

        def expose_binding(self, name, fn):
            pass

        def route(self, pattern, handler):
            pass

        def route_web_socket(self, pattern, handler):
            pass

        def new_page(self):
            return Page()

    class Browser:
        def new_context(self, **kw):
            return Context()

        def close(self):
            pass

    def launch(**kw):
        if launch_error is not None:
            raise launch_error
        return Browser()

    class PW:
        chromium = types.SimpleNamespace(launch=launch)

        def __enter__(self):
            if enter_error is not None:
                raise enter_error
            return self

        def __exit__(self, *a):
            return False
    fake = types.ModuleType("playwright.sync_api")
    fake.sync_playwright = PW
    fake.Error = type("Error", (Exception,), {})
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake)
    monkeypatch.setattr("fuzzlab.tools.browserexec.PlaywrightBrowserExecutor.SETTLE_MS", 0)


# --- M8: T11, T12, T14, T15 ------------------------------------------------------------
CANARY = re.compile(r"http://127\.0\.0\.1:\d+/cb/[0-9a-f]+")


class _Target:
    """A blind target: it fetches any canary in a value ``delay`` seconds later (None:
    never). Nothing in its HTTP response is read by the out-of-band checks."""

    def __init__(self, delay):
        self.delay, self.sent, self.timers = delay, 0, []

    def send(self, url, param, value, **kw):
        self.sent += 1
        m = CANARY.search(str(value or ""))
        if m and self.delay is not None:
            t = threading.Timer(self.delay, lambda u=m.group(0): urllib.request.urlopen(
                u, timeout=2).read())
            t.start()
            self.timers.append(t)
        return Probe(200, "<html>ok</html>")


def _oob(tmp_path, strategy, delay, mode, timeout=None):
    from fuzzlab.harness.tracing import TracingSender
    from fuzzlab.oracle.oob import OobListener
    from fuzzlab.oracle.strategies import (CommandInjectionOobStrategy, SsrfOobStrategy,
                                           XxeOobStrategy)
    listener = OobListener()
    listener.start()
    target = _Target(delay)
    wait = timeout if timeout is not None else (1.5 if delay is not None else 0.4)
    cls, cand = {
        "ssrf": (SsrfOobStrategy, Candidate("http://127.0.0.1:9/f", "url",
                                            vuln_class="ssrf", category="ssrf")),
        "cmdi": (CommandInjectionOobStrategy, Candidate(
            "http://127.0.0.1:9/p", "host", vuln_class="command-injection",
            category="command-injection")),
        "xxe": (XxeOobStrategy, Candidate("http://127.0.0.1:9/x", "body", method="POST",
                                          location="body", vuln_class="xxe",
                                          category="xxe")),
    }[strategy]
    name = f"{strategy}:{cls.mechanism}"
    db = tmp_path / f"oob-{strategy}-{delay}-{mode}-{len(list(tmp_path.iterdir()))}.db"
    try:
        with Store(db) as store:
            run = store.start_run("auto", "h")
            rec = _recorder(mode, store, run)
            with trace.recording(rec), trace.test_scope("t1"), trace.strategy_scope(name):
                verdict = cls(listener, timeout=wait).confirm(cand, TracingSender(target))
                steps = trace.collected_steps()
            for t in target.timers:
                t.join()
            if rec is not None:
                rec.close()
            events = _bodies(store, run, ("exchange", "oob.wait"))
            seq = diagram.sequence(store.conn, run, "test:t1")
            tokens = {tok: [h.received_at for h in listener.hits(tok)]
                      for tok in list(listener._hits)}
            blob = _everything(store, run)
    finally:
        listener.stop()
    waits = [e for e in events if e[3] == "oob.wait"]
    return {"verdict": None if verdict is None else verdict.confirmed,
            "hits": sum(len(v) for v in tokens.values()), "sent": target.sent,
            "events": events, "waits": waits, "steps": steps, "seq": seq,
            "tokens": tokens, "blob": blob}


def _everything(store, run) -> str:
    """The trace, the model and every diagram export of a run, as one text."""
    conn = store.conn
    parts = [r[0] for r in conn.execute("SELECT body FROM trace_event WHERE run_id=?",
                                        (run,))]
    for table in ("dg_entity", "dg_flow"):
        parts += [json.dumps(dict(r)) for r in conn.execute(
            f"SELECT * FROM {table} WHERE run_id=?", (run,))]
    model = diagram.export_json(conn, run)
    parts += [json.dumps(model), diagram.mermaid_flow(model)]
    for s in diagram.scopes(conn, run):
        parts.append(diagram.mermaid_sequence(diagram.sequence(conn, run, s["scope"])))
        parts.append(json.dumps(diagram.sequence(conn, run, s["scope"])))
    return "\n".join(parts)


def test_an_oob_wait_records_the_callback_at_the_listeners_stamp(tmp_path):
    out = _oob(tmp_path, "ssrf", 0.2, "rec")
    assert out["verdict"] is True
    (exchange,), (wait,) = [e for e in out["events"] if e[3] == "exchange"], out["waits"]
    key, seq, t, _kind, body = wait
    (stamps,) = [v for v in out["tokens"].values() if v]
    assert t == stamps[0]                              # the handler's own stamp
    assert body["outcome"] == "received" and body["remote"] == "127.0.0.1"
    assert 150 <= body["after_wait_ms"] <= 1400        # the target's 200 ms delay
    assert body["window_ms"] == 1500.0 and body["test"] == "t1"
    assert exchange[1] < seq and out["steps"] == [key]
    drawn = [s for s in out["seq"]["steps"] if s.get("kind") == "callback"]
    assert drawn[0]["type"] == "message"
    assert drawn[0]["label"].startswith("callback received from 127.0.0.1 (+")


def test_no_callback_within_the_window_is_recorded_and_drawn_as_absence(tmp_path):
    out = _oob(tmp_path, "ssrf", None, "rec")
    assert out["verdict"] is None and out["hits"] == 0
    (wait,) = out["waits"]
    body = wait[4]
    assert body["outcome"] == "none" and body["after_wait_ms"] is None
    assert body["waited_ms"] >= 380 and body["remote"] is None
    steps = out["seq"]["steps"]
    assert not any(s.get("kind") == "callback" for s in steps)
    assert [s["label"] for s in steps if s.get("kind") == "absence"] == \
        [f"no callback within 0.4 s (waited {body['waited_ms']} ms)"]


def test_the_canary_token_never_reaches_the_trace_the_model_or_the_exports(tmp_path):
    """"The exports" are the diagram exports (`export_json`, Mermaid); the ``finding``
    table's evidence JSON is out of scope."""
    for strategy in ("ssrf", "cmdi", "xxe"):
        out = _oob(tmp_path, strategy, 0.05, "rec")
        assert out["verdict"] is True and out["waits"], strategy
        hit = [tok for tok, v in out["tokens"].items() if v]
        assert hit
        for tok in out["tokens"]:
            assert tok not in out["blob"], strategy


def test_the_oob_helper_takes_listener_doubles_without_received_at(tmp_path):
    """`tests/test_probe_unobserved.py`'s listener doubles (no ``received_at``, no
    ``hits()``) give the same verdicts with a recorder, and a wait with no time."""
    from fuzzlab.oracle.strategies import (CommandInjectionOobStrategy, SsrfOobStrategy,
                                           XxeOobStrategy)
    from tests.test_probe_unobserved import _DeadSender, _Listener

    class Hit(_Listener):
        def wait_for(self, token, timeout=0.0):
            return type("H", (), {"path": "/cb/tok", "remote_addr": "127.0.0.1"})()

    cases = ((CommandInjectionOobStrategy, Candidate("http://127.0.0.1:9/p", "q")),
             (SsrfOobStrategy, Candidate("http://127.0.0.1:9/p", "q")),
             (XxeOobStrategy, Candidate("http://127.0.0.1:9/p", "body", method="POST",
                                        location="body")))
    for traced in (False, True):
        with Store(tmp_path / f"d{traced}.db") as store:
            run = store.start_run("auto", "h")
            rec = trace.TraceRecorder(store, run) if traced else None
            with trace.recording(rec), trace.test_scope("t1"):
                for cls, cand in cases:
                    with trace.strategy_scope(cls.mechanism):
                        verdict = cls(Hit()).confirm(cand, _DeadSender())
                        assert verdict is not None and verdict.confirmed
                        with pytest.raises(ProbeUnobserved):
                            cls(_Listener()).confirm(cand, _DeadSender())
            if rec is not None:
                rec.close()
            waits = [b for *_x, b in _bodies(store, run, ("oob.wait",))]
        if traced:
            # each strategy: one wait that got the double's hit, then one wait per
            # template that got none (command injection tries each of its templates)
            assert [w["outcome"] for w in waits].count("received") == 3
            assert [w["outcome"] for w in waits].count("none") >= 3
            assert {w["after_wait_ms"] for w in waits} == {None}
            assert {w["remote"] for w in waits if w["outcome"] == "received"} == \
                {"127.0.0.1"}
        else:
            assert waits == []


# --- P1, P2, P3 (PA-0520): every send of a run, counted by the server -----------------
class _ConfirmApp:
    """A loopback app with one point per sending path of `run_auto`: DOM sinks on a
    query and a fragment, three stored-XSS pairs (a form, a JSON and a query store),
    blind SSRF, command-injection and XXE sinks that fetch any canary they are given,
    and a record any account can read. It answers every request, logs each one, and
    redirects nothing (so the browser guard fetches no hop)."""

    def __init__(self):
        from fuzzlab.core.net import is_loopback_host
        assert is_loopback_host("127.0.0.1")
        self.log: list = []
        self.boards = {"1": [], "2": [], "3": []}
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, body, status=200, ctype="text/html"):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            @staticmethod
            def _fetch_canaries(text):
                for u in CANARY.findall(text or ""):
                    try:
                        urllib.request.urlopen(u, timeout=2).read()
                    except OSError:
                        pass

            def _board(self, n):
                self._send("<html><body>" + "".join(
                    f"<div>{x}</div>" for x in app.boards[n]) + "</body></html>")

            def _keep(self, n, value):
                if SENTINEL in value:              # only what the browser plants
                    app.boards[n].append(value)

            def do_GET(self):  # noqa: N802
                parts = urlsplit(self.path)
                app.log.append(("GET", parts.path))
                q = {k: v[0] for k, v in parse_qs(parts.query).items()}
                if parts.path == "/dom":
                    return self._send(DOM_PAGE)
                if parts.path == "/frag":
                    return self._send(FRAG_PAGE)
                if parts.path.startswith("/board"):
                    return self._board(parts.path[-1])
                if parts.path == "/add":
                    self._keep("3", q.get("c", ""))
                    return self._send(f"<html><body>{q.get('c', '')}</body></html>")
                if parts.path in ("/fetch", "/ping"):
                    value = q.get("url" if parts.path == "/fetch" else "host", "")
                    self._fetch_canaries(value)
                    return self._send(f"<html><body>{value}</body></html>")
                if parts.path == "/record":
                    rid = q.get("record_id", "")
                    if rid == "r-alice-1":
                        return self._send("<html>record r-alice-1 owner alice</html>")
                    return self._send(f"<html>no such record {rid}</html>", status=404)
                return self._send("<html>ok</html>")

            def do_POST(self):  # noqa: N802
                parts = urlsplit(self.path)
                app.log.append(("POST", parts.path))
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                text = raw.decode("utf-8", "replace")
                form = {k: v[0] for k, v in parse_qs(text).items()}
                if parts.path == "/post":
                    self._keep("1", form.get("c", ""))
                    return self._send(f"<html><body>{form.get('c', '')}</body></html>")
                if parts.path == "/api/msg":
                    try:
                        self._keep("2", str(json.loads(text).get("content", "")))
                    except (ValueError, AttributeError):
                        pass
                    return self._send('{"ok": true}', ctype="application/json")
                if parts.path.startswith("/board"):
                    return self._board(parts.path[-1])
                if parts.path == "/xml":
                    self._fetch_canaries(unquote_plus(text))
                    return self._send(f"<html><body>{form.get('xml', '')}</body></html>")
                return self._send("<html>ok</html>")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _ground_truth():
    from fuzzlab.labels.contract import Case, GroundTruth
    from fuzzlab.labels.contract import InjectionPoint as GtPoint

    def stored(cid, n, param, source):
        return Case(cid, f"/board{n}", "POST", param, "body", "xss-stored", "html",
                    True, "server", source_url=source)
    return GroundTruth(target="confirm-app", cases=[
        stored("S1", 1, "c", "/post"), stored("S2", 2, "content", "/api/msg"),
        stored("S3", 3, "c", "/add"),
        Case("X1", "/xml", "POST", "xml", "body", "xxe", "xml", True, "server")],
        points=[
            GtPoint("/dom", "GET", "q", "query", rendering="js"),
            GtPoint("/frag", "GET", "q", "fragment", rendering="js", client_only=True),
            GtPoint("/post", "POST", "c", "body"),
            GtPoint("/api/msg", "POST", "content", "body",
                    json_body={"content": "hi", "user": "u"}),
            GtPoint("/add", "GET", "c", "query"),
            GtPoint("/fetch", "GET", "url", "query"),
            GtPoint("/ping", "GET", "host", "query"),
            GtPoint("/xml", "POST", "xml", "body"),
            GtPoint("/record", "GET", "record_id", "query", account_value="record")])


#: The categories whose confirmations send through every sending keyword.
CATEGORIES = ["xss", "ssrf", "command-injection", "xxe", "access-control"]


def _auto_run(path, mode):
    """One `run_auto` (the layer that wraps the senders) over `_ConfirmApp`, with every
    sending keyword: ``sender``, ``browser``, ``oob`` and ``peer``."""
    from fuzzlab.harness.auto import run_auto
    from fuzzlab.oracle.oob import OobListener
    from fuzzlab.oracle.strategies import PeerAccounts
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    from fuzzlab.tools.probesender import RequestsProbeSender
    app = _ConfirmApp()
    listener = OobListener()
    listener.start()
    executor = PlaywrightBrowserExecutor(timeout_ms=8000)
    executor.SETTLE_MS = SETTLE
    store = Store(path / f"auto-{mode}.db")
    try:
        run = store.start_run("auto", "h")
        rec = _recorder(mode, store, run)
        with trace.recording(rec):
            result = run_auto(
                base_url=app.base + "/", store=store, run_id=run,
                sender=RequestsProbeSender(timeout=5.0), mode="manual",
                ground_truth=_ground_truth(), selected_categories=CATEGORIES,
                points_source="ground-truth", browser=executor, oob=listener,
                peer=PeerAccounts(sender=RequestsProbeSender(timeout=5.0),
                                  owner="alice", peer_name="bob",
                                  anonymous=RequestsProbeSender(timeout=5.0)),
                account_values={"record": "r-alice-1"}, trace_events=mode != "off")
        if rec is not None:
            rec.close()
        tokens = {tok: len(listener.hits(tok)) for tok in list(listener._hits)}
        conn = store.conn
        out = {
            "unavailable": executor._unavailable,
            "server": Counter(app.log), "n_server": len(app.log),
            "requests": result.metrics.get("requests"),
            "verdicts": (result.candidates, result.negatives, result.findings,
                         len(result.inconclusive)),
            "findings": sorted((r["vuln_class"], r["url"], r["param"]) for r in
                               conn.execute("SELECT vuln_class, url, param FROM finding "
                                            "WHERE run_id=?", (run,))),
            "statuses": sorted(Counter(r[0] for r in conn.execute(
                "SELECT oracle_status FROM candidate WHERE run_id=?", (run,))).items()),
            "hits": sorted(tokens.values()), "tokens": tokens,
            "events": [(r["kind"], json.loads(r["body"])) for r in conn.execute(
                "SELECT kind, body FROM trace_event WHERE run_id=? ORDER BY seq",
                (run,))]}
    finally:
        store.close()
        listener.stop()
        app.close()
    return out


@pytest.fixture(scope="module")
def auto_runs(tmp_path_factory):
    from tests._browser import skip_or_fail
    with pytest.MonkeyPatch.context() as mp:
        _chromium_or_skip(mp)
        runs = {mode: _auto_run(tmp_path_factory.mktemp(f"auto-{mode}"), mode)
                for mode in ("off", "rec", "raise")}
    for run in runs.values():
        if run["unavailable"]:
            skip_or_fail(f"chromium could not launch: {run['unavailable']}")
    return runs


def test_every_send_of_a_run_is_counted_by_the_server(auto_runs):
    """PA-0520 (strengthens PA-0513): through `run_auto`, with every sending keyword,
    the requests the app received equal the run's traced sends -- the senders'
    exchanges (each try), the M6 API stores and the M6 pages' answered and failed
    requests (the app redirects nothing, so the guard fetched no hop) -- and every
    out-of-band token the target called back is an ``oob.wait`` ``received``, but for
    the in-band marker checks' own tokens (the asserted gap)."""
    run = auto_runs["rec"]
    events = run["events"]
    exchanges = [b for k, b in events if k == "exchange" and b["outcome"] != "not_sent"]
    steps = [b for k, b in events if k == "browser.step"]
    api = sum(1 for b in steps if b["step"] == "store"
              and b["location"] in ("body", "json") and b["outcome"] != "not_sent")
    pages = sum(b["answered"] + b["failed"] for b in steps if b["step"] == "page")
    assert run["n_server"] == len(exchanges) + api + pages
    # every sending keyword really sent
    assert {b["identity"] for b in exchanges} >= {"bob", "anonymous"}
    assert {b["location"] for b in steps if b["step"] == "store"} == \
        {"body", "json", "query"}
    assert {b["value_sent"] for b in steps if b["step"] == "navigate"
            and b.get("param")} == {True, False}                # query and fragment
    waits = [b for k, b in events if k == "oob.wait"]
    received = [b for b in waits if b["outcome"] == "received"]
    assert {b["strategy"].split(":")[0] for b in received} == \
        {"ssrf", "command-injection", "xxe"}
    in_band = [b for k, b in events if k == "test.strategy"
               and "in-band" in (b["strategy"] or "")]
    hit = [tok for tok, n in run["tokens"].items() if n]
    assert len(hit) == len(received) + len(in_band)
    found = {f[0] for f in run["findings"]}
    assert {"xss-dom", "xss-stored", "ssrf", "command-injection", "xxe"} <= found


#: `run_auto`'s parameters, each classified by reading the code (P2). A sending
#: parameter is *wrapped* (its sends pass `TracingSender`) or *self-tracing* (its
#: producer records its own steps, FR-FUZZ-62); P1 passes every sending one.
SENDING_WRAPPED = {
    "sender": "the run's sender: rebound to TracingSender(sender) under a recorder",
    "peer": "the peer account's and the unauthenticated senders: each TracingSender",
}
SENDING_SELF = {
    "browser": "the M6 executor: each visit's browser.step events (FR-FUZZ-62)",
    "oob": "the OOB listener: each wait's oob.wait event (FR-FUZZ-62); the target's "
           "sends that carry its canary are the sender's exchanges",
}
NOT_SENDING = {
    "base_url": "configuration", "store": "the run's store", "run_id": "configuration",
    "mode": "configuration", "ground_truth": "input points and cases",
    "selected_categories": "configuration", "points_source": "configuration",
    "pages_html": "input HTML, read only", "coverage": "a coverage source it reads",
    "dbfault": "a DB-fault log it reads", "scheduler": "orders strategies, sends nothing",
    "plugins": "contributes rules, an oracle's strategies and a prioritizer; a plugin "
               "strategy sends only through the sender it is handed",
    "confirm_budget": "configuration", "prioritizer": "orders candidates, sends nothing",
    "header_names": "configuration", "writes": "configuration",
    "account_values": "values of the run's own account, not a sender",
    "trace_events": "configuration",
}
#: What `run_auto` may do with its sender before the recorder branch: configure it.
CONFIGURING = {"allow_explicit", "isolate"}


def _calls_to(tree, name):
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and (
        getattr(n.func, "id", None) == name or getattr(n.func, "attr", None) == name)]


def _is_wrap(node, arg) -> bool:
    return isinstance(node, ast.Call) and getattr(node.func, "id", None) == \
        "TracingSender" and bool(node.args) and ast.unparse(node.args[0]) == arg


def _only_wrapped(expr, arg) -> bool:
    """Every value ``expr`` can take is ``None`` or ``TracingSender(<arg>, …)``: the
    branches of a conditional are each checked, so ``x or TracingSender(x)`` fails."""
    if isinstance(expr, ast.IfExp):
        return _only_wrapped(expr.body, arg) and _only_wrapped(expr.orelse, arg)
    if isinstance(expr, ast.Constant) and expr.value is None:
        return True
    return _is_wrap(expr, arg)


def _send_path_offenders(auto_src: str, test_src: str) -> list[str]:
    """P2's checks (module docstring); [] when every sending keyword of `run_auto` is
    classified, wrapped as classified, and passed by P1's count run."""
    out = []
    tree = ast.parse(auto_src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "run_auto")
    params = [a.arg for a in fn.args.args + fn.args.kwonlyargs]
    known = {**SENDING_WRAPPED, **SENDING_SELF, **NOT_SENDING}
    out += [f"unclassified run_auto parameter: {p}" for p in params if p not in known]
    branch = next((n for n in ast.walk(fn) if isinstance(n, ast.If)
                   and {getattr(x, "id", None) for x in ast.walk(n.test)} >= {"recorder"}
                   and any(_is_wrap(c, "sender") for c in ast.walk(n))), None)
    if branch is None:
        out.append("sender: no recorder branch rebinds it to TracingSender(sender)")
        return out
    first = branch.body[0]
    if not (isinstance(first, ast.Assign) and ast.unparse(first.targets[0]) == "sender"
            and _is_wrap(first.value, "sender")):
        out.append("sender: not rebound to TracingSender(sender) first in the recorder "
                   "branch")
    peer = [n for n in ast.walk(branch) if isinstance(n, ast.Assign)
            and ast.unparse(n.targets[0]) == "peer"]
    given = {k.arg: k.value for n in peer for c in ast.walk(n.value)
             if isinstance(c, ast.Call) for k in c.keywords}
    for attr in ("sender", "anonymous"):
        if attr not in given or not _only_wrapped(given[attr], f"peer.{attr}"):
            out.append(f"peer: peer.{attr} is not wrapped in TracingSender")
    parents = {c: p for p in ast.walk(fn) for c in ast.iter_child_nodes(p)}
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and node.id == "sender" and \
                isinstance(node.ctx, ast.Load) and node.lineno < branch.lineno:
            up = parents.get(node)
            ok = (isinstance(up, ast.Attribute) and up.attr in CONFIGURING) or (
                isinstance(up, ast.Call) and getattr(up.func, "id", None) in
                ("hasattr", "getattr") and up.args and up.args[0] is node)
            if not ok:
                out.append(f"sender: used before it is wrapped (line {node.lineno})")
    pipeline = _calls_to(fn, "run_pipeline")
    if not pipeline or pipeline[0].lineno < branch.lineno:
        out.append("run_pipeline is not called after the recorder branch")
    else:
        kws = {k.arg: ast.unparse(k.value) for k in pipeline[0].keywords}
        for name in SENDING_SELF:
            if kws.get(name) != name:
                out.append(f"{name}: not passed to run_pipeline unchanged")
    test_tree = ast.parse(test_src)
    helper = next((n for n in ast.walk(test_tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "_auto_run"), None)
    calls = _calls_to(helper, "run_auto") if helper is not None else []
    passed = {k.arg for c in calls for k in c.keywords}
    for name in {**SENDING_WRAPPED, **SENDING_SELF}:
        if name not in passed:
            out.append(f"the count test does not pass {name}")
    return out


def _sources():
    return ((ROOT / "fuzzlab" / "harness" / "auto.py").read_text(),
            Path(__file__).read_text())


def test_the_count_test_covers_every_sending_keyword_of_run_auto():
    auto_src, test_src = _sources()
    assert _send_path_offenders(auto_src, test_src) == []
    from fuzzlab.harness.auto import run_auto
    assert set(inspect.signature(run_auto).parameters) == \
        set(SENDING_WRAPPED) | set(SENDING_SELF) | set(NOT_SENDING)


def test_the_keyword_guard_catches_a_synthetic_new_keyword():
    """A new keyword fails P2 because it is unclassified, whether or not P1 passes it;
    a wrapped keyword passed on unwrapped, and a sending keyword P1 omits, fail too."""
    auto_src, test_src = _sources()
    sig = "def run_auto(*, base_url: str, store, run_id: int, sender,"
    assert sig in auto_src
    added = auto_src.replace(sig, sig + " relay=None,")
    assert _send_path_offenders(added, test_src) == \
        ["unclassified run_auto parameter: relay"]
    rebind = 'sender = TracingSender(sender, identity=getattr(sender, "_identity", None))'
    assert rebind in auto_src
    unwrapped = auto_src.replace(rebind, "pass")
    assert "sender: no recorder branch rebinds it to TracingSender(sender)" in \
        _send_path_offenders(unwrapped, test_src)
    peer = ("sender=None if peer.sender is None else TracingSender(\n"
            "                    peer.sender,")
    assert peer in auto_src
    leaky = auto_src.replace(peer, "sender=None if peer.sender is None else (\n"
                                   "                    peer.sender) or TracingSender(\n"
                                   "                    peer.sender,")
    assert _send_path_offenders(leaky, test_src) == \
        ["peer: peer.sender is not wrapped in TracingSender"]
    passing = "browser=executor, oob=listener,"
    assert passing in test_src
    omitted = test_src.replace(passing, "browser=executor,")
    assert _send_path_offenders(auto_src, omitted) == ["the count test does not pass oob"]
