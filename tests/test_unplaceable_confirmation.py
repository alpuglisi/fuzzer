"""BUG-0523 (CC-FUZZ-0103, CC-AUD-0055, FR-AUD-30, PA-0523): a placement the browser
mechanism refuses, or a candidate only it can decide, is never a negative.

The M6 executor returned its placement refusals as an observation (``executed=False``),
which its only reader took as "observed, not executed": an unplaceable stored-XSS store
became a plain negative. And the oracle counted any mechanism's placement as a check, so
a reflected-XSS probe on a stored case's page (or on a DOM point whose browser could not
start) made the candidate a negative although the one mechanism that decides it never
ran. Now the executor raises its refusals, and a point the browser alone decides names
that mechanism (``decided_by``, scoped to its category) so the oracle counts only its
placement. Loopback only; no test here starts a browser.
"""

from __future__ import annotations

import ast
import json
import random
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from fuzzlab.core import trace
from fuzzlab.core.store import Store
from fuzzlab.oracle.browser import ExecRequest, FakeBrowserExecutor, StoreStep
from fuzzlab.oracle.oracle import UNPLACEABLE, Oracle
from fuzzlab.oracle.probe import Candidate, Probe, UnplaceableLocation, Verdict
from fuzzlab.oracle.strategies import (ReflectedXssStrategy, StoredXssStrategy,
                                       default_strategies)

ROOT = Path(__file__).resolve().parents[1]
STORED = "xss-stored:browser-execution"
DOM = "xss-dom:browser-execution"
STORE_REASON = "unplaceable store request POST 'header'"


def _no_driver(monkeypatch):
    """A Playwright whose driver must never start (a refusal comes first)."""
    import sys
    fake = types.ModuleType("playwright.sync_api")

    def sync_playwright():
        raise AssertionError("a refused placement started the browser driver")
    fake.sync_playwright = sync_playwright
    fake.Error = type("Error", (Exception,), {})
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake)


class _Counting:
    """The real executor, counting its calls (`PlaywrightBrowserExecutor.run`)."""

    def __init__(self):
        from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
        self.inner, self.calls = PlaywrightBrowserExecutor(), 0

    def run(self, request, token):
        self.calls += 1
        return self.inner.run(request, token)


class _Page:
    """A sender whose page shows nothing it was sent, or (``reflect``) everything."""

    def __init__(self, reflect=False):
        self.reflect, self.sent = reflect, 0

    def send(self, url, param, value, **kw):
        self.sent += 1
        body = f"<html><body>{value if self.reflect else 'page'}</body></html>"
        return Probe(200, body, headers={"Content-Type": "text/html"})


def _stored(location="header", method="POST", decided=True, **kw) -> Candidate:
    return Candidate(url="http://127.0.0.1:9/board", param="c", method="POST",
                     location="body", category="xss", store_url="http://127.0.0.1:9/st",
                     store_param="c", store_method=method, store_location=location,
                     decided_by=STORED if decided else None, **kw)


# --- 1 ------------------------------------------------------------------------------------
REFUSED = [
    ("observe header", ExecRequest(url="http://h/a", param="q", value="v",
                                   location="header"), "unplaceable location 'header'"),
    ("observe json", ExecRequest(url="http://h/a", param="q", value="v", location="json"),
     "unplaceable location 'json'"),
    *[(f"store {loc}", ExecRequest(url="http://h/a", store=StoreStep(
        url="http://h/s", param="c", value="v", method="POST", location=loc)),
       f"unplaceable store request POST '{loc}'")
      for loc in ("header", "cookie", "path", "fragment")],
    *[(f"store {m} query", ExecRequest(url="http://h/a", store=StoreStep(
        url="http://h/s", param="c", value="v", method=m, location="query")),
       f"unplaceable store request {m} 'query'") for m in ("POST", "PUT", "PATCH")],
    *[(f"store {m} body", ExecRequest(url="http://h/a", store=StoreStep(
        url="http://h/s", param="c", value="v", method=m, location="body")),
       f"unplaceable store request {m} 'body'") for m in ("GET", "DELETE")],
    ("store json without the leaf", ExecRequest(url="http://h/a", store=StoreStep(
        url="http://h/s", param="content", value="v", method="POST", location="json",
        entries=((("username",), "u"),))), "unplaceable store leaf"),
]


@pytest.mark.parametrize("name,request_,reason", REFUSED, ids=[n for n, _r, _x in REFUSED])
def test_the_executor_raises_every_placement_it_refuses(monkeypatch, name, request_,
                                                        reason):
    """PA-0523(1): a refusal is the oracle's no-verdict signal, raised before any
    browser starts -- never an observation returned as "not executed"."""
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _no_driver(monkeypatch)
    with pytest.raises(UnplaceableLocation, match=reason.replace("'", ".")):
        PlaywrightBrowserExecutor().run(request_, "tok")


# --- 2 ------------------------------------------------------------------------------------
def test_an_unplaceable_store_is_no_verdict_from_the_stored_strategy(monkeypatch):
    _no_driver(monkeypatch)
    executor = _Counting()
    confirmed, unsure = Oracle(strategies=[StoredXssStrategy(executor)]).confirm_outcome(
        _stored(decided=False), _Page())
    assert confirmed is None
    assert unsure is not None and unsure.inconclusive and unsure.mechanism == UNPLACEABLE
    assert unsure.evidence["reason"] == STORE_REASON
    assert executor.calls == 1                       # one refusal, not one per payload


# --- 3 ------------------------------------------------------------------------------------
def test_a_stored_candidate_is_decided_only_by_the_mechanism_that_plants_it(monkeypatch):
    """A reflected probe placed on the observe page and not confirmed does not make a
    stored case a negative; a reflected confirmation still counts; a store that was
    planted and did not fire is still a negative."""
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _no_driver(monkeypatch)
    page = _Page()
    confirmed, unsure = Oracle(browser=PlaywrightBrowserExecutor()).confirm_outcome(
        _stored(), page)
    assert page.sent > 0                                  # the reflected check ran
    assert confirmed is None and unsure.mechanism == UNPLACEABLE
    assert unsure.evidence["reason"] == STORE_REASON
    confirmed, unsure = Oracle(browser=PlaywrightBrowserExecutor()).confirm_outcome(
        _stored(), _Page(reflect=True))
    assert confirmed is not None and confirmed.vuln_class == "xss-reflected"
    planted = Oracle(browser=FakeBrowserExecutor(vulnerable=lambda r: False))
    assert planted.confirm_outcome(_stored(location="body"), _Page()) == (None, None)


# --- 7, 8, 9 ------------------------------------------------------------------------------
def test_a_deciding_mechanism_that_did_not_run_leaves_the_candidate_unplaceable():
    why = f"deciding mechanism {STORED} did not run"
    _c, unsure = Oracle(strategies=[ReflectedXssStrategy()]).confirm_outcome(
        _stored(), _Page())
    assert unsure is not None and unsure.mechanism == UNPLACEABLE
    assert unsure.evidence["reason"] == why

    class NotApplying(StoredXssStrategy):
        def applies(self, candidate):
            return False
    _c, unsure = Oracle(strategies=[ReflectedXssStrategy(), NotApplying(
        FakeBrowserExecutor())]).confirm_outcome(_stored(), _Page())
    assert unsure.mechanism == UNPLACEABLE and unsure.evidence["reason"] == why


def test_the_deciders_refusal_reason_wins_under_a_scheduler(monkeypatch):
    """Under a real `ThompsonBandit` whose priors put greybox first, greybox's refusal
    ("no coverage or DB-fault source") comes first; the store's own is the reason."""
    from fuzzlab.scheduler.bandit import ThompsonBandit
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _no_driver(monkeypatch)
    strategies = default_strategies(browser=PlaywrightBrowserExecutor())
    greybox = next(s for s in strategies if "grey-box" in s.arm)
    priors = {s.arm: (1.0, 1000.0) for s in strategies} | {greybox.arm: (1000.0, 1.0)}
    bandit = ThompsonBandit(rng=random.Random(7), priors=priors)
    order = []

    class Watching(ThompsonBandit):
        def order(self, context, arms):
            got = bandit.order(context, arms)
            order.extend(got)
            return got

        def update(self, *a, **k):
            pass
    oracle = Oracle(strategies=strategies, scheduler=Watching())
    _c, unsure = oracle.confirm_outcome(_stored(), _Page())
    assert order[0] == greybox.arm
    assert unsure.mechanism == UNPLACEABLE and unsure.evidence["reason"] == STORE_REASON


class _NoArmPlugin:
    """A duck-typed plugin confirmer with no ``arm`` (as a plugin may contribute)."""
    name = "no-arm-oracle"

    def __init__(self):
        self.calls = 0

    def applies(self, candidate):
        return True

    def confirm(self, candidate, sender):
        self.calls += 1
        return None                                     # placed, nothing confirmed

    def register_oracle(self):
        return self


def test_a_strategy_without_an_arm_decides_only_a_candidate_with_no_decider(monkeypatch):
    """Through the real plugin path (`PluginManager.oracles`, joined untyped at
    `Oracle.__init__`): no AttributeError; a no-arm strategy decides a candidate
    without ``decided_by`` (its not_confirmed is a negative); it does not decide one
    with ``decided_by`` (the stored case stays inconclusive)."""
    from fuzzlab.plugins.manager import PluginManager
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _no_driver(monkeypatch)
    plugin = _NoArmPlugin()
    oracle = Oracle(strategies=[StoredXssStrategy(PlaywrightBrowserExecutor())],
                    plugins=PluginManager(plugins=[plugin]))
    assert any(s is plugin for s in oracle.strategies)
    assert oracle.confirm_outcome(_stored(decided=False), _Page()) == (None, None)
    _c, unsure = oracle.confirm_outcome(_stored(), _Page())
    assert plugin.calls == 2
    assert unsure is not None and unsure.mechanism == UNPLACEABLE
    assert unsure.evidence["reason"] == STORE_REASON


# --- 5: a key shared with an ordinary point ----------------------------------------------
def _shared_key_run(tmp_path, stored_first: bool, budget: bool, monkeypatch):
    from fuzzlab.core.runmode import resolve_run
    from fuzzlab.harness.pipeline import run_pipeline
    from fuzzlab.ml.active import Prioritized
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    _no_driver(monkeypatch)
    plain = {"rule_id": "R-XSS-REFLECT", "category": "xss", "url": "http://127.0.0.1:9/board",
             "param": "c", "method": "POST", "location": "body"}
    stored = plain | {"store_url": "http://127.0.0.1:9/st", "store_param": "c",
                      "store_method": "POST", "store_location": "header",
                      "decided_by": STORED}
    plan = resolve_run("manual", selected_categories=["xss"], all_categories=["xss"])
    with Store(tmp_path / f"k{stored_first}{budget}.db") as store:
        run = store.start_run("auto", "h")
        rec = trace.TraceRecorder(store, run)
        for ev in ((stored, plain) if stored_first else (plain, stored)):
            store.conn.execute("INSERT INTO candidate (run_id, rule, evidence) "
                               "VALUES (?,?,?)", (run, "R-XSS-REFLECT", json.dumps(ev)))
        store.conn.commit()
        kw = {"confirm_budget": 1, "prioritizer": lambda s, r, ids: Prioritized(
            order=list(ids), method="stub")} if budget else {}
        with trace.recording(rec):
            run_pipeline([], store, run, _Page(), plan,
                         browser=PlaywrightBrowserExecutor(), **kw)
        rec.close()
        statuses = [r[0] for r in store.conn.execute(
            "SELECT oracle_status FROM candidate WHERE run_id=?", (run,))]
        decides = {json.loads(r[0])["strategy"]: json.loads(r[0]).get("decides")
                   for r in store.conn.execute("SELECT body FROM trace_event WHERE "
                                               "run_id=? AND kind='test.strategy'", (run,))}
    return statuses, decides


@pytest.mark.parametrize("stored_first", [True, False])
@pytest.mark.parametrize("budget", [False, True])
def test_a_key_shared_with_an_ordinary_point_keeps_every_mechanism_deciding(
        tmp_path, monkeypatch, stored_first, budget):
    """The rows of one key disagree (a stored case's observe point is also an ordinary
    point): the pipeline drops ``decided_by`` (never composes one), every mechanism
    decides, and the reflected not_confirmed is a negative -- the stated gap -- on the
    budgeted and the unbudgeted path, whichever row comes first."""
    statuses, decides = _shared_key_run(tmp_path, stored_first, budget, monkeypatch)
    assert statuses == ["checked", "checked"]
    assert decides["xss-reflected:reflected-context"] is True


# --- 4, 6, 10: through run_auto, every category ------------------------------------------
def _all_categories() -> list[str]:
    """Every rule category (derived, PA-0001): the run selects them all."""
    from fuzzlab.audit import known_categories
    return known_categories()


class _App(BaseHTTPRequestHandler):
    """A page that answers every request and reflects nothing."""

    def log_message(self, *a):
        pass

    def _ok(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        body = b"<html><body>page</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = _ok


def _run(tmp, base, gt, *, dead=False):
    from fuzzlab.harness.auto import run_auto
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    from fuzzlab.tools.probesender import RequestsProbeSender
    executor = PlaywrightBrowserExecutor()
    if dead:
        executor._unavailable = "browser unavailable: simulated"   # BUG-0126's state
    with Store(tmp / "s.db") as store:
        run = store.start_run("auto", "h")
        result = run_auto(base_url=base + "/", store=store, run_id=run,
                          sender=RequestsProbeSender(timeout=5.0), mode="manual",
                          ground_truth=gt, selected_categories=_all_categories(),
                          points_source="ground-truth", browser=executor)
        cands = {}
        for r in store.conn.execute("SELECT evidence, oracle_status FROM candidate "
                                    "WHERE run_id=?", (run,)):
            ev = json.loads(r["evidence"])
            cands[(ev["url"].rsplit("/", 1)[-1], ev["category"])] = (
                r["oracle_status"], ev.get("decided_by"))
        events = [(r["kind"], json.loads(r["body"])) for r in store.conn.execute(
            "SELECT kind, body FROM trace_event WHERE run_id=? ORDER BY seq", (run,))]
    return {"result": result, "cands": cands, "events": events}


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    from fuzzlab.labels.contract import Case, GroundTruth
    from fuzzlab.labels.contract import InjectionPoint as GtPoint
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def stored(loc):            # `id`: the SQLi and SSTI rules fire on the point too
        return GroundTruth(target="q", cases=[
            Case("S1", "/board", "POST", "id", "body", "xss-stored", "html", True,
                 "server", source_url="/st")], points=[GtPoint("/st", "POST", "id", loc)])
    dom = GroundTruth(target="q", cases=[], points=[
        GtPoint("/dom", "GET", "id", "query", rendering="js")])
    try:
        return {"header": _run(tmp_path_factory.mktemp("h"), base, stored("header")),
                "path": _run(tmp_path_factory.mktemp("p"), base, stored("path")),
                "dead-stored": _run(tmp_path_factory.mktemp("d"), base, stored("body"),
                                    dead=True),
                "dead-dom": _run(tmp_path_factory.mktemp("o"), base, dom, dead=True)}
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("store", ["header", "path"])
def test_run_auto_records_an_unplaceable_store_as_inconclusive_never_a_negative(runs,
                                                                                 store):
    run = runs[store]
    result, cands = run["result"], run["cands"]
    assert cands[("board", "xss")] == ("inconclusive", STORED)
    detail = [i for i in result.inconclusive if i["url"].endswith("/board")]
    assert detail and detail[0]["mechanism"] == UNPLACEABLE
    assert detail[0]["reason"] == f"unplaceable store request POST '{store}'"
    starts = {b["test"]: b for k, b in run["events"] if k == "test.start"}
    xss = next(t for t, b in starts.items() if b["url"].endswith("/board")
               and b["category"] == "xss")
    mine = [(k, b) for k, b in run["events"] if b.get("test") == xss]
    strategies = {b["strategy"]: b for k, b in mine if k == "test.strategy"}
    assert (strategies[STORED]["outcome"], strategies[STORED]["decides"]) == \
        ("unplaceable", True)
    assert (strategies["xss-reflected:reflected-context"]["outcome"],
            strategies["xss-reflected:reflected-context"]["decides"]) == \
        ("not_confirmed", False)
    ends = [b["outcome"] for k, b in mine if k == "browser.step" and b["step"] == "end"]
    assert ends == ["unplaceable"]                        # one refusal; the trace agrees
    assert [b["outcome"] for k, b in mine if k == "test.end"] == ["inconclusive"]
    assert result.metrics["oracle_unplaceable"] >= 1
    # no negative from the xss key: every checked key is another category's
    checked = [k for k, (st, _d) in cands.items() if st == "checked"]
    assert ("board", "xss") not in checked and result.metrics["oracle_rejected"] == \
        len({k for k in checked})


@pytest.mark.parametrize("which", ["header", "dead-dom"])
def test_decided_by_reaches_only_the_deciding_category(runs, which):
    """FR-AUD-30: the deciding mechanism reaches the xss evidence only; a sql-injection
    candidate on the same stored case (header store) or DOM point stays a negative,
    decided by its own strategies."""
    cands = runs[which]["cands"]
    page = "board" if which == "header" else "dom"
    assert cands[(page, "sql-injection")] == ("checked", None)
    assert cands[(page, "server-side-template-injection")] == ("checked", None)
    assert cands[(page, "xss")][1] == (STORED if which == "header" else DOM)
    for (p, category), (_st, decided) in cands.items():
        assert decided is None or category == "xss", (p, category)


@pytest.mark.parametrize("which,arm", [("dead-stored", STORED), ("dead-dom", DOM)])
def test_a_browser_that_cannot_start_never_makes_a_browser_only_candidate_a_negative(
        runs, which, arm):
    cands = runs[which]["cands"]
    page = "board" if which == "dead-stored" else "dom"
    assert cands[(page, "xss")] == ("inconclusive", arm)
    detail = [i for i in runs[which]["result"].inconclusive if i["url"].endswith(page)]
    assert detail[0]["reason"].startswith("browser unavailable")
    if which == "dead-stored":                  # the store point itself is an ordinary one
        assert cands[("st", "xss")] == ("checked", None)


# --- 12: the PA-0523 guards ---------------------------------------------------------------
#: The only places an executor may return an observation that is not a hit: where it
#: observed the page and the sentinel did not fire (or the offline fake's verdict).
OBSERVED_NO_HIT = {
    ("fuzzlab/tools/browserexec.py", "PlaywrightBrowserExecutor._in_browser",
     "ExecObservation(executed=False, detail='')"),
    ("fuzzlab/oracle/browser.py", "FakeBrowserExecutor.run",
     "ExecObservation(executed=fired, detail='fake' if fired else '')"),
}


def _executor_offenders(sources: dict[str, str]) -> list[str]:
    """Every ``ExecObservation(...)`` an executor class (one with ``run(self, request,
    token)``) builds whose ``executed`` is not the constant True, outside
    `OBSERVED_NO_HIT`."""
    out = []
    for rel, src in sorted(sources.items()):
        for cls in (n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.ClassDef)):
            methods = {f.name: f for f in cls.body if isinstance(f, ast.FunctionDef)}
            run = methods.get("run")
            if run is None or [a.arg for a in run.args.args][:3] != ["self", "request",
                                                                     "token"]:
                continue
            for name, fn in methods.items():
                for call in (c for c in ast.walk(fn) if isinstance(c, ast.Call)
                             and getattr(c.func, "id", None) == "ExecObservation"):
                    executed = call.args[0] if call.args else next(
                        (k.value for k in call.keywords if k.arg == "executed"), None)
                    if isinstance(executed, ast.Constant) and executed.value is True:
                        continue
                    site = (rel, f"{cls.name}.{name}", ast.unparse(call))
                    if site not in OBSERVED_NO_HIT:
                        out.append(f"{rel}:{call.lineno} {cls.name}.{name}: "
                                   f"{ast.unparse(call)}")
    return out


def _package_sources() -> dict[str, str]:
    return {str(p.relative_to(ROOT)): p.read_text()
            for p in (ROOT / "fuzzlab").rglob("*.py")}


def test_no_executor_returns_an_observation_for_a_refusal():
    assert _executor_offenders(_package_sources()) == []
    # the allowlist is exact: each site exists
    found = set()
    for rel, qual, call in OBSERVED_NO_HIT:
        src = (ROOT / rel).read_text()
        found |= {(rel, qual, call)} if call in {ast.unparse(c) for c in ast.walk(
            ast.parse(src)) if isinstance(c, ast.Call)} else set()
    assert found == OBSERVED_NO_HIT


def test_the_executor_guard_catches_a_synthetic_offender():
    rogue = ("class Rogue:\n"
             "    def run(self, request, token):\n"
             "        if request.store is None:\n"
             "            return ExecObservation(False, detail='unplaceable store')\n"
             "        return ExecObservation(True)\n")
    assert _executor_offenders({"fuzzlab/rogue.py": rogue}) == [
        "fuzzlab/rogue.py:4 Rogue.run: ExecObservation(False, detail='unplaceable store')"]


def _decider_offenders(deciders, sources: dict[str, str]) -> list[str]:
    """Every deciding mechanism names a default arm of its own category, and every
    ``decided_by=`` a point builder passes is one of `harness.auto.DECIDERS` by name."""
    arms = {(s.category, s.arm) for s in default_strategies()}
    out = [f"not a default arm of its category: {d}" for d in deciders if d not in arms]
    for rel, src in sorted(sources.items()):
        for call in (c for c in ast.walk(ast.parse(src)) if isinstance(c, ast.Call)):
            for kw in call.keywords:
                if kw.arg == "decided_by" and not (
                        isinstance(kw.value, ast.Name) and kw.value.id.endswith("_DECIDER")):
                    out.append(f"{rel}:{kw.value.lineno} decided_by="
                               f"{ast.unparse(kw.value)}")
    return out


def test_every_decided_by_names_a_default_arm_of_its_category():
    from fuzzlab.harness.auto import DECIDERS, DOM_DECIDER, STORED_DECIDER
    assert set(DECIDERS) == {STORED_DECIDER, DOM_DECIDER} == {("xss", STORED), ("xss", DOM)}
    assert _decider_offenders(DECIDERS, _package_sources()) == []


def test_the_decider_guard_catches_a_synthetic_offender():
    assert _decider_offenders([("xss", "xss-nope:browser-execution"),
                               ("sql-injection", STORED)], {}) == [
        "not a default arm of its category: ('xss', 'xss-nope:browser-execution')",
        "not a default arm of its category: ('sql-injection', "
        "'xss-stored:browser-execution')"]
    rogue = "InjectionPoint(url='u', param='p', decided_by=('xss', 'x'))\n"
    assert _decider_offenders([], {"fuzzlab/rogue.py": rogue}) == [
        "fuzzlab/rogue.py:1 decided_by=('xss', 'x')"]


def test_a_verdict_is_still_a_verdict():
    """Unchanged: a confirmation from any mechanism counts."""
    assert Verdict(True, "xss-reflected", "m", {}).confirmed
