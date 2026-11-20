"""FR-FUZZ-720/721/722 (M6CONC): the browser XSS check observes its payloads in waves.

`fuzzlab.oracle.strategies._BrowserXssStrategy.confirm` gives each of its six payloads
its own sentinel token and observes them in waves of the executor's ``workers`` (1..3)
through `fuzzlab.oracle.browser.observe_many` / `PlaywrightBrowserExecutor.run_many`.
These tests try to break that:

* cross-talk (offline): a hit is credited to the payload whose token fired, never to
  the page that saw it, and another candidate's token never counts;
* equivalence (offline): for every one of the 4^6 per-payload outcome vectors (hit /
  no hit / NotObserved / UnplaceableLocation) the verdict at workers 2 and 3 equals the
  one-at-a-time verdict, and workers=1 loads exactly what the old loop loaded;
* the cost bound: an unloadable page costs at most 3 loads at every ``workers``;
* the session: resolved once per scope per wave, on the caller thread only, and a
  login failure starts no browser visit;
* the trace: every visit of a wave is recorded from the caller thread;
* a transient launch failure inside one wave does not switch M6 off for the run;
* real browser (names contain ``real``): the late-sink fixtures of
  `tests/test_m6_slow_sinks.py` in waves of 3, and stored-XSS cross-talk between the
  payloads of one candidate and between candidates on a shared render page. Under
  ``FUZZLAB_REQUIRE_BROWSER=1`` they fail rather than skip.
"""

from __future__ import annotations

import itertools
import json
import random
import re
import sys
import threading
import time
import types
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import parse_qsl

import pytest

from fuzzlab.core import trace
from fuzzlab.core.store import Store
from fuzzlab.oracle import strategies as S
from fuzzlab.oracle.browser import (
    ExecObservation,
    ExecRequest,
    NotObserved,
    observe_many,
    workers_of,
)
from fuzzlab.oracle.probe import Candidate, UnplaceableLocation, Verdict
from fuzzlab.oracle.strategies import (
    DomXssStrategy,
    StoredXssStrategy,
    _quote_free,
    _xss_exec_payloads,
)
from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor

HIT, MISS, NO, UL = "hit", "miss", "no", "ul"
OUTCOMES = (HIT, MISS, NO, UL)
N = len(_xss_exec_payloads("0"))                 # 6 payloads
STRATEGY = "xss-dom:browser-execution"


# --- helpers ----------------------------------------------------------------------------
def _dom_candidate():
    return Candidate(url="http://127.0.0.1:9/p", param="q", location="query",
                     category="xss")


def _stored_candidate(store="http://127.0.0.1:9/store"):
    return Candidate(url="http://127.0.0.1:9/render", param="c", category="xss",
                     store_url=store, store_param="c")


@pytest.fixture
def toks(monkeypatch):
    """Deterministic tokens: confirm call k draws ``c<k>t0`` .. ``c<k>t5`` (payload i
    carries ``c<k>t<i>``)."""
    counter = itertools.count()

    def fake():
        n = next(counter)
        return f"c{n // N}t{n % N}"
    monkeypatch.setattr(S, "_token", fake)
    return counter


def _idx(token: str) -> int:
    return int(re.fullmatch(r"c\d+t(\d)", token).group(1))


def _cand_of(token: str) -> int:
    return int(re.fullmatch(r"c(\d+)t\d", token).group(1))


def _tok(cand: int, i: int) -> str:
    return f"c{cand}t{i}"


def _token_in(payload: str) -> str:
    """The sentinel token a payload carries (quoted, backticked or fromCharCode)."""
    m = re.search(r"__fzlbHit\(['`]([0-9A-Za-z]+)['`]\)", payload)
    if m:
        return m.group(1)
    m = re.search(r"String\.fromCharCode\(([\d,]+)\)", payload)
    return "".join(chr(int(c)) for c in m.group(1).split(","))


def _materialise(o, token):
    if o == HIT:
        return ExecObservation(executed=True, detail="fake", hits=frozenset({token}))
    if o == MISS:
        return ExecObservation(executed=False, detail="")
    if o == NO:
        raise NotObserved(f"not observed {token}")
    if o == UL:
        raise UnplaceableLocation(f"unplaceable {token}")
    if isinstance(o, BaseException):
        raise o
    return o                                   # an ExecObservation as given


class FakeExec:
    """Implements ``run``, ``run_many`` and ``workers``. ``outcome(token)`` gives the
    outcome of the page carrying ``token``. ``truncate``: as the real `run_many`, an
    item after a plain `UnplaceableLocation` (a refusal) is left unobserved (None)."""

    def __init__(self, outcome, workers=3, truncate=False):
        self.outcome = outcome
        self.workers = workers
        self.truncate = truncate
        self.loads: list[str] = []
        self.waves: list[list[str]] = []
        self.many_calls = 0

    def _one(self, token):
        self.loads.append(token)
        return _materialise(self.outcome(token), token)

    def run(self, request, token):
        return self._one(token)

    def run_many(self, items):
        self.many_calls += 1
        items = list(items)
        self.waves.append([t for _r, t in items])
        out: list = []
        for k, (_req, tok) in enumerate(items):
            try:
                out.append(self._one(tok))
            except BaseException as exc:  # noqa: BLE001 - the item's own result
                out.append(exc)
                if self.truncate and type(exc) is UnplaceableLocation:
                    out += [None] * (len(items) - k - 1)
                    break
        return out


class SeqExec:
    """A one-at-a-time executor: ``run`` only (no ``run_many``)."""

    def __init__(self, outcome):
        self.outcome = outcome
        self.loads: list[str] = []

    def run(self, request, token):
        self.loads.append(token)
        return _materialise(self.outcome(token), token)


def _quote_free_indices():
    return {i for i, p in enumerate(_xss_exec_payloads("abc")) if _quote_free(p)}


QUOTE_FREE = _quote_free_indices()


def reference(vec):
    """The pre-change one-at-a-time decision (the removed loop of
    `_BrowserXssStrategy.confirm` and `_last_try`), over a per-payload outcome vector:
    ``(normalised verdict, loads)``."""
    loads: list[int] = []
    not_observed = None
    misses = 0
    tried: set[int] = set()

    def last_try():
        nxt = next((i for i in range(N) if i not in tried and i in QUOTE_FREE), None)
        if nxt is not None:
            loads.append(nxt)
            if vec[nxt] == HIT:
                return ("confirmed", nxt, None)
        return ("inconclusive", not_observed)

    for i in range(N):
        tried.add(i)
        loads.append(i)
        o = vec[i]
        if o == NO:
            not_observed = not_observed or f"not observed t{i}"
            misses += 1
            if misses >= 2:
                return last_try(), loads
            continue
        if o == UL:
            if not_observed is None:
                return ("raised", "UnplaceableLocation"), loads
            break
        misses = 0
        if o == HIT:
            return ("confirmed", i, None), loads
    if not_observed is not None:
        return ("inconclusive", not_observed), loads
    return ("none",), loads


def _norm(fn):
    """A confirm call's outcome, normalised: confirmed (credited index, observed_with
    index), inconclusive (its not_observed text with the candidate prefix dropped),
    none, or raised."""
    try:
        v = fn()
    except UnplaceableLocation as exc:
        return ("raised", type(exc).__name__ if not isinstance(exc, NotObserved)
                else "NotObserved")
    if v is None:
        return ("none",)
    assert isinstance(v, Verdict)
    if v.inconclusive:
        assert not v.confirmed
        text = v.evidence.get("not_observed")
        return ("inconclusive", re.sub(r"c\d+t", "t", text) if text else text)
    assert v.confirmed
    with_ = v.evidence.get("observed_with")
    return ("confirmed", _idx(_token_in(v.evidence["payload"])),
            None if with_ is None else _idx(_token_in(with_)))


def _by_vec(vec):
    return lambda token: vec[_idx(token)]


# --- 1a/1b: cross-talk ------------------------------------------------------------------
def _crosstalk_case(strategy_cls, workers):
    """Payload 1's page sees payload 3's token only (a stored sibling's echo): the hit
    is payload 3's, observed with payload 1."""
    def outcome(token):
        if _idx(token) == 1:
            return ExecObservation(executed=False, detail="sib",
                                   hits=frozenset({token.replace("t1", "t3")}))
        return MISS
    ex = FakeExec(outcome, workers=workers)
    return strategy_cls(ex).confirm(_dom_candidate(), None)


class _NaiveCreditsThePage(DomXssStrategy):
    """Synthetic offender: credits a hit to the page that saw it."""

    def _hit(self, obs, index, payloads, tokens):
        if obs.executed or getattr(obs, "hits", None):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"payload": payloads[index], "detail": obs.detail})
        return None


class _NaiveAnyToken(DomXssStrategy):
    """Synthetic offender: any fired token counts, whoever's it is."""

    def _hit(self, obs, index, payloads, tokens):
        if obs.executed or getattr(obs, "hits", None):
            return Verdict(True, self.vuln_class, self.mechanism,
                           {"payload": payloads[index], "detail": obs.detail})
        return None


def _assert_credited_to_sibling(v):
    assert v is not None and v.confirmed
    assert _idx(_token_in(v.evidence["payload"])) == 3, v.evidence
    assert _idx(_token_in(v.evidence["observed_with"])) == 1, v.evidence


@pytest.mark.parametrize("workers", [1, 2, 3])
def test_a_siblings_token_on_another_page_is_credited_to_the_sibling(toks, workers):
    _assert_credited_to_sibling(_crosstalk_case(DomXssStrategy, workers))


def test_the_crosstalk_check_catches_a_strategy_that_credits_the_page(toks):
    with pytest.raises(AssertionError):
        _assert_credited_to_sibling(_crosstalk_case(_NaiveCreditsThePage, 3))


@pytest.mark.parametrize("workers", [1, 3])
def test_the_own_token_wins_over_a_sibling_and_the_lowest_sibling_wins(toks, workers):
    # page 0 sees its own token and payload 4's: its own
    def own(token):
        return ExecObservation(True, "x", hits=frozenset({token, token[:-1] + "4"})) \
            if _idx(token) == 0 else MISS
    v = DomXssStrategy(FakeExec(own, workers)).confirm(_dom_candidate(), None)
    assert _idx(_token_in(v.evidence["payload"])) == 0
    assert "observed_with" not in v.evidence
    # page 0 sees payloads 5 and 2 (not its own): the lowest, payload 2
    def two(token):
        return ExecObservation(False, "x", hits=frozenset(
            {token[:-1] + "5", token[:-1] + "2"})) if _idx(token) == 0 else MISS
    v = DomXssStrategy(FakeExec(two, workers)).confirm(_dom_candidate(), None)
    assert _norm(lambda: v) == ("confirmed", 2, 0)


@pytest.mark.parametrize("workers", [1, 3])
def test_a_sibling_that_fired_before_the_page_failed_is_credited(toks, workers):
    """A NotObserved page that still saw a sibling's token (``exc.hits``)."""
    def outcome(token):
        if _idx(token) == 0:
            exc = NotObserved("load failed")
            exc.hits = frozenset({token[:-1] + "2"})
            return exc
        return MISS
    v = DomXssStrategy(FakeExec(outcome, workers)).confirm(_dom_candidate(), None)
    assert _norm(lambda: v) == ("confirmed", 2, 0)


def _failed_with_sibling(page: int, sibling: int):
    """Pages 0 and 1 are not observed; page ``page`` also fails, but only after
    payload ``sibling``'s token fired on it."""
    def outcome(token):
        i = _idx(token)
        if i == page:
            exc = NotObserved("load failed late")
            exc.hits = frozenset({token[:-1] + str(sibling)})
            return exc
        return NO if i in (0, 1) else MISS
    return outcome


@pytest.mark.parametrize("workers", [1, 3])
def test_the_main_loop_credits_a_sibling_seen_before_a_page_failed(toks, workers):
    # page 1 fails after payload 0's token fired on it: payload 0's hit
    def outcome(token):
        if _idx(token) == 1:
            exc = NotObserved("load failed late")
            exc.hits = frozenset({token[:-1] + "0"})
            return exc
        return NO if _idx(token) == 0 else MISS
    v = DomXssStrategy(FakeExec(outcome, workers)).confirm(_dom_candidate(), None)
    assert _norm(lambda: v) == ("confirmed", 0, 1)


@pytest.mark.parametrize("workers", [1, 3])
def test_the_last_try_credits_a_sibling_seen_before_its_page_failed(toks, workers):
    """After two unobserved payloads, the last try (payload 2, the quote-free one)
    fails too, but payload 0's token fired on its page first. The main loop credits
    such a hit (test above); the last try must not drop it."""
    v = DomXssStrategy(FakeExec(_failed_with_sibling(2, 0), workers)).confirm(
        _dom_candidate(), None)
    assert _norm(lambda: v) == ("confirmed", 0, 2), v


def _other_candidates_tokens(toks, workers, strategy_cls=DomXssStrategy):
    """Candidate 0 is confirmed by its own payload 0; then candidate 1's every page
    sees ALL of candidate 0's tokens and none of its own."""
    first = strategy_cls(FakeExec(lambda t: HIT, workers)).confirm(_dom_candidate(), None)
    assert first is not None and first.confirmed
    foreign = frozenset(_tok(0, i) for i in range(N))

    def outcome(token):
        assert _cand_of(token) == 1
        return ExecObservation(executed=False, detail="echo", hits=foreign)
    ex = FakeExec(outcome, workers)
    return strategy_cls(ex).confirm(_dom_candidate(), None), ex


@pytest.mark.parametrize("workers", [1, 2, 3])
def test_another_candidates_token_never_confirms_this_one(toks, workers):
    v, ex = _other_candidates_tokens(toks, workers)
    assert v is None                         # every payload observed, none of its own
    assert sorted(_idx(t) for t in ex.loads) == list(range(N))


@pytest.mark.parametrize("workers", [1, 3])
def test_another_candidates_token_on_a_failed_page_never_confirms(toks, workers):
    DomXssStrategy(FakeExec(lambda t: HIT, workers)).confirm(_dom_candidate(), None)
    foreign = frozenset(_tok(0, i) for i in range(N))

    def outcome(token):
        exc = NotObserved("load failed")
        exc.hits = foreign
        return exc
    v = DomXssStrategy(FakeExec(outcome, workers)).confirm(_dom_candidate(), None)
    assert v is not None and v.inconclusive and not v.confirmed


def test_the_foreign_token_check_catches_a_strategy_that_takes_any_token(toks):
    v, _ex = _other_candidates_tokens(toks, 3, _NaiveAnyToken)
    assert v is not None and v.confirmed      # the offender is caught by the check


# --- 1c: workers=1 is the old loop; workers 2/3 decide as workers=1 ---------------------
def test_workers_1_loads_what_the_old_loop_loaded_and_stops_at_the_first_hit(toks):
    for vec in itertools.product(OUTCOMES, repeat=N):
        ref, ref_loads = reference(vec)
        ex = FakeExec(_by_vec(vec), workers=1)
        got = _norm(partial(DomXssStrategy(ex).confirm, _dom_candidate(), None))
        assert got == ref, vec
        assert [_idx(t) for t in ex.loads] == ref_loads, vec
        assert ex.many_calls == 0, vec
        # an executor without run_many is the same
        seq = SeqExec(_by_vec(vec))
        assert _norm(partial(DomXssStrategy(seq).confirm, _dom_candidate(), None)) == ref
        assert [_idx(t) for t in seq.loads] == ref_loads, vec


@pytest.mark.parametrize("truncate", [False, True])
@pytest.mark.parametrize("workers", [2, 3])
def test_every_outcome_vector_decides_as_one_at_a_time(toks, workers, truncate):
    for vec in itertools.product(OUTCOMES, repeat=N):
        ref, ref_loads = reference(vec)
        ex = FakeExec(_by_vec(vec), workers=workers, truncate=truncate)
        got = _norm(partial(DomXssStrategy(ex).confirm, _dom_candidate(), None))
        assert got == ref, (vec, got, ref)
        idx = [_idx(t) for t in ex.loads]
        assert len(idx) == len(set(idx)), (vec, idx)         # nothing observed twice
        assert len(idx) <= len(ref_loads) + workers - 1, (vec, idx, ref_loads)
        assert all(len(w) <= workers for w in ex.waves), ex.waves


@pytest.mark.parametrize("workers", [1, 2, 3])
def test_stored_strategy_decides_as_one_at_a_time_on_sampled_vectors(toks, workers):
    rng = random.Random(720)
    for _ in range(600):
        vec = tuple(rng.choice(OUTCOMES) for _ in range(N))
        ref, _loads = reference(vec)
        ex = FakeExec(_by_vec(vec), workers=workers, truncate=True)
        got = _norm(partial(StoredXssStrategy(ex).confirm, _stored_candidate(), None))
        assert got == ref, (vec, got, ref)


class _NaiveAllAtOnce(DomXssStrategy):
    """Synthetic offender: observes every payload, first hit in any order wins."""

    def confirm(self, candidate, sender):
        tokens = [S._token() for _ in range(N)]
        payloads = [_xss_exec_payloads(t)[i] for i, t in enumerate(tokens)]
        results = observe_many(self._executor, [
            (self._exec_request(candidate, p), t) for p, t in zip(payloads, tokens)])
        for i, r in enumerate(results):
            if isinstance(r, ExecObservation) and r.executed:
                return Verdict(True, self.vuln_class, self.mechanism,
                               {"payload": payloads[i]})
        return None


def test_the_equivalence_check_catches_an_all_at_once_strategy(toks):
    differs = 0
    for vec in itertools.product(OUTCOMES, repeat=N):
        ref, _ = reference(vec)
        ex = FakeExec(_by_vec(vec), workers=3)
        if _norm(partial(_NaiveAllAtOnce(ex).confirm, _dom_candidate(), None)) != ref:
            differs += 1
    assert differs > 0


# --- 2: the cost bound ------------------------------------------------------------------
@pytest.mark.parametrize("strategy,cand", [(DomXssStrategy, _dom_candidate),
                                           (StoredXssStrategy, _stored_candidate)])
@pytest.mark.parametrize("workers", [1, 2, 3])
def test_an_unloadable_page_costs_at_most_three_loads(toks, workers, strategy, cand):
    ex = FakeExec(lambda t: NO, workers=workers, truncate=True)
    v = strategy(ex).confirm(cand(), None)
    assert v is not None and v.inconclusive
    assert len(ex.loads) <= 3, ex.loads


@pytest.mark.parametrize("workers", [1, 2, 3])
def test_an_unloadable_page_costs_at_most_three_real_executor_visits(monkeypatch, toks,
                                                                     workers):
    """The same bound through the real `run`/`run_many` (the visit itself faked)."""
    visits = []

    def observe(self, request, token, visit, session):
        visits.append(token)
        raise NotObserved("never loads")
    monkeypatch.setattr(PlaywrightBrowserExecutor, "_observe", observe)
    ex = PlaywrightBrowserExecutor(workers=workers)
    v = StoredXssStrategy(ex).confirm(_stored_candidate(), None)
    assert v is not None and v.inconclusive
    assert len(visits) <= 3, visits


def test_workers_of_and_its_bounds():
    assert workers_of(SeqExec(lambda t: MISS)) == 1
    assert workers_of(FakeExec(lambda t: MISS, workers=3)) == 3
    for bad in (0, 4, True, 2.0):
        with pytest.raises(ValueError):
            PlaywrightBrowserExecutor(workers=bad)
    assert PlaywrightBrowserExecutor().workers == PlaywrightBrowserExecutor.MAX_WORKERS


# --- 3: the session, once per scope per wave, on the caller thread ---------------------
class _Manager:
    """A session whose material changes on every route call (a re-login)."""

    def __init__(self):
        self.material = 0


def _routed(monkeypatch, *, fail_on=()):
    """``(executor, route_calls, visits)``: the route records its thread and bumps the
    material; `browser_session` is the material as a fresh object; `_observe` records
    ``(thread, session)`` and returns "not executed"."""
    from fuzzlab.tools import browserauth
    mgr = _Manager()
    route_calls: list = []
    visits: list = []

    def route(urls):
        route_calls.append((threading.get_ident(), tuple(urls)))
        if len(route_calls) in fail_on:
            raise RuntimeError("the login failed")
        mgr.material += 1
        return (mgr, "alice", None)

    def browser_session(manager, identity, base_url, *, in_scope, scope_urls=()):
        return types.SimpleNamespace(material=manager.material, identity=identity)

    def observe(self, request, token, visit, session):
        visits.append((threading.get_ident(), session, token))
        time.sleep(0.02)                           # let the wave overlap
        return ExecObservation(executed=False, detail="")
    monkeypatch.setattr(browserauth, "browser_session", browser_session)
    monkeypatch.setattr(PlaywrightBrowserExecutor, "_observe", observe)
    return PlaywrightBrowserExecutor(session_route=route, workers=3), route_calls, visits


def test_each_wave_resolves_the_session_once_on_the_caller_thread(monkeypatch, toks):
    ex, route_calls, visits = _routed(monkeypatch)
    caller = threading.get_ident()
    v = StoredXssStrategy(ex).confirm(_stored_candidate(), None)
    assert v is None                                   # six observed, none fired
    assert len(route_calls) == 2, route_calls          # two waves of three, one scope
    assert all(tid == caller for tid, _u in route_calls)
    assert len(visits) == N
    assert all(tid != caller for tid, _s, _t in visits)   # each visit on a worker
    by_token = {t: s for _tid, s, t in visits}
    first = [by_token[_tok(0, i)] for i in range(3)]
    second = [by_token[_tok(0, i)] for i in range(3, N)]
    assert all(s is first[0] for s in first) and all(s is second[0] for s in second)
    assert first[0].material == 1 and second[0].material == 2   # the re-login's


def test_one_wave_resolves_the_session_once_per_scope(monkeypatch):
    from fuzzlab.oracle.browser import ExecRequest, StoreStep
    ex, route_calls, visits = _routed(monkeypatch)
    a = "http://127.0.0.1:9/store"
    b = "http://127.0.0.1:9/other-store"
    items = [(ExecRequest(url="http://127.0.0.1:9/render",
                          store=StoreStep(url=u, param="c", value=f"v{i}")), f"k{i}")
             for i, u in enumerate([a, b, a])]
    results = ex.run_many(items)
    assert all(isinstance(r, ExecObservation) for r in results)
    assert len(route_calls) == 2 and all(t == threading.get_ident()
                                         for t, _u in route_calls)
    sess = {t: s for _tid, s, t in visits}
    assert sess["k0"] is sess["k2"] and sess["k0"] is not sess["k1"]


def test_a_login_failure_starts_no_visit_of_its_wave(monkeypatch, toks):
    ex, route_calls, visits = _routed(monkeypatch, fail_on={1})
    with pytest.raises(RuntimeError, match="the login failed"):
        StoredXssStrategy(ex).confirm(_stored_candidate(), None)
    assert len(route_calls) == 1 and visits == []


def test_run_many_hands_back_a_login_failure_for_the_first_item_only(monkeypatch):
    from fuzzlab.oracle.browser import ExecRequest, StoreStep
    ex, route_calls, visits = _routed(monkeypatch, fail_on={1})
    items = [(ExecRequest(url="http://127.0.0.1:9/render",
                          store=StoreStep(url="http://127.0.0.1:9/store", param="c",
                                          value=f"v{i}")), f"k{i}") for i in range(3)]
    results = ex.run_many(items)
    assert isinstance(results[0], RuntimeError) and results[1:] == [None, None]
    assert len(route_calls) == 1 and visits == []


def test_a_login_failure_in_the_second_wave_propagates(monkeypatch, toks):
    ex, route_calls, visits = _routed(monkeypatch, fail_on={2})
    with pytest.raises(RuntimeError, match="the login failed"):
        StoredXssStrategy(ex).confirm(_stored_candidate(), None)
    assert len(visits) == 3 and len(route_calls) == 2


# --- the launch-failure counter across one wave -----------------------------------------
def _fake_playwright(monkeypatch, state):
    """A fake `playwright.sync_api`: ``launch`` fails while ``state['transient']``;
    otherwise a browser whose context creation raises the driver's Error (the visit
    is then NotObserved, after the launch succeeded)."""
    Error = type("Error", (Exception,), {})

    class Browser:
        def new_context(self, **kw):
            raise Error("context failed")

        def close(self):
            pass

    def launch(**kw):
        state["launches"] += 1
        if state["transient"]:
            raise RuntimeError("out of memory")
        return Browser()

    class PW:
        chromium = types.SimpleNamespace(launch=launch)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    fake = types.ModuleType("playwright.sync_api")
    fake.sync_playwright = PW
    fake.Error = Error
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake)


@pytest.mark.parametrize("workers", [1, 3])
def test_one_candidates_transient_launch_failure_does_not_switch_m6_off(monkeypatch, toks,
                                                                       workers):
    """`MAX_LAUNCH_FAILURES` counts launch failures in a row so that one transient
    failure does not silence M6 for the run (reviewer A). One candidate meeting a
    transient failure costs one count at workers=1; its wave must not count it once
    per concurrent visit and switch the browser off for every later candidate."""
    state = {"transient": True, "launches": 0}
    _fake_playwright(monkeypatch, state)
    ex = PlaywrightBrowserExecutor(workers=workers)
    with pytest.raises(UnplaceableLocation, match="browser unavailable"):
        DomXssStrategy(ex).confirm(_dom_candidate(), None)
    state["transient"] = False                       # the pressure is gone
    v = DomXssStrategy(ex).confirm(_dom_candidate(), None)
    assert ex._unavailable is None, ex._unavailable
    assert v is not None and v.inconclusive           # observed (NotObserved pages)


@pytest.mark.parametrize("workers", [1, 3])
def test_one_waves_driver_stop_failures_do_not_switch_m6_off(monkeypatch, toks, workers):
    """BUG-0740's sweep: the driver-stop counter (`_stop_failures`, also "in a row")
    counts one wave's concurrent stop failures once, as it counts one visit's."""
    state = {"transient": False, "launches": 0, "stop_fail": True}
    _fake_playwright(monkeypatch, state)
    fake = sys.modules["playwright.sync_api"]

    class PW(fake.sync_playwright):
        def __exit__(self, *a):
            if state["stop_fail"]:
                raise fake.Error("the driver did not stop")
            return False
    fake.sync_playwright = PW
    ex = PlaywrightBrowserExecutor(workers=workers)
    DomXssStrategy(ex).confirm(_dom_candidate(), None)
    if workers == 1:                         # one at a time: two stops in a row fail
        assert ex._unavailable is not None
        return
    assert ex._stop_failures <= 2           # one per wave (two waves at most)
    state["stop_fail"] = False
    ex2 = PlaywrightBrowserExecutor(workers=workers)
    ex2._stop_failures = 0
    # a single wave of three concurrent stop failures counts once
    state["stop_fail"] = True
    ex2.run_many([(r, t) for r, t in [
        (ExecRequest(url="http://127.0.0.1:9/p", param="q", value="v", location="query"),
         f"t{i}") for i in range(3)]])
    assert ex2._stop_failures == 1 and ex2._unavailable is None


# --- 4: the trace of a wave -------------------------------------------------------------
def _traced_visit_fakes(monkeypatch, emit_threads):
    _fake_playwright(monkeypatch, {"transient": False, "launches": 0})

    def in_browser(self, pw, request, token, error, visit=None, *, session=None,
                   hits=None):
        if visit is not None:
            visit.navigate_done(visit.started(), request, nav=types.SimpleNamespace(
                response=types.SimpleNamespace(status=200),
                committed_at=time.monotonic(), superseded=False))
        time.sleep(0.02)
        return ExecObservation(executed=False, detail="")
    monkeypatch.setattr(PlaywrightBrowserExecutor, "_in_browser", in_browser)
    real_emit = trace.emit_step

    def emit_step(kind, body, **kw):
        emit_threads.append(threading.get_ident())
        return real_emit(kind, body, **kw)
    monkeypatch.setattr(trace, "emit_step", emit_step)


def _browser_steps(store, run):
    return [json.loads(r["body"]) for r in store.conn.execute(
        "SELECT body FROM trace_event WHERE run_id=? AND kind='browser.step' ORDER BY seq",
        (run,))]


def test_every_visit_of_a_wave_is_traced_from_the_caller_thread(monkeypatch, tmp_path,
                                                                toks):
    emit_threads: list = []
    _traced_visit_fakes(monkeypatch, emit_threads)
    caller = threading.get_ident()
    with Store(tmp_path / "t.db") as store:
        run = store.start_run("auto", "h")
        rec = trace.TraceRecorder(store, run, max_buffer=1)   # each emit writes now
        with trace.recording(rec), trace.test_scope("t1"), \
                trace.strategy_scope(STRATEGY):
            v = DomXssStrategy(PlaywrightBrowserExecutor(workers=3)).confirm(
                _dom_candidate(), None)
            collected = trace.collected_steps()
        stats = rec.close()
        steps = _browser_steps(store, run)
    assert v is None
    assert stats["dropped"] == 0, stats
    assert emit_threads and all(t == caller for t in emit_threads)
    visits: dict = {}
    for b in steps:
        visits.setdefault(b["visit"], []).append(b["step"])
        assert b["test"] == "t1" and b["strategy"] == STRATEGY, b
    assert len(visits) == N, visits                     # two waves of three
    for names in visits.values():
        assert "navigate" in names and names[-1] == "end", names
    assert len(collected) == len(steps)


def test_a_visit_emitted_from_another_thread_is_lost(monkeypatch, tmp_path):
    """The trace test's detection is real: a recorder written from a worker thread
    records nothing (sqlite refuses another thread's use of its connection)."""
    from fuzzlab.oracle.browser import ExecRequest
    from fuzzlab.tools.browserexec import _VisitTrace
    with Store(tmp_path / "x.db") as store:
        run = store.start_run("auto", "h")
        rec = trace.TraceRecorder(store, run, max_buffer=1)
        with trace.recording(rec), trace.test_scope("t1"), \
                trace.strategy_scope(STRATEGY):
            visit = _VisitTrace(ExecRequest(url="http://127.0.0.1:9/p"), "tok")
            visit.end("not_executed")
            import contextvars
            ctx = contextvars.copy_context()
            th = threading.Thread(target=ctx.run, args=(visit.emit,))
            th.start()
            th.join()
        rec.close()
        assert _browser_steps(store, run) == []


# --- 5: the real browser ----------------------------------------------------------------
def _playwright_or_skip():
    from tests._browser import skip_or_fail
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")


def _skip_if_unavailable(results):
    from tests._browser import skip_or_fail
    for r in results:
        if isinstance(r, UnplaceableLocation) and not isinstance(r, NotObserved) \
                and str(r).startswith("browser unavailable"):
            skip_or_fail(f"chromium could not launch: {r}")


@pytest.fixture
def slow_base():
    _playwright_or_skip()
    from tests.test_m6_slow_sinks import _app
    server = _app()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _slow_cases():
    from tests.test_m6_slow_sinks import _CASES
    return sorted(_CASES)


@pytest.mark.parametrize("case", _slow_cases())
def test_real_every_late_sink_is_seen_in_a_wave_of_three(slow_base, case, monkeypatch):
    from fuzzlab.oracle.browser import ExecRequest
    cases = _slow_cases()
    other = cases[(cases.index(case) + 1) % len(cases)]
    spans: list = []
    real_observe = PlaywrightBrowserExecutor._observe

    def observe(self, request, token, visit, session):
        t0 = time.monotonic()
        try:
            return real_observe(self, request, token, visit, session)
        finally:
            spans.append((threading.get_ident(), t0, time.monotonic()))
    monkeypatch.setattr(PlaywrightBrowserExecutor, "_observe", observe)

    def req(path, tok):
        return (ExecRequest(url=f"{slow_base}{path}#/s", param="q",
                            value=_xss_exec_payloads(tok)[0], location="fragment"), tok)
    ex = PlaywrightBrowserExecutor(timeout_ms=10000, workers=3)
    results = ex.run_many([req(f"/{case}", "tokA"), req(f"/safe/{case}", "tokB"),
                           req(f"/safe/{other}", "tokC")])
    _skip_if_unavailable(results)
    sink, twin, twin2 = results
    assert isinstance(sink, ExecObservation) and sink.executed, sink
    assert "tokA" in sink.hits and not sink.hits - {"tokA"}, sink.hits
    for safe in (twin, twin2):
        assert isinstance(safe, ExecObservation) and not safe.executed, safe
        assert safe.hits == frozenset(), safe.hits
    # the wave really ran concurrently: three worker threads whose visits overlapped
    assert len({tid for tid, _a, _b in spans}) == 3
    assert max(a for _t, a, _b in spans) < min(b for _t, _a, b in spans)


class _Board(BaseHTTPRequestHandler):
    """``POST /store`` keeps every posted field ``(name, value)``; ``/render`` writes
    every stored value: field ``c`` with ``innerHTML`` unless it holds a ``'`` (then
    ``textContent``), field ``t`` always with ``textContent``. So payload 0 (single
    quoted) never runs, payloads 1 (backtick) and 2 (fromCharCode) do; a ``t`` plant
    never runs."""
    stored: ClassVar[list] = []
    lock = threading.Lock()

    def log_message(self, *a):
        pass

    def _send(self, status, body=b"", ctype="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if self.path != "/store":
            return self._send(404)
        with type(self).lock:
            type(self).stored.extend(parse_qsl(body, keep_blank_values=True))
        self._send(200, b"ok", "text/plain")

    def do_GET(self):
        if self.path.split("?", 1)[0] != "/render":
            return self._send(404)
        with type(self).lock:
            data = json.dumps(type(self).stored).replace("</", "<\\/")
        page = ("<html><body><div id=m></div><script>var V=" + data + ";"
                "V.forEach(function(e){var p=document.createElement('p');"
                "if(e[0]==='c'&&e[1].indexOf(\"'\")<0){p.innerHTML=e[1];}"
                "else{p.textContent=e[1];}"
                "document.getElementById('m').appendChild(p);});</script></body></html>")
        self._send(200, page.encode())


@pytest.fixture
def board():
    _playwright_or_skip()
    _Board.stored = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Board)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _values(name):
    with _Board.lock:
        return [v for k, v in _Board.stored if k == name]


def _confirm_or_skip(strategy, cand):
    from tests._browser import skip_or_fail
    try:
        return strategy.confirm(cand, None)
    except UnplaceableLocation as exc:
        if str(exc).startswith("browser unavailable"):
            skip_or_fail(f"chromium could not launch: {exc}")
        raise


def test_real_stored_crosstalk_is_credited_to_a_really_planted_token(board):
    def executor():
        ex = PlaywrightBrowserExecutor(timeout_ms=10000, workers=3)
        ex.SETTLE_MS = 2000                  # every sink here runs on render
        return ex

    def cand(param):
        return Candidate(url=board + "/render", param=param, category="xss",
                         store_url=board + "/store", store_param=param)

    # candidate A: payload 0 never runs; the credit is a planted, quote-free sibling
    va = _confirm_or_skip(StoredXssStrategy(executor()), cand("c"))
    a_values = _values("c")
    assert va is not None and va.confirmed, (va, a_values)
    credited = va.evidence["payload"]
    assert credited in a_values and "'" not in credited, va.evidence
    a_tokens = {_token_in(p) for p in a_values}
    assert _token_in(credited) in a_tokens
    if "observed_with" in va.evidence:
        assert va.evidence["observed_with"] in a_values
        assert va.evidence["observed_with"] != credited

    # candidate B plants into the escaped field: its own payloads never run, while A's
    # stored siblings fire on every one of its pages -- never B's hit
    vb = _confirm_or_skip(StoredXssStrategy(executor()), cand("t"))
    b_values = _values("t")
    assert len(b_values) == N, b_values           # all six planted and observed
    assert vb is None, vb.evidence if vb else vb

    # candidate C plants into the executing field again, A's payloads still there: the
    # credit is one of C's own plants, never one of A's
    vc = _confirm_or_skip(StoredXssStrategy(executor()), cand("c"))
    c_values = [v for v in _values("c") if v not in a_values]
    assert vc is not None and vc.confirmed
    assert vc.evidence["payload"] in c_values, (vc.evidence, c_values)
    assert _token_in(vc.evidence["payload"]) not in a_tokens
