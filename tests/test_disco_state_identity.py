"""The disco explorer's state identity, work and restore contract (BUG-0539: audit
defects 1, 2 and 3; FR-CRAWL-31, FR-CRAWL-32, FR-CRAWL-33).

* **Identity** (defect 1): a state is its execution key (`fingerprint.execution_key`,
  SP-62): ``/wizard?step=1`` and ``?step=2`` with the same Next button, ``/users/17``
  and ``/users/42``, one button and two identical buttons, a selected option -- each is
  another state. The structural key (`state_fingerprint`) only schedules and folds; an
  AST guard keeps it out of every visited-state decision.
* **Work** (defect 2): an action's work key is (execution key, signature, occurrence,
  kind); a failed attempt never consumes it; a step taken in another state is
  deprioritised, and skipped only after equal observed effects on two routes.
* **Restore** (defect 3): a recorded core is never accepted by a proper subset and never
  shrunk; a missing replay step fails the restore unless its element is declared
  optional; a path step that sent a non-idempotent request is never replayed.

The pure parts are tested here, on fakes where a page is needed; each defect also has a
real-browser test (`tests/test_disco_state_identity_browser.py`)."""

from __future__ import annotations

import ast
from pathlib import Path

from fuzzlab.disco import explore
from fuzzlab.disco.explore import (EQUIVALENT, FAILED, RETRYABLE, SUCCEEDED, Frontier,
                                   Reading, State, Step, WorkLedger, contract_mismatch,
                                   work_key)
from fuzzlab.disco.fingerprint import (element_multiset, element_signature, execution_key,
                                       execution_route, state_fingerprint,
                                       workflow_markers)

BASE = "http://127.0.0.1:8080"
NEXT = {"tag": "button", "type": "submit", "id": "next", "ancestry": "div#dlg"}
ROOT = Path(__file__).resolve().parents[1]


# --- defect 1: two keys ------------------------------------------------------------------

def test_a_query_value_a_numeric_segment_or_a_second_identical_button_is_another_state():
    """The audit's reproductions: each pair folds to one structural key (scheduling and
    folding are unchanged) but is two execution states."""
    pairs = [
        ((f"{BASE}/wizard?step=1", [NEXT]), (f"{BASE}/wizard?step=2", [NEXT])),
        ((f"{BASE}/users/17", [NEXT]), (f"{BASE}/users/42", [NEXT])),
        ((f"{BASE}/#/list?page=1", [NEXT]), (f"{BASE}/#/list?page=2", [NEXT])),
        ((f"{BASE}/cart", [NEXT]), (f"{BASE}/cart", [NEXT, dict(NEXT)])),
    ]
    for (url_a, els_a), (url_b, els_b) in pairs:
        assert state_fingerprint(url_a, els_a) == state_fingerprint(url_b, els_b)
        assert execution_key(url_a, els_a) != execution_key(url_b, els_b), (url_a, url_b)
    assert element_multiset([NEXT, dict(NEXT)]) == ((element_signature(NEXT), 2),)
    # the same page read twice is one state, whatever order the query is written in
    assert execution_key(f"{BASE}/w?a=1&b=2", [NEXT]) == execution_key(f"{BASE}/w?b=2&a=1",
                                                                       [NEXT])


def test_a_selected_control_or_a_hidden_step_marker_is_another_state_typed_text_is_not():
    sel = {"tag": "select", "name": "account", "sel": "value=business"}
    other = dict(sel, sel="value=personal")
    assert workflow_markers([sel]) != workflow_markers([other])
    assert execution_key(f"{BASE}/t", [sel], workflow_markers([sel])) != \
        execution_key(f"{BASE}/t", [other], workflow_markers([other]))
    step1 = workflow_markers([], [["hidden", "step", "1"]])
    step2 = workflow_markers([], [["hidden", "step", "2"]])
    assert step1 and step1 != step2
    stepper = workflow_markers([], [["current", "li<ol.steps", 2, "step"]])
    assert stepper == ("current:li<ol.steps@2=step",)
    typed = {"tag": "input", "type": "text", "name": "q", "value": "anything"}
    assert workflow_markers([typed]) == ()                  # typed text is data


def test_a_token_in_the_query_or_a_csrf_input_never_splits_a_state():
    """A token selects no workflow and changes per session: its value is replaced in
    the route, and a token-like or sensitively named hidden input is no marker."""
    assert execution_route(f"{BASE}/p?token=abc123&id=7") == \
        execution_route(f"{BASE}/p?token=zzz999&id=7")
    assert execution_route(f"{BASE}/p?id=7") != execution_route(f"{BASE}/p?id=9")
    assert execution_route(f"{BASE}/#/r?session=a1&x=1") == \
        execution_route(f"{BASE}/#/r?session=b2&x=1")
    assert workflow_markers([], [["hidden", "_csrf", "short"],
                                 ["hidden", "nonce", "Zq8vR2kLp0aX7mWc4tYb"],
                                 ["hidden", "blob", "x" * 70]]) == ()


def test_the_session_generation_has_its_slot_in_the_key():
    assert execution_key(f"{BASE}/a", [NEXT], (), 0) != execution_key(f"{BASE}/a", [NEXT], (), 1)


def test_a_full_route_reports_each_state_it_refuses_and_layouts_order_the_rest():
    """The per-route bound is a reported coverage exclusion, never an equivalence; the
    structural key orders a new route, then a new layout, then a variant."""
    def st(key, url, structure):
        return State(key, url, url, structure=structure)
    front = Frontier(per_route=3)
    assert front.push(st("a", f"{BASE}/w?step=1", "L1"))
    assert front.push(st("b", f"{BASE}/w?step=2", "L1"))            # a variant
    assert front.push(st("c", f"{BASE}/w?step=3", "L2"))            # a new layout
    assert not front.push(st("d", f"{BASE}/w?step=4", "L1"))        # the route is full
    assert front.excluded == {f"{BASE}/w?step": 1}
    assert front.push(st("e", f"{BASE}/other", "L3"))
    assert [front.pop().fp for _ in range(4)] == ["a", "e", "c", "b"]


# --- defect 2: the work key --------------------------------------------------------------

def test_the_same_step_in_another_execution_state_of_one_route_is_new_work():
    """A dialog's second stage keeps its Next: the work done in the first stage is not
    the second's (the pre-fix key was the route's)."""
    ledger = WorkLedger()
    nxt = Step(element_signature(NEXT), "click")
    first, second = work_key("stage-1", nxt), work_key("stage-2", nxt)
    assert ledger.claim(first)
    ledger.finish(first, SUCCEEDED)
    assert not ledger.open(first)
    assert ledger.open(second) and ledger.claim(second)


def test_a_failed_attempt_never_consumes_the_work_and_is_retried_then_failed():
    ledger = WorkLedger(max_attempts=3)
    key = work_key("s", Step("sig", "click"))
    assert ledger.claim(key)
    assert ledger.fail(key) is True and ledger.status[key] == RETRYABLE
    assert ledger.open(key) and ledger.claim(key)                  # retried
    assert ledger.fail(key) is True and ledger.claim(key)
    assert ledger.fail(key) is False and ledger.status[key] == FAILED
    assert not ledger.open(key)
    assert ledger.counts() == {FAILED: 1}


def test_presumed_chrome_is_deprioritised_and_skipped_only_on_equal_effects_on_two_routes():
    ledger = WorkLedger()
    theme = ("theme-sig", 0, "click")
    same = ((), "same")
    assert not ledger.performed(theme)
    ledger.observe(theme, f"{BASE}/", same)
    assert ledger.performed(theme) and not ledger.established(theme)   # deprioritised
    ledger.observe(theme, f"{BASE}/", same)                # another state, same route
    assert not ledger.established(theme)
    ledger.observe(theme, f"{BASE}/#/projects", same)
    assert ledger.established(theme)                       # now equivalent: skipped
    nxt = ("next-sig", 0, "click")
    ledger.observe(nxt, f"{BASE}/a", ((), "stage-2"))
    ledger.observe(nxt, f"{BASE}/b", ((("POST", f"{BASE}/api/confirm"),), "same"))
    ledger.observe(nxt, f"{BASE}/c", ((), "stage-2"))
    assert not ledger.established(nxt)                     # its effects differed once
    key = work_key("s", Step("theme-sig", "click"))
    ledger.finish(key, EQUIVALENT)
    assert ledger.counts() == {EQUIVALENT: 1}


# --- defect 3: the restore contract ------------------------------------------------------

PAY = {"tag": "button", "id": "pay"}
TERMS = {"tag": "button", "id": "terms"}


def _reading(url, els, markers=()):
    return Reading(execution_key(url, els, markers), state_fingerprint(url, els), url,
                   els, element_multiset(els), tuple(markers))


def test_a_recorded_core_is_never_accepted_by_a_proper_subset_nor_shrunk():
    """The audit's reproduction: a state recorded with {pay, terms}, read back with
    {pay} only, was accepted and its core reduced to {pay} for good."""
    url = f"{BASE}/shop"
    state = State.read(_reading(url, [PAY, TERMS]), entry_url=url)
    recorded = state.core
    assert contract_mismatch(state, _reading(url, [PAY])) == "core"
    assert state.core == recorded and state.unresolved is None
    # more than the contract (a notice shown again) still reproduces it
    assert contract_mismatch(state, _reading(url, [PAY, TERMS, NEXT])) is None
    # two of a control recorded twice: one is not enough
    two = State.read(_reading(url, [PAY, dict(PAY)]), entry_url=url)
    assert contract_mismatch(two, _reading(url, [PAY])) == "core"
    assert contract_mismatch(state, _reading(f"{BASE}/shop?step=2", [PAY, TERMS])) == "route"


def test_only_a_declared_optional_feature_or_marker_may_be_missing():
    url = f"{BASE}/shop"
    state = State.read(_reading(url, [PAY, TERMS], ["hidden:step=2"]), entry_url=url)
    assert contract_mismatch(state, _reading(url, [PAY], ["hidden:step=2"]),
                             optional=frozenset({element_signature(TERMS)})) is None
    assert contract_mismatch(state, _reading(url, [PAY, TERMS])) == "markers"
    assert contract_mismatch(state, _reading(url, [PAY, TERMS], ["hidden:step=1"])) == \
        "markers"
    state.optional_markers = ("hidden:step=2",)
    assert contract_mismatch(state, _reading(url, [PAY, TERMS])) is None


class _FakePage:
    url = f"{BASE}/shop"

    def wait_for_timeout(self, _ms):
        pass


def _replay_explorer(monkeypatch, page_els):
    """An explorer whose restore runs on fakes: navigations succeed, the page holds
    ``page_els``, every act succeeds (recorded)."""
    ex = explore.Explorer(f"{BASE}/", scope_urls=[f"{BASE}/"], proxy="127.0.0.1:2")
    navigations, acted = [], []
    monkeypatch.setattr(explore.navguard, "navigate",
                        lambda page, url, **kw: navigations.append(url))
    monkeypatch.setattr(ex, "wait_quiet", lambda page: True)
    monkeypatch.setattr(ex, "_tag", lambda ctx, prefix: prefix)
    monkeypatch.setattr(ex, "_close_popups", lambda ctx, page: None)
    els = [dict(e, signature=element_signature(e), occurrence=0) for e in page_els]
    monkeypatch.setattr(ex, "enumerate", lambda page, ctx: els)
    monkeypatch.setattr(ex, "settled_fingerprint",
                        lambda page, ctx: _reading(_FakePage.url, els))
    monkeypatch.setattr(ex, "act", lambda page, ctx, el, step: acted.append(step) or
                        explore.ACTED)
    return ex, navigations, acted


def test_a_replay_never_skips_a_missing_step_silently(monkeypatch):
    """The pre-fix replay skipped a step whose element was gone and let the contract
    check decide; a step on an element nobody declared optional now fails the
    restore, and one declared optional is skipped and counted."""
    url = _FakePage.url
    ex, _navs, _acted = _replay_explorer(monkeypatch, [PAY])
    state = State.read(_reading(url, [PAY]), entry_url=url,
                       path=[Step(element_signature(NEXT), "click")])
    assert ex.restore(_FakePage(), None, state) is False
    assert ex._restore_failure == "missing-step"
    ex._declare([element_signature(NEXT)], "dismissed")
    assert ex.restore(_FakePage(), None, state) is True
    assert ex.report.replay_skipped_optional == 1


def test_a_path_that_sent_a_non_idempotent_request_is_never_replayed(monkeypatch):
    url = _FakePage.url
    ex, navigations, acted = _replay_explorer(monkeypatch, [PAY, NEXT])
    state = State.read(_reading(url, [PAY, NEXT]), entry_url=url,
                       path=[Step(element_signature(NEXT), "click", safe=False)])
    assert ex.restore(_FakePage(), None, state) is False
    assert ex._restore_failure == "unsafe-step" and navigations == [] and acted == []
    assert state.replayable() is False


# --- SP-62: the structural key never decides a visited state -----------------------------

#: The (module, function) sites that may call `state_fingerprint`: each reads it to
#: schedule or fold, never to decide whether a state was visited.
STRUCTURAL_KEY_SITES = {
    ("fuzzlab/disco/explore.py", "reading"): "a page's structural key, kept beside its "
    "execution key for the frontier's order and the harvest alias",
    ("fuzzlab/disco/explore.py", "_alias_state"): "a harvest alias is a fold: the same "
    "layout under another address (BUG-0505)",
}


def structural_key_calls(trees: dict[str, ast.Module]) -> set[tuple[str, str | None]]:
    """``(module, enclosing function)`` of every call of ``state_fingerprint``."""
    found = set()
    for rel, tree in trees.items():
        if rel == "fuzzlab/disco/fingerprint.py":
            continue
        parents = {ch: n for n in ast.walk(tree) for ch in ast.iter_child_nodes(n)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(
                    node.func, "attr", getattr(node.func, "id", None)) == "state_fingerprint":
                fn, p = None, parents.get(node)
                while p is not None and fn is None:
                    if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        fn = p.name
                    p = parents.get(p)
                found.add((rel, fn))
    return found


def test_the_structural_key_never_decides_a_visited_state():
    """SP-62: every visited-state check reads the execution key. The structural key is
    called only at the listed scheduling and folding sites, and the explorer's
    ``known`` set is filled only from execution keys."""
    trees = {str(p.relative_to(ROOT)): ast.parse(p.read_text(encoding="utf-8"))
             for p in (ROOT / "fuzzlab").rglob("*.py") if "__pycache__" not in p.parts}
    assert structural_key_calls(trees) == set(STRUCTURAL_KEY_SITES)
    src = (ROOT / "fuzzlab/disco/explore.py").read_text(encoding="utf-8")
    assert "known.add(" in src
    for line in src.splitlines():
        if "known.add(" in line:
            assert "structure" not in line and "state_fingerprint" not in line, line


def test_the_structural_key_guard_catches_synthetic_offenders():
    offender = ast.parse("def _process(self, page, els):\n"
                         "    fp = state_fingerprint(page.url, els)\n"
                         "    return fp in self._shared.known\n")
    other = ast.parse("from fuzzlab.disco import fingerprint\n"
                      "def seen(url, els, known):\n"
                      "    return fingerprint.state_fingerprint(url, els) in known\n")
    found = structural_key_calls({"fuzzlab/disco/explore.py": offender,
                                  "fuzzlab/tools/x.py": other})
    assert found == {("fuzzlab/disco/explore.py", "_process"), ("fuzzlab/tools/x.py", "seen")}
    assert not found <= set(STRUCTURAL_KEY_SITES)
