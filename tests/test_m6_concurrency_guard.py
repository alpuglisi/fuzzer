"""SP-150 (FR-FUZZ-720, FR-FUZZ-723): concurrent M6 browser visits have one owner.

`PlaywrightBrowserExecutor.run_many` is the only place M6 visits run concurrently: it
resolves each wave's session once per scope on the calling thread, creates and emits each
visit's trace there, and gives each worker thread its own driver. A second thread pool
around ``executor.run`` would log in from worker threads (a browser login refuses a
second live worker for one identity, FR-SESS-19) and write the trace store from a thread
that does not own it. So: no module of the oracle or the browser executor starts a thread
outside `run_many`, and a confirmation strategy reaches an executor only through ``run``
or `oracle.browser.observe_many`.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

#: The modules where M6 visits are made or decided.
SCANNED = ("fuzzlab/oracle", "fuzzlab/tools/browserexec.py")
#: (file, function) allowed to start threads.
OWNER = ("fuzzlab/tools/browserexec.py", "run_many")
#: Reviewed allowances: threads that make no browser visit.
ALLOWED = {OWNER,
           # M8's loopback callback listener (its HTTP server thread): no browser
           ("fuzzlab/oracle/oob.py", "start")}
_THREAD_NAMES = {"Thread", "ThreadPoolExecutor", "ProcessPoolExecutor", "Timer",
                 "start_new_thread"}


def _files():
    for rel in SCANNED:
        path = REPO / rel
        yield from ([path] if path.is_file() else sorted(path.rglob("*.py")))


def _thread_starts(src: str, rel: str) -> list[str]:
    """``rel:function:call`` for every thread or pool constructed outside `OWNER`."""
    tree = ast.parse(src)
    out = []
    for fn in (n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        if (rel, fn.name) in ALLOWED:
            continue
        for call in (c for c in ast.walk(fn) if isinstance(c, ast.Call)):
            name = getattr(call.func, "attr", None) or getattr(call.func, "id", None)
            if name in _THREAD_NAMES:
                out.append(f"{rel}:{fn.name}:{name}")
    return sorted(set(out))


def _executor_calls(src: str, rel: str) -> list[str]:
    """Every method called on ``self._executor`` other than ``run``: a strategy reaches
    the executor through ``run`` or `observe_many(self._executor, ...)` only."""
    out = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute) \
                and node.value.attr == "_executor" and node.attr != "run":
            out.append(f"{rel}:{node.attr}")
    return sorted(set(out))


def test_only_run_many_starts_threads_for_m6_visits():
    offenders = []
    for path in _files():
        rel = path.relative_to(REPO).as_posix()
        offenders += _thread_starts(path.read_text(), rel)
    assert offenders == [], offenders


def test_strategies_reach_the_executor_through_run_or_observe_many():
    rel = "fuzzlab/oracle/strategies.py"
    assert _executor_calls((REPO / rel).read_text(), rel) == []


def test_the_guards_catch_synthetic_offenders():
    pool = ("from concurrent.futures import ThreadPoolExecutor\n"
            "def confirm(self):\n"
            "    with ThreadPoolExecutor(3) as p:\n"
            "        p.submit(self._executor.run, 1, 2)\n")
    assert _thread_starts(pool, "fuzzlab/oracle/x.py") == [
        "fuzzlab/oracle/x.py:confirm:ThreadPoolExecutor"]
    thread = "import threading\ndef go():\n    threading.Thread(target=f).start()\n"
    assert _thread_starts(thread, "fuzzlab/oracle/y.py") == ["fuzzlab/oracle/y.py:go:Thread"]
    # the owner itself is allowed
    assert _thread_starts(pool.replace("confirm", "run_many"), OWNER[0]) == []
    direct = "def f(self):\n    self._executor.run_many([])\n    self._executor.run(1, 2)\n"
    assert _executor_calls(direct, "s.py") == ["s.py:run_many"]


# --- PA-0741 (BUG-0741): every reader of a NotObserved outcome reads its hits -----------
#: What catches a `NotObserved`: itself and its bases (`oracle.browser`).
_CATCHES_NOT_OBSERVED = {"NotObserved", "UnplaceableLocation", "Exception", "BaseException"}
#: Methods whose handlers store an outcome for a later reader (never read it here).
_STORES = {"_outcomes"}


def _unread_not_observed(src: str) -> list[str]:
    """Every handler of a method that is the first in its ``try`` to catch a
    `NotObserved` (by name or by a base: `UnplaceableLocation`, ``Exception``, a bare
    ``except``) and does not hand the exception to ``self._failed_hit``: a page that
    failed after one of the candidate's tokens fired would be dropped there (BUG-0741:
    `_last_try` dropped it in an ``except UnplaceableLocation``)."""
    out = []
    for cls in (n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.ClassDef)):
        for fn in (f for f in cls.body if isinstance(f, ast.FunctionDef)):
            if fn.name in _STORES:
                continue
            for node in (t for t in ast.walk(fn) if isinstance(t, ast.Try)):
                for handler in node.handlers:
                    types = ([] if handler.type is None else handler.type.elts
                             if isinstance(handler.type, ast.Tuple) else [handler.type])
                    names = {getattr(t, "id", None) for t in types}
                    if handler.type is not None and not names & _CATCHES_NOT_OBSERVED:
                        continue
                    reads = handler.name is not None and any(
                        isinstance(c, ast.Call)
                        and getattr(c.func, "attr", None) == "_failed_hit"
                        and any(getattr(a, "id", None) == handler.name for a in c.args)
                        for c in ast.walk(handler))
                    if not reads:
                        out.append(f"{cls.name}.{fn.name}")
                    break                    # later handlers never see a NotObserved
    return sorted(set(out))


def test_every_not_observed_reader_credits_a_sibling_it_saw():
    src = (REPO / "fuzzlab/oracle/strategies.py").read_text()
    tree = ast.parse(src)
    cls = next(n for n in ast.walk(tree)
               if isinstance(n, ast.ClassDef) and n.name == "_BrowserXssStrategy")
    assert _unread_not_observed(ast.unparse(cls)) == []
    # and the class really has readers (the guard is not vacuous)
    assert ast.unparse(cls).count("except NotObserved") >= 2


def test_the_not_observed_guard_catches_a_synthetic_offender():
    offender = ("class S:\n    def _last_try(self, get):\n        try:\n            get(1)\n"
                "        except NotObserved:\n            pass\n")
    assert _unread_not_observed(offender) == ["S._last_try"]
    fixed = offender.replace("except NotObserved:\n            pass",
                             "except NotObserved as exc:\n            self._failed_hit(exc)")
    assert _unread_not_observed(fixed) == []
    # BUG-0741's own shape: a base class's handler catches it unread
    base = offender.replace("except NotObserved:", "except UnplaceableLocation:")
    assert _unread_not_observed(base) == ["S._last_try"]
    # a NotObserved handler first, then the base: the base never sees one
    both = fixed.replace("            self._failed_hit(exc)\n",
                         "            self._failed_hit(exc)\n"
                         "        except UnplaceableLocation:\n            pass\n")
    assert _unread_not_observed(both) == []
