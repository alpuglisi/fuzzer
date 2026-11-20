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
