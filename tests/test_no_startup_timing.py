"""BUG-0526 / PA-0526: a test that bounds how long a browser-driven step takes times that
step at its own call, never a span that also holds the run's start.

`test_a_login_page_that_navigates_away_fails_loudly_and_fast` bounded a whole browser
login (`took < 8.0`). Under the harness's parallel load the Playwright driver's start
alone took 4.5-7 s (0.5 s idle, measured), and the test failed on correct code. This guard
finds that shape: a duration taken around a call to a run-level entry point (one that
starts a browser or its driver) and asserted below a small constant. A whole-run bound of
30 s or more is a smoke alarm (PA-0135(1)) and stays allowed.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent
#: Calls that start a browser or its driver inside the timed span.
RUN_ENTRIES = frozenset({"_login", "fetch", "_m6_run", "crawl", "run_auto", "run",
                         "login", "ensure"})
#: Below this a whole-run bound is a timing claim, not a smoke alarm.
SMOKE_S = 30.0


def _called(nodes) -> set[str]:
    out = set()
    for node in nodes:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                f = sub.func
                out.add(f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", ""))
    return out


def _starts(node) -> str | None:
    """``x = time.monotonic()`` (or ``perf_counter``): the clock name assigned."""
    if (isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr in ("monotonic", "perf_counter")):
        return node.targets[0].id
    return None


def _value(node, consts: dict):
    """A bound's number: a literal, a module constant, or ``+ - *`` of those."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
        a, b = _value(node.left, consts), _value(node.right, consts)
        if a is None or b is None:
            return None
        return a + b if isinstance(node.op, ast.Add) else a - b \
            if isinstance(node.op, ast.Sub) else a * b
    return None


def offenders(sources: dict[str, str]) -> list[str]:
    found = []
    for name, text in sources.items():
        tree = ast.parse(text)
        consts = {t.id: n.value.value for n in tree.body if isinstance(n, ast.Assign)
                  and isinstance(n.value, ast.Constant)
                  and isinstance(n.value.value, (int, float))
                  for t in n.targets if isinstance(t, ast.Name)}
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = list(ast.walk(fn))
            stmts = [n for n in body if isinstance(n, ast.stmt)]
            stmts.sort(key=lambda n: (n.lineno, n.col_offset))
            durations: dict[str, int] = {}          # duration name -> line it was taken
            for i, st in enumerate(stmts):
                clock = _starts(st)
                if not clock:
                    continue
                for j in range(i + 1, len(stmts)):
                    end = stmts[j]
                    if (isinstance(end, ast.Assign) and isinstance(end.value, ast.BinOp)
                            and isinstance(end.value.op, ast.Sub)
                            and isinstance(end.value.right, ast.Name)
                            and end.value.right.id == clock
                            and isinstance(end.targets[0], ast.Name)):
                        between = [s for s in stmts[i + 1:j]]
                        if _called(between) & RUN_ENTRIES:
                            durations[end.targets[0].id] = end.lineno
                        break
            for node in body:
                if not isinstance(node, ast.Assert):
                    continue
                for sub in ast.walk(node.test):
                    if (isinstance(sub, ast.Compare) and isinstance(sub.left, ast.Name)
                            and sub.left.id in durations
                            and isinstance(sub.ops[0], (ast.Lt, ast.LtE))
                            and (_value(sub.comparators[0], consts) or SMOKE_S) < SMOKE_S):
                        found.append(f"{name}:{node.lineno}")
    return sorted(found)


def test_no_test_bounds_a_span_that_holds_a_browser_start():
    sources = {p.name: p.read_text() for p in ROOT.glob("test_*.py")}
    assert offenders(sources) == []


def test_the_guard_catches_bug_0526_and_allows_a_step_or_a_smoke_bound():
    bug = ("def test_x():\n"
           "    started = time.monotonic()\n"
           "    with pytest.raises(E):\n"
           "        _login(_manager(lab, pw), lab)\n"
           "    took = time.monotonic() - started\n"
           "    assert took < 8.0, took\n")
    assert offenders({"bug.py": bug}) == ["bug.py:6"]
    folded = "FAST = 3.5\n" + bug.replace("_login(_manager(lab, pw), lab)", "fetcher.fetch(u)") \
        .replace("assert took < 8.0", "assert took < FAST + 1.5")
    assert offenders({"folded.py": folded}) == ["folded.py:7"]
    smoke = bug.replace("assert took < 8.0", "assert took < 60.0")
    step = ("def test_y():\n"
            "    started = time.monotonic()\n"
            "    page.wait_for_timeout(1)\n"
            "    took = time.monotonic() - started\n"
            "    assert took < 4.0\n")
    assert offenders({"smoke.py": smoke, "step.py": step}) == []
