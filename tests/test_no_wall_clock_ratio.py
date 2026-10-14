"""BUG-0135 / PA-0135: a complexity test asserts an operation count, never a wall-clock
ratio.

`tests/test_spa_routes.py::test_the_scan_is_linear_on_adversarial_5mb_bodies` asserted
``t_large < 3.5 * t_small`` (two timed runs of `spa.scan_routes`) and failed once under
concurrent load, while the scan itself was linear; the FR-CRAWL-17 scan test repeated
the same shape. PA-0095(2) already asked for an *operation-count* bound, but nothing
enforced it. This guard does: no test under ``tests/`` compares two wall-clock
measurements (or a ratio of them). An absolute smoke bound (``elapsed < 10.0``) stays
allowed; so does a test whose measured property *is* a timing taken by the system under
test (the Ruby side-channel test reads its timings from the app's own output, not from
the test's clock).
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent

#: Clock calls (``time.perf_counter()``, ``perf_counter()``, ...).
_CLOCKS = frozenset({"perf_counter", "perf_counter_ns", "monotonic", "monotonic_ns",
                     "process_time", "process_time_ns", "time", "time_ns"})


def _is_clock(node) -> bool:
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr in _CLOCKS and isinstance(f.value, ast.Name) and f.value.id == "time"
    return isinstance(f, ast.Name) and f.id in _CLOCKS - {"time"}


def _mentions(node, clock_fns: set, timed: set) -> bool:
    """``node`` reads a clock, calls a clock-reading helper, or a timed name."""
    for n in ast.walk(node):
        if _is_clock(n):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and \
                n.func.id in clock_fns:
            return True
        if isinstance(n, ast.Name) and n.id in timed:
            return True
    return False


def _targets(node) -> list[str]:
    out = []
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for t in targets:
        for n in ast.walk(t):
            if isinstance(n, ast.Name):
                out.append(n.id)
    return out


def _ratio(node, clock_fns, timed) -> bool:
    """A division or product of two timed quantities somewhere in ``node``."""
    return any(isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Div, ast.Mult))
               and _mentions(n.left, clock_fns, timed)
               and _mentions(n.right, clock_fns, timed) for n in ast.walk(node))


def wall_clock_ratios(source: str) -> list[str]:
    """Assertions in ``source`` that compare two wall-clock measurements, or a ratio of
    them, as unparsed text."""
    tree = ast.parse(source)
    clock_fns = {f.name for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                 and any(_is_clock(n) for n in ast.walk(f))}
    found = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assigns = [n for n in ast.walk(fn)
                   if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
                   and getattr(n, "value", None) is not None]
        timed: set = set()
        ratios: set = set()
        changed = True
        while changed:                                  # a fixed point over the body
            changed = False
            for a in assigns:
                names = set(_targets(a))
                if _mentions(a.value, clock_fns, timed) and not names <= timed:
                    timed |= names
                    changed = True
                if _ratio(a.value, clock_fns, timed) and not names <= ratios:
                    ratios |= names
                    changed = True
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Assert) and isinstance(node.test, ast.Compare)):
                continue
            cmp = node.test
            sides = [cmp.left, *cmp.comparators]
            timed_sides = sum(_mentions(s, clock_fns, timed) for s in sides)
            # one timing scaled against another (``t2 < 3.5 * t1``); a deadline
            # (``now < start + 10``) is an absolute bound and stays allowed
            scaled = any(isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Mult, ast.Div))
                         and (_mentions(n.left, clock_fns, timed)
                              or _mentions(n.right, clock_fns, timed))
                         for s in sides for n in ast.walk(s))
            if (timed_sides >= 2 and scaled) or _ratio(cmp, clock_fns, timed) or any(
                    isinstance(n, ast.Name) and n.id in ratios for n in ast.walk(cmp)):
                found.append(ast.unparse(cmp))
    return found


def test_no_test_asserts_a_wall_clock_ratio():
    offenders = {}
    for path in sorted(ROOT.glob("test_*.py")):
        hits = wall_clock_ratios(path.read_text())
        if hits:
            offenders[path.name] = hits
    assert offenders == {}


#: BUG-0135's own lines, before the fix (PA-0034(2): the guard is proven on them).
_OLD_SPA_ROUTES = '''
def _time(body, cap):
    start = time.perf_counter()
    spa.scan_routes(body, max_bytes=cap)
    return time.perf_counter() - start


def test_the_scan_is_linear_on_adversarial_5mb_bodies():
    for name, body in _adversarial(big).items():
        assert _time(body, 8 * big) < 10.0, name
    for name in _adversarial(1024):
        t_small = min(_time(small, big) for _ in range(3))
        t_large = min(_time(large, big) for _ in range(3))
        assert t_large < 3.5 * max(t_small, 1e-3), name
'''


def test_the_guard_catches_bug_0135_and_synthetic_offenders():
    assert wall_clock_ratios(_OLD_SPA_ROUTES) == [
        "t_large < 3.5 * max(t_small, 0.001)"]
    for bad in ("def t():\n    a = time.perf_counter()\n    b = time.perf_counter() - a\n"
                "    assert b / a < 2\n",
                "from time import monotonic\ndef t():\n    s = monotonic()\n"
                "    e1 = monotonic() - s\n    e2 = monotonic() - s\n"
                "    r = e2 / e1\n    assert r < 2.2\n",
                "def t():\n    times = {}\n    times['a'] = time.time()\n"
                "    times['b'] = time.time()\n    assert times['b'] <= 2 * times['a']\n"):
        assert wall_clock_ratios(bad), bad
    for ok in ("def t():\n    s = time.perf_counter()\n    f()\n"
               "    assert time.perf_counter() - s < 10.0\n",                  # smoke
               "def t():\n    deadline = time.monotonic() + 5\n"
               "    assert time.monotonic() < deadline\n",                     # a deadline
               "def t():\n    assert large.steps <= 2 * small.steps + 64\n",   # op count
               "def t():\n    early, late = parse(out)\n    assert late / early > 2.0\n"):
        assert not wall_clock_ratios(ok), ok
