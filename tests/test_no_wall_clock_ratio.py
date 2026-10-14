"""BUG-0135 / PA-0135: a complexity test asserts an operation count, never a scaled
comparison or a ratio of wall-clock measurements.

`tests/test_spa_routes.py::test_the_scan_is_linear_on_adversarial_5mb_bodies` asserted
``t_large < 3.5 * t_small`` (two timed runs of `spa.scan_routes`) and failed once under
concurrent load, while the scan itself was linear; the FR-CRAWL-17 scan test repeated
the same shape. PA-0095(2) already asked for an *operation-count* bound, but nothing
enforced it. This guard does: no test under ``tests/`` checks one wall-clock measurement
**scaled** against another (``t2 < 3.5 * t1``) or a **ratio** of two (``t2 / t1 < 2``),
in any spelling the guard can see:

* every comparison nested anywhere in an ``assert`` (``assert ok and t2 < 3 * t1``), in a
  unittest assertion (``self.assertLess(t2, 3 * t1)``, ``assertTrue(...)``), or in an
  ``if`` whose body fails the test (``pytest.fail``, ``raise AssertionError``);
* clocks under any import alias (``import time as tm``, ``from time import perf_counter
  as pc``, ``from time import time``), ``timeit`` (``timeit.timeit``,
  ``default_timer``) and ``datetime.now()`` / ``utcnow()``;
* values timed through a helper: a function or lambda that reads a clock, in the same
  file or imported from another test module.

A deadline (``now < start + 10``) and an absolute smoke bound (``elapsed < 10.0``) stay
allowed, as does a test whose measured property *is* a timing taken by the system under
test (the Ruby side-channel test reads its timings from the app's own output, not from
the test's clock).
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent

#: Clock functions of the ``time`` module.
_TIME_CLOCKS = frozenset({"perf_counter", "perf_counter_ns", "monotonic", "monotonic_ns",
                          "process_time", "process_time_ns", "time", "time_ns"})
#: Clock functions of the ``timeit`` module.
_TIMEIT_CLOCKS = frozenset({"timeit", "repeat", "default_timer"})
#: unittest assertion methods that compare their first two arguments, by operator.
_UNITTEST_CMP = {"assertLess": ast.Lt, "assertLessEqual": ast.LtE,
                 "assertGreater": ast.Gt, "assertGreaterEqual": ast.GtE}
_UNITTEST_TRUTH = frozenset({"assertTrue", "assertFalse"})


class _Clocks:
    """What reads a clock in one module: its import aliases and its timing helpers."""

    def __init__(self, tree, resolve):
        self.time_mods, self.timeit_mods, self.datetime_names = set(), set(), set()
        self.names: set = set()                      # bare clock callables (aliases)
        self.helpers: set = set()                    # functions / lambdas that time
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    bound = a.asname or a.name
                    if a.name == "time":
                        self.time_mods.add(bound)
                    elif a.name == "timeit":
                        self.timeit_mods.add(bound)
                    elif a.name == "datetime":
                        self.datetime_names.add(bound)
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    bound = a.asname or a.name
                    if node.module == "time" and a.name in _TIME_CLOCKS:
                        self.names.add(bound)
                    elif node.module == "timeit" and a.name in _TIMEIT_CLOCKS:
                        self.names.add(bound)
                    elif node.module == "datetime" and a.name == "datetime":
                        self.datetime_names.add(bound)
                    elif resolve is not None and node.module:
                        other = resolve(node.module)
                        if other is not None and a.name in _helpers_of(other, None):
                            self.helpers.add(bound)
        changed = True
        while changed:                               # helpers calling helpers
            changed = False
            for node in ast.walk(tree):
                name, body = _callable(node)
                if name and name not in self.helpers and \
                        any(self.is_clock(n) for n in ast.walk(body)):
                    self.helpers.add(name)
                    changed = True

    def is_clock(self, node) -> bool:
        if not isinstance(node, ast.Call):
            return False
        f = node.func
        if isinstance(f, ast.Name):
            return f.id in self.names or f.id in self.helpers
        if isinstance(f, ast.Attribute):
            base = f.value
            if isinstance(base, ast.Name):
                if base.id in self.time_mods and f.attr in _TIME_CLOCKS:
                    return True
                if base.id in self.timeit_mods and f.attr in _TIMEIT_CLOCKS:
                    return True
                if base.id in self.datetime_names and f.attr in ("now", "utcnow"):
                    return True
            if isinstance(base, ast.Attribute) and base.attr == "datetime" and \
                    isinstance(base.value, ast.Name) and \
                    base.value.id in self.datetime_names and f.attr in ("now", "utcnow"):
                return True
        return False


def _callable(node):
    """``(name, body)`` of a function definition or a name bound to a lambda."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return node.name, node
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda) and \
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id, node.value
    return None, None


def _helpers_of(source: str, resolve) -> set:
    return _Clocks(ast.parse(source), resolve).helpers


def _mentions(node, clocks: _Clocks, timed: set) -> bool:
    """``node`` reads a clock, calls a timing helper, or reads a timed name."""
    for n in ast.walk(node):
        if clocks.is_clock(n):
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


def _ratio(node, clocks, timed) -> bool:
    """A division or product of two timed quantities somewhere in ``node``."""
    return any(isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Div, ast.Mult))
               and _mentions(n.left, clocks, timed) and _mentions(n.right, clocks, timed)
               for n in ast.walk(node))


def _fails(body) -> bool:
    """A branch that fails the test: ``pytest.fail(...)`` or ``raise AssertionError``."""
    for n in ast.walk(ast.Module(body=list(body), type_ignores=[])):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                n.func.attr == "fail":
            return True
        if isinstance(n, ast.Raise) and n.exc is not None:
            exc = n.exc.func if isinstance(n.exc, ast.Call) else n.exc
            if isinstance(exc, ast.Name) and exc.id == "AssertionError":
                return True
    return False


def _checks(fn):
    """Every comparison a test function checks: nested anywhere in an ``assert``, a
    unittest assertion's compared arguments (as a comparison), or an ``if`` whose body
    fails the test."""
    out = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assert):
            out += [n for n in ast.walk(node.test) if isinstance(n, ast.Compare)]
        elif isinstance(node, ast.If) and _fails(node.body):
            out += [n for n in ast.walk(node.test) if isinstance(n, ast.Compare)]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            name = node.func.attr
            if name in _UNITTEST_CMP and len(node.args) >= 2:
                out.append(ast.Compare(left=node.args[0], ops=[_UNITTEST_CMP[name]()],
                                       comparators=[node.args[1]]))
            elif name in _UNITTEST_TRUTH and node.args:
                out += [n for n in ast.walk(node.args[0]) if isinstance(n, ast.Compare)]
    return out


def wall_clock_ratios(source: str, resolve=None) -> list[str]:
    """Checks in ``source`` that compare a wall-clock measurement scaled against
    another, or a ratio of two, as unparsed text. ``resolve(module)`` returns another
    test module's source (for helpers imported from it), or None."""
    tree = ast.parse(source)
    clocks = _Clocks(tree, resolve)
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
                if _mentions(a.value, clocks, timed) and not names <= timed:
                    timed |= names
                    changed = True
                if _ratio(a.value, clocks, timed) and not names <= ratios:
                    ratios |= names
                    changed = True
        for cmp in _checks(fn):
            sides = [cmp.left, *cmp.comparators]
            timed_sides = sum(_mentions(s, clocks, timed) for s in sides)
            # one timing scaled against another (``t2 < 3.5 * t1``); a deadline
            # (``now < start + 10``) is an absolute bound and stays allowed
            scaled = any(isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Mult, ast.Div))
                         and (_mentions(n.left, clocks, timed)
                              or _mentions(n.right, clocks, timed))
                         for s in sides for n in ast.walk(s))
            if (timed_sides >= 2 and scaled) or _ratio(cmp, clocks, timed) or any(
                    isinstance(n, ast.Name) and n.id in ratios for n in ast.walk(cmp)):
                found.append(ast.unparse(cmp))
    return found


def _resolve_test_module(module: str):
    """Another module under ``tests/`` (``tests._bench``, ``_bench``), or None."""
    name = module.split(".")[-1]
    path = ROOT / f"{name}.py"
    return path.read_text() if path.is_file() else None


def test_no_test_asserts_a_wall_clock_ratio():
    offenders = {}
    for path in sorted(ROOT.glob("test_*.py")):
        hits = wall_clock_ratios(path.read_text(), _resolve_test_module)
        if hits:
            offenders[path.name] = hits
    assert offenders == {}


#: BUG-0135's own lines, before the fix (PA-0034(2): the guard is proven on them).
_OLD_SPA_ROUTES = '''
import time


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

#: One synthetic offender per spelling the guard must see (review A2-S2, B-N7, U6).
SYNTHETIC_OFFENDERS = {
    "ratio of two timings": (
        "import time\n"
        "def t():\n    a = time.perf_counter()\n    b = time.perf_counter() - a\n"
        "    assert b / a < 2\n"),
    "a named ratio": (
        "from time import monotonic\ndef t():\n    s = monotonic()\n"
        "    e1 = monotonic() - s\n    e2 = monotonic() - s\n"
        "    r = e2 / e1\n    assert r < 2.2\n"),
    "a dict of timings": (
        "import time\n"
        "def t():\n    times = {}\n    times['a'] = time.time()\n"
        "    times['b'] = time.time()\n    assert times['b'] <= 2 * times['a']\n"),
    "a comparison nested in an assert": (
        "import time\n"
        "def t():\n    a = time.perf_counter()\n    b = time.perf_counter()\n"
        "    assert ok and (b < 3 * a)\n"),
    "time imported under an alias": (
        "import time as tm\n"
        "def t():\n    a = tm.perf_counter()\n    b = tm.perf_counter()\n"
        "    assert b < 3 * a\n"),
    "perf_counter imported as pc": (
        "from time import perf_counter as pc\n"
        "def t():\n    a = pc()\n    b = pc()\n    assert b < 3 * a\n"),
    "from time import time": (
        "from time import time\n"
        "def t():\n    a = time()\n    b = time()\n    assert b < 3 * a\n"),
    "timeit": (
        "import timeit\n"
        "def t():\n    a = timeit.timeit(f, number=3)\n    b = timeit.timeit(g, number=3)\n"
        "    assert b < 3 * a\n"),
    "timeit's default_timer": (
        "from timeit import default_timer as clock\n"
        "def t():\n    a = clock()\n    b = clock()\n    assert b < 3 * a\n"),
    "datetime.now": (
        "import datetime\n"
        "def t():\n    a = datetime.datetime.now().timestamp()\n"
        "    b = datetime.datetime.now().timestamp()\n    assert b < 3 * a\n"),
    "from datetime import datetime": (
        "from datetime import datetime\n"
        "def t():\n    a = datetime.now()\n    b = datetime.now()\n"
        "    assert (b - a) < 3 * (b - a)\n"),
    "a unittest assertLess": (
        "import time\nclass T:\n    def test(self):\n        a = time.perf_counter()\n"
        "        b = time.perf_counter()\n        self.assertLess(b, 3 * a)\n"),
    "a unittest assertTrue": (
        "import time\nclass T:\n    def test(self):\n        a = time.perf_counter()\n"
        "        b = time.perf_counter()\n        self.assertTrue(b < 3 * a)\n"),
    "an if that fails the test": (
        "import time, pytest\n"
        "def t():\n    a = time.perf_counter()\n    b = time.perf_counter()\n"
        "    if b > 3 * a:\n        pytest.fail('slow')\n"),
    "an if that raises AssertionError": (
        "import time\n"
        "def t():\n    a = time.perf_counter()\n    b = time.perf_counter()\n"
        "    if b > 3 * a:\n        raise AssertionError('slow')\n"),
    "a lambda helper": (
        "import time\n"
        "timed = lambda f: (time.perf_counter(), f(), time.perf_counter())[2]\n"
        "def t():\n    a = timed(f)\n    b = timed(g)\n    assert b < 3 * a\n"),
    "a helper imported from another test module": (
        "from tests._bench import measure\n"
        "def t():\n    a = measure(f)\n    b = measure(g)\n    assert b < 3 * a\n"),
}
_BENCH = ("import time\n"
          "def measure(f):\n    s = time.perf_counter()\n    f()\n"
          "    return time.perf_counter() - s\n")


def _synthetic_resolve(module):
    return _BENCH if module.endswith("_bench") else None


def test_the_guard_catches_bug_0135_and_each_synthetic_offender():
    assert wall_clock_ratios(_OLD_SPA_ROUTES) == [
        "t_large < 3.5 * max(t_small, 0.001)"]
    for name, bad in SYNTHETIC_OFFENDERS.items():
        assert wall_clock_ratios(bad, _synthetic_resolve), name
    for ok in ("import time\n"
               "def t():\n    s = time.perf_counter()\n    f()\n"
               "    assert time.perf_counter() - s < 10.0\n",                  # smoke
               "import time\n"
               "def t():\n    deadline = time.monotonic() + 5\n"
               "    assert time.monotonic() < deadline\n",                     # a deadline
               "def t():\n    assert large.steps <= 2 * small.steps + 64\n",   # op count
               "def t():\n    early, late = parse(out)\n    assert late / early > 2.0\n",
               "import time\n"
               "def t():\n    a = time.perf_counter()\n    b = time.perf_counter()\n"
               "    if b > 3 * a:\n        log('slow')\n"):                    # no failure
        assert not wall_clock_ratios(ok, _synthetic_resolve), ok
