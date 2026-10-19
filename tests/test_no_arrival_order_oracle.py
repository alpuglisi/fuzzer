"""BUG-0511 / PA-0511: an absence claim about a concurrent actor ("nothing was sent
after the mark") is judged by a stamp the actor gave the event when it acted, never by
where the observer's log received it.

`tests/test_navigation_aborts.py` asserted ``("POST", "/tick") not in a.log[fallback:]``:
no tick logged by the server after the fallback's own request. Under CPU load, ticks
the browser sent seconds before the mark were handled after it, and the test failed on
correct code. This guard finds that shape: an ``assert`` whose membership test or
``.count`` reads a server or capture log sliced from a mark (``log[i:]``,
``log[i:j].count(x)``). A log sliced from its start is a whole-log claim and stays
allowed, as does a slice compared to an exact sequence by a sequential fake.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _sliced_from_a_mark(node) -> bool:
    """`<x>.log[<start>:...]` (or a bare `log[...]`) whose start is not the log's start."""
    if not (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice)):
        return False
    base = node.value
    name = base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", "")
    if not name.endswith("log"):
        return False
    lower = node.slice.lower
    return lower is not None and not (isinstance(lower, ast.Constant) and lower.value == 0)


def offenders(sources: dict[str, str]) -> list[str]:
    found = []
    for name, text in sources.items():
        for node in ast.walk(ast.parse(text)):
            if not isinstance(node, ast.Assert):
                continue
            for sub in ast.walk(node.test):
                hit = (isinstance(sub, ast.Compare)
                       and any(isinstance(op, (ast.In, ast.NotIn)) for op in sub.ops)
                       and any(_sliced_from_a_mark(c) for c in sub.comparators))
                hit = hit or (isinstance(sub, ast.Call)
                              and isinstance(sub.func, ast.Attribute)
                              and sub.func.attr == "count"
                              and _sliced_from_a_mark(sub.func.value))
                if hit:
                    found.append(f"{name}:{node.lineno}")
                    break
    return sorted(found)


def test_no_test_judges_a_concurrent_actor_by_arrival_after_a_mark():
    sources = {p.name: p.read_text() for p in ROOT.glob("*.py")}
    assert offenders(sources) == []


def test_the_guard_catches_bug_0511_and_each_synthetic_offender():
    bug = ('fallback = a.log.index(("GET", "/go"), seen)\n'
           'assert ("POST", "/tick") not in a.log[fallback:]\n'
           'assert a.log[seen:fallback].count(("POST", "/tick")) <= 2\n')
    assert offenders({"bug.py": bug}) == ["bug.py:2", "bug.py:3"]
    assert offenders({"x.py": "assert ok and 'x' in server_log[mark:]\n"}) == ["x.py:1"]
    allowed = ("assert ('GET', '/a') not in site.log\n"                 # the whole log
               "assert x not in a.log[0:]\n"
               "assert log[i + 1:i + 3] == [('GET', '/n')]\n"         # a sequential fake
               "assert x not in a.requests[k:]\n")                    # not a log
    assert offenders({"ok.py": allowed}) == []
