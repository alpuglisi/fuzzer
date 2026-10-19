"""One recorder per run (SP-48): a `TraceRecorder` is made only by the command that
started the run, at the sites listed here. Two recorders on one run would collide on
``seq`` (each reads ``MAX(seq)`` once) and overwrite each other's ``trace_*`` counters;
no CLI writes into an existing run (CC-CRAWL-0050)."""

from __future__ import annotations

import ast
from pathlib import Path

#: ``(module path, enclosing function)`` of every `TraceRecorder(` call in the package.
ALLOWED = {
    ("harness/auto_cli.py", "_run"),            # the auto run it started
    ("harness/auto.py", "run_auto"),            # a library caller's run without one
    ("proxy/history.py", "_trace"),             # the proxy's run (FR-PROXY-13)
    ("proxy/history.py", "close"),
    ("disco/livetrace.py", "open"),             # the disco capture's run (FR-CRAWL-30)
}


def recorder_sites(sources: dict[str, str]) -> set[tuple[str, str]]:
    """Every ``TraceRecorder(...)`` call (by name or attribute) and its function."""
    found = set()
    for path, text in sources.items():
        tree = ast.parse(text)

        def walk(node, fn, path=path):
            for child in ast.iter_child_nodes(node):
                name = child.name if isinstance(child, (ast.FunctionDef,
                                                        ast.AsyncFunctionDef)) else fn
                if isinstance(child, ast.Call):
                    f = child.func
                    if (isinstance(f, ast.Name) and f.id == "TraceRecorder") or \
                            (isinstance(f, ast.Attribute) and f.attr == "TraceRecorder"):
                        found.add((path, fn or "<module>"))
                walk(child, name, path)
        walk(tree, None)
    return found


def test_trace_recorders_are_made_only_at_the_listed_sites():
    root = Path(__file__).resolve().parents[1] / "fuzzlab"
    found = recorder_sites({str(p.relative_to(root)): p.read_text()
                            for p in root.rglob("*.py") if p.name != "trace.py"})
    assert found == ALLOWED


def test_the_recorder_site_guard_catches_a_synthetic_offender():
    src = ("from fuzzlab.core import trace\n"
           "def import_into(store, run_id):\n"
           "    rec = trace.TraceRecorder(store, run_id)\n"
           "class W:\n"
           "    def go(self):\n"
           "        return TraceRecorder(self.s, 1)\n"
           "x = TraceRecorder(None, 2)\n")
    assert recorder_sites({"x.py": src}) == {("x.py", "import_into"), ("x.py", "go"),
                                             ("x.py", "<module>")}
