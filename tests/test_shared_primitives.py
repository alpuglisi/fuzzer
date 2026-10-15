"""`docs/SHARED_PRIMITIVES.md` is checked, not just written.

Each row names a mechanism with exactly one implementation: its owner
(``fuzzlab/<path>.py::Name`` or ``::Class.member``) and its guard tests. This file
asserts that every guard test exists (resolved by AST, nothing imported), that every
owner exists, and that no other module of ``fuzzlab/`` defines a function or class
with an owner's name -- the cheap "defined once" check, a row's guard where no
dedicated AST guard exists. It also adds the one missing structural guard the table
needs: a browser route is aborted only inside ``navguard`` (SP-02, PA-0136). Each check
is proven on a synthetic offender (PA-0034(2)).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TABLE = ROOT / "docs" / "SHARED_PRIMITIVES.md"
PACKAGE = ROOT / "fuzzlab"
pytestmark = pytest.mark.package_guard

ROW = re.compile(r"^\| (SP-\d{2}) \|")
OWNER = re.compile(r"`(fuzzlab/[\w/]+\.py)::([\w.]+)`")
GUARD = re.compile(r"`(tests/[\w/]+\.py)::(\w+(?:::\w+)?)`")


@dataclass
class Row:
    sp: str
    owner: tuple[str, str]
    guards: list[tuple[str, str]]


def parse_table(text: str) -> list[Row]:
    rows = []
    for line in text.splitlines():
        m = ROW.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        owner = OWNER.search(cells[2])
        guards = GUARD.findall(cells[3])
        rows.append(Row(m.group(1), owner.groups() if owner else ("", ""), guards))
    return rows


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _test_names(path: Path) -> set[str]:
    names = set()
    for node in _parse(path).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.ClassDef):
            names |= {f"{node.name}::{s.name}" for s in node.body
                      if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))}
    return names


def _defines(tree: ast.Module, dotted: str) -> bool:
    """Does the module define ``Name`` or ``Class.member`` at its top level?"""
    head, _, member = dotted.partition(".")
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == head:
            if not member:
                return True
            if isinstance(node, ast.ClassDef):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.name == member:
                        return True
                    if isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name) and sub.target.id == member:
                        return True
                    if isinstance(sub, ast.Assign) and any(isinstance(t, ast.Name) and t.id == member for t in sub.targets):
                        return True
        if not member and isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == head for t in targets):
                return True
    return False


def second_definitions(owners: dict[str, str], files: dict[str, ast.Module]) -> list[str]:
    """Functions or classes named like an owner, defined anywhere but the owner's module."""
    out = []
    for rel, tree in files.items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                home = owners.get(node.name)
                if home is not None and home != rel:
                    out.append(f"{rel}:{node.lineno}: {node.name} (owned by {home})")
    return out


def route_abort_sites(tree: ast.Module) -> list[int]:
    """Calls ``<something route-named>.abort(...)``: refusing a browser request."""
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "abort":
            recv = node.func.value
            name = recv.id if isinstance(recv, ast.Name) else recv.attr if isinstance(recv, ast.Attribute) else ""
            if "route" in name.lower():
                lines.append(node.lineno)
    return lines


def _package_trees() -> dict[str, ast.Module]:
    return {
        str(p.relative_to(ROOT)): _parse(p)
        for p in sorted(PACKAGE.rglob("*.py"))
        if "__pycache__" not in p.parts and "skeleton" not in p.parts
    }


ROWS = parse_table(TABLE.read_text(encoding="utf-8"))


def test_the_table_is_parsed_and_every_row_is_complete():
    assert len(ROWS) >= 8
    ids = [r.sp for r in ROWS]
    assert len(ids) == len(set(ids)), "duplicate SP id"
    for r in ROWS:
        assert r.owner != ("", ""), f"{r.sp}: no owner"
        assert r.guards, f"{r.sp}: no guard test"


@pytest.mark.parametrize("row", ROWS, ids=[r.sp for r in ROWS])
def test_every_rows_guard_tests_exist(row):
    for rel, name in row.guards:
        path = ROOT / rel
        assert path.is_file(), f"{row.sp}: {rel} does not exist"
        assert name in _test_names(path), f"{row.sp}: {rel} defines no test {name}"


@pytest.mark.parametrize("row", ROWS, ids=[r.sp for r in ROWS])
def test_every_owner_exists(row):
    rel, dotted = row.owner
    path = ROOT / rel
    assert path.is_file(), f"{row.sp}: {rel} does not exist"
    assert _defines(_parse(path), dotted), f"{row.sp}: {rel} defines no {dotted}"


def test_every_owner_is_defined_once():
    owners = {dotted.split(".")[-1]: rel for rel, dotted in (r.owner for r in ROWS)}
    assert second_definitions(owners, _package_trees()) == []


def test_route_aborts_happen_only_in_navguard():
    offenders = [
        f"{rel}:{line}"
        for rel, tree in _package_trees().items()
        if rel != "fuzzlab/tools/navguard.py"
        for line in route_abort_sites(tree)
    ]
    assert offenders == []
    # and navguard itself refuses in exactly one place, with the one code helper
    nav = _parse(PACKAGE / "tools" / "navguard.py")
    assert len(route_abort_sites(nav)) >= 1
    calls = [n for n in ast.walk(nav) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "_abort_code"]
    assert calls, "navguard no longer derives the abort code from _abort_code"


# ---------------------------------------------------------------- synthetic offenders

def test_the_defined_once_check_flags_a_second_implementation():
    files = {
        "fuzzlab/core/urls.py": ast.parse("def canonical_origin(u):\n    return u\n"),
        "fuzzlab/tools/spider.py": ast.parse(
            "class C:\n    def canonical_origin(self, u):\n        return u\n"),
        "fuzzlab/tools/fine.py": ast.parse("def other():\n    pass\n"),
    }
    hits = second_definitions({"canonical_origin": "fuzzlab/core/urls.py"}, files)
    assert hits == ["fuzzlab/tools/spider.py:2: canonical_origin (owned by fuzzlab/core/urls.py)"]


def test_the_abort_check_flags_a_route_abort_and_ignores_other_aborts():
    tree = ast.parse(
        "def h(route, transport, self):\n"
        "    route.abort()\n"
        "    self._route.abort('failed')\n"
        "    transport.abort()\n"
    )
    assert route_abort_sites(tree) == [2, 3]


def test_the_table_checks_flag_a_missing_guard_or_owner(tmp_path):
    text = ("| SP-01 | x | `fuzzlab/core/urls.py::no_such_function` | "
            "`tests/test_shared_primitives.py::test_no_such_test` | PA-0003 |\n")
    (row,) = parse_table(text)
    assert not _defines(_parse(ROOT / row.owner[0]), row.owner[1])
    assert row.guards[0][1] not in _test_names(ROOT / row.guards[0][0])
    assert _defines(_parse(ROOT / "fuzzlab/session/state.py"), "SessionState.origins")
    assert not _defines(_parse(ROOT / "fuzzlab/session/state.py"), "SessionState.no_such_field")
