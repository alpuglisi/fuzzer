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


#: A module allowed to define an owner's name again, with why. The redaction floor is
#: the pushed tree's redactors frozen at 7393c90 (BUG-0556 r6; SP-17's owner includes
#: it): only the owner's layered consumers call it, and it is pinned verbatim, so it is
#: not a second implementation (`tests/test_redaction_floor.py`).
FROZEN_COPIES = {
    "fuzzlab/core/redaction_floor.py":
        "tests/test_redaction_floor.py::test_the_floor_is_the_pushed_trees_code_verbatim",
}


def test_every_owner_is_defined_once():
    owners = {dotted.split(".")[-1]: rel for rel, dotted in (r.owner for r in ROWS)}
    trees = {rel: tree for rel, tree in _package_trees().items() if rel not in FROZEN_COPIES}
    assert second_definitions(owners, trees) == []
    for rel, guard in FROZEN_COPIES.items():           # each exemption names its guard
        path, name = guard.split("::")
        assert (ROOT / rel).is_file() and name in _test_names(ROOT / path), guard


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


# ------------------------------------------------- SP-38: closing a guarded browser page
#: Receivers that are browser pages in this package (a page, a popup, a tab).
_PAGE_NAMES = re.compile(r"(^|_)(page|popup|tab)s?$|^(other|extra)$")


def page_close_sites(tree: ast.Module) -> list[int]:
    """Lines calling ``<page>.close()`` -- a receiver named like a page, or a loop
    variable over ``<x>.pages``."""
    loop_vars: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.comprehension)) and \
                isinstance(node.target, ast.Name) and \
                any(isinstance(n, ast.Attribute) and n.attr == "pages"
                    for n in ast.walk(node.iter)):
            loop_vars.add(node.target.id)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                node.func.attr == "close" and not node.args:
            recv = node.func.value
            name = recv.id if isinstance(recv, ast.Name) else \
                recv.attr if isinstance(recv, ast.Attribute) else None
            if name and (name in loop_vars or _PAGE_NAMES.search(name)):
                out.append(node.lineno)
    return out


def test_a_guarded_page_is_closed_only_through_close_pages():
    """SP-38 (BUG-0504): closing a page that has just started a refused navigation let
    it out un-intercepted; `navguard.close_pages` freezes and drains first. No module
    but navguard closes a page itself. Proven on synthetic offenders."""
    offenders = [f"{rel}:{line}" for rel, tree in _package_trees().items()
                 if rel != "fuzzlab/tools/navguard.py"
                 for line in page_close_sites(tree)]
    assert offenders == []
    bad = ast.parse("def f(ctx, page):\n    for o in ctx.pages:\n        o.close()\n"
                    "    page.close()\n    self._page.close()\n    popup.close()\n"
                    "    storage.close()\n    browser.close()\n")
    assert sorted(page_close_sites(bad)) == [3, 4, 5, 6]


# ------------------------------------------- SP-01: a failed load's cleanup (BUG-0522)
#: ``about:blank`` navigations outside navguard that are not a failed load's cleanup,
#: by (module, enclosing function), each with its reason. A failed load's cleanup is
#: `navguard.end_failed_load` (SP-01, PA-0522).
BLANK_ALLOWED = {
    ("fuzzlab/tools/spider.py", "_restore"):
        "a reload that did not complete (no exception, no error page): its stopped "
        "document is left (BUG-0138 review B-N1)",
    ("fuzzlab/tools/spider.py", "_leave"):
        "a seed or probe window's exit: the load's timers die inside the window",
    ("fuzzlab/tools/spider.py", "_visit"):
        "a seed or probe load starts from a fresh document (M7), outside its window",
    ("fuzzlab/disco/explore.py", "restore"):
        "a restore starts from a fresh document (hash routes, measured on Juice Shop)",
}


def blank_sites(tree: ast.Module) -> list[tuple[int, str | None, str]]:
    """Every ``navigate``/``goto`` of a literal ``about:blank`` (positional or ``url=``):
    ``(line, enclosing function, "except" | "finally" | "body")``."""
    parents = {ch: node for node in ast.walk(tree) for ch in ast.iter_child_nodes(node)}
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        if getattr(n.func, "attr", getattr(n.func, "id", None)) not in ("navigate", "goto"):
            continue
        values = [a.value for a in n.args if isinstance(a, ast.Constant)]
        values += [k.value.value for k in n.keywords
                   if k.arg == "url" and isinstance(k.value, ast.Constant)]
        if "about:blank" not in values:
            continue
        where, fn, child, p = "body", None, n, parents.get(n)
        while p is not None:
            if where == "body" and isinstance(p, ast.ExceptHandler):
                where = "except"
            if where == "body" and isinstance(p, ast.Try) and child in p.finalbody:
                where = "finally"
            if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = p.name
                break
            child, p = p, parents.get(p)
        out.append((n.lineno, fn, where))
    return out


def blank_offenders(trees: dict[str, ast.Module]) -> tuple[list[str], set]:
    """``(offenders, (module, function) pairs found)``: an about:blank navigation
    outside navguard that is not allow-listed, or sits in an ``except``/``finally``."""
    found, offenders = set(), []
    for rel, tree in trees.items():
        if rel == "fuzzlab/tools/navguard.py":
            continue
        for line, fn, where in blank_sites(tree):
            found.add((rel, fn))
            if where != "body" or (rel, fn) not in BLANK_ALLOWED:
                offenders.append(f"{rel}:{line} {fn} ({where})")
    return offenders, found


def test_every_about_blank_navigation_is_a_reasoned_exception():
    """SP-01 (BUG-0522, PA-0522): a failed load's cleanup goes through
    `navguard.end_failed_load`; any other about:blank navigation outside navguard is
    allow-listed, with its reason, by module and function -- and never in an ``except``
    or ``finally`` (a cleanup by hand). No stale allow-list entry."""
    offenders, found = blank_offenders(_package_trees())
    assert offenders == []
    assert set(BLANK_ALLOWED) <= found, set(BLANK_ALLOWED) - found


def test_the_about_blank_guard_catches_synthetic_offenders():
    by_hand = ("def f(page):\n    try:\n        go(page)\n    except Exception:\n"
               "        navguard.navigate(page, 'about:blank', timeout_ms=1)\n")
    keyword = ("def g(page):\n    try:\n        go(page)\n    finally:\n"
               "        navguard.navigate(page, url='about:blank', timeout_ms=1)\n")
    unlisted = "def h(page):\n    page.goto('about:blank')\n"
    # an allow-listed function whose about:blank sits in an `except`: still an offender
    listed_in_except = ("def _leave(page):\n    try:\n        go(page)\n"
                        "    except Exception:\n"
                        "        navguard.navigate(page, 'about:blank', timeout_ms=1)\n")
    owner = ("def k(page):\n    try:\n        go(page)\n    except Exception as e:\n"
             "        navguard.end_failed_load(page, e, timeout_ms=1)\n")
    assert blank_sites(ast.parse(by_hand)) == [(5, "f", "except")]
    assert blank_sites(ast.parse(keyword)) == [(5, "g", "finally")]
    assert blank_sites(ast.parse(unlisted)) == [(2, "h", "body")]
    assert blank_sites(ast.parse(owner)) == []
    offenders, _found = blank_offenders({
        "fuzzlab/tools/x.py": ast.parse(by_hand), "fuzzlab/tools/y.py": ast.parse(keyword),
        "fuzzlab/tools/z.py": ast.parse(unlisted),
        "fuzzlab/tools/spider.py": ast.parse(listed_in_except),
        "fuzzlab/tools/w.py": ast.parse(owner)})
    assert offenders == ["fuzzlab/tools/x.py:5 f (except)",
                         "fuzzlab/tools/y.py:5 g (finally)",
                         "fuzzlab/tools/z.py:2 h (body)",
                         "fuzzlab/tools/spider.py:5 _leave (except)"]
