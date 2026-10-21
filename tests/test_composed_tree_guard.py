"""SP-70: a crawler page script reads the composed UI tree (BUG-0551, PA-0551).

Both crawlers enumerated with ``document.querySelectorAll``, which sees neither an open
shadow root nor a frame, so a web component's form was absent from both (BUG-0551).
The walk that sees open shadow roots has one owner, `fuzzlab.tools.composed.COMPOSED_JS`.

The guard scans every string constant of ``fuzzlab/`` -- page scripts are Python
strings -- for a light-tree DOM query (``.querySelector(``, ``.querySelectorAll(``,
``.getElementsBy...(``) and attributes each one to the definition holding it. Every such
query outside the owner is a reviewed allowance in `ALLOWED`, with its exact count and
its reason. A new one fails; so does a stale entry. The scripts disco reads a page with
(`disco.compose.READ_JS`, `disco.compose.FIELDS_JS`) and the spider's form read
(`spa.FORMS_JS`) are built on the owner.

What it does not see: a query built from a name held in a variable (``el[q](s)``); a
page script read from a file; a ``closest`` or ``matches`` (they look up or at one
element, never across a tree).
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "fuzzlab"
OWNER = "fuzzlab/tools/composed.py"
pytestmark = pytest.mark.package_guard

QUERY = re.compile(r"\.(?:querySelectorAll|querySelector|getElementsBy\w+)\(")

_LEGACY_SPIDER = ("the legacy spider's reveal and option scripts read the light tree only: "
                  "FR-CRAWL-40's known gap (deprecated tool, D70)")

#: Every light-tree query in a page script outside the owner: ``module::definition`` ->
#: (count, why). Compared exactly.
ALLOWED: dict[str, tuple[int, str]] = {
    "fuzzlab/tools/spa.py::_LABELS_FN": (
        1, "queries a detached clone of one button for its icon glyphs: no tree to compose"),
    "fuzzlab/tools/spa.py::FORMS_JS": (
        1, "a container holding a password control inside a shadow root is read by its "
           "light tree only, as before BUG-0551, until the X3 clear and the G1 read are "
           "composed (both pinned by strict xfails in tests/test_disco_compose.py)"),
    "fuzzlab/tools/spa.py::G1_READ_JS": (
        2, "pinned: tests/test_disco_compose.py::"
           "test_the_g1_read_resolves_a_control_through_open_shadow_roots (owner: the "
           "spider's G1 read); its field-label lookup reads one form field's subtree"),
    "fuzzlab/tools/spa.py::G1_OPTIONS_JS": (1, _LEGACY_SPIDER),
    "fuzzlab/tools/spa.py::REVEAL_JS": (
        5, _LEGACY_SPIDER + "; two of them query one candidate's clone and subtree"),
    "fuzzlab/tools/spa.py::CARD_LABELS_JS": (1, "queries a detached clone of one card"),
    "fuzzlab/tools/spa.py::MENU_ITEMS_JS": (1, _LEGACY_SPIDER),
    "fuzzlab/tools/spider.py::LocalSpider._goto_and_parse": (
        1, "reads the document's own <base> element: one per document, not UI discovery"),
    "fuzzlab/session/browserlogin.py::_CLEAR_IF_PRESENT": (
        1, "pinned: tests/test_disco_compose.py::"
           "test_the_browser_logins_password_clear_reaches_a_shadow_root (owner: SESS)"),
}


def _qualname(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    """The definition holding ``node``: a module-level assignment's target, or the chain
    of classes and functions around it."""
    chain: list[str] = []
    cur = node
    while cur in parents:
        cur_parent = parents[cur]
        if isinstance(cur_parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            chain.append(cur_parent.name)
        elif isinstance(cur_parent, ast.Module):
            if isinstance(cur, (ast.Assign, ast.AnnAssign)):
                targets = cur.targets if isinstance(cur, ast.Assign) else [cur.target]
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                if names:
                    chain.append(names[0])
            break
        cur = cur_parent
    return ".".join(reversed(chain)) or None


def light_queries(source: str, rel: str) -> dict[str, int]:
    """``module::definition`` -> the number of light-tree DOM queries in its strings."""
    tree = ast.parse(source)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    found: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            n = len(QUERY.findall(node.value))
            if n:
                key = f"{rel}::{_qualname(node, parents) or '<module>'}"
                found[key] = found.get(key, 0) + n
    return found


def _package_queries() -> dict[str, int]:
    found: dict[str, int] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        rel = str(path.relative_to(ROOT))
        if "__pycache__" in path.parts or "skeleton" in path.parts or rel == OWNER:
            continue
        found.update(light_queries(path.read_text(encoding="utf-8"), rel))
    return found


def test_every_crawler_page_script_reads_the_composed_tree():
    found = _package_queries()
    unexpected = {k: n for k, n in found.items() if ALLOWED.get(k, (None,))[0] != n}
    stale = sorted(k for k in ALLOWED if k not in found)
    assert unexpected == {} and stale == [], (
        f"light-tree DOM queries not allowed (read the composed tree through "
        f"{OWNER}, SP-70, or add a reviewed allowance): {unexpected}; stale: {stale}")


def test_discos_reads_and_the_spiders_form_read_are_built_on_the_owner():
    from fuzzlab.disco import compose
    from fuzzlab.tools import spa
    from fuzzlab.tools.composed import COMPOSED_JS
    # what FORMS_JS may hold besides the owner: `_LABELS_FN` (its own allowance: a
    # detached clone's query) and the reviewed legacy read of a container holding a
    # shadow-root password control (ALLOWED["...::FORMS_JS"])
    allowed = (COMPOSED_JS, spa._LABELS_FN, "Array.from(c.querySelectorAll(sel))")
    for script in (compose.READ_JS, compose.FIELDS_JS, spa.FORMS_JS):
        assert COMPOSED_JS in script
        rest = script
        for fragment in allowed:
            rest = rest.replace(fragment, "")
        assert not QUERY.findall(rest), "a light-tree query in a composed read"


def test_the_composed_tree_guard_catches_synthetic_offenders():
    offender = (
        "ENUM_JS = '() => document.querySelectorAll(\"button\")'\n"
        "class Crawler:\n"
        "    def read(self, page):\n"
        "        return page.evaluate(\"() => document.getElementsByTagName('form')\")\n"
        "FIND = 'el => el.querySelector(\"input\")' + 'x'\n")
    assert light_queries(offender, "fuzzlab/x.py") == {
        "fuzzlab/x.py::ENUM_JS": 1, "fuzzlab/x.py::Crawler.read": 1, "fuzzlab/x.py::FIND": 1}
    near_misses = (
        "OK_JS = '() => composedAll(document, \"button\")'\n"
        "DOC = 'reads with ``document.querySelectorAll`` no more'\n"
        "M = 'el => el.closest(\"form\") && el.matches(\"x\")'\n")
    assert light_queries(near_misses, "fuzzlab/y.py") == {}
