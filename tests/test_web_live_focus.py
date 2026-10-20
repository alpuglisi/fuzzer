"""Every page script that refreshes itself keeps the user's place (FR-UI-514, PA-0534(3)).

A live view re-renders while the user works in it. BUG-0534: the site map and the Diagrams
page dropped focus to <body> from every control kind but the one tested (a recurrence of
BUG-0518's root cause). So each script that polls or streams is **registered** here with
the real-browser tests that change the store after the first load and check each control
kind, or with a reasoned exemption; a new polling script fails until it is registered,
and a registered view restores focus through the one helper, ``static/js/livefocus.js``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
STATIC = REPO / "fuzzlab" / "web" / "static" / "js"
HELPER = "livefocus.js"

#: How a script refreshes itself: a poll of the store version, a timer, a stream.
_LIVE = re.compile(r"/api/sitetree/version|setInterval\(|setTimeout\(\s*poll\b"
                   r"|new\s+EventSource\(|\bsubscribe\(")

#: script -> its real-browser focus tests (``file::test``), or ("exempt", reason).
LIVE_VIEWS: dict[str, tuple[str, ...] | tuple[str, str]] = {
    "sitetree.js": (
        "tests/test_web_sitetree_browser.py::test_a_refresh_keeps_focus_on_show_more_and_enter_still_loads_the_page",
        "tests/test_web_sitetree_browser.py::test_a_refresh_during_a_show_more_load_still_delivers_that_page",
        "tests/test_web_sitetree_browser.py::test_show_more_pressed_while_a_refresh_loads_its_group_is_kept",
        "tests/test_web_sitetree_browser.py::test_a_refresh_that_ends_a_groups_paging_keeps_focus_in_the_tree",
        "tests/test_web_sitetree_browser.py::test_a_refresh_keeps_focus_on_a_control_inside_a_row",
        "tests/test_web_sitetree_browser.py::test_a_refresh_keeps_the_issues_pages_and_the_focused_finding",
        "tests/test_web_sitetree_browser.py::test_show_more_findings_pressed_while_a_refresh_loads_issues_is_kept",
        "tests/test_web_sitetree_browser.py::test_every_focusable_control_in_the_site_maps_live_regions_has_a_focus_key",
        "tests/test_web_sitetree_browser.py::test_a_refresh_keeps_focus_selection_and_loaded_pages",
        "tests/test_web_sitetree_browser.py::test_a_refresh_during_a_show_more_findings_load_still_delivers_that_page",
        "tests/test_web_sitetree_browser.py::test_restore_focus_skips_every_candidate_that_refuses_focus_and_ends_at_the_pane",
        "tests/test_web_sitetree_browser.py::test_a_refresh_that_removes_the_focused_item_never_scrolls_nor_drops_to_the_body",
        "tests/test_web_sitetree_browser.py::test_a_refresh_whose_group_fetch_fails_is_retried_at_the_next_poll",
        "tests/test_web_sitetree_browser.py::test_a_refresh_whose_contents_fetch_fails_keeps_the_table_and_is_retried",
        "tests/test_web_sitetree_browser.py::test_a_group_whose_refresh_fails_on_expand_is_retried_at_the_next_expand",
        "tests/test_web_sitetree_browser.py::test_unkeyed_siblings_with_one_label_keep_distinct_identities_across_refreshes",
        "tests/test_web_sitetree_browser.py::test_the_page_refreshes_when_the_store_changes",
        "tests/test_web_sitetree_browser.py::test_a_refresh_that_overtakes_an_expand_still_fills_the_node",
        "tests/test_web_sitetree_browser.py::test_an_expand_inside_a_refresh_loads_the_node_once",
        "tests/test_web_sitetree_browser.py::test_a_checkpoint_with_no_write_never_refreshes_the_page",
    ),
    "diagrams.js": (
        "tests/test_web_diagrams.py::test_a_live_refresh_keeps_focus_on_every_kind_of_control",
        "tests/test_web_diagrams.py::test_every_focusable_control_in_the_diagrams_live_regions_has_a_focus_key",
        "tests/test_web_diagrams.py::test_the_page_renders_labels_as_text_navigates_evidence_and_updates_live",
        "tests/test_web_diagrams.py::test_a_sequence_answer_overtaken_by_a_scope_change_is_never_drawn",
    ),
    "proxy.js": ("exempt", "its 1.2 s poll re-renders the pending-flow rows, which hold no "
                           "focusable control (no tabindex, link or button); the editor "
                           "and its buttons are static template elements"),
    "lab.js": ("exempt", "its stream appends text to one <pre>; it re-renders no control"),
    "launcher.js": ("exempt", "its stream appends text to one <pre>; it re-renders no "
                              "control"),
    "common.js": ("exempt", "the `subscribe` helper only; it touches no DOM"),
}


def live_scripts(static: Path = STATIC) -> set[str]:
    return {p.name for p in static.glob("*.js") if _LIVE.search(p.read_text("utf-8"))}


def _test_exists(node: str, repo: Path = REPO) -> bool:
    rel, _sep, name = node.partition("::")
    path = repo / rel
    if not path.is_file():
        return False
    return any(isinstance(n, ast.FunctionDef) and n.name == name
               for n in ast.walk(ast.parse(path.read_text("utf-8"))))


def registry_problems(found: set[str], views: dict, repo: Path = REPO) -> list[str]:
    out = [f"{s}: refreshes itself and is not registered" for s in sorted(found - set(views))]
    out += [f"{s}: registered but no longer refreshes itself" for s in sorted(set(views) - found)]
    for s, entry in sorted(views.items()):
        if entry and entry[0] == "exempt":
            if len(entry) != 2 or len(entry[1]) < 20:
                out.append(f"{s}: an exemption needs its reason")
        elif not entry:
            out.append(f"{s}: no focus test")
        else:
            out += [f"{s}: {t} does not exist" for t in entry if not _test_exists(t, repo)]
    return out


def test_every_live_view_is_registered_with_its_focus_test():
    """G1: every script that polls or streams is registered with real-browser tests that
    exist, or exempted with a reason; a stale entry fails."""
    assert registry_problems(live_scripts(), LIVE_VIEWS) == []


def test_the_live_view_registry_catches_synthetic_offenders(tmp_path):
    """G2 (PA-0034(2)): an unregistered poller, a stale entry, a missing test and an
    exemption without a reason are each reported; a registered view passes."""
    static = tmp_path / "js"
    static.mkdir()
    (static / "new.js").write_text("setInterval(poll, 1000);")
    (static / "ok.js").write_text('fetch("/api/sitetree/version")')
    (static / "quiet.js").write_text("const x = 1;")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_ok.py").write_text("def test_ok_keeps_focus():\n    pass\n")
    views = {"ok.js": ("tests/test_ok.py::test_ok_keeps_focus",),
             "gone.js": ("exempt", "it used to poll, a long enough reason"),
             "quiet2.js": ("tests/test_ok.py::test_missing",),
             "bad.js": ("exempt", "short")}
    found = live_scripts(static) | {"quiet2.js", "bad.js"}
    assert live_scripts(static) == {"new.js", "ok.js"}
    assert registry_problems(found, views, tmp_path) == [
        "new.js: refreshes itself and is not registered",
        "gone.js: registered but no longer refreshes itself",
        "bad.js: an exemption needs its reason",
        "quiet2.js: tests/test_ok.py::test_missing does not exist",
    ]


_DEFINES = re.compile(r"\bfunction\s+(focusKeyIn|restoreFocus|rerender)\b"
                      r"|\b(focusKeyIn|restoreFocus|rerender)\s*=\s*(?:async\s*)?\(")


def test_every_live_view_restores_focus_through_the_one_helper():
    """G3: each registered (non-exempt) view imports `livefocus.js`, and no other script
    defines its functions: one remembering and restoring of the user's place."""
    assert (STATIC / HELPER).is_file(), f"{HELPER} is missing"
    for name, entry in sorted(LIVE_VIEWS.items()):
        if entry[0] == "exempt":
            continue
        text = (STATIC / name).read_text("utf-8")
        assert re.search(r'from\s+"/static/js/livefocus\.js"', text), \
            f"{name} does not import {HELPER}"
    others = [p.name for p in STATIC.glob("*.js")
              if p.name != HELPER and _DEFINES.search(p.read_text("utf-8"))]
    assert others == []


@pytest.mark.parametrize("src,defines", [
    ("export function restoreFocus(root, key) {}", True),
    ("const rerender = (root, draw) => draw();", True),
    ("const focusKeyIn = async (r) => null;", True),
    ('import { restoreFocus } from "/static/js/livefocus.js";', False),
    ("restoreFocus(tree, key, pane);", False),
])
def test_the_one_helper_guard_tells_a_definition_from_a_use(src, defines):
    assert bool(_DEFINES.search(src)) is defines


_SLEEPS = {"wait_for_timeout", "sleep"}


def sleeping_tests(views: dict, repo: Path = REPO) -> list[str]:
    """Registered real-browser focus tests that synchronise by sleeping (a Playwright
    `wait_for_timeout`, a `time.sleep`) instead of the page's counters (D8) -- in the test
    itself or in a module-level helper it calls by name, transitively. (A method called
    on an object, e.g. ``tab.item``, is not followed.)"""
    out = []
    for entry in views.values():
        if not entry or entry[0] == "exempt":
            continue
        for node in entry:
            rel, _sep, name = node.partition("::")
            tree = ast.parse((repo / rel).read_text("utf-8"))
            funcs = {f.name: f for f in tree.body if isinstance(f, ast.FunctionDef)}
            todo, seen = [name], set()
            while todo:
                fname = todo.pop()
                if fname in seen or fname not in funcs:
                    continue
                seen.add(fname)
                for n in ast.walk(funcs[fname]):
                    if not isinstance(n, ast.Call):
                        continue
                    if isinstance(n.func, ast.Attribute) and n.func.attr in _SLEEPS:
                        where = "" if fname == name else f" (in {fname})"
                        out.append(f"{node}: {n.func.attr}() at line {n.lineno}{where}")
                    elif isinstance(n.func, ast.Name):
                        todo.append(n.func.id)
    return sorted(set(out))


def test_no_registered_live_view_test_synchronises_by_sleeping():
    """G4 (D8, PA-0534(3)): a live view's focus tests wait on the page's own counters
    (`data-baseline`, `data-polls`, `data-refreshes`, `data-loads`), never on a sleep.
    A 900 ms "the poll has its baseline" sleep stood behind one failure (DRAFT §5.6)."""
    assert sleeping_tests(LIVE_VIEWS) == []


def test_the_sleep_guard_catches_a_synthetic_offender(tmp_path):
    """PA-0034(2): a `wait_for_timeout` and a `time.sleep` in a registered test are found,
    and in a helper it calls through another helper; a counter wait and an unregistered
    test's sleep are not."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_x.py").write_text(
        "import time\n"
        "def test_sleeps(page):\n    page.wait_for_timeout(900)\n    time.sleep(1)\n"
        "def test_counts(page):\n    page.wait_for_function('() => 1')\n"
        "def test_unregistered(page):\n    page.wait_for_timeout(500)\n"
        "def _settle(page):\n    page.wait_for_timeout(300)\n"
        "def _helper(page):\n    return _settle(page)\n"
        "def test_via_a_helper(page):\n    _helper(page)\n")
    views = {"a.js": ("tests/test_x.py::test_sleeps", "tests/test_x.py::test_counts",
                      "tests/test_x.py::test_via_a_helper"),
             "b.js": ("exempt", "a reason long enough to be one")}
    assert sleeping_tests(views, tmp_path) == [
        "tests/test_x.py::test_sleeps: sleep() at line 4",
        "tests/test_x.py::test_sleeps: wait_for_timeout() at line 3",
        "tests/test_x.py::test_via_a_helper: wait_for_timeout() at line 10 (in _settle)"]


#: Browser test files whose locators the descendant-filter guard reads.
_BROWSER_TESTS = ("test_web_*browser*.py", "test_web_diagrams.py")
#: ``(file, function)`` allowed to filter locators by a descendant (``has=``), with why:
#: none today.
_HAS_ALLOWED: dict[tuple[str, str], str] = {}


def descendant_filters(src: str) -> list[str]:
    """Functions that filter a locator by a descendant (``has=`` / ``has_not=``)."""
    out = []

    def visit(node, where):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(ch, f"{where}.{ch.name}" if where else ch.name)
                continue
            if isinstance(ch, ast.Call) and any(k.arg in ("has", "has_not")
                                                for k in ch.keywords):
                out.append(where or "<module>")
            visit(ch, where)

    visit(ast.parse(src), "")
    return out


def test_no_browser_test_locates_by_a_descendant_filter():
    """G5 (DRAFT-AU-SITETREE §5.6): Playwright evaluates a ``has=`` filter inside every
    candidate's subtree; over the site map's nested tree items one resolution took ~1.9 s
    of a renderer core with 250 items (quadratic), and every action and `expect` retry
    re-resolves it, so under the harness's parallel load live-view tests overran their
    5 s. A test locates the descendant and steps up instead; any ``has=`` is a reviewed
    allowance."""
    tests = REPO / "tests"
    found = sorted({(p.name, f) for pat in _BROWSER_TESTS for p in tests.glob(pat)
                    for f in descendant_filters(p.read_text("utf-8"))})
    assert [k for k in found if k not in _HAS_ALLOWED] == []
    assert [k for k in _HAS_ALLOWED if k not in found] == []      # no stale allowance


def test_the_descendant_filter_guard_catches_synthetic_offenders():
    """PA-0034(2): the old `Tab.item` (a `has=` filter over tree items) and a `has_not=`
    are found; locating the label and stepping up (`xpath=../..`) is not."""
    old = ("class Tab:\n    def item(self, label):\n"
           "        return self.page.locator('li[role=\"treeitem\"]', has=self.page.locator(\n"
           "            ':scope > .st-row > .st-label', has_text=label))\n"
           "def f(page):\n    return page.locator('tr', has_not=page.locator('a'))\n")
    new = ("class Tab:\n    def item(self, label):\n"
           "        return self.page.locator('li > .st-row > .st-label', has_text=label)"
           ".locator('xpath=../..')\n")
    assert descendant_filters(old) == ["Tab.item", "f"]
    assert descendant_filters(new) == []
