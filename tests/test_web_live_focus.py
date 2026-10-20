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
    ),
    "diagrams.js": (
        "tests/test_web_diagrams.py::test_a_live_refresh_keeps_focus_on_every_kind_of_control",
        "tests/test_web_diagrams.py::test_every_focusable_control_in_the_diagrams_live_regions_has_a_focus_key",
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
