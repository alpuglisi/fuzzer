"""CC-LAB-0241 / FR-LAB-159 (`docs/LAB_LANE1_REMAINING_GAPS_PLAN.md`):
offline generated-source coverage for Lane 1 step 5's two emitter fixes.

* §2a -- the per-profile `default_value` key: `/product.php` and
  `/blog_post.php` render `$request->query('id', '1')` (the real pages' own
  `?? '1'` fallback), and the crawl-surfaced `/booking/continue`/
  `/comments/share` default to `/`; every other `get_param` cell keeps its
  no-default read byte-for-byte (no blanket template change, R2).
* §2b -- `html_body_echo.blade.php.j2` extends the shared `layouts.site`
  layout with a `page_title`; every cell that resolves to that sink (computed
  from the manifests, not restated -- PA-0027) renders the layout wrapper,
  and a profile with no `page_title` falls back to the app name (R1).

The real served behavior (bare `GET /product.php` -> 200; the 4 pages inside
the site nav/header) is proven live in `tests/test_labgen_conformance_live_boot.py`,
`tests/test_labgen_conformance_live_boot_mariadb.py` and
`tests/test_labgen_navigability_live_boot.py`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fuzzlab.labgen.assemble import collect_cells
from fuzzlab.labgen.conformance.live_boot import LiveBootHarness
from fuzzlab.labgen.emitters.php_laravel.app_site import APP_REGISTRY, site_layer_files
from fuzzlab.labgen.emitters.php_laravel import (
    _DEFAULT_VALUE_KEY,
    _PAGE_PROFILES,
    _PAGE_TITLE_KEY,
    LaravelEmitter,
    _render_route_for,
)
from fuzzlab.labgen.emitters.php_laravel.modules import DEFAULT_PAGE_TITLE, SINKS
from fuzzlab.labgen.schema import load_manifest

_MANIFEST_DIR = Path("lab/manifests")

#: The two profiles the plan scopes the default to (§2a), plus the two the
#: navigability crawl surfaced with the same missing default (§3 step 3's
#: same-class rule) -- a design decision of this change, deliberately literal.
_DEFAULTED_PAGES = {"/product.php": "1", "/blog_post.php": "1", "/booking/continue": "/", "/comments/share": "/"}

#: The four pages §2b names, with the title each response must carry.
#: `/edit_profile.php` has no `html_body_echo` view of its own: its POST
#: redirects to `/profile.php`, whose view is the echo a visitor sees.
_TITLED_PAGES = {"/contact.php": "Contact us", "/newsletter.php": "Newsletter", "/profile.php": "Profile"}


def _laravel_cells():
    emitter = LaravelEmitter()
    for path in sorted(_MANIFEST_DIR.glob("*.yaml")):
        for cell in load_manifest(path).cells:
            if cell.stack_profile == "php_laravel" and emitter.supports(cell.vuln_class, cell.sink_context):
                yield cell


def _render(cell) -> dict[str, str]:
    return {f.role: f.content.decode("utf-8") for f in LaravelEmitter().render(cell)}


def _composition(source: str) -> list[str]:
    line = next(ln for ln in source.splitlines() if ln.startswith("// Module composition:"))
    return [part.strip() for part in line.split(":", 1)[1].split("->")]


# --- §2a: missing-?id= default ------------------------------------------------


def test_only_the_two_scoped_profiles_set_a_default_value() -> None:
    defaulted = {path: p[_DEFAULT_VALUE_KEY] for path, p in _PAGE_PROFILES.items() if _DEFAULT_VALUE_KEY in p}
    assert defaulted == _DEFAULTED_PAGES


def test_defaulted_pages_render_the_default_and_every_other_get_param_cell_does_not() -> None:
    seen_defaulted = 0
    seen_plain = 0
    for cell in _laravel_cells():
        controller = _render(cell)["controller"]
        if _composition(controller)[0] != "get_param":
            continue
        param = _PAGE_PROFILES[_render_route_for(cell).path]["param_name"]
        default = _DEFAULTED_PAGES.get(_render_route_for(cell).path)
        if default is not None:
            assert f"$request->query('{param}', '{default}');" in controller, cell.cell_id
            seen_defaulted += 1
        else:
            assert f"$request->query('{param}');" in controller, cell.cell_id
            seen_plain += 1
    # Non-vacuous: both twins of all four pages, and the untouched remainder.
    assert seen_defaulted == 8
    assert seen_plain >= 10


# --- §2b: bare-fragment layout fix -------------------------------------------


def _html_body_echo_views() -> dict[str, tuple[str, str]]:
    """cell_id -> (render page path, rendered Blade view) for every cell whose
    composition names the `html_body_echo` sink."""
    views = {}
    for cell in _laravel_cells():
        files = _render(cell)
        if "view" in files and "html_body_echo" in _composition(files["view"]):
            views[cell.cell_id] = (_render_route_for(cell).path, files["view"])
    return views


def test_every_html_body_echo_view_extends_the_site_layout_r1() -> None:
    views = _html_body_echo_views()
    # R1: 4 tracked page cells (contact, newsletter, profile x2) plus the
    # untracked `/search.php` XSS twins and `/example/profile` pair.
    assert len(views) >= 8, sorted(views)
    assert {page for page, _ in views.values()} >= set(_TITLED_PAGES)
    for cell_id, (page, view) in views.items():
        body = view.split("?>\n", 1)[1]
        assert body.startswith("@extends('layouts.site')\n"), (cell_id, body)
        assert "@section('content')\n" in body and body.rstrip().endswith("@endsection"), (cell_id, body)
        assert "{!! $value !!}" in body, cell_id
        expected_title = _TITLED_PAGES.get(page, DEFAULT_PAGE_TITLE)
        assert f"@section('title', '{expected_title}')" in body, (cell_id, body)


def test_untitled_profiles_fall_back_instead_of_failing_r1() -> None:
    untitled = {
        page for page, _ in _html_body_echo_views().values() if _PAGE_TITLE_KEY not in _PAGE_PROFILES[page]
    }
    assert untitled == {"/search.php", "/example/profile"}


def test_page_title_with_a_quote_fails_loud() -> None:
    with pytest.raises(ValueError, match="page_title"):
        SINKS["html_body_echo"].render({"css_class": "bio", "page_title": "Ryder's"})


def test_page_title_is_never_passed_on_to_later_modules() -> None:
    result = SINKS["html_body_echo"].render({"css_class": "bio"})
    assert "page_title" not in result.context


# --- R6: LiveBootHarness(app=...) boots a split app's whole site -------------


def test_live_boot_harness_rejects_an_unknown_app() -> None:
    with pytest.raises(ValueError, match="unknown app"):
        LiveBootHarness(LaravelEmitter(), [], app="nope")


def test_live_boot_harness_app_overlays_the_same_site_layer_assemble_lab_writes(tmp_path) -> None:
    """Offline (no composer/boot): `_assemble()` with `app=` writes exactly
    `app_site.site_layer_files(app)` over the skeleton -- the same files
    `assemble_lab(app=...)` writes, so the navigability crawl boots the real
    standalone app, not its cells under PFF's own nav (R6)."""
    cells = collect_cells(cell_id_prefix=APP_REGISTRY["circlefeed"]["prefix"])
    harness = LiveBootHarness(LaravelEmitter(), cells, app="circlefeed")
    harness._app_dir = tmp_path / "app"
    harness._assemble()
    for rel_path, content in site_layer_files("circlefeed").items():
        assert (tmp_path / "app" / rel_path).read_bytes() == content, rel_path
    assert "loginForm" not in (tmp_path / "app" / "routes" / "site.php").read_text()

    default = LiveBootHarness(LaravelEmitter(), cells)
    default._app_dir = tmp_path / "default"
    default._assemble()
    assert "loginForm" in (tmp_path / "default" / "routes" / "site.php").read_text()
