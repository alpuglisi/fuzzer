"""CC-LAB-0240 / FR-LAB-158 (`docs/LAB_PFF_JSON_TO_HTML_PLAN.md`): PFF's own
migrated real pages render real HTML, not `response()->json($rows)`.

Offline (no network/composer) generated-source coverage for:

* the tail-flag hygiene fix -- named `_HTML_ROW_VIEW_KEY`/`_HTML_LIST_VIEW_KEY`
  constants, all tail flags popped out of the shared module context, and a
  fail-loud check when a profile sets more than one;
* the new `html_list_view` tail on `/product.php`, `/blog_post.php`,
  `/products.php` and `/search.php`'s SQLi twins;
* R5 (leakage-gate substitute): each twin pair `return view()`s the exact
  same shared, hand-authored Blade file;
* R3: `/search.php`'s four XSS cells (`render_only`) cannot pick up the tail;
* `/register.php`/`/login.php`'s HTML tails (status codes unchanged).

The real, executed behavior -- including R1's literal >= 300-byte
found/not-found HTML delta -- is proven against both live-boot harnesses in
`tests/test_labgen_conformance_live_boot.py` and
`tests/test_labgen_conformance_live_boot_mariadb.py`.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance import tier0
from fuzzlab.labgen.emitters import php_laravel
from fuzzlab.labgen.emitters.php_laravel import (
    _HTML_LIST_VIEW_KEY,
    _HTML_ROW_VIEW_KEY,
    _PAGE_PROFILES,
    _REGISTER_INSERT_KEY,
    _SESSION_LOGIN_KEY,
    _TAIL_FLAG_KEYS,
    LaravelEmitter,
)
from fuzzlab.labgen.schema import load_manifest

_VIEWS_DIR = Path("fuzzlab/labgen/emitters/php_laravel/stack/skeleton/resources/views")
_MANIFESTS = {
    "numeric": "lab/manifests/phase3_php_laravel_real_pages_numeric.yaml",
    "g2": "lab/manifests/phase3_php_laravel_real_pages_g2.yaml",
    "search": "lab/manifests/phase3_php_laravel_real_pages_search.yaml",
    "auth": "lab/manifests/phase3_php_laravel_real_pages_auth.yaml",
}

#: (page path, manifest key, vulnerable cell, secure cell) -- the converted
#: twin pairs (R5). `/products.php` is secure-only, covered separately.
_TWIN_PAIRS = (
    ("/product.php", "numeric", "LABGEN-RPL-PRODUCT", "LABGEN-RPL-PRODUCT-BOUND"),
    ("/blog_post.php", "numeric", "LABGEN-RPL-BLOGPOST", "LABGEN-RPL-BLOGPOST-BOUND"),
    ("/search.php", "search", "LABGEN-PL-RP-0001", "LABGEN-PL-RP-0002"),
)


def _cells(manifest_key: str):
    return {c.cell_id: c for c in load_manifest(_MANIFESTS[manifest_key]).cells}


def _controller(cell) -> str:
    files = LaravelEmitter().render(cell)
    return next(f for f in files if f.role == "controller").content.decode("utf-8")


def _complexity_of(controller_source: str) -> str:
    line = next(ln for ln in controller_source.splitlines() if ln.startswith("// Module composition:"))
    return line.rsplit("->", 1)[1].strip()


def _view_file(view_name: str) -> Path:
    return _VIEWS_DIR / (view_name.replace(".", "/") + ".blade.php")


def _list_view_call(view_name: str) -> str:
    return f"return view('{view_name}', ['rows' => $rows]);"


# --- hygiene fix (plan §2) ---------------------------------------------------


def test_tail_flag_keys_are_the_four_named_constants() -> None:
    assert _HTML_ROW_VIEW_KEY == "html_row_view"
    assert _HTML_LIST_VIEW_KEY == "html_list_view"
    assert set(_TAIL_FLAG_KEYS) == {
        _SESSION_LOGIN_KEY,
        _REGISTER_INSERT_KEY,
        _HTML_ROW_VIEW_KEY,
        _HTML_LIST_VIEW_KEY,
    }
    assert len(_TAIL_FLAG_KEYS) == len(set(_TAIL_FLAG_KEYS))


def test_no_page_profile_sets_more_than_one_tail_flag() -> None:
    for path, profile in _PAGE_PROFILES.items():
        present = [k for k in _TAIL_FLAG_KEYS if k in profile]
        assert len(present) <= 1, (path, present)


@pytest.mark.parametrize("pair", list(itertools.combinations(_TAIL_FLAG_KEYS, 2)))
def test_a_profile_with_two_tail_flags_fails_loud(monkeypatch, pair) -> None:
    """Every pair of tail flags on one profile raises -- never a silent
    first-branch-wins pick by the template's elif chain."""
    profile = dict(_PAGE_PROFILES["/product.php"])
    profile.pop(_HTML_LIST_VIEW_KEY)
    for key in pair:
        profile[key] = {"placeholder": True}
    monkeypatch.setitem(php_laravel._PAGE_PROFILES, "/product.php", profile)
    cell = _cells("numeric")["LABGEN-RPL-PRODUCT"]
    with pytest.raises(ValueError, match="more than one method-tail flag"):
        LaravelEmitter().render(cell)


def test_one_tail_flag_alone_still_renders(monkeypatch) -> None:
    """The mutual-exclusivity check does not false-positive on the ordinary
    one-flag case (the negative control for the test above)."""
    cell = _cells("numeric")["LABGEN-RPL-PRODUCT"]
    assert _list_view_call("site.product") in _controller(cell)


def test_tail_flags_are_popped_before_source_transform_and_sink_modules_render(monkeypatch) -> None:
    """Tail flags reach only the complexity module: a spy on the sink
    module's render sees none of them, while the complexity still renders
    the tail (the flag was handed back to it)."""
    seen: list[set[str]] = []
    sinks = php_laravel.SINKS
    real_sink = sinks["sql_numeric_lookup"]

    class _Spy:
        def __getattr__(self, name):
            return getattr(real_sink, name)

        def render(self, ctx):
            seen.append(set(ctx))
            return real_sink.render(ctx)

    monkeypatch.setitem(sinks, "sql_numeric_lookup", _Spy())
    cell = _cells("numeric")["LABGEN-RPL-PRODUCT"]
    source = _controller(cell)
    assert seen and not (seen[0] & set(_TAIL_FLAG_KEYS)), seen
    assert _list_view_call("site.product") in source


# --- html_list_view tail: twin pairs (R5) and the secure-only listing --------


@pytest.mark.parametrize("path,manifest_key,vulnerable_id,secure_id", _TWIN_PAIRS)
def test_both_twins_render_via_the_same_shared_html_list_view_r5(path, manifest_key, vulnerable_id, secure_id) -> None:
    """R5 (the leakage/fingerprint gate structurally skips these small
    manifests): both twins hand `$rows` to the exact same hand-authored Blade
    file -- one file, so byte-identical by construction -- and neither still
    returns JSON."""
    view_name = _PAGE_PROFILES[path][_HTML_LIST_VIEW_KEY]
    cells = _cells(manifest_key)
    vulnerable_src = _controller(cells[vulnerable_id])
    secure_src = _controller(cells[secure_id])
    for src in (vulnerable_src, secure_src):
        assert _list_view_call(view_name) in src
        assert "response()->json(" not in src
        assert _complexity_of(src) == "single_statement"
    assert _view_file(view_name).is_file(), view_name
    view_source = _view_file(view_name).read_text("utf-8")
    assert "@extends('layouts.site')" in view_source
    assert "@forelse ($rows as $row)" in view_source and "@empty" in view_source


def test_products_listing_renders_its_html_list_view() -> None:
    cell = _cells("g2")["LABGEN-PLRP-G2-0001"]
    src = _controller(cell)
    assert _list_view_call(_PAGE_PROFILES["/products.php"][_HTML_LIST_VIEW_KEY]) in src
    assert "response()->json(" not in src
    # The JSON feed at /api/products.php stays JSON (json_view Resource).
    assert _HTML_LIST_VIEW_KEY not in _PAGE_PROFILES["/api/products.php"]


def test_list_views_reuse_the_real_pages_empty_state_copy() -> None:
    """The historical PFF copy (`git show 876d2f9^:puppy-fort-factory/...`),
    reused verbatim rather than invented."""
    assert "Sorry, we couldn't find that fort." in _view_file("site.product").read_text("utf-8")
    assert "<p>Post not found.</p>" in _view_file("site.blog-post").read_text("utf-8")


def test_blog_post_view_guards_the_columns_only_the_real_schema_has_r6() -> None:
    """R6: the SQLite harness's `posts` has only id/title/body, so the view
    reads `author`/`published_at` only behind an isset() guard."""
    source = _view_file("site.blog-post").read_text("utf-8")
    assert "@if (isset($row->author) && isset($row->published_at))" in source


def test_search_view_does_not_reflect_the_query_value() -> None:
    """The SQLi twins' shared view must not add a `q` reflection of its own:
    `/search.php`'s XSS reflections are separate, exempted cells."""
    source = _view_file("site.search").read_text("utf-8")
    assert "$q" not in source and "request(" not in source and "old(" not in source


# --- R3: /search.php's four XSS cells stay unaffected ------------------------


def test_search_php_xss_cells_cannot_pick_up_the_list_view_tail_r3() -> None:
    """The four cells sharing `/search.php`'s profile through `render_only`
    render their own generated view, never the SQLi twins' `html_list_view`
    tail -- asserted on the rendered code, not inferred from reading
    `RenderOnlyComplexity.render`."""
    view_name = _PAGE_PROFILES["/search.php"][_HTML_LIST_VIEW_KEY]
    render_only_ids = []
    for cell_id, cell in _cells("search").items():
        src = _controller(cell)
        if _complexity_of(src) != "render_only":
            continue
        render_only_ids.append(cell_id)
        assert "['rows' => $rows]" not in src, cell_id
        assert view_name not in src, cell_id
        assert f"return view('cells.{cell_id.lower()}'" in src, cell_id
    assert sorted(render_only_ids) == [
        "LABGEN-PL-RP-0003",
        "LABGEN-PL-RP-0004",
        "LABGEN-PL-RP-0005",
        "LABGEN-PL-RP-0006",
    ]


# --- register.php / login.php (plan §3) --------------------------------------


def test_login_failure_renders_the_real_login_form_with_its_error_status_401() -> None:
    cells = _cells("auth")
    for cell_id in ("LABGEN-PLA-0001", "LABGEN-PLA-0002"):
        src = _controller(cells[cell_id])
        assert (
            "return response()->view('site.login', ['error' => 'Invalid username or password.'], 401);" in src
        ), cell_id
        assert "response()->json(" not in src, cell_id
    view = _view_file(_PAGE_PROFILES["/login.php"][_SESSION_LOGIN_KEY]["form_view"]).read_text("utf-8")
    assert '<p class="notice err">{{ $error }}</p>' in view
    assert "@isset($error)" in view  # GET /login.php (no data) still renders


def test_register_renders_html_for_duplicate_409_and_success_200() -> None:
    src = _controller(_cells("auth")["LABGEN-PLA-0003"])
    assert "return response()->view('site.register', [" in src
    assert "'error' => 'That username is already taken.'," in src
    assert "], 409);" in src
    assert "return response()->view('site.register', ['registered_username' => $username], 200);" in src
    assert "response()->json(" not in src
    view = _view_file(_PAGE_PROFILES["/register.php"][_REGISTER_INSERT_KEY]["form_view"]).read_text("utf-8")
    assert "Welcome to the pack, {{ $registered_username }}!" in view
    assert '<p class="notice err">{{ $error }}</p>' in view
    assert "value=\"{{ $username ?? '' }}\"" in view


# --- whole-collection checks (PA-0024) ---------------------------------------


def test_every_view_a_page_profile_names_exists_in_the_skeleton() -> None:
    """Every Blade view any profile's tail names (for every profile, not only
    the ones this change touched) exists -- a missing one would only 500 at
    request time."""
    named: list[str] = []
    for profile in _PAGE_PROFILES.values():
        for key in (_HTML_ROW_VIEW_KEY, _HTML_LIST_VIEW_KEY):
            if key in profile:
                named.append(profile[key])
        for key in (_SESSION_LOGIN_KEY, _REGISTER_INSERT_KEY):
            if key in profile and "form_view" in profile[key]:
                named.append(profile[key]["form_view"])
    assert len(named) >= 8
    for view_name in named:
        assert _view_file(view_name).is_file(), view_name
    assert _view_file("site.partials.product-card").is_file()


@pytest.mark.skipif(not tier0.php_available(), reason="php CLI not on PATH (PA-0005)")
def test_tier0_lint_passes_for_every_converted_cell() -> None:
    emitter = LaravelEmitter()
    for key in ("numeric", "g2", "search", "auth"):
        for cell in _cells(key).values():
            for result in tier0.lint_emitted_files(emitter.render(cell)):
                assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"
