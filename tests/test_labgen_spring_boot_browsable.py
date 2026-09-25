"""Offline checks for TrackerNest/ReelQueue/WanderFare's browsable site
(`CC-LAB-0244` / `FR-LAB-164-165`, `docs/LAB_LANE4_SPRING_BOOT_PLAN.md`).

Everything here runs without a real Maven/Java build (the real rendering is
proven by the `slow` live-boot module,
`tests/test_labgen_spring_boot_absent_input_live_boot.py`, and by
`tests/test_labgen_spring_boot_navigability_live_boot.py`): the PA-0053/
PA-0054 absent-input declarations every route must carry, the page/api
classification cross-checked against the plan's §1.5 table, the
app/ROUTE_APP cross-check (S11), and S7's layout/page-chrome checks (no
standalone 3+-digit token, matching the same guard every other stack's own
browsable-checks module carries).
"""

from __future__ import annotations

import re

from fuzzlab.labgen.emitters.spring_boot import (
    _CLIENT_PAGE_SPECS,
    _PAGE_PARAMS,
    ABSENT_INPUT_KINDS,
    SpringBootEmitter,
    app_cells_for,
)
from fuzzlab.labgen.emitters.spring_boot.app_site import APP_REGISTRY, ROUTE_APP
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.harness.auto import points_from_ground_truth
from fuzzlab.labels import contract

#: Plan §1.5: 1 `page`, 15 `api`.
_EXPECTED_CLASSIFICATION = {
    "/wiki/pages/render": "page",
    "/issues/import": "api",
    "/integrations/webhook-payload": "api",
    "/api/playback/resume": "api",
    "/api/content/import": "api",
    "/api/profiles/switch": "api",
    "/api/account/billing": "api",
    "/api/subscription/change-plan": "api",
    "/api/profiles/avatar": "api",
    "/api/account/settings": "api",
    "/api/account/preferences": "api",
    "/api/content/thumbnail-import": "api",
    "/api/session/refresh": "api",
    "/api/support/template-preview": "api",
    "/api/hotels/search-sort": "api",
    "/api/trips/restore": "api",
}

_THREE_PLUS_DIGITS = re.compile(r"\d{3,}")


def test_every_route_declares_absent_input_and_classification() -> None:
    """Every route in the route profile declares exactly one
    `ABSENT_INPUT_KINDS` value, an `app` naming a real `APP_REGISTRY` entry,
    and a `classification` matching plan §1.5 -- PA-0053, enforced offline
    for the whole emitter (PA-0054)."""
    assert set(_PAGE_PARAMS) == set(_EXPECTED_CLASSIFICATION), (
        set(_PAGE_PARAMS), set(_EXPECTED_CLASSIFICATION),
    )
    for route, profile in _PAGE_PARAMS.items():
        assert "absent_input" in profile, route
        assert profile["absent_input"] in ABSENT_INPUT_KINDS, (route, profile["absent_input"])
        assert profile.get("app") in APP_REGISTRY, (route, profile.get("app"))
        assert profile.get("classification") == _EXPECTED_CLASSIFICATION[route], (
            route, profile.get("classification"),
        )


def test_route_app_matches_page_params_app_s11() -> None:
    """S11: `app_site.ROUTE_APP` (the site layer's own source of truth for
    nav/catalog membership) never drifts from `_PAGE_PARAMS`'s own `app`
    key."""
    for route, profile in _PAGE_PARAMS.items():
        if route not in ROUTE_APP:
            continue  # the one `page`-classified route has no ROUTE_APP entry
        assert ROUTE_APP[route] == profile["app"], (route, ROUTE_APP[route], profile["app"])


def test_every_api_route_has_a_client_page_spec() -> None:
    """Every `api`-classified route (15 of them, plan §1.5) has a
    `_CLIENT_PAGE_SPECS` entry (plan §2c) -- no api route is left without a
    browsable client page."""
    api_routes = {r for r, c in _EXPECTED_CLASSIFICATION.items() if c == "api"}
    assert api_routes == set(_CLIENT_PAGE_SPECS), (api_routes, set(_CLIENT_PAGE_SPECS))


#: S3: `rendering` doubles as `fuzzlab.harness.auto`'s request-encoding hint
#: (`auto.py:92-96`) -- 9 of the 16 points are whole-body (`param="body"`),
#: 6 of them `rendering: server-json`. This pins that ground truth is
#: genuinely unedited (S3's own rule: no ground-truth edits by this
#: change) by asserting `points_from_ground_truth`'s derived
#: `body_content_type` is exactly what it always was for all 16 points.
_EXPECTED_BODY_CONTENT_TYPE = {
    ("lab/ground-truth-trackernest", "/integrations/webhook-payload", "POST", "body"): None,
    ("lab/ground-truth-trackernest", "/issues/import", "POST", "body"): None,
    ("lab/ground-truth-trackernest", "/wiki/pages/render", "GET", "macroExpr"): None,
    ("lab/ground-truth-netflix-clone", "/api/account/billing", "GET", "account_id"): None,
    ("lab/ground-truth-netflix-clone", "/api/account/preferences", "GET", "Authorization"): None,
    ("lab/ground-truth-netflix-clone", "/api/account/settings", "POST", "body"): "application/json",
    ("lab/ground-truth-netflix-clone", "/api/content/import", "POST", "body"): None,
    ("lab/ground-truth-netflix-clone", "/api/content/thumbnail-import", "POST", "thumbnail_url"): None,
    ("lab/ground-truth-netflix-clone", "/api/playback/resume", "POST", "body"): "application/json",
    ("lab/ground-truth-netflix-clone", "/api/profiles/avatar", "POST", "file"): None,
    ("lab/ground-truth-netflix-clone", "/api/profiles/switch", "POST", "body"): "application/json",
    ("lab/ground-truth-netflix-clone", "/api/session/refresh", "POST", "body"): "application/json",
    ("lab/ground-truth-netflix-clone", "/api/subscription/change-plan", "POST", "body"): "application/json",
    ("lab/ground-truth-netflix-clone", "/api/support/template-preview", "GET", "expr"): None,
    ("lab/ground-truth-expedia-clone", "/api/hotels/search-sort", "GET", "sortBy"): None,
    ("lab/ground-truth-expedia-clone", "/api/trips/restore", "POST", "body"): "application/json",
}


def test_ground_truth_body_content_type_is_unchanged() -> None:
    """S3: no ground-truth edit changed `points_from_ground_truth`'s
    derived request encoding for any of the 16 real points."""
    actual = {}
    for gt_dir in ("lab/ground-truth-trackernest", "lab/ground-truth-netflix-clone", "lab/ground-truth-expedia-clone"):
        gt = contract.load(gt_dir)
        points = points_from_ground_truth(gt, "http://x")[0]
        for p in points:
            actual[(gt_dir, p.url.removeprefix("http://x"), p.method, p.param)] = p.body_content_type
    assert actual == _EXPECTED_BODY_CONTENT_TYPE, (
        sorted(set(actual) ^ set(_EXPECTED_BODY_CONTENT_TYPE)),
        {k: v for k, v in actual.items() if _EXPECTED_BODY_CONTENT_TYPE.get(k) != v},
    )


def test_app_cells_for_partitions_every_cell_exactly_once() -> None:
    """Every real cell belongs to exactly one app (plan §1.3's 6/22/4 split,
    32 total)."""
    by_app = {app: app_cells_for(app) for app in APP_REGISTRY}
    counts = {app: len(cells) for app, cells in by_app.items()}
    assert counts == {"trackernest": 6, "reelqueue": 22, "wanderfare": 4}, counts
    all_ids = [c.cell_id for cells in by_app.values() for c in cells]
    assert len(all_ids) == len(set(all_ids)) == 32, len(all_ids)


def test_shared_layout_has_no_standalone_three_digit_token() -> None:
    """S7: the one shared layout file (`SiteLayout.java`, byte-identical
    across every app and every cell) contains no standalone 3+-digit run in
    any of its Java string literals, so a future page reuse by an
    SSTI-style arithmetic-product canary never coincidentally matches in
    the chrome every page shares. (Page-specific content, like `/catalog`'s
    cell-ID listing, legitimately contains digits and is out of scope for
    this check -- it is never evaluated as part of any cell's own SSTI
    sink.)"""
    layout_path = (
        "fuzzlab/labgen/emitters/spring_boot/stack/skeleton/"
        "src/main/java/com/fuzzlab/trackernest/SiteLayout.java"
    )
    text = open(layout_path, encoding="utf-8").read()
    string_literals = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    hits = [s for s in string_literals if _THREE_PLUS_DIGITS.search(s)]
    assert not hits, hits


def test_site_layer_renders_deterministically() -> None:
    """Two renders of the same app's site controller are byte-identical
    (no randomness, no wall-clock, no request-derived content)."""
    emitter = SpringBootEmitter(site_build=True)
    for app_key in APP_REGISTRY:
        cells = app_cells_for(app_key)
        first = emitter.render_site(cells, app_key)
        second = emitter.render_site(cells, app_key)
        assert first[0].content == second[0].content, app_key


#: S9: the page_handler.java.j2-specific lines that must be byte-identical
#: on both `/wiki/pages/render` twins -- everything the page-layer wrapping
#: itself contributes (the declared-absent-input guard and the call into
#: the shared layout). `fuzzlab.labgen.minimal_pair`'s generic checker
#: assumes `fuzzlab.labgen.modules`' own SOURCES/TRANSFORMS/SINKS/
#: COMPLEXITIES registry for its "// Module composition: ..." parsing,
#: which does not cover `spring_boot`'s own, separate module registry
#: (a pre-existing gap, out of this change's scope) -- so this is a
#: bespoke structural check instead, in the same spirit as BUG-0027.
_PAGE_HANDLER_INVARIANT_LINES = (
    'String pageInput = request.getParameter(',
    'org.springframework.http.ResponseEntity<String> result =',
    '(pageInput == null || pageInput.isEmpty()) ? null : compute(request);',
    'return com.fuzzlab.trackernest.SiteLayout.page(',
)


def test_wiki_pages_render_page_conversion_is_a_minimal_pair() -> None:
    """S9: `page_handler.java.j2` (T1's `/wiki/pages/render` conversion)
    wraps the vulnerable and secure `ssti` cells identically -- every line
    the page layer itself contributes (the declared `form_when_absent`
    guard and the call into the shared layout) is byte-identical between
    the real `LABGEN-SSTI-0001`/`0002` twins; only the wrapped `compute()`
    body (the existing, separately-tested transform/sink region) may
    differ."""
    cells = {}
    for path in ("lab/manifests/ssti_spring_boot_sample.yaml",):
        for cell in load_manifest(path).cells:
            if cell.cell_id in ("LABGEN-SSTI-0001", "LABGEN-SSTI-0002"):
                cells[cell.cell_id] = cell
    assert set(cells) == {"LABGEN-SSTI-0001", "LABGEN-SSTI-0002"}, sorted(cells)

    emitter = SpringBootEmitter()
    vulnerable = emitter.render(cells["LABGEN-SSTI-0001"])[0].content.decode("utf-8")
    secure = emitter.render(cells["LABGEN-SSTI-0002"])[0].content.decode("utf-8")
    for needle in _PAGE_HANDLER_INVARIANT_LINES:
        assert needle in vulnerable, (needle, vulnerable)
        assert needle in secure, (needle, secure)
    v_lines = {ln.strip() for ln in vulnerable.splitlines() if any(n in ln for n in _PAGE_HANDLER_INVARIANT_LINES)}
    s_lines = {ln.strip() for ln in secure.splitlines() if any(n in ln for n in _PAGE_HANDLER_INVARIANT_LINES)}
    assert v_lines == s_lines, (v_lines, s_lines)
