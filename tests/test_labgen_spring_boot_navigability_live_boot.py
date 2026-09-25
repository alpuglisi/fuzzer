"""Spider-based navigability acceptance test for the three `spring_boot`
apps -- TrackerNest, ReelQueue, WanderFare (CC-LAB-0244 / FR-LAB-164/165,
`docs/LAB_LANE4_SPRING_BOOT_PLAN.md` §4; the acceptance criterion is
`docs/LAB_BROWSABLE_APPS_PLAN.md`'s design-contract point 6). Mirrors
`tests/test_labgen_django_navigability_live_boot.py` (Lane 2's `django`
version) for the `spring_boot` stack, parametrized over the three apps.

For each app, boots its **whole** build with the real
`SpringBootLiveBootHarness` in ``app=`` mode (every real cell -- vulnerable
and secure twin -- `app_cells_for` assigns to that app, PA-0027-derived,
never a hand-kept cell-ID list) plus the generated site layer
(`render_site`'s homepage/`/catalog`/client pages), then crawls it from `/`
with fuzzlab's own `fuzzlab.tools.spider.LocalSpider` (`requests` engine:
every page is server-rendered HTML, no client-side routing), same-host
scope, and asserts:

1. **non-vacuous guards first** (R5) -- each app's ground-truth point list
   and the crawl's discovered-page set are each at least a hard-coded,
   measured minimum (never derived from the file being asserted against);
2. every ground-truth injection-point URL is discovered;
3. each one returns what a real anonymous visitor gets: for a `page`- or a
   GET `api`-classified route this is the route's own declared absent-input
   status (plan §2e -- `EXPECTED_STATUS`, restated here on purpose, the same
   contract `tests/test_labgen_spring_boot_absent_input_live_boot.py`
   exercises directly and `tests/test_labgen_spring_boot_browsable.py`
   cross-checks offline against the emitter's own `absent_input`
   declarations); for a POST `api`-classified route it is 200 -- a browser
   visiting that URL with a plain `GET` gets the route's own client page
   (plan §2c: a POST api's client page is registered at the api's own
   served URL), never the sink;
4. `GET /` returns 200;
5. **PA-0053's bare-GET sweep** (R7) -- no crawled URL answers 5xx; and,
   beyond what links reach (PA-0054), a bare `GET` of **every** route the
   build serves (from the emitter's own `served_url_for` plus the site
   layer, not from the crawl) answers < 500.

A GET `api` route's client page lives at a *separate*, non-`/api` URL
(plan §2c) and its form's own `action` target -- or a `bearer_fetch` page's
`fetch()` target -- is never itself a crawlable link (a static crawl only
follows `<a href>`), so each such client page also carries a plain
`<a href>` straight to the api's own URL (mirroring `django`'s
`upload.html` "This page calls PicTrail's link-preview API: `<a href>`"
pattern) -- without it the ground-truth URL itself would be unreachable
from `/` and this test's point 2 above would fail for those four routes.

Depth cap (R2/R7, measured, not guessed): on 2026-09-25 every ground-truth
URL was reached at link depth <= 1 from `/` (nav links every real page and
every client page directly; the four GET-api ground-truth URLs are reached
via the client page's own `<a href>` at depth <= 2) in all three apps;
:data:`_MAX_DEPTH` is 4, and the test asserts the deepest ground-truth URL
stays strictly below the cap so a truncated crawl can never look complete.

Skip-guarded (PA-0005) on `spring_boot_boot_available()` and marked `slow`,
like every other live-boot module. Three real Maven/Spring Boot builds run
(one per app), so this module is slower than a single-app live-boot suite.
"""

from __future__ import annotations

import sqlite3
from urllib.parse import urlsplit

import pytest

from fuzzlab.labels.contract import load_injection_points
from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.spring_boot import (
    _PAGE_PARAMS,
    SpringBootEmitter,
    app_cells_for,
    served_url_for,
)
from fuzzlab.tools.spider import LocalSpider

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not spring_boot_boot_available(),
        reason=(
            "spring_boot live-boot harness requires java + mvn on PATH and real Maven Central "
            "reachability (PA-0005) -- see live_boot_spring_boot.spring_boot_boot_available()"
        ),
    ),
]

#: R7: the crawl's depth cap. Measured deepest ground-truth URL is 2 (see
#: the module docstring); 4 leaves headroom.
_MAX_DEPTH = 4

#: CC-LAB-0244: per-app ground-truth directory, R5's hard-coded measured
#: minimums (2026-09-25, never computed from the file under test), and the
#: status a real anonymous visitor's `GET` gets on each ground-truth URL
#: (plan §2e's declared absent-input status for a `page`/GET-`api` route;
#: 200 -- the route's own client page -- for a POST `api` route, point 3
#: above).
_APPS: dict[str, dict] = {
    "trackernest": {
        "ground_truth_dir": "lab/ground-truth-trackernest",
        "min_ground_truth_points": 3,
        "min_discovered_pages": 5,
        "expected_status": {
            "/wiki/pages/render": 200,  # page, form_when_absent
            "/issues/import": 200,  # POST api -> its own client page
            "/integrations/webhook-payload": 200,  # POST api -> its own client page
        },
    },
    "reelqueue": {
        "ground_truth_dir": "lab/ground-truth-netflix-clone",
        "min_ground_truth_points": 11,
        "min_discovered_pages": 16,
        "expected_status": {
            "/api/account/billing": 400,  # GET api, required_param
            "/api/account/preferences": 401,  # GET api, required_header
            "/api/account/settings": 200,  # POST api -> its own client page
            "/api/content/import": 200,  # POST api -> its own client page
            "/api/content/thumbnail-import": 200,  # POST api -> its own client page
            "/api/playback/resume": 200,  # POST api -> its own client page
            "/api/profiles/avatar": 200,  # POST api -> its own client page
            "/api/profiles/switch": 200,  # POST api -> its own client page
            "/api/session/refresh": 200,  # POST api -> its own client page
            "/api/subscription/change-plan": 200,  # POST api -> its own client page
            "/api/support/template-preview": 400,  # GET api, required_param
        },
    },
    "wanderfare": {
        "ground_truth_dir": "lab/ground-truth-expedia-clone",
        "min_ground_truth_points": 2,
        "min_discovered_pages": 4,
        "expected_status": {
            "/api/hotels/search-sort": 200,  # GET api, default_value 'recommended'
            "/api/trips/restore": 200,  # POST api -> its own client page
        },
    },
}


def _linkable_urls(app_key: str, cells) -> set[str]:
    """Every URL `render_site` puts an `<a href>` to for this app: the site
    layer's own `/` and `/catalog`, every cell's own served URL -- both
    twins, `/catalog`'s site-map table links each one (plan design
    contract point 3) -- and every GET `api` route's separate, non-`/api`
    client-page URL (a POST route's client page lives at the api's own
    served URL, already covered)."""
    urls = {"/", "/catalog"}
    for c in cells:
        urls.add(served_url_for(c, site_build=True))
        profile = _PAGE_PARAMS[c.route.path]
        if profile["classification"] == "api" and c.route.method == "GET":
            urls.add(c.route.path.removeprefix("/api") or "/")
    return urls


@pytest.fixture(scope="module", params=sorted(_APPS))
def crawl(request, tmp_path_factory):
    app_key = request.param
    cells = app_cells_for(app_key)
    harness = SpringBootLiveBootHarness(SpringBootEmitter(), cells, app=app_key, build_timeout=600.0)
    harness.build()
    try:
        db = tmp_path_factory.mktemp(f"crawl-{app_key}") / "spider.db"
        spider = LocalSpider(harness._base_url() + "/", max_depth=_MAX_DEPTH, db_name=str(db), engine="requests")
        # Loopback lab target: never route through an ambient HTTP proxy.
        spider.session.trust_env = False
        spider.crawl()
        conn = sqlite3.connect(db)
        try:
            rows = conn.execute("SELECT url, status_code, depth FROM discovered_pages").fetchall()
        finally:
            conn.close()
        pages = {}
        for url, status, depth in rows:
            parts = urlsplit(url)
            if not parts.query:
                pages[parts.path or "/"] = (status, depth)
        print(f"[{app_key}] crawl: {len(rows)} URLs, {len(pages)} without a query; max depth "
              f"{max(d for _, _, d in rows)}")
        for url, status, depth in sorted(rows, key=lambda r: (r[2], r[0])):
            print(f"  [{status}] depth {depth}: {url}")
        yield {"app_key": app_key, "harness": harness, "cells": cells, "rows": rows, "pages": pages}
    finally:
        harness.close()


def test_crawl_from_root_discovers_every_ground_truth_url_with_anonymous_status(crawl) -> None:
    config = _APPS[crawl["app_key"]]
    points = load_injection_points(config["ground_truth_dir"])
    pages = crawl["pages"]

    # --- R5: non-vacuous-pass guards (before any per-URL assertion) --------
    assert len(points) >= config["min_ground_truth_points"], (crawl["app_key"], len(points))
    assert len(crawl["rows"]) >= config["min_discovered_pages"], (
        crawl["app_key"], len(crawl["rows"]), sorted(pages),
    )

    # --- GET / ---------------------------------------------------------------
    assert pages.get("/", (None, None))[0] == 200, (crawl["app_key"], pages.get("/"))
    assert crawl["harness"].get("/").status == 200

    # --- every ground-truth URL is discovered -------------------------------
    gt_urls = {p.url for p in points}
    expected_status = config["expected_status"]
    # Every ground-truth URL is accounted for -- nothing silently skipped.
    assert gt_urls == set(expected_status), (crawl["app_key"], sorted(gt_urls), sorted(expected_status))
    missing = sorted(u for u in gt_urls if u not in pages)
    assert not missing, (crawl["app_key"], missing, sorted(pages))

    # --- R7: nothing sits at the depth cap ----------------------------------
    deepest = max(pages[u][1] for u in gt_urls)
    assert deepest < _MAX_DEPTH, (crawl["app_key"], deepest)

    # --- anonymous-visitor status --------------------------------------------
    wrong = {u: (pages[u][0], want) for u, want in expected_status.items() if pages[u][0] != want}
    assert not wrong, (crawl["app_key"], wrong)


def test_every_catalog_page_is_link_reachable(crawl) -> None:
    """Every URL `render_site` links to -- the site layer, every `page`-
    classified cell's own served URL (both twins), and every `api` route's
    client page URL -- is reachable by clicking through the site from `/`."""
    pages = crawl["pages"]
    linkable = _linkable_urls(crawl["app_key"], crawl["cells"])
    missing = sorted(linkable - set(pages))
    assert not missing, (crawl["app_key"], missing, sorted(pages))


def test_pa_0053_bare_get_sweep_no_route_answers_5xx(crawl) -> None:
    """R7 / PA-0053 (strengthened by PA-0054): (a) no URL the crawl reached
    -- with or without a query string -- answered 5xx (or failed outright,
    status 0); (b) independently of what links reach, a bare `GET` (no
    query, no body) of **every** route the build serves -- every cell's own
    served URL (both twins) plus the site layer -- answers < 500."""
    crashed = sorted((url, status) for url, status, _ in crawl["rows"] if status == 0 or status >= 500)
    assert not crashed, (crawl["app_key"], crashed)

    harness = crawl["harness"]
    cells = crawl["cells"]
    every_route = sorted(
        {served_url_for(c, site_build=True) for c in cells} | _linkable_urls(crawl["app_key"], cells)
    )
    statuses = {}
    for url in every_route:
        try:
            statuses[url] = harness.get(url).status
        except Exception as exc:  # urllib raises on 4xx/5xx in some paths
            statuses[url] = getattr(exc, "code", None) or 0
    print(f"[{crawl['app_key']}] bare-GET sweep:", statuses)
    bad = {u: s for u, s in statuses.items() if not s or s >= 500}
    assert not bad, (crawl["app_key"], bad)


def test_s2_browser_accept_negotiation_reflected_xss_flagged_follow_up(crawl) -> None:
    """S2 (plan §3, flagged follow-up -- **not fixed by this lane**): a
    browser's `Accept: text/html` is honored by Spring's own content
    negotiation for an `api` route's plain-`String` body, serving an
    OGNL-vulnerable twin's unescaped, reflected error text
    (`/api/support/template-preview`'s `expr`) as `text/html` -- a latent,
    unlabelled reflected XSS. Confirmed live 2026-09-25: `Accept: text/html`
    -> `Content-Type: text/html;charset=UTF-8` with the payload verbatim in
    the body; `Accept: application/json` / no `Accept` header do not trigger
    it. The `page`-classified route already sets `text/html` explicitly and
    escapes (plan §2b); `api` routes are deliberately unchanged here (would
    alter 10 plain-text api wire contracts -- a different class). Pinned so
    a real fix flips this xfail and forces deletion of the marker; the next
    unreserved `CC-LAB` number is allocated by the orchestrator when that
    happens."""
    if crawl["app_key"] != "reelqueue":
        pytest.skip("S2 is reproduced on reelqueue's /api/support/template-preview")
    payload = "<b>xss-canary</b>"
    resp = crawl["harness"].get(
        "/api/support/template-preview", params={"expr": payload}, headers={"Accept": "text/html"},
    )
    is_html = resp.headers.get("Content-Type", "").split(";")[0].strip() == "text/html"
    reflected_unescaped = payload in resp.body
    if is_html and reflected_unescaped:
        pytest.xfail("S2: browser Accept negotiation reflects the payload as text/html (known, not fixed)")
    pytest.fail("S2 appears fixed -- delete this xfail-by-manual-check test (S15 decision rule)")


#: S6 (plan §3, flagged follow-up -- **not fixed by this lane**): malformed
#: *present* JSON (the input exists, but doesn't parse) crashes both twins
#: of these two routes with a raw Spring 500 -- a different bug class from
#: S4/BUG-0054 (which is about *absent* input). Confirmed live 2026-09-25.
_S6_MALFORMED_JSON_ROUTES = ("/api/account/settings", "/api/subscription/change-plan")


def test_s6_malformed_present_json_flagged_follow_up(crawl) -> None:
    """S6: a syntactically invalid (but present) JSON body 500s on both
    twins of `/api/account/settings` and `/api/subscription/change-plan`.
    Reviewer-reproduced; confirmed live here. Pinned the same way as S2 --
    a real fix flips this xfail."""
    if crawl["app_key"] != "reelqueue":
        pytest.skip("S6 is reproduced on reelqueue's account/settings and subscription/change-plan routes")
    still_crashing = []
    for path in _S6_MALFORMED_JSON_ROUTES:
        resp = crawl["harness"].post(path, data=b"{not valid json", content_type="application/json")
        if resp.status >= 500:
            still_crashing.append((path, resp.status))
    if still_crashing:
        pytest.xfail(f"S6: malformed present JSON still 500s (known, not fixed): {still_crashing}")
    pytest.fail("S6 appears fixed -- delete this xfail-by-manual-check test (S15 decision rule)")
