"""Spider-based navigability acceptance test for LoopCast, the `go_net_http`
app (`CC-LAB-0243` / `FR-LAB-162`, `docs/LAB_LANE3_GO_NET_HTTP_TWITCH_PLAN.md`
§4; the acceptance criterion is `docs/LAB_BROWSABLE_APPS_PLAN.md`'s
design-contract point 6). Mirrors `tests/test_labgen_django_navigability_live_boot.py`
(Lane 2's `django` version) for the `go_net_http` stack.

Boots LoopCast's **whole** site with the real `GoLiveBootHarness` -- all 28
`go_net_http` cells (14 real pages + their 14 secure twins at their
twin-suffixed URLs) plus the checked-in site layer (`/`) -- then crawls it
from `/` with `fuzzlab.tools.spider.LocalSpider` (`requests` engine: every
page is server-rendered HTML/plain text), same-host scope, and asserts:

1. **non-vacuous guards first** (R12) -- the ground-truth point count and the
   crawl's discovered-page count are each at least a hard-coded, measured
   minimum;
2. every ground-truth injection-point URL is discovered by the crawl;
3. `GET /` returns 200;
4. **PA-0053's bare-request sweep, strengthened by PA-0054** -- no crawled
   URL answers 5xx; independently of what links reach, a bare `GET` **and**
   a bare request with the route's own method (empty body, no headers) of
   **every** route the build serves (from `served_url_for`, not the crawl)
   answers < 500, and each GT URL's own-method bare status matches its
   declared `absent_input` behavior;
5. **R1 twin byte-identity** -- every real page's vulnerable and secure-twin
   URL serve byte-identical content on a bare GET (both are a pure function
   of the route's canonical path, never of which URL served them).

`requests`'s default redirect-following means the crawl's own recorded
status for the 2 redirect routes (`/channels/redirect`, `/auth/login-redirect`)
is the *followed* destination's status (200, landing on `/`), not the raw
302 -- the raw redirect status is asserted directly against the un-redirected
harness instead (mirrors this project's `test_labgen_go_live_boot.py`'s own
redirect-differential tests, which use the same no-redirect harness).

Skip-guarded (PA-0005) on `go_boot_available()`, marked `slow`, like every
other live-boot module.
"""

from __future__ import annotations

import sqlite3
from urllib.parse import urlsplit

import pytest

from fuzzlab.labels.contract import load_injection_points
from fuzzlab.labgen.conformance.go_live_boot import GoLiveBootHarness, go_boot_available
from fuzzlab.labgen.emitters.go_net_http import (
    _REAL_PAGE_CELL_IDS,
    _REAL_PAGE_TWIN_CELL_IDS,
    GoEmitter,
    app_cells,
    served_url_for,
)
from fuzzlab.tools.spider import LocalSpider

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not go_boot_available(),
        reason=(
            "go_net_http live-boot harness requires the go toolchain and a real "
            "module-proxy round trip (PA-0005/PA-0035) -- see go_live_boot.go_boot_available()"
        ),
    ),
]

_GROUND_TRUTH_DIR = "lab/ground-truth-twitch-clone"

#: R7/R12: the crawl's depth cap. LoopCast's nav links every real page
#: directly from `/`, so the measured deepest ground-truth URL is 1;
#: 4 leaves headroom.
_MAX_DEPTH = 4

#: R12: hard-coded, measured minimums (2026-09-25) -- never computed from
#: the file under test. Measured: 14 ground-truth points; 16 crawled pages
#: (the homepage + 14 real pages + `/dashboard`, every one nav-linked).
_MIN_GROUND_TRUTH_POINTS = 14
_MIN_DISCOVERED_PAGES = 16

#: ground-truth URL -> the status its own declared method (GET or POST, per
#: the manifest) gets on a bare request with no input (plan §2d/BUG-0053).
#: `form_on_get` (§2d) only says GET serves the site page -- a bare request
#: with the route's OWN method (POST, for 6 of these) still reaches that
#: route's real handler, whose own pre-existing bare-input behavior is
#: measured here, not assumed (each is < 500, so none is itself a bug):
#: `/channels/emotes/upload` and `/subscriptions/purchase` already answer a
#: handled 400 (missing file / empty JSON body); `/webhooks/eventsub`
#: already answers a handled 401 (missing/invalid signature).
_EXPECTED_OWN_METHOD_STATUS = {
    "/webhooks/eventsub": 401,  # existing signature check rejects a bare POST
    "/api/clips/thumbnail": 400,  # required_param (BUG-0053; renamed from required_400, CC-LAB-0247)
    "/channels/analytics": 401,  # default_caller_else_401, no caller header
    "/channels/settings": 401,  # auth_reject_401
    "/sessions/refresh": 200,  # no_input: the source reads nothing
    "/channels/profile": 200,  # existing handler accepts a bare POST
    "/channels/subscribers": 401,  # default_caller_else_401
    "/clips/download": 400,  # required_param (BUG-0053; renamed from required_400, CC-LAB-0247)
    "/channels/emotes/upload": 400,  # existing handler: missing file part
    "/subscriptions/purchase": 400,  # existing handler: empty JSON body
    "/clips/export": 400,  # required_param (BUG-0053; renamed from required_400, CC-LAB-0247)
    "/channels/commands": 200,  # existing handler accepts a bare POST
    "/channels/redirect": 302,  # default: redirects to "/"
    "/auth/login-redirect": 302,  # default: redirects to "/dashboard"
}


@pytest.fixture(scope="module")
def crawl(tmp_path_factory):
    cells = app_cells()
    harness = GoLiveBootHarness(GoEmitter(), cells)
    harness.build()
    try:
        db = tmp_path_factory.mktemp("crawl-loopcast") / "spider.db"
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
        print(f"crawl: {len(rows)} URLs, {len(pages)} without a query; max depth "
              f"{max(d for _, _, d in rows)}")
        for url, status, depth in sorted(rows, key=lambda r: (r[2], r[0])):
            print(f"  [{status}] depth {depth}: {url}")
        yield {"harness": harness, "cells": cells, "rows": rows, "pages": pages}
    finally:
        harness.close()


def test_crawl_from_root_discovers_every_ground_truth_url(crawl) -> None:
    points = load_injection_points(_GROUND_TRUTH_DIR)
    pages = crawl["pages"]

    # --- R12: non-vacuous-pass guards (before any per-URL assertion) -------
    assert len(points) >= _MIN_GROUND_TRUTH_POINTS, len(points)
    assert len(crawl["rows"]) >= _MIN_DISCOVERED_PAGES, (len(crawl["rows"]), sorted(pages))

    # --- GET / ---------------------------------------------------------------
    assert pages.get("/", (None, None))[0] == 200, pages.get("/")
    assert crawl["harness"].request("GET", "/").status == 200

    # --- every ground-truth URL is discovered -------------------------------
    gt_urls = {p.url for p in points}
    assert gt_urls == set(_EXPECTED_OWN_METHOD_STATUS), (
        sorted(gt_urls), sorted(_EXPECTED_OWN_METHOD_STATUS),
    )
    missing = sorted(u for u in gt_urls if u not in pages)
    assert not missing, (missing, sorted(pages))

    # --- R7: nothing sits at the depth cap ----------------------------------
    deepest = max(pages[u][1] for u in gt_urls)
    assert deepest < _MAX_DEPTH, deepest


def test_pa_0053_bare_request_sweep_no_route_answers_5xx(crawl) -> None:
    """PA-0053, strengthened by PA-0054: (a) no URL the crawl reached
    answered 5xx (or failed outright, status 0); (b) independently of what
    links reach, a bare `GET` of **every** route the build serves,
    enumerated from `served_url_for` (both twins), answers < 500; (c) each
    ground-truth URL's own-method bare status matches its declared
    `absent_input` behavior (`_EXPECTED_OWN_METHOD_STATUS`, BUG-0053)."""
    crashed = sorted((url, status) for url, status, _ in crawl["rows"] if status == 0 or status >= 500)
    assert not crashed, crashed

    harness = crawl["harness"]
    every_route = sorted({served_url_for(c) for c in crawl["cells"]} | {"/"})
    assert len(every_route) == len(crawl["cells"]) + 1
    bare_get = {url: harness.request("GET", url).status for url in every_route}
    print("bare-GET sweep:", bare_get)
    bad = {u: s for u, s in bare_get.items() if not s or s >= 500}
    assert not bad, bad

    own_method = {}
    for cell in crawl["cells"]:
        if cell.route.path not in _EXPECTED_OWN_METHOD_STATUS:
            continue
        url = served_url_for(cell)
        method = cell.route.method.upper()
        own_method[cell.route.path] = harness.request(method, url, body=b"" if method == "POST" else None).status
    print("own-method sweep:", own_method)
    wrong = {
        p: (s, _EXPECTED_OWN_METHOD_STATUS[p])
        for p, s in own_method.items()
        if s != _EXPECTED_OWN_METHOD_STATUS[p]
    }
    assert not wrong, wrong


def test_real_pages_are_byte_identical_on_both_twins(crawl) -> None:
    """R1: a bare `GET` of a real page's vulnerable URL and its secure
    twin's URL return byte-identical bodies -- both are a pure function of
    the route's canonical path (`sitePage`/`renderPage`), never of which
    twin served them."""
    harness = crawl["harness"]
    cells = {c.cell_id: c for c in crawl["cells"]}
    twin_by_route: dict[str, tuple[str, str]] = {}
    for real_id in _REAL_PAGE_CELL_IDS:
        real_url = served_url_for(cells[real_id])
        twin_id = next(
            tid for tid in _REAL_PAGE_TWIN_CELL_IDS
            if cells[tid].route.path == cells[real_id].route.path
        )
        twin_url = served_url_for(cells[twin_id])
        twin_by_route[cells[real_id].route.path] = (real_url, twin_url)

    assert len(twin_by_route) == len(_REAL_PAGE_CELL_IDS) == 14

    mismatched = {}
    for route, (real_url, twin_url) in sorted(twin_by_route.items()):
        real_body = harness.request("GET", real_url).body
        twin_body = harness.request("GET", twin_url).body
        if real_body != twin_body:
            mismatched[route] = (real_url, twin_url)
    assert not mismatched, mismatched
