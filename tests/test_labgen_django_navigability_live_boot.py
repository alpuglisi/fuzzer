"""Spider-based navigability acceptance test for PicTrail, the `django` app
(CC-LAB-0242 / FR-LAB-160, `docs/LAB_LANE2_DJANGO_PICTRAIL_PLAN.md` §4; the
acceptance criterion is `docs/LAB_BROWSABLE_APPS_PLAN.md`'s design-contract
point 6). Mirrors `tests/test_labgen_navigability_live_boot.py` (Lane 1's
`php_laravel` version) for the `django` stack.

Boots PicTrail's **whole** site with the real `DjangoLiveBootHarness` --
every `django` cell across every manifest (the 6 real pages, their 6 secure
twins at their twin-suffixed URLs, and the 6 illustrative Phase A/B cells),
plus the checked-in site layer (`/`, `/catalog`, `/upload`) -- then crawls it
from `/` with fuzzlab's own `fuzzlab.tools.spider.LocalSpider` (`requests`
engine: every page is server-rendered HTML), same-host scope, and asserts:

1. **non-vacuous guards first** (R5) -- PicTrail's ground-truth point list
   and the crawl's discovered-page set are each at least a hard-coded,
   measured minimum (never derived from the file being asserted against);
2. every ground-truth injection-point URL is discovered;
3. each one returns what a real anonymous visitor gets: 200 for every page
   (no session gating exists in the `django` emitter -- confirmed, plan §1),
   and the handled 400 for the one genuine `api`, `/upload/link-preview`,
   when requested bare (R4: no safe default URL exists; its client page is
   `/upload`);
4. `GET /` returns 200;
5. **PA-0053's bare-GET sweep** (R7) -- no crawled URL answers 5xx; and,
   beyond what links reach (PA-0054), a bare `GET` of **every** route the
   build serves (from the emitter's own `served_url_for`, not from the
   crawl) answers < 500.

Depth cap (R2/R7, measured, not guessed): on 2026-09-25 every ground-truth
URL was reached at link depth <= 2 from `/` (nav -> page; `/upload` or
`/catalog` -> `/upload/link-preview`), and the whole site at depth <= 2;
:data:`_MAX_DEPTH` is 4, and the test asserts the deepest ground-truth URL
stays strictly below the cap so a truncated crawl can never look complete.

Skip-guarded (PA-0005) on `django_boot_available()` and marked `slow`, like
every other live-boot module.
"""

from __future__ import annotations

import glob
import sqlite3
from urllib.parse import urlsplit

import pytest

from fuzzlab.labels.contract import load_injection_points
from fuzzlab.labgen.conformance.django_live_boot import DjangoLiveBootHarness, django_boot_available
from fuzzlab.labgen.emitters.django import _SITE_ROUTES, DjangoEmitter, served_url_for
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.tools.spider import LocalSpider

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not django_boot_available(),
        reason=(
            "django live-boot harness requires python3/venv on PATH and real PyPI "
            "network reachability (PA-0005) -- see django_live_boot.django_boot_available()"
        ),
    ),
]

_GROUND_TRUTH_DIR = "lab/ground-truth-picktrail-django"

#: R7: the crawl's depth cap. Measured deepest ground-truth URL is 2 (see the
#: module docstring); 4 leaves 2 levels of headroom.
_MAX_DEPTH = 4

#: R5: hard-coded, measured minimums (2026-09-25) -- never computed from the
#: file under test. Measured: 6 ground-truth points; 21 crawled URLs (19
#: without a query string, plus explore's `/post?id=1`/`?id=2` row links) --
#: the page floor leaves headroom for small nav/catalog changes but fails a
#: crawl that silently stopped early.
_MIN_GROUND_TRUTH_POINTS = 6
_MIN_DISCOVERED_PAGES = 16

#: ground-truth URL -> the final status a real anonymous visitor gets.
_EXPECTED_STATUS = {
    "/post": 200,  # bare -> the real page's default (post 1)
    "/post/comments": 200,
    # The one genuine `api` (stays JSON): requested bare it answers the
    # handled 400 before the sink (R4); its client page is `/upload`.
    "/upload/link-preview": 400,
    "/settings": 200,  # GET renders the settings form
    "/explore": 200,  # bare -> default sort=id
    "/inbox": 200,  # GET renders the inbox + compose form
}


def _django_cells():
    """Every django cell across every manifest, derived from the emitter's
    own `supports()` predicate (PA-0027) -- PicTrail's whole build."""
    emitter = DjangoEmitter()
    seen = {}
    for path in sorted(glob.glob("lab/manifests/*.yaml")):
        for cell in load_manifest(path).cells:
            if cell.stack_profile == "django" and emitter.supports(cell.vuln_class, cell.sink_context):
                seen.setdefault(cell.cell_id, cell)
    return list(seen.values())


@pytest.fixture(scope="module")
def crawl(tmp_path_factory):
    cells = _django_cells()
    harness = DjangoLiveBootHarness(DjangoEmitter(), cells)
    harness.build()
    try:
        db = tmp_path_factory.mktemp("crawl-picktrail") / "spider.db"
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


def test_crawl_from_root_discovers_every_ground_truth_url_with_anonymous_status(crawl) -> None:
    points = load_injection_points(_GROUND_TRUTH_DIR)
    pages = crawl["pages"]

    # --- R5: non-vacuous-pass guards (before any per-URL assertion) --------
    assert len(points) >= _MIN_GROUND_TRUTH_POINTS, len(points)
    assert len(crawl["rows"]) >= _MIN_DISCOVERED_PAGES, (len(crawl["rows"]), sorted(pages))

    # --- GET / ---------------------------------------------------------------
    assert pages.get("/", (None, None))[0] == 200, pages.get("/")
    assert crawl["harness"].get("/").status == 200

    # --- every ground-truth URL is discovered -------------------------------
    gt_urls = {p.url for p in points}
    # Every ground-truth URL is accounted for -- nothing silently skipped.
    assert gt_urls == set(_EXPECTED_STATUS), (sorted(gt_urls), sorted(_EXPECTED_STATUS))
    missing = sorted(u for u in gt_urls if u not in pages)
    assert not missing, (missing, sorted(pages))

    # --- R7: nothing sits at the depth cap ----------------------------------
    deepest = max(pages[u][1] for u in gt_urls)
    assert deepest < _MAX_DEPTH, deepest

    # --- anonymous-visitor status (no session gating in django, plan §1) ----
    wrong = {u: (pages[u][0], want) for u, want in _EXPECTED_STATUS.items() if pages[u][0] != want}
    assert not wrong, wrong


def test_every_catalog_page_is_link_reachable(crawl) -> None:
    """Every page the build serves that a GET can open (every GET cell, both
    POST pages' form views, their twins, and the site layer) is reachable by
    clicking through the site -- nav, home, `/upload` or `/catalog`."""
    pages = crawl["pages"]
    linkable = {served_url_for(c) for c in crawl["cells"]
                if c.route.method == "GET" or c.route.path in ("/settings", "/inbox")}
    linkable |= {"/" + url_path for url_path, _, _ in _SITE_ROUTES}
    missing = sorted(linkable - set(pages))
    assert not missing, (missing, sorted(pages))


def test_pa_0053_bare_get_sweep_no_route_answers_5xx(crawl) -> None:
    """R7 / PA-0053 (strengthened by PA-0054): (a) no URL the crawl reached
    -- with or without a query string -- answered 5xx (or failed outright,
    status 0); (b) independently of what links reach, a bare `GET` (no
    query, no body) of **every** route the build serves, enumerated from the
    emitter's own `served_url_for` plus the site layer, answers < 500."""
    crashed = sorted((url, status) for url, status, _ in crawl["rows"] if status == 0 or status >= 500)
    assert not crashed, crashed

    harness = crawl["harness"]
    every_route = sorted({served_url_for(c) for c in crawl["cells"]}
                         | {"/" + url_path for url_path, _, _ in _SITE_ROUTES})
    assert len(every_route) == len(crawl["cells"]) + len(_SITE_ROUTES)
    statuses = {}
    for url in every_route:
        try:
            statuses[url] = harness.get(url).status
        except Exception as exc:  # urllib raises on 4xx/5xx in some paths
            statuses[url] = getattr(exc, "code", None) or 0
    print("bare-GET sweep:", statuses)
    bad = {u: s for u, s in statuses.items() if not s or s >= 500}
    assert not bad, bad
