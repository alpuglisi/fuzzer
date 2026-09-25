"""Spider-based navigability acceptance test for MeadowMart, the
`node_express` app (CC-LAB-0246 / FR-LAB-168, `docs/LAB_LANE6_NODE_FASTAPI_PLAN.md`
§4A; the acceptance criterion is `docs/LAB_BROWSABLE_APPS_PLAN.md`'s
design-contract point 6). Mirrors Lane 2's
`tests/test_labgen_django_navigability_live_boot.py`.

Boots MeadowMart's whole build for real (`npm install` + `node app.js`; the
build is exactly `MEADOWMART_MANIFESTS` -- the generic Tier-A `LABGEN-NE-*`
sample is not part of it, so its F1/F2 findings cannot affect this test),
crawls it from `/` with fuzzlab's own `LocalSpider` (`requests` engine,
same-host scope, proxy-free), and asserts:

1. **non-vacuous guards first** (R8) -- hard-coded, measured minimums for
   the ground-truth point count and the crawled-URL count;
2. every ground-truth path is discovered, below the depth cap, and answers
   an anonymous visitor 200 at the URL a visitor clicks (`/catalog` links
   the preferences URLs, which answer GET with the resource read -- R3
   branch (a) -- and the search URLs with an example query); no session
   gating exists in `node_express`;
3. `GET /` is 200 HTML naming MeadowMart, and every nav link answers 200;
4. PA-0053: no crawled URL answered 5xx (or failed outright);
5. PA-0054 (2): independently of the crawl, a bare request to **every**
   route the build serves (cells via `served_url_for`, the site layer via
   `SITE_ROUTES`, the inert APIs via `INERT_ROUTES`) answers < 500, with the
   declared statuses asserted exactly;
6. R2: the site layer is not a prototype-pollution gadget -- page bytes are
   identical before and after a polluting POST to the vulnerable twin, in a
   separate boot so the pollution cannot leak into other tests.

Depth cap (measured, not guessed): every ground-truth URL is reached at
depth 2 (`/` -> `/catalog` -> endpoint); :data:`_MAX_DEPTH` is 4 and the
test asserts the deepest ground-truth URL stays strictly below it.

Skip-guarded (PA-0005/PA-0035) on node/npm and a real npm-registry probe,
and marked `slow`, like every other navigability module.
"""

from __future__ import annotations

import sqlite3
from urllib.parse import urlsplit

import pytest
import requests

from fuzzlab.labels.contract import load_injection_points
from fuzzlab.labgen.emitters.node_express import INERT_ROUTES, SITE_ROUTES, served_url_for
from fuzzlab.tools.spider import LocalSpider

from ._meadowmart_app import assemble, boot, install, meadowmart_cells

pytestmark = [pytest.mark.slow]

_GROUND_TRUTH_DIR = "lab/ground-truth-meadowmart"
_MAX_DEPTH = 4

#: R8: hard-coded, measured minimums (2026-09-25) -- never derived from the
#: files under test. Measured: 4 ground-truth points; 14 crawled URLs (`/`,
#: 6 more site pages at depth 1, 7 catalog links at depth 2); the floor
#: leaves headroom for small nav changes but fails a crawl that stopped early.
_MIN_GROUND_TRUTH_POINTS = 4
_MIN_CRAWLED_URLS = 12

#: ground-truth path -> the status an anonymous visitor gets at the URL they click.
_EXPECTED_STATUS = {
    "/api/preferences": 200,  # GET resource read (R3 branch (a))
    "/api/preferences-twin-labgen-pp-0002": 200,
    "/api/search": 200,  # via /catalog's example query ?q=shoes
    "/api/search-twin-labgen-rd-0002": 200,
}

#: Bare-request sweep: declared statuses asserted exactly (PA-0054 (2)).
_BARE_GET_STATUS = {
    "/api/search": 400,  # required_param, before the RegExp is built (D3)
    "/api/search-twin-labgen-rd-0002": 400,
    "/api/preferences": 200,  # GET resource read
    "/api/preferences-twin-labgen-pp-0002": 200,
    "/api/orders/": 404,  # R10: no route without an order id
}
_BARE_POST_STATUS = {
    "/api/preferences": 400,  # empty_body_400
    "/api/preferences-twin-labgen-pp-0002": 400,
}


def _session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False  # loopback lab target: never via an ambient proxy
    return s


@pytest.fixture(scope="module")
def app_root(tmp_path_factory):
    root = assemble(tmp_path_factory.mktemp("meadowmart_nav"))
    install(root, tmp_path_factory.mktemp("npm_probe_nav"))
    return root


@pytest.fixture(scope="module")
def crawl(app_root, tmp_path_factory):
    with boot(app_root) as base:
        db = tmp_path_factory.mktemp("crawl-meadowmart") / "spider.db"
        spider = LocalSpider(base + "/", max_depth=_MAX_DEPTH, db_name=str(db), engine="requests")
        spider.session.trust_env = False
        spider.crawl()
        conn = sqlite3.connect(db)
        try:
            rows = conn.execute("SELECT url, status_code, depth FROM discovered_pages").fetchall()
        finally:
            conn.close()
        by_path: dict[str, list[tuple[int, int, str]]] = {}
        for url, status, depth in rows:
            by_path.setdefault(urlsplit(url).path or "/", []).append((status, depth, url))
        print(f"crawl: {len(rows)} URLs, max depth {max(d for _, _, d in rows)}")
        for url, status, depth in sorted(rows, key=lambda r: (r[2], r[0])):
            print(f"  [{status}] depth {depth}: {url}")
        yield {"base": base, "rows": rows, "by_path": by_path}


def test_crawl_from_root_discovers_every_ground_truth_url_with_anonymous_status(crawl) -> None:
    points = load_injection_points(_GROUND_TRUTH_DIR)
    rows, by_path = crawl["rows"], crawl["by_path"]

    # --- R8: non-vacuous guards (before any per-URL assertion) --------------
    assert len(points) >= _MIN_GROUND_TRUTH_POINTS, len(points)
    assert len(rows) >= _MIN_CRAWLED_URLS, (len(rows), sorted(by_path))

    # --- every ground-truth URL accounted for and discovered ---------------
    gt_paths = {p.url for p in points}
    assert gt_paths == set(_EXPECTED_STATUS), sorted(gt_paths)
    missing = sorted(p for p in gt_paths if p not in by_path)
    assert not missing, (missing, sorted(by_path))

    # --- depth cap -------------------------------------------------------------
    deepest = max(min(d for _, d, _ in by_path[p]) for p in gt_paths)
    assert deepest < _MAX_DEPTH, deepest

    # --- anonymous-visitor status at the clicked URL ----------------------------
    wrong = {p: by_path[p] for p, want in _EXPECTED_STATUS.items() if not any(s == want for s, _, _ in by_path[p])}
    assert not wrong, wrong


def test_homepage_and_every_nav_link_answer_200(crawl) -> None:
    s = _session()
    home = s.get(crawl["base"] + "/", timeout=10)
    assert home.status_code == 200 and "text/html" in home.headers["Content-Type"]
    assert "MeadowMart" in home.text
    for path in SITE_ROUTES:
        assert f'href="{path}"' in home.text, path
        r = s.get(crawl["base"] + path, timeout=10)
        assert r.status_code == 200 and "<header>" in r.text, (path, r.status_code)
    # Every site page is link-reachable in the crawl too.
    assert not sorted(set(SITE_ROUTES) - set(crawl["by_path"]))


def test_pa_0053_no_crawled_url_answers_5xx(crawl) -> None:
    crashed = sorted((u, s) for u, s, _ in crawl["rows"] if s == 0 or s >= 500)
    assert not crashed, crashed


def test_pa_0054_bare_request_sweep_of_every_served_route(crawl) -> None:
    cells = meadowmart_cells()
    every_get = sorted(
        {served_url_for(c) for c in cells}
        | set(SITE_ROUTES)
        | {example for _, example in INERT_ROUTES}
        | {"/api/orders/"}
    )
    assert len(every_get) == len(cells) + len(SITE_ROUTES) + len(INERT_ROUTES) + 1
    s = _session()
    statuses = {url: s.get(crawl["base"] + url, timeout=10).status_code for url in every_get}
    print("bare-GET sweep:", statuses)
    assert not {u: st for u, st in statuses.items() if st >= 500}
    for url, want in _BARE_GET_STATUS.items():
        assert statuses[url] == want, (url, statuses[url], want)
    for url in every_get:
        if url not in _BARE_GET_STATUS:
            assert statuses[url] == 200, (url, statuses[url])

    post_urls = sorted(served_url_for(c) for c in cells if c.route.method == "POST")
    assert set(post_urls) == set(_BARE_POST_STATUS)
    for url in post_urls:
        r = s.post(crawl["base"] + url, timeout=10)
        assert r.status_code == _BARE_POST_STATUS[url], (url, r.status_code)


def test_r2_site_layer_is_not_a_prototype_pollution_gadget(app_root) -> None:
    """R2, in its own boot: a polluting POST to the vulnerable twin leaves
    every site page byte-identical."""
    with boot(app_root) as base:
        s = _session()
        before = {p: s.get(base + p, timeout=10).content for p in SITE_ROUTES}
        polluting = '{"__proto__": {"mmProbe": "x", "href": "javascript:x", "path": "/x", "method": "X"}}'
        r = s.post(base + "/api/preferences", data=polluting, headers={"Content-Type": "application/json"}, timeout=10)
        assert r.status_code == 200
        # Non-vacuity: prove Object.prototype really is polluted now. Both
        # twins' merges iterate `for (const key in source)`, which also walks
        # inherited enumerable keys, so the polluted key surfaces in the next
        # ordinary merge's response.
        probe = s.post(base + "/api/preferences-twin-labgen-pp-0002", json={"theme": "dark"}, timeout=10)
        assert probe.status_code == 200 and probe.json()["preferences"].get("mmProbe") == "x", probe.text
        after = {p: s.get(base + p, timeout=10) for p in SITE_ROUTES}
        assert all(a.status_code == 200 for a in after.values())
        changed = sorted(p for p in SITE_ROUTES if after[p].content != before[p])
        assert not changed, changed
