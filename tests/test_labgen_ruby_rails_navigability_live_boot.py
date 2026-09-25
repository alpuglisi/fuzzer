"""Spider-based navigability acceptance test for ForgeCart, the ``ruby_rails``
app (CC-LAB-0245 / FR-LAB-166, ``docs/LAB_LANE5_RUBY_RAILS_FORGECART_PLAN.md``
§4 "Live"; the acceptance criterion is ``docs/LAB_BROWSABLE_APPS_PLAN.md``
design-contract point 6). Mirrors the ``php_laravel``/``django`` lanes'
navigability tests, with this lane's PA-0054 strengthening (R7): the sweep of
every served route asserts each route's **declared** bare-request status, not
merely "< 500" -- this stack had a sink whose catch-all ``rescue`` turned an
absent input into a 200.

Boots ForgeCart's whole build with the real ``RailsLiveBootHarness`` (all 12
``ruby_rails`` cells: the illustrative ``LABGEN-RR-0001``, the 6 Phase B
sample cells, the 5 real pages -- plus the skeleton's site pages), crawls it
from ``/`` with fuzzlab's own ``LocalSpider`` (``requests`` engine, same
host), and asserts:

1. non-vacuous guards first (R13);
2. ``GET /`` is 200;
3. every ground-truth URL is discovered, at its anonymous-visitor status (200
   for all five -- no session gating exists in ``ruby_rails``, plan §1f), below
   the depth cap;
4. every GET route of the build is link-reachable;
5. the PA-0053/PA-0054 sweep: every route of the rendered ``config/routes.rb``
   (``served_routes``, not the crawl), bare, at its declared status;
6. BUG-0055's regression checks: no error page carries Rails debug content,
   no page carries a view annotation;
7. twin/determinism identity (R6/R1/R3);
8. the per-page functional checks, including 9d (the webhook console's
   malformed-JSON error branch, R2).

This file names Rails debug-page strings only to assert their absence; it is
on O7's pinned allowlist (``tests/test_labgen_ruby_rails_browsable.py``).

Skip-guarded on ``rails_boot_available()`` (PA-0005/PA-0035) and ``slow``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests

from fuzzlab.labels.contract import load_injection_points
from fuzzlab.labgen.conformance.rails_live_boot import SKELETON_DIR, RailsLiveBootHarness, rails_boot_available
from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter, app_cells, bare_request_status_for, url_path_for
from fuzzlab.labgen.emitters.ruby_rails.route_accumulator import served_routes
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext
from fuzzlab.tools.spider import LocalSpider

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not rails_boot_available(),
        reason=(
            "rails live-boot harness requires ruby + bundle on PATH and real RubyGems "
            "network reachability (PA-0005/PA-0035) -- see rails_live_boot.rails_boot_available()"
        ),
    ),
]

_GROUND_TRUTH_DIR = "lab/ground-truth-forgecart"

#: R13: crawl depth cap -- measured 2026-09-25: deepest ground-truth URL is at
#: depth 1 (every one is in the layout nav), deepest page overall at depth 2
#: (`/cell/labgen_rr_0001`, via `/catalog`); 4 leaves headroom.
_MAX_DEPTH = 4

#: R13: hard-coded, measured minimums (never computed from the file under test).
#: Measured 2026-09-25: 5 ground-truth points; 12 crawled URLs (11 pages at
#: depth <= 1 plus `/cell/labgen_rr_0001` at depth 2 via `/catalog`). The page
#: floor leaves headroom for small nav changes but fails a crawl that stopped.
_MIN_GROUND_TRUTH_POINTS = 5
_MIN_DISCOVERED_PAGES = 10

#: Ground-truth URL -> the status a real anonymous visitor gets on GET.
_EXPECTED_STATUS = {
    "/search": 200,  # bare -> the declared default q=""
    "/webhooks/orders/create": 200,  # api: its GET fetch() client page
    "/webhooks/customers/update": 200,  # api: its GET fetch() client page
    "/admin/customers/update": 200,  # page: its GET form
    "/admin/products/import": 200,  # page: its GET form
}

#: BUG-0055 regression: strings only a Rails debug page (or generated source)
#: contains. Asserted ABSENT from every error response.
_DEBUG_MARKERS = ("Extracted source", "Routing Error", "Full Trace", "Application Trace",
                  "Module composition", "permit", "YAML.", "labgen")

_WEBHOOK_SECRET = "whsec_lab_lab_only_not_a_real_secret"


def _illustrative_cell(cell_id: str) -> Cell:
    return Cell(
        cell_id=cell_id,
        vuln_class="xss",
        stack_profile="ruby_rails",
        route=Route(method="GET", path=url_path_for(cell_id)),
        sink_context=SinkContext(family="html_body"),
        transform=Pipeline(),
    )


def _forgecart_cells() -> list[Cell]:
    """The whole ForgeCart build: every real `ruby_rails` cell (`app_cells()`,
    CC-LAB-0247 -- the same single source of truth `assemble_ruby_rails_app`
    uses, PA-0027), plus the test-only illustrative cell."""
    seen: dict[str, Cell] = {"LABGEN-RR-0001": _illustrative_cell("LABGEN-RR-0001")}
    for cell in app_cells():
        seen.setdefault(cell.cell_id, cell)
    return list(seen.values())


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    cells = _forgecart_cells()
    harness = RailsLiveBootHarness(RailsEmitter(), cells)
    harness.build()
    try:
        base = harness._base_url()
        session = requests.Session()
        session.trust_env = False  # loopback lab target: never via an ambient proxy
        db = tmp_path_factory.mktemp("crawl-forgecart") / "spider.db"
        spider = LocalSpider(base + "/", max_depth=_MAX_DEPTH, db_name=str(db), engine="requests")
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
        print(f"crawl: {len(rows)} URLs, {len(pages)} without a query; max depth {max(d for _, _, d in rows)}")
        for url, status, depth in sorted(rows, key=lambda r: (r[2], r[0])):
            print(f"  [{status}] depth {depth}: {url}")
        routes_rb = (harness._app_dir / "config" / "routes.rb").read_text(encoding="utf-8")
        yield {
            "harness": harness, "base": base, "session": session, "cells": cells,
            "rows": rows, "pages": pages, "routes": served_routes(routes_rb),
        }
    finally:
        harness.close()


def _req(site, method: str, path: str, **kwargs) -> requests.Response:
    return site["session"].request(method, site["base"] + path, allow_redirects=False, timeout=15, **kwargs)


def test_crawl_from_root_discovers_every_ground_truth_url_with_anonymous_status(site) -> None:
    points = load_injection_points(_GROUND_TRUTH_DIR)
    pages = site["pages"]

    # --- R13: non-vacuous-pass guards, before any per-URL assertion --------
    assert len(points) >= _MIN_GROUND_TRUTH_POINTS, len(points)
    assert len(site["rows"]) >= _MIN_DISCOVERED_PAGES, (len(site["rows"]), sorted(pages))

    # --- GET / ---------------------------------------------------------------
    assert pages.get("/", (None, None))[0] == 200, pages.get("/")
    assert _req(site, "GET", "/").status_code == 200

    # --- every ground-truth URL discovered, nothing silently skipped -------
    gt_urls = {p.url for p in points}
    assert gt_urls == set(_EXPECTED_STATUS), (sorted(gt_urls), sorted(_EXPECTED_STATUS))
    missing = sorted(u for u in gt_urls if u not in pages)
    assert not missing, (missing, sorted(pages))
    deepest = max(pages[u][1] for u in gt_urls)
    assert deepest < _MAX_DEPTH, deepest

    # --- anonymous-visitor status (no session gating in ruby_rails) --------
    wrong = {u: (pages[u][0], want) for u, want in _EXPECTED_STATUS.items() if pages[u][0] != want}
    assert not wrong, wrong


def test_every_get_route_of_the_build_is_link_reachable(site) -> None:
    get_paths = {path for verb, path, _ in site["routes"] if verb == "GET" and path != "/up"}
    assert len(get_paths) >= 12
    missing = sorted(get_paths - set(site["pages"]))
    assert not missing, (missing, sorted(site["pages"]))


def test_pa_0054_sweep_every_served_route_answers_its_declared_bare_status(site) -> None:
    """R7 / PA-0053 / PA-0054: (a) no crawled URL answered 5xx or failed;
    (b) for every route of the rendered routes.rb -- enumerated from the file
    Rails loads, not from the crawl -- a bare GET of the path and a bare
    request with the route's own verb each return exactly the declared
    status (never only "< 500")."""
    crashed = sorted((url, status) for url, status, _ in site["rows"] if not status or status >= 500)
    assert not crashed, crashed

    routes = site["routes"]
    assert len(routes) >= 20
    get_paths = {path for verb, path, _ in routes if verb == "GET"}
    cell_by_path = {url_path_for(c.cell_id): c for c in site["cells"]}
    expected: dict[tuple[str, str], int] = {}
    for verb, path, _ in routes:
        expected[("GET", path)] = 200 if path in get_paths else 404  # R8: POST-only illustrative -> 404
        if verb != "GET":
            expected[(verb, path)] = bare_request_status_for(cell_by_path[path])
    observed = {}
    for (verb, path), _ in sorted(expected.items()):
        observed[(verb, path)] = _req(site, verb, path).status_code
    print("bare-request sweep:", observed)
    wrong = {k: (observed[k], v) for k, v in expected.items() if observed[k] != v}
    assert not wrong, wrong
    # The declared statuses actually exercised (non-vacuous): 200, 400, 401, 404.
    assert set(expected.values()) == {200, 400, 401, 404}


def test_bug_0055_no_debug_page_content_and_no_view_annotations(site) -> None:
    routes = site["routes"]
    probes = [("GET", path) for _, path in {(v, p) for v, p, _ in routes}]
    probes += [(verb, path) for verb, path, _ in routes if verb != "GET"]
    probes += [("GET", "/no-such-page"), ("POST", "/search")]
    seen_error_statuses = set()
    for verb, path in sorted(set(probes)):
        resp = _req(site, verb, path)
        body = resp.text
        if resp.status_code >= 400:
            seen_error_statuses.add(resp.status_code)
            leaked = [m for m in _DEBUG_MARKERS if m in body]
            assert not leaked, (verb, path, resp.status_code, leaked)
        else:
            assert "BEGIN app/views" not in body, (verb, path)
            if path != "/catalog":  # the catalog lists /cell/labgen_* routes by design
                assert "labgen" not in body, (verb, path)
    # Non-vacuous: the error pages this lane declares were actually probed.
    assert {400, 401, 404} <= seen_error_statuses, seen_error_statuses
    # The static error pages, byte-for-byte (not a debug page).
    assert _req(site, "GET", "/no-such-page").text == (SKELETON_DIR / "public" / "404.html").read_text(encoding="utf-8")
    assert _req(site, "POST", "/admin/customers/update").text == (
        SKELETON_DIR / "public" / "400.html"
    ).read_text(encoding="utf-8")


def test_twin_and_determinism_identity(site) -> None:
    orders = _req(site, "GET", "/webhooks/orders/create")
    customers = _req(site, "GET", "/webhooks/customers/update")
    assert orders.status_code == customers.status_code == 200
    assert orders.content == customers.content  # R6: the twins' client pages cannot be told apart
    assert _WEBHOOK_SECRET not in orders.text
    first, second = _req(site, "GET", "/"), _req(site, "GET", "/")
    assert first.content == second.content  # R1/R3: no per-request token in the layout
    assert "csrf-token" not in first.text


def test_pages_render_in_the_layout_and_keep_their_vulnerability(site) -> None:
    # /search: raw reflection inside the layout (the modelled XSS).
    search = _req(site, "GET", "/search", params={"q": "<b>forgecart-probe</b>"})
    assert search.status_code == 200
    assert '<div class="cell-output"><b>forgecart-probe</b></div>' in search.text
    assert "<nav>" in search.text and "<title>Search results - ForgeCart</title>" in search.text
    # Every GET page is in the layout.
    for verb, path, _ in site["routes"]:
        if verb == "GET" and path != "/up":
            body = _req(site, "GET", path).text
            assert "<nav>" in body and "ForgeCart" in body, path
    # The catalog links the illustrative GET cell and lists the others unlinked.
    catalog = _req(site, "GET", "/catalog").text
    assert '<a href="/cell/labgen_rr_0001">' in catalog
    assert "<code>POST /cell/labgen_rr_0002</code>" in catalog
    assert '<a href="/cell/labgen_rr_0002">' not in catalog
    # GET forms post to themselves, tokenless (R3).
    form = _req(site, "GET", "/admin/customers/update").text
    assert '<form method="post" action="/admin/customers/update">' in form
    assert 'name="user[bio]"' in form and 'name="user[username]"' not in form and "authenticity_token" not in form
    assert '<form method="post" action="/admin/products/import">' in _req(site, "GET", "/admin/products/import").text


def test_post_pages_render_escaped_results_with_the_verdict_observable(site) -> None:
    # Mass assignment: the unlisted `role` field lands (the modelled weakness),
    # rendered escaped -- no XSS introduced by the conversion (R5).
    mass = _req(site, "POST", "/admin/customers/update", data={"user[bio]": "<b>note</b>", "user[role]": "admin"})
    assert mass.status_code == 200, mass.text
    assert '<td id="customer-role">admin</td>' in mass.text
    assert "&lt;b&gt;note&lt;/b&gt;" in mass.text and "<b>note</b>" not in mass.text
    # Insecure deserialization: the object tag is honoured, the result escaped.
    yaml_payload = "--- !ruby/object:OpenStruct\ntable:\n  imported: true\n"
    deser = _req(site, "POST", "/admin/products/import", data={"yaml_payload": yaml_payload})
    assert deser.status_code == 200, deser.text
    assert '<code id="parsed-class">OpenStruct</code>' in deser.text
    # An empty form submit is the declared handled 400 (require rejects blank).
    assert _req(site, "POST", "/admin/products/import", data={"yaml_payload": ""}).status_code == 400


def test_webhook_api_contract_and_console_error_branch(site) -> None:
    body = b'{"order_id": 1}'
    sig = base64.b64encode(hmac.new(_WEBHOOK_SECRET.encode(), body, hashlib.sha256).digest()).decode()
    for path in ("/webhooks/orders/create", "/webhooks/customers/update"):
        ok = _req(site, "POST", path, data=body, headers={"Content-Type": "application/json", "X-Shopify-Hmac-SHA256": sig})
        assert ok.status_code == 200 and ok.json() == {"verified": True}, ok.text
    # 9d (plan R2): a malformed JSON body sent with exactly the console
    # script's headers (no Accept override, so Accept: */*). The source-derived
    # prediction for a body Rails rejects is 400 + the static HTML 400 page; R2's
    # decision rule records and asserts the *measured* result exactly instead
    # if the action is reached (see EXPECTED_9D).
    for path in ("/webhooks/orders/create", "/webhooks/customers/update"):
        resp = _req(site, "POST", path, data=b'{"order_id": ', headers={
            "Content-Type": "application/json", "X-Shopify-Hmac-SHA256": "not-a-signature", "Accept": "*/*",
        })
        print("9d", path, resp.status_code, resp.headers.get("Content-Type"), resp.text[:80])
        assert (resp.status_code, resp.headers.get("Content-Type", "").split(";")[0]) == EXPECTED_9D, (
            resp.status_code, resp.headers.get("Content-Type"), resp.text[:200])
        if EXPECTED_9D[0] == 400:
            assert resp.text == (SKELETON_DIR / "public" / "400.html").read_text(encoding="utf-8")
        else:
            assert resp.json() == {"verified": False}
        assert "Extracted source" not in resp.text


#: 9d's asserted outcome (plan R2 decision rule). The source-derived
#: prediction was 400 + the static HTML 400 page *if Rails rejects the body*;
#: R2 flagged that whether anything parses it at all cannot be settled from
#: source. Measured live 2026-09-25: nothing does -- the webhook action reads
#: `request.body.read`, never `params`, instrumentation rescues the parse error,
#: and forgery protection is skipped -- so the request reaches the action and
#: fails signature verification over the raw bytes: 401 `{"verified":false}`
#: (JSON). Per R2's rule the measured result is asserted exactly (never "HTML
#: or JSON"); the console's guarded JSON.parse handles it (O5b).
EXPECTED_9D = (401, "application/json")
