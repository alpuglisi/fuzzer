"""Spider-based navigability acceptance test (CC-LAB-0241 / FR-LAB-159,
`docs/LAB_LANE1_REMAINING_GAPS_PLAN.md` §2c; the acceptance criterion is
`docs/LAB_BROWSABLE_APPS_PLAN.md`'s design-contract point 6).

For each Lane 1 app -- Puppy Fort Factory (the default merged build), and the
`--app` split CircleFeed, Huddle Hub and Booking clone builds -- this boots
the **whole** site with the real `LiveBootHarness` (every cell the app's own
build carries, plus its own site layer: `app=` overlays the split app's
branded layout/home/`routes/site.php`, R6), then crawls it from `/` with
fuzzlab's own `fuzzlab.tools.spider.LocalSpider` (`requests` engine: every
converted page is server-rendered HTML), same-host scope, and asserts:

1. **non-vacuous guards first** -- the app's ground-truth point list and the
   crawl's discovered-page set are each at least a hard-coded, measured
   minimum (never derived from the file being asserted against), so an empty
   ground-truth load or a crawl that silently failed to start cannot satisfy
   the per-URL loop vacuously (the `mariadb.py:431` bug class CC-LAB-0240's
   R2 found);
2. every ground-truth injection-point URL the build serves is discovered;
3. each one returns what a real anonymous visitor gets (the final status
   after following redirects, as a browser would): 200 for a public page or
   an API's GET client page; the R8 sign-off's 401 for a split app's
   session-gated cell (`docs/LAB_BROWSABLE_APPS_PLAN.md` point 6);
4. `GET /` returns 200.

Depth cap (R7, measured, not guessed): on 2026-09-25 every ground-truth URL
of every app was reached at link depth <= 2 from `/` (nav/home -> `/catalog`
-> the cell); :data:`_MAX_DEPTH` is 4, and the test asserts the deepest
ground-truth URL stays strictly below the cap so a truncated crawl can never
look complete.

Two documented, strict-xfail gaps this crawl surfaced that are **not** fixed
here (different class, flagged as follow-ups -- plan §3 step 3's scope-creep
rule): PFF's ground truth lists 4 URLs no `php_laravel` cell serves at all
(`/track.php`, `/add_to_cart.php`, `/cart.php`, `/checkout.php`), and Huddle
Hub's `/messages/unfurl` vulnerable twin 500s on a bare GET (no missing-
parameter guard). Each is its own `xfail(strict=True)` test, so fixing it
turns the suite red until the exception is removed -- never silently waved
through.

R4 sign-off (PFF's `LABGEN-MA-0003`/`0004`): branch (b), recorded in
`docs/components/01-target-lab/requirements.md`'s FR-LAB-159 -- see
:func:`test_pff_mass_assignment_cells_anonymous_response_r4`.

Skip-guarded (PA-0005) on `live_boot_available()` and marked `slow`, like
every other live-boot module.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from urllib.parse import urlsplit

import pytest

from fuzzlab.labels.contract import load_injection_points
from fuzzlab.labgen.assemble import collect_cells
from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.emitters.php_laravel.app_site import APP_REGISTRY
from fuzzlab.tools.spider import LocalSpider

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not live_boot_available(),
        reason=(
            "live-boot harness requires composer + php on PATH and real Packagist "
            "network reachability (PA-0005) -- see live_boot.live_boot_available()"
        ),
    ),
]

#: R7: the crawl's depth cap. Measured deepest ground-truth URL is 2 in every
#: app (see the module docstring); 4 leaves 2 levels of headroom.
_MAX_DEPTH = 4


@dataclass(frozen=True)
class _AppSpec:
    app: str | None  # `app_site.APP_REGISTRY` key; None = the default merged PFF build
    ground_truth_dir: str
    #: Hard-coded, measured minimums (2026-09-25) -- never computed from the
    #: file under test (non-vacuous-pass guard, plan §2c step 3).
    min_ground_truth_points: int
    min_discovered_pages: int
    #: ground-truth URL -> the final status a real anonymous visitor gets.
    expected_status: dict[str, int]
    #: ground-truth URLs no cell of this build serves (strict-xfail follow-up).
    unserved: frozenset[str] = frozenset()


_SPECS: dict[str, _AppSpec] = {
    "pff": _AppSpec(
        app=None,
        ground_truth_dir="lab/ground-truth",
        min_ground_truth_points=24,
        min_discovered_pages=40,
        expected_status={
            # Public pages (GET form pages for the POST endpoints) -- 200.
            "/product.php": 200,
            "/products.php": 200,
            "/search.php": 200,
            "/blog_post.php": 200,
            "/login.php": 200,
            "/register.php": 200,
            "/contact.php": 200,
            "/newsletter.php": 200,
            "/edit_profile.php": 200,
            "/reviews.php": 200,
            "/feedback.php": 200,
            # Genuine JSON API (stays JSON), public -- 200.
            "/api/products.php": 200,
        },
        unserved=frozenset({"/track.php", "/add_to_cart.php", "/cart.php", "/checkout.php"}),
    ),
    "circlefeed": _AppSpec(
        app="circlefeed",
        ground_truth_dir="lab/ground-truth-circlefeed",
        min_ground_truth_points=4,
        min_discovered_pages=8,
        expected_status={
            # R8 sign-off: session-gated photo page, no login in a split app.
            "/photos/view": 401,
            # POST-only webhook api: its GET client page (CC-LAB-0239).
            "/groups/webhook": 200,
            # Share redirect, bare: defaults to `/` (CC-LAB-0241) -> home.
            "/comments/share": 200,
            # Genuine deserialization api (stays JSON) reached with no `pref`
            # cookie: both twins return their handled 400 JSON error -- the
            # response any client gets calling this API without its input.
            # (No shared default exists: the twins decode different formats.)
            "/settings/preferences": 400,
        },
    ),
    "huddlehub": _AppSpec(
        app="huddlehub",
        ground_truth_dir="lab/ground-truth-huddlehub",
        min_ground_truth_points=3,
        min_discovered_pages=6,
        expected_status={
            "/webhooks/events": 200,  # POST-only webhook api's GET client page
            "/integrations/outgoing-webhook": 200,
            # `/messages/unfurl`: strict-xfail follow-up, see
            # test_huddlehub_unfurl_bare_get_is_a_handled_error_not_a_crash.
        },
    ),
    "booking": _AppSpec(
        app="booking",
        ground_truth_dir="lab/ground-truth-booking-clone",
        min_ground_truth_points=3,
        min_discovered_pages=6,
        expected_status={
            # Bare continue link: defaults to `/` (CC-LAB-0241) -> home.
            "/booking/continue": 200,
            "/extranet/export": 200,
            "/booking/checkout": 200,  # POST-only page's GET form (CC-LAB-0239)
        },
    ),
}

#: Ground-truth URLs whose anonymous status is deliberately not asserted in
#: the main test because a strict-xfail test below tracks a known gap.
_XFAIL_STATUS = {"huddlehub": frozenset({"/messages/unfurl"})}


@dataclass
class _Crawl:
    harness: LiveBootHarness
    #: path (no query) -> (final status, link depth) for every crawled URL
    #: whose own URL carried no query string.
    pages: dict[str, tuple[int, int]]
    total_rows: int


def _boot_and_crawl(key: str, tmp_path_factory) -> _Crawl:
    spec = _SPECS[key]
    prefix = APP_REGISTRY[spec.app]["prefix"] if spec.app is not None else None
    cells = collect_cells(cell_id_prefix=prefix)
    harness = LiveBootHarness(LaravelEmitter(), cells, app=spec.app)
    harness.build()
    try:
        db = tmp_path_factory.mktemp(f"crawl-{key}") / "spider.db"
        spider = LocalSpider(harness._base_url() + "/", max_depth=_MAX_DEPTH, db_name=str(db), engine="requests")
        # Loopback lab target: never route through an ambient HTTP proxy.
        spider.session.trust_env = False
        spider.crawl()
        conn = sqlite3.connect(db)
        try:
            rows = conn.execute("SELECT url, status_code, depth FROM discovered_pages").fetchall()
        finally:
            conn.close()
    except BaseException:
        harness.close()
        raise
    pages = {}
    for url, status, depth in rows:
        parts = urlsplit(url)
        if not parts.query:
            pages[parts.path or "/"] = (status, depth)
    return _Crawl(harness=harness, pages=pages, total_rows=len(rows))


@pytest.fixture(scope="module")
def crawls(tmp_path_factory):
    booted: dict[str, _Crawl] = {}

    def get(key: str) -> _Crawl:
        if key not in booted:
            booted[key] = _boot_and_crawl(key, tmp_path_factory)
        return booted[key]

    yield get
    for crawl in booted.values():
        crawl.harness.close()


@pytest.mark.parametrize("key", sorted(_SPECS))
def test_crawl_from_root_discovers_every_ground_truth_url_with_anonymous_status(key, crawls) -> None:
    spec = _SPECS[key]
    points = load_injection_points(spec.ground_truth_dir)
    crawl = crawls(key)

    # --- non-vacuous-pass guards (before any per-URL assertion) -------------
    assert len(points) >= spec.min_ground_truth_points, (key, len(points))
    assert crawl.total_rows >= spec.min_discovered_pages, (key, crawl.total_rows, crawl.pages)

    # --- GET / -------------------------------------------------------------
    assert crawl.pages.get("/", (None, None))[0] == 200, (key, crawl.pages.get("/"))
    assert crawl.harness.get("/").status == 200

    # --- every served ground-truth URL is discovered -------------------------
    gt_urls = {p.url for p in points}
    served = gt_urls - spec.unserved
    # Every ground-truth URL is accounted for: served-with-expectation,
    # tracked by a strict xfail, or listed unserved -- nothing silently skipped.
    assert served == set(spec.expected_status) | _XFAIL_STATUS.get(key, frozenset()), (
        key, sorted(served), sorted(spec.expected_status),
    )
    missing = sorted(u for u in served if u not in crawl.pages)
    assert not missing, (key, missing, sorted(crawl.pages))

    # --- R7: nothing sits at the depth cap -----------------------------------
    deepest = max(crawl.pages[u][1] for u in served)
    assert deepest < _MAX_DEPTH, (key, deepest)

    # --- anonymous-visitor status ------------------------------------------
    wrong = {
        u: (crawl.pages[u][0], want)
        for u, want in spec.expected_status.items()
        if crawl.pages[u][0] != want
    }
    assert not wrong, (key, wrong)


def test_pff_mass_assignment_cells_anonymous_response_r4(crawls) -> None:
    """R4 sign-off, branch (b) (FR-LAB-159): `LABGEN-MA-0003`/`0004` are
    crawled anonymously. They are not in PFF's `injection-points.json`, and
    they turned out not to be session-gated at all: the sink
    (`orm_entity_bulk_assign.php.j2`) deliberately degrades a missing session
    to `WHERE id = NULL` (`$request->user()?->id`), so there is no 401/
    redirect for an authenticated crawl to get past. What an anonymous
    visitor actually gets is asserted exactly: the public GET client page at
    the canonical URL (crawl-discovered, 200), and on a direct anonymous
    POST to either twin a 200 JSON body that updated nothing."""
    crawl = crawls("pff")
    cells = {c.cell_id: c for c in collect_cells(cell_id_prefix="LABGEN-MA-")}
    canonical = served_url_for(cells["LABGEN-MA-0003"])
    twin = served_url_for(cells["LABGEN-MA-0004"])
    assert canonical == "/example/account_settings"

    assert crawl.pages.get(canonical, (None,))[0] == 200, crawl.pages.get(canonical)
    page = crawl.harness.get(canonical)
    assert page.status == 200 and "<h2>Account settings</h2>" in page.body, page.body[:500]
    # The twin's URL is POST-only; a GET-only crawl cannot (and should not)
    # reach it.
    assert twin not in crawl.pages, twin

    for url in (canonical, twin):
        resp = crawl.harness.post(url, data={"bio": "anon-r4"})
        assert resp.status == 200, (url, resp.status, resp.body[:500])
        assert "updated_fields" in json.loads(resp.body), (url, resp.body[:500])
    # ...and nothing was written: no row matches `WHERE id = NULL`.
    assert not crawl.harness.query_db("SELECT id FROM users WHERE bio = 'anon-r4'")


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Follow-up flagged by CC-LAB-0241 (different class: missing pages, not a "
        "missing link/default/@extends): lab/ground-truth/injection-points.json "
        "lists /track.php, /add_to_cart.php, /cart.php and /checkout.php, which "
        "no php_laravel cell or site route serves (the Blade product views even "
        "post an add-to-cart form to /add_to_cart.php)."
    ),
)
def test_pff_unserved_ground_truth_urls_are_discovered(crawls) -> None:
    crawl = crawls("pff")
    missing = sorted(u for u in _SPECS["pff"].unserved if crawl.pages.get(u, (None,))[0] != 200)
    assert not missing, missing


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Follow-up flagged by CC-LAB-0241 (different class: needs a new "
        "missing-required-parameter guard, not a default -- any default URL "
        "would make the vulnerable twin fetch it): a bare GET /messages/unfurl "
        "makes the vulnerable twin call file_get_contents(null) and 500, where "
        "its secure twin answers a handled 400."
    ),
)
def test_huddlehub_unfurl_bare_get_is_a_handled_error_not_a_crash(crawls) -> None:
    crawl = crawls("huddlehub")
    assert crawl.pages.get("/messages/unfurl", (None,))[0] == 400
