"""Live-boot conformance check for `php_laravel` (T-LAB0.7 Tier 1/2 --
`docs/LAB_IMPLEMENTATION_PLAN.md` ~line 154, `CC-LAB-0054`/`FR-LAB-52`).

Unlike every other `tests/test_labgen_*` module, this one is a **real,
on-host integration test**: it assembles a real Laravel 13 project from the
checked-in skeleton plus a real manifest's real `LaravelEmitter` output, runs
a real `composer install --no-dev` against Packagist, seeds a real SQLite
database, boots a real `php artisan serve` process, and makes real HTTP
requests against it -- entirely within this test run, with its own temp
directory, port, and process torn down on every exit path (`finally`/context
manager), never left running or leaked (per this task's own requirement and
this project's PA-0012 "bounded, deterministic teardown" convention, applied
here to a subprocess).

Skip-guarded (PA-0005) on `live_boot_available()` -- composer + php on PATH
and Packagist actually reachable -- so this SKIPS cleanly, not fails, in any
environment without them, exactly like `tier0.php_available()` gates `php
-l`. Marked `@pytest.mark.slow` (a real `composer install` against the
network, ~tens of seconds) -- see `pyproject.toml`'s `markers` entry for the
convention this introduces.

**What this proves, and what it does not:** see `fuzzlab/labgen/conformance
/live_boot.py`'s own module docstring for the full scope statement. In
short: real boot + real HTTP responses + a real payload differential on the
`product.php` vulnerable/secure SQLi twin, against a per-run SQLite database
-- never a live-lab-grade dialect-sensitive oracle confirmation (that stays
Tier 2's, genuinely out of scope, per `tier2.py`).

**`CC-LAB-0056`/`FR-LAB-54` extends this module's own coverage** to three
more of the five real-page manifest groups this harness can prove (the
`forms`/`numeric` tests above are `CC-LAB-0054`'s): `auth` (a real SQLi
login bypass against a real seeded `users` row, and a real `register.php`
`INSERT`), `g2` (`products.php`/`api/products.php`'s real JSON feed), and
`g4` (the `edit_profile.php` -> `profile.php` stored-second-order
write-then-read round trip). `search.php` is deliberately left out --
`lab/manifests/phase3_php_laravel_real_pages_search.yaml`'s own header
documents that all six of its cells are still without a canonical
URL-owning cell pending the `L-P3.3c-CUT` policy decision (`CC-LAB-0052`/
`0053`), so there is no single stable `/search.php` URL to live-boot
against yet -- attempting one here would mean inventing a canonical choice
this project has explicitly deferred to a human decision, not proving
anything the generator itself claims.
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.labgen.conformance.live_boot import (
    SEED_BIO,
    SEED_PASSWORD,
    SEED_USER_ID,
    SEED_USERNAME,
    LiveBootHarness,
    live_boot_available,
)
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot harness requires composer + php on PATH and real Packagist "
        "network reachability (PA-0005) -- see live_boot.live_boot_available()"
    ),
)

#: One rendered row of `site.product`/`site.partials.product-card`
#: (CC-LAB-0240) -- the HTML analogue of the old JSON body's `"id"` key.
_PRODUCT_ROW_MARKER = 'data-product-id="'

#: R1 (CC-LAB-0240, docs/LAB_PFF_JSON_TO_HTML_PLAN.md): the designed minimum
#: found-vs-not-found byte delta of every converted page's HTML. A fixed,
#: independently-chosen literal (a design contract of the Blade views), NOT
#: derived from `SqliBooleanStrategy`'s own `_similar` threshold -- deriving
#: it would make this guard move with the thing it guards.
_MIN_FOUND_NOT_FOUND_DELTA = 300


def _assert_found_not_found_delta(harness, url, param, *, found, not_found, empty_text) -> None:
    """Fetch ``url`` in its found and not-found states and assert the served
    HTML bodies differ by at least :data:`_MIN_FOUND_NOT_FOUND_DELTA` bytes
    -- a literal length comparison on the real response, nothing else."""
    found_resp = harness.get(url, params={param: found})
    missing_resp = harness.get(url, params={param: not_found})
    assert found_resp.status == 200, (url, found_resp.body[:500])
    assert missing_resp.status == 200, (url, missing_resp.body[:500])
    assert empty_text in missing_resp.body, (url, missing_resp.body[:2000])
    assert empty_text not in found_resp.body, (url, found_resp.body[:2000])
    delta = len(found_resp.body.encode("utf-8")) - len(missing_resp.body.encode("utf-8"))
    print(f"R1 found/not-found delta {url}: {delta} bytes")
    assert delta >= _MIN_FOUND_NOT_FOUND_DELTA, (
        f"{url}: found/not-found HTML delta is only {delta} bytes (< {_MIN_FOUND_NOT_FOUND_DELTA}) "
        "-- SqliBooleanStrategy's length-similarity signal needs this designed margin (R1)"
    )


def _content_type(resp) -> str:
    """The response's Content-Type, looked up case-insensitively."""
    return {k.lower(): v for k, v in resp.headers.items()}.get("content-type", "")


@pytest.mark.slow
def test_live_boot_forms_manifest_serves_real_pages() -> None:
    """`contact.php`/`newsletter.php` (POST, no DB): the app boots and both
    real pinned URLs return a real HTTP 200 whose body reflects the escaped
    submitted value -- proving the escaped-echo XSS-secure real pages this
    generator claims to reproduce are genuinely reachable and behave as
    claimed, not just syntactically valid PHP."""
    manifest = load_manifest("lab/manifests/phase3_laravel_real_pages_forms.yaml")
    emitter = LaravelEmitter()
    cells = manifest.cells
    assert all(emitter.supports(c.vuln_class, c.sink_context) for c in cells)

    with LiveBootHarness(emitter, cells) as harness:
        for cell, field, marker in (
            (cells[0], "message", "<script>alert(1)</script>"),
            (cells[1], "email", "<script>alert(2)</script>"),
        ):
            url = served_url_for(cell)
            resp = harness.post(url, data={field: marker})
            assert resp.status == 200, (cell.cell_id, url, resp.status, resp.body[:500])
            # The value is echoed back HTML-entity-escaped (e()), never the
            # raw payload -- the actual, observable security property this
            # cell's own `html_entity_escape` transform is supposed to grant.
            assert marker not in resp.body, (cell.cell_id, resp.body)
            assert "&lt;script&gt;" in resp.body, (cell.cell_id, resp.body)


@pytest.mark.slow
def test_live_boot_numeric_manifest_sqli_twin_round_trips_a_payload() -> None:
    """`product.php`'s vulnerable/secure twin (PFF-0001's own shape): boots
    against a real seeded SQLite `products` table and shows a REAL,
    observable behavior difference between the raw-concatenation cell and
    its bound-parameter twin for a classic boolean-injection payload -- the
    actual point of this lab existing (task instruction 4's third bullet),
    not just that both cells produce syntactically valid PHP.
    """
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_numeric.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-RPL-PRODUCT"]
    secure = cells["LABGEN-RPL-PRODUCT-BOUND"]

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        vuln_url = served_url_for(vulnerable)
        secure_url = served_url_for(secure)

        # Sanity: both variants serve the real page for a normal id and
        # return the one seeded row (real HTTP response, not a stub).
        baseline_vuln = harness.get(vuln_url, params={"id": "1"})
        baseline_secure = harness.get(secure_url, params={"id": "1"})
        assert baseline_vuln.status == 200, baseline_vuln.body[:500]
        assert baseline_secure.status == 200, baseline_secure.body[:500]
        assert "Chew Toy" in baseline_vuln.body
        assert "Chew Toy" in baseline_secure.body

        # The differential: `1 OR 1=1` as a raw-concatenated numeric literal
        # returns EVERY row (both seeded products); as a bound parameter it
        # is treated as an opaque, non-numeric string id (or errors), and
        # never returns more than the single matching row. This is the
        # actual security-relevant behavior difference the safety matrix's
        # derived verdicts claim exists -- proven here against a real
        # response, not asserted from the source text.
        payload = "1 OR 1=1"
        vuln_resp = harness.get(vuln_url, params={"id": payload})
        secure_resp = harness.get(secure_url, params={"id": payload})
        assert vuln_resp.status == 200, vuln_resp.body[:500]
        # CC-LAB-0240: the page is real HTML now (`site.product`), one
        # `data-product-id` article per row -- counted instead of the old
        # JSON `"id"` keys, plus each seeded row's own name.
        assert vuln_resp.body.count(_PRODUCT_ROW_MARKER) >= 2, (
            "vulnerable cell did not return multiple rows for a boolean-injection "
            f"payload -- expected the raw-concatenation SQLi to leak every row: {vuln_resp.body[:1000]}"
        )
        assert "Chew Toy" in vuln_resp.body and "Puppy Bed" in vuln_resp.body, vuln_resp.body[:2000]
        secure_row_count = secure_resp.body.count(_PRODUCT_ROW_MARKER)
        assert secure_row_count < vuln_resp.body.count(_PRODUCT_ROW_MARKER), (
            "secure (bound-parameter) twin did not behave differently from the vulnerable twin "
            f"for the same payload: vulnerable={vuln_resp.body[:500]!r} secure={secure_resp.body[:500]!r}"
        )
        assert "Puppy Bed" not in secure_resp.body, secure_resp.body[:2000]

        # R1 (CC-LAB-0240): found vs not-found must differ by a designed,
        # literal >= 300 bytes of real page content on BOTH twins -- checked
        # on the actual served HTML, independent of any oracle strategy's own
        # similarity threshold.
        for url in (vuln_url, secure_url):
            _assert_found_not_found_delta(
                harness, url, "id", found="1", not_found="999999", empty_text="couldn't find that fort"
            )

        # /blog_post.php's twin (same manifest, same `html_list_view` tail,
        # `site.blog-post`): real HTML for the seeded post, the real page's
        # own "Post not found." empty state, and the same R1 delta.
        blog_vuln_url = served_url_for(cells["LABGEN-RPL-BLOGPOST"])
        blog_secure_url = served_url_for(cells["LABGEN-RPL-BLOGPOST-BOUND"])
        assert blog_vuln_url == "/blog_post.php"
        for url in (blog_vuln_url, blog_secure_url):
            post = harness.get(url, params={"id": "1"})
            assert post.status == 200, (url, post.body[:500])
            assert "<h1>Welcome to the Fort</h1>" in post.body, (url, post.body[:2000])
            assert post.body.count('data-post-id="') == 1, (url, post.body[:2000])
            _assert_found_not_found_delta(
                harness, url, "id", found="1", not_found="999999", empty_text="Post not found."
            )
        blog_payload = "999999 OR 1=1"
        blog_vuln = harness.get(blog_vuln_url, params={"id": blog_payload})
        blog_secure = harness.get(blog_secure_url, params={"id": blog_payload})
        assert "Welcome to the Fort" in blog_vuln.body, blog_vuln.body[:2000]
        assert "Welcome to the Fort" not in blog_secure.body, blog_secure.body[:2000]
        assert "Post not found." in blog_secure.body, blog_secure.body[:2000]


@pytest.mark.slow
def test_live_boot_auth_manifest_sqli_bypasses_login_and_register_inserts_a_row() -> None:
    """`login.php`'s vulnerable/secure twin (`LABGEN-PLA-0001`/`0002`)
    against a real seeded `users` row, plus `register.php`'s real prepared
    `INSERT` (`LABGEN-PLA-0003`).

    The classic auth-bypass comment payload (`' OR '1'='1' -- `) is spliced
    into `whereRaw("username = '" . $username . "'")` on the vulnerable
    cell, which comments out the trailing `->where('password', ...)`
    condition entirely -- so it authenticates as *some* real row with no
    correct password at all. The secure (bound-parameter) twin treats the
    same string as an opaque literal username, matches no row, and returns
    the real page's own 401.
    """
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_auth.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-PLA-0001"]
    secure = cells["LABGEN-PLA-0002"]
    register = cells["LABGEN-PLA-0003"]

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        vuln_url = served_url_for(vulnerable)
        secure_url = served_url_for(secure)
        register_url = served_url_for(register)
        assert vuln_url == "/login.php"
        assert secure_url == "/login.labgen-pla-0002.php"
        assert register_url == "/register.php"

        # Sanity: the seeded identity's own real credentials really do log
        # in on both twins first -- proves the seed data itself is correct
        # before trusting the injection differential built on top of it.
        for url in (vuln_url, secure_url):
            good = harness.post(url, data={"username": SEED_USERNAME, "password": SEED_PASSWORD})
            assert good.status == 302, (url, good.status, good.body[:500])

        # A plain `' OR '1'='1' -- ` breaks this exact rendered statement in
        # an uninteresting way rather than bypassing auth: the comment also
        # eats Laravel's own separately-bound `and password = ?` clause's
        # placeholder, and PDO/SQLite (`General error: 25 column index out
        # of range`) refuses to bind a value the compiled statement no
        # longer has a slot for -- a real, observed 500, not a bypass. The
        # payload below keeps one placeholder of its own (`username=?`)
        # BEFORE the comment marker, so the value Laravel's builder still
        # binds for the password clause lands on that placeholder instead --
        # an unauthenticated boolean-injection bypass that leaves the
        # statement itself valid.
        bypass_payload = "nonexistent-user' OR 1=1 OR username=? -- "

        # VULNERABLE: the boolean injection makes the WHERE unconditionally
        # true regardless of which row it evaluates against -- a genuine,
        # unauthenticated auth bypass, not merely "a different response". A
        # matched row -> 302 redirect to /profile.php with a session
        # established; the harness's `request()` never auto-follows a
        # redirect (`BUG-0028`), so it reports the raw 302 rather than
        # chasing it to whatever /profile.php happens to return.
        vuln_resp = harness.post(vuln_url, data={"username": bypass_payload, "password": "wrong-password"})
        assert vuln_resp.status == 302, (
            "expected the raw-concatenation login cell to authenticate via SQLi boolean "
            f"injection (a 302 redirect to /profile.php): got {vuln_resp.status} {vuln_resp.body[:500]!r}"
        )

        # SECURE: the same string is bound as a literal username -- no user
        # named that exists, so the real page's own 401 + error message.
        secure_resp = harness.post(secure_url, data={"username": bypass_payload, "password": "wrong-password"})
        assert secure_resp.status == 401, (
            "expected the bound-parameter login twin to reject the same payload as a literal, "
            f"nonexistent username: got {secure_resp.status} {secure_resp.body[:500]!r}"
        )
        # CC-LAB-0240: the 401 body is the real login page (HTML, the form
        # re-rendered with the real page's inline error), not a JSON body.
        assert '<p class="notice err">Invalid username or password.</p>' in secure_resp.body
        assert 'action="/login.php"' in secure_resp.body, secure_resp.body[:2000]
        assert "text/html" in _content_type(secure_resp), secure_resp.headers

        # register.php: a real prepared INSERT the app itself performs, not
        # a stub -- observed by reading the real row back out of the same
        # SQLite database the booted app just wrote to.
        new_username = "brand_new_recruit"
        reg_resp = harness.post(
            register_url,
            data={
                "username": new_username,
                "email": "recruit@example.test",
                "password": "kennel-club-1",
                "full_name": "Brand New Recruit",
            },
        )
        assert reg_resp.status == 200, (reg_resp.status, reg_resp.body[:500])
        # CC-LAB-0240: the real page's own HTML welcome notice (was the JSON
        # body `{"registered": true}`).
        assert f"Welcome to the pack, {new_username}!" in reg_resp.body, reg_resp.body[:2000]
        assert "text/html" in _content_type(reg_resp), reg_resp.headers
        rows = harness.query_db("SELECT * FROM users WHERE username = ?", (new_username,))
        assert len(rows) == 1, f"register.php did not insert a real row: {rows}"
        row = rows[0]
        assert row["email"] == "recruit@example.test"
        assert row["full_name"] == "Brand New Recruit"
        assert row["bio"] == ""
        import hashlib

        assert row["password"] == hashlib.md5(b"kennel-club-1").hexdigest()

        # A duplicate registration of the already-seeded username is
        # correctly rejected by the real duplicate-username check.
        dup_resp = harness.post(
            register_url,
            data={"username": SEED_USERNAME, "email": "x@example.test", "password": "x", "full_name": "X"},
        )
        assert dup_resp.status == 409, (dup_resp.status, dup_resp.body[:500])
        # CC-LAB-0240: the register form re-rendered with the real page's
        # inline error and the submitted username prefilled -- real HTML.
        assert '<p class="notice err">That username is already taken.</p>' in dup_resp.body
        assert f'name="username" value="{SEED_USERNAME}"' in dup_resp.body, dup_resp.body[:2000]
        assert "Welcome to the pack" not in dup_resp.body


@pytest.mark.slow
def test_live_boot_g2_manifest_serves_real_html_listing_and_real_json_feed() -> None:
    """`products.php` (secure-only, `LABGEN-PLRP-G2-0001`) and
    `api/products.php` (secure-only, `LABGEN-PLRP-G2-0002`) against the
    seeded `products` table: a real, category-filtered HTML listing and a
    real, well-formed JSON feed (the `json_view` Eloquent API Resource),
    both bound-parameter and therefore both unaffected by an injection
    payload in the same `category` position.
    """
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_g2.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    listing = cells["LABGEN-PLRP-G2-0001"]
    api = cells["LABGEN-PLRP-G2-0002"]

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        listing_url = served_url_for(listing)
        api_url = served_url_for(api)
        assert listing_url == "/products.php"
        assert api_url == "/api/products.php"

        # products.php: a real, category-filtered HTML result set.
        filtered = harness.get(listing_url, params={"category": "toys"})
        assert filtered.status == 200, filtered.body[:500]
        assert "Chew Toy" in filtered.body
        assert "Puppy Bed" not in filtered.body
        # CC-LAB-0240: real HTML listing (`site.products`), one card per row.
        assert filtered.body.count(_PRODUCT_ROW_MARKER) == 1, filtered.body[:2000]
        assert "text/html" in _content_type(filtered), filtered.headers
        _assert_found_not_found_delta(
            harness, listing_url, "category", found="toys", not_found="no-such-category",
            empty_text="No forts in that category yet.",
        )

        # api/products.php: a real, well-formed JSON array (not HTML), with
        # the declared field shape/casts the json_view Resource publishes.
        api_resp = harness.get(api_url, params={"category": "toys"})
        assert api_resp.status == 200, api_resp.body[:500]
        payload = json.loads(api_resp.body)  # must not raise -- real, parseable JSON
        assert isinstance(payload, list)
        assert len(payload) == 1
        item = payload[0]
        assert set(item) == {"id", "name", "price", "description", "category"}
        assert item["name"] == "Chew Toy"
        assert item["category"] == "toys"
        assert isinstance(item["id"], int)
        assert isinstance(item["price"], float)

        # Same SQL position, bound in both cells: a classic string-literal
        # breakout payload matches nothing (an opaque literal category), on
        # both the HTML and the JSON endpoint alike -- no differential to
        # prove here (both are secure-only per the manifest itself), but
        # the real bound-parameter behavior is still observed directly.
        payload_str = "toys' OR '1'='1"
        injected_html = harness.get(listing_url, params={"category": payload_str})
        assert injected_html.status == 200, injected_html.body[:500]
        assert "Chew Toy" not in injected_html.body
        assert "Puppy Bed" not in injected_html.body
        # Non-vacuous (R2): the page really rendered its own empty state.
        assert "No forts in that category yet." in injected_html.body, injected_html.body[:2000]
        injected_api = harness.get(api_url, params={"category": payload_str})
        assert injected_api.status == 200, injected_api.body[:500]
        assert json.loads(injected_api.body) == []


@pytest.mark.slow
def test_live_boot_search_manifest_serves_real_html_results_and_like_sqli_twin() -> None:
    """`search.php`'s SQLi twin (`LABGEN-PL-RP-0001`/`0002`, `CC-LAB-0240`)
    against the seeded SQLite `products` table: a real HTML results page
    (`site.search`), the `LIKE`-clause breakout differential, and R1's
    designed found/not-found byte delta on both twins. (Since `CC-LAB-0058`
    resolved `search.php`'s canonical cell, the module docstring's
    "search.php is deliberately left out" note is historical.)"""
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_search.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vuln_url = served_url_for(cells["LABGEN-PL-RP-0001"])
    secure_url = served_url_for(cells["LABGEN-PL-RP-0002"])
    assert vuln_url == "/search.php"

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        for url in (vuln_url, secure_url):
            baseline = harness.get(url, params={"q": "Chew"})
            assert baseline.status == 200, (url, baseline.body[:500])
            assert "text/html" in _content_type(baseline), baseline.headers
            assert "Chew Toy" in baseline.body and "Puppy Bed" not in baseline.body, baseline.body[:2000]
            assert baseline.body.count(_PRODUCT_ROW_MARKER) == 1, baseline.body[:2000]
            _assert_found_not_found_delta(
                harness, url, "q", found="Chew", not_found="zzz-no-such-fort",
                empty_text="No forts matched your search.",
            )

        payload = "%' OR '1'='1"
        vuln_resp = harness.get(vuln_url, params={"q": payload})
        secure_resp = harness.get(secure_url, params={"q": payload})
        assert vuln_resp.status == 200, vuln_resp.body[:500]
        assert vuln_resp.body.count(_PRODUCT_ROW_MARKER) == 2, vuln_resp.body[:2000]
        assert secure_resp.status == 200, secure_resp.body[:500]
        assert secure_resp.body.count(_PRODUCT_ROW_MARKER) == 0, secure_resp.body[:2000]
        assert "No forts matched your search." in secure_resp.body, secure_resp.body[:2000]


def _write_url_for(emitter: LaravelEmitter, cell) -> str:
    """The URL a `stored_second_order` cell's own write route is registered
    at (canonical or twin) -- derived from the emitter's own
    `route_fragment_for()` output (the same fragment `routes/web.php` is
    assembled from) rather than a second, independent re-derivation of the
    canonical/twin URL-pinning rule `served_url_for()` already owns
    (PA-0001/PA-0021): a `stored_second_order` fragment's second line is
    always its write route's own `Route::post(...)` registration."""
    fragment = emitter.route_fragment_for(cell)
    lines = fragment.splitlines()
    assert len(lines) == 2, f"{cell.cell_id}: expected a read line + a write line, got {lines!r}"
    write_line = lines[1]
    assert "Route::post(" in write_line, write_line
    return write_line.split("'")[1]


@pytest.mark.slow
def test_live_boot_g4_manifest_stored_bio_round_trips_write_then_read() -> None:
    """`edit_profile.php` (write) -> `profile.php` (read/sink), the
    stored-second-order pair (`LABGEN-PLRP-0401` vulnerable / `0402`
    secure): a genuine two-request sequence -- POST a payload to the write
    endpoint, then GET the read endpoint -- confirming the stored value
    round-trips through the real seeded `users` row (`SEED_USER_ID`, the
    write/read default `?user=` owner) and that the vulnerable twin's
    payload survives unescaped at the sink while the secure twin's is
    HTML-entity-escaped.
    """
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_g4.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-PLRP-0401"]
    secure = cells["LABGEN-PLRP-0402"]

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        vuln_write_url = _write_url_for(emitter, vulnerable)
        vuln_read_url = served_url_for(vulnerable)
        secure_write_url = _write_url_for(emitter, secure)
        secure_read_url = served_url_for(secure)
        assert vuln_write_url == "/edit_profile.labgen-plrp-0401.php"
        assert vuln_read_url == "/profile.php"
        assert secure_write_url == "/edit_profile.php"
        assert secure_read_url == "/profile.labgen-plrp-0402.php"

        # Sanity: the read endpoint really does render the seeded bio before
        # either write below touches it.
        baseline = harness.get(vuln_read_url, params={"user": str(SEED_USER_ID)})
        assert baseline.status == 200, baseline.body[:500]
        assert SEED_BIO in baseline.body

        marker_vuln = "<script>alert('vuln-g4')</script>"
        write_resp = harness.post(vuln_write_url, data={"bio": marker_vuln})
        assert write_resp.status == 302, (write_resp.status, write_resp.body[:500])
        read_resp = harness.get(vuln_read_url, params={"user": str(SEED_USER_ID)})
        assert read_resp.status == 200, read_resp.body[:500]
        assert marker_vuln in read_resp.body, (
            "vulnerable stored-XSS cell did not reflect the stored payload UNESCAPED at the "
            f"sink: {read_resp.body[:800]!r}"
        )

        marker_secure = "<script>alert('secure-g4')</script>"
        write_resp2 = harness.post(secure_write_url, data={"bio": marker_secure})
        assert write_resp2.status == 302, (write_resp2.status, write_resp2.body[:500])
        read_resp2 = harness.get(secure_read_url, params={"user": str(SEED_USER_ID)})
        assert read_resp2.status == 200, read_resp2.body[:500]
        assert marker_secure not in read_resp2.body, (
            "secure twin reflected the stored payload UNESCAPED -- html_entity_escape did not "
            f"apply at the sink: {read_resp2.body[:800]!r}"
        )
        assert "&lt;script&gt;alert(&#039;secure-g4&#039;)&lt;/script&gt;" in read_resp2.body, (
            read_resp2.body[:800]
        )


@pytest.mark.slow
def test_live_boot_dom_manifest_serves_reviews_and_feedback() -> None:
    """`reviews.php`/`feedback.php` (L-P3.3c-DOM, `PFF-0007`/`PFF-0008`): the
    app boots and both real pinned URLs return a real HTTP 200 whose body
    embeds the client-side `<script>` block this generator claims to
    reproduce -- the read AND the write happen entirely in that script, so
    (unlike every other live-boot test in this module) there is no server
    round trip to differentiate on. This proves reachability and the
    presence of the vulnerable (`innerHTML`) vs. secure (`textContent`)
    JS-assignment shape, never a JS-*execution* proof -- headless,
    JS-executing crawling is a deliberate, documented gap (D-open-1,
    `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.7; `docs/ON_HOST_RUNBOOK.md`)."""
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_dom.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        vuln_reviews_url = served_url_for(cells["LABGEN-PLRP-DOM-0001"])
        secure_reviews_url = served_url_for(cells["LABGEN-PLRP-DOM-0001-SAFE"])
        vuln_feedback_url = served_url_for(cells["LABGEN-PLRP-DOM-0002"])
        secure_feedback_url = served_url_for(cells["LABGEN-PLRP-DOM-0002-SAFE"])
        assert vuln_reviews_url == "/reviews.php"
        assert vuln_feedback_url == "/feedback.php"

        resp = harness.get(vuln_reviews_url)
        assert resp.status == 200, resp.body[:500]
        assert "location.hash" in resp.body
        assert ".innerHTML =" in resp.body

        resp = harness.get(secure_reviews_url)
        assert resp.status == 200, resp.body[:500]
        assert ".textContent =" in resp.body
        assert ".innerHTML =" not in resp.body

        resp = harness.get(vuln_feedback_url)
        assert resp.status == 200, resp.body[:500]
        assert "location.search" in resp.body
        assert ".innerHTML =" in resp.body

        resp = harness.get(secure_feedback_url)
        assert resp.status == 200, resp.body[:500]
        assert ".textContent =" in resp.body
        assert ".innerHTML =" not in resp.body
