"""Live-boot conformance check for `php_laravel`'s access-control/IDOR cell
(`CC-LAB-0216`, CircleFeed -- category 2's Facebook pick, first designed
cell). Reuses `lab/safety_matrix.yaml`'s existing `ownership_check_bypass`
concern/`access_control` family (`no_ownership_check`/
`identity_match_before_fetch` x `db_row_by_id_lookup`, added `CC-LAB-0063`)
-- this project's first real implementation of that family by any emitter.

Real, on-host integration test: assembles a real Laravel project from the
checked-in skeleton (including this change's own `Photo` model/migration)
plus this manifest's real `LaravelEmitter` output, runs a real `composer
install`, boots a real `php artisan serve`, and sends real HTTP requests
against it -- **both twins together in one harness instance**, alongside
the real `/login.php` page (`phase3_php_laravel_real_pages_auth.yaml`'s
`LABGEN-PLA-0001`), since a genuine ownership-check differential needs a
real session for a real *second* user, which only a real login gets. Two
distinct users are seeded by `LiveBootHarness`'s own fixed rows
(`SEED_USER_ID`/`SEED_USER_B_ID`), each owning one seeded private photo
(`SEED_PHOTO_A_ID`/`SEED_PHOTO_B_ID`).

Proves the real differential, both directions, from real HTTP responses:

* the **vulnerable** twin (`no_ownership_check`) lets user B fetch user A's
  private photo -- a real 200 carrying user A's real content;
* the **secure** twin (`identity_match_before_fetch`) refuses the same
  request for user B -- a real 404 (`firstOrFail()`'s default exception
  rendering) -- while user B can still fetch their *own* photo through the
  secure twin, proving this is a real ownership check, not a blanket deny.

Skip-guarded (PA-0005) on `live_boot_available()`. Marked `@pytest.mark.slow`.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.live_boot import (
    SEED_PASSWORD_B,
    SEED_PHOTO_A_ID,
    SEED_PHOTO_B_ID,
    SEED_USERNAME_B,
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


def _cells():
    login_manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_auth.yaml")
    cf_manifest = load_manifest("lab/manifests/access_control_circlefeed_sample.yaml")
    login_cell = {c.cell_id: c for c in login_manifest.cells}["LABGEN-PLA-0001"]
    cf_cells = {c.cell_id: c for c in cf_manifest.cells}
    return login_cell, cf_cells["LABGEN-CF-0001"], cf_cells["LABGEN-CF-0002"]


def _session_cookie(harness: LiveBootHarness, login_cell, *, username: str, password: str) -> str:
    """Logs in as ``username`` through the real `/login.php` page and
    returns the `Cookie:` value for the resulting session -- the harness's
    own `HttpResponse.headers` dict keeps the *last* same-named response
    header (`dict(resp.headers.items())`, see this module's own
    change-control entry for the confirmed real ordering), which for a real
    Laravel response is the session cookie (`XSRF-TOKEN` is set first,
    the session cookie second)."""
    url = served_url_for(login_cell)
    resp = harness.post(url, data={"username": username, "password": password})
    assert resp.status == 302, f"login as {username!r} did not redirect (session not established): {resp.body[:500]}"
    set_cookie = resp.headers.get("Set-Cookie")
    assert set_cookie, f"login as {username!r} set no cookie at all: {resp.headers}"
    assert "-session=" in set_cookie, (
        f"login as {username!r}: expected the session cookie (name contains '-session='), "
        f"got {set_cookie!r} -- the harness's header-collapsing assumption may have changed"
    )
    return set_cookie.split(";", 1)[0]


@pytest.mark.slow
def test_access_control_vulnerable_twin_leaks_another_users_private_photo() -> None:
    login_cell, vulnerable, secure = _cells()
    emitter = LaravelEmitter()
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with LiveBootHarness(emitter, [login_cell, vulnerable, secure]) as harness:
        cookie_b = _session_cookie(harness, login_cell, username=SEED_USERNAME_B, password=SEED_PASSWORD_B)

        url = served_url_for(vulnerable)
        # User B fetches user A's private photo through the vulnerable
        # twin: a real 200 carrying user A's real content -- the fetch is
        # scoped by primary key alone, so the id belonging to a different
        # user is honored anyway.
        resp = harness.request("GET", url, params={"id": str(SEED_PHOTO_A_ID)}, headers={"Cookie": cookie_b})
        assert resp.status == 200, (resp.status, resp.body[:500])
        # CC-LAB-0239: the page is now real HTML (`site.photo-view.blade.php`),
        # not JSON -- these substrings are what that template actually emits.
        # The apostrophe is Blade's own `{{ }}` HTML-escaping of the stored
        # caption (`&#039;`), not a literal quote -- the caption isn't this
        # cell's own taint source, so escaping it is simply correct, real
        # HTML output, not a security-relevant choice this test needs to
        # weaken.
        assert f"Photo #{SEED_PHOTO_A_ID}" in resp.body, resp.body
        assert "Owner:</strong> 1" in resp.body, resp.body
        assert "User A&#039;s private beach photo" in resp.body, resp.body

        # Sanity: user B can also fetch their own photo through this same
        # (never-checking) twin.
        resp_own = harness.request("GET", url, params={"id": str(SEED_PHOTO_B_ID)}, headers={"Cookie": cookie_b})
        assert resp_own.status == 200, (resp_own.status, resp_own.body[:500])
        assert "Owner:</strong> 2" in resp_own.body, resp_own.body


@pytest.mark.slow
def test_access_control_secure_twin_rejects_cross_user_access_but_allows_own() -> None:
    login_cell, vulnerable, secure = _cells()
    emitter = LaravelEmitter()
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    with LiveBootHarness(emitter, [login_cell, vulnerable, secure]) as harness:
        cookie_b = _session_cookie(harness, login_cell, username=SEED_USERNAME_B, password=SEED_PASSWORD_B)

        url = served_url_for(secure)
        # User B tries user A's private photo through the SECURE twin: a
        # real 404 -- ModelNotFoundException from the ownership-scoped
        # ->where('owner_id', ...) clause failing to match any row, the
        # exact same result a nonexistent id would produce (never leaks
        # whether id=1 exists at all).
        resp = harness.request("GET", url, params={"id": str(SEED_PHOTO_A_ID)}, headers={"Cookie": cookie_b})
        assert resp.status == 404, (resp.status, resp.body[:500])
        assert "User A&#039;s private beach photo" not in resp.body

        # User B fetches their OWN photo through the same secure twin: a
        # real 200 -- proving this is a real ownership check, not a
        # blanket deny.
        resp_own = harness.request("GET", url, params={"id": str(SEED_PHOTO_B_ID)}, headers={"Cookie": cookie_b})
        assert resp_own.status == 200, (resp_own.status, resp_own.body[:500])
        assert "Owner:</strong> 2" in resp_own.body, resp_own.body
        assert "User B&#039;s private beach photo" in resp_own.body, resp_own.body


@pytest.mark.slow
def test_access_control_unauthenticated_request_is_rejected_on_both_twins() -> None:
    """No session cookie at all -- both twins share the same
    non-differentiating unauthenticated guard (the sink's own boilerplate,
    never the security-relevant differentiator this cell pair tests)."""
    login_cell, vulnerable, secure = _cells()
    emitter = LaravelEmitter()

    with LiveBootHarness(emitter, [login_cell, vulnerable, secure]) as harness:
        for cell in (vulnerable, secure):
            resp = harness.get(served_url_for(cell), params={"id": str(SEED_PHOTO_A_ID)})
            assert resp.status == 401, (cell.cell_id, resp.status, resp.body[:500])
