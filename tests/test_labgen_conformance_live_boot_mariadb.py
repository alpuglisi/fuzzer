"""MariaDB-backed live-boot conformance check for `php_laravel`
(`CC-LAB-0058`/`FR-LAB-55`, extending `CC-LAB-0054`/`CC-LAB-0056`'s SQLite-
backed `tests/test_labgen_conformance_live_boot.py`).

**What this closes.** `live_boot.py`'s original harness proves a
`php_laravel`-emitted build boots and serves real HTTP against a per-run
SQLite database -- an explicitly-scoped test-harness substitute for the real
lab's MariaDB (`lab/compose.yaml`'s `db` service, matching
`puppy-fort-factory/sql/schema.sql`). Nobody had proven the generator's
output against the *actual* database engine the real lab is built around.
This module does: it starts a real local `mariadbd` (`fuzzlab.labgen
.conformance.live_boot.MariaDbServer`, via the system `service` command),
imports the REAL `puppy-fort-factory/sql/schema.sql` verbatim (never a port
or a synthetic equivalent), points the assembled Laravel skeleton's `.env` at
it (`DB_CONNECTION=mysql`), and re-runs the same real-HTTP proof already
established against SQLite for `forms`/`numeric`/`auth`/`g2`/`g4`, plus (new,
`CC-LAB-0058`) `search.php`'s now-resolved canonical `LIKE`-clause SQLi cell
(`LABGEN-PL-RP-0001`, `PFF-0002`).

**Skip-guarded** (PA-0005) on both `live_boot_available()` (composer + php +
Packagist -- the original harness's own probe) and the new
`mariadb_available()` (the `mariadb`/`mariadb-admin` client binaries, the
system `service` command and `/etc/init.d/mariadb` init script, and
`puppy-fort-factory/sql/schema.sql` itself). SKIPS cleanly, never fails, in
any environment without a real local MariaDB. Marked `@pytest.mark.slow`
(a real `composer install` plus a real `mariadbd` start/provision/stop per
test).

**Real, observed MariaDB-vs-SQLite differences -- reported here, never
papered over (this task's own explicit instruction).** The real engine and
the real schema surfaced two genuine behavioral differences the SQLite
harness's synthetic schema/data had been masking:

1. **The classic `-- ` (dash-dash-space) SQL comment does not survive
   Laravel's default `TrimStrings` middleware against a real MySQL-dialect
   server.** `TrimStrings` trims the payload's own trailing whitespace
   before it ever reaches the query -- turning `... username=? -- ` into
   `... username=? --` once concatenated with the sink template's closing
   quote (`... username=? --'`). SQLite's line-comment syntax needs no
   trailing whitespace after `--`, so the SQLite-backed auth test's payload
   (`tests/test_labgen_conformance_live_boot
   .test_live_boot_auth_manifest_sqli_bypasses_login_and_register_inserts_a_row`)
   bypasses cleanly there. Real MySQL/MariaDB's grammar requires at least one
   whitespace/control character immediately *after* `--` for it to be
   recognized as a comment at all; with the trailing space trimmed away and
   only a bare quote following, MariaDB raises a genuine
   `SQLSTATE[42000]` syntax error (1064) instead of bypassing --
   `test_live_boot_auth_manifest_sqli_bypasses_login_and_register_inserts_a_row_mariadb`
   below asserts this exact, real, observed 500 for the SQLite test's own
   payload, then demonstrates the SAME underlying vulnerability still holds
   for real against MariaDB with a dialect-appropriate payload (`#`, MySQL's
   own to-end-of-line comment marker, which needs no trailing character to
   be recognized -- so `TrimStrings` cannot break it). The vulnerability is
   real either way; only the exact classic-textbook payload happens to be
   SQLite-specific once combined with this scaffold's own `TrimStrings`
   default.
2. **`puppy-fort-factory/sql/schema.sql`'s real `users` table has no
   `updated_at` column** (only `created_at TIMESTAMP ... DEFAULT
   CURRENT_TIMESTAMP`, no `ON UPDATE` companion) -- unlike the SQLite
   harness's own synthetic schema, which added one specifically because
   Eloquent's default `$timestamps = true` unconditionally sets it on every
   `->save()` (see `live_boot.py`'s own `_SCHEMA_SQL` comment, `BUG-0028`).
   The G4 stored-second-order **write** path
   (`edit_profile.php`'s `$storedOwner->save()`) goes through Eloquent, so
   against the REAL schema it now genuinely 500s
   (`SQLSTATE[42S22]: Column not found: 1054 Unknown column
   'users.updated_at' in 'SET'`) -- a real compatibility gap between the
   `php_laravel` skeleton's default `App\\Models\\User` (framework default:
   timestamps on) and the real lab schema, first surfaced by this real
   MariaDB proof, not previously known. `register.php`'s own real `INSERT`
   (G3) is unaffected -- it goes through `DB::table('users')` (the query
   builder), never Eloquent, exactly like `login.php`'s own read path (see
   `live_boot.py`'s own docstring on why `login.php`/`register.php` never
   invoke the model's cast machinery). `test_live_boot_g4_manifest_mariadb`
   below asserts this exact, real, currently-true 500 for the write leg
   (documented, not silently retried or worked around) while still proving
   the READ leg boots and serves the real seeded `bio` correctly. Fixing the
   skeleton's `User` model (`public $timestamps = false;`, or a real
   `updated_at` column added to a *copy* of the schema this harness owns) is
   real future work, deliberately not done here: this task's brief is
   additive-only ("no re-pointing... no touching puppy-fort-factory/"), and
   the fix belongs to whichever lane resolves cutover-readiness for G4, not
   to a conformance harness whose job is to observe and report, not silently
   patch around, a real gap.

Everything else observed matches the SQLite-backed proof's own claims
(the SQLi/XSS differentials, the real INSERT/read round trips) -- see each
test's own docstring for what it specifically re-confirms against the real
engine.
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.labgen.conformance.live_boot import (
    LiveBootHarness,
    MariaDbServer,
    live_boot_available,
    mariadb_available,
)
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.schema import load_manifest

pytestmark = [
    pytest.mark.skipif(
        not live_boot_available(),
        reason=(
            "live-boot harness requires composer + php on PATH and real Packagist "
            "network reachability (PA-0005) -- see live_boot.live_boot_available()"
        ),
    ),
    pytest.mark.skipif(
        not mariadb_available(),
        reason=(
            "MariaDB-backed mode requires the real mariadb/mariadb-admin client "
            "binaries, the system 'service' command, /etc/init.d/mariadb, and "
            "puppy-fort-factory/sql/schema.sql (PA-0005) -- see "
            "live_boot.mariadb_available()"
        ),
    ),
]


def _write_url_for(emitter: LaravelEmitter, cell) -> str:
    """Same derivation as the SQLite-backed suite's own helper (PA-0001/
    PA-0021: never a second, independent re-derivation of the write-route
    URL `served_url_for()`'s twin-URL convention already owns)."""
    fragment = emitter.route_fragment_for(cell)
    lines = fragment.splitlines()
    assert len(lines) == 2, f"{cell.cell_id}: expected a read line + a write line, got {lines!r}"
    write_line = lines[1]
    assert "Route::post(" in write_line, write_line
    return write_line.split("'")[1]


@pytest.mark.slow
def test_live_boot_forms_manifest_serves_real_pages_mariadb() -> None:
    """`contact.php`/`newsletter.php`: no database involved at all, so this
    re-run against a MariaDB-backed harness is a pure boot/serve sanity check
    -- confirms the harness's MariaDB wiring doesn't itself break a page that
    never touches the database."""
    manifest = load_manifest("lab/manifests/phase3_laravel_real_pages_forms.yaml")
    emitter = LaravelEmitter()
    cells = manifest.cells

    with MariaDbServer() as db:
        with LiveBootHarness(emitter, cells, mariadb_server=db) as harness:
            for cell, field, marker in (
                (cells[0], "message", "<script>alert(1)</script>"),
                (cells[1], "email", "<script>alert(2)</script>"),
            ):
                url = served_url_for(cell)
                resp = harness.post(url, data={field: marker})
                assert resp.status == 200, (cell.cell_id, url, resp.status, resp.body[:500])
                assert marker not in resp.body, (cell.cell_id, resp.body)
                assert "&lt;script&gt;" in resp.body, (cell.cell_id, resp.body)


@pytest.mark.slow
def test_live_boot_numeric_manifest_sqli_twin_round_trips_a_payload_mariadb() -> None:
    """`product.php`'s vulnerable/secure twin against the REAL `products`
    table (ten real seeded rows, real `DECIMAL`/`VARCHAR` column types) --
    the same boolean-injection differential the SQLite-backed test proves,
    now against the real engine and the real seed data (`Puppy Fort
    Deluxe`, id 1, not the SQLite harness's synthetic `Chew Toy`)."""
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_numeric.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-RPL-PRODUCT"]
    secure = cells["LABGEN-RPL-PRODUCT-BOUND"]

    with MariaDbServer() as db:
        with LiveBootHarness(emitter, list(manifest.cells), mariadb_server=db) as harness:
            vuln_url = served_url_for(vulnerable)
            secure_url = served_url_for(secure)

            baseline_vuln = harness.get(vuln_url, params={"id": "1"})
            baseline_secure = harness.get(secure_url, params={"id": "1"})
            assert baseline_vuln.status == 200, baseline_vuln.body[:500]
            assert baseline_secure.status == 200, baseline_secure.body[:500]
            assert "Puppy Fort Deluxe" in baseline_vuln.body
            assert "Puppy Fort Deluxe" in baseline_secure.body

            payload = "1 OR 1=1"
            vuln_resp = harness.get(vuln_url, params={"id": payload})
            secure_resp = harness.get(secure_url, params={"id": payload})
            assert vuln_resp.status == 200, vuln_resp.body[:500]
            # Ten real seeded products -> ten real leaked rows.
            assert vuln_resp.body.count('"id"') == 10, (
                "vulnerable cell did not leak every real seeded row for a boolean-injection "
                f"payload against real MariaDB: {vuln_resp.body[:1000]}"
            )
            secure_row_count = secure_resp.body.count('"id"')
            assert secure_row_count < vuln_resp.body.count('"id"'), (
                "secure (bound-parameter) twin did not behave differently from the vulnerable "
                f"twin for the same payload against real MariaDB: vulnerable={vuln_resp.body[:300]!r} "
                f"secure={secure_resp.body[:300]!r}"
            )


@pytest.mark.slow
def test_live_boot_g2_manifest_serves_real_listing_and_json_feed_mariadb() -> None:
    """`products.php`/`api/products.php` against the real `products` table's
    real `forts`/`accessories`/`treats` categories (not the SQLite harness's
    synthetic `toys`/`beds`). Also confirms a real, observed MariaDB-vs-
    SQLite TYPE difference does NOT leak through the `json_view` Eloquent API
    Resource: `price` is a real `DECIMAL(10,2)` column, which MariaDB's raw
    driver surfaces as a string (see this manifest's numeric-twin sibling,
    whose raw `DB::select()` output legitimately differs this way) -- but the
    Resource's own explicit float cast (asserted below) means the JSON feed's
    contract is unaffected by the underlying engine, exactly as designed.
    """
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_g2.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    listing = cells["LABGEN-PLRP-G2-0001"]
    api = cells["LABGEN-PLRP-G2-0002"]

    with MariaDbServer() as db:
        with LiveBootHarness(emitter, list(manifest.cells), mariadb_server=db) as harness:
            listing_url = served_url_for(listing)
            api_url = served_url_for(api)

            filtered = harness.get(listing_url, params={"category": "forts"})
            assert filtered.status == 200, filtered.body[:500]
            assert "Puppy Fort Deluxe" in filtered.body
            assert "Glow-in-the-Dark Flags" not in filtered.body  # a real 'accessories' row

            api_resp = harness.get(api_url, params={"category": "forts"})
            assert api_resp.status == 200, api_resp.body[:500]
            payload = json.loads(api_resp.body)
            assert isinstance(payload, list)
            names = {item["name"] for item in payload}
            assert "Puppy Fort Deluxe" in names
            assert all(item["category"] == "forts" for item in payload)
            assert all(isinstance(item["price"], float) for item in payload), (
                "json_view Resource did not cast the real DECIMAL price column to float "
                f"against real MariaDB: {payload}"
            )

            payload_str = "forts' OR '1'='1"
            injected_html = harness.get(listing_url, params={"category": payload_str})
            assert injected_html.status == 200, injected_html.body[:500]
            assert "Puppy Fort Deluxe" not in injected_html.body
            injected_api = harness.get(api_url, params={"category": payload_str})
            assert injected_api.status == 200, injected_api.body[:500]
            assert json.loads(injected_api.body) == []


@pytest.mark.slow
def test_live_boot_auth_manifest_sqli_bypasses_login_and_register_inserts_a_row_mariadb() -> None:
    """`login.php`'s twin against the REAL seeded `admin`/`alice`/`bob` rows,
    plus `register.php`'s real prepared `INSERT` against the real schema.

    **The real, observed MariaDB-vs-SQLite dialect difference (see this
    module's own docstring, point 1):** the SQLite-backed suite's own
    classic bypass payload (`nonexistent-user' OR 1=1 OR username=? -- `,
    relying on a trailing `-- ` comment) is proven here to 500 for real
    against MariaDB -- `TrimStrings` strips its trailing space, and MariaDB's
    `--` comment syntax (unlike SQLite's) requires that trailing whitespace
    to be recognized as a comment at all. The SAME underlying boolean-
    injection auth bypass is then shown to still be real against MariaDB
    with a dialect-appropriate payload (`#`, MySQL's own bare to-end-of-line
    comment marker)."""
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_auth.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-PLA-0001"]
    secure = cells["LABGEN-PLA-0002"]
    register = cells["LABGEN-PLA-0003"]

    with MariaDbServer() as db:
        with LiveBootHarness(emitter, list(manifest.cells), mariadb_server=db) as harness:
            vuln_url = served_url_for(vulnerable)
            secure_url = served_url_for(secure)
            register_url = served_url_for(register)

            # Sanity: the REAL seeded admin identity really does log in on
            # both twins (real MD5 password hash matches schema.sql's own
            # MD5('admin123') seed, per `password_hash_fn: "md5"`).
            for url in (vuln_url, secure_url):
                good = harness.post(url, data={"username": "admin", "password": "admin123"})
                assert good.status == 302, (url, good.status, good.body[:500])

            # The SQLite suite's own payload: a genuine, observed 500 against
            # real MariaDB (see module docstring point 1) -- asserted here,
            # not papered over.
            sqlite_suite_payload = "nonexistent-user' OR 1=1 OR username=? -- "
            trimmed_resp = harness.post(
                vuln_url, data={"username": sqlite_suite_payload, "password": "wrong-password"}
            )
            assert trimmed_resp.status == 500, (
                "expected the SQLite-suite's own bypass payload to 500 for real against MariaDB "
                f"(TrimStrings + MariaDB's stricter '--' comment rule): got {trimmed_resp.status} "
                f"{trimmed_resp.body[:300]!r}"
            )

            # The same underlying vulnerability, exploited with a dialect-
            # appropriate payload: MySQL's bare `#` end-of-line comment needs
            # no trailing whitespace, so TrimStrings cannot break it.
            mariadb_payload = "nonexistent-user' OR 1=1 OR username=?#"
            vuln_resp = harness.post(vuln_url, data={"username": mariadb_payload, "password": "wrong-password"})
            assert vuln_resp.status == 302, (
                "expected the raw-concatenation login cell to authenticate via SQLi boolean "
                f"injection against real MariaDB (a 302 redirect): got {vuln_resp.status} "
                f"{vuln_resp.body[:500]!r}"
            )
            secure_resp = harness.post(secure_url, data={"username": mariadb_payload, "password": "wrong-password"})
            assert secure_resp.status == 401, (
                "expected the bound-parameter login twin to reject the same payload as a "
                f"literal, nonexistent username against real MariaDB: got {secure_resp.status} "
                f"{secure_resp.body[:500]!r}"
            )
            assert "Invalid username or password." in secure_resp.body

            # register.php: a real prepared INSERT against the real schema
            # (DB::table(), never Eloquent -- unaffected by the G4 finding).
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
            assert json.loads(reg_resp.body) == {"registered": True}
            rows = db.query("SELECT * FROM users WHERE username = %s", (new_username,))
            assert len(rows) == 1, f"register.php did not insert a real row into MariaDB: {rows}"
            row = rows[0]
            assert row["email"] == "recruit@example.test"
            assert row["full_name"] == "Brand New Recruit"
            import hashlib

            assert row["password"] == hashlib.md5(b"kennel-club-1").hexdigest()

            dup_resp = harness.post(
                register_url,
                data={"username": "admin", "email": "x@example.test", "password": "x", "full_name": "X"},
            )
            assert dup_resp.status == 409, (dup_resp.status, dup_resp.body[:500])
            assert "That username is already taken." in dup_resp.body


@pytest.mark.slow
def test_live_boot_g4_manifest_mariadb() -> None:
    """`edit_profile.php` -> `profile.php` against the REAL schema.

    **The real, observed MariaDB-vs-SQLite schema gap (see this module's own
    docstring, point 2):** the real `puppy-fort-factory/sql/schema.sql` has
    no `updated_at` column, but the write leg goes through Eloquent
    (`$storedOwner->save()`), which unconditionally sets one -- a genuine
    500 against the real schema, asserted here precisely rather than
    silently worked around. The READ leg (no Eloquent `save()` involved)
    still boots and serves the real seeded `admin` row's real `bio` value
    correctly, proving the read half of this proof is unaffected.
    """
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_g4.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-PLRP-0401"]

    with MariaDbServer() as db:
        with LiveBootHarness(emitter, list(manifest.cells), mariadb_server=db) as harness:
            vuln_write_url = _write_url_for(emitter, vulnerable)
            vuln_read_url = served_url_for(vulnerable)
            assert vuln_read_url == "/profile.php"

            # READ leg: the real seeded admin row's real bio, unaffected.
            baseline = harness.get(vuln_read_url, params={"user": "1"})
            assert baseline.status == 200, baseline.body[:500]
            assert "Chief Fort Architect and head of biscuit security." in baseline.body

            # WRITE leg: a real, currently-true 500 against the real schema
            # (Eloquent's default $timestamps=true vs. schema.sql's missing
            # `updated_at`) -- documented, not papered over.
            marker = "<script>alert('vuln-g4-mariadb')</script>"
            write_resp = harness.post(vuln_write_url, data={"bio": marker})
            assert write_resp.status == 500, (
                "expected the G4 write leg to 500 against the real schema (no 'updated_at' "
                f"column for Eloquent's default $timestamps=true): got {write_resp.status} "
                f"{write_resp.body[:300]!r} -- if this now succeeds, the skeleton's User model "
                "or the real schema changed and this module's own docstring finding is stale"
            )
            log_path = harness._app_dir / "storage" / "logs" / "laravel.log"  # noqa: SLF001
            assert "Unknown column 'users.updated_at'" in log_path.read_text("utf-8")


@pytest.mark.slow
def test_live_boot_search_manifest_like_sqli_twin_mariadb() -> None:
    """`search.php`'s now-resolved canonical cell (`LABGEN-PL-RP-0001`,
    `PFF-0002`, `CC-LAB-0058`/`FR-LAB-55`): a real `GET /search.php?q=...`
    against the real `products` table, proving the `LIKE '%q%'` catalogue
    SQLi differential this task's Path B resolution keeps "covered" (not
    exempted) for real against the real database engine."""
    manifest = load_manifest("lab/manifests/phase3_php_laravel_real_pages_search.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-PL-RP-0001"]
    secure = cells["LABGEN-PL-RP-0002"]

    with MariaDbServer() as db:
        with LiveBootHarness(emitter, list(manifest.cells), mariadb_server=db) as harness:
            vuln_url = served_url_for(vulnerable)
            secure_url = served_url_for(secure)
            assert vuln_url == "/search.php"
            assert secure_url == "/search.labgen-pl-rp-0002.php"

            baseline = harness.get(vuln_url, params={"q": "Fort"})
            assert baseline.status == 200, baseline.body[:500]
            assert "Puppy Fort Deluxe" in baseline.body

            # A classic LIKE-clause breakout: closes the wildcarded string
            # literal early and appends an always-true condition, leaking
            # every real seeded product on the vulnerable twin; the bound
            # secure twin treats it as an opaque, never-matching literal.
            payload = "%' OR '1'='1"
            vuln_resp = harness.get(vuln_url, params={"q": payload})
            secure_resp = harness.get(secure_url, params={"q": payload})
            assert vuln_resp.status == 200, vuln_resp.body[:500]
            assert vuln_resp.body.count('"id"') == 10, (
                "vulnerable LIKE-clause SQLi cell did not leak every real seeded product against "
                f"real MariaDB: {vuln_resp.body[:1000]}"
            )
            assert secure_resp.status == 200, secure_resp.body[:500]
            assert secure_resp.body.count('"id"') == 0, (
                "secure (bound-parameter) LIKE twin unexpectedly matched a real row for the "
                f"same payload against real MariaDB: {secure_resp.body[:500]!r}"
            )
