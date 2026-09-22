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
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot harness requires composer + php on PATH and real Packagist "
        "network reachability (PA-0005) -- see live_boot.live_boot_available()"
    ),
)


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
        assert vuln_resp.body.count('"id"') >= 2, (
            "vulnerable cell did not return multiple rows for a boolean-injection "
            f"payload -- expected the raw-concatenation SQLi to leak every row: {vuln_resp.body[:1000]}"
        )
        secure_row_count = secure_resp.body.count('"id"')
        assert secure_row_count < vuln_resp.body.count('"id"'), (
            "secure (bound-parameter) twin did not behave differently from the vulnerable twin "
            f"for the same payload: vulnerable={vuln_resp.body[:500]!r} secure={secure_resp.body[:500]!r}"
        )
