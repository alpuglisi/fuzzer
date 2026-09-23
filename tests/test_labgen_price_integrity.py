"""The `price_integrity_bypass` shape (`CC-LAB-0212`/`FR-LAB-82`/`FR-LAB-83`)
-- category 5's (Travel/booking/marketplaces) Booking.com pilot, third
increment (first: `open_redirect`, `CC-LAB-0210`; second:
`csv_formula_injection`, `CC-LAB-0211`).
`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5.

Reuses `lab/safety_matrix.yaml`'s pre-existing `price_integrity_bypass`
concern / `payment_charge_amount` sink family (`CC-LAB-0063`), first
rendered by any emitter here. Mirrors `tests/test_labgen_csv_export_injection.py`'s
structure (verdict derivation, static-precheck, Tier 0/3, CLI `--check`,
ground-truth cross-check), plus a real live-boot proof that reads the
actual inserted `bookings` row back via `LiveBootHarness.query_db` (the
same DB-introspection mechanism `CC-LAB-0056`'s real `register.php`
`INSERT` proof already established) -- the vulnerable twin stores the
attacker's own submitted amount; the secure twin always stores its
server-side rate-table lookup, regardless of what the client sent.
"""

from __future__ import annotations

import dataclasses
import shutil

import pytest

from fuzzlab.labels import contract as labels_contract
from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.schema import Pipeline, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/booking_price_integrity_sample.yaml"
GROUND_TRUTH_DIR = "lab/ground-truth-booking-clone"

#: An attacker-controlled amount, far below any real room rate -- the real
#: differential this test proves: does the stored `total_amount` reflect
#: this value (vulnerable) or the server's own rate-table lookup (secure)?
ATTACKER_AMOUNT = "0.01"

#: The secure twin's fallback rate for an unrecognized/absent `room_type`
#: (`default_room_type: "standard"` in the page profile) -- what the secure
#: twin's stored `total_amount` must equal regardless of `ATTACKER_AMOUNT`.
EXPECTED_SECURE_AMOUNT = 89.00


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture()
def emitter():
    return LaravelEmitter()


def _cell(manifest, cell_id: str):
    return next(c for c in manifest.cells if c.cell_id == cell_id)


# ---------------------------------------------------------------------------
# Verdict / matrix scorability
# ---------------------------------------------------------------------------


def test_every_cell_derives_its_expected_verdict(manifest, matrix) -> None:
    vulnerable = _cell(manifest, "LABGEN-BC-0005")
    secure = _cell(manifest, "LABGEN-BC-0006")
    assert verdict(vulnerable.transform, vulnerable.sink_context, matrix).verdict == "VULNERABLE"
    assert verdict(secure.transform, secure.sink_context, matrix).verdict == "SECURE"


def test_every_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        # Must not raise: an unregistered shape fails loud by design.
        static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)


def test_the_verdict_agrees_with_this_apps_own_ground_truth(manifest) -> None:
    """`BKNG-0003` (appended to this app's existing ground-truth directory)
    names the vulnerable cell's served URL/param and
    `expected_vulnerable: true` -- cross-checked here against the real
    `verdict()` derivation, not just asserted independently of it."""
    gt = labels_contract.load(GROUND_TRUTH_DIR)
    case = gt.case_by_id("BKNG-0003")
    assert case is not None
    vulnerable = _cell(manifest, "LABGEN-BC-0005")
    assert case.expected_vulnerable is True
    assert case.url == served_url_for(vulnerable)
    assert case.param == "amount"
    # This app's first two cases are unaffected by this increment's addition.
    assert gt.case_by_id("BKNG-0001") is not None
    assert gt.case_by_id("BKNG-0002") is not None


# ---------------------------------------------------------------------------
# Tier 0 / Tier 3
# ---------------------------------------------------------------------------


def test_tier3_whole_sample_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, manifest.cells)  # must not raise


def test_tier3_renders_one_unique_path_per_emitted_file(emitter, manifest) -> None:
    tree = tier3.render_whole_sample(emitter, manifest.cells)
    expected = sum(len(emitter.render(cell)) for cell in manifest.cells)
    assert len(tree) == expected


def test_tier0_minimal_pair_holds_between_each_cell_and_its_weakened_twin(emitter, manifest) -> None:
    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        if not cell.transform.ops:
            continue
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_cell(emitter, manifest) -> None:
    for cell in manifest.cells:
        for result in tier0.lint_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"


def test_cli_check_passes_end_to_end_on_the_new_manifest(tmp_path) -> None:
    from fuzzlab.labgen import cli as labgen_cli

    assert (
        labgen_cli.main(
            ["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--emitter", "php_laravel", "--check"]
        )
        == 0
    )


# ---------------------------------------------------------------------------
# Real live-boot proof: a real HTTP POST against both twins with an
# attacker-controlled amount, reading the real inserted `bookings` row
# back via LiveBootHarness.query_db.
# ---------------------------------------------------------------------------

pytestmark_live_boot = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot environment not available (composer/php on PATH and a real, bounded "
        "Packagist round trip -- PA-0005; see live_boot.live_boot_available())"
    ),
)


@pytestmark_live_boot
def test_live_boot_price_integrity_manifest_ignores_the_client_amount_on_the_secure_twin() -> None:
    emitter = LaravelEmitter()
    manifest = load_manifest(MANIFEST_PATH)
    vulnerable = _cell(manifest, "LABGEN-BC-0005")
    secure = _cell(manifest, "LABGEN-BC-0006")
    vuln_url = served_url_for(vulnerable)
    secure_url = served_url_for(secure)

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        # Each twin's row is read back immediately after its own POST --
        # both twins write to the same `bookings` table, so querying only
        # after *both* requests would just read the most recent row twice.
        vuln_resp = harness.post(vuln_url, data={"amount": ATTACKER_AMOUNT})
        assert vuln_resp.status == 200, f"vulnerable twin did not return 200 (status {vuln_resp.status})"

        # The vulnerable twin's real HTTP response already reflects the
        # attacker's amount (proving the endpoint accepted it at all) --
        # $request->input() yields a string, so Laravel's JSON encoder
        # quotes it verbatim.
        assert f'"charged_amount":"{ATTACKER_AMOUNT}"' in vuln_resp.body.replace(" ", ""), vuln_resp.body

        # ...and the real database row it wrote is checked directly, not
        # inferred from the response alone (CC-LAB-0056's own discipline):
        vuln_rows = harness.query_db(
            "SELECT total_amount FROM bookings ORDER BY id DESC LIMIT 1"
        )
        assert vuln_rows, "vulnerable twin's POST did not insert a bookings row at all"
        assert vuln_rows[0]["total_amount"] == float(ATTACKER_AMOUNT), (
            f"vulnerable twin's real stored total_amount was {vuln_rows[0]['total_amount']!r}, "
            f"expected the attacker's own submitted amount {ATTACKER_AMOUNT!r} -- this is this "
            "test's own proof that the vulnerable twin is actually exploitable, not just "
            "structurally different"
        )

        # The secure twin's real stored row ignores the same attacker
        # amount entirely and reflects its own server-side rate lookup.
        secure_resp = harness.post(secure_url, data={"amount": ATTACKER_AMOUNT})
        assert secure_resp.status == 200, f"secure twin did not return 200 (status {secure_resp.status})"
        secure_rows = harness.query_db(
            "SELECT total_amount FROM bookings ORDER BY id DESC LIMIT 1"
        )
        assert secure_rows, "secure twin's POST did not insert a bookings row at all"
        assert secure_rows[0]["total_amount"] == EXPECTED_SECURE_AMOUNT, (
            f"secure twin's real stored total_amount was {secure_rows[0]['total_amount']!r}, "
            f"expected the server's own rate-table lookup {EXPECTED_SECURE_AMOUNT!r} -- a "
            "regression here would show up as the attacker's submitted amount leaking through"
        )
        assert secure_rows[0]["total_amount"] != float(ATTACKER_AMOUNT)

        # A recognized, non-default room type also reaches its own real
        # rate, proving the lookup is genuinely data-driven, not a
        # disguised constant that happens to equal the default.
        secure_deluxe_resp = harness.post(
            secure_url, data={"amount": ATTACKER_AMOUNT, "room_type": "deluxe"}
        )
        assert secure_deluxe_resp.status == 200
        deluxe_rows = harness.query_db("SELECT total_amount FROM bookings ORDER BY id DESC LIMIT 1")
        assert deluxe_rows[0]["total_amount"] == 149.00
