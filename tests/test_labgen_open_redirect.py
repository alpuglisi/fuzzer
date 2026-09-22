"""The `open_redirect` shape (CWE-601, `CC-LAB-0090`/`FR-LAB-64`/`FR-LAB-65`)
-- category 5's (Travel/booking/marketplaces) Booking.com pilot, first
increment. `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5.

Mirrors `tests/test_labgen_php_laravel_harder_shapes.py`'s Tier 0/Tier 3/
CLI-check structure (the dedicated `php_laravel` test file -- *not*
`tests/test_labgen_mass_assignment.py`, whose Laravel-relevant section is
verdict-only; see this component's own `CC-LAB-0090` change-control entry
for why that citation was corrected during review) over the new, standalone
manifest, plus a real live-boot proof of the actual adversarial bypass
shapes the new `redirect_target_allowlist` transform is meant to close
(matching this component's `CC-LAB-0069` evidentiary bar: a real HTTP round
trip, not just a structural/lint pass), and a smoke test that this app's own
ground-truth directory (`lab/ground-truth-booking-clone/`) loads
independently of the default one.
"""

from __future__ import annotations

import dataclasses
import shutil
from urllib.parse import urlsplit

import pytest

from fuzzlab.labels import contract as labels_contract
from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.schema import Pipeline, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/booking_open_redirect_sample.yaml"
GROUND_TRUTH_DIR = "lab/ground-truth-booking-clone"

#: The two payloads verified for real (via a live boot of this exact
#: manifest, not assumed) to actually reach `evil.example` through Laravel's
#: own `redirect()`/`UrlGenerator::isValidUrl()` helper when no allowlist
#: runs -- a protocol-relative target and a scheme-qualified absolute URL,
#: both of which `isValidUrl()` recognizes as "already a URL" and passes
#: through unchanged. This is the real vulnerable/secure differential this
#: test proves, matching this component's `CC-LAB-0069` evidentiary bar.
EXPLOITABLE_RETURN_TO_PAYLOADS: tuple[str, ...] = (
    "//evil.example",
    "https://evil.example",
)

#: Two more adversarial-looking shapes that, verified for real against this
#: exact live-booted app, Laravel's own `redirect()` helper already resolves
#: to a same-origin URL regardless of any allowlist -- `isValidUrl()` does
#: not recognize a bare backslash-prefixed value or a `javascript:` scheme
#: as "already a URL", so both are rewritten as an ordinary relative *path*
#: on this app's own host before either twin's transform ever matters (a
#: `javascript:` value in an HTTP `Location:` header is also not a
#: browser-exploitable sink shape in the first place -- that scheme matters
#: for an `href`/`src` attribute sink, not a redirect response). Kept as a
#: negative control: both twins must behave identically and safely here, so
#: this test does not silently rely on Laravel's own behavior for these two
#: without checking it.
NON_EXPLOITABLE_ADVERSARIAL_PAYLOADS: tuple[str, ...] = (
    "/\\evil.example",
    "javascript:alert(1)",
)

#: A same-origin relative path -- must pass through and land on the real
#: booked destination on both twins (the allowlist is meant to reject an
#: attacker-controlled destination, not every redirect target at all).
BENIGN_RETURN_TO_PAYLOAD = "/booking/confirmation?ref=abc123"


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
    vulnerable = _cell(manifest, "LABGEN-BC-0001")
    secure = _cell(manifest, "LABGEN-BC-0002")
    assert verdict(vulnerable.transform, vulnerable.sink_context, matrix).verdict == "VULNERABLE"
    assert verdict(secure.transform, secure.sink_context, matrix).verdict == "SECURE"


def test_every_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        # Must not raise: an unregistered shape fails loud by design.
        static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)


def test_the_verdict_agrees_with_this_apps_own_ground_truth(manifest) -> None:
    """The one ground-truth case this increment authors (`BKNG-0001`) names
    the vulnerable cell's served URL/param and `expected_vulnerable: true`
    -- cross-checked here against the real `verdict()` derivation, not just
    asserted independently of it."""
    gt = labels_contract.load(GROUND_TRUTH_DIR)
    case = gt.case_by_id("BKNG-0001")
    assert case is not None
    vulnerable = _cell(manifest, "LABGEN-BC-0001")
    assert case.expected_vulnerable is True
    assert case.url == served_url_for(vulnerable)
    assert case.param == "return_to"


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
# Ground truth: this app's own directory loads independently of the default
# one (FR-LAB-65 -- the first test in this repo to exercise two
# `ground_truth_dir`s side by side).
# ---------------------------------------------------------------------------


def test_the_new_ground_truth_directory_loads_independently_of_the_default_one() -> None:
    default_gt = labels_contract.load("lab/ground-truth")
    booking_gt = labels_contract.load(GROUND_TRUTH_DIR)

    assert booking_gt.target == "php_laravel"
    assert [c.case_id for c in booking_gt.cases] == ["BKNG-0001"]
    # Neither directory's case IDs bleed into the other's.
    assert "BKNG-0001" not in {c.case_id for c in default_gt.cases}
    assert not any(c.case_id.startswith("BKNG-") for c in default_gt.cases)
    assert default_gt.case_by_id("PFF-0001") is not None  # the default dir is unaffected


# ---------------------------------------------------------------------------
# Real live-boot proof (CC-LAB-0069's evidentiary bar): a real HTTP round
# trip against both twins, with real adversarial payloads, reading the real
# (unfollowed) `Location:` header back.
# ---------------------------------------------------------------------------

pytestmark_live_boot = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot environment not available (composer/php on PATH and a real, bounded "
        "Packagist round trip -- PA-0005; see live_boot.live_boot_available())"
    ),
)


@pytestmark_live_boot
def test_live_boot_redirect_manifest_blocks_the_bypass_shapes_the_allowlist_is_meant_to_catch() -> None:
    emitter = LaravelEmitter()
    manifest = load_manifest(MANIFEST_PATH)
    vulnerable = _cell(manifest, "LABGEN-BC-0001")
    secure = _cell(manifest, "LABGEN-BC-0002")
    vuln_url = served_url_for(vulnerable)
    secure_url = served_url_for(secure)

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        # The harness's own host:port, established from a known-benign
        # request rather than reaching into the harness's private port
        # field -- the reference every "stayed on this origin" assertion
        # below compares against.
        own_netloc = urlsplit(harness.get(vuln_url, params={"return_to": "/"}).headers["Location"]).netloc

        for payload in EXPLOITABLE_RETURN_TO_PAYLOADS:
            vuln_resp = harness.get(vuln_url, params={"return_to": payload})
            secure_resp = harness.get(secure_url, params={"return_to": payload})

            # The vulnerable twin issues a real 3xx redirect straight at the
            # attacker-controlled destination, unvalidated -- Laravel's own
            # `redirect()` helper recognizes both of this payload set as
            # already-a-URL and passes them through verbatim.
            assert 300 <= vuln_resp.status < 400, (
                f"{payload!r}: vulnerable twin did not redirect at all (status {vuln_resp.status})"
            )
            vuln_netloc = urlsplit(vuln_resp.headers.get("Location", "")).netloc
            assert vuln_netloc == "evil.example", (
                f"{payload!r}: vulnerable twin's real Location header was "
                f"{vuln_resp.headers.get('Location', '')!r} (netloc {vuln_netloc!r}), expected it to "
                "reach the attacker's host -- this is this test's own proof that the vulnerable "
                "twin is actually exploitable, not just structurally different"
            )

            # The secure twin's allowlist collapses every exploitable target
            # to a same-origin destination -- never the attacker's host.
            assert 300 <= secure_resp.status < 400, (
                f"{payload!r}: secure twin did not redirect at all (status {secure_resp.status})"
            )
            secure_url_parts = urlsplit(secure_resp.headers.get("Location", ""))
            assert secure_url_parts.netloc == own_netloc, (
                f"{payload!r}: secure twin's real Location header was "
                f"{secure_resp.headers.get('Location', '')!r} (netloc {secure_url_parts.netloc!r}, "
                f"expected {own_netloc!r}) -- an allowlist bypass would show up here as the "
                "attacker's destination leaking through"
            )
            assert secure_url_parts.path in ("", "/"), (
                f"{payload!r}: secure twin's fallback path was {secure_url_parts.path!r}, "
                "expected the safe default root path"
            )

        # Two more adversarial-looking payloads that Laravel's own
        # `redirect()` helper already resolves safely regardless of the
        # allowlist (verified for real -- see this constant's own docstring)
        # -- a negative control: neither twin diverges from "stays on this
        # origin," proven by netloc, not by a fragile substring check (the
        # literal string "evil.example" legitimately appears in the *path*
        # of these two payloads' safe, same-origin resolution).
        for payload in NON_EXPLOITABLE_ADVERSARIAL_PAYLOADS:
            vuln_resp = harness.get(vuln_url, params={"return_to": payload})
            secure_resp = harness.get(secure_url, params={"return_to": payload})
            assert urlsplit(vuln_resp.headers.get("Location", "")).netloc == own_netloc, payload
            assert urlsplit(secure_resp.headers.get("Location", "")).netloc == own_netloc, payload

        # A benign, same-origin target reaches the real booked destination
        # on both twins -- the allowlist is not "reject every redirect."
        vuln_benign = harness.get(vuln_url, params={"return_to": BENIGN_RETURN_TO_PAYLOAD})
        secure_benign = harness.get(secure_url, params={"return_to": BENIGN_RETURN_TO_PAYLOAD})
        assert BENIGN_RETURN_TO_PAYLOAD in vuln_benign.headers.get("Location", "")
        assert BENIGN_RETURN_TO_PAYLOAD in secure_benign.headers.get("Location", "")
