"""Live-boot conformance check for PicTrail's `/settings` real page
(category 2 pilot, Phase C, `CC-LAB-0095`).

Real, on-host integration tests, same discipline as every other
`test_labgen_django_live_boot_*` module. Proves, for the first time in
this emitter, a genuinely new *source* shape (the whole POST body as a
dict, not one named parameter) feeding a mass-assignment (CWE-915) sink:

1. **Both directions of the differential** (`CC-LAB-0095`'s own risk
   section, per `PA-0034`): the vulnerable twin's `unfiltered_body_update`
   transform really lets a POST body set the privileged `is_verified`
   profile column the real settings form never exposes -- verified by
   reading the seeded DB row back, not just by inspecting the response
   body -- **and** the secure twin's `runtime_field_allowlist` transform
   really blocks that same payload while still applying the legitimate
   `bio` field, proven together in one request so the test can't pass by
   accident (a transform that dropped every field would also "block"
   `is_verified`, but would fail the `bio`-still-updates half).
2. **Ground truth cross-check** (`PT-0004`, extending the same directory
   `CC-LAB-0092`/`CC-LAB-0093`/`CC-LAB-0094` established).
"""

from __future__ import annotations

import pytest

from fuzzlab.labels.contract import load as load_ground_truth
from fuzzlab.labgen.conformance.django_live_boot import DjangoLiveBootHarness, django_boot_available
from fuzzlab.labgen.emitters.django import DjangoEmitter
from fuzzlab.labgen.schema import load_manifest
from tests._django_site import assert_bare_get_gate, assert_in_picktrail_layout

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
_MANIFEST_PATH = "lab/manifests/phase_c_picktrail_settings.yaml"
_PAYLOAD = {"bio": "updated bio text", "is_verified": "1"}


def test_vulnerable_twin_mass_assigns_the_privileged_column() -> None:
    """A single POST carrying both a legitimate field (`bio`) and a
    privileged one the real form never exposes (`is_verified`) must set
    *both* real DB columns on the vulnerable twin -- read back from the
    harness's own seeded database, not inferred from the response body
    alone."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    vuln_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0013"]
    with DjangoLiveBootHarness(emitter, vuln_cells) as harness:
        resp = harness.post("/settings", data=_PAYLOAD)
        rows = harness.query_db("SELECT bio, is_verified FROM profiles WHERE id = 1")

    assert resp.status == 200
    assert rows == [{"bio": "updated bio text", "is_verified": 1}], (
        "the vulnerable twin must genuinely persist both the legitimate field and the "
        f"privileged one an attacker smuggled in -- got {rows!r}"
    )


def test_secure_twin_blocks_the_privileged_field_but_still_applies_bio() -> None:
    """The identical payload against the secure twin must update `bio`
    (proving the allowlist isn't just rejecting the whole request) while
    leaving `is_verified` at its seeded default -- both checked together,
    so a transform that dropped every field can't pass this test by
    accident."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    secure_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0014"]
    with DjangoLiveBootHarness(emitter, secure_cells) as harness:
        resp = harness.post("/settings.labgen-dj-0014", data=_PAYLOAD)
        rows = harness.query_db("SELECT bio, is_verified FROM profiles WHERE id = 1")

    assert resp.status == 200
    assert rows == [{"bio": "updated bio text", "is_verified": 0}], (
        "the secure twin must apply the legitimate field while leaving the privileged "
        f"one untouched -- got {rows!r}"
    )


def test_ground_truth_case_pt_0004_matches_the_real_served_page() -> None:
    """`PT-0004` names `POST /settings` as a real, exploitable
    mass-assignment. Loaded independently (never re-deriving the URL from
    `DjangoEmitter`'s own `_ROUTE_PARAMS`/`_REAL_PAGE_CELL_IDS`
    internals) and confirmed against a real booted request at exactly
    that URL, with the same privileged-field payload the differential
    tests above use."""
    ground_truth = load_ground_truth(_GROUND_TRUTH_DIR)
    case = ground_truth.case_by_id("PT-0004")
    assert case is not None, "PT-0004 must exist in the loaded ground truth"
    assert case.expected_vulnerable is True
    assert case.vuln_class == "mass_assignment"
    assert case.sink_context == "mass_assignment"

    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    vuln_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0013"]
    with DjangoLiveBootHarness(emitter, vuln_cells) as harness:
        resp = harness.request(case.method, case.url, data=_PAYLOAD)
        rows = harness.query_db("SELECT is_verified FROM profiles WHERE id = 1")

    assert resp.status == 200
    assert rows == [{"is_verified": 1}], (
        "the ground truth's own expected_vulnerable=true claim must hold at the exact "
        "URL/method/param it names"
    )


def test_settings_page_gate_get_renders_the_form_post_renders_the_saved_page() -> None:
    """CC-LAB-0242's per-page gate for `/settings` (plan §5 step 2): the
    page reads the whole POST body, not a named GET parameter, so a bare
    `GET` never reaches the sink -- it renders the real settings form (200,
    its one publicly-settable field `bio`, pre-filled from the stored
    profile) inside the shared layout, byte-identical between the
    vulnerable URL and its secure twin's own URL (R1), and writes nothing.
    A POST processes the form and re-renders the page (real HTML, no longer
    a JSON body) with a saved notice naming the fields actually written."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, manifest.cells) as harness:
        before = harness.query_db("SELECT bio, is_verified FROM profiles WHERE id = 1")
        assert_bare_get_gate(
            harness, "/settings", "/settings.labgen-dj-0014", status=200, title="Account settings · PicTrail"
        )
        form = harness.get("/settings")
        assert '<form method="post" action="">' in form.body, form.body[:2000]
        assert 'name="bio"' in form.body and "is_verified" not in form.body, form.body[:2000]
        assert harness.query_db("SELECT bio, is_verified FROM profiles WHERE id = 1") == before

        saved = harness.post("/settings.labgen-dj-0014", data=_PAYLOAD)
    assert saved.status == 200, saved.body[:500]
    assert_in_picktrail_layout(saved, "Account settings · PicTrail")
    assert 'data-updated-fields="bio"' in saved.body, saved.body[:2000]
    assert ">updated bio text</textarea>" in saved.body, saved.body[:2000]
