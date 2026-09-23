"""Live-boot conformance check for PicTrail's `/post` real page (category 2
pilot, Phase C, `CC-LAB-0092`).

Real, on-host integration tests, same discipline as every other
`test_labgen_django_live_boot_*` module: real `venv`, real `pip install
django==<pinned>`, real `manage.py migrate`/`runserver`, real HTTP
requests, torn down on every exit path.

Two things this module proves that no earlier Django test does:

1. **Ground truth actually describes the real served page** -- loads
   PicTrail's own out-of-band ground truth
   (`lab/ground-truth-picktrail-django/`, D9's three-file contract) via
   `fuzzlab.labels.contract.load()` and cross-checks it against a real
   booted request at the *exact* URL/param/method the ground truth names
   -- an independent check (PA-0003/PA-0021), never a re-derivation of the
   URL from the emitter's own internals.
2. **The `PA-0034` adversarial test** `CC-LAB-0092`'s own pre-change
   review required, citing `BUG-0031` (`php_laravel`'s own first
   real-URL-serving mechanism silently hardcoded the wrong HTTP method,
   producing false ground truth) as the directly analogous precedent:
   this is the `django` emitter's *first* real-URL-pinning mechanism
   (`_REAL_PAGE_CELL_IDS`), so a mismatched-HTTP-method request against
   the pinned `/post` URL is exercised for real, not assumed safe. The
   real, observed result (found by this test, not predicted in advance):
   a clean `403` (Django's own `CsrfViewMiddleware`, since this cell's
   route method is `GET` and therefore was never decorated with
   `@csrf_exempt`) -- safe, no crash, no widened attack surface.
"""

from __future__ import annotations

import pytest

from fuzzlab.labels.contract import load as load_ground_truth
from fuzzlab.labgen.conformance.django_live_boot import DjangoLiveBootHarness, django_boot_available
from fuzzlab.labgen.emitters.django import DjangoEmitter
from fuzzlab.labgen.schema import load_manifest

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
_MANIFEST_PATH = "lab/manifests/phase_c_picktrail_post_detail.yaml"


def test_ground_truth_case_matches_the_real_served_page() -> None:
    """The `PT-0001` ground-truth case names `GET /post?id=` as a real,
    exploitable SQLi. Loads it independently (never re-deriving the URL
    from `DjangoEmitter`'s own `_ROUTE_PARAMS`/`_REAL_PAGE_CELL_IDS`
    internals) and confirms a real booted request at exactly that
    URL/param/method observes the real vulnerable-vs-not differential the
    ground truth claims."""
    ground_truth = load_ground_truth(_GROUND_TRUTH_DIR)
    case = ground_truth.case_by_id("PT-0001")
    assert case is not None, "PT-0001 must exist in the loaded ground truth"
    assert case.expected_vulnerable is True

    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, manifest.cells) as harness:
        # Independent of the emitter's own route-profile dict -- built
        # purely from the ground-truth case's own fields.
        normal_resp = harness.request(case.method, case.url, params={case.param: "1"})
        assert normal_resp.status == 200, "the real, named ground-truth URL must actually serve"

        payload_resp = harness.request(case.method, case.url, params={case.param: "1' OR '1'='1"})
        assert payload_resp.status == 500, (
            "the ground truth's own expected_vulnerable=true claim must hold at the exact "
            "URL/param/method it names -- a real syntax-breaking payload must reach a real, "
            "unparameterized sink"
        )


def test_mismatched_http_method_against_the_pinned_real_page() -> None:
    """`PA-0034` (`CC-LAB-0092`'s pre-change review, citing `BUG-0031` as
    the directly analogous precedent -- `django`'s first real-URL-pinning
    mechanism, exercised against an adversarial input orthogonal to the
    SQLi shape's own demonstration): a `POST` against the pinned `/post`
    URL (declared `GET` in both the manifest and the ground truth).
    Confirms the mechanism does not silently widen the attack surface or
    crash -- the real, observed result is a clean `403` (Django's own
    `CsrfViewMiddleware`, since a `GET`-method cell is never decorated
    with `@csrf_exempt`), not a `500` (a crash) and not a `200` (an
    unintended bypass of the route's own declared method)."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, manifest.cells) as harness:
        resp = harness.post("/post", data={"id": "1"})

    assert resp.status == 403, (
        "a POST against a GET-only pinned real page must be rejected cleanly (Django's own "
        "CSRF protection) -- never a 500 (crash) or a 200 (unintended method bypass)"
    )


def test_secure_twin_is_not_reachable_at_the_real_page_url() -> None:
    """The secure twin (`LABGEN-DJ-0008`) is deliberately not in
    `_REAL_PAGE_CELL_IDS` -- confirms it is genuinely served at its own,
    separate generic URL, never silently sharing or shadowing the real
    page's pinned `/post` URL (which would make the ground truth's own
    `expected_vulnerable=true` claim unreliable, since both twins would
    then be reachable at the same URL)."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, manifest.cells) as harness:
        vuln_resp = harness.get("/post", params={"id": "1"})
        secure_resp = harness.get("/generated/labgen_dj_0008/", params={"id": "1"})

    assert vuln_resp.status == 200
    assert secure_resp.status == 200
    # Both serve the same seeded row under normal use -- the differential
    # is only observable under the adversarial payload (proven by
    # test_ground_truth_case_matches_the_real_served_page above); this
    # test only proves the two twins are reachable at two distinct URLs.
