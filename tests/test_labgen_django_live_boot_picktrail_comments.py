"""Live-boot conformance check for PicTrail's `/post/comments` real page
(category 2 pilot, Phase C, `CC-LAB-0093`).

Real, on-host integration tests, same discipline as every other
`test_labgen_django_live_boot_*` module. Proves, for the first time in
this emitter, a real round trip through Django's own template engine
(`django.shortcuts.render()` + a real `.html` template file), not a
hand-built `HttpResponse` string:

1. **Both directions of the differential** (`CC-LAB-0093`'s own risk
   section, per `PA-0034`): the vulnerable twin's `mark_safe()` genuinely
   bypasses Django's default template auto-escaping through the *real*
   engine, **and** the secure twin's plain string is genuinely still
   protected by that same default -- not just asserting the vulnerable
   direction and assuming the secure one is fine "because it's the
   default."
2. **Ground truth cross-check** (`PT-0002`, extending the same directory
   `CC-LAB-0092` established) -- loaded independently and checked against
   a real booted request at the exact URL/param/method it names.
"""

from __future__ import annotations

import pytest

from fuzzlab.labels.contract import load as load_ground_truth
from fuzzlab.labgen.conformance.django_live_boot import DjangoLiveBootHarness, django_boot_available
from fuzzlab.labgen.emitters.django import DjangoEmitter
from fuzzlab.labgen.schema import load_manifest
from tests._django_site import assert_bare_get_gate

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
_MANIFEST_PATH = "lab/manifests/phase_c_picktrail_comments.yaml"
_XSS_PAYLOAD = "<script>alert(1)</script>"


def test_mark_safe_bypasses_autoescaping_through_the_real_template_engine() -> None:
    """The vulnerable twin's real, observed response body must contain
    the raw, unescaped payload -- proving `mark_safe()` genuinely defeats
    Django's own template auto-escaping through the real engine, not
    just in a unit-level string check."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    vuln_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0009"]
    with DjangoLiveBootHarness(emitter, vuln_cells, seed_comment=_XSS_PAYLOAD) as harness:
        resp = harness.get("/post/comments")

    assert resp.status == 200
    assert _XSS_PAYLOAD in resp.body, "the vulnerable twin must serve the raw, unescaped payload"


def test_default_autoescaping_still_protects_the_secure_twin() -> None:
    """The secure twin's real, observed response body must contain the
    real HTML-entity-escaped form -- proving Django's own default
    template auto-escaping is genuinely still in effect when the
    transform does not opt out of it (the flip side of the differential;
    not merely inferred from "no `mark_safe()` call")."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    secure_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0010"]
    with DjangoLiveBootHarness(emitter, secure_cells, seed_comment=_XSS_PAYLOAD) as harness:
        resp = harness.get("/post/comments.labgen-dj-0010")

    assert resp.status == 200
    assert _XSS_PAYLOAD not in resp.body, "the secure twin must not serve the raw payload"
    assert "&lt;script&gt;" in resp.body, "the secure twin must serve the real HTML-entity-escaped form"


def test_ground_truth_case_pt_0002_matches_the_real_served_page() -> None:
    """`PT-0002` names `GET /post/comments` as a real, exploitable
    stored-XSS. Loaded independently (never re-deriving the URL from
    `DjangoEmitter`'s own `_ROUTE_PARAMS`/`_REAL_PAGE_CELL_IDS`
    internals) and confirmed against a real booted request at exactly
    that URL, seeded with the same adversarial payload the differential
    tests above use."""
    ground_truth = load_ground_truth(_GROUND_TRUTH_DIR)
    case = ground_truth.case_by_id("PT-0002")
    assert case is not None, "PT-0002 must exist in the loaded ground truth"
    assert case.expected_vulnerable is True
    assert case.vuln_class == "xss-stored"

    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    vuln_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0009"]
    with DjangoLiveBootHarness(emitter, vuln_cells, seed_comment=_XSS_PAYLOAD) as harness:
        resp = harness.request(case.method, case.url)

    assert resp.status == 200
    assert _XSS_PAYLOAD in resp.body, (
        "the ground truth's own expected_vulnerable=true claim must hold at the exact "
        "URL/method it names"
    )


def test_comments_page_gate_bare_get_and_shared_layout() -> None:
    """CC-LAB-0242's per-page gate for `/post/comments` (plan §5 step 2):
    the page reads no request parameter (its value is the stored comment),
    so a bare `GET` returns 200 on both twins; the page now renders inside
    PicTrail's shared layout (`_COMMENT_TEMPLATE_HTML` extends
    `layouts/site.html`) instead of a bare `<div>` fragment; and with a
    benign seeded comment the vulnerable URL and the secure twin's own
    twin-suffixed URL serve byte-identical pages (R1)."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, manifest.cells) as harness:
        assert_bare_get_gate(
            harness, "/post/comments", "/post/comments.labgen-dj-0010", status=200, title="Comments · PicTrail"
        )
        resp = harness.get("/post/comments")
    assert '<div class="comment">Great shot! Love the lighting.</div>' in resp.body, resp.body[:2000]
