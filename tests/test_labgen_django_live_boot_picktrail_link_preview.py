"""Live-boot conformance check for PicTrail's `/upload/link-preview` real
page (category 2 pilot, Phase C, `CC-LAB-0094`).

Real, on-host integration tests, same discipline as every other
`test_labgen_django_live_boot_*` module. Proves, for the first time in
this emitter, a genuinely new sink *category* -- outbound server-side HTTP
fetch (SSRF, CWE-918), ported from the already-reviewed corpus example
(`docs/research/corpus-examples/ssrf/python/{vulnerable,idiomatic}-oembed-
unfurl-4.py`) almost verbatim:

1. **Both directions of the differential** (`CC-LAB-0094`'s own risk
   section, per `PA-0034`): the vulnerable twin's `requests.get()` really
   reaches a local "internal service" fixture (standing in for a real
   internal-only service a public-facing link-preview feature should
   never be able to reach), **and** the secure twin's
   `scheme_and_resolved_ip_allowlist` transform really blocks that same
   payload via the *resolved-IP* check (not incidentally by the scheme
   check -- both schemes are allowed, so only the resolved-IP check can
   be doing the blocking).
2. **The `PA-0034` adversarial angle**: a well-formed, allowlisted URL
   (a real, public, JSON-returning endpoint) must still succeed on the
   secure twin -- proving the allowlist doesn't fail closed on
   *everything*. Uses :func:`external_http_probe` (`PA-0035`-compliant: a
   real, dedicated capability probe against the *exact* URL this test
   fetches, never the PyPI-reachability probe `django_boot_available()`
   already depends on for an unrelated operation) to skip this one test,
   independently of the other tests in this module, when that specific
   external endpoint is not reachable from this environment.
3. **Ground truth cross-check** (`PT-0003`, extending the same directory
   `CC-LAB-0092`/`CC-LAB-0093` established).
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.labels.contract import load as load_ground_truth
from fuzzlab.labgen.conformance.django_live_boot import (
    DjangoLiveBootHarness,
    InternalServiceFixture,
    INTERNAL_SERVICE_SECRET,
    django_boot_available,
    external_http_probe,
)
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
_MANIFEST_PATH = "lab/manifests/phase_c_picktrail_link_preview.yaml"

#: A real, public, dedicated test endpoint that returns fixed JSON --
#: distinct from `django_boot_available()`'s own PyPI-reachability probe
#: target, since this test needs a URL that both resolves to a real,
#: non-private/non-loopback IP *and* returns valid JSON (the sink calls
#: `response.json()` unconditionally, matching the corpus example it
#: ports).
_ALLOWLISTED_JSON_URL = "https://httpbin.org/json"


def test_vulnerable_twin_really_reaches_the_internal_service() -> None:
    """The vulnerable twin's `unchecked_url_fetch` transform performs no
    validation -- a real request pointing it at the internal-service
    fixture's own loopback URL must genuinely reach that fixture and
    return its secret marker, proving the SSRF is real (not just "no
    validation code is present" at a source-level glance)."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    vuln_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0011"]
    with InternalServiceFixture() as internal, DjangoLiveBootHarness(emitter, vuln_cells) as harness:
        resp = harness.get("/upload/link-preview", params={"url": internal.url})

    assert resp.status == 200
    assert INTERNAL_SERVICE_SECRET in resp.body, (
        "the vulnerable twin must genuinely reach the internal-service fixture and "
        "relay its secret marker back in the response"
    )


def test_secure_twin_blocks_the_same_payload_via_the_resolved_ip_check() -> None:
    """The identical payload against the secure twin must be rejected --
    and, because `ALLOWED_SCHEMES` includes both `http` and `https`
    (`CC-LAB-0094`'s own deliberate adaptation from the corpus example),
    the only thing that can be blocking a `http://127.0.0.1:<port>/...`
    payload is the *resolved-IP* check, not the scheme check -- proving
    the actually-interesting defense, not a coincidental one. Rejection
    surfaces as a real Django 500 (the transform's `ValueError`
    propagating, `DEBUG=False`-safe, no stack-trace leak -- the same
    mechanism `CC-LAB-0090`'s own test already proved)."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    secure_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0012"]
    with InternalServiceFixture() as internal, DjangoLiveBootHarness(emitter, secure_cells) as harness:
        resp = harness.get("/upload/link-preview.labgen-dj-0012", params={"url": internal.url})

    assert resp.status == 500
    assert INTERNAL_SERVICE_SECRET not in resp.body, (
        "the secure twin must never relay the internal service's response back to the caller"
    )


@pytest.mark.skipif(
    not external_http_probe(_ALLOWLISTED_JSON_URL),
    reason=(
        f"real network reachability to {_ALLOWLISTED_JSON_URL} is required for this "
        "PA-0034 adversarial-direction test (PA-0035: a dedicated probe against the exact "
        "URL this test fetches, not django_boot_available()'s own PyPI probe)"
    ),
)
def test_secure_twin_still_allows_a_well_formed_allowlisted_url() -> None:
    """`PA-0034`: the secure twin's allowlist must not fail closed on
    *everything* -- a real, public, `https://` URL resolving to a real,
    non-private IP must still succeed, proving the resolved-IP check is
    a genuine allowlist, not a blanket deny disguised as one."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    secure_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0012"]
    with DjangoLiveBootHarness(emitter, secure_cells) as harness:
        resp = harness.get("/upload/link-preview.labgen-dj-0012", params={"url": _ALLOWLISTED_JSON_URL})

    assert resp.status == 200, (
        "a well-formed, allowlisted URL must still succeed on the secure twin -- "
        f"got {resp.status}: {resp.body[:500]!r}"
    )


def test_ground_truth_case_pt_0003_matches_the_real_served_page() -> None:
    """`PT-0003` names `GET /upload/link-preview` as a real, exploitable
    SSRF. Loaded independently (never re-deriving the URL from
    `DjangoEmitter`'s own `_ROUTE_PARAMS`/`_REAL_PAGE_CELL_IDS`
    internals) and confirmed against a real booted request at exactly
    that URL, pointed at the internal-service fixture."""
    ground_truth = load_ground_truth(_GROUND_TRUTH_DIR)
    case = ground_truth.case_by_id("PT-0003")
    assert case is not None, "PT-0003 must exist in the loaded ground truth"
    assert case.expected_vulnerable is True
    assert case.vuln_class == "ssrf"
    assert case.sink_context == "network"

    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    vuln_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0011"]
    with InternalServiceFixture() as internal, DjangoLiveBootHarness(emitter, vuln_cells) as harness:
        resp = harness.request(case.method, case.url, params={case.param: internal.url})

    assert resp.status == 200
    assert INTERNAL_SERVICE_SECRET in resp.body, (
        "the ground truth's own expected_vulnerable=true claim must hold at the exact "
        "URL/method/param it names"
    )


def test_link_preview_bare_get_is_a_handled_400_before_the_sink_and_has_a_client_page() -> None:
    """CC-LAB-0242 (plan §2c/§2d, R4): `/upload/link-preview` stays a JSON
    `api` (wire contract unchanged), so it gets no layout -- but a bare
    `GET` with no `url` must be a handled 4xx *before* the sink runs: the
    corpus source it ports (`vulnerable-oembed-unfurl-4.py`'s
    `unfurl_link(message_url: str)`) defines no default URL, and any
    default would make the vulnerable twin fetch it. It used to reach
    `requests.get(None)` and 500 on the vulnerable twin (BUG-0052). An
    empty `?url=` is treated the same. Both twins answer the identical
    JSON 400 (R1). The API's own browser client page, `/upload`, renders
    inside the shared layout and calls the API with `fetch()`."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, manifest.cells) as harness:
        assert_bare_get_gate(
            harness, "/upload/link-preview", "/upload/link-preview.labgen-dj-0012", status=400, title=None
        )
        bare = harness.get("/upload/link-preview")
        empty = harness.get("/upload/link-preview", params={"url": ""})
        client = harness.get("/upload")
    assert json.loads(bare.body) == {"error": "missing required parameter: url"}, bare.body
    assert empty.status == 400 and empty.body == bare.body, (empty.status, empty.body)
    assert client.status == 200, client.body[:500]
    assert_in_picktrail_layout(client, "Share a link · PicTrail")
    assert 'fetch("/upload/link-preview?url=" + encodeURIComponent(url))' in client.body, client.body[:3000]
    assert '<a href="/upload/link-preview">' in client.body, client.body[:3000]
