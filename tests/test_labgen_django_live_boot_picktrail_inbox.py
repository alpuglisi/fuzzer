"""Live-boot conformance check for PicTrail's `/inbox` real page
(category 2 pilot, Phase C, `CC-LAB-0097`).

Real, on-host integration tests, same discipline as every other
`test_labgen_django_live_boot_*` module. Proves, for the first time in
this emitter, a genuinely new sink shape -- the deserialize *mechanism*
itself (pickle vs. JSON) differs between twins, not just a transform
filtering a shared sink -- and, per `PA-0034`, a real, executed
adversarial payload rather than a source-level "pickle.loads() is
present" glance:

1. **Both directions of the differential**: a real, crafted pickle
   payload whose `__reduce__` hook writes a real, checkable marker file
   during unpickling genuinely executes on the vulnerable twin -- proven
   by the marker file's own existence after the request, not merely by
   the response claiming success -- **and** the identical bytes reach
   the secure twin's `json.loads()` instead, which cannot parse pickle's
   binary protocol at all, so the marker file is never created and the
   secure twin reports a real parse failure (HTTP 400).
2. **The secure twin's own positive path, proven separately**: a
   legitimate JSON object payload must still succeed on the secure twin
   (HTTP 200, `parsed_type: "dict"`) -- proving `json_loads_type_check`
   is a real, working deserializer, not a blanket rejection that would
   trivially "block" the pickle payload too.
3. **Ground truth cross-check** (`PT-0006`, extending the same directory
   `CC-LAB-0092`/`CC-LAB-0093`/`CC-LAB-0094`/`CC-LAB-0095`/`CC-LAB-0096`
   established).
"""

from __future__ import annotations

import base64
import json
import os
import pickle
import re

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
_MANIFEST_PATH = "lab/manifests/phase_c_picktrail_inbox.yaml"


class _MarkerDropper:
    """A pickle-friendly object whose `__reduce__` hook, when unpickled,
    calls ``os.system`` to write a real marker file -- the standard,
    minimal way to prove `pickle.loads()` genuinely executed
    attacker-chosen code, not just that it returned an object.
    Deliberately reduces to `os.system` (stdlib, always resolvable by
    module+qualname) rather than a function defined in this test module
    -- the unpickling happens inside the booted app's own separate
    subprocess/venv, which has no access to this test file at all, so a
    `__reduce__` target must be something that subprocess can actually
    import."""

    def __init__(self, marker_path: str) -> None:
        self._marker_path = marker_path

    def __reduce__(self):
        return (os.system, (f"echo pwned > {self._marker_path}",))


def _pickle_payload(marker_path: str) -> str:
    return base64.b64encode(pickle.dumps(_MarkerDropper(marker_path))).decode("ascii")


def _inbox_result(body: str) -> dict:
    """CC-LAB-0242: `/inbox` re-renders the real inbox page after a POST
    (was a bare JSON body) -- the delivery result is read back from the
    page's own notice element's data attributes."""
    ok = re.search(r'data-ok="true" data-parsed-type="([^"]*)"', body)
    if ok:
        return {"ok": True, "parsed_type": ok.group(1)}
    err = re.search(r'data-ok="false" data-error="([^"]*)"', body)
    assert err, body[:2000]
    return {"ok": False, "error": err.group(1)}


def _json_payload() -> str:
    return base64.b64encode(json.dumps({"subject": "hello"}).encode("utf-8")).decode("ascii")


def test_vulnerable_twin_really_executes_the_pickled_payload(tmp_path) -> None:
    """A real, crafted pickle payload must genuinely execute its
    `__reduce__` hook inside the booted app process -- proven by the
    marker file it writes actually appearing on disk, the standard,
    unambiguous proof that `pickle.loads()` ran attacker code (not
    merely returned a benign object)."""
    marker_path = str(tmp_path / "pwned.txt")
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    vuln_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0017"]
    with DjangoLiveBootHarness(emitter, vuln_cells) as harness:
        resp = harness.post("/inbox", data={"payload": _pickle_payload(marker_path)})

    assert resp.status == 200
    body = _inbox_result(resp.body)
    assert body["ok"] is True
    with open(marker_path, encoding="utf-8") as fh:
        assert fh.read().strip() == "pwned", "the vulnerable twin must genuinely execute the pickled __reduce__ hook"


def test_secure_twin_never_executes_the_same_payload(tmp_path) -> None:
    """The identical pickle bytes against the secure twin must never
    reach `pickle.loads()` at all -- `json.loads()` cannot parse
    pickle's binary protocol, so the marker file must never be created,
    and the response must report a real parse failure."""
    marker_path = str(tmp_path / "pwned.txt")
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    secure_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0018"]
    with DjangoLiveBootHarness(emitter, secure_cells) as harness:
        resp = harness.post("/inbox.labgen-dj-0018", data={"payload": _pickle_payload(marker_path)})

    assert resp.status == 400
    body = _inbox_result(resp.body)
    assert body["ok"] is False
    assert not os.path.exists(marker_path), (
        "the secure twin must never execute the pickled payload -- the marker file must not exist"
    )


def test_secure_twin_still_accepts_a_legitimate_json_payload() -> None:
    """The secure twin's `json.loads()` path must still work for a real,
    legitimate JSON-object payload -- proving it's a genuine working
    deserializer, not a blanket rejection that would "block" the pickle
    payload above only by accident."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    secure_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0018"]
    with DjangoLiveBootHarness(emitter, secure_cells) as harness:
        resp = harness.post("/inbox.labgen-dj-0018", data={"payload": _json_payload()})

    assert resp.status == 200
    body = _inbox_result(resp.body)
    assert body == {"ok": True, "parsed_type": "dict"}


def test_ground_truth_case_pt_0006_matches_the_real_served_page(tmp_path) -> None:
    """`PT-0006` names `POST /inbox` as a real, exploitable insecure
    deserialization. Loaded independently (never re-deriving the URL
    from `DjangoEmitter`'s own `_ROUTE_PARAMS`/`_REAL_PAGE_CELL_IDS`
    internals) and confirmed against a real booted request at exactly
    that URL, with the same adversarial pickle payload the differential
    tests above use."""
    ground_truth = load_ground_truth(_GROUND_TRUTH_DIR)
    case = ground_truth.case_by_id("PT-0006")
    assert case is not None, "PT-0006 must exist in the loaded ground truth"
    assert case.expected_vulnerable is True
    assert case.vuln_class == "insecure_deserialization"
    assert case.sink_context == "deserialization"

    marker_path = str(tmp_path / "pwned.txt")
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    vuln_cells = [c for c in manifest.cells if c.cell_id == "LABGEN-DJ-0017"]
    with DjangoLiveBootHarness(emitter, vuln_cells) as harness:
        resp = harness.request(case.method, case.url, data={case.param: _pickle_payload(marker_path)})

    assert resp.status == 200
    with open(marker_path, encoding="utf-8") as fh:
        assert fh.read().strip() == "pwned", (
            "the ground truth's own expected_vulnerable=true claim must hold at the exact "
            "URL/method/param it names"
        )


def test_inbox_page_gate_get_renders_the_compose_form() -> None:
    """CC-LAB-0242's per-page gate for `/inbox` (plan §5 step 2): the page
    reads its `payload` from the POST body, so a bare `GET` never reaches
    the deserializer -- it renders the inbox page with its compose form
    (200; it used to fall through to the sink and answer a JSON 400) inside
    the shared layout, byte-identical between the vulnerable URL and its
    secure twin's own URL (R1). A POST re-renders the same page with a
    delivered/rejected notice (real HTML, no longer a JSON body)."""
    manifest = load_manifest(_MANIFEST_PATH)
    emitter = DjangoEmitter()
    with DjangoLiveBootHarness(emitter, manifest.cells) as harness:
        assert_bare_get_gate(harness, "/inbox", "/inbox.labgen-dj-0018", status=200, title="Inbox · PicTrail")
        page = harness.get("/inbox")
        assert '<form method="post" action="">' in page.body and 'name="payload"' in page.body, page.body[:2000]
        delivered = harness.post("/inbox.labgen-dj-0018", data={"payload": _json_payload()})
        rejected = harness.post("/inbox.labgen-dj-0018", data={"payload": "not base64 json"})
    assert delivered.status == 200
    assert_in_picktrail_layout(delivered, "Inbox · PicTrail")
    assert _inbox_result(delivered.body) == {"ok": True, "parsed_type": "dict"}
    assert rejected.status == 400
    assert_in_picktrail_layout(rejected, "Inbox · PicTrail")
    assert _inbox_result(rejected.body)["ok"] is False
