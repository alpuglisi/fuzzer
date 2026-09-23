"""Real, executed live-boot proof for Netflix's sixth real page
(`CC-LAB-0191`, `FR-LAB-131`): this stack's first `unrestricted_file_upload`
instance, a per-profile avatar-image upload endpoint at
`POST /api/profiles/avatar`.

Mirrors `tests/test_labgen_go_live_boot.py`'s own
`test_real_boot_proves_the_unrestricted_file_upload_differential_for_both_
twins` (`CC-LAB-0186`) -- the same four-assertion shape, ported to this
stack's own `SpringBootLiveBootHarness` (one cell per harness instance, so
each twin gets its own boot, the same pattern
`tests/test_labgen_spring_boot_subscription_price_integrity_live_boot.py`
already established for a same-route twin pair).

**Filesystem safety** (mandatory, per this dispatch's own instruction):
every write this test causes lands under `SpringBootLiveBootHarness`'s own
throwaway `tempfile.TemporaryDirectory`-backed `app_dir` (the generated
handler's `static/avatars` path is relative, resolved against the booted
`java -jar` process's own `cwd`, which the harness sets to that same
`app_dir`) -- never a real, permanent, or shared path. The malicious
probe's payload is an inert `<!DOCTYPE html><p>FUZZLAB-...</p>` marker,
never an executing `<script>` tag.

A second test class (`Test...Generalizes...`) proves
`UnrestrictedFileUploadContentTypeTrustStrategy` (already built for
Twitch's `TWCH-0009`/`CC-FUZZ-0036`/`CC-AUD-0023`) needs zero new detection
code to confirm this new `spring_boot` vulnerable twin and correctly fail
closed on its secure twin -- the second proof this strategy generalizes
across stacks (the first was `go_net_http` itself; this is
`go_net_http -> spring_boot`, the same direction `CC-LAB-0187`'s own
`AccessControlIdorStrategy` proof and `CC-LAB-0188`'s own
`PriceIntegrityBypassStrategy`-generalizes-the-other-way proof already
established for other vuln classes on this exact app).

Skip-guarded (PA-0005) on `spring_boot_boot_available()`. Marked
`@pytest.mark.slow`.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.oracle.probe import Candidate
from fuzzlab.oracle.strategies import UnrestrictedFileUploadContentTypeTrustStrategy
from fuzzlab.tools.probesender import RequestsProbeSender

_MANIFEST_PATH = "lab/manifests/unrestricted_file_upload_netflix_avatar_sample.yaml"
_ROUTE = "/api/profiles/avatar"

pytestmark = [
    pytest.mark.skipif(
        not spring_boot_boot_available(),
        reason=(
            "live-boot harness requires java + mvn on PATH and real Maven Central "
            "network reachability (PA-0005) -- see live_boot_spring_boot.spring_boot_boot_available()"
        ),
    ),
    pytest.mark.slow,
]

#: An inert marker (NEVER an executing <script> tag) -- proves the response
#: genuinely serves back THIS upload's own bytes, per this dispatch's own
#: filesystem/payload-safety instruction.
_UPLOAD_MARKER = "FUZZLAB-NETFLIX-AVATAR-UPLOAD-MARKER-9c2e7a"
_INERT_HTML_PAYLOAD = f"<!DOCTYPE html><p>{_UPLOAD_MARKER}</p>".encode()

#: The real PNG magic-number signature (the 8 fixed bytes this stack's own
#: minimal magic-byte sniff keys its `image/png` check on) -- enough to
#: prove the differential (content-type sniffing, not full image-format
#: validation), the same narrow claim `go_net_http`'s own test makes.
_PNG_SIGNATURE_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24


def _cells() -> dict[str, object]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


def _multipart_upload(filename: str, content: bytes, content_type: str) -> tuple[bytes, str]:
    """Hand-encodes a real `multipart/form-data` body with one file part
    named `file` -- the exact field name `ReadUploadedAvatarFileSource`'s
    generated code reads via `request.getPart("file")`."""
    boundary = "fuzzlabnetflixavatarboundary9c2e"
    body = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f'Content-Type: {content_type}\r\n\r\n'
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def test_vulnerable_twin_serves_an_uploaded_html_file_as_text_html() -> None:
    """(a) the vulnerable twin writes an uploaded `evil.html` and serves it
    back as `text/html` (MediaTypeFactory's extension-derived type), with
    the marker intact in the body -- stored XSS via unrestricted file
    upload (CWE-434)."""
    emitter = SpringBootEmitter()
    vulnerable = _cells()["LABGEN-JV-0011"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        body, ctype = _multipart_upload("evil.html", _INERT_HTML_PAYLOAD, "text/html")
        resp = harness.request("POST", _ROUTE, data=body, content_type=ctype)
        assert resp.status == 200, f"vulnerable twin rejected the upload: {resp.body}"
        served_type = resp.headers.get("Content-Type", "")
        assert "text/html" in served_type, (
            f"vulnerable twin did not serve the upload as text/html -- got {served_type!r}"
        )
        assert _UPLOAD_MARKER in resp.body


def test_secure_twin_rejects_the_same_html_upload_outright() -> None:
    """(b) the secure twin rejects the identical `evil.html` upload
    outright (extension not on the `.png`/`.jpg`/`.jpeg` allowlist)."""
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0012"]

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        body, ctype = _multipart_upload("evil.html", _INERT_HTML_PAYLOAD, "text/html")
        resp = harness.request("POST", _ROUTE, data=body, content_type=ctype)
        assert resp.status == 415, f"secure twin did not reject a non-allowlisted extension: {resp.body}"


def test_secure_twin_rejects_a_spoofed_upload_with_a_real_extension_but_fake_bytes() -> None:
    """(c) the secure twin ALSO rejects a spoofed upload (real HTML bytes,
    but named `fake.png`, an allowlisted extension) -- proving the secure
    twin's magic-byte sniffing half, not just its extension check, is what
    actually closes the gap."""
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0012"]

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        body, ctype = _multipart_upload("fake.png", _INERT_HTML_PAYLOAD, "image/png")
        resp = harness.request("POST", _ROUTE, data=body, content_type=ctype)
        assert resp.status == 415, (
            f"secure twin let a spoofed (extension-only) upload through: {resp.body}"
        )


def test_secure_twin_accepts_a_real_png_and_serves_the_sniffed_content_type() -> None:
    """(d) the secure twin accepts a real PNG-signature upload and serves
    it back with the sniffed `image/png` content type, proving the secure
    path is not simply "reject everything"."""
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0012"]

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        body, ctype = _multipart_upload("real.png", _PNG_SIGNATURE_BYTES, "image/png")
        resp = harness.request("POST", _ROUTE, data=body, content_type=ctype)
        assert resp.status == 200, f"secure twin rejected a real PNG upload: {resp.body}"
        served_type = resp.headers.get("Content-Type", "")
        assert "image/png" in served_type, (
            f"secure twin did not serve the sniffed PNG content type -- got {served_type!r}"
        )


class TestUnrestrictedFileUploadContentTypeTrustStrategyGeneralizesToSpringBoot:
    """Proves `UnrestrictedFileUploadContentTypeTrustStrategy` needs zero
    new detection code to confirm this new `spring_boot` vulnerable twin
    and correctly fail closed on its secure twin -- the same generalization
    proof style `CC-LAB-0187`'s own `AccessControlIdorStrategy` test and
    `CC-LAB-0189`'s own `PriceIntegrityBypassStrategy` test already
    established for other vuln classes, applied here for the first time to
    this specific strategy on a second stack."""

    def test_confirms_the_vulnerable_twin(self) -> None:
        emitter = SpringBootEmitter()
        vulnerable = _cells()["LABGEN-JV-0011"]
        strategy = UnrestrictedFileUploadContentTypeTrustStrategy()
        sender = RequestsProbeSender(timeout=10.0)

        with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
            candidate = Candidate(
                url=harness.base_url + _ROUTE, param="file", method="POST", location="body",
                vuln_class="unrestricted_file_upload",
                category="unrestricted-file-upload", sink_context="fs_web_root_write",
            )
            verdict = strategy.confirm(candidate, sender)
            assert verdict is not None and verdict.confirmed
            assert verdict.vuln_class == "unrestricted_file_upload"
            # MediaTypeFactory's own extension-to-MediaType table maps
            # .svg to image/svg+xml (the strategy's own probe.svg filename)
            # -- one of the SCRIPT_EXECUTABLE_CONTENT_TYPES the strategy
            # requires for its malicious leg.
            assert verdict.evidence["served_content_type"] == "image/svg+xml"
            assert verdict.evidence["control_content_type"] == "image/png"

    def test_fails_closed_on_the_secure_twin(self) -> None:
        emitter = SpringBootEmitter()
        secure = _cells()["LABGEN-JV-0012"]
        strategy = UnrestrictedFileUploadContentTypeTrustStrategy()
        sender = RequestsProbeSender(timeout=10.0)

        with SpringBootLiveBootHarness(emitter, secure) as harness:
            candidate = Candidate(
                url=harness.base_url + _ROUTE, param="file", method="POST", location="body",
                vuln_class="unrestricted_file_upload",
                category="unrestricted-file-upload", sink_context="fs_web_root_write",
            )
            assert strategy.confirm(candidate, sender) is None
