"""Real, executed live-boot proof for Netflix's ninth real page
(`CC-LAB-0194`, `FR-LAB-149`): this stack's first `ssrf` instance, a
partner-content thumbnail-import endpoint at
`POST /api/content/thumbnail-import`.

Mirrors `tests/test_labgen_go_live_boot.py`'s own
`test_real_boot_proves_the_ssrf_ip_allowlist_specifically_not_just_the_scheme_check`/
`test_real_boot_proves_the_ssrf_strategies_generalize_to_clips_download_route`
(`CC-LAB-0172`/`CC-LAB-0185`) -- the same three-case differential (plain-HTTP
loopback accepted by the vulnerable twin; rejected by the secure twin on the
scheme check; an HTTPS loopback target ALSO rejected by the secure twin,
isolating the resolved-IP-allowlist check specifically) then a real
strategy-generalization proof, ported to this stack's own
`SpringBootLiveBootHarness` (one cell per harness instance, so each twin
gets its own boot).

**Network safety (`CLAUDE.md`'s lab-only/authorized-only discipline)**:
every fetch target in every test below is a throwaway HTTP/HTTPS listener
this test process itself starts on loopback -- never a real external or
production host.

A second test class (`Test...GeneralizesToSpringBoot`) proves
`SsrfInBandMarkerStrategy`/`SsrfOobStrategy` (already built for Twitch's
`TWCH-0002`/`TWCH-0008`/`CC-FUZZ-0031`) need zero new detection code to
confirm this new `spring_boot` vulnerable twin and correctly fail closed on
its secure twin, using a real, started `OobListener` -- the same
generalization direction (`go_net_http` -> `spring_boot`) `CC-LAB-0187`'s
own `AccessControlIdorStrategy` proof, `CC-LAB-0191`'s own
`UnrestrictedFileUploadContentTypeTrustStrategy` proof, `CC-LAB-0192`'s own
`MassAssignmentPrivilegedFieldStrategy` proof, and `CC-LAB-0193`'s own
`JwtAlgNoneConfusionStrategy` proof already established for other vuln
classes on this exact app.

Skip-guarded (PA-0005) on `spring_boot_boot_available()`. Marked
`@pytest.mark.slow`.
"""

from __future__ import annotations

import http.server
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest

_MANIFEST_PATH = "lab/manifests/ssrf_netflix_thumbnail_sample.yaml"
_ROUTE = "/api/content/thumbnail-import"

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


def _cells() -> dict[str, object]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


# -- throwaway loopback fetch targets, this test process's own -----------------


class _ThumbHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib override
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"thumb-bytes")

    def log_message(self, *args: object) -> None:  # silence per-request stderr noise
        pass


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_plain_http_listener() -> http.server.HTTPServer:
    """A throwaway plain-HTTP loopback listener this test process itself
    starts and owns -- never a real external host, per `CLAUDE.md`'s own
    lab-only/authorized-only safety discipline (mirrors `CC-LAB-0172`'s
    own `go_net_http` precedent, `tests/test_labgen_go_live_boot.py`)."""
    server = http.server.HTTPServer(("127.0.0.1", _free_loopback_port()), _ThumbHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _start_https_loopback_listener(cert_dir: Path) -> http.server.HTTPServer:
    """Same as :func:`_start_plain_http_listener`, but TLS-wrapped with a
    throwaway self-signed cert generated for this test run only -- needed
    to isolate the secure twin's *resolved-IP* rejection from its *scheme*
    rejection (a plain-HTTP loopback target would be rejected on the
    scheme check alone, proving nothing about the IP-allowlist logic
    specifically), exactly mirroring `CC-LAB-0172`'s own corrected test
    design."""
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "1", "-nodes", "-subj", "/CN=localhost",
        ],
        capture_output=True,
        timeout=30.0,
        check=True,
    )
    server = http.server.HTTPServer(("127.0.0.1", _free_loopback_port()), _ThumbHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_real_boot_proves_the_ssrf_ip_allowlist_specifically_not_just_the_scheme_check() -> None:
    """Three cases, each isolating one specific piece of logic (per
    `CC-LAB-0172`'s own adequacy-review correction, applied directly to
    this port):

    (a) the vulnerable twin fetches a plain-HTTP loopback target
        successfully -- no validation at all (CWE-918).
    (b) the secure twin rejects that same plain-HTTP loopback target --
        the scheme check (reject non-``https``) alone is enough here.
    (c) the secure twin **also** rejects an HTTPS loopback target --
        isolating the resolved-IP-allowlist check specifically, since the
        scheme check alone would have let this one through.
    """
    emitter = SpringBootEmitter()
    cells = _cells()

    plain_server = _start_plain_http_listener()
    try:
        plain_port = plain_server.server_address[1]
        plain_url = f"http://127.0.0.1:{plain_port}/thumb.jpg"

        # (a) vulnerable twin: plain-HTTP loopback target accepted.
        with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0017"]) as harness:
            vuln_resp = harness.request(
                "POST", _ROUTE, params={"thumbnail_url": plain_url}
            )
            assert vuln_resp.status == 200, (
                f"vulnerable twin rejected an unvalidated loopback target (status {vuln_resp.status}): "
                f"{vuln_resp.body!r}"
            )
            assert vuln_resp.body == "thumb-bytes"

        with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0018"]) as harness:
            # (b) secure twin: same plain-HTTP target rejected (scheme check).
            secure_http_resp = harness.request(
                "POST", _ROUTE, params={"thumbnail_url": plain_url}
            )
            assert secure_http_resp.status == 403, (
                f"secure twin accepted a plain-HTTP loopback target (status {secure_http_resp.status}) "
                "-- the scheme check should have rejected it"
            )

            # (c) secure twin: an HTTPS loopback target is ALSO rejected --
            # this isolates the resolved-IP-allowlist check specifically,
            # since the scheme check alone would not catch this one.
            with tempfile.TemporaryDirectory(prefix="fuzzlab-spring-boot-ssrf-tls-") as cert_dir:
                https_server = _start_https_loopback_listener(Path(cert_dir))
                try:
                    https_port = https_server.server_address[1]
                    https_url = f"https://127.0.0.1:{https_port}/thumb.jpg"
                    secure_https_resp = harness.request(
                        "POST", _ROUTE, params={"thumbnail_url": https_url}
                    )
                    assert secure_https_resp.status == 403, (
                        f"secure twin accepted an HTTPS loopback target (status {secure_https_resp.status}) "
                        "-- the resolved-IP-allowlist check should have rejected it even though the "
                        "scheme check alone would have let it through"
                    )
                finally:
                    https_server.shutdown()
    finally:
        plain_server.shutdown()


class TestSsrfStrategiesGeneralizeToSpringBoot:
    """Proves `SsrfInBandMarkerStrategy`/`SsrfOobStrategy` need zero new
    detection code to confirm this new `spring_boot` vulnerable twin and
    correctly fail closed on its secure twin, using a real, started
    `OobListener` (needed even for the in-band-marker layer, since it
    mints and checks the callback token, not just for the OOB-wait
    fallback layer) -- the same generalization proof `CC-LAB-0185` made
    for Twitch's second SSRF instance."""

    def _candidate(self):
        from fuzzlab.oracle.probe import Candidate
        return Candidate(
            url="http://h" + _ROUTE, param="thumbnail_url", method="POST", location="query",
            vuln_class="ssrf", category="ssrf",
        )

    def test_confirms_the_vulnerable_twin(self) -> None:
        from fuzzlab.oracle.oob import OobListener
        from fuzzlab.oracle.probe import Probe
        from fuzzlab.oracle.strategies import SsrfInBandMarkerStrategy, SsrfOobStrategy

        emitter = SpringBootEmitter()
        vulnerable = _cells()["LABGEN-JV-0017"]

        listener = OobListener()
        listener.start()
        try:
            with SpringBootLiveBootHarness(emitter, vulnerable) as harness:

                class _HarnessSender:
                    def send(self, url, param, value, timing=False, method="POST",
                              location="query", content_type=None):
                        resp = harness.request("POST", _ROUTE, params={param: value})
                        return Probe(resp.status, resp.body)

                for strategy in (SsrfInBandMarkerStrategy(listener), SsrfOobStrategy(listener)):
                    verdict = strategy.confirm(self._candidate(), _HarnessSender())
                    assert verdict is not None and verdict.confirmed, (
                        f"{type(strategy).__name__} failed to confirm the real vulnerable spring_boot twin"
                    )
                    assert verdict.vuln_class == "ssrf"
        finally:
            listener.stop()

    def test_fails_closed_on_the_secure_twin(self) -> None:
        from fuzzlab.oracle.oob import OobListener
        from fuzzlab.oracle.probe import Probe
        from fuzzlab.oracle.strategies import SsrfInBandMarkerStrategy, SsrfOobStrategy

        emitter = SpringBootEmitter()
        secure = _cells()["LABGEN-JV-0018"]

        listener = OobListener()
        listener.start()
        try:
            with SpringBootLiveBootHarness(emitter, secure) as harness:

                class _HarnessSender:
                    def send(self, url, param, value, timing=False, method="POST",
                              location="query", content_type=None):
                        resp = harness.request("POST", _ROUTE, params={param: value})
                        return Probe(resp.status, resp.body)

                for strategy in (SsrfInBandMarkerStrategy(listener), SsrfOobStrategy(listener, timeout=1.0)):
                    assert strategy.confirm(self._candidate(), _HarnessSender()) is None, (
                        f"{type(strategy).__name__} incorrectly confirmed the secure spring_boot twin"
                    )
        finally:
            listener.stop()
