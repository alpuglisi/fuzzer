"""Real, executed live-boot proof for `go_net_http` (category 4 pilot,
`CC-LAB-0170`/`FR-LAB-76`, Phase A). Mirrors
`tests/test_labgen_ruby_rails_live_boot.py`'s convention: skip-guarded on
the real capability probe (never a bare socket check -- `PA-0035`/
`BUG-0033`), one real assemble+build+boot+HTTP round trip proving a real
payload differential end to end.

**What "payload differential" means for this shape.** Unlike SQLi/XSS
(where the vulnerable/secure twins diverge on a *malicious* payload and
agree on a *benign* one), this stack's one illustrative shape is a boolean
signature check: both twins must accept a **correct** signature and reject
an **incorrect** one -- that functional behavior is identical by
construction (`lab/safety_matrix.yaml`'s `webhook_signature_verification`
family: `naive_string_compare` is `partial`, not `no_effect` -- it still
performs a real, correct comparison, just not a constant-time one). What
this test proves is exactly that shared functional contract holding for
both twins against a *real* boot -- the CWE-347 timing-side-channel
property itself is not empirically provable by a single-request functional
oracle and is not claimed to be here (the same honesty rule already applied
to other non-functional-oracle classes, e.g. CWE-1333/ReDoS, in this
category's own Walmart research note).
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance.go_live_boot import GoLiveBootHarness, go_boot_available
from fuzzlab.labgen.emitters.go_net_http import GoEmitter
from fuzzlab.labgen.schema import load_manifest

_SHARED_SECRET = b"fuzzlab-go-net-http-lab-fixed-demo-secret"


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_correct_and_incorrect_signature_for_both_twins() -> None:
    manifest = load_manifest("lab/manifests/webhook_signature_go_sample.yaml")
    emitter = GoEmitter()
    body = b'{"event":"channel.follow","broadcaster":"twitch_lab"}'
    correct_digest = hmac.new(_SHARED_SECRET, body, hashlib.sha256).hexdigest()

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        for cell_id, path in (
            ("LABGEN-GO-0001", "/generated/labgen-go-0001"),  # vulnerable: naive ==
            ("LABGEN-GO-0002", "/generated/labgen-go-0002"),  # secure: hmac.Equal
        ):
            ok = harness.post(path, body=body, headers={"X-Signature-256": correct_digest})
            assert ok.status == 200, f"{cell_id}: correct signature was rejected"

            bad = harness.post(path, body=body, headers={"X-Signature-256": "0" * 64})
            assert bad.status == 401, f"{cell_id}: incorrect signature was accepted"

            missing = harness.post(path, body=body, headers={})
            assert missing.status == 401, f"{cell_id}: missing signature header was accepted"


# -- CC-LAB-0172 Phase B: SSRF (server_side_http_fetch) -----------------------


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
    starts and owns -- never a real external host, per `CC-LAB-0172`'s own
    lab-only/authorized-only safety scoping (`CLAUDE.md`)."""
    server = http.server.HTTPServer(("127.0.0.1", _free_loopback_port()), _ThumbHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _start_https_loopback_listener(cert_dir: Path) -> http.server.HTTPServer:
    """Same as :func:`_start_plain_http_listener`, but TLS-wrapped with a
    throwaway self-signed cert generated for this test run only -- needed
    to isolate the secure twin's *resolved-IP* rejection from its *scheme*
    rejection (a plain-HTTP loopback target would be rejected on the
    scheme check alone, proving nothing about the IP-allowlist logic
    specifically; see `CC-LAB-0172`'s change-control entry for why the
    first draft of this test was wrong)."""
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


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_ssrf_ip_allowlist_specifically_not_just_the_scheme_check() -> None:
    """Three cases, each isolating one specific piece of logic (per
    `CC-LAB-0172`'s adequacy-review correction):

    (a) the vulnerable twin fetches a plain-HTTP loopback target
        successfully -- no validation at all (CWE-918).
    (b) the secure twin rejects that same plain-HTTP loopback target --
        the scheme check (reject non-``https``) alone is enough here.
    (c) the secure twin **also** rejects an HTTPS loopback target --
        isolating the resolved-IP-allowlist check specifically, since the
        scheme check alone would have let this one through.

    A "secure twin successfully fetches some real allowed external
    target" positive case is explicitly out of scope for this increment
    (no real target allowlist exists yet for this stack) -- deferred, not
    silently omitted; see `CC-LAB-0172`'s own change-control entry.
    """
    manifest = load_manifest("lab/manifests/ssrf_go_sample.yaml")
    emitter = GoEmitter()

    plain_server = _start_plain_http_listener()
    try:
        plain_port = plain_server.server_address[1]
        plain_url = f"http://127.0.0.1:{plain_port}/thumb.jpg"

        with GoLiveBootHarness(emitter, manifest.cells) as harness:
            # (a) vulnerable twin: plain-HTTP loopback target accepted.
            vuln_resp = harness.request(
                "GET", f"/generated/labgen-go-0003?url={plain_url}"
            )
            assert vuln_resp.status == 200, (
                f"vulnerable twin rejected an unvalidated loopback target (status {vuln_resp.status})"
            )
            assert vuln_resp.body == "thumb-bytes"

            # (b) secure twin: same plain-HTTP target rejected (scheme check).
            secure_http_resp = harness.request(
                "GET", f"/generated/labgen-go-0004?url={plain_url}"
            )
            assert secure_http_resp.status == 403, (
                f"secure twin accepted a plain-HTTP loopback target (status {secure_http_resp.status}) "
                "-- the scheme check should have rejected it"
            )

            # (c) secure twin: an HTTPS loopback target is ALSO rejected --
            # this isolates the resolved-IP-allowlist check specifically,
            # since the scheme check alone would not catch this one.
            with tempfile.TemporaryDirectory(prefix="fuzzlab-go-net-http-ssrf-tls-") as cert_dir:
                https_server = _start_https_loopback_listener(Path(cert_dir))
                try:
                    https_port = https_server.server_address[1]
                    https_url = f"https://127.0.0.1:{https_port}/thumb.jpg"
                    secure_https_resp = harness.request(
                        "GET", f"/generated/labgen-go-0004?url={https_url}"
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


# -- Phase B increment 2: access-control / IDOR (db_row_by_id_lookup) --------


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_idor_differential_for_both_twins() -> None:
    """Three cases, isolating exactly what the ownership check controls:

    (a) the vulnerable twin leaks another channel's analytics when the
        requested `channel_id` does not match `X-Broadcaster-Id`.
    (b) the secure twin rejects that same mismatched request with a real
        HTTP 403 and no data.
    (c) the secure twin still serves analytics when `channel_id` *does*
        match `X-Broadcaster-Id` -- proving the fix doesn't break the
        legitimate case, not just that it blocks the attack one.
    """
    manifest = load_manifest("lab/manifests/access_control_go_sample.yaml")
    emitter = GoEmitter()

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        # (a) vulnerable twin: mismatched IDs still leak the data.
        vuln_resp = harness.request(
            "GET", "/generated/labgen-go-0005?channel_id=victim-channel",
            headers={"X-Broadcaster-Id": "attacker-channel"},
        )
        assert vuln_resp.status == 200, (
            f"vulnerable twin rejected a mismatched channel_id (status {vuln_resp.status})"
        )
        assert "victim-channel" in vuln_resp.body and "subscriber_count" in vuln_resp.body, (
            f"vulnerable twin did not leak the requested channel's analytics: {vuln_resp.body!r}"
        )

        # (b) secure twin: the same mismatched request is rejected outright.
        secure_mismatch_resp = harness.request(
            "GET", "/generated/labgen-go-0006?channel_id=victim-channel",
            headers={"X-Broadcaster-Id": "attacker-channel"},
        )
        assert secure_mismatch_resp.status == 403, (
            f"secure twin accepted a mismatched channel_id (status {secure_mismatch_resp.status}): "
            f"{secure_mismatch_resp.body!r}"
        )
        assert "subscriber_count" not in secure_mismatch_resp.body

        # (c) secure twin: the legitimate, matching-identity request still works.
        secure_match_resp = harness.request(
            "GET", "/generated/labgen-go-0006?channel_id=own-channel",
            headers={"X-Broadcaster-Id": "own-channel"},
        )
        assert secure_match_resp.status == 200, (
            f"secure twin rejected its own caller's legitimate request (status {secure_match_resp.status}): "
            f"{secure_match_resp.body!r}"
        )
        assert "own-channel" in secure_match_resp.body and "subscriber_count" in secure_match_resp.body
