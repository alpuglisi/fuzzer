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


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_ssrf_differential_for_both_twins_at_clips_download_route() -> None:
    """Same plain-HTTP-loopback differential as
    `test_real_boot_proves_the_ssrf_ip_allowlist_specifically_not_just_the_scheme_check`
    (`CC-LAB-0172`), against the second, distinct `/clips/download` route
    (`CC-LAB-0185`) -- proving the already-built shape genuinely
    generalizes to a new real page, not just a renamed copy of the same
    one."""
    manifest = load_manifest("lab/manifests/ssrf_clips_download_go_sample.yaml")
    emitter = GoEmitter()

    plain_server = _start_plain_http_listener()
    try:
        plain_port = plain_server.server_address[1]
        plain_url = f"http://127.0.0.1:{plain_port}/clip.mp4"

        with GoLiveBootHarness(emitter, manifest.cells) as harness:
            # (a) vulnerable twin: plain-HTTP loopback target accepted.
            vuln_resp = harness.request(
                "GET", f"/generated/labgen-go-0015?source_url={plain_url}"
            )
            assert vuln_resp.status == 200, (
                f"vulnerable twin rejected an unvalidated loopback target (status {vuln_resp.status})"
            )
            assert vuln_resp.body == "thumb-bytes"

            # (b) secure twin: the same plain-HTTP target is rejected (scheme check).
            secure_resp = harness.request(
                "GET", f"/generated/labgen-go-0016?source_url={plain_url}"
            )
            assert secure_resp.status == 403, (
                f"secure twin accepted a plain-HTTP loopback target (status {secure_resp.status}) "
                "-- the scheme check should have rejected it"
            )
    finally:
        plain_server.shutdown()


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_ssrf_strategies_generalize_to_clips_download_route() -> None:
    """The real, already-built `SsrfInBandMarkerStrategy`/`SsrfOobStrategy`
    (`CC-FUZZ-0027`), keyed only on `vuln_class`/sink shape, not per-route --
    confirm this new vulnerable twin and fail closed on the new secure twin
    with zero new detection code, using a real, started `OobListener`
    (needed even for the in-band-marker layer, since it mints and checks
    the callback token, not just for the OOB-wait fallback layer) -- the
    same generalization proof `CC-LAB-0183` made for Twitch's
    `access_control` detection."""
    from fuzzlab.oracle.oob import OobListener
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import SsrfInBandMarkerStrategy, SsrfOobStrategy

    manifest = load_manifest("lab/manifests/ssrf_clips_download_go_sample.yaml")
    emitter = GoEmitter()

    listener = OobListener()
    listener.start()
    try:
        with GoLiveBootHarness(emitter, manifest.cells) as harness:

            class _HarnessSender:
                def __init__(self, path: str):
                    self._path = path

                def send(self, url, param, value, timing=False, method="GET",
                          location="query", content_type=None):
                    resp = harness.request("GET", f"{self._path}?{param}={value}")
                    return Probe(resp.status, resp.body)

            vuln_cand = Candidate(url="http://h/generated/labgen-go-0015", param="source_url",
                                  method="GET", location="query",
                                  vuln_class="ssrf", category="ssrf")
            secure_cand = Candidate(url="http://h/generated/labgen-go-0016", param="source_url",
                                    method="GET", location="query",
                                    vuln_class="ssrf", category="ssrf")

            for strategy in (SsrfInBandMarkerStrategy(listener), SsrfOobStrategy(listener)):
                verdict = strategy.confirm(vuln_cand, _HarnessSender("/generated/labgen-go-0015"))
                assert verdict is not None and verdict.confirmed, (
                    f"{type(strategy).__name__} failed to confirm the real vulnerable twin"
                )
                assert verdict.vuln_class == "ssrf"

                assert strategy.confirm(secure_cand, _HarnessSender("/generated/labgen-go-0016")) is None, (
                    f"{type(strategy).__name__} incorrectly confirmed the real secure twin"
                )
    finally:
        listener.stop()


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


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_access_control_idor_strategy_end_to_end() -> None:
    """The real `AccessControlIdorStrategy` (CC-FUZZ-0029/FR-FUZZ-16), driven
    against a real booted app rather than a fake sender: confirms the
    vulnerable twin and fails closed on the secure twin, using the exact
    probes the strategy itself sends (no `X-Broadcaster-Id` header -- the
    strategy has no session/identity to drive)."""
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import AccessControlIdorStrategy

    manifest = load_manifest("lab/manifests/access_control_go_sample.yaml")
    emitter = GoEmitter()

    with GoLiveBootHarness(emitter, manifest.cells) as harness:

        class _HarnessSender:
            def __init__(self, path: str):
                self._path = path

            def send(self, url, param, value, timing=False, method="GET",
                      location="query", content_type=None):
                resp = harness.request("GET", f"{self._path}?{param}={value}")
                return Probe(resp.status, resp.body)

        strategy = AccessControlIdorStrategy()
        vuln_cand = Candidate(url="http://h/generated/labgen-go-0005", param="channel_id",
                              method="GET", location="query",
                              vuln_class="access_control", category="access-control")
        secure_cand = Candidate(url="http://h/generated/labgen-go-0006", param="channel_id",
                                method="GET", location="query",
                                vuln_class="access_control", category="access-control")

        verdict = strategy.confirm(vuln_cand, _HarnessSender("/generated/labgen-go-0005"))
        assert verdict is not None and verdict.confirmed, "strategy failed to confirm the real vulnerable twin"
        assert verdict.vuln_class == "access_control"

        assert strategy.confirm(secure_cand, _HarnessSender("/generated/labgen-go-0006")) is None, (
            "strategy incorrectly confirmed the real secure twin"
        )


# -- Twitch's 7th real page (CC-LAB-0183): access-control/IDOR, second     --
# -- instance, /channels/subscribers, reusing CC-LAB-0178's modules        --
# -- verbatim at a new route -- zero new generator code.                  --


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_idor_differential_for_both_twins_at_subscribers_route() -> None:
    """Same three-case differential as `test_real_boot_proves_the_idor_
    differential_for_both_twins` (`CC-LAB-0178`), against the second,
    distinct `/channels/subscribers` route (`CC-LAB-0183`) -- proving the
    already-built shape genuinely generalizes to a new real page, not just
    a renamed copy of the same one."""
    manifest = load_manifest("lab/manifests/access_control_subscribers_go_sample.yaml")
    emitter = GoEmitter()

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        # (a) vulnerable twin: mismatched IDs still leak the data.
        vuln_resp = harness.request(
            "GET", "/generated/labgen-go-0013?channel_id=victim-channel",
            headers={"X-Broadcaster-Id": "attacker-channel"},
        )
        assert vuln_resp.status == 200, (
            f"vulnerable twin rejected a mismatched channel_id (status {vuln_resp.status})"
        )
        assert "victim-channel" in vuln_resp.body and "subscriber_count" in vuln_resp.body, (
            f"vulnerable twin did not leak the requested channel's subscriber data: {vuln_resp.body!r}"
        )

        # (b) secure twin: the same mismatched request is rejected outright.
        secure_mismatch_resp = harness.request(
            "GET", "/generated/labgen-go-0014?channel_id=victim-channel",
            headers={"X-Broadcaster-Id": "attacker-channel"},
        )
        assert secure_mismatch_resp.status == 403, (
            f"secure twin accepted a mismatched channel_id (status {secure_mismatch_resp.status}): "
            f"{secure_mismatch_resp.body!r}"
        )
        assert "subscriber_count" not in secure_mismatch_resp.body

        # (c) secure twin: the legitimate, matching-identity request still works.
        secure_match_resp = harness.request(
            "GET", "/generated/labgen-go-0014?channel_id=own-channel",
            headers={"X-Broadcaster-Id": "own-channel"},
        )
        assert secure_match_resp.status == 200, (
            f"secure twin rejected its own caller's legitimate request (status {secure_match_resp.status}): "
            f"{secure_match_resp.body!r}"
        )
        assert "own-channel" in secure_match_resp.body and "subscriber_count" in secure_match_resp.body


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_access_control_idor_strategy_generalizes_to_subscribers_route() -> None:
    """The real, already-built `AccessControlIdorStrategy` (`CC-FUZZ-0029`),
    keyed only on `vuln_class`/sink shape, not per-route -- confirms this
    new vulnerable twin and fails closed on the new secure twin with zero
    new detection code, proving the existing detection genuinely
    generalizes to a second instance of the same shape (`CC-LAB-0183`'s
    own point)."""
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import AccessControlIdorStrategy

    manifest = load_manifest("lab/manifests/access_control_subscribers_go_sample.yaml")
    emitter = GoEmitter()

    with GoLiveBootHarness(emitter, manifest.cells) as harness:

        class _HarnessSender:
            def __init__(self, path: str):
                self._path = path

            def send(self, url, param, value, timing=False, method="GET",
                      location="query", content_type=None):
                resp = harness.request("GET", f"{self._path}?{param}={value}")
                return Probe(resp.status, resp.body)

        strategy = AccessControlIdorStrategy()
        vuln_cand = Candidate(url="http://h/generated/labgen-go-0013", param="channel_id",
                              method="GET", location="query",
                              vuln_class="access_control", category="access-control")
        secure_cand = Candidate(url="http://h/generated/labgen-go-0014", param="channel_id",
                                method="GET", location="query",
                                vuln_class="access_control", category="access-control")

        verdict = strategy.confirm(vuln_cand, _HarnessSender("/generated/labgen-go-0013"))
        assert verdict is not None and verdict.confirmed, "strategy failed to confirm the real vulnerable twin"
        assert verdict.vuln_class == "access_control"

        assert strategy.confirm(secure_cand, _HarnessSender("/generated/labgen-go-0014")) is None, (
            "strategy incorrectly confirmed the real secure twin"
        )


# -- Phase B increment 3: JWT alg:none confusion (jwt_signature_verification) --


def _b64url(obj: dict) -> str:
    import base64
    import json
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_jwt_alg_none_differential_for_both_twins() -> None:
    """Three cases, isolating exactly what algorithm-pinning controls:

    (a) the vulnerable twin honors an attacker-chosen `alg: none` header
        and returns the token's own forged, unsigned claims.
    (b) the vulnerable twin still correctly rejects a garbage/invalid
        HS256-claimed signature -- proving it isn't simply "always 200",
        only specifically bypassable via `alg: none`.
    (c) the secure twin rejects the exact same `alg: none` token outright,
        with a real HTTP 401 and no data.
    """
    manifest = load_manifest("lab/manifests/jwt_alg_confusion_go_sample.yaml")
    emitter = GoEmitter()

    alg_none_token = (
        _b64url({"alg": "none", "typ": "JWT"}) + "."
        + _b64url({"channel_id": "attacker-channel", "role": "owner"}) + "."
    )
    garbage_hs256_token = (
        _b64url({"alg": "HS256", "typ": "JWT"}) + "."
        + _b64url({"channel_id": "attacker-channel", "role": "owner"}) + "."
        + "not-a-real-signature"
    )

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        # (a) vulnerable twin: alg:none is honored, forged claims returned.
        vuln_resp = harness.request(
            "GET", "/generated/labgen-go-0007",
            headers={"Authorization": f"Bearer {alg_none_token}"},
        )
        assert vuln_resp.status == 200, (
            f"vulnerable twin rejected an alg:none token (status {vuln_resp.status}): {vuln_resp.body!r}"
        )
        assert "attacker-channel" in vuln_resp.body and "owner" in vuln_resp.body, (
            f"vulnerable twin did not honor the forged claims: {vuln_resp.body!r}"
        )

        # (b) vulnerable twin: a garbage HS256 signature is still rejected.
        vuln_garbage_resp = harness.request(
            "GET", "/generated/labgen-go-0007",
            headers={"Authorization": f"Bearer {garbage_hs256_token}"},
        )
        assert vuln_garbage_resp.status == 401, (
            f"vulnerable twin accepted a garbage HS256 signature (status {vuln_garbage_resp.status}): "
            f"{vuln_garbage_resp.body!r}"
        )

        # (c) secure twin: the same alg:none token is rejected outright.
        secure_resp = harness.request(
            "GET", "/generated/labgen-go-0008",
            headers={"Authorization": f"Bearer {alg_none_token}"},
        )
        assert secure_resp.status == 401, (
            f"secure twin accepted an alg:none token (status {secure_resp.status}): {secure_resp.body!r}"
        )
        assert "attacker-channel" not in secure_resp.body


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_jwt_alg_none_strategy_end_to_end() -> None:
    """The real `JwtAlgNoneConfusionStrategy` (CC-FUZZ-0033/FR-FUZZ-19),
    driven against a real booted app rather than a fake sender: confirms
    the vulnerable twin and fails closed on the secure twin, using the
    exact two-probe differential the strategy itself sends."""
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import JwtAlgNoneConfusionStrategy

    manifest = load_manifest("lab/manifests/jwt_alg_confusion_go_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    def _cand():
        return Candidate(url="http://h/generated/labgen-go-0007", param="Authorization",
                         method="GET", location="header",
                         vuln_class="jwt_algorithm_confusion",
                         category="jwt-algorithm-confusion")

    strategy = JwtAlgNoneConfusionStrategy()

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0007"]]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="GET",
                      location="header", content_type=None):
                resp = harness.request("GET", "/generated/labgen-go-0007",
                                       headers={param: value})
                return Probe(resp.status, resp.body)

        verdict = strategy.confirm(_cand(), _HarnessSender())
        assert verdict is not None and verdict.confirmed, "strategy failed to confirm the real vulnerable twin"
        assert verdict.vuln_class == "jwt_algorithm_confusion"

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0008"]]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="GET",
                      location="header", content_type=None):
                resp = harness.request("GET", "/generated/labgen-go-0008",
                                       headers={param: value})
                return Probe(resp.status, resp.body)

        assert strategy.confirm(_cand(), _HarnessSender()) is None, (
            "strategy incorrectly confirmed the real secure twin"
        )


# -- Phase B increment 4: predictable session token (session_token_generation) --


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_weak_token_entropy_differential_for_both_twins() -> None:
    """Two cases, isolating exactly what token generation controls:

    (a) the vulnerable twin's two consecutive tokens both parse as
        decimal integers whose difference tracks real elapsed wall-clock
        time (nanosecond-timestamp-derived, CWE-330).
    (b) the secure twin's tokens are 64-character hex strings that never
        parse as base-10 integers at all (crypto/rand-sourced).
    """
    import json
    import time

    manifest = load_manifest("lab/manifests/weak_token_entropy_go_sample.yaml")
    emitter = GoEmitter()

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        # (a) vulnerable twin: timestamp-derived, tracks real elapsed time.
        t0 = time.time()
        vuln_r1 = harness.request("POST", "/generated/labgen-go-0009", body=b"")
        vuln_r2 = harness.request("POST", "/generated/labgen-go-0009", body=b"")
        elapsed_ns = (time.time() - t0) * 1e9
        assert vuln_r1.status == 200 and vuln_r2.status == 200
        token1 = json.loads(vuln_r1.body)["session_token"]
        token2 = json.loads(vuln_r2.body)["session_token"]
        delta = int(token2) - int(token1)   # raises if either isn't a real integer
        assert 0 <= delta <= max(elapsed_ns * 50, 1e8), (
            f"vulnerable twin's token delta ({delta}ns) is not consistent with "
            f"real elapsed time (~{elapsed_ns:.0f}ns) -- not actually timestamp-derived"
        )

        # (b) secure twin: neither token parses as a decimal integer at all.
        secure_r1 = harness.request("POST", "/generated/labgen-go-0010", body=b"")
        secure_r2 = harness.request("POST", "/generated/labgen-go-0010", body=b"")
        assert secure_r1.status == 200 and secure_r2.status == 200
        secure_token1 = json.loads(secure_r1.body)["session_token"]
        secure_token2 = json.loads(secure_r2.body)["session_token"]
        for tok in (secure_token1, secure_token2):
            with pytest.raises(ValueError):
                int(tok)
        assert secure_token1 != secure_token2


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_weak_token_entropy_strategy_end_to_end() -> None:
    """The real `PredictableTokenSourceStrategy` (CC-FUZZ-0034/FR-FUZZ-20),
    driven against a real booted app rather than a fake sender: confirms
    the vulnerable twin and fails closed on the secure twin."""
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import PredictableTokenSourceStrategy

    manifest = load_manifest("lab/manifests/weak_token_entropy_go_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    def _cand():
        return Candidate(url="http://h/generated/labgen-go-0009", param="body",
                         method="POST", location="body",
                         vuln_class="weak_token_entropy",
                         category="weak-token-entropy", content_type="application/json")

    strategy = PredictableTokenSourceStrategy()

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0009"]]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                resp = harness.request("POST", "/generated/labgen-go-0009",
                                       body=value.encode("utf-8"))
                return Probe(resp.status, resp.body)

        verdict = strategy.confirm(_cand(), _HarnessSender())
        assert verdict is not None and verdict.confirmed, "strategy failed to confirm the real vulnerable twin"
        assert verdict.vuln_class == "weak_token_entropy"

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0010"]]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                resp = harness.request("POST", "/generated/labgen-go-0010",
                                       body=value.encode("utf-8"))
                return Probe(resp.status, resp.body)

        assert strategy.confirm(_cand(), _HarnessSender()) is None, (
            "strategy incorrectly confirmed the real secure twin"
        )


# -- Phase B increment 5: channel-profile mass assignment (orm_entity_bulk_assign) --


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_mass_assignment_differential_for_both_twins() -> None:
    """Two cases, isolating exactly what field-allowlisting controls:

    (a) the vulnerable twin echoes back `is_partner: true` when the
        request body sets it, even though no user-facing form for this
        endpoint ever exposes that field (CWE-915).
    (b) the secure twin silently drops the same `is_partner: true` key --
        its response never reflects anything but the seeded `false`.
    """
    import json

    manifest = load_manifest("lab/manifests/mass_assignment_go_sample.yaml")
    emitter = GoEmitter()
    body = b'{"display_name":"new_name","bio":"hi","is_partner":true}'

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        # (a) vulnerable twin: is_partner reaches the persisted record.
        vuln_resp = harness.request("POST", "/generated/labgen-go-0011", body=body)
        assert vuln_resp.status == 200
        vuln_record = json.loads(vuln_resp.body)
        assert vuln_record["display_name"] == "new_name"
        assert vuln_record["is_partner"] is True, (
            "vulnerable twin did not honor the privileged is_partner field -- "
            "not actually mass-assignable"
        )

        # (b) secure twin: only display_name/bio ever reach the record.
        secure_resp = harness.request("POST", "/generated/labgen-go-0012", body=body)
        assert secure_resp.status == 200
        secure_record = json.loads(secure_resp.body)
        assert secure_record["display_name"] == "new_name"
        assert secure_record["bio"] == "hi"
        assert secure_record["is_partner"] is False, (
            "secure twin incorrectly let is_partner through its DTO allowlist"
        )


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_mass_assignment_strategy_end_to_end() -> None:
    """The real `MassAssignmentPrivilegedFieldStrategy` (CC-FUZZ-0035/
    FR-FUZZ-21), driven against a real booted app rather than a fake
    sender: confirms the vulnerable twin and fails closed on the secure
    twin."""
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import MassAssignmentPrivilegedFieldStrategy

    manifest = load_manifest("lab/manifests/mass_assignment_go_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    def _cand():
        return Candidate(url="http://h/generated/labgen-go-0011", param="body",
                         method="POST", location="body",
                         vuln_class="mass_assignment",
                         category="mass-assignment", content_type="application/json")

    strategy = MassAssignmentPrivilegedFieldStrategy()

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0011"]]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                resp = harness.request("POST", "/generated/labgen-go-0011",
                                       body=value.encode("utf-8"))
                return Probe(resp.status, resp.body)

        verdict = strategy.confirm(_cand(), _HarnessSender())
        assert verdict is not None and verdict.confirmed, "strategy failed to confirm the real vulnerable twin"
        assert verdict.vuln_class == "mass_assignment"

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0012"]]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                resp = harness.request("POST", "/generated/labgen-go-0012",
                                       body=value.encode("utf-8"))
                return Probe(resp.status, resp.body)

        assert strategy.confirm(_cand(), _HarnessSender()) is None, (
            "strategy incorrectly confirmed the real secure twin"
        )


# -- Phase B increment 6: channel-emote unrestricted file upload (fs_web_root_write) --

#: An inert HTML snippet carrying a distinctive marker -- proves the
#: CWE-434-to-XSS content-type-chaining point (a same-origin response
#: served as `text/html` with attacker-controlled markup) without the
#: probe payload itself being anything that could plausibly execute if
#: mishandled (per this dispatch's own filesystem-safety instruction: no
#: real `<script>`-executing payload is needed to prove the Content-Type
#: divergence, just a marker a test can grep for).
_UPLOAD_MARKER = "FUZZLAB-UPLOAD-MARKER-3f9c2a"
_INERT_HTML_PAYLOAD = f"<!DOCTYPE html><p>{_UPLOAD_MARKER}</p>".encode()

#: The real PNG magic-number signature (the first 8 bytes `http.
#: DetectContentType` keys its `image/png` sniff on) -- enough for Go's
#: real sniffer to classify this as a real image without needing a fully
#: valid PNG chunk stream, matching this differential's own narrow claim
#: (content-type sniffing, not full image-format validation).
_PNG_SIGNATURE_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24


def _multipart_upload(filename: str, content: bytes, content_type: str) -> tuple[bytes, str]:
    """Hand-encodes a real ``multipart/form-data`` body with one file part
    named ``file`` -- the exact field name ``ReadUploadedFileSource``'s
    generated code reads via ``r.FormFile("file")``. No dependency beyond
    the stdlib; mirrors this test file's own preference for small,
    dependency-free real-protocol encoding (e.g. the HMAC digests
    elsewhere in this file) over pulling in `requests`."""
    boundary = "fuzzlabuploadboundary7f3a"
    body = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f'Content-Type: {content_type}\r\n\r\n'
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_unrestricted_file_upload_differential_for_both_twins() -> None:
    """Four real assertions, isolating exactly what allowlisting +
    content sniffing controls (CC-LAB-0186):

    (a) the vulnerable twin writes an uploaded ``evil.html`` and serves it
        back as ``text/html``, with the marker intact in the body --
        stored XSS via unrestricted file upload (CWE-434), the CWE-434-
        to-XSS chain a Go-idiomatic vulnerable twin models since Go has
        no PHP-style server-side-script-execution footgun.
    (b) the secure twin rejects the identical ``evil.html`` upload
        outright (extension not on the image allowlist).
    (c) the secure twin ALSO rejects a spoofed upload (real HTML bytes,
        but named ``fake.png``, an allowlisted extension) -- proving the
        secure twin's content-sniffing half, not just its extension
        check, is what actually closes the gap.
    (d) the secure twin accepts a real PNG-signature upload and serves it
        back with a sniffed ``image/png`` content type, proving the
        secure path is not simply "reject everything".

    Every write in this test lands under the booted app's own process
    ``cwd`` -- a throwaway `tempfile.TemporaryDirectory` `GoLiveBootHarness`
    itself creates and tears down (never a real, permanent, or shared
    path), per this dispatch's own filesystem-safety instruction.
    """
    manifest = load_manifest("lab/manifests/unrestricted_file_upload_go_sample.yaml")
    emitter = GoEmitter()

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        # (a) vulnerable twin: evil.html served back as text/html.
        html_body, html_ctype = _multipart_upload("evil.html", _INERT_HTML_PAYLOAD, "text/html")
        vuln_resp = harness.request(
            "POST", "/generated/labgen-go-0017", body=html_body,
            headers={"Content-Type": html_ctype},
        )
        assert vuln_resp.status == 200
        assert "text/html" in vuln_resp.headers.get("Content-Type", ""), (
            f"vulnerable twin did not serve the upload as text/html -- got "
            f"{vuln_resp.headers.get('Content-Type')!r}"
        )
        assert _UPLOAD_MARKER in vuln_resp.body

        # (b) secure twin: the same evil.html upload is rejected outright.
        html_body2, html_ctype2 = _multipart_upload("evil.html", _INERT_HTML_PAYLOAD, "text/html")
        secure_reject_resp = harness.request(
            "POST", "/generated/labgen-go-0018", body=html_body2,
            headers={"Content-Type": html_ctype2},
        )
        assert secure_reject_resp.status == 415, (
            "secure twin did not reject a non-allowlisted extension "
            f"(status={secure_reject_resp.status})"
        )

        # (c) secure twin: a spoofed upload (real HTML bytes, allowlisted
        # .png extension) is still rejected -- the content-sniffing half.
        spoof_body, spoof_ctype = _multipart_upload("fake.png", _INERT_HTML_PAYLOAD, "image/png")
        secure_spoof_resp = harness.request(
            "POST", "/generated/labgen-go-0018", body=spoof_body,
            headers={"Content-Type": spoof_ctype},
        )
        assert secure_spoof_resp.status == 415, (
            "secure twin let a spoofed (extension-only) upload through -- "
            "content sniffing did not actually run"
        )

        # (d) secure twin: a real PNG-signature upload is accepted and
        # served back with the sniffed image/png content type.
        png_body, png_ctype = _multipart_upload("real.png", _PNG_SIGNATURE_BYTES, "image/png")
        secure_ok_resp = harness.request(
            "POST", "/generated/labgen-go-0018", body=png_body,
            headers={"Content-Type": png_ctype},
        )
        assert secure_ok_resp.status == 200, (
            f"secure twin incorrectly rejected a real PNG upload (status="
            f"{secure_ok_resp.status})"
        )
        assert "image/png" in secure_ok_resp.headers.get("Content-Type", ""), (
            f"secure twin did not serve a real PNG back as image/png -- got "
            f"{secure_ok_resp.headers.get('Content-Type')!r}"
        )


# -- Phase B tenth increment: price-integrity-bypass (payment_charge_amount) --


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_price_integrity_differential_for_both_twins() -> None:
    """Three real assertions, isolating exactly what the server-side price
    lookup controls (CC-LAB-0189):

    (a) the vulnerable twin echoes back whatever `monthly_charge` the
        client sends, for an entirely made-up `plan_tier` -- it never
        looks the price up at all (CWE-807).
    (b) the secure twin fails closed (HTTP 400) on that same made-up
        `plan_tier`, since its price table has no entry for it -- the
        client-supplied amount is never trusted as a fallback.
    (c) the secure twin's lookup is genuinely data-driven, not a
        disguised constant: two different real tiers (`tier1`/`tier2`)
        return two different, real, fixed prices, both independent of
        whatever the client submitted.
    """
    import json

    manifest = load_manifest("lab/manifests/price_integrity_twitch_subscription_sample.yaml")
    emitter = GoEmitter()

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        # (a) vulnerable twin: the client-supplied amount tracks verbatim.
        vuln_low = harness.request(
            "POST", "/generated/labgen-go-0019",
            body=json.dumps({"plan_tier": "standard", "monthly_charge": 0.01}).encode(),
        )
        assert vuln_low.status == 200
        assert json.loads(vuln_low.body)["monthly_charge"] == 0.01

        vuln_high = harness.request(
            "POST", "/generated/labgen-go-0019",
            body=json.dumps({"plan_tier": "standard", "monthly_charge": 999999.99}).encode(),
        )
        assert vuln_high.status == 200
        assert json.loads(vuln_high.body)["monthly_charge"] == 999999.99, (
            "vulnerable twin did not honor the client-supplied monthly_charge -- "
            "not actually price-integrity-bypassable"
        )

        # (b) secure twin: an unrecognized plan_tier fails closed, never
        # falling back to the client-supplied amount.
        secure_unknown = harness.request(
            "POST", "/generated/labgen-go-0020",
            body=json.dumps({"plan_tier": "standard", "monthly_charge": 0.01}).encode(),
        )
        assert secure_unknown.status == 400, (
            f"secure twin did not fail closed on an unrecognized plan_tier "
            f"(status={secure_unknown.status})"
        )

        # (c) secure twin: two real tiers return two distinct, real, fixed
        # prices -- a genuine data-driven lookup, never a disguised constant.
        secure_tier1 = harness.request(
            "POST", "/generated/labgen-go-0020",
            body=json.dumps({"plan_tier": "tier1", "monthly_charge": 0.01}).encode(),
        )
        secure_tier2 = harness.request(
            "POST", "/generated/labgen-go-0020",
            body=json.dumps({"plan_tier": "tier2", "monthly_charge": 0.01}).encode(),
        )
        assert secure_tier1.status == 200 and secure_tier2.status == 200
        price_tier1 = json.loads(secure_tier1.body)["monthly_charge"]
        price_tier2 = json.loads(secure_tier2.body)["monthly_charge"]
        assert price_tier1 == 4.99
        assert price_tier2 == 9.99
        assert price_tier1 != price_tier2, (
            "secure twin's plan_tier price lookup returned the same price for "
            "two different tiers -- a disguised constant, not a real map"
        )


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_price_integrity_strategy_generalizes_from_spring_boot() -> None:
    """The real `PriceIntegrityBypassStrategy` (`CC-FUZZ-0037`, built for
    `spring_boot`'s Netflix cell, `CC-LAB-0188`), driven against a real
    booted `go_net_http` app rather than a fake sender: needs **zero** new
    code to confirm this stack's new vulnerable twin and correctly fail
    closed on its new secure twin -- the first proof this strategy
    generalizes across stacks in the direction `spring_boot` ->
    `go_net_http` (complementing `CC-LAB-0187`'s own proof of
    `AccessControlIdorStrategy` generalizing `go_net_http` ->
    `spring_boot`)."""
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import PriceIntegrityBypassStrategy

    manifest = load_manifest("lab/manifests/price_integrity_twitch_subscription_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    def _cand():
        return Candidate(url="http://h/generated/labgen-go-0019", param="body",
                         method="POST", location="body",
                         vuln_class="price_integrity_bypass",
                         category="price-integrity-bypass", content_type="application/json")

    strategy = PriceIntegrityBypassStrategy()

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0019"]]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                resp = harness.request("POST", "/generated/labgen-go-0019",
                                       body=value.encode("utf-8"))
                return Probe(resp.status, resp.body)

        verdict = strategy.confirm(_cand(), _HarnessSender())
        assert verdict is not None and verdict.confirmed, "strategy failed to confirm the real vulnerable twin"
        assert verdict.vuln_class == "price_integrity_bypass"

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0020"]]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                resp = harness.request("POST", "/generated/labgen-go-0020",
                                       body=value.encode("utf-8"))
                return Probe(resp.status, resp.body)

        assert strategy.confirm(_cand(), _HarnessSender()) is None, (
            "strategy incorrectly confirmed the real secure twin"
        )


# -- Phase B eleventh increment: path traversal (fs_path_read, CC-LAB-0190) --

_PATH_TRAVERSAL_CANARY_MARKER = "FUZZLAB-PATH-TRAVERSAL-CANARY-9d71ab"


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_path_traversal_differential_for_both_twins() -> None:
    """Real assertions, isolating exactly what real-path confinement
    controls (CC-LAB-0190):

    (a) both twins serve a legitimate, in-directory filename identically --
        this shape's functional contract (serve a previously-exported
        clip) is unaffected by the fix.
    (b) the vulnerable twin serves a `../../<canary>`-style traversal
        payload straight through, reaching a file two directories above
        the intended export directory (CWE-22).
    (c) the secure twin rejects the identical traversal payload outright
        (HTTP 403), and the canary's own marker never appears in its
        response body.
    (d) the secure twin's confinement check and its existence check are
        two genuinely distinct code paths -- a missing-but-in-bounds
        filename fails closed as "not found", not as a confinement error.

    **Filesystem safety.** Every file this test creates or reads lives
    under `harness.app_dir` -- always a path inside `GoLiveBootHarness`'s
    own throwaway `tempfile.TemporaryDirectory` (never a real, permanent,
    or shared path, and never a real system file like `/etc/passwd`), per
    this dispatch's own filesystem-safety instruction. The canary file is a
    sibling of the export directory two levels up, entirely inside that
    same disposable temp tree -- proving the escape without ever touching
    anything outside it.
    """
    manifest = load_manifest("lab/manifests/path_traversal_go_sample.yaml")
    emitter = GoEmitter()

    with GoLiveBootHarness(emitter, manifest.cells) as harness:
        export_dir = harness.app_dir / "static" / "clips_exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        legit_content = b"a legitimate previously-exported clip file"
        (export_dir / "clip123.mp4").write_bytes(legit_content)

        # The canary: a sibling file two levels above clipExportDir, still
        # entirely inside this harness's own disposable temp root.
        canary_path = harness.app_dir / "secret_canary.txt"
        canary_path.write_text(_PATH_TRAVERSAL_CANARY_MARKER)

        # (a) legitimate filename: both twins serve the real file back
        # identically -- the fix does not break the intended functionality.
        vuln_ok = harness.request("GET", "/generated/labgen-go-0021?filename=clip123.mp4")
        assert vuln_ok.status == 200
        assert vuln_ok.body == legit_content.decode()

        secure_ok = harness.request("GET", "/generated/labgen-go-0022?filename=clip123.mp4")
        assert secure_ok.status == 200
        assert secure_ok.body == legit_content.decode()

        # (b) vulnerable twin: the traversal payload escapes clipExportDir
        # and reaches the canary two directories up (CWE-22).
        vuln_escape = harness.request(
            "GET", "/generated/labgen-go-0021?filename=../../secret_canary.txt"
        )
        assert vuln_escape.status == 200, (
            f"vulnerable twin did not serve the escaped canary (status={vuln_escape.status})"
        )
        assert _PATH_TRAVERSAL_CANARY_MARKER in vuln_escape.body

        # (c) secure twin: the identical traversal payload is rejected
        # outright, and the canary's marker never leaks into the response.
        secure_escape = harness.request(
            "GET", "/generated/labgen-go-0022?filename=../../secret_canary.txt"
        )
        assert secure_escape.status == 403, (
            f"secure twin did not reject the traversal payload (status={secure_escape.status})"
        )
        assert _PATH_TRAVERSAL_CANARY_MARKER not in secure_escape.body

        # (d) secure twin: an unknown/missing filename inside the export
        # directory fails closed as "not found", not as a confinement
        # error -- proving the confinement check and the existence check
        # are two genuinely distinct code paths.
        secure_missing = harness.request(
            "GET", "/generated/labgen-go-0022?filename=does-not-exist.mp4"
        )
        assert secure_missing.status == 404


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_path_traversal_strategy_closes_the_fs_path_read_detection_gap() -> None:
    """`CC-FUZZ-0042`: `PathTraversalFsPathReadStrategy` (`fuzzlab/oracle/
    strategies.py`) confirms `CC-LAB-0190`'s own vulnerable twin for real,
    over the network via `RequestsProbeSender` (not a stub), and correctly
    declines the secure twin -- closing `TWCH-0011`'s own deliberately-
    deferred detection follow-on (its own `labels.json` `notes` field
    explicitly tracked this as "genuinely unbuilt ... a false negative
    until that follow-on lands").

    This is the ORACLE-side proof, distinct from `tests/
    test_labgen_go_live_boot.py::
    test_real_boot_proves_the_path_traversal_differential_for_both_twins`
    above, which only proves the LAB shape's own vulnerable/secure
    differential exists (via an inert, harness-planted canary file) and
    explicitly defers detection. This test proves the real oracle
    strategy actually confirms it, reading the target's real, pre-existing
    `/etc/passwd` (present in the harness's own build/boot container) --
    never a canary planted on the target's filesystem, and never any file
    this test itself writes: the strategy's own payload traverses to a
    file that already exists there, exactly the safe, standard black-box
    technique this project's own `fuzzlab/labgen/nuclei_oracle.py` already
    bundles for a different sub-purpose (`lab/nuclei-templates/
    path-traversal-etc-passwd.yaml`).
    """
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import PathTraversalFsPathReadStrategy
    from fuzzlab.tools.probesender import RequestsProbeSender

    manifest = load_manifest("lab/manifests/path_traversal_go_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    with GoLiveBootHarness(emitter, list(cells.values())) as harness:
        sender = RequestsProbeSender(timeout=10.0)
        strategy = PathTraversalFsPathReadStrategy()

        vuln_candidate = Candidate(
            url=f"{harness.base_url}/generated/labgen-go-0021", param="filename",
            method="GET", location="query",
        )
        verdict = strategy.confirm(vuln_candidate, sender)
        assert verdict is not None and verdict.confirmed, verdict
        assert verdict.vuln_class == "path_traversal"
        assert "etc/passwd" in verdict.evidence["payload"]

        secure_candidate = Candidate(
            url=f"{harness.base_url}/generated/labgen-go-0022", param="filename",
            method="GET", location="query",
        )
        assert strategy.confirm(secure_candidate, sender) is None


# -- Phase B twelfth increment: SSTI (template_render, CC-LAB-0196) --


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_ssti_differential_for_both_twins() -> None:
    """Real assertions, isolating exactly what compiling-vs-looking-up the
    caller-supplied `template` field controls (CC-LAB-0196):

    (a) the vulnerable twin actually EVALUATES a real-field-access payload
        (`{{.Uptime}}`), not just echoes it -- the literal `{{.Uptime}}`
        never appears in the response, the real substituted value does.
    (b) the vulnerable twin also evaluates a conditional (`{{if}}...{{end}}`)
        construct, proving real template-language control flow runs, not
        dumb single-value substitution.
    (c) a malformed/unparseable template produces a real HTTP 400 parse
        error on the vulnerable twin, distinguishing "evaluated and
        failed" from "not evaluated at all".
    (d) the secure twin treats the exact same field-access/conditional
        payloads as opaque, unrecognized variable NAMES -- never
        evaluated -- while a real, fixed, pre-approved variable name
        (`uptime`) still resolves through its lookup path.

    **What this does NOT prove (an open question, stated plainly, not
    routed around).** The existing generic `SstiStrategy`
    (`fuzzlab.oracle.strategies`) does NOT confirm this vulnerable twin --
    see `test_ssti_strategy_does_not_generalize_to_go_text_template`
    below for the real, executed proof of that gap.
    """
    manifest = load_manifest("lab/manifests/ssti_channel_commands_go_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0023"]]) as harness:
        # (a) real field-access evaluation.
        resp = harness.post(
            "/generated/labgen-go-0023",
            body=b'{"trigger":"!uptime","template":"{{.Uptime}} since going live"}',
            headers={"Content-Type": "application/json"},
        )
        assert resp.status == 200, resp.body
        assert resp.body == "3h27m since going live"
        assert "{{.Uptime}}" not in resp.body

        # (b) real conditional/control-flow evaluation -- beyond simple
        # substitution.
        cond_resp = harness.post(
            "/generated/labgen-go-0023",
            body=(
                b'{"trigger":"!check","template":'
                b'"{{if eq .Uptime \\"3h27m\\"}}MATCHED{{else}}NO{{end}}"}'
            ),
            headers={"Content-Type": "application/json"},
        )
        assert cond_resp.status == 200, cond_resp.body
        assert cond_resp.body == "MATCHED"

        # (c) a malformed template is a real parse error, not silently
        # echoed back or ignored.
        bad_resp = harness.post(
            "/generated/labgen-go-0023",
            body=b'{"trigger":"!broken","template":"{{.Uptime"}',
            headers={"Content-Type": "application/json"},
        )
        assert bad_resp.status == 400
        assert "template error" in bad_resp.body

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0024"]]) as harness:
        # (d) the secure twin never evaluates the same payloads -- they
        # are simply unrecognized variable names.
        secure_field_resp = harness.post(
            "/generated/labgen-go-0024",
            body=b'{"trigger":"!uptime","template":"{{.Uptime}} since going live"}',
            headers={"Content-Type": "application/json"},
        )
        assert secure_field_resp.status == 200, secure_field_resp.body
        assert secure_field_resp.body == "!uptime: unknown variable"

        secure_cond_resp = harness.post(
            "/generated/labgen-go-0024",
            body=(
                b'{"trigger":"!check","template":'
                b'"{{if eq .Uptime \\"3h27m\\"}}MATCHED{{else}}NO{{end}}"}'
            ),
            headers={"Content-Type": "application/json"},
        )
        assert secure_cond_resp.status == 200, secure_cond_resp.body
        assert "MATCHED" not in secure_cond_resp.body
        assert secure_cond_resp.body == "!check: unknown variable"

        # A real, pre-approved variable name still resolves correctly --
        # proving the lookup path itself genuinely runs.
        legit_resp = harness.post(
            "/generated/labgen-go-0024",
            body=b'{"trigger":"!uptime","template":"uptime"}',
            headers={"Content-Type": "application/json"},
        )
        assert legit_resp.status == 200, legit_resp.body
        assert legit_resp.body == "!uptime: 3h27m"


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_ssti_strategy_does_not_generalize_to_go_text_template() -> None:
    """Honest, executed documentation of an open detection question
    (CC-LAB-0196's own change-control entry): the existing generic
    `SstiStrategy` (`fuzzlab.oracle.strategies`, arm `ssti:evaluation-
    marker`) sends an arithmetic-expression payload wrapped in one of five
    template-engine syntaxes (`${a*b}`, `{{a*b}}`, `<%= a*b %>`, `#{a*b}`,
    `${{a*b}}`) and checks whether the numeric PRODUCT appears while the
    literal expression does not. Against a REAL booted `go_net_http`
    vulnerable twin (never asserted from a `go run` unit check alone,
    though that check is what first found this and is reproduced in
    `test_ssti_go_text_template_syntax_mismatch` below), none of the five
    payloads is evaluated: `{{a*b}}`/`${{a*b}}` are rejected by the
    handler as unparseable templates (Go's `text/template` action grammar
    has no infix arithmetic operators at all -- a hard syntax
    restriction, not a missing `FuncMap` entry), and
    `${a*b}`/`<%= a*b %>`/`#{a*b}` contain no `{{`/`}}` at all, so
    `text/template` treats them as inert literal text and echoes them back
    completely unevaluated. `SstiStrategy.confirm()` therefore correctly
    returns `None` here -- a real, verified false negative, not a bug in
    the strategy itself (it does exactly what it is designed to do; Go's
    template syntax is simply incompatible with an arithmetic-infix-
    operator marker)."""
    manifest = load_manifest("lab/manifests/ssti_channel_commands_go_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import SstiStrategy

    def _cand():
        return Candidate(url="http://h/generated/labgen-go-0023", param="body",
                         method="POST", location="body",
                         vuln_class="ssti", category="server-side-template-injection")

    strategy = SstiStrategy()

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0023"]]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                # The strategy sends a raw arithmetic-expression payload
                # string; this app's own handler expects a JSON body with
                # a `template` field, so wrap it exactly the way a real
                # custom-command-creation client would.
                import json as _json
                body = _json.dumps({"trigger": "!probe", "template": value}).encode("utf-8")
                resp = harness.request("POST", "/generated/labgen-go-0023", body=body,
                                       headers={"Content-Type": "application/json"})
                return Probe(resp.status, resp.body)

        verdict = strategy.confirm(_cand(), _HarnessSender())
        assert verdict is None, (
            "SstiStrategy unexpectedly confirmed the real go_net_http vulnerable twin -- "
            "this test's own docstring (and CC-LAB-0196's own change-control entry) claim "
            "this generalization does NOT happen; if this now fails, the analysis needs "
            "updating, not this assertion silently loosened."
        )


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_go_template_ssti_strategy_closes_the_generalization_gap() -> None:
    """CC-LAB-0196 documented that `SstiStrategy` does not generalize to Go's
    `text/template` (`test_ssti_strategy_does_not_generalize_to_go_text_
    template` above). `GoTemplateSstiStrategy` (`fuzzlab.oracle.strategies`,
    arm `ssti:go-template-len-marker`, CC-FUZZ-0038) closes that gap: run
    against a REAL booted vulnerable twin, it must confirm; run against the
    REAL booted secure twin (which only ever does a fixed-map lookup and
    never evaluates `len` on caller input), it must correctly fail closed.
    """
    manifest = load_manifest("lab/manifests/ssti_channel_commands_go_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import GoTemplateSstiStrategy

    def _cand(cell_path):
        return Candidate(url=f"http://h{cell_path}", param="body",
                         method="POST", location="body",
                         vuln_class="ssti", category="server-side-template-injection")

    class _HarnessSender:
        def __init__(self, harness, path):
            self._harness = harness
            self._path = path

        def send(self, url, param, value, timing=False, method="POST",
                 location="body", content_type=None):
            import json as _json
            body = _json.dumps({"trigger": "!probe", "template": value}).encode("utf-8")
            resp = self._harness.request("POST", self._path, body=body,
                                         headers={"Content-Type": "application/json"})
            return Probe(resp.status, resp.body)

    strategy = GoTemplateSstiStrategy()

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0023"]]) as harness:
        verdict = strategy.confirm(
            _cand("/generated/labgen-go-0023"),
            _HarnessSender(harness, "/generated/labgen-go-0023"),
        )
        assert verdict is not None and verdict.confirmed, (
            "GoTemplateSstiStrategy failed to confirm the real go_net_http vulnerable "
            "SSTI twin (LABGEN-GO-0023) -- the whole point of this strategy is closing "
            "this exact detection gap"
        )
        assert verdict.mechanism == "go-template-len-marker"

    with GoLiveBootHarness(emitter, [cells["LABGEN-GO-0024"]]) as harness:
        verdict = strategy.confirm(
            _cand("/generated/labgen-go-0024"),
            _HarnessSender(harness, "/generated/labgen-go-0024"),
        )
        assert verdict is None, (
            "GoTemplateSstiStrategy incorrectly confirmed the real go_net_http secure "
            "SSTI twin (LABGEN-GO-0024), which only ever does a fixed-map lookup and "
            "never evaluates `len` on caller input -- a false positive"
        )


def test_ssti_go_text_template_syntax_mismatch() -> None:
    """Non-boot, fast, always-run reproduction of the syntax-level
    incompatibility above: `fuzzlab.oracle.strategies._ssti_payloads`'s
    exact five candidate payload strings run through Go's REAL
    `text/template` package (a subprocess `go run`, skip-guarded on `go`
    being on PATH -- distinct from `go_boot_available()`'s network-
    reachability requirement, since this needs no module fetch at all).
    Kept as its own fast, non-slow test (unlike the two live-boot tests
    above) precisely because it needs no full app boot -- just the Go
    toolchain compiling and running one trivial program -- so this
    specific empirical claim stays checked on every non-slow run, not
    only when `-m slow` is explicitly requested."""
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path as _Path

    if shutil.which("go") is None:
        pytest.skip("go CLI not available on this build host (PA-0005 pattern)")

    from fuzzlab.oracle.strategies import _ssti_payloads

    payloads = _ssti_payloads("413*271")
    assert payloads == ["${413*271}", "{{413*271}}", "<%= 413*271 %>", "#{413*271}", "${{413*271}}"]

    go_src = '''package main

import (
	"bytes"
	"fmt"
	"os"
	"text/template"
)

func main() {
	payload := os.Args[1]
	t, err := template.New("x").Parse(payload)
	if err != nil {
		fmt.Println("PARSE_ERROR")
		return
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, nil); err != nil {
		fmt.Println("EXEC_ERROR")
		return
	}
	fmt.Println("OUTPUT:" + buf.String())
}
'''
    with tempfile.TemporaryDirectory(prefix="fuzzlab-ssti-syntax-check-") as tmp:
        main_go = _Path(tmp) / "main.go"
        main_go.write_text(go_src)
        for payload in payloads:
            result = subprocess.run(
                ["go", "run", str(main_go), payload],
                capture_output=True, text=True, timeout=30.0,
            )
            output = result.stdout.strip()
            if "{{" in payload:
                # text/template's action grammar has no infix arithmetic
                # operators -- these two payloads fail to parse outright.
                assert output == "PARSE_ERROR", f"{payload!r} -> {output!r} (expected a parse error)"
            else:
                # No `{{`/`}}` at all -- treated as inert literal text and
                # echoed back completely unevaluated (the product never
                # appears, the literal expression always does).
                assert output == f"OUTPUT:{payload}", f"{payload!r} -> {output!r} (expected verbatim echo)"


# -- Phase B thirteenth increment: HTTP response header injection
# (http_response_header_value, CC-LAB-0198) -------------------------------


def test_go_net_http_header_set_sanitizes_bare_crlf_on_the_wire() -> None:
    """Non-boot, fast, always-run reproduction of the empirical claim
    `CC-LAB-0198`'s own change-control entry rests on: Go's ORDINARY
    `net/http` response-header-writing path (`w.Header().Set()` +
    `w.WriteHeader()`) already replaces a bare CR/LF byte in a header
    value with a space before writing the response to the wire, so an
    honest vulnerable instance of this concern cannot be built through
    that ordinary path in Go -- this shape's vulnerable twin instead uses
    `http.Hijacker.Hijack()` to bypass it. Mirrors
    `test_ssti_go_text_template_syntax_mismatch`'s own "keep the empirical
    claim checked on every ordinary run, not only under `-m slow`"
    discipline: a real `go run` against a real, booted (via a raw TCP
    dial, not `GoLiveBootHarness`, so this stays fast and dependency-light)
    `net/http.Server`, skip-guarded on the `go` CLI alone (not
    `go_boot_available()`'s module-proxy reachability requirement, since
    this program imports only the standard library)."""
    import shutil
    import socket as _socket
    import subprocess
    import tempfile
    from pathlib import Path as _Path

    if shutil.which("go") is None:
        pytest.skip("go CLI not available on this build host (PA-0005 pattern)")

    go_src = '''package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/normal", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("destination"))
		w.WriteHeader(http.StatusFound)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(ln.Addr().String())
	os.Stdout.Sync()
	http.Serve(ln, mux)
}
'''
    with tempfile.TemporaryDirectory(prefix="fuzzlab-header-injection-syntax-check-") as tmp:
        main_go = _Path(tmp) / "main.go"
        main_go.write_text(go_src)
        proc = subprocess.Popen(
            ["go", "run", str(main_go)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            addr_line = proc.stdout.readline().strip()
            assert addr_line, "go program produced no listen-address line"
            host, port_s = addr_line.rsplit(":", 1)
            port = int(port_s)
            with _socket.create_connection((host or "127.0.0.1", port), timeout=10.0) as conn:
                request = (
                    "GET /normal?destination=%2Fok%0d%0aX-Injected%3A%20evil "
                    "HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                )
                conn.sendall(request.encode("ascii"))
                chunks = []
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                raw_response = b"".join(chunks).decode("latin-1")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()

    # The CR/LF bytes reached w.Header().Set() as literal text, but
    # net/http's own transfer-writer replaced them with spaces before
    # writing to the wire -- no second "X-Injected:" header line exists,
    # and the value itself no longer contains a raw CR/LF.
    header_lines = raw_response.split("\r\n")
    assert not any(line.lower().startswith("x-injected:") for line in header_lines), (
        f"a bare CR/LF byte reaching w.Header().Set() produced a real second header line "
        f"-- Go's own net/http sanitization did not fire as expected:\n{raw_response!r}"
    )
    location_line = next(line for line in header_lines if line.lower().startswith("location:"))
    assert "\r" not in location_line and "\n" not in location_line
    assert "X-Injected" in location_line, (
        f"expected the sanitized (space-joined) Location value to still contain the literal "
        f"text 'X-Injected', proving the bytes reached Set() rather than being dropped "
        f"entirely: {location_line!r}"
    )


_HEADER_INJECTION_CANARY_HEADER = "X-Fuzzlab-Header-Injection-Canary"


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_http_header_injection_differential_for_both_twins() -> None:
    """Real assertions against a real booted app (`CC-LAB-0198`):

    (a) both twins serve a legitimate, plain-path `destination` value
        identically -- this shape's functional contract (redirect the
        caller somewhere after subscribing/following) is unaffected by
        the fix.
    (b) the vulnerable twin's raw-socket-hijack response genuinely
        splices in a whole extra HTTP response header the caller did not
        ask for by name (CWE-113) -- proven by reading it back as a real,
        independently-parsed header on the response Python's own
        `http.client` received, not by inspecting the raw bytes this
        process itself wrote.
    (c) the secure twin rejects the identical CRLF-bearing payload
        outright (HTTP 400), and the injected header never appears.
    """
    from urllib.parse import quote

    manifest = load_manifest("lab/manifests/http_header_injection_redirect_go_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    with GoLiveBootHarness(emitter, list(cells.values())) as harness:
        # (a) a legitimate destination: both twins redirect identically.
        vuln_ok = harness.request("GET", "/generated/labgen-go-0025?destination=/ok")
        assert vuln_ok.status == 302
        assert vuln_ok.headers.get("Location") == "/ok"

        secure_ok = harness.request("GET", "/generated/labgen-go-0026?destination=/ok")
        assert secure_ok.status == 302
        assert secure_ok.headers.get("Location") == "/ok"

        # (b) vulnerable twin: a CRLF-bearing destination splices in a real
        # extra response header (CWE-113), parsed independently by
        # Python's own http.client, not merely present in raw bytes this
        # test wrote itself.
        payload = quote(f"/ok\r\n{_HEADER_INJECTION_CANARY_HEADER}: injected", safe="")
        vuln_injected = harness.request("GET", f"/generated/labgen-go-0025?destination={payload}")
        assert vuln_injected.status == 302, vuln_injected.body
        assert vuln_injected.headers.get(_HEADER_INJECTION_CANARY_HEADER) == "injected", (
            f"vulnerable twin did not splice in the injected header -- headers were "
            f"{vuln_injected.headers!r}"
        )

        # (c) secure twin: the identical CRLF-bearing payload is rejected
        # outright, and the injected header never appears at all.
        secure_injected = harness.request(
            "GET", f"/generated/labgen-go-0026?destination={payload}"
        )
        assert secure_injected.status == 400, secure_injected.body
        assert _HEADER_INJECTION_CANARY_HEADER not in secure_injected.headers


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_http_header_injection_strategy_closes_the_crlf_detection_gap() -> None:
    """`CC-FUZZ-0041`: `HttpHeaderInjectionCrlfStrategy` (`fuzzlab/oracle/
    strategies.py`) confirms `CC-LAB-0198`'s own vulnerable twin for real,
    over the network via `RequestsProbeSender` (not a stub), and correctly
    declines the secure twin -- closing `TWCH-0013`'s own deliberately-
    deferred detection follow-on (its own `labels.json` `notes` field
    explicitly tracked this as an open gap until this strategy landed).

    Also a live regression proof that a plain `requests`-based sender
    genuinely observes a CRLF-spliced-in extra response header without any
    normalization/merging defeating it (verified directly, not assumed,
    before this strategy was designed -- see its own docstring): had
    `requests`/`urllib3` folded or dropped the injected header the way a
    duplicate-header-name case gets comma-joined, this test would fail
    with `verdict is None` rather than a wrong-but-passing result.
    """
    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import HttpHeaderInjectionCrlfStrategy
    from fuzzlab.tools.probesender import RequestsProbeSender

    manifest = load_manifest("lab/manifests/http_header_injection_redirect_go_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    with GoLiveBootHarness(emitter, list(cells.values())) as harness:
        sender = RequestsProbeSender(timeout=10.0)
        strategy = HttpHeaderInjectionCrlfStrategy()

        vuln_candidate = Candidate(
            url=f"{harness.base_url}/generated/labgen-go-0025", param="destination",
            method="GET", location="query",
        )
        verdict = strategy.confirm(vuln_candidate, sender)
        assert verdict is not None and verdict.confirmed, verdict
        assert verdict.vuln_class == "http_header_injection"
        assert verdict.evidence["value"] and verdict.evidence["value"] in verdict.evidence["header"]

        secure_candidate = Candidate(
            url=f"{harness.base_url}/generated/labgen-go-0026", param="destination",
            method="GET", location="query",
        )
        assert strategy.confirm(secure_candidate, sender) is None


# -- Phase B fourteenth increment: open redirect (open_redirect,
# http_redirect_location, CC-LAB-0199) ------------------------------------


@pytest.mark.slow
@pytest.mark.skipif(not go_boot_available(), reason="go toolchain/module-proxy not available (PA-0035 pattern)")
def test_real_boot_proves_the_open_redirect_differential_for_both_twins() -> None:
    """Real assertions against a real booted app (`CC-LAB-0199`):

    (a) both twins serve a legitimate, plain-path `next` value identically
        -- this shape's functional contract ("return here after login") is
        unaffected by which twin handles the request.
    (b) the vulnerable twin reflects a caller-supplied ABSOLUTE EXTERNAL
        URL verbatim into the `Location` header (CWE-601) -- no CR/LF byte
        involved at all, unlike CC-LAB-0198's own http_header_injection
        shape, since a bare external URL is already a well-formed
        `Location` value.
    (c) the secure twin rejects that same external-URL payload, a
        protocol-relative bypass (`//evil.example`), and a
        backslash-prefixed bypass (`/\\evil.example`) outright (HTTP 400),
        and never sets a `Location` header pointing off-site.
    (d) `fuzzlab.oracle.strategies.OpenRedirectStrategy` -- already built,
        with zero new detection code needed -- confirms the vulnerable
        twin for real and returns no verdict for the secure twin, sending
        real probes over the network via `RequestsProbeSender` (not a
        stub), which is ALSO a live regression proof that `BUG-0042`'s fix
        (the sender now sets `allow_redirects=False`) still holds: had it
        regressed, the strategy's canary probe against the vulnerable
        twin would follow the external `Location` chain and raise
        `TooManyRedirects`/a connection error instead of ever seeing the
        header it needs.
    """
    from urllib.parse import quote

    from fuzzlab.oracle.probe import Candidate
    from fuzzlab.oracle.strategies import OpenRedirectStrategy
    from fuzzlab.tools.probesender import RequestsProbeSender

    manifest = load_manifest("lab/manifests/open_redirect_login_go_sample.yaml")
    emitter = GoEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    with GoLiveBootHarness(emitter, list(cells.values())) as harness:
        # (a) a legitimate next: both twins redirect identically.
        vuln_ok = harness.request("GET", "/generated/labgen-go-0027?next=/ok")
        assert vuln_ok.status == 302
        assert vuln_ok.headers.get("Location") == "/ok"

        secure_ok = harness.request("GET", "/generated/labgen-go-0028?next=/ok")
        assert secure_ok.status == 302
        assert secure_ok.headers.get("Location") == "/ok"

        # (b) vulnerable twin: an absolute external URL is reflected
        # verbatim into Location -- no CRLF needed at all.
        external = "https://evil.example/phish"
        vuln_bad = harness.request(
            "GET", f"/generated/labgen-go-0027?next={quote(external, safe='')}"
        )
        assert vuln_bad.status == 302, vuln_bad.body
        assert vuln_bad.headers.get("Location") == external, (
            f"vulnerable twin did not reflect the external next verbatim -- "
            f"headers were {vuln_bad.headers!r}"
        )

        # (c) secure twin: rejects the identical external-URL payload...
        secure_bad = harness.request(
            "GET", f"/generated/labgen-go-0028?next={quote(external, safe='')}"
        )
        assert secure_bad.status == 400, secure_bad.body
        assert "evil.example" not in (secure_bad.headers.get("Location") or "")

        # ...and every other open-redirect bypass shape this concern is
        # meant to close: protocol-relative and backslash-prefixed.
        for bypass in ("//evil.example", "/\\evil.example"):
            resp = harness.request(
                "GET", f"/generated/labgen-go-0028?next={quote(bypass, safe='')}"
            )
            assert resp.status == 400, (bypass, resp.status, resp.body)
            assert "evil.example" not in (resp.headers.get("Location") or "")

        # (d) OpenRedirectStrategy confirms the vulnerable twin for real,
        # over the network, with zero new detection code, and correctly
        # declines the secure twin -- also a live regression proof BUG-0042's
        # fix (allow_redirects=False) holds: a regression here would surface
        # as an exception from `sender.send`, not a wrong verdict.
        sender = RequestsProbeSender(timeout=10.0)
        strategy = OpenRedirectStrategy()

        vuln_candidate = Candidate(
            url=f"{harness.base_url}/generated/labgen-go-0027", param="next",
            method="GET", location="query",
        )
        verdict = strategy.confirm(vuln_candidate, sender)
        assert verdict is not None and verdict.confirmed, verdict
        assert verdict.vuln_class == "open_redirect"
        assert verdict.evidence.get("sink") == "location-header"

        secure_candidate = Candidate(
            url=f"{harness.base_url}/generated/labgen-go-0028", param="next",
            method="GET", location="query",
        )
        assert strategy.confirm(secure_candidate, sender) is None
