"""Real, executed live-boot proof for Netflix's eighth real page
(`CC-LAB-0193`, `FR-LAB-148`): this stack's first `jwt_algorithm_confusion`
instance, an account-level viewing-preferences lookup at
`GET /api/account/preferences`, gated by a Bearer JWT in the
`Authorization` header.

Mirrors `tests/test_labgen_go_live_boot.py`'s own
`test_real_boot_proves_the_jwt_alg_none_differential_for_both_twins`/
`test_real_boot_proves_the_jwt_alg_none_strategy_end_to_end`
(`CC-LAB-0180`/`CC-FUZZ-0037`) -- the same three-case differential-then-
strategy shape, ported to this stack's own `SpringBootLiveBootHarness`
(one cell per harness instance, so each twin gets its own boot).

A second test class (`Test...GeneralizesToSpringBoot`) proves
`JwtAlgNoneConfusionStrategy` (already built for Twitch's
`TWCH-0004`/`CC-FUZZ-0037`/`CC-AUD-0020`) needs zero new detection code to
confirm this new `spring_boot` vulnerable twin and correctly fail closed on
its secure twin -- the same generalization direction (`go_net_http` ->
`spring_boot`) `CC-LAB-0187`'s own `AccessControlIdorStrategy` proof,
`CC-LAB-0191`'s own `UnrestrictedFileUploadContentTypeTrustStrategy` proof,
and `CC-LAB-0192`'s own `MassAssignmentPrivilegedFieldStrategy` proof
already established for other vuln classes on this exact app.

Skip-guarded (PA-0005) on `spring_boot_boot_available()`. Marked
`@pytest.mark.slow`.
"""

from __future__ import annotations

import base64
import json

import pytest

from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import JwtAlgNoneConfusionStrategy

_MANIFEST_PATH = "lab/manifests/jwt_alg_confusion_netflix_sample.yaml"
_ROUTE = "/api/account/preferences"

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


def _b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _cells() -> dict[str, object]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


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
    emitter = SpringBootEmitter()
    cells = _cells()

    alg_none_token = (
        _b64url({"alg": "none", "typ": "JWT"}) + "."
        + _b64url({"channel_id": "attacker-account", "role": "owner"}) + "."
    )
    garbage_hs256_token = (
        _b64url({"alg": "HS256", "typ": "JWT"}) + "."
        + _b64url({"channel_id": "attacker-account", "role": "owner"}) + "."
        + "not-a-real-signature"
    )

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0015"]) as harness:
        # (a) vulnerable twin: alg:none is honored, forged claims returned.
        vuln_resp = harness.request(
            "GET", _ROUTE, headers={"Authorization": f"Bearer {alg_none_token}"}
        )
        assert vuln_resp.status == 200, (
            f"vulnerable twin rejected an alg:none token (status {vuln_resp.status}): {vuln_resp.body!r}"
        )
        assert "attacker-account" in vuln_resp.body and "owner" in vuln_resp.body, (
            f"vulnerable twin did not honor the forged claims: {vuln_resp.body!r}"
        )

        # (b) vulnerable twin: a garbage HS256 signature is still rejected.
        vuln_garbage_resp = harness.request(
            "GET", _ROUTE, headers={"Authorization": f"Bearer {garbage_hs256_token}"}
        )
        assert vuln_garbage_resp.status == 401, (
            f"vulnerable twin accepted a garbage HS256 signature (status {vuln_garbage_resp.status}): "
            f"{vuln_garbage_resp.body!r}"
        )

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0016"]) as harness:
        # (c) secure twin: the same alg:none token is rejected outright.
        secure_resp = harness.request(
            "GET", _ROUTE, headers={"Authorization": f"Bearer {alg_none_token}"}
        )
        assert secure_resp.status == 401, (
            f"secure twin accepted an alg:none token (status {secure_resp.status}): {secure_resp.body!r}"
        )
        assert "attacker-account" not in secure_resp.body


class TestJwtAlgNoneConfusionStrategyGeneralizesToSpringBoot:
    """Proves `JwtAlgNoneConfusionStrategy` needs zero new detection code
    to confirm this new `spring_boot` vulnerable twin and correctly fail
    closed on its secure twin."""

    def _candidate(self) -> Candidate:
        return Candidate(
            url="http://h" + _ROUTE, param="Authorization", method="GET", location="header",
            vuln_class="jwt_algorithm_confusion", category="jwt-algorithm-confusion",
        )

    def test_confirms_the_vulnerable_twin(self) -> None:
        emitter = SpringBootEmitter()
        vulnerable = _cells()["LABGEN-JV-0015"]
        strategy = JwtAlgNoneConfusionStrategy()

        with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
            class _HarnessSender:
                def send(self, url, param, value, timing=False, method="GET",
                          location="header", content_type=None):
                    resp = harness.request("GET", _ROUTE, headers={param: value})
                    return Probe(resp.status, resp.body)

            verdict = strategy.confirm(self._candidate(), _HarnessSender())
            assert verdict is not None and verdict.confirmed, (
                "strategy failed to confirm the real vulnerable spring_boot twin"
            )
            assert verdict.vuln_class == "jwt_algorithm_confusion"

    def test_fails_closed_on_the_secure_twin(self) -> None:
        emitter = SpringBootEmitter()
        secure = _cells()["LABGEN-JV-0016"]
        strategy = JwtAlgNoneConfusionStrategy()

        with SpringBootLiveBootHarness(emitter, secure) as harness:
            class _HarnessSender:
                def send(self, url, param, value, timing=False, method="GET",
                          location="header", content_type=None):
                    resp = harness.request("GET", _ROUTE, headers={param: value})
                    return Probe(resp.status, resp.body)

            assert strategy.confirm(self._candidate(), _HarnessSender()) is None, (
                "strategy incorrectly confirmed the real secure spring_boot twin"
            )
