"""Real, executed live-boot proof for Netflix's fourth real page
(`CC-LAB-0187`, `FR-LAB-142`): this stack's first `access_control`/IDOR
instance, an account-billing-details lookup at `GET /api/account/billing`.

Mirrors `tests/test_labgen_spring_boot_deserialization_netflix_profiles_
live_boot.py`'s own shape (each-twin-its-own-boot, a third test proving the
already-built oracle strategy generalizes with zero new detection code) --
here for `AccessControlIdorStrategy` (`CC-FUZZ-0033`, already built for
Twitch's `TWCH-0003`/`CC-LAB-0178`), the same generalization proof
`CC-LAB-0183` made for Twitch's own second `access_control` instance,
extended for the first time to a genuinely different stack
(`go_net_http` -> `spring_boot`).

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

_MANIFEST_PATH = "lab/manifests/access_control_netflix_billing_sample.yaml"
_ROUTE = "/api/account/billing"
_ID_A = "50172"
_ID_B = "88190475"

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


def test_vulnerable_twin_returns_arbitrary_accounts_billing_data() -> None:
    emitter = SpringBootEmitter()
    vulnerable = _cells()["LABGEN-JV-0007"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        resp_a = harness.get(_ROUTE, params={"account_id": _ID_A})
        assert resp_a.status == 200, f"vulnerable twin rejected id A: {resp_a.body}"
        assert _ID_A in resp_a.body

        resp_b = harness.get(_ROUTE, params={"account_id": _ID_B})
        assert resp_b.status == 200, f"vulnerable twin rejected id B: {resp_b.body}"
        assert _ID_B in resp_b.body

        assert resp_a.body != resp_b.body, "vulnerable twin returned identical bodies for two distinct ids"


def test_secure_twin_requires_the_caller_identity_header_to_match() -> None:
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0008"]
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        mismatch_resp = harness.get(
            _ROUTE, params={"account_id": _ID_A}, headers={"X-Account-Id": _ID_B}
        )
        assert mismatch_resp.status == 403, (
            f"secure twin should reject a mismatched caller identity (status {mismatch_resp.status}): "
            f"{mismatch_resp.body}"
        )

        match_resp = harness.get(
            _ROUTE, params={"account_id": _ID_A}, headers={"X-Account-Id": _ID_A}
        )
        assert match_resp.status == 200, (
            f"secure twin rejected a matching caller identity (status {match_resp.status}): {match_resp.body}"
        )
        assert _ID_A in match_resp.body

        no_header_resp = harness.get(_ROUTE, params={"account_id": _ID_A})
        assert no_header_resp.status == 403, (
            "secure twin should reject a request with no caller-identity header at all "
            f"(status {no_header_resp.status}): {no_header_resp.body}"
        )


def test_real_boot_proves_the_access_control_idor_strategy_generalizes_to_spring_boot() -> None:
    """Detection-generalization proof, verified for real against a real
    booted app, not asserted from theory: `AccessControlIdorStrategy`
    (`CC-FUZZ-0033`, already built for Twitch's `go_net_http` cells) needs
    zero new code to confirm this new Spring Boot vulnerable twin and
    correctly fail closed on its new secure twin."""
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import AccessControlIdorStrategy

    emitter = SpringBootEmitter()
    cells = _cells()

    def _cand():
        return Candidate(url=f"http://h{_ROUTE}", param="account_id", method="GET", location="query",
                         vuln_class="access_control", category="access-control")

    strategy = AccessControlIdorStrategy()

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0007"]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="GET", location="query", content_type=None):
                resp = harness.get(_ROUTE, params={param: value})
                return Probe(resp.status, resp.body)

        verdict = strategy.confirm(_cand(), _HarnessSender())
        assert verdict is not None and verdict.confirmed, "strategy failed to confirm the real vulnerable twin"
        assert verdict.vuln_class == "access_control"

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0008"]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="GET", location="query", content_type=None):
                resp = harness.get(_ROUTE, params={param: value})
                return Probe(resp.status, resp.body)

        assert strategy.confirm(_cand(), _HarnessSender()) is None, (
            "strategy incorrectly confirmed the real secure twin"
        )
