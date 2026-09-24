"""Real, executed live-boot proof for Netflix's tenth real page
(`CC-LAB-0195`, `FR-LAB-150`): this stack's first `weak_token_entropy`
instance, a session/token-refresh endpoint at `POST /api/session/refresh`.

Mirrors `tests/test_labgen_go_live_boot.py`'s own
`test_real_boot_proves_the_weak_token_entropy_differential_for_both_twins`/
`test_real_boot_proves_the_weak_token_entropy_strategy_end_to_end`
(`CC-LAB-0181`/`CC-FUZZ-0038`) -- the same two-case differential-then-
strategy shape, ported to this stack's own `SpringBootLiveBootHarness`
(one cell per harness instance, so each twin gets its own boot).

A second test class (`Test...GeneralizesToSpringBoot`) proves
`PredictableTokenSourceStrategy` (already built for Twitch's
`TWCH-0005`/`CC-FUZZ-0038`/`CC-AUD-0021`) needs zero new detection code to
confirm this new `spring_boot` vulnerable twin and correctly fail closed on
its secure twin -- the same generalization direction (`go_net_http` ->
`spring_boot`) `CC-LAB-0187`'s own `AccessControlIdorStrategy` proof,
`CC-LAB-0191`'s own `UnrestrictedFileUploadContentTypeTrustStrategy` proof,
`CC-LAB-0192`'s own `MassAssignmentPrivilegedFieldStrategy` proof,
`CC-LAB-0193`'s own `JwtAlgNoneConfusionStrategy` proof, and `CC-LAB-0194`'s
own `SsrfInBandMarkerStrategy`/`SsrfOobStrategy` proof already established
for other vuln classes on this exact app.

Skip-guarded (PA-0005) on `spring_boot_boot_available()`. Marked
`@pytest.mark.slow`.
"""

from __future__ import annotations

import json
import time

import pytest

from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest

_MANIFEST_PATH = "lab/manifests/weak_token_entropy_netflix_sample.yaml"
_ROUTE = "/api/session/refresh"

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


def test_real_boot_proves_the_weak_token_entropy_differential_for_both_twins() -> None:
    """Two cases, isolating exactly what token generation controls:

    (a) the vulnerable twin's two consecutive tokens both parse as
        decimal integers whose difference tracks real elapsed wall-clock
        time (`System.nanoTime()`-derived, CWE-330).
    (b) the secure twin's tokens are 64-character hex strings that never
        parse as base-10 integers at all (`SecureRandom`-sourced).
    """
    emitter = SpringBootEmitter()
    cells = _cells()

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0019"]) as harness:
        t0 = time.time()
        vuln_r1 = harness.request("POST", _ROUTE)
        vuln_r2 = harness.request("POST", _ROUTE)
        elapsed_ns = (time.time() - t0) * 1e9
        assert vuln_r1.status == 200 and vuln_r2.status == 200
        token1 = json.loads(vuln_r1.body)["session_token"]
        token2 = json.loads(vuln_r2.body)["session_token"]
        delta = int(token2) - int(token1)   # raises if either isn't a real integer
        assert 0 <= delta <= max(elapsed_ns * 50, 1e8), (
            f"vulnerable twin's token delta ({delta}ns) is not consistent with "
            f"real elapsed time (~{elapsed_ns:.0f}ns) -- not actually nanoTime()-derived"
        )

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0020"]) as harness:
        secure_r1 = harness.request("POST", _ROUTE)
        secure_r2 = harness.request("POST", _ROUTE)
        assert secure_r1.status == 200 and secure_r2.status == 200
        secure_token1 = json.loads(secure_r1.body)["session_token"]
        secure_token2 = json.loads(secure_r2.body)["session_token"]
        for tok in (secure_token1, secure_token2):
            assert len(tok) == 64
            with pytest.raises(ValueError):
                int(tok)
        assert secure_token1 != secure_token2


class TestPredictableTokenSourceStrategyGeneralizesToSpringBoot:
    """Proves `PredictableTokenSourceStrategy` (already built for Twitch's
    `TWCH-0005`/`CC-FUZZ-0038`) needs zero new detection code to confirm
    this new `spring_boot` vulnerable twin and correctly fail closed on
    its secure twin."""

    def _candidate(self):
        from fuzzlab.oracle.probe import Candidate
        return Candidate(
            url="http://h" + _ROUTE, param="body", method="POST", location="body",
            vuln_class="weak_token_entropy", category="weak-token-entropy",
            content_type="application/json",
        )

    def test_confirms_the_vulnerable_twin(self) -> None:
        from fuzzlab.oracle.probe import Probe
        from fuzzlab.oracle.strategies import PredictableTokenSourceStrategy

        emitter = SpringBootEmitter()
        vulnerable = _cells()["LABGEN-JV-0019"]

        with SpringBootLiveBootHarness(emitter, vulnerable) as harness:

            class _HarnessSender:
                def send(self, url, param, value, timing=False, method="POST",
                          location="body", content_type=None):
                    resp = harness.request("POST", _ROUTE, data=value.encode("utf-8"),
                                           content_type=content_type)
                    return Probe(resp.status, resp.body)

            verdict = PredictableTokenSourceStrategy().confirm(self._candidate(), _HarnessSender())
            assert verdict is not None and verdict.confirmed, (
                "PredictableTokenSourceStrategy failed to confirm the real vulnerable spring_boot twin"
            )
            assert verdict.vuln_class == "weak_token_entropy"

    def test_fails_closed_on_the_secure_twin(self) -> None:
        from fuzzlab.oracle.probe import Probe
        from fuzzlab.oracle.strategies import PredictableTokenSourceStrategy

        emitter = SpringBootEmitter()
        secure = _cells()["LABGEN-JV-0020"]

        with SpringBootLiveBootHarness(emitter, secure) as harness:

            class _HarnessSender:
                def send(self, url, param, value, timing=False, method="POST",
                          location="body", content_type=None):
                    resp = harness.request("POST", _ROUTE, data=value.encode("utf-8"),
                                           content_type=content_type)
                    return Probe(resp.status, resp.body)

            assert PredictableTokenSourceStrategy().confirm(self._candidate(), _HarnessSender()) is None, (
                "PredictableTokenSourceStrategy incorrectly confirmed the secure spring_boot twin"
            )
