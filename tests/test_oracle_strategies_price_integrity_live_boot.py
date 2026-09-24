"""Real, executed live-boot proof for `PriceTrustDifferentialStrategy`
(`CC-FUZZ-0041`/`FR-FUZZ-27`): this project's first real detection
capability for `price_integrity_bypass`, driven through a real
`RequestsProbeSender` against a real booted Spring Boot app -- never a
fake sender, mirroring `tests/test_oracle_strategies_unrestricted_file_
upload_live_boot.py`'s own real-sender discipline (`CC-FUZZ-0040`).

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
from fuzzlab.oracle.strategies import PriceTrustDifferentialStrategy
from fuzzlab.tools.probesender import RequestsProbeSender

_MANIFEST_PATH = "lab/manifests/price_integrity_netflix_subscription_sample.yaml"
_ROUTE = "/api/subscription/change-plan"

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


def _cand(base_url: str) -> Candidate:
    return Candidate(url=base_url + _ROUTE, param="body", method="POST", location="body",
                     vuln_class="price_integrity_bypass", category="price-integrity-bypass",
                     content_type="application/json")


def test_real_boot_proves_the_price_integrity_bypass_strategy_confirms_the_vulnerable_twin() -> None:
    emitter = SpringBootEmitter()
    vulnerable = _cells()["LABGEN-JV-0009"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    strategy = PriceTrustDifferentialStrategy()
    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        sender = RequestsProbeSender()
        verdict = strategy.confirm(_cand(harness.base_url), sender)
        assert verdict is not None and verdict.confirmed, "strategy failed to confirm the real vulnerable twin"
        assert verdict.vuln_class == "price_integrity_bypass"
        assert verdict.evidence["low"] == 0.01
        assert verdict.evidence["high"] == 999999.99


def test_real_boot_proves_the_price_integrity_bypass_strategy_fails_closed_on_the_secure_twin() -> None:
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0010"]
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    strategy = PriceTrustDifferentialStrategy()
    with SpringBootLiveBootHarness(emitter, secure) as harness:
        sender = RequestsProbeSender()
        verdict = strategy.confirm(_cand(harness.base_url), sender)
        assert verdict is None, (
            f"strategy incorrectly confirmed the real secure twin (should fail closed): {verdict}"
        )
