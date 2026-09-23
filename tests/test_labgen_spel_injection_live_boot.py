"""Live-boot conformance check for `spring_boot`'s SpEL-injection cell
(`CC-LAB-0214`, category 5 pilot's first Expedia-specific cell, CWE-917).

Real, on-host integration test, same shape as
`test_labgen_spring_boot_xxe_live_boot.py`'s own proof: assembles a real
Spring Boot project from the checked-in skeleton plus one cell's real
`SpringBootEmitter` output, runs a real `mvn package`, boots a real
executable jar, and sends real HTTP GET requests.

**Safety.** The canary payload is `T(java.lang.Math).abs(-99)`, a
side-effect-free type-reference/method-invocation SpEL expression
(deliberately not a `Runtime.exec`-shaped payload, even in this lab-only
sandbox) -- it proves the same "can an attacker reach a type reference/
method invocation at all" differential a dangerous payload would, without
actually invoking a process, per `CC-LAB-0214`'s own review-gate record.

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

_TYPE_REFERENCE_CANARY = "T(java.lang.Math).abs(-99)"
_BENIGN_EXPRESSION = "'price'"


def _cells() -> dict[str, object]:
    manifest = load_manifest("lab/manifests/expedia_spel_injection_sample.yaml")
    return {c.cell_id: c for c in manifest.cells}


def test_vulnerable_twin_evaluates_the_type_reference_for_real() -> None:
    """The vulnerable cell (`standard_evaluation_context_unrestricted`) must
    actually evaluate a `T(...)` type-reference/method-invocation SpEL
    expression -- the real CVE-2018-1273 differential -- against a real
    booted Spring Boot app, not just a structural/lint check."""
    cells = _cells()
    vulnerable = cells["LABGEN-EXP-0001"]
    emitter = SpringBootEmitter()
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        resp = harness.get("/api/hotels/search-sort", params={"sortBy": _TYPE_REFERENCE_CANARY})
        assert resp.status == 200, resp.body
        assert "99" in resp.body, resp.body

        benign_resp = harness.get("/api/hotels/search-sort", params={"sortBy": _BENIGN_EXPRESSION})
        assert benign_resp.status == 200, benign_resp.body
        assert "price" in benign_resp.body, benign_resp.body


def test_secure_twin_rejects_the_type_reference_but_still_evaluates_legitimate_expressions() -> None:
    """The secure cell (`simple_evaluation_context_restricted`) must reject
    any type-reference/method-invocation expression outright (a real HTTP
    error, never a silently-stripped-and-succeeded response) while still
    correctly evaluating a real, legitimate property-path-shaped expression
    -- proving the fix doesn't just break the feature."""
    cells = _cells()
    secure = cells["LABGEN-EXP-0002"]
    emitter = SpringBootEmitter()
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        injection_resp = harness.get("/api/hotels/search-sort", params={"sortBy": _TYPE_REFERENCE_CANARY})
        assert injection_resp.status == 400, injection_resp.body
        assert "99" not in injection_resp.body, injection_resp.body

        benign_resp = harness.get("/api/hotels/search-sort", params={"sortBy": _BENIGN_EXPRESSION})
        assert benign_resp.status == 200, benign_resp.body
        assert "price" in benign_resp.body, benign_resp.body
