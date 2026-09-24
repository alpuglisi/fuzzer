"""Real, executed live-boot proof for the Netflix cell ported into
`spring_boot` by `CC-LAB-0173` (the §9.2a Java/Spring Boot consolidation --
originally `CC-LAB-0171` on the now-retired `java_spring_boot` package).

Mirrors `tests/test_labgen_spring_boot_deserialization_live_boot.py`'s own
convention exactly: each twin gets its own separate
`SpringBootLiveBootHarness(emitter, single_cell)` instance (never both
twins live-booted in the same running app -- this stack's own established
one-cell-per-boot pattern, which is also why both twins can safely share
the literal route `/api/playback/resume`, matching TrackerNest's own
`LABGEN-DESER-0001`/`0002` twin pair's identical-route precedent).

**Coverage-shrinkage check (per `CC-LAB-0173`'s own change-control
commitment): this test asserts everything the deleted
`tests/test_labgen_java_live_boot.py` asserted**, adapted to
`spring_boot`'s real HTTP contract (its `post()` takes `content_type`, not
a `headers` dict) -- the same three cases: (a) the vulnerable twin accepts
a type-hint-wrapped body naming an arbitrary class; (b) the secure twin
accepts its own well-formed, plain-flat-JSON request shape; (c) the secure
twin rejects the same type-hint-wrapped body the vulnerable twin accepted.

**What this proves, concretely (verified against a real boot this
session, not assumed).** Jackson's (3.x, `tools.jackson.databind.*`, not
Jackson 2's `com.fasterxml.jackson.databind.*` the original cell used)
`JsonMapper.builder().activateDefaultTyping(...)` changes what JSON
*shape* the vulnerable endpoint accepts: with default typing active,
Jackson requires an embedded type hint -- a
`["<fully-qualified-class-name>", {...}]`-shaped body -- and uses that
attacker-supplied class name to pick the concrete type it instantiates.
The secure twin's fixed-DTO deserializer has no such polymorphic
type-selection step at all: it accepts a plain, flat JSON object matching
`PlaybackResumeRequest`'s own fields, and rejects the type-hint-wrapped
shape. This is **not** a working `ysoserial`-style RCE gadget chain
(neither twin has one on its classpath -- a deliberate, declared scope
boundary carried over from the original `CC-LAB-0171` entry, not an
oversight) and **not** a timing side channel (CWE-502 has none to prove
here) -- the same honest "code-path proof, not a working exploit" scoping
the original test used.

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

_MANIFEST_PATH = "lab/manifests/insecure_deserialization_spring_boot_sample.yaml"
_ROUTE = "/api/playback/resume"

#: A body carrying an attacker-chosen type hint Jackson's default typing
#: will honor -- `java.util.HashMap`, a real, always-on-the-classpath JDK
#: class chosen here only to demonstrate that *the vulnerable endpoint
#: lets the request body pick the class*, not to demonstrate a gadget
#: chain (HashMap is inert).
_POLYMORPHIC_TYPE_HINT_BODY = b'["java.util.HashMap",{"profileId":"p1"}]'

#: A plain, flat JSON body matching `PlaybackResumeRequest`'s own fields --
#: what the secure twin's fixed-DTO deserializer actually expects.
_PLAIN_BODY = b'{"profileId":"p1","eventType":"resume","positionMs":1200}'

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


def test_ported_vulnerable_twin_accepts_an_attacker_type_hinted_body() -> None:
    emitter = SpringBootEmitter()
    vulnerable = _cells()["LABGEN-JV-0001"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        resp = harness.post(_ROUTE, data=_POLYMORPHIC_TYPE_HINT_BODY, content_type="application/json")
        assert resp.status == 200, (
            f"vulnerable twin rejected an attacker-type-hinted body (status {resp.status}): {resp.body}"
        )


def test_ported_secure_twin_accepts_plain_body_but_rejects_the_type_hinted_one() -> None:
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0002"]
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        plain_resp = harness.post(_ROUTE, data=_PLAIN_BODY, content_type="application/json")
        assert plain_resp.status == 200, (
            f"secure twin rejected its own well-formed request shape (status {plain_resp.status}): "
            f"{plain_resp.body}"
        )

        poly_resp = harness.post(_ROUTE, data=_POLYMORPHIC_TYPE_HINT_BODY, content_type="application/json")
        assert poly_resp.status != 200, (
            "secure twin accepted an attacker-type-hinted body -- it should have no polymorphic "
            "deserialization path to honor that hint on"
        )


def test_real_boot_proves_the_insecure_deserialization_strategy_end_to_end() -> None:
    """The real `InsecureDeserializationTypeConfusionStrategy`
    (CC-FUZZ-0034/FR-FUZZ-21), driven against a real booted app rather than
    a fake sender: confirms the vulnerable twin and fails closed on the
    secure twin, using the exact two-probe differential the strategy
    itself sends."""
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import InsecureDeserializationTypeConfusionStrategy

    emitter = SpringBootEmitter()
    cells = _cells()

    def _cand():
        return Candidate(url=f"http://h{_ROUTE}", param="body", method="POST", location="body",
                         vuln_class="insecure_deserialization", category="insecure-deserialization",
                         content_type="application/json")

    strategy = InsecureDeserializationTypeConfusionStrategy()

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0001"]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                resp = harness.post(_ROUTE, data=value.encode("utf-8"), content_type=content_type)
                return Probe(resp.status, resp.body)

        verdict = strategy.confirm(_cand(), _HarnessSender())
        assert verdict is not None and verdict.confirmed, "strategy failed to confirm the real vulnerable twin"
        assert verdict.vuln_class == "insecure_deserialization"

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0002"]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                resp = harness.post(_ROUTE, data=value.encode("utf-8"), content_type=content_type)
                return Probe(resp.status, resp.body)

        assert strategy.confirm(_cand(), _HarnessSender()) is None, (
            "strategy incorrectly confirmed the real secure twin"
        )
