"""Real, executed live-boot proof for Netflix's third real page
(`CC-LAB-0184`, `FR-LAB-154`): a second `insecure_deserialization` instance
at `/api/profiles/switch`, reusing `LABGEN-JV-0001`/`0002`'s own
`jackson_body`/`jackson_default_typing_deserialize`/`jackson_typed_
allowlist_deserialize` module set verbatim -- zero new generator code.

Mirrors `tests/test_labgen_spring_boot_deserialization_jackson_live_boot.py`
exactly (same three-assertion shape, same each-twin-its-own-boot pattern),
just against the new route/cell pair. The third test in this file is the
detection-generalization proof this whole increment exists to make: the
already-built `InsecureDeserializationTypeConfusionStrategy`
(`CC-FUZZ-0034`) is keyed on `vuln_class` + sink shape, not per-route, so it
is driven here against a real booted instance of the *new* route with zero
new strategy/rule code, exactly like `CC-LAB-0183`'s own analogous proof for
`AccessControlIdorStrategy`.

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

_MANIFEST_PATH = "lab/manifests/insecure_deserialization_netflix_profiles_sample.yaml"
_ROUTE = "/api/profiles/switch"

#: Same illustrative, inert JDK class as the playback-resume live-boot
#: test's own body -- demonstrates the endpoint lets the request body pick
#: the class, not a gadget chain.
_POLYMORPHIC_TYPE_HINT_BODY = b'["java.util.HashMap",{"profileId":"p2"}]'

#: A plain, flat JSON body matching `PlaybackResumeRequest`'s own fields --
#: the fixed DTO class the secure twin's template still hardcodes (the same
#: accepted cosmetic gap `CC-LAB-0179` recorded for its own shared XXE
#: templates' TrackerNest-flavored response text -- not fixed here either,
#: for the same reason: it would risk breaking the established playback-
#: resume test that asserts on it).
_PLAIN_BODY = b'{"profileId":"p2","eventType":"resume","positionMs":0}'

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


def test_vulnerable_twin_accepts_an_attacker_type_hinted_body() -> None:
    emitter = SpringBootEmitter()
    vulnerable = _cells()["LABGEN-JV-0005"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        resp = harness.post(_ROUTE, data=_POLYMORPHIC_TYPE_HINT_BODY, content_type="application/json")
        assert resp.status == 200, (
            f"vulnerable twin rejected an attacker-type-hinted body (status {resp.status}): {resp.body}"
        )


def test_secure_twin_accepts_plain_body_but_rejects_the_type_hinted_one() -> None:
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-JV-0006"]
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


def test_real_boot_proves_the_insecure_deserialization_strategy_generalizes_to_profiles_route() -> None:
    """Detection-generalization proof, verified for real against a real
    booted app, not asserted from theory: `InsecureDeserializationType
    ConfusionStrategy` (`CC-FUZZ-0034`, already built for `NFLX-0001`) needs
    zero new code to confirm this new vulnerable twin and correctly fail
    closed on its new secure twin -- the whole point of `CC-LAB-0184`."""
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import InsecureDeserializationTypeConfusionStrategy

    emitter = SpringBootEmitter()
    cells = _cells()

    def _cand():
        return Candidate(url=f"http://h{_ROUTE}", param="body", method="POST", location="body",
                         vuln_class="insecure_deserialization", category="insecure-deserialization",
                         content_type="application/json")

    strategy = InsecureDeserializationTypeConfusionStrategy()

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0005"]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                resp = harness.post(_ROUTE, data=value.encode("utf-8"), content_type=content_type)
                return Probe(resp.status, resp.body)

        verdict = strategy.confirm(_cand(), _HarnessSender())
        assert verdict is not None and verdict.confirmed, "strategy failed to confirm the real vulnerable twin"
        assert verdict.vuln_class == "insecure_deserialization"

    with SpringBootLiveBootHarness(emitter, cells["LABGEN-JV-0006"]) as harness:
        class _HarnessSender:
            def send(self, url, param, value, timing=False, method="POST",
                      location="body", content_type=None):
                resp = harness.post(_ROUTE, data=value.encode("utf-8"), content_type=content_type)
                return Probe(resp.status, resp.body)

        assert strategy.confirm(_cand(), _HarnessSender()) is None, (
            "strategy incorrectly confirmed the real secure twin"
        )
