"""Real, executed live-boot proof for Expedia's second own cell
(`CC-LAB-0220`, category 5 pilot) -- the trip-restore insecure-
deserialization shape at `/api/trips/restore`, closing the route-borrowing
gap `CC-LAB-0213`'s port left open (that entry's ported Netflix cell sits
on a borrowed Netflix route, not an Expedia-flavored one).

Mirrors `tests/test_labgen_spring_boot_deserialization_jackson_live_boot.py`'s
own structure exactly, since this manifest reuses the identical
`jackson_default_typing_deserialize`/`jackson_typed_allowlist_deserialize`
ops (no new emitter code) -- only the route/cell identity differs.

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

_MANIFEST_PATH = "lab/manifests/expedia_trip_restore_sample.yaml"
_ROUTE = "/api/trips/restore"

#: Same inert, always-on-the-classpath JDK class used by CC-LAB-0213's own
#: proof -- demonstrates the vulnerable endpoint lets the request body pick
#: the class, not a gadget chain.
_POLYMORPHIC_TYPE_HINT_BODY = b'["java.util.HashMap",{"tripId":"t1"}]'

#: A plain, flat JSON body matching PlaybackResumeRequest's own fields --
#: what the secure twin's fixed-DTO deserializer actually expects (this
#: shape reuses that same DTO class; a real Expedia-specific DTO is real,
#: sized follow-on work distinct from this page's own scope).
_PLAIN_BODY = b'{"profileId":"t1","eventType":"resume","positionMs":0}'

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


def test_trip_restore_vulnerable_twin_accepts_an_attacker_type_hinted_body() -> None:
    emitter = SpringBootEmitter()
    vulnerable = _cells()["LABGEN-EXP-0003"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        resp = harness.post(_ROUTE, data=_POLYMORPHIC_TYPE_HINT_BODY, content_type="application/json")
        assert resp.status == 200, (
            f"vulnerable twin rejected an attacker-type-hinted body (status {resp.status}): {resp.body}"
        )


def test_trip_restore_secure_twin_accepts_plain_body_but_rejects_the_type_hinted_one() -> None:
    emitter = SpringBootEmitter()
    secure = _cells()["LABGEN-EXP-0004"]
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
