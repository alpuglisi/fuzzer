"""Live-boot conformance check for `spring_boot`'s insecure-deserialization
cell (`CC-LAB-0132`, TrackerNest's third and final designed cell).

Real, on-host integration test, same shape as the SSTI/XXE live-boot
proofs: assembles a real Spring Boot project, runs a real `mvn package`,
boots a real executable jar, and sends real HTTP POSTs with a raw
Java-serialization-protocol body.

**Fixture generation.** Per `CC-LAB-0132`'s change-control entry, fixture
bytes are produced by running the skeleton's own
`com.fuzzlab.trackernest.tools.SerializeFixtureTool` helper directly against
the harness's own assembled `target/classes` (via the new
`SpringBootLiveBootHarness.app_dir` property), *after* entering the
harness's `with` block (assembly + real `mvn package` + real boot have all
already completed by then) -- Python cannot emit Java's serialization wire
format itself. Each twin's test boots its own separate harness instance and
regenerates both fixtures against its own copy of `target/classes`
(deliberately not shared across the two independent harness/test
boundaries -- see the change-control entry for why this is accepted as-is).

**Safety.** No gadget chain, no RCE-capable class anywhere on this
classpath -- `UnexpectedType` is an inert POJO holding a string, standing in
for whatever a real attack's class would be without including one.

Skip-guarded (PA-0005) on `spring_boot_boot_available()`. Marked
`@pytest.mark.slow`.
"""

from __future__ import annotations

import subprocess

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

_MARKER = "SECRET-MARKER-fuzzlab-deserialization-live-boot-test"


def _serialize_fixture(harness: SpringBootLiveBootHarness, class_name: str) -> bytes:
    """Runs the skeleton's own `SerializeFixtureTool` against this harness's
    real, already-compiled `target/classes` to produce real Java-
    serialization-protocol bytes -- see this module's own docstring."""
    result = subprocess.run(
        [
            "java", "-cp", str(harness.app_dir / "target" / "classes"),
            "com.fuzzlab.trackernest.tools.SerializeFixtureTool",
            class_name, _MARKER,
        ],
        capture_output=True,
        timeout=30.0,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return result.stdout


def test_deserialization_vulnerable_twin_constructs_the_unexpected_type_for_real() -> None:
    """The vulnerable cell (`function_executing_deserialize`) must actually
    construct whatever `Serializable` class a request's bytes name -- not
    just the endpoint's intended `WebhookEvent`."""
    manifest = load_manifest("lab/manifests/insecure_deserialization_spring_boot_sample.yaml")
    emitter = SpringBootEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-DESER-0001"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        webhook_bytes = _serialize_fixture(harness, "WebhookEvent")
        unexpected_bytes = _serialize_fixture(harness, "UnexpectedType")

        legit_resp = harness.post(
            "/integrations/webhook-payload", data=webhook_bytes, content_type="application/octet-stream"
        )
        assert legit_resp.status == 200, legit_resp.body
        assert "WebhookEvent" in legit_resp.body, legit_resp.body

        injection_resp = harness.post(
            "/integrations/webhook-payload", data=unexpected_bytes, content_type="application/octet-stream"
        )
        assert injection_resp.status == 200, injection_resp.body
        assert "UnexpectedType" in injection_resp.body, injection_resp.body
        assert _MARKER in injection_resp.body, injection_resp.body


def test_deserialization_secure_twin_rejects_the_unexpected_type_but_accepts_the_expected_one() -> None:
    """The secure cell (`handler_registry_lookup`) must reject any class
    other than the one allowlisted name with a real HTTP error, while still
    correctly deserializing the legitimate, expected type."""
    manifest = load_manifest("lab/manifests/insecure_deserialization_spring_boot_sample.yaml")
    emitter = SpringBootEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    secure = cells["LABGEN-DESER-0002"]
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        webhook_bytes = _serialize_fixture(harness, "WebhookEvent")
        unexpected_bytes = _serialize_fixture(harness, "UnexpectedType")

        legit_resp = harness.post(
            "/integrations/webhook-payload", data=webhook_bytes, content_type="application/octet-stream"
        )
        assert legit_resp.status == 200, legit_resp.body
        assert "WebhookEvent" in legit_resp.body, legit_resp.body

        injection_resp = harness.post(
            "/integrations/webhook-payload", data=unexpected_bytes, content_type="application/octet-stream"
        )
        assert injection_resp.status == 400, injection_resp.body
        assert "Rejected unexpected class" in injection_resp.body, injection_resp.body
        assert _MARKER not in injection_resp.body, injection_resp.body
