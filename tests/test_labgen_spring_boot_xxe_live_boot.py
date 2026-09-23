"""Live-boot conformance check for `spring_boot`'s XXE cell (`CC-LAB-0131`,
TrackerNest's second cell).

Real, on-host integration test, same shape as
`test_labgen_spring_boot_live_boot.py`'s SSTI proof: assembles a real
Spring Boot project from the checked-in skeleton plus one cell's real
`SpringBootEmitter` output, runs a real `mvn package`, boots a real
executable jar, and sends a real HTTP POST with a raw XML body.

**Safety.** The classic external-entity-resolution proof-of-concept reads a
local file via a `file://` `SYSTEM` identifier. The target here is a fixture
file this test creates and owns for the duration of one test run
(`tempfile.NamedTemporaryFile`, deleted in a `finally`) -- never a real host
path -- per `CC-LAB-0131`'s own risk mitigation, mirroring this project's
existing safety discipline for other exploit-shaped proofs (e.g. the
mass-assignment live-boot test's syntax-injection-shaped key).

Skip-guarded (PA-0005) on `spring_boot_boot_available()`. Marked
`@pytest.mark.slow`.
"""

from __future__ import annotations

import os
import tempfile

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

_FIXTURE_MARKER = "SECRET-MARKER-fuzzlab-xxe-live-boot-test"


def _xxe_payload(fixture_path: str) -> bytes:
    return (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE issue [<!ENTITY xxe SYSTEM "file://{fixture_path}">]>'
        "<issue><title>&xxe;</title></issue>"
    ).encode("utf-8")


_BENIGN_PAYLOAD = b"<issue><title>Normal title</title></issue>"


def test_xxe_vulnerable_twin_resolves_the_external_entity_for_real() -> None:
    """The vulnerable cell (`xml_external_entities_enabled`) must actually
    resolve a DOCTYPE-declared external entity referencing a real, harness-
    owned fixture file -- the classic XXE local-file-read proof, against a
    target this test creates and controls, never a real host path."""
    fixture = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        fixture.write(_FIXTURE_MARKER)
        fixture.close()

        manifest = load_manifest("lab/manifests/xxe_spring_boot_sample.yaml")
        emitter = SpringBootEmitter()
        cells = {c.cell_id: c for c in manifest.cells}
        vulnerable = cells["LABGEN-XXE-0001"]
        assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

        with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
            resp = harness.post("/issues/import", data=_xxe_payload(fixture.name))
            assert resp.status == 200, resp.body
            assert _FIXTURE_MARKER in resp.body, resp.body

            benign_resp = harness.post("/issues/import", data=_BENIGN_PAYLOAD)
            assert benign_resp.status == 200, benign_resp.body
            assert "Normal title" in benign_resp.body, benign_resp.body
    finally:
        os.unlink(fixture.name)


def test_xxe_secure_twin_rejects_the_doctype_but_still_parses_legitimate_documents() -> None:
    """The secure cell (`xml_external_entities_disabled`) must reject any
    document containing a DOCTYPE outright (a real HTTP error, never a
    silently-stripped-and-succeeded response) while still correctly parsing
    a real, legitimate document with no DOCTYPE at all."""
    fixture = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        fixture.write(_FIXTURE_MARKER)
        fixture.close()

        manifest = load_manifest("lab/manifests/xxe_spring_boot_sample.yaml")
        emitter = SpringBootEmitter()
        cells = {c.cell_id: c for c in manifest.cells}
        secure = cells["LABGEN-XXE-0002"]
        assert emitter.supports(secure.vuln_class, secure.sink_context)

        with SpringBootLiveBootHarness(emitter, secure) as harness:
            injection_resp = harness.post("/issues/import", data=_xxe_payload(fixture.name))
            assert injection_resp.status == 400, injection_resp.body
            assert _FIXTURE_MARKER not in injection_resp.body, injection_resp.body

            benign_resp = harness.post("/issues/import", data=_BENIGN_PAYLOAD)
            assert benign_resp.status == 200, benign_resp.body
            assert "Normal title" in benign_resp.body, benign_resp.body
    finally:
        os.unlink(fixture.name)


def test_real_boot_proves_the_xxe_strategy_end_to_end() -> None:
    """The real `XxeInBandMarkerStrategy`/`XxeOobStrategy`
    (CC-FUZZ-0031/FR-FUZZ-18), driven against a real booted app rather than
    a fake sender: confirms the vulnerable twin and fails closed on the
    secure twin, using the exact `OobListener`-only payload the strategies
    themselves send (never `file://`, per this file's own safety
    discipline above)."""
    from fuzzlab.oracle.oob import OobListener
    from fuzzlab.oracle.probe import Candidate, Probe
    from fuzzlab.oracle.strategies import XxeInBandMarkerStrategy

    manifest = load_manifest("lab/manifests/xxe_spring_boot_sample.yaml")
    emitter = SpringBootEmitter()
    cells = {c.cell_id: c for c in manifest.cells}

    def _cand():
        return Candidate(url="http://h/issues/import", param="body", method="POST",
                         location="body", vuln_class="xxe", category="xxe")

    listener = OobListener()
    listener.start()
    try:
        strategy = XxeInBandMarkerStrategy(listener)

        with SpringBootLiveBootHarness(emitter, cells["LABGEN-XXE-0001"]) as harness:
            class _HarnessSender:
                def send(self, url, param, value, timing=False, method="POST",
                          location="body", content_type=None):
                    resp = harness.post("/issues/import", data=value.encode("utf-8"))
                    return Probe(resp.status, resp.body)

            verdict = strategy.confirm(_cand(), _HarnessSender())
            assert verdict is not None and verdict.confirmed, (
                "strategy failed to confirm the real vulnerable twin"
            )
            assert verdict.vuln_class == "xxe"

        with SpringBootLiveBootHarness(emitter, cells["LABGEN-XXE-0002"]) as harness:
            class _HarnessSender:
                def send(self, url, param, value, timing=False, method="POST",
                          location="body", content_type=None):
                    resp = harness.post("/issues/import", data=value.encode("utf-8"))
                    return Probe(resp.status, resp.body)

            assert strategy.confirm(_cand(), _HarnessSender()) is None, (
                "strategy incorrectly confirmed the real secure twin"
            )
    finally:
        listener.stop()
