"""Live-boot conformance check for Netflix's second real cell, partner
content-metadata ingestion XXE (`CC-LAB-0179`, reusing TrackerNest's own
already-built/live-boot-proved `CC-LAB-0131` shape at a new route).

Mirrors `tests/test_labgen_spring_boot_xxe_live_boot.py`'s own convention
exactly, adapted to `/api/content/import` and this cell's own `LABGEN-JV-`
prefix. **Accepted, stated cosmetic gap**: the shared `xml_external_
entities_enabled/_disabled` sink templates hardcode TrackerNest-flavored
response text ("Imported issue title: ..."), which this test therefore
does not assert on directly -- only the marker/title *content*, which is
genuinely shared, correct behavior regardless of the surrounding wording.

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

_FIXTURE_MARKER = "SECRET-MARKER-fuzzlab-netflix-xxe-live-boot-test"


def _xxe_payload(fixture_path: str) -> bytes:
    return (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE contentFeed [<!ENTITY xxe SYSTEM "file://{fixture_path}">]>'
        "<contentFeed><title>&xxe;</title></contentFeed>"
    ).encode("utf-8")


_BENIGN_PAYLOAD = b"<contentFeed><title>Stranger Things S5</title></contentFeed>"


def test_netflix_xxe_vulnerable_twin_resolves_the_external_entity_for_real() -> None:
    fixture = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        fixture.write(_FIXTURE_MARKER)
        fixture.close()

        manifest = load_manifest("lab/manifests/xxe_netflix_sample.yaml")
        emitter = SpringBootEmitter()
        cells = {c.cell_id: c for c in manifest.cells}
        vulnerable = cells["LABGEN-JV-0003"]
        assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

        with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
            resp = harness.post("/api/content/import", data=_xxe_payload(fixture.name))
            assert resp.status == 200, resp.body
            assert _FIXTURE_MARKER in resp.body, resp.body

            benign_resp = harness.post("/api/content/import", data=_BENIGN_PAYLOAD)
            assert benign_resp.status == 200, benign_resp.body
            assert "Stranger Things S5" in benign_resp.body, benign_resp.body
    finally:
        os.unlink(fixture.name)


def test_netflix_xxe_secure_twin_rejects_the_doctype_but_still_parses_legitimate_documents() -> None:
    fixture = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    try:
        fixture.write(_FIXTURE_MARKER)
        fixture.close()

        manifest = load_manifest("lab/manifests/xxe_netflix_sample.yaml")
        emitter = SpringBootEmitter()
        cells = {c.cell_id: c for c in manifest.cells}
        secure = cells["LABGEN-JV-0004"]
        assert emitter.supports(secure.vuln_class, secure.sink_context)

        with SpringBootLiveBootHarness(emitter, secure) as harness:
            injection_resp = harness.post("/api/content/import", data=_xxe_payload(fixture.name))
            assert injection_resp.status == 400, injection_resp.body
            assert _FIXTURE_MARKER not in injection_resp.body, injection_resp.body

            benign_resp = harness.post("/api/content/import", data=_BENIGN_PAYLOAD)
            assert benign_resp.status == 200, benign_resp.body
            assert "Stranger Things S5" in benign_resp.body, benign_resp.body
    finally:
        os.unlink(fixture.name)
