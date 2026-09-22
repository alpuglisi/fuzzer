"""Emitter-level tests for `java_spring_boot` (category 4 pilot,
`CC-LAB-0171`/`FR-LAB-77`): `JavaEmitter.render`, plus a real, executed
`mvn -q compile` Tier 0 lint pass over the rendered output -- this
project's JVM analogue of `go vet` (`tests/test_labgen_go_net_http.py`'s
own convention). Skip-guarded on `java_boot_available()` since compiling
against Spring Boot needs the same resolved dependencies the live-boot
harness needs (PA-0005/PA-0035 pattern; the trade-off -- Tier 0 for this
stack is not fully offline -- is acknowledged, not silently assumed,
per `CC-LAB-0171`'s own adequacy review).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance.java_live_boot import java_boot_available
from fuzzlab.labgen.emitters.java_spring_boot import GENERATED_PACKAGE, JavaEmitter
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext

_FAMILY = "object_deserialization"


def _cell(cell_id: str, ops: list[str]) -> Cell:
    return Cell(
        cell_id=cell_id,
        vuln_class="insecure_deserialization",
        stack_profile="java_spring_boot",
        route=Route(method="POST", path="/api/playback/resume"),
        sink_context=SinkContext(family=_FAMILY, required_neutralizations=["insecure_deserialization"]),
        transform=Pipeline(ops=ops),
    )


VULN_CELL = _cell("LABGEN-JV-0001", ["jackson_default_typing_deserialize"])
SECURE_CELL = _cell("LABGEN-JV-0002", ["jackson_typed_allowlist_deserialize"])


def test_supports_only_the_one_phase_a_shape() -> None:
    em = JavaEmitter()
    assert em.supports("insecure_deserialization", SinkContext(family=_FAMILY, required_neutralizations=[]))
    assert not em.supports("sqli", SinkContext(family="sql_numeric_literal", required_neutralizations=[]))


def test_render_unsupported_cell_raises() -> None:
    em = JavaEmitter()
    bad = _cell("LABGEN-JV-9999", [])
    object.__setattr__(bad, "vuln_class", "sqli")
    with pytest.raises(ValueError):
        em.render(bad)


def test_vulnerable_twin_uses_default_typing_into_object() -> None:
    em = JavaEmitter()
    (emitted,) = em.render(VULN_CELL)
    code = emitted.content.decode()
    assert "activateDefaultTyping" in code
    assert "Object event = mapper.readValue" in code
    assert emitted.path == "src/main/java/com/fuzzlab/lab/cells/CellLabgenJv0001.java"
    assert f"package {GENERATED_PACKAGE};" in code


def test_secure_twin_uses_fixed_dto() -> None:
    em = JavaEmitter()
    (emitted,) = em.render(SECURE_CELL)
    code = emitted.content.decode()
    assert "activateDefaultTyping" not in code
    assert "PlaybackResumeRequest event = mapper.readValue" in code


def test_twin_pair_maps_to_distinct_cell_derived_paths() -> None:
    em = JavaEmitter()
    (vuln,) = em.render(VULN_CELL)
    (secure,) = em.render(SECURE_CELL)
    assert '@PostMapping("/generated/labgen-jv-0001")' in vuln.content.decode()
    assert '@PostMapping("/generated/labgen-jv-0002")' in secure.content.decode()


def test_two_renders_of_the_same_cell_are_byte_identical() -> None:
    em = JavaEmitter()
    (first,) = em.render(VULN_CELL)
    (second,) = em.render(VULN_CELL)
    assert first.content == second.content


@pytest.mark.skipif(
    not java_boot_available(), reason="mvn/java toolchain not available (PA-0005/PA-0035 pattern)"
)
def test_rendered_controllers_pass_mvn_compile() -> None:
    """Real Tier-0 lint: assembles the vulnerable+secure cells onto the real
    checked-in skeleton and runs a real `mvn -q compile` -- the JVM
    analogue of `go vet`/`php -l`/`node --check` (a bare syntax check does
    not exist for Java; `mvn compile` parses and type-checks, a strictly
    stronger and still-reasonably-fast real check)."""
    em = JavaEmitter()
    skeleton = Path(__file__).resolve().parent.parent / "fuzzlab/labgen/emitters/java_spring_boot/stack/skeleton"
    with tempfile.TemporaryDirectory(prefix="fuzzlab-java-spring-boot-tier0-") as tmp:
        app_dir = Path(tmp) / "app"
        shutil.copytree(skeleton, app_dir)
        for cell in (VULN_CELL, SECURE_CELL):
            (emitted,) = em.render(cell)
            dest = app_dir / emitted.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(emitted.content)

        result = subprocess.run(
            ["mvn", "-q", "-B", "compile"],
            cwd=app_dir,
            capture_output=True,
            text=True,
            timeout=180.0,
        )
        assert result.returncode == 0, f"mvn compile failed:\nstdout={result.stdout}\nstderr={result.stderr}"
