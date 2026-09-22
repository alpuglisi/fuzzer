"""Emitter-level tests for `go_net_http` (category 4 pilot,
`CC-LAB-0090`/`FR-LAB-64`): `GoEmitter.render`/`render_route_accumulator`,
plus a real, executed `go vet`/`gofmt -l`-equivalent Tier 0 lint pass over
the rendered output -- this project's Go analogue of `node --check`
(`tests/test_labgen_node_express.py`'s own convention), skip-guarded when
`go` isn't on the build host (PA-0005).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from fuzzlab.labgen.emitters.go_net_http import GoEmitter
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext

_FAMILY = "webhook_signature_verification"


def _cell(cell_id: str, ops: list[str]) -> Cell:
    return Cell(
        cell_id=cell_id,
        vuln_class="webhook_signature",
        stack_profile="go_net_http",
        route=Route(method="POST", path="/webhooks/eventsub"),
        sink_context=SinkContext(family=_FAMILY, required_neutralizations=["weak_signature_comparison"]),
        transform=Pipeline(ops=ops),
    )


VULN_CELL = _cell("LABGEN-GO-0001", ["naive_string_compare"])
SECURE_CELL = _cell("LABGEN-GO-0002", ["constant_time_compare"])


def test_supports_only_the_one_phase_a_shape() -> None:
    em = GoEmitter()
    assert em.supports("webhook_signature", SinkContext(family=_FAMILY, required_neutralizations=[]))
    assert not em.supports("sqli", SinkContext(family="sql_numeric_literal", required_neutralizations=[]))


def test_render_unsupported_cell_raises() -> None:
    em = GoEmitter()
    bad = _cell("LABGEN-GO-9999", [])
    object.__setattr__(bad, "vuln_class", "sqli")
    with pytest.raises(ValueError):
        em.render(bad)


def test_vulnerable_twin_uses_naive_go_equality() -> None:
    em = GoEmitter()
    (emitted,) = em.render(VULN_CELL)
    code = emitted.content.decode()
    assert "headerSig == computed" in code
    assert "hmac.Equal" not in code
    assert emitted.path == "labgen_go_0001.go"


def test_secure_twin_uses_hmac_equal() -> None:
    em = GoEmitter()
    (emitted,) = em.render(SECURE_CELL)
    code = emitted.content.decode()
    assert "hmac.Equal([]byte(headerSig), []byte(computed))" in code


def test_render_route_accumulator_sorts_by_cell_id_and_uses_cell_derived_paths() -> None:
    em = GoEmitter()
    accumulator = em.render_route_accumulator([SECURE_CELL, VULN_CELL])
    code = accumulator.content.decode()
    assert accumulator.path == "routes_generated.go"
    first = code.index("labgen-go-0001")
    second = code.index("labgen-go-0002")
    assert first < second
    assert "/generated/labgen-go-0001" in code
    assert "/generated/labgen-go-0002" in code


def test_two_renders_of_the_same_cell_are_byte_identical() -> None:
    em = GoEmitter()
    (first,) = em.render(VULN_CELL)
    (second,) = em.render(VULN_CELL)
    assert first.content == second.content


def go_available() -> bool:
    return shutil.which("go") is not None


@pytest.mark.skipif(not go_available(), reason="go CLI not available on this build host (PA-0005 pattern)")
def test_rendered_handler_passes_go_vet() -> None:
    """Real Tier-0 lint: assembles the vulnerable+secure cells onto the real
    checked-in skeleton and runs a real `go vet ./...`, the Go analogue of
    `php -l`/`node --check` (Go has no bare syntax-only checker; `go vet`
    parses and type-checks, a strictly stronger and still-fast real check).
    """
    em = GoEmitter()
    skeleton = Path(__file__).resolve().parent.parent / "fuzzlab/labgen/emitters/go_net_http/stack/skeleton"
    with tempfile.TemporaryDirectory(prefix="fuzzlab-go-net-http-tier0-") as tmp:
        app_dir = Path(tmp) / "app"
        shutil.copytree(skeleton, app_dir)
        for cell in (VULN_CELL, SECURE_CELL):
            (emitted,) = em.render(cell)
            (app_dir / emitted.path).write_bytes(emitted.content)
        accumulator = em.render_route_accumulator([VULN_CELL, SECURE_CELL])
        (app_dir / accumulator.path).write_bytes(accumulator.content)

        result = subprocess.run(
            ["go", "vet", "./..."],
            cwd=app_dir,
            capture_output=True,
            text=True,
            timeout=60.0,
        )
        assert result.returncode == 0, f"go vet failed:\nstdout={result.stdout}\nstderr={result.stderr}"


@pytest.mark.skipif(not go_available(), reason="go CLI not available on this build host (PA-0005 pattern)")
def test_rendered_handler_is_gofmt_clean() -> None:
    """`gofmt -l` on the one illustrative cell's rendered output -- flags
    any file `gofmt` would reformat (empty output means clean), the closest
    Go analogue of a bare syntax check for a single file in isolation."""
    em = GoEmitter()
    (emitted,) = em.render(VULN_CELL)
    with tempfile.TemporaryDirectory(prefix="fuzzlab-go-net-http-gofmt-") as tmp:
        cell_path = Path(tmp) / "cell.go"
        cell_path.write_bytes(emitted.content)
        result = subprocess.run(["gofmt", "-l", str(cell_path)], capture_output=True, text=True, timeout=20.0)
        assert result.returncode == 0, f"gofmt failed to run:\n{result.stderr}"
        assert result.stdout.strip() == "", f"gofmt would reformat:\n{result.stdout}"
