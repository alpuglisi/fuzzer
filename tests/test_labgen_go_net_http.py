"""Emitter-level tests for `go_net_http` (category 4 pilot,
`CC-LAB-0170`/`FR-LAB-76` Phase A, `CC-LAB-0172`/`FR-LAB-78` Phase B):
`GoEmitter.render`/`render_route_accumulator`, plus a real, executed
`go vet`/`gofmt -l`-equivalent Tier 0 lint pass over the rendered output
-- this project's Go analogue of `node --check`
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

_WEBHOOK_FAMILY = "webhook_signature_verification"
_SSRF_FAMILY = "server_side_http_fetch"


def _webhook_cell(cell_id: str, ops: list[str]) -> Cell:
    return Cell(
        cell_id=cell_id,
        vuln_class="webhook_signature",
        stack_profile="go_net_http",
        route=Route(method="POST", path="/webhooks/eventsub"),
        sink_context=SinkContext(family=_WEBHOOK_FAMILY, required_neutralizations=["weak_signature_comparison"]),
        transform=Pipeline(ops=ops),
    )


def _ssrf_cell(cell_id: str, ops: list[str]) -> Cell:
    return Cell(
        cell_id=cell_id,
        vuln_class="ssrf",
        stack_profile="go_net_http",
        route=Route(method="GET", path="/api/clips/thumbnail"),
        sink_context=SinkContext(family=_SSRF_FAMILY, required_neutralizations=["ssrf_request_forgery"]),
        transform=Pipeline(ops=ops),
    )


# Backwards-compatible alias for the rest of this module's existing tests.
_cell = _webhook_cell

VULN_CELL = _webhook_cell("LABGEN-GO-0001", ["naive_string_compare"])
SECURE_CELL = _webhook_cell("LABGEN-GO-0002", ["constant_time_compare"])
SSRF_VULN_CELL = _ssrf_cell("LABGEN-GO-0003", ["unchecked_url_fetch"])
SSRF_SECURE_CELL = _ssrf_cell("LABGEN-GO-0004", ["scheme_and_resolved_ip_allowlist"])
ALL_CELLS = (VULN_CELL, SECURE_CELL, SSRF_VULN_CELL, SSRF_SECURE_CELL)


def test_supports_both_shapes() -> None:
    em = GoEmitter()
    assert em.supports("webhook_signature", SinkContext(family=_WEBHOOK_FAMILY, required_neutralizations=[]))
    assert em.supports("ssrf", SinkContext(family=_SSRF_FAMILY, required_neutralizations=[]))
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
    first = code.index("LabgenGo0001")
    second = code.index("LabgenGo0002")
    assert first < second
    # CC-LAB-0243 (R1): the vulnerable cell at its own realistic route.path;
    # its secure twin at the twin-suffixed variant (served_url_for), not
    # the pre-Lane-3 generic `/generated/{cell_id}` scheme.
    assert '"POST /webhooks/eventsub"' in code
    assert '"POST /webhooks/eventsub.labgen-go-0002"' in code


def test_two_renders_of_the_same_cell_are_byte_identical() -> None:
    em = GoEmitter()
    (first,) = em.render(VULN_CELL)
    (second,) = em.render(VULN_CELL)
    assert first.content == second.content


# -- CC-LAB-0172 Phase B: SSRF (server_side_http_fetch) -----------------------


def test_ssrf_vulnerable_twin_has_no_validation_and_only_needed_imports() -> None:
    em = GoEmitter()
    (emitted,) = em.render(SSRF_VULN_CELL)
    code = emitted.content.decode()
    assert "client.Get(targetUrl)" in code
    assert '"net/url"' not in code
    assert '"net"\n' not in code
    assert "url.Parse" not in code


def test_ssrf_secure_twin_checks_scheme_and_resolved_ip() -> None:
    em = GoEmitter()
    (emitted,) = em.render(SSRF_SECURE_CELL)
    code = emitted.content.decode()
    assert '"net/url"' in code
    assert '"net"' in code
    assert "url.Parse(targetUrl)" in code
    assert "net.LookupIP(parsed.Hostname())" in code


def test_ssrf_cell_with_more_than_one_op_raises() -> None:
    em = GoEmitter()
    bad = _ssrf_cell("LABGEN-GO-9998", ["unchecked_url_fetch", "scheme_and_resolved_ip_allowlist"])
    with pytest.raises(ValueError):
        em.render(bad)


def test_ssrf_cell_with_unknown_op_raises() -> None:
    em = GoEmitter()
    bad = _ssrf_cell("LABGEN-GO-9997", ["not_a_real_sink"])
    with pytest.raises(ValueError):
        em.render(bad)


def test_accumulator_covers_both_shapes_with_distinct_paths() -> None:
    em = GoEmitter()
    accumulator = em.render_route_accumulator(list(ALL_CELLS))
    code = accumulator.content.decode()
    # CC-LAB-0243 (R1): every cell registers at its own served_url_for
    # result (a real route, twin-suffixed for the secure twin), not the
    # pre-Lane-3 generic `/generated/{cell_id}` scheme -- and every
    # registered path is distinct.
    from fuzzlab.labgen.emitters.go_net_http import served_url_for

    served_urls = {served_url_for(cell) for cell in ALL_CELLS}
    assert len(served_urls) == len(ALL_CELLS)
    for url in served_urls:
        assert f' {url}"' in code


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
        for cell in ALL_CELLS:
            (emitted,) = em.render(cell)
            (app_dir / emitted.path).write_bytes(emitted.content)
        accumulator = em.render_route_accumulator(list(ALL_CELLS))
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
def test_rendered_handlers_are_gofmt_clean() -> None:
    """`gofmt -l` on every illustrative cell's rendered output (both
    shapes) -- flags any file `gofmt` would reformat (empty output means
    clean), the closest Go analogue of a bare syntax check per file."""
    em = GoEmitter()
    with tempfile.TemporaryDirectory(prefix="fuzzlab-go-net-http-gofmt-") as tmp:
        tmp_path = Path(tmp)
        for cell in ALL_CELLS:
            (emitted,) = em.render(cell)
            (tmp_path / f"{cell.cell_id.lower()}.go").write_bytes(emitted.content)
        result = subprocess.run(["gofmt", "-l", str(tmp_path)], capture_output=True, text=True, timeout=20.0)
        assert result.returncode == 0, f"gofmt failed to run:\n{result.stderr}"
        assert result.stdout.strip() == "", f"gofmt would reformat:\n{result.stdout}"
