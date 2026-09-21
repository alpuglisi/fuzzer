"""End-to-end test for `node_express` against
`lab/manifests/phase3_node_express_sample.yaml` (L-P3.1).

Mirrors `tests/test_labgen_php_current_real_pages.py`'s shape: verdict
cross-check against the same derived verdict engine every stack's cells go
through, supports()/determinism checks, module-reuse-across-routes checks,
and a `node --check` syntax-validity check (skip-guarded when the `node`
CLI isn't on the build host, mirroring `php_available()`/`lint_php`'s
convention in `fuzzlab.labgen.conformance.tier0` -- kept local to this test
file rather than added to that shared module, per this lane's scope
discipline, the same way the php_current real-pages test defines its own
inline `php -l` check rather than importing `tier0.lint_php`).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from fuzzlab.labgen.emitters.node_express import NodeExpressEmitter
from fuzzlab.labgen.schema import Cell, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/phase3_node_express_sample.yaml"


def _load_cells() -> dict[str, Cell]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {cell.cell_id: cell for cell in manifest.cells}


_CELLS = _load_cells()

_EXPECTED_VERDICTS = {
    "LABGEN-NE-0001": "VULNERABLE",  # /api/products, raw concat
    "LABGEN-NE-0002": "SECURE",  # /api/products, param_bind twin
    "LABGEN-NE-0003": "VULNERABLE",  # /api/posts, raw concat
    "LABGEN-NE-0004": "SECURE",  # /api/posts, param_bind twin
    "LABGEN-NE-0005": "VULNERABLE",  # /api/login, raw concat
    "LABGEN-NE-0006": "SECURE",  # /api/login, param_bind twin
    "LABGEN-NE-0007": "VULNERABLE",  # /api/profile, no escaping
    "LABGEN-NE-0008": "SECURE",  # /api/profile, escapeHtml twin
}


def node_available() -> bool:
    return shutil.which("node") is not None


def test_manifest_loads_and_validates() -> None:
    assert set(_CELLS) == set(_EXPECTED_VERDICTS)


@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_verdict_matches_expected(cell_id: str) -> None:
    # Cross-checks this sample's cells against the same derived-verdict
    # engine every other stack's cells go through -- not asserted by fiat.
    cell = _CELLS[cell_id]
    matrix = load_safety_matrix()
    result = verdict(cell.transform, cell.sink_context, matrix)
    assert result.verdict == _EXPECTED_VERDICTS[cell_id]


@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_node_express_supports_every_sample_cell(cell_id: str) -> None:
    emitter = NodeExpressEmitter()
    cell = _CELLS[cell_id]
    assert emitter.supports(cell.vuln_class, cell.sink_context) is True


@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_render_is_byte_deterministic_across_two_calls(cell_id: str) -> None:
    emitter = NodeExpressEmitter()
    cell = _CELLS[cell_id]
    first = emitter.render(cell)
    second = emitter.render(cell)
    assert first == second


def test_products_and_posts_reuse_the_same_module_set() -> None:
    # /api/products and /api/posts are two different routes with the same
    # sink-context shape (sql_numeric_literal, GET) -- proves module reuse
    # across routes, the Express analogue of php_current's
    # product.php/blog_post.php test.
    emitter = NodeExpressEmitter()
    products = emitter.render(_CELLS["LABGEN-NE-0001"])[0].content.decode("utf-8")
    posts = emitter.render(_CELLS["LABGEN-NE-0003"])[0].content.decode("utf-8")
    assert "get_query_param -> identity -> sql_numeric_lookup -> single_statement" in products
    assert "get_query_param -> identity -> sql_numeric_lookup -> single_statement" in posts
    assert "FROM products" in products
    assert "FROM posts" in posts


def test_login_uses_post_source_and_string_literal_sink() -> None:
    emitter = NodeExpressEmitter()
    content = emitter.render(_CELLS["LABGEN-NE-0005"])[0].content.decode("utf-8")
    assert "req.body.username" in content
    assert "WHERE username = '\" + username + \"'" in content
    assert "createHash('md5')" in content


def test_login_secure_twin_parameterizes_the_username() -> None:
    emitter = NodeExpressEmitter()
    content = emitter.render(_CELLS["LABGEN-NE-0006"])[0].content.decode("utf-8")
    assert "[username, passwordHash]" in content
    assert '" + username' not in content


def test_profile_reads_a_stored_field_not_a_request_parameter() -> None:
    emitter = NodeExpressEmitter()
    content = emitter.render(_CELLS["LABGEN-NE-0007"])[0].content.decode("utf-8")
    assert "req.query" not in content
    assert "req.body" not in content
    assert "currentUser.bio" in content
    assert "res.send('<div class=\"bio\">' + bio + '</div>');" in content


def test_profile_secure_twin_escapes_before_sending() -> None:
    emitter = NodeExpressEmitter()
    content = emitter.render(_CELLS["LABGEN-NE-0008"])[0].content.decode("utf-8")
    assert "res.send('<div class=\"bio\">' + escapeHtml(bio) + '</div>');" in content


def test_route_accumulator_is_sorted_by_cell_id_not_input_order() -> None:
    emitter = NodeExpressEmitter()
    cells = list(_CELLS.values())
    forward = emitter.render_route_accumulator(cells)
    backward = emitter.render_route_accumulator(list(reversed(cells)))
    assert forward == backward
    content = forward.content.decode("utf-8")
    positions = [content.index(f"routes/{cid.lower()}") for cid in sorted(_EXPECTED_VERDICTS)]
    assert positions == sorted(positions)


def test_route_accumulator_is_byte_deterministic_across_two_calls() -> None:
    emitter = NodeExpressEmitter()
    cells = list(_CELLS.values())
    first = emitter.render_route_accumulator(cells)
    second = emitter.render_route_accumulator(cells)
    assert first == second


def test_route_accumulator_registers_only_supported_cells() -> None:
    from fuzzlab.labgen.schema import Pipeline, Route, SinkContext

    emitter = NodeExpressEmitter()
    unsupported = Cell(
        cell_id="LABGEN-NE-UNSUPPORTED-0001",
        vuln_class="ssrf",
        stack_profile="node_express",
        route=Route(method="GET", path="/somewhere"),
        sink_context=SinkContext(family="network_egress", required_neutralizations=("allowlist",)),
        transform=Pipeline.from_list([]),
    )
    result = emitter.render_route_accumulator([*_CELLS.values(), unsupported])
    assert "labgen-ne-unsupported-0001" not in result.content.decode("utf-8")


@pytest.mark.skipif(not node_available(), reason="node CLI not available on this build host (PA-0005 pattern)")
@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_generated_js_is_syntactically_valid(cell_id: str) -> None:
    emitter = NodeExpressEmitter()
    content = emitter.render(_CELLS[cell_id])[0].content
    with tempfile.TemporaryDirectory() as tmpdir:
        js_path = Path(tmpdir) / "cell.js"
        js_path.write_bytes(content)
        result = subprocess.run(
            ["node", "--check", str(js_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"node --check failed:\nstdout={result.stdout}\nstderr={result.stderr}"


@pytest.mark.skipif(not node_available(), reason="node CLI not available on this build host (PA-0005 pattern)")
def test_generated_route_accumulator_is_syntactically_valid() -> None:
    emitter = NodeExpressEmitter()
    content = emitter.render_route_accumulator(list(_CELLS.values())).content
    with tempfile.TemporaryDirectory() as tmpdir:
        js_path = Path(tmpdir) / "app.js"
        js_path.write_bytes(content)
        result = subprocess.run(
            ["node", "--check", str(js_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"node --check failed:\nstdout={result.stdout}\nstderr={result.stderr}"
