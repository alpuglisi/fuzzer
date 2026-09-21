"""End-to-end test for the `php_laravel` emitter (lane L-P3.3a).

Mirrors `tests/test_labgen_php_current.py`'s basic-rendering test shape,
scaled down since this lane builds the `StackEnv` + accumulator +
conformance-harness *foundation* only -- the real module inventory (harder
SQLi/XSS shapes) and app migration are separate, later lanes (L-P3.3b,
L-P3.3c). Additionally exercises what `php_current`'s test file doesn't need
to: the `StackEnv` scaffold (`.env` with debug mode off) and the `route`
accumulator's cell-ID-sort determinism (`CR-LAB-0001` Addendum D), since
`php_current` is filesystem-routed and has neither.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance.tier0 import lint_php, php_available
from fuzzlab.labgen.conformance.tier3 import regenerate_and_diff_emitter
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, PHP_LARAVEL_STACK_ENV
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import RouteAccumulator, assemble_routes_file
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext, load_manifest

_MANIFEST_PATH = "lab/manifests/phase3_php_laravel_sample.yaml"

_VULNERABLE_CELL = Cell(
    cell_id="LABGEN-PL-0001",
    vuln_class="sqli",
    stack_profile="php_laravel",
    route=Route(method="GET", path="/example/product"),
    sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
    transform=Pipeline.from_list([]),
)

_SECURE_TWIN_CELL = Cell(
    cell_id="LABGEN-PL-0002",
    vuln_class="sqli",
    stack_profile="php_laravel",
    route=Route(method="GET", path="/example/product"),
    sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
    transform=Pipeline.from_list(["param_bind"]),
)


# --- StackEnv -----------------------------------------------------------


def test_stack_env_is_pinned_and_multi_file() -> None:
    env = PHP_LARAVEL_STACK_ENV
    assert env.language == "php"
    assert env.framework == "laravel"
    assert env.framework_version  # non-empty, pinned
    assert env.is_multi_file is True
    # Digest-pinned, never a bare mutable tag.
    assert "@sha256:" in env.base_image
    digest = env.base_image.split("@sha256:", 1)[1]
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_scaffold_env_file_disables_debug_mode() -> None:
    emitter = LaravelEmitter()
    files = {f.path: f.content for f in emitter.render_scaffold()}
    env_content = files[".env"].decode("utf-8")
    assert "APP_DEBUG=false" in env_content
    assert "APP_ENV=production" in env_content
    assert "APP_DEBUG=true" not in env_content


def test_scaffold_is_byte_deterministic_across_two_calls() -> None:
    emitter = LaravelEmitter()
    first = emitter.render_scaffold()
    second = emitter.render_scaffold()
    assert first == second


# --- Emitter basics (mirrors test_labgen_php_current.py) ----------------


def test_supports_the_sample_manifest_sqli_cells() -> None:
    emitter = LaravelEmitter()
    assert emitter.supports(_VULNERABLE_CELL.vuln_class, _VULNERABLE_CELL.sink_context) is True
    assert emitter.supports(_SECURE_TWIN_CELL.vuln_class, _SECURE_TWIN_CELL.sink_context) is True


def test_does_not_support_xss_cells_yet_and_a_caller_would_skip() -> None:
    emitter = LaravelEmitter()
    xss_cell = Cell(
        cell_id="LABGEN-PL-0003",
        vuln_class="xss",
        stack_profile="php_laravel",
        route=Route(method="GET", path="/example/profile"),
        sink_context=SinkContext(family="html_body", required_neutralizations=("html_tag_break",)),
        transform=Pipeline.from_list([]),
    )
    assert emitter.supports(xss_cell.vuln_class, xss_cell.sink_context) is False
    with pytest.raises(ValueError):
        emitter.render(xss_cell)


def test_render_produces_exactly_one_controller_file() -> None:
    emitter = LaravelEmitter()
    files = emitter.render(_VULNERABLE_CELL)
    assert len(files) == 1
    assert files[0].path == "app/Http/Controllers/LabgenPl0001Controller.php"
    assert files[0].role == "controller"
    assert files[0].content.startswith(b"<?php\n")


def test_render_is_byte_deterministic_across_two_calls() -> None:
    emitter = LaravelEmitter()
    first = emitter.render(_VULNERABLE_CELL)
    second = emitter.render(_VULNERABLE_CELL)
    assert first == second


def test_vulnerable_cell_renders_raw_concatenation_sql() -> None:
    emitter = LaravelEmitter()
    content = emitter.render(_VULNERABLE_CELL)[0].content.decode("utf-8")
    assert 'DB::select("SELECT * FROM products WHERE id = " . $id)' in content
    assert "?" not in content.split("DB::select(")[1].split(")")[0]


def test_secure_twin_renders_param_bind_and_the_diff_is_only_the_sink_region() -> None:
    emitter = LaravelEmitter()
    vulnerable = emitter.render(_VULNERABLE_CELL)[0].content.decode("utf-8")
    secure = emitter.render(_SECURE_TWIN_CELL)[0].content.decode("utf-8")

    assert 'DB::select("SELECT * FROM products WHERE id = ?", [$id])' in secure
    assert vulnerable != secure

    def _body_lines(src: str) -> list[str]:
        return [
            line
            for line in src.splitlines()
            if not line.startswith("// Generated by")
            and not line.startswith("// Module composition:")
            and not line.startswith("// Manifest cell.route.path:")
            and "Controller extends Controller" not in line
        ]

    vuln_lines = _body_lines(vulnerable)
    secure_lines = _body_lines(secure)
    assert vuln_lines[0] == secure_lines[0] == "<?php"
    assert any(line.strip() == "$id = $request->query('id');" for line in vuln_lines)
    assert any(line.strip() == "$id = $request->query('id');" for line in secure_lines)


def test_unknown_transform_op_raises_rather_than_guessing() -> None:
    emitter = LaravelEmitter()
    cell = Cell(
        cell_id="LABGEN-PL-0099",
        vuln_class="sqli",
        stack_profile="php_laravel",
        route=Route(method="GET", path="/example/product"),
        sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
        transform=Pipeline.from_list(["html_entity_escape"]),
    )
    with pytest.raises(ValueError):
        emitter.render(cell)


# --- Route accumulator (Addendum D determinism rule) ---------------------


def test_route_accumulator_sorts_by_cell_id_not_append_order() -> None:
    accumulator = RouteAccumulator()
    frag_1 = accumulator.fragment_for_cell(
        cell_id="LABGEN-PL-0001", controller_class="LabgenPl0001Controller", url_path="/cell/labgen-pl-0001"
    )
    frag_2 = accumulator.fragment_for_cell(
        cell_id="LABGEN-PL-0002", controller_class="LabgenPl0002Controller", url_path="/cell/labgen-pl-0002"
    )

    # Insert out of cell-ID order -- render_file must still sort.
    out_of_order = {"LABGEN-PL-0002": frag_2, "LABGEN-PL-0001": frag_1}
    in_order = {"LABGEN-PL-0001": frag_1, "LABGEN-PL-0002": frag_2}

    assert accumulator.render_file(out_of_order) == accumulator.render_file(in_order)
    rendered = accumulator.render_file(out_of_order)
    assert rendered.index("LABGEN-PL-0001") < rendered.index("LABGEN-PL-0002")


def test_assemble_routes_file_is_byte_deterministic_regardless_of_fragment_order() -> None:
    emitter = LaravelEmitter()
    frag_1 = emitter.route_fragment_for(_VULNERABLE_CELL)
    frag_2 = emitter.route_fragment_for(_SECURE_TWIN_CELL)

    first = assemble_routes_file({"LABGEN-PL-0001": frag_1, "LABGEN-PL-0002": frag_2})
    second = assemble_routes_file({"LABGEN-PL-0002": frag_2, "LABGEN-PL-0001": frag_1})
    assert first == second
    assert first.path == "routes/web.php"
    assert first.role == "route"
    # A twin sharing one logical page still gets its own URL (see
    # route_accumulator.py's module docstring) -- both coexist, no collision.
    content = first.content.decode("utf-8")
    assert "/cell/labgen-pl-0001" in content
    assert "/cell/labgen-pl-0002" in content


# --- Conformance suite: Tier 0 + Tier 3 (§4.3 step 3) --------------------


def _sample_cells() -> tuple[Cell, ...]:
    manifest = load_manifest(_MANIFEST_PATH)
    return manifest.cells


def test_sample_manifest_loads_and_matches_the_hand_built_cells() -> None:
    cells = _sample_cells()
    assert [c.cell_id for c in cells] == ["LABGEN-PL-0001", "LABGEN-PL-0002"]
    assert all(c.stack_profile == "php_laravel" for c in cells)


def test_tier3_whole_sample_regeneration_is_byte_identical() -> None:
    """Tier 3 (whole-lab regeneration): render the sample manifest's cells
    twice via a real emitter and byte-diff the whole tree. Raises
    `RegenerateDiffError` (via an assertion failure surfaced as a test
    failure) on any divergence -- see
    `fuzzlab.labgen.conformance.tier3.regenerate_and_diff_emitter`.
    """
    emitter = LaravelEmitter()
    regenerate_and_diff_emitter(emitter, _sample_cells())  # raises on any diff


def test_tier3_route_accumulator_regeneration_is_byte_identical() -> None:
    """The accumulator-specific extension of the Tier-3 pattern (see
    `route_accumulator.py`'s module docstring for why this isn't folded
    into `regenerate_and_diff_emitter` itself): two independent assemblies
    of `routes/web.php` from the same manifest's cells must be
    byte-identical.
    """
    emitter = LaravelEmitter()
    cells = _sample_cells()

    def _assemble() -> bytes:
        fragments = {c.cell_id: emitter.route_fragment_for(c) for c in cells if emitter.supports(c.vuln_class, c.sink_context)}
        return assemble_routes_file(fragments).content

    assert _assemble() == _assemble()


@pytest.mark.skipif(not php_available(), reason="php CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_sample_manifest_cell() -> None:
    emitter = LaravelEmitter()
    for cell in _sample_cells():
        assert emitter.supports(cell.vuln_class, cell.sink_context)
        for emitted in emitter.render(cell):
            result = lint_php(emitted.path, emitted.content)
            assert result.ok, f"{cell.cell_id} ({emitted.path}): php -l failed:\n{result.detail}"


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
@pytest.mark.parametrize("cell", [_VULNERABLE_CELL, _SECURE_TWIN_CELL])
def test_generated_php_is_syntactically_valid(cell: Cell) -> None:
    emitter = LaravelEmitter()
    content = emitter.render(cell)[0].content
    with tempfile.TemporaryDirectory() as tmpdir:
        php_path = Path(tmpdir) / "cell.php"
        php_path.write_bytes(content)
        result = subprocess.run(
            ["php", "-l", str(php_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"php -l failed:\nstdout={result.stdout}\nstderr={result.stderr}"


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_scaffold_index_php_is_syntactically_valid() -> None:
    emitter = LaravelEmitter()
    for f in emitter.render_scaffold():
        if not f.path.endswith(".php"):
            continue
        with tempfile.TemporaryDirectory() as tmpdir:
            php_path = Path(tmpdir) / "scaffold.php"
            php_path.write_bytes(f.content)
            result = subprocess.run(
                ["php", "-l", str(php_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, f"php -l failed for {f.path}:\nstdout={result.stdout}\nstderr={result.stderr}"
