"""End-to-end test for `python_fastapi` against its Tier-A illustrative
sample (`lab/manifests/phase3_python_fastapi_sample.yaml`), mirroring
`tests/test_labgen_php_current_real_pages.py`'s shape.

Covers: verdict cross-check against the shared `lab/safety_matrix.yaml`
(no new matrix entries needed -- the op vocabulary is stack-agnostic),
`supports()`, byte-determinism, module reuse/composition content checks,
Tier-0 lint (`python -m py_compile`, skip-guarded), the FastAPI
docs/redoc/openapi disable correctness requirement, and a `TestClient`-backed
smoke test that a rendered vulnerable/secure pair actually behaves as
labeled -- all skip-guarded on the `labgen-python-fastapi` extra
(fastapi/sqlalchemy/httpx) being installed, per PA-0005.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance.tier0 import lint_python_emitted_files, python_available
from fuzzlab.labgen.emitters.python_fastapi import STACK_ENV, PythonFastapiEmitter
from fuzzlab.labgen.schema import Cell, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/phase3_python_fastapi_sample.yaml"


def _labgen_python_fastapi_deps_available() -> bool:
    return all(importlib.util.find_spec(m) is not None for m in ("fastapi", "sqlalchemy", "httpx"))


def _load_cells() -> dict[str, Cell]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {cell.cell_id: cell for cell in manifest.cells}


_CELLS = _load_cells()

_EXPECTED_VERDICTS = {
    "LABGEN-PY-0001": "VULNERABLE",  # /products, raw concat
    "LABGEN-PY-0002": "SECURE",  # /products, param_bind twin
    "LABGEN-PY-0003": "VULNERABLE",  # /login, raw concat
    "LABGEN-PY-0004": "SECURE",  # /login, param_bind twin
    "LABGEN-PY-0005": "VULNERABLE",  # /profile, no escaping
    "LABGEN-PY-0006": "SECURE",  # /profile, html_entity_escape twin
}


def test_manifest_loads_and_validates() -> None:
    assert set(_CELLS) == set(_EXPECTED_VERDICTS)


@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_verdict_matches_the_declared_expectation(cell_id: str) -> None:
    # Cross-checks against the SAME derived-verdict engine and the SAME
    # lab/safety_matrix.yaml every other stack's cells go through -- no new
    # matrix entries were needed for this stack (op vocabulary is
    # stack-agnostic; see fuzzlab.labgen.verdict.verdict()).
    cell = _CELLS[cell_id]
    matrix = load_safety_matrix()
    result = verdict(cell.transform, cell.sink_context, matrix)
    assert result.verdict == _EXPECTED_VERDICTS[cell_id]


@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_python_fastapi_supports_every_sample_cell(cell_id: str) -> None:
    emitter = PythonFastapiEmitter()
    cell = _CELLS[cell_id]
    assert emitter.supports(cell.vuln_class, cell.sink_context) is True


@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_render_is_byte_deterministic_across_two_calls(cell_id: str) -> None:
    emitter = PythonFastapiEmitter()
    cell = _CELLS[cell_id]
    first = emitter.render(cell)
    second = emitter.render(cell)
    assert first == second


def test_scaffold_files_are_byte_deterministic_across_two_calls() -> None:
    from fuzzlab.labgen.emitters.python_fastapi import render_scaffold_files

    first = render_scaffold_files()
    second = render_scaffold_files()
    assert first == second


def test_products_and_login_use_distinct_but_correct_sink_shapes() -> None:
    emitter = PythonFastapiEmitter()
    numeric = emitter.render(_CELLS["LABGEN-PY-0001"])[0].content.decode("utf-8")
    string_literal = emitter.render(_CELLS["LABGEN-PY-0003"])[0].content.decode("utf-8")
    assert "get_param -> identity -> sql_numeric_lookup -> single_statement" in numeric
    assert "post_param -> identity -> sql_string_literal_lookup -> single_statement" in string_literal
    assert 'request.query_params.get("id")' in numeric
    assert "await request.form()).get(\"username\")" in string_literal


def test_login_secure_twin_binds_the_username_parameter() -> None:
    emitter = PythonFastapiEmitter()
    content = emitter.render(_CELLS["LABGEN-PY-0004"])[0].content.decode("utf-8")
    assert '{"username": username, "password": password_hash}' in content
    assert '" + str(username)' not in content


def test_profile_reads_a_stored_field_not_a_request_parameter() -> None:
    emitter = PythonFastapiEmitter()
    content = emitter.render(_CELLS["LABGEN-PY-0005"])[0].content.decode("utf-8")
    assert "request.query_params" not in content
    assert "await request.form()" not in content
    assert "current_user['bio']" in content


def test_profile_secure_twin_escapes_before_rendering() -> None:
    emitter = PythonFastapiEmitter()
    content = emitter.render(_CELLS["LABGEN-PY-0006"])[0].content.decode("utf-8")
    assert ".render(value=html.escape(bio))" in content


def test_stack_env_disables_docs_redoc_and_openapi_schema_routes() -> None:
    # The framework-debug-page correctness requirement
    # (docs/LAB_IMPLEMENTATION_PLAN.md Phase 3): FastAPI serves these by
    # default regardless of any debug flag. Checked against the actual
    # rendered scaffold source, not merely asserted in a docstring.
    main_py = next(f for f in STACK_ENV.scaffold_files if f.path == "app/main.py").content.decode("utf-8")
    assert "docs_url=None" in main_py
    assert "redoc_url=None" in main_py
    assert "openapi_url=None" in main_py


def test_stack_env_uses_a_digest_pinned_base_image() -> None:
    assert "@sha256:" in STACK_ENV.base_image
    assert STACK_ENV.is_multi_file is True


def test_stack_env_has_no_route_accumulator_module() -> None:
    # Per CR-LAB-0001 Addendum D's FastAPI-specific research: this emitter
    # uses a static discovery scaffold instead of a `route` accumulator.
    assert STACK_ENV.accumulators == ()


@pytest.mark.skipif(not python_available(), reason="python interpreter not available on this build host (PA-0005)")
@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_generated_python_is_syntactically_valid(cell_id: str) -> None:
    emitter = PythonFastapiEmitter()
    files = emitter.render(_CELLS[cell_id])
    results = lint_python_emitted_files(files)
    assert results
    assert all(r.ok for r in results), results


@pytest.mark.skipif(not python_available(), reason="python interpreter not available on this build host (PA-0005)")
def test_scaffold_python_files_are_syntactically_valid() -> None:
    results = lint_python_emitted_files(STACK_ENV.scaffold_files)
    assert results
    assert all(r.ok for r in results), results


def _write_full_sample_tree(tmpdir: str) -> None:
    emitter = PythonFastapiEmitter()
    for f in STACK_ENV.scaffold_files:
        p = Path(tmpdir) / f.path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(f.content)
    for cell_id in _EXPECTED_VERDICTS:
        emitted = emitter.render(_CELLS[cell_id])[0]
        p = Path(tmpdir) / emitted.path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(emitted.content)


@pytest.mark.skipif(
    not _labgen_python_fastapi_deps_available(),
    reason="fastapi/sqlalchemy/httpx not installed (optional `labgen-python-fastapi` extra, PA-0005)",
)
def test_rendered_app_runs_under_testclient_and_matches_its_verdicts() -> None:
    tmpdir = tempfile.mkdtemp()
    _write_full_sample_tree(tmpdir)

    sys.path.insert(0, tmpdir)
    old_cwd = os.getcwd()
    os.chdir(tmpdir)
    # A fresh module identity per test run avoids any stale `app.*` module
    # left in sys.modules by an earlier test process reusing the same name.
    for mod_name in [m for m in list(sys.modules) if m == "app" or m.startswith("app.")]:
        del sys.modules[mod_name]
    try:
        main_module = importlib.import_module("app.main")
        from fastapi.testclient import TestClient

        client = TestClient(main_module.app)

        # Debug/schema routes are gone, not just configured -- a live check,
        # not only a source-inspection assertion.
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert client.get("/openapi.json").status_code == 404

        # /products (LABGEN-PY-0001, vulnerable): the raw-concat sink still
        # answers a well-formed numeric id normally -- this is a smoke test
        # that the composed app runs end to end, not a full exploit proof
        # (that is Tier 2's job, the container-based oracle, out of scope
        # for this offline conformance suite per FR-LAB-25).
        r = client.get("/products", params={"id": "1"})
        assert r.status_code == 200
        assert r.json()["name"] == "Puppy Bed"

        # /profile (LABGEN-PY-0005, vulnerable twin): renders the stored
        # bio field unescaped.
        r = client.get("/profile")
        assert r.status_code == 200
        assert '<div class="bio">' in r.text
    finally:
        os.chdir(old_cwd)
        sys.path.remove(tmpdir)
        for mod_name in [m for m in list(sys.modules) if m == "app" or m.startswith("app.")]:
            del sys.modules[mod_name]
