"""Offline checks for the `node_express` Browsable Labs work (CC-LAB-0246 /
FR-LAB-168, `docs/LAB_LANE6_NODE_FASTAPI_PLAN.md` §2A/§4A).

- PA-0054 (1): every route any `node_express` manifest produces declares
  its absent-input behavior (`absent_input`), with a value allowed for its
  source kind, actually rendered in the source region, identically on both
  twins (BUG-0027's minimal-pair discipline; plan R4).
- The MeadowMart site layer (`scaffold/site.js`): route drift against
  `SITE_ROUTES` (§2A-a), `RUNTIME_SCAFFOLD_FILES` drift (R7), the
  prototype-gadget construct scan (R2), the name-leak scan (R5), the single
  permitted `innerHTML` write (R6), `node --check` (skip-guarded), and the
  accumulator's byte-determinism with the catalog included.
- F1/F2 (different class, plan §7): pinned by strict xfails naming their
  finding IDs; their follow-up CC-LAB numbers are assigned by the
  orchestrator (PA-0031).
"""

from __future__ import annotations

import glob
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from fuzzlab.labgen.emitters.node_express import (
    _MODULE_SET_BY_SHAPE,
    _ROUTE_PARAMS,
    ABSENT_INPUT_BY_SOURCE,
    MEADOWMART_MANIFESTS,
    RUNTIME_SCAFFOLD_FILES,
    SITE_ROUTES,
    NodeExpressEmitter,
)
from fuzzlab.labgen.gates import scan_name_leaks
from fuzzlab.labgen.schema import load_manifest

SCAFFOLD_DIR = Path("fuzzlab/labgen/emitters/node_express/scaffold")
SITE_JS = SCAFFOLD_DIR / "site.js"


def _node_cells():
    """Every node_express cell across every manifest, via supports() (PA-0027)."""
    emitter = NodeExpressEmitter()
    seen = {}
    for path in sorted(glob.glob("lab/manifests/*.yaml")):
        for cell in load_manifest(path).cells:
            if cell.stack_profile == "node_express" and emitter.supports(cell.vuln_class, cell.sink_context):
                seen.setdefault(cell.cell_id, cell)
    return list(seen.values())


def _meadowmart_cells():
    return [c for m in MEADOWMART_MANIFESTS for c in load_manifest(m).cells]


def _source_of(cell) -> str:
    return _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)].source


# --- PA-0054 (1): absent-input behavior is declared, per source kind -------


def test_every_node_express_route_declares_an_allowed_absent_input() -> None:
    cells = _node_cells()
    routes = {c.route.path for c in cells}
    # Hard-coded so a new route cannot slip past undeclared.
    assert routes == {"/api/login", "/api/posts", "/api/preferences", "/api/products", "/api/profile", "/api/search"}
    for cell in cells:
        profile = _ROUTE_PARAMS[cell.route.path]
        allowed = ABSENT_INPUT_BY_SOURCE[_source_of(cell)]
        assert profile.get("absent_input") in allowed, (cell.cell_id, profile.get("absent_input"), allowed)
        if profile["absent_input"] == "default_value":
            assert profile.get("default_literal"), cell.cell_id


def test_every_route_profile_declares_absent_input() -> None:
    missing = sorted(route for route, profile in _ROUTE_PARAMS.items() if "absent_input" not in profile)
    assert not missing, missing


_DECLARATION_MARKERS = (
    "req.query.", "req.body", "missing required parameter", "missing request body", "Object.keys(",
)


def _declaration_lines(cell) -> str:
    source = NodeExpressEmitter().render(cell)[0].content.decode("utf-8")
    body = source[source.index(f"function handle{''.join(p.capitalize() for p in cell.cell_id.split('-'))}"):]
    keep = [ln.strip() for ln in body.splitlines() if any(m in ln for m in _DECLARATION_MARKERS)]
    return "\n".join(keep)


def test_declared_absent_input_is_rendered_before_the_transform() -> None:
    for cell in _node_cells():
        decl = _ROUTE_PARAMS[cell.route.path]["absent_input"]
        lines = _declaration_lines(cell)
        if decl == "default_value":
            assert f"|| '{_ROUTE_PARAMS[cell.route.path]['default_literal']}'" in lines, (cell.cell_id, lines)
        elif decl == "required_param":
            assert "missing required parameter" in lines, (cell.cell_id, lines)
        elif decl == "empty_body_400":
            assert "missing request body" in lines, (cell.cell_id, lines)
        # The guard/default sits in the source region, before any transform comment.
        source = NodeExpressEmitter().render(cell)[0].content.decode("utf-8")
        if decl in ("required_param", "empty_body_400"):
            assert source.index("status(400)") < source.index("transform"), cell.cell_id


def test_absent_input_lines_are_identical_on_both_twins() -> None:
    by_route: dict[str, set[str]] = {}
    for cell in _node_cells():
        by_route.setdefault(cell.route.path, set()).add(_declaration_lines(cell))
    for route, variants in by_route.items():
        assert len(variants) == 1, (route, variants)


# --- Site layer ---------------------------------------------------------------


def test_site_routes_match_site_js_registrations() -> None:
    registered = set(re.findall(r"app\.get\('([^']+)'", SITE_JS.read_text(encoding="utf-8")))
    assert registered == set(SITE_ROUTES)


def test_runtime_scaffold_files_match_the_scaffold_directory() -> None:
    on_disk = {p.name for p in SCAFFOLD_DIR.iterdir() if p.is_file()}
    assert set(RUNTIME_SCAFFOLD_FILES) == on_disk - {"Dockerfile", "package-lock.json"}


def test_site_js_uses_no_prototype_gadget_constructs() -> None:
    """R2: nothing in site.js may change its output when Object.prototype
    has been polluted by the vulnerable /api/preferences twin."""
    code = "\n".join(ln for ln in SITE_JS.read_text(encoding="utf-8").splitlines() if not ln.strip().startswith("//"))
    assert not re.search(r"for\s*\([^)]*\bin\b", code), "for...in loop in site.js"
    assert "Object.assign(" not in code
    assert "req.query" not in code and "req.body" not in code and "req.params" not in code


def test_site_js_has_exactly_one_innerhtml_write_the_search_results() -> None:
    """R6: the only innerHTML write renders /api/search's fixed-alphabet response."""
    writes = re.findall(r"\.innerHTML\s*=\s*([^;]+);", SITE_JS.read_text(encoding="utf-8"))
    assert writes == ["text"], writes
    assert "fetch('/api/search?q=' + encodeURIComponent(term)).then((r) => r.text()).then((text) =>" in (
        SITE_JS.read_text(encoding="utf-8")
    )


def test_site_and_app_js_carry_no_vulnerability_class_names() -> None:
    """R5: the name-leak scanner over the full text of site.js and app.js."""
    app_js = NodeExpressEmitter().render_route_accumulator(_meadowmart_cells()).content.decode("utf-8")
    leaks = scan_name_leaks([("site.js", SITE_JS.read_text(encoding="utf-8")), ("app.js", app_js)])
    assert not leaks, leaks


def test_accumulator_with_catalog_is_byte_deterministic() -> None:
    cells = _meadowmart_cells()
    emitter = NodeExpressEmitter()
    first = emitter.render_route_accumulator(cells).content
    second = emitter.render_route_accumulator(list(reversed(cells))).content
    assert first == second
    text = first.decode("utf-8")
    assert "require('./site').register(app, [" in text
    # Both preferences URLs gain the GET resource read (R3 branch (a)).
    assert "app.get('/api/preferences', (req, res) => {" in text
    assert "app.get('/api/preferences-twin-labgen-pp-0002', (req, res) => {" in text


@pytest.mark.skipif(shutil.which("node") is None, reason="node CLI not available (PA-0005)")
def test_site_js_and_app_js_pass_node_check(tmp_path: Path) -> None:
    app_js = tmp_path / "app.js"
    app_js.write_bytes(NodeExpressEmitter().render_route_accumulator(_meadowmart_cells()).content)
    for path in (SITE_JS, app_js):
        result = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, (path, result.stderr)


# --- Different-class findings, pinned (plan §7) --------------------------------


@pytest.mark.xfail(
    strict=True,
    reason=(
        "F1 (CC-LAB-0246 plan §7): /api/profile's stored_expr root `currentUser` is never "
        "defined, so every request 500s; follow-up CC-LAB number to be assigned by the "
        "orchestrator (PA-0031)."
    ),
)
def test_f1_every_stored_expr_root_is_defined() -> None:
    scaffold = "\n".join((SCAFFOLD_DIR / name).read_text(encoding="utf-8") for name in RUNTIME_SCAFFOLD_FILES)
    for cell in _node_cells():
        expr = _ROUTE_PARAMS[cell.route.path].get("stored_expr")
        if not expr:
            continue
        root = expr.split(".")[0]
        source = NodeExpressEmitter().render(cell)[0].content.decode("utf-8")
        pattern = rf"\b(const|let|var|function)\s+{re.escape(root)}\b"
        assert re.search(pattern, source) or re.search(pattern, scaffold), (cell.cell_id, root)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "F2 (CC-LAB-0246 plan §7): async (single_statement) handlers have no error handling, so "
        "any rejected DB call exits the Node process under Express 4 + Node 22; follow-up "
        "CC-LAB number to be assigned by the orchestrator (PA-0031)."
    ),
)
def test_f2_async_handlers_handle_rejections() -> None:
    for cell in _node_cells():
        source = NodeExpressEmitter().render(cell)[0].content.decode("utf-8")
        if "async function" in source:
            assert "try {" in source or ".catch(" in source, cell.cell_id
