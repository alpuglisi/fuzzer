"""Prototype pollution (CC-LAB-0070): the `object_property_bulk_set` sink
family's first code-generation increment for `node_express` -- both module
registries (the shared `fuzzlab.labgen.modules` vocabulary-only entries and
`node_express`'s own rendering registry), the safety-matrix rows, the
`lab/manifests/prototype_pollution_node_sample.yaml` manifest, and Tier-0/
Tier-3 conformance.

Everything here is real and offline, mirroring
`tests/test_labgen_mass_assignment.py`'s own structure and discipline:

- The real `lab/safety_matrix.yaml` (rows added by CC-LAB-0070).
- The real manifest, the real emitter, the real Jinja2 module fragments.
- A real, executed adversarial proof (not a Python simulation): the
  vulnerable/secure twins are rendered for real and each run as a real
  Node.js subprocess against a real `{"__proto__": {"polluted": true}}`
  payload, checking `Object.prototype`'s own state afterward -- Node/npm
  are confirmed available in this build environment (PA-0005's skip-guard
  pattern still applies for portability to a host without them).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.node_express import NodeExpressEmitter
from fuzzlab.labgen.emitters.node_express.modules import SINKS, SOURCES, TRANSFORMS
from fuzzlab.labgen.schema import Cell, SinkContext, load_manifest
from fuzzlab.labgen.verdict import Effect, load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/prototype_pollution_node_sample.yaml"

FAMILY = SinkContext(family="object_property_bulk_set", required_neutralizations=("proto_pollution",))


def node_available() -> bool:
    return shutil.which("node") is not None


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture()
def emitter():
    return NodeExpressEmitter()


def _cell(manifest, cell_id: str) -> Cell:
    return next(c for c in manifest.cells if c.cell_id == cell_id)


# ---------------------------------------------------------------------------
# Safety matrix: the CC-LAB-0070 rows this increment renders code for
# ---------------------------------------------------------------------------


def test_matrix_version_is_not_bumped_by_purely_additive_rows(matrix) -> None:
    assert matrix.version == 1


def test_unguarded_deep_merge_has_no_effect(matrix) -> None:
    entry = matrix.lookup("unguarded_deep_merge", "object_property_bulk_set")
    assert entry.effect is Effect.NO_EFFECT
    assert entry.neutralizes == ()


def test_proto_key_filtered_merge_neutralises_proto_pollution(matrix) -> None:
    entry = matrix.lookup("proto_key_filtered_merge", "object_property_bulk_set")
    assert entry.effect is Effect.NEUTRALISES
    assert entry.neutralizes == ("proto_pollution",)


def test_every_op_this_increment_renders_is_scorable_by_the_matrix(matrix) -> None:
    """A transform module node_express can render at a family the matrix has
    no row for would render fine and then make `verdict()` raise -- an
    emitter/matrix lockstep gap of exactly the kind PA-0024 is about."""
    for op in ("unguarded_deep_merge", "proto_key_filtered_merge"):
        assert op in TRANSFORMS, f"{op!r} is registered but not a real transform module"
        matrix.lookup(op, "object_property_bulk_set")  # must not raise


# ---------------------------------------------------------------------------
# Derived verdicts for both cells of the new manifest
# ---------------------------------------------------------------------------


EXPECTED_VERDICTS = {
    "LABGEN-PP-0001": ("VULNERABLE", "trivial"),
    "LABGEN-PP-0002": ("SECURE", None),
}


def test_every_cell_of_the_new_manifest_derives_its_expected_verdict(manifest, matrix) -> None:
    assert {c.cell_id for c in manifest.cells} == set(EXPECTED_VERDICTS)
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert (derived.verdict, derived.difficulty) == EXPECTED_VERDICTS[cell.cell_id], cell.cell_id


def test_the_pair_is_a_minimal_pair_on_class_and_family(manifest) -> None:
    """Both cells share one route, one class, one sink family -- the only
    difference is the transform region (the minimal-pair invariant)."""
    v = _cell(manifest, "LABGEN-PP-0001")
    s = _cell(manifest, "LABGEN-PP-0002")
    assert v.vuln_class == s.vuln_class == "prototype_pollution"
    assert v.route.path == s.route.path
    assert v.sink_context.family == s.sink_context.family == "object_property_bulk_set"
    assert v.sink_context.required_neutralizations == s.sink_context.required_neutralizations
    assert v.transform.ops != s.transform.ops


# ---------------------------------------------------------------------------
# Emitter: shape support, rendered content
# ---------------------------------------------------------------------------


def test_supports_the_prototype_pollution_shape(emitter) -> None:
    assert emitter.supports("prototype_pollution", FAMILY) is True


def test_vulnerable_cell_merges_with_no_proto_guard(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-PP-0001"))[0].content.decode("utf-8")
    assert "function deepMerge(target, source)" in content
    assert "__proto__" not in content.split("function deepMerge")[1].split("const currentPreferences")[0]
    assert "const mergedPreferences = deepMerge(currentPreferences, incomingPreferences);" in content


def test_secure_cell_skips_proto_shaped_keys(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-PP-0002"))[0].content.decode("utf-8")
    assert "function deepMergeSafe(target, source)" in content
    assert "key === '__proto__' || key === 'constructor' || key === 'prototype'" in content
    assert "const mergedPreferences = deepMergeSafe(currentPreferences, incomingPreferences);" in content


def test_both_cells_respond_with_the_same_shaped_object(emitter, manifest) -> None:
    """The sink never decides the proto_pollution concern itself -- only the
    transform (merge function) differs between the twins."""
    for cell_id in ("LABGEN-PP-0001", "LABGEN-PP-0002"):
        content = emitter.render(_cell(manifest, cell_id))[0].content.decode("utf-8")
        assert "res.json({ preferences: mergedPreferences });" in content


def test_every_cell_of_the_new_manifest_renders(emitter, manifest) -> None:
    for cell in manifest.cells:
        files = emitter.render(cell)  # must not raise
        assert files and files[0].content.startswith(b"'use strict';\n"), cell.cell_id


# ---------------------------------------------------------------------------
# Module fragments: the authoring-gap guard, checked for real
# ---------------------------------------------------------------------------


def test_unguarded_deep_merge_module_refuses_a_missing_target() -> None:
    with pytest.raises(ValueError, match="target_var"):
        TRANSFORMS["unguarded_deep_merge"].render({"value_expr": "incomingPreferences"})


def test_proto_key_filtered_merge_module_refuses_a_missing_target() -> None:
    with pytest.raises(ValueError, match="target_var"):
        TRANSFORMS["proto_key_filtered_merge"].render({"value_expr": "incomingPreferences"})


def test_post_body_json_source_is_registered() -> None:
    assert "post_body_json" in SOURCES


def test_object_property_bulk_set_sink_never_decides_the_proto_pollution_concern() -> None:
    """The invariant every other sink has (never decides the vulnerability
    concern itself, so both twins can share it unchanged) still holds here."""
    ctx = {"value_expr": "MARKER_EXPR"}
    code = SINKS["object_property_bulk_set"].render(ctx).code
    assert "MARKER_EXPR" in code
    assert "__proto__" not in code


# ---------------------------------------------------------------------------
# Shared vocabulary registration (fuzzlab.labgen.modules), per the
# L-P3.3c-DOM precedent this addition follows
# ---------------------------------------------------------------------------


def test_shared_php_oriented_registry_also_knows_the_new_names() -> None:
    """CC-LAB-0070 registers this shape in BOTH node_express's own registry
    AND the shared fuzzlab.labgen.modules registry (vocabulary-only there,
    per the task's explicit L-P3.3c-DOM precedent), even though no PHP
    emitter's own _MODULE_SET_BY_SHAPE renders it."""
    from fuzzlab.labgen.modules import SINKS as SHARED_SINKS
    from fuzzlab.labgen.modules import SOURCES as SHARED_SOURCES
    from fuzzlab.labgen.modules import TRANSFORMS as SHARED_TRANSFORMS

    assert "post_body_json" in SHARED_SOURCES
    assert SHARED_SOURCES["post_body_json"].category == "source"
    assert "unguarded_deep_merge" in SHARED_TRANSFORMS
    assert "proto_key_filtered_merge" in SHARED_TRANSFORMS
    assert SHARED_TRANSFORMS["unguarded_deep_merge"].category == "transform"
    assert "object_property_bulk_set" in SHARED_SINKS
    assert SHARED_SINKS["object_property_bulk_set"].category == "sink"

    # The shared registry's own fragments must still render for real (they
    # are documentary/placeholder PHP, never actually assembled into a PHP
    # page by any emitter, but must not be dead entries that raise).
    SHARED_SOURCES["post_body_json"].render({})
    SHARED_TRANSFORMS["unguarded_deep_merge"].render({"value_expr": "$__wholeBody"})
    SHARED_TRANSFORMS["proto_key_filtered_merge"].render({"value_expr": "$__wholeBody"})
    SHARED_SINKS["object_property_bulk_set"].render({"value_expr": "$__wholeBody"})


# ---------------------------------------------------------------------------
# Conformance: static-precheck flag, Tier 0, Tier 3
# ---------------------------------------------------------------------------


def test_the_new_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        # Must not raise: an unregistered shape fails loud by design.
        status = static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)
        assert status is static_precheck.StaticPrecheckStatus.UNINFORMATIVE


def test_tier3_whole_sample_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, manifest.cells)  # must not raise


def test_tier3_renders_one_unique_path_per_cell(emitter, manifest) -> None:
    tree = tier3.render_whole_sample(emitter, manifest.cells)
    assert len(tree) == len(manifest.cells)


@pytest.mark.skipif(not node_available(), reason="node CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_new_cell_node_check(emitter, manifest) -> None:
    """node_express's own Tier-0 lint is `node --check`, not `tier0.lint_php`
    (see `tests/test_labgen_node_express.py`'s own docstring for why this
    stack's Tier-0 syntax check stays local rather than going through the
    shared, PHP-oriented `fuzzlab.labgen.conformance.tier0.lint_emitted_files`)."""
    for cell in manifest.cells:
        content = emitter.render(cell)[0].content
        with tempfile.TemporaryDirectory() as tmpdir:
            js_path = Path(tmpdir) / "cell.js"
            js_path.write_bytes(content)
            result = subprocess.run(
                ["node", "--check", str(js_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                f"{cell.cell_id}: node --check failed:\nstdout={result.stdout}\nstderr={result.stderr}"
            )


# Not attempted here: `fuzzlab.labgen.cli`'s own `--check` end-to-end run
# (unlike `test_labgen_mass_assignment.py`'s equivalent test). `cli.py`'s
# `--emitter` flag does not offer `node_express` at all yet (only
# `php_current`/`php_laravel`) -- pre-existing, out of this addition's scope
# to widen; `tests/test_labgen_node_express*.py` do not exercise the CLI for
# the same reason.


# ---------------------------------------------------------------------------
# The real, executed adversarial proof: a genuine Node.js subprocess running
# the rendered module against a real `{"__proto__": {...}}` payload, not a
# Python simulation of what Node would do (mirrors
# tests/test_labgen_mass_assignment.py::..._rejects_a_syntax_injection_shaped_key's
# discipline of executing the real mechanism, for this stack's real runtime).
# ---------------------------------------------------------------------------

_RUN_HANDLER_SCRIPT = """
'use strict';
const handlerPath = process.argv[2];
const handler = require(handlerPath);
const req = { body: JSON.parse(process.argv[3]) };
let captured = null;
const res = { json(obj) { captured = obj; } };
handler(req, res);
process.stdout.write(JSON.stringify({
    response: captured,
    objectPrototypePolluted: Object.prototype.polluted === true,
}));
"""

_ADVERSARIAL_PAYLOAD = json.dumps({"__proto__": {"polluted": True}})


def _run_rendered_handler_in_real_node(content: bytes, payload_json: str) -> dict:
    """Write the rendered controller + a stub `../db` sibling (the real
    file's own `require('../db')`, never exercised by this cell but present
    in every generated controller -- see `NodeExpressEmitter.render`'s fixed
    boilerplate) into a real temp directory tree, then run it as a real
    `node` subprocess -- not a Python simulation of Node's own `for...in`/
    bracket-assignment semantics, since that JS-runtime-specific behavior is
    exactly the mechanism under test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "routes").mkdir()
        handler_path = root / "routes" / "handler.js"
        handler_path.write_bytes(content)
        (root / "db.js").write_text("module.exports = {};\n", encoding="utf-8")
        runner_path = root / "run_check.js"
        runner_path.write_text(_RUN_HANDLER_SCRIPT, encoding="utf-8")
        result = subprocess.run(
            ["node", str(runner_path), str(handler_path), payload_json],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"node run_check.js failed:\nstdout={result.stdout}\nstderr={result.stderr}"
        return json.loads(result.stdout)


@pytest.mark.skipif(not node_available(), reason="node CLI not available on this build host (PA-0005 pattern)")
def test_vulnerable_twin_really_pollutes_object_prototype_in_real_node(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-PP-0001"))[0].content
    outcome = _run_rendered_handler_in_real_node(content, _ADVERSARIAL_PAYLOAD)
    assert outcome["objectPrototypePolluted"] is True, (
        "the vulnerable twin's unguarded_deep_merge did not pollute Object.prototype "
        f"for real -- outcome={outcome!r}"
    )
    # The endpoint's own response still looks entirely ordinary -- the real
    # finding is invisible in the HTTP response, only in the shared runtime
    # state a later, unrelated request could then observe.
    assert outcome["response"] == {"preferences": {"theme": "light", "notifications": True}}


@pytest.mark.skipif(not node_available(), reason="node CLI not available on this build host (PA-0005 pattern)")
def test_secure_twin_does_not_pollute_object_prototype_in_real_node(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-PP-0002"))[0].content
    outcome = _run_rendered_handler_in_real_node(content, _ADVERSARIAL_PAYLOAD)
    assert outcome["objectPrototypePolluted"] is False, (
        "the secure twin's proto_key_filtered_merge polluted Object.prototype -- "
        f"the fix does not actually work: outcome={outcome!r}"
    )
    assert outcome["response"] == {"preferences": {"theme": "light", "notifications": True}}


@pytest.mark.skipif(not node_available(), reason="node CLI not available on this build host (PA-0005 pattern)")
def test_both_twins_still_merge_ordinary_keys_correctly_in_real_node(emitter, manifest) -> None:
    """Both twins are real merges, not "reject the whole body" stubs -- an
    ordinary, non-adversarial preference update still lands."""
    ordinary_payload = json.dumps({"theme": "dark"})
    for cell_id in ("LABGEN-PP-0001", "LABGEN-PP-0002"):
        content = emitter.render(_cell(manifest, cell_id))[0].content
        outcome = _run_rendered_handler_in_real_node(content, ordinary_payload)
        assert outcome["response"] == {"preferences": {"theme": "dark", "notifications": True}}, cell_id
        assert outcome["objectPrototypePolluted"] is False, cell_id
