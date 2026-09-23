"""ReDoS (CC-LAB-0076): the `regex_highlight_match` sink family's first
code-generation increment for `node_express` -- both module registries (the
shared `fuzzlab.labgen.modules` vocabulary-only entries and `node_express`'s
own rendering registry), the safety-matrix rows, the
`lab/manifests/redos_node_sample.yaml` manifest, Tier-0/Tier-3 conformance,
and a real, executed adversarial timing proof.

Mirrors `tests/test_labgen_prototype_pollution.py`'s own structure and
discipline:

- The real `lab/safety_matrix.yaml` (rows added by CC-LAB-0076).
- The real manifest, the real emitter, the real Jinja2 module fragments.
- A real, executed adversarial proof (not a Python simulation, and not a
  simulated timing number): the vulnerable/secure twins are rendered for
  real and each run as a real Node.js subprocess, timed with
  `process.hrtime.bigint()` *inside* the Node process (so Python-side
  subprocess-spawn overhead is never counted), against a benign search term
  and a classic catastrophic-backtracking pattern (`(a+)+$`) -- checking
  that the vulnerable twin's elapsed time on the adversarial term is far
  above both its own benign-term baseline and the secure twin's adversarial-
  term time, which stays effectively unchanged from its own baseline.

Threshold judgment call, stated plainly (also called out in this lane's
final report): calibration (see the emitter's own
`_ROUTE_PARAMS['/api/search']` docstring) measured the vulnerable twin at
~55-70ms and the secure twin at <1ms for this exact payload/content pair,
repeated 5 times with no observed flakiness. This test's own thresholds
(`_VULNERABLE_FLOOR_MS`/`_SECURE_CEILING_MS`) sit with wide margin on both
sides of that measured gap specifically so ordinary CI scheduling jitter
(observed here at low-single-digit milliseconds) cannot flip the verdict,
while still being tight enough that a regression which quietly removed the
escaping (or the intentional 22-character run in the lab content) would
fail the test rather than pass by accident.
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
from fuzzlab.labgen.emitters.node_express.modules import SINKS, TRANSFORMS
from fuzzlab.labgen.schema import Cell, SinkContext, load_manifest
from fuzzlab.labgen.verdict import Effect, load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/redos_node_sample.yaml"

FAMILY = SinkContext(family="regex_highlight_match", required_neutralizations=("redos",))


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
# Safety matrix: the CC-LAB-0076 rows this increment renders code for
# ---------------------------------------------------------------------------


def test_matrix_version_is_not_bumped_by_purely_additive_rows(matrix) -> None:
    assert matrix.version == 1


def test_unescaped_regex_construct_has_no_effect(matrix) -> None:
    entry = matrix.lookup("unescaped_regex_construct", "regex_highlight_match")
    assert entry.effect is Effect.NO_EFFECT
    assert entry.neutralizes == ()


def test_regex_escape_construct_neutralises_redos(matrix) -> None:
    entry = matrix.lookup("regex_escape_construct", "regex_highlight_match")
    assert entry.effect is Effect.NEUTRALISES
    assert entry.neutralizes == ("redos",)


def test_every_op_this_increment_renders_is_scorable_by_the_matrix(matrix) -> None:
    """A transform module node_express can render at a family the matrix has
    no row for would render fine and then make `verdict()` raise -- an
    emitter/matrix lockstep gap of exactly the kind PA-0024 is about."""
    for op in ("unescaped_regex_construct", "regex_escape_construct"):
        assert op in TRANSFORMS, f"{op!r} is registered but not a real transform module"
        matrix.lookup(op, "regex_highlight_match")  # must not raise


# ---------------------------------------------------------------------------
# Derived verdicts for both cells of the new manifest
# ---------------------------------------------------------------------------


EXPECTED_VERDICTS = {
    "LABGEN-RD-0001": ("VULNERABLE", "trivial"),
    "LABGEN-RD-0002": ("SECURE", None),
}


def test_every_cell_of_the_new_manifest_derives_its_expected_verdict(manifest, matrix) -> None:
    assert {c.cell_id for c in manifest.cells} == set(EXPECTED_VERDICTS)
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert (derived.verdict, derived.difficulty) == EXPECTED_VERDICTS[cell.cell_id], cell.cell_id


def test_the_pair_is_a_minimal_pair_on_class_and_family(manifest) -> None:
    """Both cells share one route, one class, one sink family -- the only
    difference is the transform region (the minimal-pair invariant)."""
    v = _cell(manifest, "LABGEN-RD-0001")
    s = _cell(manifest, "LABGEN-RD-0002")
    assert v.vuln_class == s.vuln_class == "redos"
    assert v.route.path == s.route.path
    assert v.sink_context.family == s.sink_context.family == "regex_highlight_match"
    assert v.sink_context.required_neutralizations == s.sink_context.required_neutralizations
    assert v.transform.ops != s.transform.ops


# ---------------------------------------------------------------------------
# Emitter: shape support, rendered content
# ---------------------------------------------------------------------------


def test_supports_the_redos_shape(emitter) -> None:
    assert emitter.supports("redos", FAMILY) is True


def test_vulnerable_cell_builds_the_regexp_with_no_escaping(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-RD-0001"))[0].content.decode("utf-8")
    assert "const highlightRegex = new RegExp(searchTerm, 'gi');" in content
    assert "escapeRegExp(searchTerm)" not in content
    # The escapeRegExp helper is still present unconditionally (fixed
    # boilerplate, same convention as escapeHtml), just unused by this twin.
    assert "function escapeRegExp(value)" in content


def test_secure_cell_escapes_before_constructing_the_regexp(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-RD-0002"))[0].content.decode("utf-8")
    assert "const highlightRegex = new RegExp(escapeRegExp(searchTerm), 'gi');" in content


def test_both_cells_highlight_the_same_fixed_content(emitter, manifest) -> None:
    """The sink never decides the redos concern itself -- only the transform
    (regex construction) differs between the twins."""
    for cell_id in ("LABGEN-RD-0001", "LABGEN-RD-0002"):
        content = emitter.render(_cell(manifest, cell_id))[0].content.decode("utf-8")
        assert (
            "const content = 'Comfortable running shoes with breathable mesh ' "
            "+ 'a'.repeat(22) + '!';" in content
        )
        assert "res.send(content.replace(highlightRegex, '<mark>$&</mark>'));" in content


def test_every_cell_of_the_new_manifest_renders(emitter, manifest) -> None:
    for cell in manifest.cells:
        files = emitter.render(cell)  # must not raise
        assert files and files[0].content.startswith(b"'use strict';\n"), cell.cell_id


# ---------------------------------------------------------------------------
# Module fragments: the authoring-gap guard, checked for real
# ---------------------------------------------------------------------------


def test_regex_highlight_match_sink_refuses_a_missing_content_literal() -> None:
    with pytest.raises(ValueError, match="content_literal"):
        SINKS["regex_highlight_match"].render({"value_expr": "highlightRegex"})


def test_regex_highlight_match_sink_never_decides_the_redos_concern() -> None:
    """The invariant every other sink has (never decides the vulnerability
    concern itself, so both twins can share it unchanged) still holds here."""
    ctx = {"value_expr": "MARKER_EXPR", "content_literal": "'x'"}
    code = SINKS["regex_highlight_match"].render(ctx).code
    assert "MARKER_EXPR" in code
    assert "escapeRegExp" not in code


def test_transforms_publish_the_fixed_highlight_regex_marker() -> None:
    for op in ("unescaped_regex_construct", "regex_escape_construct"):
        result = TRANSFORMS[op].render({"value_expr": "searchTerm"})
        assert result.context["value_expr"] == "highlightRegex"


# ---------------------------------------------------------------------------
# Shared vocabulary registration (fuzzlab.labgen.modules), per the
# L-P3.3c-DOM/CC-LAB-0070 precedent this addition follows
# ---------------------------------------------------------------------------


def test_shared_php_oriented_registry_also_knows_the_new_names() -> None:
    """CC-LAB-0076 registers this shape in BOTH node_express's own registry
    AND the shared fuzzlab.labgen.modules registry (vocabulary-only there),
    even though no PHP emitter's own _MODULE_SET_BY_SHAPE renders it."""
    from fuzzlab.labgen.modules import SINKS as SHARED_SINKS
    from fuzzlab.labgen.modules import TRANSFORMS as SHARED_TRANSFORMS

    assert "unescaped_regex_construct" in SHARED_TRANSFORMS
    assert "regex_escape_construct" in SHARED_TRANSFORMS
    assert SHARED_TRANSFORMS["unescaped_regex_construct"].category == "transform"
    assert "regex_highlight_match" in SHARED_SINKS
    assert SHARED_SINKS["regex_highlight_match"].category == "sink"

    # The shared registry's own fragments must still render for real (they
    # are documentary/placeholder PHP, never actually assembled into a PHP
    # page by any emitter, but must not be dead entries that raise).
    SHARED_TRANSFORMS["unescaped_regex_construct"].render({})
    SHARED_TRANSFORMS["regex_escape_construct"].render({})
    SHARED_SINKS["regex_highlight_match"].render({"value_expr": "$term"})


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


# Not attempted here, same as tests/test_labgen_prototype_pollution.py: the
# CLI's `--check` end-to-end run (node_express is not offered by `--emitter`
# yet).


# ---------------------------------------------------------------------------
# The real, executed adversarial timing proof: a genuine Node.js subprocess
# running the rendered module against a benign term and a classic
# catastrophic-backtracking pattern, timed *inside* the Node process (never
# a Python-side simulation of the timing, and never a simulated elapsed
# number) -- mirrors
# tests/test_labgen_prototype_pollution.py::..._rejects_a_syntax_injection_shaped_key's
# discipline of executing the real mechanism, adapted for this stack's real
# timing-differential mechanism.
# ---------------------------------------------------------------------------

_RUN_HANDLER_SCRIPT = """
'use strict';
const handlerPath = process.argv[2];
const term = process.argv[3];
const handler = require(handlerPath);
const req = { query: { q: term } };
let captured = null;
const res = { send(body) { captured = body; } };
const t0 = process.hrtime.bigint();
handler(req, res);
const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
process.stdout.write(JSON.stringify({ response: captured, elapsedMs }));
"""

_BENIGN_TERM = "shoes"
_EVIL_TERM = "(a+)+$"

# Judgment-call thresholds -- see the module docstring's "Threshold judgment
# call" paragraph for the full rationale and the calibration numbers behind
# these margins.
_VULNERABLE_FLOOR_MS = 20.0    # measured ~55-70ms; floor sits well below that
_SECURE_CEILING_MS = 5.0       # measured <1ms; ceiling sits well above that


def _run_rendered_handler_in_real_node(content: bytes, term: str) -> dict:
    """Write the rendered controller + a stub `../db` sibling (the real
    file's own `require('../db')`, never exercised by this cell but present
    in every generated controller) into a real temp directory tree, then run
    it as a real `node` subprocess -- not a Python simulation of V8's own
    regex-engine backtracking behavior, since that JS-runtime-specific
    behavior is exactly the mechanism under test. The elapsed time is
    measured with `process.hrtime.bigint()` *inside* the subprocess, around
    exactly the `handler(req, res)` call -- so it excludes Node's own
    startup/require time and any Python-side subprocess overhead, both of
    which would otherwise swamp a tens-of-milliseconds signal."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "routes").mkdir()
        handler_path = root / "routes" / "handler.js"
        handler_path.write_bytes(content)
        (root / "db.js").write_text("module.exports = {};\n", encoding="utf-8")
        runner_path = root / "run_check.js"
        runner_path.write_text(_RUN_HANDLER_SCRIPT, encoding="utf-8")
        result = subprocess.run(
            ["node", str(runner_path), str(handler_path), term],
            capture_output=True,
            text=True,
            timeout=10,   # bounded: the calibrated payload never approaches this
        )
        assert result.returncode == 0, f"node run_check.js failed:\nstdout={result.stdout}\nstderr={result.stderr}"
        return json.loads(result.stdout)


@pytest.mark.skipif(not node_available(), reason="node CLI not available on this build host (PA-0005 pattern)")
def test_vulnerable_twin_really_backtracks_catastrophically_in_real_node(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-RD-0001"))[0].content
    benign = _run_rendered_handler_in_real_node(content, _BENIGN_TERM)
    evil = _run_rendered_handler_in_real_node(content, _EVIL_TERM)
    assert evil["elapsedMs"] > _VULNERABLE_FLOOR_MS, (
        "the vulnerable twin's unescaped_regex_construct did not really blow up "
        f"in real Node for the calibrated payload -- benign={benign!r} evil={evil!r}"
    )
    assert evil["elapsedMs"] > benign["elapsedMs"] * 50, (
        "the evil-term run should be dramatically slower than the benign-term run "
        f"on the SAME (vulnerable) handler -- benign={benign!r} evil={evil!r}"
    )
    # The endpoint's own response still looks entirely ordinary -- `(a+)+$`
    # is anchored to end-of-string but the fixed content ends in '!', so it
    # never actually matches (that mismatch, tried exhaustively across every
    # backtracking permutation, is exactly what makes this pattern
    # catastrophic) -- the real finding is invisible in the response body,
    # only in how long the request took.
    assert evil["response"] == "Comfortable running shoes with breathable mesh " + "a" * 22 + "!"


@pytest.mark.skipif(not node_available(), reason="node CLI not available on this build host (PA-0005 pattern)")
def test_secure_twin_stays_fast_on_the_same_adversarial_term_in_real_node(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-RD-0002"))[0].content
    benign = _run_rendered_handler_in_real_node(content, _BENIGN_TERM)
    evil = _run_rendered_handler_in_real_node(content, _EVIL_TERM)
    assert evil["elapsedMs"] < _SECURE_CEILING_MS, (
        "the secure twin's regex_escape_construct is not actually fast on the "
        f"adversarial term -- the fix does not work: benign={benign!r} evil={evil!r}"
    )
    # An escaped '(a+)+$' can only ever match itself literally -- it is not
    # present in the fixed content, so nothing is highlighted.
    assert "<mark>" not in evil["response"]


@pytest.mark.skipif(not node_available(), reason="node CLI not available on this build host (PA-0005 pattern)")
def test_both_twins_still_highlight_an_ordinary_term_correctly_in_real_node(emitter, manifest) -> None:
    """Both twins are real regex-based highlighters, not "reject everything"
    stubs -- an ordinary, non-adversarial search term still highlights."""
    for cell_id in ("LABGEN-RD-0001", "LABGEN-RD-0002"):
        content = emitter.render(_cell(manifest, cell_id))[0].content
        outcome = _run_rendered_handler_in_real_node(content, "mesh")
        assert "<mark>mesh</mark>" in outcome["response"], cell_id
