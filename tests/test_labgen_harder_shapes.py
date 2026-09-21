"""The harder SQLi/XSS shapes (lane L-P1.2b, `docs/LAB_IMPLEMENTATION_PLAN.md`
§2.2): new `sink_context.family` values, their safety-matrix rows, the
`php_current` module fragments that render them, and the Tier-0/Tier-3
conformance passes over the new manifest.

Everything here is real and offline: the real `lab/safety_matrix.yaml`, the
real `lab/manifests/phase1_harder_shapes_sample.yaml`, the real emitter and
its real Jinja2 module fragments -- no fakes, and (where `php` is on the
build host, PA-0005's skip-guard pattern) a real `php -l` syntax check of
every generated cell.

The build-time *oracle* wiring for the identifier shapes lives in
tests/test_labgen_identifier_sqli_assertion.py, since that is a different
contract (lane L-P1.2a's prober) with its own failure modes.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.modules import SINKS, TRANSFORMS
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext, load_manifest
from fuzzlab.labgen.verdict import Effect, SafetyMatrixError, load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/phase1_harder_shapes_sample.yaml"
ALL_MANIFEST_PATHS = sorted(str(p) for p in Path("lab/manifests").glob("*.yaml"))

#: The families this lane added, and (for the identifier ones) the concern
#: that distinguishes them from a value-position cell.
NEW_SQL_FAMILIES = ("sql_identifier", "sql_join_alias")
NEW_XSS_FAMILIES = ("url_javascript_scheme", "html_attribute_unquoted")


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture()
def emitter():
    return PhpCurrentEmitter()


# ---------------------------------------------------------------------------
# Safety matrix: the new rows, and the properties that make them meaningful
# ---------------------------------------------------------------------------


def test_matrix_version_is_not_bumped_by_purely_additive_rows(matrix) -> None:
    """This file's own append-only rule: a brand-new op or sink_family is a
    new entry under the same version; only a breaking change to an existing
    (op, sink_family) pair bumps it. Every L-P1.2b row is a new pair."""
    assert matrix.version == 1


@pytest.mark.parametrize("family", NEW_SQL_FAMILIES)
def test_param_bind_has_no_effect_at_an_identifier_position(matrix, family: str) -> None:
    """The single most important row of this lane: no dialect can bind an
    identifier placeholder, so the textbook fix is *inapplicable* here, not
    merely omitted."""
    assert matrix.lookup("param_bind", family).effect is Effect.NO_EFFECT


@pytest.mark.parametrize("family", NEW_SQL_FAMILIES)
def test_identifier_charset_filter_is_partial_not_neutralising(matrix, family: str) -> None:
    entry = matrix.lookup("identifier_charset_filter", family)
    assert entry.effect is Effect.PARTIAL
    assert entry.neutralizes == ("sql_syntax_break",)
    # It must not claim the defining concern of this shape.
    assert "sql_identifier_substitution" not in entry.neutralizes


@pytest.mark.parametrize("family", NEW_SQL_FAMILIES)
def test_identifier_allowlist_is_the_only_row_closing_both_concerns(matrix, family: str) -> None:
    entry = matrix.lookup("identifier_allowlist", family)
    assert entry.effect is Effect.NEUTRALISES
    assert set(entry.neutralizes) == {"sql_syntax_break", "sql_identifier_substitution"}


def test_html_entity_escape_is_partial_in_a_javascript_url(matrix) -> None:
    """The escaping-context mismatch itself: correct escaping, wrong context
    -> still VULNERABLE, just harder (D20), never SECURE."""
    entry = matrix.lookup("html_entity_escape", "url_javascript_scheme")
    assert entry.effect is Effect.PARTIAL
    assert entry.neutralizes == ("js_context_break",)


def test_the_context_correct_xss_fixes_neutralise(matrix) -> None:
    assert matrix.lookup("url_scheme_allowlist", "url_javascript_scheme").effect is Effect.NEUTRALISES
    assert matrix.lookup("attr_value_allowlist", "html_attribute_unquoted").effect is Effect.NEUTRALISES


def test_every_transform_op_the_emitter_can_render_is_scorable_by_the_matrix(matrix) -> None:
    """A transform module php_current can render at a family the matrix has no
    row for would render fine and then make `verdict()` raise -- an emitter/
    matrix lockstep gap of exactly the kind PA-0024 is about. Asserted for
    every (op, family) pair this lane authored, from the registries
    themselves rather than a hand-kept list (PA-0001)."""
    authored = {
        "sql_identifier": ("param_bind", "identifier_charset_filter", "identifier_allowlist"),
        "sql_join_alias": ("param_bind", "identifier_charset_filter", "identifier_allowlist"),
        "url_javascript_scheme": ("html_entity_escape", "url_scheme_allowlist"),
        "html_attribute_unquoted": ("html_entity_escape", "attr_value_allowlist"),
    }
    for family, ops in authored.items():
        for op in ops:
            assert op in TRANSFORMS, f"{op!r} is authored against {family!r} but is not a registered module"
            matrix.lookup(op, family)  # must not raise


def test_an_unscored_op_at_a_new_family_still_fails_loud(matrix) -> None:
    """The fail-loud contract is not weakened by the new families: an op with
    no row for them raises rather than defaulting to no_effect."""
    with pytest.raises(SafetyMatrixError):
        verdict(
            Pipeline.from_list(["html_entity_escape"]),
            SinkContext(family="sql_identifier", required_neutralizations=("sql_syntax_break",)),
            matrix,
        )


# ---------------------------------------------------------------------------
# Derived verdicts for every cell of the new manifest
# ---------------------------------------------------------------------------


#: cell_id -> (verdict, difficulty). Written out per cell deliberately: these
#: are the *expected corpus labels* this lane claims to produce, so a silent
#: change in either the matrix rows or verdict()'s walk must fail here.
EXPECTED_VERDICTS = {
    "LABGEN-HS-0001": ("VULNERABLE", "trivial"),
    "LABGEN-HS-0002": ("VULNERABLE", "easy"),
    "LABGEN-HS-0003": ("VULNERABLE", "trivial"),
    "LABGEN-HS-0004": ("SECURE", None),
    "LABGEN-HS-0005": ("VULNERABLE", "trivial"),
    "LABGEN-HS-0006": ("VULNERABLE", "easy"),
    "LABGEN-HS-0007": ("SECURE", None),
    "LABGEN-HS-0008": ("VULNERABLE", "trivial"),
    "LABGEN-HS-0009": ("VULNERABLE", "easy"),
    "LABGEN-HS-0010": ("SECURE", None),
    "LABGEN-HS-0011": ("VULNERABLE", "trivial"),
    "LABGEN-HS-0012": ("VULNERABLE", "easy"),
    "LABGEN-HS-0013": ("SECURE", None),
}


def test_every_cell_of_the_new_manifest_derives_its_expected_verdict(manifest, matrix) -> None:
    assert {c.cell_id for c in manifest.cells} == set(EXPECTED_VERDICTS)
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert (derived.verdict, derived.difficulty) == EXPECTED_VERDICTS[cell.cell_id], cell.cell_id


def test_each_shape_has_a_vulnerable_and_a_secure_cell(manifest, matrix) -> None:
    """Both halves of every shape are present -- a corpus of only-vulnerable
    cells for a new family would teach a detector the family itself is the
    label (the fingerprint-independence concern, CR-LAB-0001 §3)."""
    by_family: dict[str, set[str]] = {}
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        by_family.setdefault(cell.sink_context.family, set()).add(derived.verdict)
    assert set(by_family) == set(NEW_SQL_FAMILIES) | set(NEW_XSS_FAMILIES)
    for family, verdicts in by_family.items():
        assert verdicts == {"VULNERABLE", "SECURE"}, family


def test_the_partial_middle_case_is_vulnerable_but_harder_than_the_raw_case(manifest, matrix) -> None:
    """D20's mechanism, end to end on real cells: the plausible-but-wrong fix
    never becomes a third verdict value, it raises the difficulty tier."""
    raw = verdict(Pipeline.from_list([]), _family("sql_identifier"), matrix)
    filtered = verdict(Pipeline.from_list(["identifier_charset_filter"]), _family("sql_identifier"), matrix)
    assert raw.verdict == filtered.verdict == "VULNERABLE"
    from fuzzlab.labgen.verdict import DIFFICULTY_TIERS

    assert DIFFICULTY_TIERS.index(filtered.difficulty) > DIFFICULTY_TIERS.index(raw.difficulty)


def _family(name: str) -> SinkContext:
    required = {
        "sql_identifier": ("sql_syntax_break", "sql_identifier_substitution"),
        "sql_join_alias": ("sql_syntax_break", "sql_identifier_substitution"),
        "url_javascript_scheme": ("js_context_break",),
        "html_attribute_unquoted": ("html_tag_break",),
    }[name]
    return SinkContext(family=name, required_neutralizations=required)


# ---------------------------------------------------------------------------
# Emitter: shape support, rendered content, PA-0024 whole-collection render
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("family", NEW_SQL_FAMILIES)
def test_supports_the_identifier_shapes(emitter, family: str) -> None:
    assert emitter.supports("sqli", _family(family)) is True


@pytest.mark.parametrize("family", NEW_XSS_FAMILIES)
def test_supports_the_escaping_context_mismatch_shapes(emitter, family: str) -> None:
    assert emitter.supports("xss", _family(family)) is True


def test_every_cell_of_every_manifest_that_targets_php_current_renders(emitter) -> None:
    """PA-0024, applied to this lane's widening of `supports()`: every
    *existing* record that could newly match a widened shape must be
    exercised, as a standing test -- not only the new manifest this change
    was written for. BUG-0022 was exactly a shape/page-profile lockstep gap
    of this kind (`supports()` returned True while `render()` raised), and
    this lane widens `supports()` by four shapes, one of which
    (`xss`/`html_attribute_unquoted`) is matched by a manifest cell authored
    back in Phase 0 (LABGEN-EX-0003).

    Scoped to `stack_profile == "php_current"`: the Phase-3 manifests
    describe other emitters' pages, which php_current has (correctly) no page
    profile for.
    """
    rendered_any = False
    for path in ALL_MANIFEST_PATHS:
        for cell in load_manifest(path).cells:
            if cell.stack_profile != "php_current":
                continue
            if not emitter.supports(cell.vuln_class, cell.sink_context):
                continue
            files = emitter.render(cell)  # must not raise
            assert files and files[0].content.startswith(b"<?php\n"), f"{path}:{cell.cell_id}"
            rendered_any = True
    assert rendered_any


def test_the_long_unrenderable_example_manifest_cell_now_renders(emitter) -> None:
    """LABGEN-EX-0003 (xss/html_attribute_unquoted, the illustrative
    manifest's escaping-context-mismatch cell) has been skipped as
    unsupported since Phase 0. It renders now, and via `read_stored_field` --
    its taint is a stored `bio`, not a request parameter, which is what the
    page profile's `source_override` expresses."""
    cell = next(
        c for c in load_manifest("lab/manifests/example_phase0_scaffold.yaml").cells
        if c.cell_id == "LABGEN-EX-0003"
    )
    assert emitter.supports(cell.vuln_class, cell.sink_context) is True
    content = emitter.render(cell)[0].content.decode("utf-8")
    assert "read_stored_field -> html_entity_escape -> html_attribute_unquoted_echo" in content
    assert "$bio = $currentUser['bio'];" in content
    assert "data-bio=' . htmlspecialchars($bio)" in content


def test_an_unknown_source_override_fails_loud(emitter, monkeypatch) -> None:
    """The override is fail-loud, not fail-quiet: a typo'd module name raises
    rather than silently falling back to the shape's default source."""
    from fuzzlab.labgen.emitters import php_current as php_current_module

    profiles = dict(php_current_module._PAGE_PARAMS)
    profiles["/theme.php"] = {**profiles["/theme.php"], "source_override": "nope_not_a_module"}
    monkeypatch.setattr(php_current_module, "_PAGE_PARAMS", profiles)
    cell = Cell(
        cell_id="LABGEN-HS-0011",
        vuln_class="xss",
        stack_profile="php_current",
        route=Route(method="GET", path="/theme.php"),
        sink_context=_family("html_attribute_unquoted"),
        transform=Pipeline.from_list([]),
    )
    with pytest.raises(ValueError, match="unknown source module"):
        emitter.render(cell)


def test_identifier_cell_renders_a_concatenated_identifier_not_a_placeholder(emitter, manifest) -> None:
    cell = _cell(manifest, "LABGEN-HS-0001")
    content = emitter.render(cell)[0].content.decode("utf-8")
    assert '"SELECT id, name FROM products ORDER BY " . $sort' in content
    assert "prepare(" not in content


def test_param_bind_cell_shows_the_identifier_is_still_concatenated(emitter, manifest) -> None:
    """The generated-code evidence for the (param_bind, sql_identifier) ->
    no_effect matrix row: a real prepared statement binds the WHERE value
    while the identifier is still glued into the statement text."""
    content = emitter.render(_cell(manifest, "LABGEN-HS-0003"))[0].content.decode("utf-8")
    assert "$pdo->prepare(" in content
    assert 'ORDER BY " . $sort' in content


def test_join_alias_cell_substitutes_the_tainted_value_three_times(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-HS-0005"))[0].content.decode("utf-8")
    sql_line = next(line for line in content.splitlines() if line.strip().startswith("$sql ="))
    assert sql_line.count("$alias") == 3


def test_identifier_allowlist_cell_can_only_emit_an_allowlisted_identifier(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-HS-0004"))[0].content.decode("utf-8")
    assert "in_array((string) $sort, ['id', 'name', 'price'], true) ? $sort : 'id'" in content


def test_javascript_url_cell_escapes_for_the_wrong_context(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-HS-0009"))[0].content.decode("utf-8")
    # The escaping is really applied -- that is the whole point of the shape.
    assert "htmlspecialchars($link)" in content
    # ...inside a javascript: URL, where it is the wrong escaping.
    assert 'href="javascript:' in content


def test_url_scheme_allowlist_cell_collapses_a_non_http_scheme(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-HS-0010"))[0].content.decode("utf-8")
    assert "parse_url((string) $link, PHP_URL_SCHEME)" in content
    assert "['http', 'https']" in content
    assert "htmlspecialchars" not in content


def test_unquoted_attribute_cell_has_no_quotes_around_the_value(emitter, manifest) -> None:
    content = emitter.render(_cell(manifest, "LABGEN-HS-0012"))[0].content.decode("utf-8")
    assert "data-theme=' . htmlspecialchars($theme)" in content


def _cell(manifest, cell_id: str) -> Cell:
    return next(c for c in manifest.cells if c.cell_id == cell_id)


# ---------------------------------------------------------------------------
# Module fragments: the authoring-gap guards, checked for real
# ---------------------------------------------------------------------------


def test_identifier_allowlist_module_refuses_a_missing_allowlist() -> None:
    with pytest.raises(ValueError, match="allowed_identifiers"):
        TRANSFORMS["identifier_allowlist"].render({"value_expr": "$sort"})


def test_identifier_allowlist_module_refuses_an_empty_allowlist() -> None:
    with pytest.raises(ValueError, match="empty"):
        TRANSFORMS["identifier_allowlist"].render({"value_expr": "$sort", "allowed_identifiers": ()})


def test_identifier_allowlist_module_refuses_a_non_identifier_entry() -> None:
    """Allowlisted identifiers are emitted into PHP source verbatim; a value
    needing escaping is an authoring error, not something to quietly quote."""
    with pytest.raises(ValueError, match="not a bare identifier"):
        TRANSFORMS["identifier_allowlist"].render(
            {"value_expr": "$sort", "allowed_identifiers": ("id", "name'); DROP TABLE x --")}
        )


def test_identifier_allowlist_module_preserves_author_order_as_the_fallback() -> None:
    result = TRANSFORMS["identifier_allowlist"].render(
        {"value_expr": "$sort", "allowed_identifiers": ("zeta", "alpha")}
    )
    # Not sorted: the first authored entry is the documented safe fallback.
    assert "['zeta', 'alpha']" in result.context["value_expr"]
    assert result.context["value_expr"].endswith(": 'zeta')")


def test_attr_value_allowlist_module_refuses_a_default_its_own_check_would_reject() -> None:
    with pytest.raises(ValueError, match="allowlist this"):
        TRANSFORMS["attr_value_allowlist"].render({"value_expr": "$theme", "attr_default": "not ok!"})


def test_identifier_charset_filter_module_emits_a_guard_and_leaves_value_expr_alone() -> None:
    result = TRANSFORMS["identifier_charset_filter"].render({"value_expr": "$sort"})
    assert "preg_match('/^[A-Za-z0-9_]+$/', (string) $sort)" in result.code
    assert "http_response_code(400)" in result.code
    assert result.context["value_expr"] == "$sort"


@pytest.mark.parametrize(
    "sink_name",
    ["sql_identifier_order_by", "sql_join_alias_lookup", "html_js_url_echo", "html_attribute_unquoted_echo"],
)
def test_new_sinks_reflect_whatever_value_expr_they_are_given(sink_name: str) -> None:
    """Same invariant the Phase-0 sinks have: a sink never escapes anything
    itself, so both twins of a pair can share it."""
    ctx = {
        "value_expr": "MARKER_EXPR",
        "bound": False,
        "table": "t",
        "join_table": "t",
        "column": "c",
        "join_column": "p",
        "css_class": "x",
        "attr_name": "a",
    }
    code = SINKS[sink_name].render(ctx).code
    assert "MARKER_EXPR" in code
    # Ignore comment lines: some sinks *document* htmlspecialchars()'s
    # context mismatch by name, which is documentation, not behavior.
    executable = "\n".join(line for line in code.splitlines() if not line.lstrip().startswith("//"))
    assert "htmlspecialchars(" not in executable
    assert "preg_match(" not in executable


# ---------------------------------------------------------------------------
# Conformance: static-precheck flags, Tier 0, Tier 3
# ---------------------------------------------------------------------------


def test_every_new_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        # Must not raise: an unregistered shape fails loud by design.
        status = static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)
        assert status is static_precheck.StaticPrecheckStatus.UNINFORMATIVE


def test_tier3_whole_sample_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, manifest.cells)  # must not raise


def test_tier3_renders_one_unique_path_per_cell(emitter, manifest) -> None:
    tree = tier3.render_whole_sample(emitter, manifest.cells)
    assert len(tree) == len(manifest.cells)


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_new_cell(emitter, manifest) -> None:
    for cell in manifest.cells:
        for result in tier0.lint_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"


def test_tier0_minimal_pair_holds_between_each_cell_and_its_weakened_twin(emitter, manifest) -> None:
    """Every cell's only difference from the same cell with its pipeline
    emptied must be the transform region -- the same `_weakened_twin`
    convention `fuzzlab.labgen.cli`'s own --check uses."""
    import dataclasses

    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        if not cell.transform.ops:
            continue
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


def test_cli_check_passes_end_to_end_on_the_new_manifest(tmp_path) -> None:
    """The real build gate, run for real: name-leak scanner, secret scanner,
    determinism, minimal pair, Tier 0 and Tier 3 over all 13 new cells."""
    from fuzzlab.labgen import cli as labgen_cli

    assert labgen_cli.main(["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--check"]) == 0
