"""The **full-depth** module inventory for the `php_laravel` emitter (lane
L-P3.3b, `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3 step 2): every shape
`php_current` supports, ported to Laravel/Eloquent/Blade idiom, plus the
conformance passes over the widened
`lab/manifests/phase3_php_laravel_sample.yaml`.

Deliberately mirrors `tests/test_labgen_harder_shapes.py` (L-P1.2b's own test
file, for the same shapes on `php_current`) so the two PHP stacks' evidence is
directly comparable -- same sections, same invariants, the Laravel-rendered
equivalents of the same assertions. Everything here is real and offline: the
real safety matrix, the real manifest, the real emitter and its real Jinja2
fragments, and (skip-guarded per PA-0005) a real `php -l` of every generated
file.

Two things this file covers that `php_current`'s cannot, because they only
exist on a routed, multi-file stack: the per-cell **Blade view** an HTML-sink
cell emits alongside its controller, and the identifier-SQLi oracle's
**route-rewrite adapter**
(`fuzzlab.labgen.emitters.php_laravel.identifier_sqli`) -- this stack serves a
cell at its own cell-ID-derived URL, not at `cell.route.path`.
"""

from __future__ import annotations

import dataclasses
import re
import shutil
from pathlib import Path

import pytest

from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.emitters.php_laravel import (
    _MODULE_SET_BY_SHAPE,
    _PAGE_PROFILES,
    LaravelEmitter,
)
from fuzzlab.labgen.emitters.php_laravel.modules import SINKS, TRANSFORMS, VIEW_SINKS
from fuzzlab.labgen.emitters.php_laravel.route_accumulator import assemble_routes_file
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/phase3_php_laravel_sample.yaml"
ALL_MANIFEST_PATHS = sorted(str(p) for p in Path("lab/manifests").glob("*.yaml"))


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture()
def emitter():
    return LaravelEmitter()


def _cell(manifest, cell_id: str) -> Cell:
    return next(c for c in manifest.cells if c.cell_id == cell_id)


def _rendered(emitter, manifest, cell_id: str) -> dict[str, str]:
    """This cell's emitted files as ``{role: decoded content}``."""
    return {f.role: f.content.decode("utf-8") for f in emitter.render(_cell(manifest, cell_id))}


# ---------------------------------------------------------------------------
# Inventory: the emitter really does carry every shape, full depth
# ---------------------------------------------------------------------------


#: The shapes the plan's §4.3 step 2 requires of this stack: "every shape
#: `php_current` already supports ... plus the identifier/alias/connector-
#: position SQLi and escaping-context-mismatch XSS shapes from Phase 1".
#: Written out as the *contract* (a fixed external requirement, the one case
#: PA-0001 reserves literals for); the assertion below compares it against
#: `php_current`'s live registry so the two can never silently diverge.
REQUIRED_SHAPES = {
    ("sqli", "sql_numeric_literal"),
    ("sqli", "sql_string_literal"),
    ("sqli", "sql_identifier"),
    ("sqli", "sql_join_alias"),
    ("xss", "html_body"),
    ("xss", "url_javascript_scheme"),
    ("xss", "html_attribute_unquoted"),
}


def test_laravel_carries_every_shape_php_current_supports() -> None:
    """"Full depth" is not a claim in a docstring: this stack's shape set is
    compared against `php_current`'s own live registry (PA-0001/PA-0027(b) --
    derived from the registry, not from a hand-kept roster), so a shape added
    to that emitter later shows up here as a failure rather than as a silent
    Laravel gap.
    """
    from fuzzlab.labgen.emitters.php_current import _MODULE_SET_BY_SHAPE as PHP_CURRENT_SHAPES

    assert set(PHP_CURRENT_SHAPES) == REQUIRED_SHAPES, (
        "php_current's shape set moved; php_laravel is the stack the plan assigns FULL depth, "
        "so this lane's inventory must move with it"
    )
    assert set(_MODULE_SET_BY_SHAPE) == set(PHP_CURRENT_SHAPES)


@pytest.mark.parametrize("shape", sorted(REQUIRED_SHAPES))
def test_supports_every_required_shape(emitter, shape: tuple[str, str]) -> None:
    vuln_class, family = shape
    assert emitter.supports(vuln_class, SinkContext(family=family, required_neutralizations=())) is True


def test_every_module_a_shape_names_is_registered(emitter) -> None:
    """A shape map that names a module the registry does not have would raise
    only when that shape is first rendered -- the emitter/registry lockstep gap
    PA-0024 is about, checked from both registries directly."""
    from fuzzlab.labgen.emitters.php_laravel.modules import COMPLEXITIES, SOURCES

    for shape, module_set in _MODULE_SET_BY_SHAPE.items():
        assert module_set.source in SOURCES, shape
        assert module_set.sink in SINKS, shape
        assert module_set.complexity in COMPLEXITIES, shape


def test_module_names_are_classifiable_by_the_shared_minimal_pair_checker() -> None:
    """The load-bearing reason this emitter uses the project's shared module
    names (see modules.py's docstring, decision 1): `fuzzlab.labgen
    .minimal_pair` classifies each composition position by looking the name up
    in `fuzzlab.labgen.modules`' registries and *raises* for one it cannot
    find -- so a Laravel-only name would make every cell fail the minimal-pair
    gate with a setup error rather than a real finding.
    """
    from fuzzlab.labgen.emitters.php_laravel.modules import COMPLEXITIES, SOURCES
    from fuzzlab.labgen.minimal_pair import _MODULE_CATEGORY

    for registry, category in (
        (SOURCES, "source"),
        (TRANSFORMS, "transform"),
        (SINKS, "sink"),
        (COMPLEXITIES, "complexity"),
    ):
        for name in registry:
            assert _MODULE_CATEGORY.get(name) == category, name


def test_every_transform_op_the_emitter_can_render_is_scorable_by_the_matrix(matrix) -> None:
    """An op this emitter can render at a family the matrix has no row for
    would render fine and then make `verdict()` raise. Asserted for every
    (op, family) pair this manifest actually authors, read from the manifest
    and the registry rather than a hand-kept list (PA-0001)."""
    manifest = load_manifest(MANIFEST_PATH)
    seen = set()
    for cell in manifest.cells:
        for op in cell.transform.ops:
            assert op in TRANSFORMS, f"{op!r} is authored but not a registered php_laravel module"
            matrix.lookup(op, cell.sink_context.family)  # must not raise
            seen.add((op, cell.sink_context.family))
    assert seen, "no transform ops authored -- this test would be vacuous"


# ---------------------------------------------------------------------------
# Derived verdicts for every cell of the widened manifest
# ---------------------------------------------------------------------------


#: cell_id -> (verdict, difficulty). Written out per cell deliberately, the
#: same convention tests/test_labgen_harder_shapes.py uses: these are the
#: *expected corpus labels* this lane claims to produce, so a silent change in
#: either the matrix rows or verdict()'s walk must fail here.
EXPECTED_VERDICTS = {
    "LABGEN-PL-0001": ("VULNERABLE", "trivial"),
    "LABGEN-PL-0002": ("SECURE", None),
    "LABGEN-PL-0003": ("VULNERABLE", "trivial"),
    "LABGEN-PL-0004": ("SECURE", None),
    "LABGEN-PL-0005": ("VULNERABLE", "trivial"),
    "LABGEN-PL-0006": ("SECURE", None),
    "LABGEN-PL-0007": ("VULNERABLE", "trivial"),
    "LABGEN-PL-0008": ("VULNERABLE", "easy"),
    "LABGEN-PL-0009": ("VULNERABLE", "trivial"),
    "LABGEN-PL-0010": ("SECURE", None),
    "LABGEN-PL-0011": ("VULNERABLE", "trivial"),
    "LABGEN-PL-0012": ("VULNERABLE", "easy"),
    "LABGEN-PL-0013": ("VULNERABLE", "trivial"),
    "LABGEN-PL-0014": ("SECURE", None),
    "LABGEN-PL-0015": ("VULNERABLE", "trivial"),
    "LABGEN-PL-0016": ("VULNERABLE", "easy"),
    "LABGEN-PL-0017": ("SECURE", None),
    "LABGEN-PL-0018": ("VULNERABLE", "trivial"),
    "LABGEN-PL-0019": ("VULNERABLE", "easy"),
    "LABGEN-PL-0020": ("SECURE", None),
}


def test_every_cell_of_the_widened_manifest_derives_its_expected_verdict(manifest, matrix) -> None:
    assert {c.cell_id for c in manifest.cells} == set(EXPECTED_VERDICTS)
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        assert (derived.verdict, derived.difficulty) == EXPECTED_VERDICTS[cell.cell_id], cell.cell_id


def test_each_shape_has_a_vulnerable_and_a_secure_cell(manifest, matrix) -> None:
    """Both halves of every shape are present -- a corpus of only-vulnerable
    cells for a family would teach a detector the family itself is the label
    (the fingerprint-independence concern, CR-LAB-0001 §3)."""
    by_family: dict[str, set[str]] = {}
    for cell in manifest.cells:
        derived = verdict(cell.transform, cell.sink_context, matrix)
        by_family.setdefault(cell.sink_context.family, set()).add(derived.verdict)
    assert set(by_family) == {family for _, family in _MODULE_SET_BY_SHAPE}
    for family, verdicts in by_family.items():
        assert verdicts == {"VULNERABLE", "SECURE"}, family


def test_the_partial_middle_case_is_vulnerable_but_harder_than_the_raw_case(manifest, matrix) -> None:
    """D20's mechanism on Laravel-rendered cells: the plausible-but-wrong fix
    never becomes a third verdict value, it raises the difficulty tier."""
    from fuzzlab.labgen.verdict import DIFFICULTY_TIERS

    raw = verdict(_cell(manifest, "LABGEN-PL-0007").transform, _cell(manifest, "LABGEN-PL-0007").sink_context, matrix)
    filtered = verdict(
        _cell(manifest, "LABGEN-PL-0008").transform, _cell(manifest, "LABGEN-PL-0008").sink_context, matrix
    )
    assert raw.verdict == filtered.verdict == "VULNERABLE"
    assert DIFFICULTY_TIERS.index(filtered.difficulty) > DIFFICULTY_TIERS.index(raw.difficulty)


# ---------------------------------------------------------------------------
# Rendering: the Laravel idiom each shape is actually ported to
# ---------------------------------------------------------------------------


def test_string_literal_cell_uses_where_raw_and_its_twin_uses_a_bound_where(emitter, manifest) -> None:
    """The real Laravel footgun, not a transliterated PDO call: the query
    builder binds values through `where()`, and `whereRaw()` is the escape
    hatch that splices the value into the statement."""
    raw = _rendered(emitter, manifest, "LABGEN-PL-0003")["controller"]
    bound = _rendered(emitter, manifest, "LABGEN-PL-0004")["controller"]
    assert "->whereRaw(\"username = '\" . $username . \"'\")" in raw
    assert "->where('username', $username)" in bound
    assert "whereRaw" not in bound


def test_identifier_cell_renders_order_by_raw_not_a_bound_placeholder(emitter, manifest) -> None:
    content = _rendered(emitter, manifest, "LABGEN-PL-0007")["controller"]
    assert "->orderByRaw($sort)" in content
    assert "?" not in content.split("orderByRaw")[1].split("\n")[0]


def test_param_bind_identifier_cell_shows_the_identifier_is_still_concatenated(emitter, manifest) -> None:
    """The generated-code evidence for the (param_bind, sql_identifier) ->
    no_effect matrix row: a real bound parameter carries the WHERE value while
    the identifier is still glued into the statement text."""
    content = _rendered(emitter, manifest, "LABGEN-PL-0009")["controller"]
    assert "WHERE active = ? ORDER BY \" . $sort" in content
    assert ", [1]);" in content


def test_join_alias_cell_substitutes_the_tainted_value_three_times(emitter, manifest) -> None:
    content = _rendered(emitter, manifest, "LABGEN-PL-0011")["controller"]
    sql_line = next(line for line in content.splitlines() if line.strip().startswith("$sql ="))
    assert sql_line.count("$alias") == 3


def test_identifier_allowlist_cell_can_only_emit_an_allowlisted_identifier(emitter, manifest) -> None:
    content = _rendered(emitter, manifest, "LABGEN-PL-0010")["controller"]
    allowed = _PAGE_PROFILES["/catalog"]["allowed_identifiers"]
    rendered_list = ", ".join(f"'{name}'" for name in allowed)
    assert f"in_array((string) $sort, [{rendered_list}], true) ? $sort : '{allowed[0]}'" in content


def test_charset_filter_cell_uses_laravels_abort_idiom(emitter, manifest) -> None:
    content = _rendered(emitter, manifest, "LABGEN-PL-0008")["controller"]
    assert "preg_match('/^[A-Za-z0-9_]+$/', (string) $sort)" in content
    assert "abort(400);" in content
    # The filter must not restrict WHICH identifier is used -- that is what
    # keeps it `partial` rather than neutralising.
    assert "in_array" not in content


def test_html_cells_emit_a_controller_and_their_own_blade_view(emitter, manifest) -> None:
    """A Laravel controller returns a view; that is what porting an XSS shape
    to this stack's idiom means, and it is why an HTML cell is a two-file
    cell here while `php_current`'s is a one-file `echo`."""
    for cell in manifest.cells:
        files = emitter.render(cell)
        sink = _MODULE_SET_BY_SHAPE[(cell.vuln_class, cell.sink_context.family)].sink
        expected_roles = ["controller", "view"] if sink in VIEW_SINKS else ["controller"]
        assert [f.role for f in files] == expected_roles, cell.cell_id
        if sink in VIEW_SINKS:
            view = next(f for f in files if f.role == "view")
            assert view.path == f"resources/views/cells/{cell.cell_id.lower()}.blade.php"
            assert f"view('cells.{cell.cell_id.lower()}'" in files[0].content.decode("utf-8")


def test_escaped_html_body_cell_applies_laravels_e_helper_in_the_controller(emitter, manifest) -> None:
    """Decision 2 of modules.py, asserted on real output: the escape lives in
    the *transform* region (the controller), and the Blade view echoes raw --
    so both twins of the pair share one byte-identical view file and the whole
    security-relevant difference is inside the declared region."""
    vulnerable = _rendered(emitter, manifest, "LABGEN-PL-0005")
    secure = _rendered(emitter, manifest, "LABGEN-PL-0006")
    assert "['value' => $bio]" in vulnerable["controller"]
    assert "['value' => e($bio)]" in secure["controller"]
    assert "{!! $value !!}" in vulnerable["view"] and "{!! $value !!}" in secure["view"]
    # Only the provenance comment (which names the composition) differs.
    def _code(view: str) -> list[str]:
        return [line for line in view.splitlines() if not line.startswith("//")]

    assert _code(vulnerable["view"]) == _code(secure["view"])


def test_javascript_url_cell_escapes_for_the_wrong_context(emitter, manifest) -> None:
    files = _rendered(emitter, manifest, "LABGEN-PL-0016")
    # The escaping is really applied -- that is the whole point of the shape.
    assert "e($link)" in files["controller"]
    # ...inside a javascript: URL, where it is the wrong escaping.
    assert 'href="javascript:{!! $value !!}"' in files["view"]


def test_url_scheme_allowlist_cell_collapses_a_non_http_scheme(emitter, manifest) -> None:
    content = _rendered(emitter, manifest, "LABGEN-PL-0017")["controller"]
    assert "parse_url((string) $link, PHP_URL_SCHEME)" in content
    assert "['http', 'https']" in content
    # The context-correct fix does not reach for entity escaping at all.
    assert "e($link)" not in content


def test_unquoted_attribute_cell_has_no_quotes_around_the_value(emitter, manifest) -> None:
    view = _rendered(emitter, manifest, "LABGEN-PL-0019")["view"]
    assert "data-theme={!! $value !!}" in view
    assert 'data-theme="' not in view


def test_attr_value_allowlist_cell_falls_back_to_the_profiles_default(emitter, manifest) -> None:
    content = _rendered(emitter, manifest, "LABGEN-PL-0020")["controller"]
    default = _PAGE_PROFILES["/theme"]["attr_default"]
    assert f"preg_match('/^[A-Za-z0-9_-]+$/', (string) $theme) ? $theme : '{default}'" in content


@pytest.mark.parametrize("sink_name", sorted(SINKS))
def test_no_sink_escapes_anything_itself(sink_name: str) -> None:
    """The invariant that lets both twins of a pair share one sink fragment:
    a sink reflects whatever `value_expr` it is given and never escapes."""
    ctx = {
        "value_expr": "MARKER_EXPR",
        "bound": False,
        "table": "t",
        "join_table": "t",
        "column": "c",
        "join_column": "p",
        "css_class": "x",
        "attr_name": "a",
        "password_var": "secret_hash",
        "password_param": "secret",
    }
    code = SINKS[sink_name].render(ctx).code
    if sink_name in VIEW_SINKS:
        # A view fragment reads the value the controller passed in, so its
        # marker is the Blade variable rather than the raw expression.
        assert "{!! $value !!}" in code
    else:
        assert "MARKER_EXPR" in code
    # Ignore comment lines: some fragments *document* the escaping-context
    # mismatch by name, which is documentation, not behavior.
    executable = "\n".join(
        line for line in code.splitlines() if not line.lstrip().startswith(("//", "{#"))
    )
    assert "htmlspecialchars(" not in executable
    # Laravel's escape helper is the bare function `e(...)`; anchor the match
    # so it cannot collide with the tail of `where(`/`get(` etc. (PA-0022's
    # word-boundary rule for any mechanical substring check).
    assert re.search(r"(?<![A-Za-z0-9_$>])e\(", executable) is None, executable


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
    assert "abort(400);" in result.code
    assert result.context["value_expr"] == "$sort"


def test_an_unknown_source_override_fails_loud(emitter, monkeypatch) -> None:
    """The page-profile source override is fail-loud, not fail-quiet: a typo'd
    module name raises rather than silently falling back to the shape's
    default source (the same guard php_current grew in L-P1.2b)."""
    from fuzzlab.labgen.emitters import php_laravel as php_laravel_module

    profiles = dict(php_laravel_module._PAGE_PROFILES)
    profiles["/theme"] = {**profiles["/theme"], "source_override": "nope_not_a_module"}
    monkeypatch.setattr(php_laravel_module, "_PAGE_PROFILES", profiles)
    cell = Cell(
        cell_id="LABGEN-PL-0018",
        vuln_class="xss",
        stack_profile="php_laravel",
        route=Route(method="GET", path="/theme"),
        sink_context=SinkContext(family="html_attribute_unquoted", required_neutralizations=("html_tag_break",)),
        transform=Pipeline.from_list([]),
    )
    with pytest.raises(ValueError, match="unknown source module"):
        emitter.render(cell)


def test_a_page_this_emitter_has_no_profile_for_fails_loud(emitter) -> None:
    cell = Cell(
        cell_id="LABGEN-PL-0097",
        vuln_class="sqli",
        stack_profile="php_laravel",
        route=Route(method="GET", path="/catalog.php"),  # php_current's route, not this stack's
        sink_context=SinkContext(family="sql_identifier", required_neutralizations=("sql_syntax_break",)),
        transform=Pipeline.from_list([]),
    )
    with pytest.raises(ValueError, match="no page profile for route"):
        emitter.render(cell)


def test_a_non_direct_context_depth_is_refused_rather_than_flattened(emitter, manifest) -> None:
    """The depth axis is not ported to Laravel yet; rendering a
    `same_file_helper` cell as `direct` would mislabel the depth its corpus
    record claims, so the emitter refuses loudly (see the emitter docstring's
    "deliberately not carried" list)."""
    cell = dataclasses.replace(_cell(manifest, "LABGEN-PL-0001"), context_depth="same_file_helper")
    with pytest.raises(ValueError, match="context_depth 'direct' only"):
        emitter.render(cell)


# ---------------------------------------------------------------------------
# PA-0024: the widening exercises every existing record that could match
# ---------------------------------------------------------------------------


def test_every_cell_of_every_manifest_that_targets_php_laravel_renders(emitter) -> None:
    """PA-0024, applied to this lane's widening of `supports()` from one shape
    to seven: every *existing* record that could newly match must be
    exercised, as a standing test -- not only the manifest this change was
    written for. BUG-0022 was exactly a shape/page-profile lockstep gap of
    this kind (`supports()` True while `render()` raised).

    Scoped to `stack_profile == "php_laravel"`, the same scoping
    `tests/test_labgen_harder_shapes.py` uses for `php_current`: the other
    manifests describe other emitters' pages, which this emitter has
    (correctly) no page profile for.
    """
    rendered_any = False
    for path in ALL_MANIFEST_PATHS:
        for cell in load_manifest(path).cells:
            if cell.stack_profile != "php_laravel":
                continue
            if not emitter.supports(cell.vuln_class, cell.sink_context):
                continue
            files = emitter.render(cell)  # must not raise
            assert files and files[0].content.startswith(b"<?php\n"), f"{path}:{cell.cell_id}"
            rendered_any = True
    assert rendered_any


# ---------------------------------------------------------------------------
# Conformance: static precheck, minimal pair, Tier 0, Tier 3, the route file
# ---------------------------------------------------------------------------


def test_every_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        # Must not raise: an unregistered shape fails loud by design.
        static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)


def test_tier3_whole_sample_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, manifest.cells)  # must not raise


def test_tier3_renders_one_unique_path_per_emitted_file(emitter, manifest) -> None:
    """Every cell's controller (and every HTML cell's view) lands at its own
    path -- no two cells, twins included, collide."""
    tree = tier3.render_whole_sample(emitter, manifest.cells)
    expected = sum(len(emitter.render(cell)) for cell in manifest.cells)
    assert len(tree) == expected


def test_tier0_minimal_pair_holds_between_each_cell_and_its_weakened_twin(emitter, manifest) -> None:
    """Every cell's only difference from the same cell with its pipeline
    emptied must be the transform region -- the same `_weakened_twin`
    convention `fuzzlab.labgen.cli`'s own --check uses, here against the real
    (PHP-oriented) shared checker, which this stack's generated files are
    shaped for."""
    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        if not cell.transform.ops:
            continue
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_cell_including_the_blade_views(emitter, manifest) -> None:
    for cell in manifest.cells:
        for result in tier0.lint_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"


def test_the_routes_file_carries_one_sorted_line_per_cell(emitter, manifest) -> None:
    fragments = {c.cell_id: emitter.route_fragment_for(c) for c in manifest.cells}
    content = assemble_routes_file(fragments).content.decode("utf-8")
    route_lines = [line for line in content.splitlines() if line.startswith("Route::get(")]
    assert len(route_lines) == len(manifest.cells)
    # Sorted by cell ID, never by append order (Addendum D determinism rule).
    assert route_lines == sorted(route_lines)
    for cell in manifest.cells:
        assert f"/cell/{cell.cell_id.lower()}" in content


def test_cli_check_passes_end_to_end_on_the_widened_manifest(tmp_path) -> None:
    """The real build gate, run for real over all 20 cells: name-leak scanner,
    secret scanner, determinism, minimal pair, Tier 0 and Tier 3 -- through the
    CLI's own emitter registry, which this lane registers `php_laravel` in."""
    from fuzzlab.labgen import cli as labgen_cli

    assert labgen_cli.main(
        ["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--emitter", "php_laravel", "--check"]
    ) == 0


# ---------------------------------------------------------------------------
# The identifier-SQLi oracle adapter (task step 3: verified, not assumed)
# ---------------------------------------------------------------------------


class FakeHttpRunner:
    """Scripted :class:`HttpProbeResult` per probe leg (baseline/TRUE/FALSE),
    recording every URL -- the same fixture shape
    tests/test_labgen_identifier_sqli_assertion.py uses."""

    def __init__(self, *scripted):
        self._scripted = list(scripted)
        self.urls: list[str] = []

    def __call__(self, url, headers, cookie, timeout_s):
        from fuzzlab.labgen.identifier_sqli_oracle import HttpProbeResult

        self.urls.append(url)
        status, body = self._scripted[min(len(self.urls) - 1, len(self._scripted) - 1)]
        return HttpProbeResult(url=url, status_code=status, body=body, timed_out=False, elapsed_s=0.01)


def test_the_shared_assertion_probes_the_manifest_route_which_laravel_does_not_serve(manifest) -> None:
    """Why an adapter is needed at all, demonstrated rather than asserted in
    prose: the stack-agnostic module derives the probe URL from
    `cell.route.path` (correct for filesystem-routed `php_current`), but this
    emitter serves the cell at its own cell-ID-derived URL."""
    from fuzzlab.labgen.identifier_sqli_assertion import build_identifier_sqli_request

    cell = _cell(manifest, "LABGEN-PL-0007")
    request = build_identifier_sqli_request(
        cell, target_base_url="http://127.0.0.1:8000", param_name="sort", column_a="name", column_b="price"
    )
    assert request.endpoint_path == "/catalog"  # the manifest's logical page...
    # ...but routes/web.php registers this cell at its own URL.
    fragment = LaravelEmitter().route_fragment_for(cell)
    assert "/cell/labgen-pl-0007" in fragment
    assert "'/catalog'" not in fragment


def test_the_adapter_rewrites_the_probe_to_the_url_laravel_actually_serves(manifest) -> None:
    from fuzzlab.labgen.emitters.php_laravel.identifier_sqli import (
        build_laravel_identifier_sqli_request,
    )

    request = build_laravel_identifier_sqli_request(
        _cell(manifest, "LABGEN-PL-0007"), target_base_url="http://127.0.0.1:8000"
    )
    assert request.endpoint_path == "/cell/labgen-pl-0007"
    # Probe metadata comes from the emitter's own page profile (PA-0001).
    assert request.param_name == _PAGE_PROFILES["/catalog"]["param_name"]
    assert (request.column_a, request.column_b) == (
        _PAGE_PROFILES["/catalog"]["column_a"],
        _PAGE_PROFILES["/catalog"]["column_b"],
    )


def test_the_adapter_keeps_every_fail_closed_refusal_of_the_shared_module(manifest) -> None:
    """The adapter delegates rather than re-implements, so the shared
    module's refusals (non-identifier family, non-query parameter, non-raw
    encoding) still apply unchanged."""
    from fuzzlab.labgen.emitters.php_laravel.identifier_sqli import (
        build_laravel_identifier_sqli_request,
    )
    from fuzzlab.labgen.identifier_sqli_assertion import IdentifierSqliAssertionError
    from fuzzlab.labgen.schema import ParamSpec

    with pytest.raises(IdentifierSqliAssertionError, match="not an identifier/alias position"):
        build_laravel_identifier_sqli_request(
            _cell(manifest, "LABGEN-PL-0001"), target_base_url="http://127.0.0.1:8000"
        )
    cookie_cell = dataclasses.replace(_cell(manifest, "LABGEN-PL-0007"), param=ParamSpec(location="cookie"))
    with pytest.raises(IdentifierSqliAssertionError, match="query-string URL only"):
        build_laravel_identifier_sqli_request(cookie_cell, target_base_url="http://127.0.0.1:8000")


def test_a_raw_laravel_identifier_cell_is_confirmed_vulnerable(manifest, matrix) -> None:
    from fuzzlab.labgen.emitters.php_laravel.identifier_sqli import (
        assert_laravel_identifier_sqli_cell,
    )

    runner = FakeHttpRunner((200, "baseline"), (200, "true-order"), (200, "false-order"))
    result = assert_laravel_identifier_sqli_cell(
        _cell(manifest, "LABGEN-PL-0007"),
        matrix,
        target_base_url="http://127.0.0.1:8000",
        runner=runner,
    )
    assert (result.derived.verdict, result.oracle.confirmed_vulnerable, result.matches) == (
        "VULNERABLE",
        True,
        True,
    )
    assert all("/cell/labgen-pl-0007" in url for url in runner.urls)


def test_an_allowlisted_laravel_identifier_cell_is_confirmed_secure(manifest, matrix) -> None:
    from fuzzlab.labgen.emitters.php_laravel.identifier_sqli import (
        assert_laravel_identifier_sqli_cell,
    )

    runner = FakeHttpRunner((200, "rows"), (200, "rows"), (200, "rows"))
    result = assert_laravel_identifier_sqli_cell(
        _cell(manifest, "LABGEN-PL-0010"),
        matrix,
        target_base_url="http://127.0.0.1:8000",
        runner=runner,
    )
    assert (result.derived.verdict, result.oracle.confirmed_secure, result.matches) == ("SECURE", True, True)


def test_a_join_alias_cell_is_probed_at_its_own_url_with_its_own_columns(manifest, matrix) -> None:
    from fuzzlab.labgen.emitters.php_laravel.identifier_sqli import (
        assert_laravel_identifier_sqli_cell,
    )

    runner = FakeHttpRunner((200, "baseline"), (200, "a"), (200, "b"))
    result = assert_laravel_identifier_sqli_cell(
        _cell(manifest, "LABGEN-PL-0011"),
        matrix,
        target_base_url="http://127.0.0.1:8000",
        runner=runner,
    )
    assert result.matches is True
    assert all("/cell/labgen-pl-0011" in url for url in runner.urls)
    assert _PAGE_PROFILES["/inventory"]["param_name"] + "=" in runner.urls[1]
