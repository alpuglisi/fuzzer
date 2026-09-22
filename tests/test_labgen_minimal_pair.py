"""Tests for the minimal-pair invariant checker (fuzzlab/labgen/minimal_pair.py).

The positive fixture is a *real* vulnerable/secure pair produced by the
actual `php_current` emitter: one `Cell`, rendered twice with only its
`transform` field swapped (`dataclasses.replace`), so "the same cell" (per
the task brief's own framing) is genuinely the same identity -- same
cell_id, same route, same sink_context -- and only the declared transform
differs. This is what makes the pair a legitimate minimal pair to begin
with; two independently-numbered manifest cells (e.g. the example
scaffold's LABGEN-EX-0001/0002) are NOT used here because they carry
different cell_ids and would therefore *legitimately* emit different
handler names under php_current's own cell_id-derived naming -- a
different concern (manifest-level twin pairing) this Phase-0-pulled-forward
checker does not attempt to solve.
"""

from __future__ import annotations

import dataclasses

import pytest

from fuzzlab.labgen.emitter import EmittedFile
from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.minimal_pair import (
    MinimalPairError,
    MinimalPairViolation,
    check_identifier_stability,
    check_minimal_pair,
)
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext

EMITTER = PhpCurrentEmitter()


def _base_cell(**overrides) -> Cell:
    defaults = dict(
        cell_id="LABGEN-MP-TEST-0001",
        vuln_class="sqli",
        stack_profile="php_current",
        route=Route(method="GET", path="/example/product.php"),
        sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
        transform=Pipeline(()),
    )
    defaults.update(overrides)
    return Cell(**defaults)


@pytest.fixture()
def real_pair():
    """A real vulnerable/secure pair from php_current: same cell identity,
    transform toggled between empty (vulnerable) and `param_bind` (secure)."""
    vulnerable_cell = _base_cell(transform=Pipeline(()))
    secure_cell = dataclasses.replace(vulnerable_cell, transform=Pipeline(("param_bind",)))
    return EMITTER.render(vulnerable_cell), EMITTER.render(secure_cell)


# ---------------------------------------------------------------------------
# Positive case: the real php_current pair passes
# ---------------------------------------------------------------------------


def test_real_php_current_pair_passes(real_pair):
    vulnerable, secure = real_pair
    check_minimal_pair(vulnerable, secure)  # must not raise


def test_real_pair_actually_differs_in_content(real_pair):
    """Sanity check the fixture itself is meaningful -- not a trivial
    identical-content pass."""
    vulnerable, secure = real_pair
    assert vulnerable[0].content != secure[0].content
    assert b"param_bind" not in vulnerable[0].content
    assert b"param_bind" in secure[0].content


def test_identical_pair_passes_trivially(real_pair):
    vulnerable, _ = real_pair
    check_minimal_pair(vulnerable, vulnerable)


# ---------------------------------------------------------------------------
# Negative cases: hand-constructed violations
# ---------------------------------------------------------------------------


def test_file_set_mismatch_raises(real_pair):
    vulnerable, secure = real_pair
    extra = secure + (EmittedFile(path="generated/extra.php", content=b"<?php\n", role="page"),)
    with pytest.raises(MinimalPairViolation, match="file sets differ"):
        check_minimal_pair(vulnerable, extra)


def test_role_mismatch_raises(real_pair):
    vulnerable, secure = real_pair
    retagged = tuple(dataclasses.replace(f, role="route") for f in secure)
    with pytest.raises(MinimalPairViolation, match="role differs"):
        check_minimal_pair(vulnerable, retagged)


def test_missing_composition_comment_raises_error_not_violation(real_pair):
    vulnerable, secure = real_pair
    stripped = tuple(
        dataclasses.replace(f, content=b"\n".join(
            line for line in f.content.split(b"\n") if not line.startswith(b"// Module composition:")
        ))
        for f in secure
    )
    # This is "can't tell" (no composition line to parse), not "found a
    # problem" -- must be the base MinimalPairError, not the Violation
    # subtype, and the message must say why.
    with pytest.raises(MinimalPairError) as excinfo:
        check_minimal_pair(vulnerable, stripped)
    assert not isinstance(excinfo.value, MinimalPairViolation)
    assert "Module composition" in str(excinfo.value)


def test_unrelated_identifier_rename_with_no_composition_change_is_caught(real_pair):
    """The Juliet-style failure mode: someone renames an unrelated variable
    (not a transform/sink change at all) and the composition line doesn't
    even change -- this must be caught, not waved through as "small diff"."""
    vulnerable, _ = real_pair
    renamed = tuple(
        dataclasses.replace(f, content=f.content.replace(b"$id", b"$identifier"))
        for f in vulnerable
    )
    with pytest.raises(MinimalPairViolation, match="differ outside any declared transform/sink change"):
        check_minimal_pair(vulnerable, renamed)


def test_handler_name_mismatch_is_caught_as_identifier_violation(real_pair):
    vulnerable, secure = real_pair
    renamed_secure = tuple(
        dataclasses.replace(f, content=f.content.replace(b"handle_labgen_mp_test_0001", b"handle_renamed_helper"))
        for f in secure
    )
    with pytest.raises(MinimalPairViolation, match="function/handler identifier"):
        check_minimal_pair(vulnerable, renamed_secure)


def test_composition_length_mismatch_raises_error(real_pair):
    vulnerable, secure = real_pair
    longer = tuple(
        dataclasses.replace(
            f,
            content=f.content.replace(
                b"// Module composition: get_param -> param_bind -> sql_numeric_lookup -> single_statement",
                b"// Module composition: get_param -> param_bind -> param_bind -> sql_numeric_lookup -> single_statement",
            ),
        )
        for f in secure
    )
    with pytest.raises(MinimalPairError, match="different lengths"):
        check_minimal_pair(vulnerable, longer)


def test_unknown_module_name_in_composition_raises_error(real_pair):
    vulnerable, secure = real_pair
    bogus = tuple(
        dataclasses.replace(
            f,
            content=f.content.replace(b"get_param ->", b"totally_unregistered_module ->"),
        )
        for f in secure
    )
    with pytest.raises(MinimalPairError, match="not registered"):
        check_minimal_pair(vulnerable, bogus)


def test_restricting_variable_categories_still_allows_same_name_sink(real_pair):
    """Restricting the declared-variable set to {"transform"} only: the
    sink module's own branch-driven content difference is still fine here
    because its NAME is identical in both variants (both use
    "sql_numeric_lookup") -- the composition-level check only fires on a
    NAME difference at a non-declared-variable position, and content-level
    confinement is separately satisfied since the differing content is
    still contiguous with the transform region."""
    vulnerable, secure = real_pair
    check_minimal_pair(vulnerable, secure, variable_categories=frozenset({"transform"}))


def test_disallowed_sink_name_swap_raises_when_sink_not_declared_variable(real_pair):
    vulnerable, secure = real_pair
    # A hypothetical secure twin whose composition names a *different*,
    # still-registered module at the sink position (only the composition
    # comment changes -- the sink template's own rendered code never
    # contains its own module name, so this isolates the composition-name
    # check from the content-confinement check). With "sink" excluded from
    # the declared-variable set, this must be rejected.
    swapped = tuple(
        dataclasses.replace(f, content=f.content.replace(b"sql_numeric_lookup", b"get_param"))
        for f in secure
    )
    with pytest.raises(MinimalPairViolation, match="composition position"):
        check_minimal_pair(vulnerable, swapped, variable_categories=frozenset({"transform"}))


def test_content_diff_reported_when_no_composition_difference_exists():
    error = None
    vulnerable_text = (
        "<?php\n"
        "// Module composition: get_param -> identity -> sql_numeric_lookup -> single_statement\n"
        "function handle_x(PDO $pdo) {\n"
        "    $id = isset($_GET['id']) ? $_GET['id'] : null;\n"
        "    // identity transform: $id passed through unmodified (no pipeline ops)\n"
        "    $sql = \"SELECT * FROM products WHERE id = \" . $id;\n"
        "    $result = $pdo->query($sql);\n"
        "    $row = $result ? $result->fetch(PDO::FETCH_ASSOC) : null;\n"
        "    return $row;\n"
        "}\n"
    )
    secure_text = vulnerable_text.replace("FROM products", "FROM widgets")  # unrelated content change
    vuln = (EmittedFile(path="p.php", content=vulnerable_text.encode(), role="page"),)
    sec = (EmittedFile(path="p.php", content=secure_text.encode(), role="page"),)
    with pytest.raises(MinimalPairViolation) as excinfo:
        check_minimal_pair(vuln, sec)
    assert "differ outside any declared transform/sink change" in str(excinfo.value)


# ---------------------------------------------------------------------------
# check_identifier_stability() directly
# ---------------------------------------------------------------------------


def test_check_identifier_stability_passes_for_equal_names():
    check_identifier_stability("function foo(PDO $pdo) {}", "function foo(PDO $pdo) {}")


def test_check_identifier_stability_raises_for_different_names():
    with pytest.raises(MinimalPairViolation, match="function/handler identifier"):
        check_identifier_stability("function foo(PDO $pdo) {}", "function bar(PDO $pdo) {}")


def test_check_identifier_stability_label_included_in_message():
    with pytest.raises(MinimalPairViolation, match=r"^generated/x\.php: "):
        check_identifier_stability("function foo() {}", "function bar() {}", label="generated/x.php")


# ---------------------------------------------------------------------------
# `pair_by`: two independently-authored, differently-pathed cells
# (CC-LAB-0055/FR-LAB-53, closing the gap lane L-P3.3c-G3 worked around --
# see docs/bugs/BUG-0029-*.md).
# ---------------------------------------------------------------------------


@pytest.fixture()
def two_named_cells():
    """Two *distinct* authored cells, rendered to two distinct file paths --
    exactly the shape G3's `LABGEN-PLA-0001`/`LABGEN-PLA-0002`
    (`login.php`/its secure twin) is: two manifest cells the caller's own
    authoring convention has already established as a pair by construction,
    not "one cell rendered twice" (`real_pair`, above). Hand-built (like
    `test_content_diff_reported_when_no_composition_difference_exists`
    below) rather than run through `PhpCurrentEmitter`, so this fixture
    isolates exactly the capability under test -- path-independent pairing
    -- without also dragging in `PhpCurrentEmitter`'s own cell_id-derived
    provenance comment and handler name, which legitimately differ between
    any two distinct cell_ids (see `check_identifier_stability`'s docstring)
    and are exercised by their own, separate fixtures/tests already."""
    vulnerable_text = (
        "<?php\n"
        "// Module composition: get_param -> identity -> sql_numeric_lookup -> single_statement\n"
        "function handle_the_pair(PDO $pdo) {\n"
        "    $id = isset($_GET['id']) ? $_GET['id'] : null;\n"
        "    $sql = \"SELECT * FROM products WHERE id = \" . $id;\n"
        "    $result = $pdo->query($sql);\n"
        "    $row = $result ? $result->fetch(PDO::FETCH_ASSOC) : null;\n"
        "    return $row;\n"
        "}\n"
    )
    secure_text = (
        "<?php\n"
        "// Module composition: get_param -> param_bind -> sql_numeric_lookup -> single_statement\n"
        "function handle_the_pair(PDO $pdo) {\n"
        "    $id = isset($_GET['id']) ? $_GET['id'] : null;\n"
        '    $stmt = $pdo->prepare("SELECT * FROM products WHERE id = ?");\n'
        "    $stmt->execute([$id]);\n"
        "    $row = $stmt->fetch(PDO::FETCH_ASSOC);\n"
        "    return $row;\n"
        "}\n"
    )
    vulnerable = (EmittedFile(path="generated/login.php", content=vulnerable_text.encode(), role="page"),)
    secure = (EmittedFile(path="generated/login.secure-twin.php", content=secure_text.encode(), role="page"),)
    return vulnerable, secure


def test_default_pairing_still_rejects_two_differently_pathed_cells(two_named_cells):
    """Backward compatibility: with `pair_by` omitted, strict path pairing
    is unchanged -- two distinct cell_ids render to two distinct paths, so
    this must still fail exactly as it always has."""
    vulnerable, secure = two_named_cells
    assert vulnerable[0].path != secure[0].path
    with pytest.raises(MinimalPairViolation, match="file sets differ"):
        check_minimal_pair(vulnerable, secure)


def test_pair_by_lets_two_differently_pathed_cells_be_compared(two_named_cells):
    """The new capability: an explicit `pair_by` normalizes cell identity
    (here, by role -- both are the lone `role="page"` file each renders) so
    a manifest-authored vulnerable/secure pair with two distinct paths is
    checked directly, without needing "each cell against its own weakened
    self" as G3's test file had to."""
    vulnerable, secure = two_named_cells
    check_minimal_pair(vulnerable, secure, pair_by=lambda f: f.role)  # must not raise


def test_pair_by_still_reports_a_real_violation(two_named_cells):
    """`pair_by` changes how files are matched, not what is then checked --
    an actual violation between the paired files must still raise."""
    vulnerable, secure = two_named_cells
    renamed_secure = tuple(
        dataclasses.replace(f, content=f.content.replace(b"handle_the_pair", b"handle_something_else"))
        for f in secure
    )
    with pytest.raises(MinimalPairViolation, match="function/handler identifier"):
        check_minimal_pair(vulnerable, renamed_secure, pair_by=lambda f: f.role)


def test_pair_by_ambiguous_mapping_raises_setup_error(two_named_cells):
    """A `pair_by` that maps two files on the same side to the same key is
    a caller bug, not a finding -- `MinimalPairError`, not a `Violation`."""
    vulnerable, secure = two_named_cells
    doubled_vulnerable = vulnerable + (dataclasses.replace(vulnerable[0], path="generated/extra-copy.php"),)
    with pytest.raises(MinimalPairError) as excinfo:
        check_minimal_pair(doubled_vulnerable, secure, pair_by=lambda f: f.role)
    assert not isinstance(excinfo.value, MinimalPairViolation)
    assert "ambiguous" in str(excinfo.value) or "more than one" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Content confinement between compositions that differ by name -- the
# common vulnerable/secure case (CC-LAB-0055/FR-LAB-53). Before this fix,
# any composition-name difference (e.g. `identity` -> `param_bind`) fully
# disabled the content-confinement check for the whole file; a twin could
# rewrite anything else and still pass. See docs/bugs/BUG-0029-*.md.
# ---------------------------------------------------------------------------


def test_a_real_transform_rename_alone_still_passes(real_pair):
    """Sanity check for the fixtures used below: the *real*, legitimate
    php_current pair (transform toggled, nothing else touched) must still
    pass -- the new check must not turn a real positive into a false one."""
    vulnerable, secure = real_pair
    check_minimal_pair(vulnerable, secure)  # must not raise


def test_unrelated_rewrite_before_the_transform_region_now_caught(real_pair):
    """The concrete gap this fix closes: `secure`'s composition already
    legitimately differs from `vulnerable`'s (`identity` -> `param_bind`,
    a real declared difference at a variable-category position), which
    used to disable content-confinement checking for the *entire* file.
    Here `secure` *also* rewrites its source line -- `$_GET` to `$_POST`,
    unrelated to the declared transform difference and structurally
    *before* the transform region (php_current's `render()` concatenates
    source, then transform, then sink) -- a change no declared difference
    covers. Before this fix this passed silently; now it must not."""
    vulnerable, secure = real_pair
    assert b"// param_bind transform:" in secure[0].content
    tampered = tuple(
        dataclasses.replace(f, content=f.content.replace(b"$_GET['id']", b"$_POST['id']"))
        for f in secure
    )
    # Confirm the tamper actually lands before the transform's own marker
    # line, i.e. this is genuinely testing the *leading*-region gap, not
    # accidentally landing inside the already-checked transform/sink band.
    text = tampered[0].content.decode()
    assert text.index("$_POST['id']") < text.index("// param_bind transform:")
    with pytest.raises(MinimalPairViolation, match="differ before the declared transform/sink region"):
        check_minimal_pair(vulnerable, tampered)


def test_content_confinement_runs_even_when_variable_categories_is_narrowed(real_pair):
    """The new check is independent of `variable_categories`'s value --
    even when the caller narrows it (excluding "sink", as one test above
    already does for the composition-name check), a leading-region rewrite
    must still be caught."""
    vulnerable, secure = real_pair
    tampered = tuple(
        dataclasses.replace(f, content=f.content.replace(b"$_GET['id']", b"$_POST['id']"))
        for f in secure
    )
    with pytest.raises(MinimalPairViolation, match="differ before the declared transform/sink region"):
        check_minimal_pair(vulnerable, tampered, variable_categories=frozenset({"transform"}))
