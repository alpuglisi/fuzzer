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
