"""Tier 0 (lint + minimal-pair diff) tests (T-LAB0.7).

`lint_php`/`lint_emitted_files` are exercised for real (php -l, skip-guarded
per PA-0005's pattern). `fuzzlab.labgen.minimal_pair` (the real, sibling-owned
checker) has since landed, so `get_minimal_pair_checker()` now always prefers
it over the naive fallback in this branch -- the naive-fallback tests below
exercise `_naive_minimal_pair_check` directly rather than through
`get_minimal_pair_checker`, so they keep testing the fallback's own behavior
regardless of which checker `get_minimal_pair_checker` currently resolves to.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.tier0 import (
    _naive_minimal_pair_check,
    get_minimal_pair_checker,
    lint_emitted_files,
    lint_php,
    lint_python,
    php_available,
    python_available,
)
from fuzzlab.labgen.emitter import EmittedFile
from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.minimal_pair import check_minimal_pair
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext

_VULNERABLE_CELL = Cell(
    cell_id="LABGEN-EX-0001",
    vuln_class="sqli",
    stack_profile="php_current",
    route=Route(method="GET", path="/example/product.php"),
    sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
    transform=Pipeline.from_list([]),
)
_SECURE_TWIN_CELL = Cell(
    cell_id="LABGEN-EX-0002",
    vuln_class="sqli",
    stack_profile="php_current",
    route=Route(method="GET", path="/example/product.php"),
    sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
    transform=Pipeline.from_list(["param_bind"]),
)


@pytest.mark.skipif(not php_available(), reason="php CLI not available on this build host (PA-0005 pattern)")
def test_lint_php_passes_on_real_emitted_output() -> None:
    emitter = PhpCurrentEmitter()
    files = emitter.render(_VULNERABLE_CELL)
    results = lint_emitted_files(files)
    assert results
    assert all(r.ok for r in results)


@pytest.mark.skipif(not php_available(), reason="php CLI not available on this build host (PA-0005 pattern)")
def test_lint_php_fails_on_deliberately_broken_php() -> None:
    result = lint_php("broken.php", b"<?php\nif (true) {\n")  # unclosed brace
    assert result.ok is False


def test_lint_php_without_php_cli_raises_rather_than_false_passing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("fuzzlab.labgen.conformance.tier0.shutil.which", lambda _name: None)
    with pytest.raises(RuntimeError):
        lint_php("x.php", b"<?php\n")


def test_naive_minimal_pair_check_confirms_a_real_vulnerable_secure_pair() -> None:
    emitter = PhpCurrentEmitter()
    result = _naive_minimal_pair_check(emitter.render(_VULNERABLE_CELL), emitter.render(_SECURE_TWIN_CELL))
    assert result.is_minimal_pair is True
    assert result.differing_paths  # at least the one page file differs


def test_naive_minimal_pair_check_rejects_a_mismatched_file_count() -> None:
    vulnerable = (EmittedFile(path="a.php", content=b"<?php\n"),)
    secure = (
        EmittedFile(path="a.php", content=b"<?php\n"),
        EmittedFile(path="b.php", content=b"<?php\n"),
    )
    result = _naive_minimal_pair_check(vulnerable, secure)
    assert result.is_minimal_pair is False


def test_naive_minimal_pair_check_compares_positionally_not_by_path() -> None:
    # php_current names its one output file per cell_id, not per page, so a
    # vulnerable cell and its secure twin have two different paths by
    # construction -- the naive checker must still recognize this as a
    # valid pair (same count, differing content), not reject it for having
    # different paths.
    vulnerable = (EmittedFile(path="generated/cell-a.php", content=b"<?php\n// vulnerable\n"),)
    secure = (EmittedFile(path="generated/cell-b.php", content=b"<?php\n// secure\n"),)
    result = _naive_minimal_pair_check(vulnerable, secure)
    assert result.is_minimal_pair is True


def test_naive_minimal_pair_check_rejects_byte_identical_twins() -> None:
    same = (EmittedFile(path="a.php", content=b"<?php\necho 1;\n"),)
    result = _naive_minimal_pair_check(same, same)
    assert result.is_minimal_pair is False


@pytest.mark.skipif(not python_available(), reason="python interpreter not available on this build host (PA-0005)")
def test_lint_python_passes_on_valid_python_source() -> None:
    result = lint_python("x.py", b"def f():\n    return 1\n")
    assert result.ok is True


@pytest.mark.skipif(not python_available(), reason="python interpreter not available on this build host (PA-0005)")
def test_lint_python_fails_on_deliberately_broken_python() -> None:
    result = lint_python("broken.py", b"def f(:\n    return 1\n")  # syntax error
    assert result.ok is False


def test_lint_python_without_interpreter_raises_rather_than_false_passing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("fuzzlab.labgen.conformance.tier0.shutil.which", lambda _name: None)
    with pytest.raises(RuntimeError):
        lint_python("x.py", b"pass\n")


def test_get_minimal_pair_checker_prefers_the_real_sibling_module_now_that_it_has_landed() -> None:
    # fuzzlab.labgen.minimal_pair (owned by a sibling lane) has since landed
    # in this branch, so get_minimal_pair_checker() must resolve to its real
    # check_minimal_pair -- never the naive fallback above -- with no change
    # needed at any call site, per this module's own docstring guarantee.
    checker = get_minimal_pair_checker()
    assert checker is check_minimal_pair
