"""Emitter interface contract tests (T-LAB0.4).

Covers the ABC shape (`fuzzlab.labgen.emitter.Emitter`), the `EmittedFile`/
`EmittedFiles` output shape being able to represent more than one file per
cell, and the "declare unsupported and skip" contract.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.emitter import EmittedFile, Emitter
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext


def _cell(cell_id: str, vuln_class: str, sink_family: str, ops: list[str]) -> Cell:
    return Cell(
        cell_id=cell_id,
        vuln_class=vuln_class,
        stack_profile="php_current",
        route=Route(method="GET", path="/example/product.php"),
        sink_context=SinkContext(family=sink_family, required_neutralizations=("sql_syntax_break",)),
        transform=Pipeline.from_list(ops),
    )


def test_emitter_is_abstract_and_cannot_be_instantiated_directly() -> None:
    with pytest.raises(TypeError):
        Emitter()  # type: ignore[abstract]


def test_emitted_file_defaults_role_to_page() -> None:
    f = EmittedFile(path="generated/x.php", content=b"<?php\n")
    assert f.role == "page"
    assert f.path == "generated/x.php"
    assert f.content == b"<?php\n"


def test_emitted_files_can_represent_more_than_one_file_per_cell() -> None:
    # EmittedFiles = tuple[EmittedFile, ...] -- the interface must not
    # structurally assume single-file output (CR-LAB-0001 Addendum D), even
    # though php_current itself only ever returns one entry.
    files = (
        EmittedFile(path="app/Http/Controllers/XController.php", content=b"<?php\n", role="controller"),
        EmittedFile(path="resources/views/x.blade.php", content=b"<div></div>\n", role="view"),
        EmittedFile(path="routes/web.php", content=b"<?php\n", role="route"),
    )
    assert len(files) == 3
    assert {f.role for f in files} == {"controller", "view", "route"}


class _FakeEmitter(Emitter):
    """A minimal concrete Emitter used only to exercise the ABC contract
    (a real stack emitter is fuzzlab.labgen.emitters.php_current)."""

    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        return vuln_class == "sqli" and sink_context.family == "sql_numeric_literal"

    def render(self, cell: Cell):
        if not self.supports(cell.vuln_class, cell.sink_context):
            raise ValueError("unsupported")
        return (EmittedFile(path=f"{cell.cell_id}.php", content=b"<?php\n"),)


def test_supports_declares_unsupported_pairs_rather_than_erroring_on_render() -> None:
    emitter = _FakeEmitter()
    supported = _cell("C1", "sqli", "sql_numeric_literal", [])
    unsupported = _cell("C2", "xss", "html_body", ["html_entity_escape"])

    assert emitter.supports(supported.vuln_class, supported.sink_context) is True
    assert emitter.supports(unsupported.vuln_class, unsupported.sink_context) is False

    # A well-behaved caller checks supports() and skips -- it never calls
    # render() on a cell supports() rejected. render() raising here is a
    # defensive guard against a caller bug, not the intended control flow.
    with pytest.raises(ValueError):
        emitter.render(unsupported)
