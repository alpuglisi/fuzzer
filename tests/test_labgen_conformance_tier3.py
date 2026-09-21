"""Tier 3 (whole-lab regeneration) tests (T-LAB0.7).

Fully real and offline: renders both the illustrative and the real-page
sample manifests twice via `php_current` and asserts byte-identical output
across the whole tree, plus failure-mode tests (a mismatched path set, a
deliberately non-deterministic emitter).
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.tier3 import RegenerateDiffError, regenerate_and_diff_emitter, render_whole_sample
from fuzzlab.labgen.emitter import EmittedFile, Emitter
from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext, load_manifest


def test_regenerate_and_diff_emitter_passes_for_the_illustrative_manifest() -> None:
    manifest = load_manifest("lab/manifests/example_phase0_scaffold.yaml")
    emitter = PhpCurrentEmitter()
    # Should not raise.
    regenerate_and_diff_emitter(emitter, manifest.cells)


def test_regenerate_and_diff_emitter_passes_for_the_real_page_sample_manifest() -> None:
    manifest = load_manifest("lab/manifests/phase0_real_pages_sample.yaml")
    emitter = PhpCurrentEmitter()
    regenerate_and_diff_emitter(emitter, manifest.cells)


def test_render_whole_sample_skips_unsupported_cells_rather_than_erroring() -> None:
    supported_cell = Cell(
        cell_id="LABGEN-RP-0001",
        vuln_class="sqli",
        stack_profile="php_current",
        route=Route(method="GET", path="/product.php"),
        sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
        transform=Pipeline.from_list([]),
    )
    unsupported_cell = Cell(
        cell_id="LABGEN-UNSUPPORTED-0001",
        vuln_class="ssrf",
        stack_profile="php_current",
        route=Route(method="GET", path="/somewhere.php"),
        sink_context=SinkContext(family="network_egress", required_neutralizations=("allowlist",)),
        transform=Pipeline.from_list([]),
    )
    tree = render_whole_sample(PhpCurrentEmitter(), [supported_cell, unsupported_cell])
    assert len(tree) == 1
    assert "labgen-rp-0001" in next(iter(tree))


def test_render_whole_sample_raises_on_a_colliding_output_path() -> None:
    class _CollidingEmitter(Emitter):
        def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:  # noqa: ARG002
            return True

        def render(self, cell: Cell):  # noqa: ARG002
            return (EmittedFile(path="same.php", content=b"<?php\n"),)

    cell_a = Cell(
        cell_id="A",
        vuln_class="sqli",
        stack_profile="php_current",
        route=Route(method="GET", path="/a.php"),
        sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
        transform=Pipeline.from_list([]),
    )
    cell_b = Cell(
        cell_id="B",
        vuln_class="sqli",
        stack_profile="php_current",
        route=Route(method="GET", path="/b.php"),
        sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
        transform=Pipeline.from_list([]),
    )
    with pytest.raises(RegenerateDiffError):
        render_whole_sample(_CollidingEmitter(), [cell_a, cell_b])


def test_regenerate_and_diff_emitter_raises_on_a_non_deterministic_emitter() -> None:
    call_count = {"n": 0}

    class _FlakyEmitter(Emitter):
        def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:  # noqa: ARG002
            return True

        def render(self, cell: Cell):  # noqa: ARG002
            call_count["n"] += 1
            # Differs on every call -- simulates a real determinism bug.
            return (EmittedFile(path="x.php", content=f"<?php // {call_count['n']}\n".encode()),)

    cell = Cell(
        cell_id="A",
        vuln_class="sqli",
        stack_profile="php_current",
        route=Route(method="GET", path="/a.php"),
        sink_context=SinkContext(family="sql_numeric_literal", required_neutralizations=("sql_syntax_break",)),
        transform=Pipeline.from_list([]),
    )
    with pytest.raises(RegenerateDiffError):
        regenerate_and_diff_emitter(_FlakyEmitter(), [cell])
