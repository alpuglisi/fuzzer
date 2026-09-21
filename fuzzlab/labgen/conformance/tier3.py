"""Tier 3 -- whole-lab regeneration (T-LAB0.7).

The one tier this task can fully exercise offline: two full regenerations
of a real emitter's output for a set of cells, byte-diffed. Mirrors
``fuzzlab.labgen.gates.regenerate_and_diff`` (which proves this property
for the Phase-0 *scaffold* renderer,
``fuzzlab.labgen.subseed.render_cell_stub``) but drives a real
:class:`~fuzzlab.labgen.emitter.Emitter` (e.g. ``php_current``) instead,
over :data:`~fuzzlab.labgen.emitter.EmittedFiles` rather than the
scaffold's single-JSON-per-cell shape. This is a separate, emitter-level
Tier-3 check -- not a modification of ``gates.py`` (a sibling lane's file)
-- consistent with T-LAB0.7's own framing of Tier 3 as a distinct tier from
T-LAB0.5's determinism gate.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from fuzzlab.labgen.emitter import Emitter
from fuzzlab.labgen.schema import Cell


class RegenerateDiffError(AssertionError):
    """Raised when two full regenerations of the same cells via the same
    emitter disagree (violates NFR-LAB-reproducible)."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def render_whole_sample(emitter: Emitter, cells: Iterable[Cell]) -> dict[str, bytes]:
    """Render every cell in ``cells`` that ``emitter`` supports, keyed by
    output path. Unsupported cells are skipped -- the same declare-
    unsupported-and-skip rule :class:`~fuzzlab.labgen.emitter.Emitter`
    itself documents, not an error.
    """
    tree: dict[str, bytes] = {}
    for cell in cells:
        if not emitter.supports(cell.vuln_class, cell.sink_context):
            continue
        for emitted in emitter.render(cell):
            if emitted.path in tree:
                raise RegenerateDiffError(
                    f"two cells emitted the same path {emitted.path!r} -- "
                    "whole-lab regeneration requires unique output paths"
                )
            tree[emitted.path] = emitted.content
    return tree


def regenerate_and_diff_emitter(emitter: Emitter, cells: Iterable[Cell]) -> None:
    """Render ``cells`` via ``emitter`` twice and assert byte-identical
    output across the whole tree (Tier 3). Raises
    :class:`RegenerateDiffError` naming the first differing (or missing)
    file on failure.
    """
    cells = list(cells)
    first = render_whole_sample(emitter, cells)
    second = render_whole_sample(emitter, cells)
    if first.keys() != second.keys():
        raise RegenerateDiffError(
            f"file set differs between two whole-sample regenerations: "
            f"{sorted(first.keys())} vs {sorted(second.keys())}"
        )
    for path in sorted(first):
        if first[path] != second[path]:
            raise RegenerateDiffError(
                f"{path}: output differs between two regenerations of the same cells "
                f"(before sha256={_sha256(first[path])}, after sha256={_sha256(second[path])})"
            )
