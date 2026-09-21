"""Sub-seed derivation + canonical serialization (T-LAB0.5 scaffold).

A minimal, correct scaffold — not a fully-general generator. Its job is to
be sufficient for the regenerate-and-diff CI gate
(``fuzzlab.labgen.gates.regenerate_and_diff``) to actually exercise
determinism: derive a sub-seed deterministically from a cell's identity,
serialize a cell's rendering canonically, and prove two runs from the same
manifest+seed are byte-identical.

``render_cell_stub`` is explicitly **not** the real per-stack emitter
(T-LAB0.4, module-composition per NIST VTSG's schema — out of scope for this
delivery). It exists only to give the determinism gate something real to
regenerate and diff.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from .schema import Cell
from .verdict import SafetyMatrix, verdict as compute_verdict


def derive_subseed(
    root_seed: str | bytes,
    cell_id: str,
    *,
    transform: tuple[str, ...] = (),
    sink_family: str = "",
    stack_profile: str = "",
) -> str:
    """Deterministically derive a per-cell sub-seed:
    ``HMAC-SHA256(root_seed, cell_id || transform || sink_family || stack_profile)``.

    Using the cell's identity *and* its transform/sink/stack axes (not just
    ``cell_id``) means two cells that happen to share an ID prefix across
    manifest revisions but differ in shape never collide, and the same cell
    always derives the same sub-seed for the same root seed regardless of
    process, host, or call order (NFR-LAB-reproducible).
    """
    key = root_seed.encode("utf-8") if isinstance(root_seed, str) else root_seed
    material = "\x1f".join([cell_id, ",".join(transform), sink_family, stack_profile])
    return hmac.new(key, material.encode("utf-8"), hashlib.sha256).hexdigest()


def _assert_no_floats(obj: Any, path: str = "$") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            _assert_no_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _assert_no_floats(v, f"{path}[{i}]")
    elif isinstance(obj, float):
        raise ValueError(f"canonical_json: float not allowed in label-contract-style output at {path}")


def canonical_json(obj: Any) -> bytes:
    """Canonical JSON serialization for generated/label-contract-style
    output: sorted keys, compact separators, no floats, a single trailing
    newline, stdlib ``json`` only (no third-party formatter — see
    ``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.5's "no formatter inside the
    generator" rule). Two calls with an equal ``obj`` are byte-identical.
    """
    _assert_no_floats(obj)
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return (text + "\n").encode("utf-8")


def render_cell_stub(cell: Cell, matrix: SafetyMatrix, root_seed: str) -> bytes:
    """Minimal, deterministic rendering of one cell, sufficient to exercise
    the regenerate-and-diff gate. NOT the real emitter (T-LAB0.4)."""
    v = compute_verdict(cell.transform, cell.sink_context, matrix)
    subseed = derive_subseed(
        root_seed,
        cell.cell_id,
        transform=cell.transform.ops,
        sink_family=cell.sink_context.family,
        stack_profile=cell.stack_profile,
    )
    payload = {
        "cell_id": cell.cell_id,
        "stack_profile": cell.stack_profile,
        "route": cell.route.to_dict(),
        "sink_context": cell.sink_context.to_dict(),
        "transform": cell.transform.to_list(),
        "subseed": subseed,
        "verdict": v.to_dict(),
    }
    return canonical_json(payload)
