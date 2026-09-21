"""Manifest schema + IR (T-LAB0.1/T-LAB0.3 foundation; T-LAB2.1 wiring).

Loads and validates a lab-generator manifest against
``lab/schemas/manifest.schema.json`` and turns it into the typed IR the
verdict engine (``fuzzlab.labgen.verdict``) consumes: :class:`Pipeline` (an
ordered transform op list, never a single enum) and :class:`SinkContext` (a
structured family + required-neutralizations object, never a bare string) —
the CR-LAB-0001 §3 generalization of the old single-enum/bare-string model.

Phase 0's manifest lists cells explicitly, one axis level each. Phase 1
(T-LAB2.1) adds an optional ``axis_ranges`` block, expanded via
``fuzzlab.labgen.resolver.expand()`` (the covertable-backed covering-array
engine, previously wired but unused — see that module's own docstring) into
concrete cells *before* :class:`Manifest` is built, so the emitter and
verdict engine downstream see the same :class:`Cell` IR either way and need
no changes of their own. A manifest with no ``axis_ranges`` (today's format)
loads byte-for-byte identically to before this was added — ``_expand_axis_ranges``
is a no-op for an empty/absent list.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from fuzzlab.labgen import resolver as _resolver

DEFAULT_MANIFEST_SCHEMA_PATH = Path("lab/schemas/manifest.schema.json")


class ManifestError(ValueError):
    """Raised when a manifest, or its schema file, is missing or invalid."""


def load_manifest_schema(path: str | Path = DEFAULT_MANIFEST_SCHEMA_PATH) -> dict[str, Any]:
    """Load the manifest JSON Schema from disk.

    ``path`` defaults to the repo-relative conventional location and is
    resolved against the current working directory, the same convention
    ``fuzzlab.labels.contract`` uses for ``lab/ground-truth`` (tests run from
    the repo root).
    """
    path = Path(path)
    if not path.is_file():
        raise ManifestError(
            f"manifest schema not found at {path!r} — pass an explicit path, "
            "or run from the repo root (e.g. 'lab/schemas/manifest.schema.json')"
        )
    return json.loads(path.read_text("utf-8"))


def validate_manifest(instance: dict[str, Any], schema: dict[str, Any] | None = None) -> None:
    """Validate a raw manifest dict against the manifest JSON Schema."""
    schema = load_manifest_schema() if schema is None else schema
    try:
        jsonschema.validate(instance, schema)
    except jsonschema.ValidationError as exc:  # pragma: no cover - message passthrough
        raise ManifestError(f"manifest: {exc.message} at {list(exc.path)}") from exc


@dataclass(frozen=True)
class SinkContext:
    """A structured sink context: a family plus the concerns a pipeline must
    fully neutralize for a cell in this context to be SECURE.

    Replaces the old bare-string ``sink_context`` (e.g. ``"sql"``) per
    CR-LAB-0001 §3.
    """

    family: str
    required_neutralizations: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SinkContext":
        return cls(
            family=data["family"],
            required_neutralizations=tuple(data.get("required_neutralizations", ())),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "required_neutralizations": list(self.required_neutralizations),
        }


@dataclass(frozen=True)
class Pipeline:
    """An ordered sequence of transform ops applied to a tainted value before
    it reaches the sink. Replaces the old single-enum ``transform`` field per
    CR-LAB-0001 §3. An empty pipeline means the raw/unmediated value.
    """

    ops: tuple[str, ...] = ()

    @classmethod
    def from_list(cls, ops: list[str]) -> "Pipeline":
        return cls(ops=tuple(ops))

    def to_list(self) -> list[str]:
        return list(self.ops)


@dataclass(frozen=True)
class Route:
    method: str
    path: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Route":
        return cls(method=data["method"], path=data["path"])

    def to_dict(self) -> dict[str, Any]:
        return {"method": self.method, "path": self.path}


@dataclass(frozen=True)
class Cell:
    """One resolved manifest cell — the typed IR the verdict engine and any
    future emitter (T-LAB0.4, out of this delivery's scope) consume."""

    cell_id: str
    vuln_class: str
    stack_profile: str
    route: Route
    sink_context: SinkContext
    transform: Pipeline
    sink_endpoint: Route | None = None
    """Where the tainted value actually reaches the sink and executes, if
    different from ``route`` (the injection point). ``None`` (the default)
    means same-endpoint -- today's entire corpus, and every existing manifest
    is unaffected by this field. Populated only for stored/second-order
    cells (e.g. a profile-bio write endpoint whose payload executes on a
    separate profile-view page). Render/tracking metadata only, like
    ``identity.py``'s data -- ``fuzzlab.labgen.verdict`` never reads it (see
    docs/LAB_IMPLEMENTATION_PLAN.md §3.3 / CC-LAB-0029)."""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Cell":
        sink_endpoint_data = data.get("sink_endpoint")
        return cls(
            cell_id=data["cell_id"],
            vuln_class=data["class"],
            stack_profile=data["stack_profile"],
            route=Route.from_dict(data["route"]),
            sink_context=SinkContext.from_dict(data["sink_context"]),
            transform=Pipeline.from_list(data.get("transform", [])),
            sink_endpoint=Route.from_dict(sink_endpoint_data) if sink_endpoint_data else None,
        )


# Axis names an axis_range's `factors` may use, and the Cell-dict field each
# one places. Kept in one place so `_expand_axis_range` and the schema's own
# `$defs/axis_range.factors.properties` list stay in lockstep — an axis name
# recognized by one and not the other is exactly the silently-wrong-
# granularity failure mode PA-0010 warns about, so both are asserted to
# agree in tests/test_labgen_schema.py.
AXIS_RANGE_FACTOR_NAMES = frozenset(
    {"class", "stack_profile", "sink_context_family", "transform", "route_method", "route_path"}
)


def _expand_axis_range(block: dict[str, Any]) -> list[dict[str, Any]]:
    """Expand one ``axis_ranges`` block into concrete cell dicts (the same
    shape ``Cell.from_dict`` already consumes), via
    ``fuzzlab.labgen.resolver.expand()``.

    Any Cell field not varied by a factor here must come from this block's
    own fixed value; a field with neither a factor nor a fixed value raises
    :class:`ManifestError` rather than silently defaulting (PA-0010) — this
    is deliberately fail-closed, matching the resolver's own "reject, don't
    swallow" convention for unrecognized/missing covering-array config.
    """
    prefix = block["cell_id_prefix"]
    factors = block["factors"]

    resolver_config: dict[str, Any] = {"factors": factors}
    for key in ("strength", "sub_models", "constraints"):
        if key in block:
            resolver_config[key] = block[key]

    try:
        rows = _resolver.expand(resolver_config)
    except _resolver.CoveringArrayError as exc:
        raise ManifestError(f"axis_ranges block {prefix!r}: {exc}") from exc

    fixed_route = block.get("route") or {}
    neutral_map = block.get("sink_context_neutralizations")

    cells: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        cls = row.get("class", block.get("class"))
        if cls is None:
            raise ManifestError(
                f"axis_ranges block {prefix!r}: 'class' is neither a factor nor a fixed value"
            )

        stack_profile = row.get("stack_profile", block.get("stack_profile"))
        if stack_profile is None:
            raise ManifestError(
                f"axis_ranges block {prefix!r}: 'stack_profile' is neither a factor nor a fixed value"
            )

        method = row.get("route_method", fixed_route.get("method"))
        path = row.get("route_path", fixed_route.get("path"))
        if not method or not path:
            raise ManifestError(
                f"axis_ranges block {prefix!r}: route method/path is neither a factor nor a fixed value"
            )

        family = row.get("sink_context_family")
        if family is not None:
            if not neutral_map or family not in neutral_map:
                raise ManifestError(
                    f"axis_ranges block {prefix!r}: no sink_context_neutralizations entry for "
                    f"sink_context_family {family!r} (required whenever that axis is a factor)"
                )
            sink_context = {"family": family, "required_neutralizations": neutral_map[family]}
        else:
            sink_context = block.get("sink_context")
            if sink_context is None:
                raise ManifestError(
                    f"axis_ranges block {prefix!r}: 'sink_context' is neither a factor "
                    "(sink_context_family) nor a fixed value"
                )

        transform = row.get("transform", block.get("transform", []))

        cells.append(
            {
                "cell_id": f"{prefix}{index:04d}",
                "class": cls,
                "stack_profile": stack_profile,
                "route": {"method": method, "path": path},
                "sink_context": sink_context,
                "transform": transform,
            }
        )
    return cells


def _expand_axis_ranges(axis_ranges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Expand every ``axis_ranges`` block, in manifest order. Empty/absent
    input returns ``[]`` — the no-op case that keeps an axis-range-less
    manifest's loaded result byte-for-byte unchanged."""
    generated: list[dict[str, Any]] = []
    for block in axis_ranges:
        generated.extend(_expand_axis_range(block))
    return generated


@dataclass(frozen=True)
class Manifest:
    manifest_version: int
    safety_matrix_version: int
    cells: tuple[Cell, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, validate: bool = True) -> "Manifest":
        if validate:
            validate_manifest(data)
        all_cells = list(data.get("cells", [])) + _expand_axis_ranges(data.get("axis_ranges", []))
        cell_ids = [c["cell_id"] for c in all_cells]
        dupes = {cid for cid in cell_ids if cell_ids.count(cid) > 1}
        if dupes:
            raise ManifestError(f"duplicate cell_id(s) in manifest: {sorted(dupes)}")
        return cls(
            manifest_version=data["manifest_version"],
            safety_matrix_version=data["safety_matrix_version"],
            cells=tuple(Cell.from_dict(c) for c in all_cells),
        )


def load_manifest(path: str | Path, *, schema_path: str | Path | None = None) -> Manifest:
    """Load a manifest from a YAML or JSON file and validate + resolve it."""
    path = Path(path)
    if not path.is_file():
        raise ManifestError(f"manifest not found at {path!r}")
    raw = yaml.safe_load(path.read_text("utf-8"))
    schema = load_manifest_schema(schema_path) if schema_path is not None else None
    if schema is None:
        validate_manifest(raw)
    else:
        validate_manifest(raw, schema)
    return Manifest.from_dict(raw, validate=False)
