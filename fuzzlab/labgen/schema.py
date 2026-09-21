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


#: Allowed values for `ParamSpec.location`/`.encoding` (§3.4, L-P2.4). Kept as
#: plain validated strings, not an importable enum shared with
#: `fuzzlab.labgen.oracle_wrapper`: that module is deliberately independent of
#: any manifest/schema type (see its module docstring), so this schema owns
#: its own copy of the allowed vocabulary rather than creating a coupling
#: that module explicitly disclaims.
PARAM_LOCATIONS = ("query", "body", "header", "cookie", "json")
PARAM_ENCODINGS = ("raw", "url_encoded", "double_url_encoded", "base64")


@dataclass(frozen=True)
class ParamSpec:
    """Where the injection parameter lives and how its value is encoded on
    the wire (§3.4, L-P2.4).

    Deliberately a `Cell`-level field, not folded into `SinkContext`:
    `SinkContext` (family + `required_neutralizations`) is the
    verdict-derivation contract -- what a pipeline must neutralize for a
    cell to be SECURE, consumed directly by `fuzzlab.labgen.verdict`.
    Parameter location/encoding never changes that contract -- the same
    `(transform, sink_context)` pair still derives the same verdict whether
    the tainted value arrived via a raw query string or a base64-encoded
    cookie. It changes only how the cell is *rendered into a request* and
    how the build-time oracle must construct its confirmation request --
    render/tracking metadata, the same category the plan's §3.3 (a proposed
    `sink_endpoint` field, lane L-P2.3, separately tracked) is framed as, not
    a verdict input.
    """

    location: str = "query"
    encoding: str = "raw"

    def __post_init__(self) -> None:
        if self.location not in PARAM_LOCATIONS:
            raise ManifestError(
                f"param.location must be one of {PARAM_LOCATIONS}, got {self.location!r}"
            )
        if self.encoding not in PARAM_ENCODINGS:
            raise ManifestError(
                f"param.encoding must be one of {PARAM_ENCODINGS}, got {self.encoding!r}"
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ParamSpec":
        if data is None:
            return cls()
        return cls(
            location=data.get("location", "query"),
            encoding=data.get("encoding", "raw"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"location": self.location, "encoding": self.encoding}


#: Context-depth levels a manifest may actually declare today (§3.5, L-P2.5) --
#: how far the tainted value travels from the injection point to the sink.
#: These four are the *reachable* subset of the five names CR-LAB-0001
#: Addendum B gave the ground-truth `Case.flow_variant` field: the vocabulary
#: is deliberately identical in both directions (`context_depth` *declares*
#: the depth to generate at; `flow_variant` *records* the depth a case was
#: generated at), so `flow_variant_for()` below is a pure identity mapping
#: rather than a translation table that could drift.
CONTEXT_DEPTHS = ("direct", "same_file_helper", "cross_file", "stored_second_order")

#: Depth levels Addendum B names for `Case.flow_variant` but which no manifest
#: can be generated at yet. `cross_service` needs real ≥2-service wiring (one
#: service's sink reached through another service's request path); Phase 3's
#: multiple stack emitters are a necessary but not sufficient condition for it,
#: so declaring it must fail loud rather than render something meaningless
#: (docs/LAB_IMPLEMENTATION_PLAN.md §3.5, which scopes this lane to the four
#: reachable values).
UNREACHABLE_CONTEXT_DEPTHS = ("cross_service",)

DEFAULT_CONTEXT_DEPTH = "direct"


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
    docs/LAB_IMPLEMENTATION_PLAN.md §3.3 / CC-LAB-0038)."""
    param: ParamSpec = ParamSpec()
    context_depth: str = DEFAULT_CONTEXT_DEPTH
    """How far the tainted value travels from the injection point to the sink
    -- one of :data:`CONTEXT_DEPTHS` (§3.5, L-P2.5). The generator-input
    counterpart of the ground-truth ``Case.flow_variant`` field (L-P0.9): this
    *declares* the depth to generate at, ``flow_variant`` *records* the depth a
    case was generated at, and :func:`flow_variant_for` is the one shared
    function that maps one to the other (PA-0003/PA-0021).

    ``"direct"`` (the default) means source and sink in the same function --
    today's entire corpus, so every pre-existing manifest keeps its exact
    meaning. Not a verdict input: a depth hop is a pure pass-through of the
    tainted value and neutralizes nothing, so ``fuzzlab.labgen.verdict`` never
    reads this field, exactly like ``sink_endpoint``/``param``.

    ``"stored_second_order"`` is, by definition, precisely the case where the
    payload executes on a *different* endpoint than the one it was submitted
    to, which is what ``sink_endpoint`` already expresses -- so the two fields
    are kept biconditionally consistent (see :meth:`__post_init__`) rather than
    duplicating each other's purpose: ``context_depth`` names the flow shape,
    ``sink_endpoint`` names the second endpoint that shape requires."""

    def __post_init__(self) -> None:
        if self.context_depth in UNREACHABLE_CONTEXT_DEPTHS:
            raise ManifestError(
                f"{self.cell_id}: context_depth {self.context_depth!r} is a known depth level "
                "but is not reachable by any emitter yet (it needs real cross-service wiring, "
                "which having several single-service stack emitters does not provide) -- "
                f"declare one of {CONTEXT_DEPTHS} instead "
                "(docs/LAB_IMPLEMENTATION_PLAN.md §3.5)"
            )
        if self.context_depth not in CONTEXT_DEPTHS:
            raise ManifestError(
                f"{self.cell_id}: context_depth must be one of {CONTEXT_DEPTHS}, "
                f"got {self.context_depth!r}"
            )
        # `stored_second_order` <=> `sink_endpoint` differs from `route`. Both
        # directions are enforced so the IR can never carry a half-declared
        # second-order cell (a depth with no second endpoint to reach, or a
        # second endpoint with no flow shape that explains it).
        if self.context_depth == "stored_second_order":
            if self.sink_endpoint is None:
                raise ManifestError(
                    f"{self.cell_id}: context_depth 'stored_second_order' requires a "
                    "sink_endpoint distinct from route -- that is exactly what makes a cell "
                    "second-order (the payload is submitted to one endpoint and executes on "
                    "another)"
                )
            if self.sink_endpoint == self.route:
                raise ManifestError(
                    f"{self.cell_id}: context_depth 'stored_second_order' requires "
                    f"sink_endpoint != route, but both are {self.route!r}"
                )
        elif self.sink_endpoint is not None:
            raise ManifestError(
                f"{self.cell_id}: sink_endpoint is set (a payload that executes on a "
                f"different endpoint) but context_depth is {self.context_depth!r} -- a cell "
                "with a distinct sink_endpoint is a 'stored_second_order' cell by definition; "
                "omit context_depth to have it derived, or declare it explicitly"
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Cell":
        sink_endpoint_data = data.get("sink_endpoint")
        # An omitted `context_depth` is *derived*, not blindly defaulted: a
        # cell that declares a distinct `sink_endpoint` is a second-order cell
        # by definition, so pre-existing stored/second-order manifests and
        # fixtures (written before this axis existed) stay valid and mean what
        # they always meant.
        context_depth = data.get("context_depth") or (
            "stored_second_order" if sink_endpoint_data else DEFAULT_CONTEXT_DEPTH
        )
        return cls(
            cell_id=data["cell_id"],
            vuln_class=data["class"],
            stack_profile=data["stack_profile"],
            route=Route.from_dict(data["route"]),
            sink_context=SinkContext.from_dict(data["sink_context"]),
            transform=Pipeline.from_list(data.get("transform", [])),
            sink_endpoint=Route.from_dict(sink_endpoint_data) if sink_endpoint_data else None,
            param=ParamSpec.from_dict(data.get("param")),
            context_depth=context_depth,
        )


def flow_variant_for(cell: Cell) -> str:
    """The ground-truth ``Case.flow_variant`` value a cell generated at this
    ``context_depth`` must be labelled with (§3.5, L-P2.5).

    The one shared place this mapping lives (PA-0003/PA-0021), so the
    generator-input axis and the ground-truth label can never drift apart. It
    is an identity mapping *by construction*: :data:`CONTEXT_DEPTHS` is
    deliberately the same vocabulary Addendum B gave ``flow_variant`` (a test
    asserts every level here is accepted by
    ``fuzzlab/labels/schemas/labels.schema.json``'s own ``flow_variant`` enum,
    rather than restating that enum here, per PA-0001).

    **Not yet called by any production path, and deliberately so:** no
    Cell-to-GroundTruth converter exists in this codebase today --
    ``fuzzlab.labgen.cli.run_checks`` records that gap explicitly as
    ``# TODO(L-P0.9-integration)`` (see FR-LAB-32's own "two things this CLI
    still does not do"), and building a whole ground-truth emission pipeline
    speculatively is out of §3.5's scope. This function exists so that the
    converter, when it is built, has exactly one obvious call to make instead
    of re-deriving the mapping locally.
    """
    if cell.context_depth not in CONTEXT_DEPTHS:  # pragma: no cover - __post_init__ guards
        raise ManifestError(f"{cell.cell_id}: unknown context_depth {cell.context_depth!r}")
    return cell.context_depth


# Axis names an axis_range's `factors` may use, and the Cell-dict field each
# one places. Kept in one place so `_expand_axis_range` and the schema's own
# `$defs/axis_range.factors.properties` list stay in lockstep — an axis name
# recognized by one and not the other is exactly the silently-wrong-
# granularity failure mode PA-0010 warns about, so both are asserted to
# agree in tests/test_labgen_schema.py.
AXIS_RANGE_FACTOR_NAMES = frozenset(
    {
        "class",
        "stack_profile",
        "sink_context_family",
        "transform",
        "route_method",
        "route_path",
        "context_depth",
    }
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

    # A fixed `sink_endpoint` on a block is only meaningful for a
    # `stored_second_order` level; declared without one it would be silently
    # dropped from every generated cell, which is exactly the
    # silently-ignored-config failure mode PA-0010 warns about. Checked before
    # expansion, so the error names the real authoring mistake.
    depth_levels = list(factors.get("context_depth") or ())
    if block.get("context_depth") is not None:
        depth_levels.append(block["context_depth"])
    if block.get("sink_endpoint") is not None and "stored_second_order" not in depth_levels:
        raise ManifestError(
            f"axis_ranges block {prefix!r}: a fixed 'sink_endpoint' is only used by a "
            "'stored_second_order' context_depth level, which this block never produces"
        )

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

        cell: dict[str, Any] = {
            "cell_id": f"{prefix}{index:04d}",
            "class": cls,
            "stack_profile": stack_profile,
            "route": {"method": method, "path": path},
            "sink_context": sink_context,
            "transform": transform,
        }

        # `context_depth` (§3.5) may be a factor or this block's fixed value;
        # absent from both, it is simply omitted and `Cell.from_dict` derives
        # it, so an axis-range block written before this axis existed expands
        # byte-for-byte as before. A `stored_second_order` level additionally
        # needs the block's fixed `sink_endpoint` (the axis itself cannot
        # invent a second endpoint); Cell.__post_init__ fails loud if it is
        # missing, and it is carried here whenever the block declares one.
        context_depth = row.get("context_depth", block.get("context_depth"))
        if context_depth is not None:
            cell["context_depth"] = context_depth
        fixed_sink_endpoint = block.get("sink_endpoint")
        if fixed_sink_endpoint is not None and context_depth == "stored_second_order":
            cell["sink_endpoint"] = fixed_sink_endpoint

        cells.append(cell)
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
