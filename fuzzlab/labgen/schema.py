"""Manifest schema + IR (T-LAB0.1/T-LAB0.3 foundation).

Loads and validates a lab-generator manifest against
``lab/schemas/manifest.schema.json`` and turns it into the typed IR the
verdict engine (``fuzzlab.labgen.verdict``) consumes: :class:`Pipeline` (an
ordered transform op list, never a single enum) and :class:`SinkContext` (a
structured family + required-neutralizations object, never a bare string) —
the CR-LAB-0001 §3 generalization of the old single-enum/bare-string model.

This module is a thin resolver, not the full covering-array machinery
(T-LAB0.3): Phase 0's manifest lists cells explicitly, one axis level each,
and this loader does no expansion — it is intentionally "dormant" per
``docs/LAB_PHASE_0_PLAN.md``'s own phrasing for that task.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml

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
    param: ParamSpec = ParamSpec()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Cell":
        return cls(
            cell_id=data["cell_id"],
            vuln_class=data["class"],
            stack_profile=data["stack_profile"],
            route=Route.from_dict(data["route"]),
            sink_context=SinkContext.from_dict(data["sink_context"]),
            transform=Pipeline.from_list(data.get("transform", [])),
            param=ParamSpec.from_dict(data.get("param")),
        )


@dataclass(frozen=True)
class Manifest:
    manifest_version: int
    safety_matrix_version: int
    cells: tuple[Cell, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, validate: bool = True) -> "Manifest":
        if validate:
            validate_manifest(data)
        cell_ids = [c["cell_id"] for c in data["cells"]]
        dupes = {cid for cid in cell_ids if cell_ids.count(cid) > 1}
        if dupes:
            raise ManifestError(f"duplicate cell_id(s) in manifest: {sorted(dupes)}")
        return cls(
            manifest_version=data["manifest_version"],
            safety_matrix_version=data["safety_matrix_version"],
            cells=tuple(Cell.from_dict(c) for c in data["cells"]),
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
