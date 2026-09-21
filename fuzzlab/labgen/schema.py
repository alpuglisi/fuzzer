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
