"""Ground-truth label contract: loader, schema validation, consistency checks.

The contract is read out-of-band from disk (never served by the target) and is
the single source of truth the integration harness scores against (D9/D10).
Three files live together in a ground-truth directory:

- ``labels.json``          — per-case verdicts (opaque case IDs).
- ``expectedresults.csv``  — Benchmark-style mirror of the verdicts.
- ``injection-points.json``— parameter-discovery ground truth.

The loader validates each file against its JSON Schema and cross-checks
``labels.json`` against ``expectedresults.csv`` so the two cannot silently drift.
Case IDs are opaque (no vulnerability class in the ID) so a tool under evaluation
cannot read the answer from the ID.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema

_SCHEMA_PKG = "fuzzlab.labels.schemas"


class ContractError(ValueError):
    """Raised when a ground-truth file is invalid or inconsistent."""


def _load_schema(name: str) -> dict[str, Any]:
    return json.loads(resources.files(_SCHEMA_PKG).joinpath(name).read_text("utf-8"))


def _validate(instance: Any, schema_name: str) -> None:
    try:
        jsonschema.validate(instance, _load_schema(schema_name))
    except jsonschema.ValidationError as exc:  # pragma: no cover - message passthrough
        raise ContractError(f"{schema_name}: {exc.message} at {list(exc.path)}") from exc


@dataclass(frozen=True)
class Case:
    case_id: str
    url: str
    method: str
    param: str
    location: str
    vuln_class: str
    sink_context: str
    expected_vulnerable: bool
    rendering: str
    subtypes: tuple[str, ...] = ()
    source_url: str | None = None
    notes: str | None = None

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Identity used to match a tool's result to this case."""
        return (self.url, self.method, self.param, self.vuln_class)


@dataclass(frozen=True)
class InjectionPoint:
    url: str
    method: str
    param: str
    location: str
    rendering: str | None = None
    client_only: bool = False

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.url, self.method, self.param)


@dataclass
class GroundTruth:
    target: str
    cases: list[Case] = field(default_factory=list)
    points: list[InjectionPoint] = field(default_factory=list)

    def positives(self) -> list[Case]:
        return [c for c in self.cases if c.expected_vulnerable]

    def negatives(self) -> list[Case]:
        return [c for c in self.cases if not c.expected_vulnerable]

    def case_by_id(self, case_id: str) -> Case | None:
        return next((c for c in self.cases if c.case_id == case_id), None)


def load_labels(ground_truth_dir: str | Path) -> list[Case]:
    path = Path(ground_truth_dir) / "labels.json"
    data = json.loads(path.read_text("utf-8"))
    _validate(data, "labels.schema.json")
    cases = [
        Case(
            case_id=c["case_id"], url=c["url"], method=c["method"], param=c["param"],
            location=c["location"], vuln_class=c["vuln_class"],
            sink_context=c["sink_context"],
            expected_vulnerable=bool(c["expected_vulnerable"]),
            rendering=c["rendering"], subtypes=tuple(c.get("subtypes", ())),
            source_url=c.get("source_url"), notes=c.get("notes"),
        )
        for c in data["cases"]
    ]
    ids = [c.case_id for c in cases]
    if len(ids) != len(set(ids)):
        raise ContractError("duplicate case_id in labels.json")
    return cases


def load_injection_points(ground_truth_dir: str | Path) -> list[InjectionPoint]:
    path = Path(ground_truth_dir) / "injection-points.json"
    data = json.loads(path.read_text("utf-8"))
    _validate(data, "injection-points.schema.json")
    return [
        InjectionPoint(
            url=p["url"], method=p["method"], param=p["param"], location=p["location"],
            rendering=p.get("rendering"), client_only=bool(p.get("client_only", False)),
        )
        for p in data["points"]
    ]


def _load_expected_csv(ground_truth_dir: str | Path) -> dict[str, bool]:
    path = Path(ground_truth_dir) / "expectedresults.csv"
    out: dict[str, bool] = {}
    with path.open(encoding="utf-8") as fh:
        rows = (line for line in fh if not line.lstrip().startswith("#"))
        for row in csv.DictReader(rows):
            out[row["case_id"]] = row["expected_vulnerable"].strip().lower() == "true"
    return out


def load(ground_truth_dir: str | Path) -> GroundTruth:
    """Load and validate all three files, cross-checking labels vs expected CSV."""
    gt_dir = Path(ground_truth_dir)
    if not (gt_dir / "labels.json").is_file():
        raise ContractError(
            f"ground-truth directory not found or incomplete: {gt_dir} "
            f"(expected {gt_dir / 'labels.json'}). Pass a path relative to your current "
            f"directory — e.g. 'lab/ground-truth' from the repo root, or 'ground-truth' "
            f"from inside lab/ — or an absolute path."
        )
    labels_data = json.loads((gt_dir / "labels.json").read_text("utf-8"))
    cases = load_labels(gt_dir)
    points = load_injection_points(gt_dir)

    expected = _load_expected_csv(gt_dir)
    label_map = {c.case_id: c.expected_vulnerable for c in cases}
    if set(expected) != set(label_map):
        missing = set(label_map) - set(expected)
        extra = set(expected) - set(label_map)
        raise ContractError(
            f"labels.json and expectedresults.csv case sets differ "
            f"(missing from csv: {sorted(missing)}; extra in csv: {sorted(extra)})"
        )
    for case_id, verdict in label_map.items():
        if expected[case_id] != verdict:
            raise ContractError(
                f"verdict mismatch for {case_id}: labels={verdict} csv={expected[case_id]}"
            )

    return GroundTruth(target=labels_data["target"], cases=cases, points=points)
