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
    # Multi-artifact ground truth (CR-LAB-0001 Addendum B / T-LAB0.9). A cell's
    # ground truth stays one row/case even when it spans more than one
    # endpoint (Juliet/SARIF "one primary location, N related locations"
    # shape): ``primary_endpoint``/``primary_role`` name the location where
    # the untrusted value reaches the dangerous operation (the tie-break rule
    # is always "where it's used", never "where it's set"), and
    # ``related_endpoints`` carries the rest as ``{"endpoint": ..., "role":
    # ...}`` mappings (role one of source|propagator|sanitizer|sink).
    # ``flow_variant`` names how far the flow travels, per Juliet's naming.
    # All four are additive metadata: every case predating this field set
    # defaults to a single direct location, and no scorer/consumer logic
    # changes based on them (see docs/bugs and CR-LAB-0001 Addendum B).
    primary_endpoint: str | None = None
    primary_role: str | None = None
    related_endpoints: tuple[dict, ...] = ()
    flow_variant: str = "direct"
    # Which stack profile this case's code was generated for / hand-written in
    # (CR-LAB-0001 §4's `stack_profile` naming; `fuzzlab.labgen.schema.Cell`'s
    # field of the same meaning). Inline here, per the settled research
    # decision in docs/LAB_IMPLEMENTATION_PLAN.md §4 ("prior art uniformly
    # inlines this kind of metadata" -- OWASP Benchmark's expectedresults.csv,
    # CrossVul/CVEfixes/DiverseVul/ICVul) rather than in a separate
    # analysis-only file. Optional and additive: a case predating multi-stack
    # ground truth carries None, and no scorer/consumer keys on it -- it is
    # analysis metadata (what the fingerprint-independence gate,
    # `fuzzlab.labgen.fingerprint_gate`, consumes as a record's `stack`), not
    # part of `key`/matching.
    stack: str | None = None
    #: Another origin of the lab this case lives on (FR-LAB-308); None: the lab's base.
    #: Not part of `key`: scoring matches paths, and `load` refuses a path that two
    #: origins of one ground truth share.
    origin: str | None = None

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
    #: A JSON body the app sends to this endpoint, ``param`` naming one of its leaves
    #: (`core.jsonbody.display_name`): the point is then a JSON-leaf point whose probes
    #: carry the other leaves too (FR-FUZZ-54). None for any other point.
    json_body: dict | None = None
    #: Another origin of the lab this point lives on (FR-LAB-308); None: the lab's base.
    origin: str | None = None
    #: The point's value is this value of the run's own account (FR-LAB-309): stored by
    #: the lab's bootstrap with the credential, read by `fuzzlab auto --identity`.
    account_value: str | None = None

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
            primary_endpoint=c.get("primary_endpoint"),
            primary_role=c.get("primary_role"),
            related_endpoints=tuple(c.get("related_endpoints", ())),
            flow_variant=c.get("flow_variant", "direct"),
            stack=c.get("stack"), origin=c.get("origin"),
        )
        for c in data["cases"]
    ]
    ids = [c.case_id for c in cases]
    if len(ids) != len(set(ids)):
        raise ContractError("duplicate case_id in labels.json")
    for case in cases:
        _check_path_template(path, case)
    return cases


def _check_path_template(path, item) -> None:
    """A ``path`` point or case names its parameter as one whole segment of its URL
    (``/ticket/{id}``, FR-FUZZ-57); scoring matches findings by that template path."""
    if item.location != "path":
        return
    from fuzzlab.core.urls import PathPlacementError, place_path_param
    try:
        place_path_param(item.url, item.param, "x")
    except PathPlacementError as exc:
        raise ContractError(f"{path}: {item.method} {item.url} {item.param!r}: a path "
                            f"parameter must be one segment of its url: {exc}") from exc


def load_injection_points(ground_truth_dir: str | Path) -> list[InjectionPoint]:
    path = Path(ground_truth_dir) / "injection-points.json"
    data = json.loads(path.read_text("utf-8"))
    _validate(data, "injection-points.schema.json")
    points = [
        InjectionPoint(
            url=p["url"], method=p["method"], param=p["param"], location=p["location"],
            rendering=p.get("rendering"), client_only=bool(p.get("client_only", False)),
            json_body=p.get("json_body"), origin=p.get("origin"),
            account_value=p.get("account_value"),
        )
        for p in data["points"]
    ]
    from fuzzlab.core import jsonbody
    for pt in points:
        _check_path_template(path, pt)
        if pt.json_body is None:
            continue
        leaves = jsonbody.leaves(pt.json_body)
        if leaves is None or pt.param not in {jsonbody.display_name(p) for p, _v in leaves}:
            raise ContractError(f"{path}: point {pt.method} {pt.url} {pt.param!r}: its "
                                f"json_body has no such leaf (or is not a JSON object)")
    return points


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

    _check_origins(cases, points)
    return GroundTruth(target=labels_data["target"], cases=cases, points=points)


def _check_origins(cases, points) -> None:
    """FR-LAB-308: another origin is a loopback origin (a ground truth never directs
    traffic off the machine), a stored case's absolute ``source_url`` is one too, and no
    path is used on two origins (scoring matches findings by path)."""
    from urllib.parse import urlsplit

    from fuzzlab.core.net import is_loopback_host

    def loopback(url: str, what: str) -> None:
        host = urlsplit(url).hostname or ""
        if not is_loopback_host(host):
            raise ContractError(f"{what} {url!r} is not a loopback origin")
    seen: dict[str, str | None] = {}
    for item in [*cases, *points]:
        if item.origin is not None:
            loopback(item.origin, "origin")
        path = item.url if item.url.startswith("/") else "/" + item.url
        if path in seen and seen[path] != item.origin:
            raise ContractError(f"path {path} is used on two origins ({seen[path]!r}, "
                                f"{item.origin!r}): scoring matches by path")
        seen[path] = item.origin
    for case in cases:
        if case.source_url and "://" in case.source_url:
            loopback(case.source_url, "source_url")
