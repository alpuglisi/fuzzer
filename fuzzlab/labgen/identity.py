"""Identity/ownership graph schema + loader (Phase 2, CR-LAB-0001 §8, L-P2.1).

Loads and validates ``lab/identities/identities.yaml`` against
``lab/schemas/identities.schema.json`` and turns it into a typed
:class:`IdentityGraph`: named test identities, the resources they own, and
the ``authz_expectations`` that connect an accessing identity to a target
resource and a binary expected outcome (``allowed`` | ``denied``, D20's
binary-verdict convention).

This is genuinely novel schema ground for this project — no external
prior-art project (crAPI, vAPI, AuthProbe) declares "identity X owns
resource Y" as static, hand-authored data; see
``docs/LAB_IMPLEMENTATION_PLAN.md`` §3.1 for the research this schema is
built from.

**Decoupling (do not weaken):** this module is deliberately decoupled from
the manifest/``Cell`` IR the verdict engine consumes, the same way
``lab/patterns/provenance.yaml`` is decoupled from manifest cells
(``CR-LAB-0001`` Addendum A, ``fuzzlab.labgen.schema``'s own docstring).
``fuzzlab.labgen.verdict`` must never import this module or read this
file's content — ownership/authz-expectation metadata is annotation feeding
future test classes and audit tooling, not an input the verdict engine
needs. ``tests/test_labgen_identity.py`` asserts this module's name never
appears in ``verdict.py``'s source.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

DEFAULT_IDENTITIES_SCHEMA_PATH = Path("lab/schemas/identities.schema.json")
DEFAULT_IDENTITIES_PATH = Path("lab/identities/identities.yaml")


class IdentityGraphError(ValueError):
    """Raised when the identity graph file, or its schema, is missing or invalid."""


def load_identities_schema(
    path: str | Path = DEFAULT_IDENTITIES_SCHEMA_PATH,
) -> dict[str, Any]:
    """Load the identity-graph JSON Schema from disk.

    ``path`` defaults to the repo-relative conventional location and is
    resolved against the current working directory, the same convention
    ``fuzzlab.labgen.schema.load_manifest_schema`` uses (tests run from the
    repo root).
    """
    path = Path(path)
    if not path.is_file():
        raise IdentityGraphError(
            f"identities schema not found at {path!r} — pass an explicit path, "
            "or run from the repo root (e.g. 'lab/schemas/identities.schema.json')"
        )
    return json.loads(path.read_text("utf-8"))


def validate_identities(instance: dict[str, Any], schema: dict[str, Any] | None = None) -> None:
    """Validate a raw identity-graph dict against the identities JSON Schema."""
    schema = load_identities_schema() if schema is None else schema
    try:
        jsonschema.validate(instance, schema)
    except jsonschema.ValidationError as exc:  # pragma: no cover - message passthrough
        raise IdentityGraphError(f"identities: {exc.message} at {list(exc.path)}") from exc


@dataclass(frozen=True)
class Identity:
    id: str
    role: str


@dataclass(frozen=True)
class Resource:
    resource_id: str
    owner: str
    cell_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthzExpectation:
    cell_id: str
    endpoint: str
    accessing_identity: str
    target_resource: str
    expected_outcome: str  # "allowed" | "denied"


@dataclass
class IdentityGraph:
    """The whole identity/ownership graph, plus lookup helpers.

    Mirrors ``fuzzlab.labels.contract.GroundTruth``'s shape: a flat list per
    record type plus ``*_by_id``-style lookup helpers, rather than nested
    dicts, so a caller can iterate or look up interchangeably.
    """

    schema_version: int
    identities: list[Identity] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    authz_expectations: list[AuthzExpectation] = field(default_factory=list)

    def identity_by_id(self, identity_id: str) -> Identity | None:
        return next((i for i in self.identities if i.id == identity_id), None)

    def resource_by_id(self, resource_id: str) -> Resource | None:
        return next((r for r in self.resources if r.resource_id == resource_id), None)

    def expectations_for_cell(self, cell_id: str) -> list[AuthzExpectation]:
        return [e for e in self.authz_expectations if e.cell_id == cell_id]


def load_identities(path: str | Path = DEFAULT_IDENTITIES_PATH) -> IdentityGraph:
    """Load, schema-validate, and cross-check ``identities.yaml`` into an
    :class:`IdentityGraph`.

    Raises :class:`IdentityGraphError` for anything wrong with the file —
    missing file, schema violation, duplicate IDs, or a dangling reference
    (``resources[].owner``, ``authz_expectations[].accessing_identity``,
    ``authz_expectations[].target_resource``) — never a raw
    ``KeyError``/``jsonschema.ValidationError``/``yaml`` error.
    """
    path = Path(path)
    if not path.is_file():
        raise IdentityGraphError(
            f"identities file not found at {path!r} — pass an explicit path, "
            "or run from the repo root (e.g. 'lab/identities/identities.yaml')"
        )
    try:
        data = yaml.safe_load(path.read_text("utf-8"))
    except yaml.YAMLError as exc:
        raise IdentityGraphError(f"identities: invalid YAML in {path}: {exc}") from exc

    validate_identities(data)

    identities = [Identity(id=i["id"], role=i["role"]) for i in data["identities"]]
    ids = [i.id for i in identities]
    if len(ids) != len(set(ids)):
        raise IdentityGraphError(f"duplicate identities[].id in {path}")

    resources = [
        Resource(
            resource_id=r["resource_id"],
            owner=r["owner"],
            cell_ids=tuple(r.get("cell_ids", ())),
        )
        for r in data["resources"]
    ]
    resource_ids = [r.resource_id for r in resources]
    if len(resource_ids) != len(set(resource_ids)):
        raise IdentityGraphError(f"duplicate resources[].resource_id in {path}")

    id_set = set(ids)
    resource_id_set = set(resource_ids)
    for r in resources:
        if r.owner not in id_set:
            raise IdentityGraphError(
                f"resource {r.resource_id!r} has unknown owner {r.owner!r} in {path}"
            )

    authz_expectations = [
        AuthzExpectation(
            cell_id=e["cell_id"],
            endpoint=e["endpoint"],
            accessing_identity=e["accessing_identity"],
            target_resource=e["target_resource"],
            expected_outcome=e["expected_outcome"],
        )
        for e in data["authz_expectations"]
    ]
    for e in authz_expectations:
        if e.accessing_identity not in id_set:
            raise IdentityGraphError(
                f"authz_expectations[{e.cell_id!r}] has unknown "
                f"accessing_identity {e.accessing_identity!r} in {path}"
            )
        if e.target_resource not in resource_id_set:
            raise IdentityGraphError(
                f"authz_expectations[{e.cell_id!r}] has unknown "
                f"target_resource {e.target_resource!r} in {path}"
            )

    return IdentityGraph(
        schema_version=data["schema_version"],
        identities=identities,
        resources=resources,
        authz_expectations=authz_expectations,
    )
