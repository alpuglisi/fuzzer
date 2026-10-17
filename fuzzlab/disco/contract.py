"""The execution contract (``contract_version: "1.0"``): what the runner may send.

A contract names its target and scope, its auth profiles, the endpoints (from a disco
inventory) and the test cases (from Phase 2, or written by hand), and receives the
runner's ``results``. It is YAML or JSON. `load_contract` is the one reader: the
schema (`CONTRACT_SCHEMA`) and then the semantic checks below, every failure a typed
`ContractError` (PA-0021: a missing file, bad YAML, a schema or reference error alike).

**Semantic checks** (before anything is sent, PA-0079):
- ids are unique; every test case, setup step and state check names a defined
  endpoint, and every auth profile it uses is defined;
- the target's ``base_url`` is inside ``scope_allowlist`` (`scope_origins`: an entry is
  a URL, or a ``host:port`` admitting both schemes on that port);
- every ``{{var}}`` a request uses is extracted by an earlier setup step of its case;
- a test case's literals never name another host: a string holding ``://`` must be in
  scope (Phase 2's "never introduce new hosts", held for hand-written contracts too);
- an auth profile ``ref`` names a secret's *location* (``keyring:<identity>``,
  ``env:<NAME>``, a storage-state file), never the secret (D12).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from fuzzlab.core.urls import canonical_origin, in_origin_scope, origin_scope

CONTRACT_VERSION = "1.0"
CLASSES = ("type", "boundary", "structural", "syntax", "logic", "injection")
STATUS_CLASSES = ("1xx", "2xx", "3xx", "4xx", "5xx")
AUTH_KINDS = ("none", "storage_state", "bearer", "basic", "cookie", "header")
VERDICTS = ("pass", "finding", "error", "skipped")
#: ``{{name}}`` in a request value.
VAR = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]{0,63})\s*\}\}")
_URLISH = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]{1,15}://[^\s\"'<>]{1,2048}")

_STR_MAP = {"type": "object", "additionalProperties": {"type": ["string", "number",
                                                                   "integer", "boolean"]}}
_FINDING = {
    "type": "object",
    "minProperties": 1, "maxProperties": 1,
    "properties": {
        "status_class": {"enum": list(STATUS_CLASSES)},
        "status_in": {"type": "array", "items": {"type": "integer"}},
        "body_matches": {"type": "array", "items": {"type": "string", "maxLength": 200},
                         "maxItems": 10},
        "latency_ms_gt": {"type": "integer", "minimum": 1},
        "response_schema_drift": {"type": "boolean"},
        "state_check": {
            "type": "object", "required": ["call", "assert_jsonpath"],
            "properties": {"call": {"type": "string"}, "path_params": _STR_MAP,
                           "query": _STR_MAP, "auth_profile": {"type": "string"},
                           "assert_jsonpath": {"type": "string", "maxLength": 300}},
            "additionalProperties": False},
    },
    "additionalProperties": False,
}
_STEP = {
    "type": "object", "required": ["call"],
    "properties": {"call": {"type": "string"}, "auth_profile": {"type": "string"},
                   "path_params": _STR_MAP, "query": _STR_MAP, "headers": _STR_MAP,
                   "body": {}, "extract": {"type": "object",
                                           "additionalProperties": {"type": "string"}}},
    "additionalProperties": False,
}
TEST_CASE_SCHEMA = {
    "type": "object",
    "required": ["id", "endpoint", "class", "request", "oracle", "safety"],
    "properties": {
        "id": {"type": "string", "pattern": r"^[A-Za-z0-9_.\-]{1,80}$"},
        "endpoint": {"type": "string"},
        "class": {"enum": list(CLASSES)},
        "rationale": {"type": "string", "maxLength": 400},
        "auth_profile": {"type": "string"},
        "setup": {"type": "array", "items": _STEP, "maxItems": 10},
        "request": {
            "type": "object",
            "properties": {"path_params": _STR_MAP, "query": _STR_MAP, "headers": _STR_MAP,
                           "body": {}, "raw_body": {"type": ["string", "null"]},
                           "content_type_override": {"type": ["string", "null"]}},
            "additionalProperties": False},
        "oracle": {
            "type": "object",
            "properties": {"expect_status_class": {"type": "array",
                                                   "items": {"enum": list(STATUS_CLASSES)}},
                           "findings_if": {"type": "array", "items": _FINDING,
                                           "maxItems": 12}},
            "additionalProperties": False},
        "safety": {
            "type": "object", "required": ["destructive"],
            "properties": {"destructive": {"type": "boolean"},
                           "idempotent": {"type": "boolean"}},
            "additionalProperties": False},
    },
    "additionalProperties": False,
}
CONTRACT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["contract_version", "run", "auth_profiles", "endpoints", "test_cases"],
    "properties": {
        "contract_version": {"const": CONTRACT_VERSION},
        "run": {
            "type": "object", "required": ["id", "target"],
            "properties": {
                "id": {"type": "string", "pattern": r"^[A-Za-z0-9_.\-]{1,80}$"},
                "target": {"type": "object", "required": ["base_url", "scope_allowlist"],
                           "properties": {"base_url": {"type": "string"},
                                          "scope_allowlist": {"type": "array", "minItems": 1,
                                                              "items": {"type": "string"}}},
                           "additionalProperties": False},
                "limits": {"type": "object",
                           "properties": {"rps": {"type": "number", "exclusiveMinimum": 0,
                                                  "maximum": 1000},
                                          "timeout_ms": {"type": "integer", "minimum": 100,
                                                         "maximum": 600000},
                                          "max_body_bytes": {"type": "integer", "minimum": 1,
                                                             "maximum": 64 * 1024 * 1024}},
                           "additionalProperties": False},
                "reset_hook": {"type": ["string", "null"]},
            },
            "additionalProperties": False},
        "auth_profiles": {
            "type": "array", "minItems": 1,
            "items": {"type": "object", "required": ["id", "kind"],
                      "properties": {"id": {"type": "string"},
                                     "kind": {"enum": list(AUTH_KINDS)},
                                     "ref": {"type": "string"},
                                     "refresh": {"type": "object"}},
                      "additionalProperties": False}},
        "endpoints": {
            "type": "array",
            "items": {"type": "object", "required": ["id", "method", "path"],
                      "properties": {"id": {"type": "string"},
                                     "method": {"type": "string",
                                                "pattern": r"^[A-Z]{3,10}$"},
                                     "path": {"type": "string", "pattern": r"^/"},
                                     "origin": {"type": "string"},
                                     "content_type": {"type": ["string", "null"]},
                                     "path_params": {"type": "object"},
                                     "query_params": {"type": "object"},
                                     "request_schema": {}, "response_schema": {},
                                     "headers": {"type": "object",
                                                 "additionalProperties": {"type": "string"}},
                                     "auth": {"enum": ["required", "optional", "none"]},
                                     "provenance": {"type": "object"}},
                      "additionalProperties": False}},
        "test_cases": {"type": "array", "items": TEST_CASE_SCHEMA},
        "results": {"type": "array"},
    },
    "additionalProperties": False,
}

DEFAULT_LIMITS = {"rps": 10, "timeout_ms": 10000, "max_body_bytes": 1048576}


class ContractError(ValueError):
    """The contract cannot be used: unreadable, invalid, or unsafe. Never names a
    secret."""


def scope_origins(allowlist: list[str]) -> frozenset[str]:
    """The canonical origins a scope allowlist admits: a URL entry its origin, a
    ``host:port`` entry that port under both schemes."""
    urls = []
    for entry in allowlist:
        entry = str(entry).strip()
        if "://" in entry:
            urls.append(entry)
        elif entry:
            urls += [f"http://{entry}/", f"https://{entry}/"]
    return origin_scope(*urls)


@dataclass
class Contract:
    doc: dict
    path: Path | None = None

    @property
    def run_id(self) -> str:
        return self.doc["run"]["id"]

    @property
    def base_url(self) -> str:
        return self.doc["run"]["target"]["base_url"]

    @property
    def allowed_origins(self) -> frozenset[str]:
        return scope_origins(self.doc["run"]["target"]["scope_allowlist"])

    @property
    def limits(self) -> dict:
        return {**DEFAULT_LIMITS, **(self.doc["run"].get("limits") or {})}

    def endpoint(self, eid: str) -> dict:
        return self._endpoints[eid]

    def profile(self, pid: str) -> dict:
        return self._profiles[pid]

    def __post_init__(self) -> None:
        self._endpoints = {e["id"]: e for e in self.doc["endpoints"]}
        self._profiles = {p["id"]: p for p in self.doc["auth_profiles"]}


def _strings(value, depth: int = 0):
    if depth > 32:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v, depth + 1)


def foreign_urls(value, origins: frozenset[str]) -> list[str]:
    """URLs inside ``value``'s strings that are outside ``origins``."""
    out = []
    for text in _strings(value):
        for m in _URLISH.finditer(text):
            url = m.group(0)
            if url.lower().startswith(("http://", "https://", "ws://", "wss://")) \
                    and not in_origin_scope(url, origins):
                out.append(url)
    return out


def case_problems(case: dict, endpoints: set[str], profiles: set[str],
                  origins: frozenset[str]) -> list[str]:
    """Semantic problems of one test case (shared with Phase 2's validation)."""
    probs = []
    if case.get("endpoint") not in endpoints:
        probs.append(f"unknown endpoint {case.get('endpoint')!r}")
    for pid in [case.get("auth_profile")] + [s.get("auth_profile") for s in
                                             case.get("setup") or []]:
        if pid is not None and pid not in profiles:
            probs.append(f"unknown auth profile {pid!r}")
    defined: set[str] = set()
    for step in case.get("setup") or []:
        if step.get("call") not in endpoints:
            probs.append(f"setup calls unknown endpoint {step.get('call')!r}")
        used = {m for s in _strings({k: v for k, v in step.items() if k != "extract"})
                for m in VAR.findall(s)}
        if used - defined:
            probs.append(f"setup uses undefined variable(s) {sorted(used - defined)}")
        defined |= set((step.get("extract") or {}).keys())
    used = {m for s in _strings(case.get("request") or {}) for m in VAR.findall(s)}
    for f in (case.get("oracle") or {}).get("findings_if") or []:
        sc = f.get("state_check")
        if sc:
            if sc.get("call") not in endpoints:
                probs.append(f"state_check calls unknown endpoint {sc.get('call')!r}")
            used |= {m for s in _strings(sc) for m in VAR.findall(s)}
        for rx in f.get("body_matches") or []:
            try:
                re.compile(rx)
            except re.error:
                probs.append("an invalid body_matches pattern")
    if used - defined:
        probs.append(f"request uses undefined variable(s) {sorted(used - defined)}")
    foreign = foreign_urls(case, origins)
    if foreign:
        probs.append(f"names {len(foreign)} out-of-scope URL(s)")
    return probs


def validate(doc) -> list[str]:
    """Every problem of a contract document (schema first, then semantics)."""
    from jsonschema import Draft202012Validator
    errors = sorted(Draft202012Validator(CONTRACT_SCHEMA).iter_errors(doc),
                    key=lambda e: list(e.absolute_path))
    if errors:
        return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message[:200]}"
                for e in errors[:20]]
    probs = []
    origins = scope_origins(doc["run"]["target"]["scope_allowlist"])
    if not origins:
        probs.append("run.target.scope_allowlist names no usable origin")
    base = doc["run"]["target"]["base_url"]
    if canonical_origin(base) is None or not in_origin_scope(base, origins):
        probs.append("run.target.base_url is outside scope_allowlist")
    for kind, items in (("endpoint", doc["endpoints"]), ("auth profile", doc["auth_profiles"]),
                        ("test case", doc["test_cases"])):
        ids = [i["id"] for i in items]
        dup = sorted({i for i in ids if ids.count(i) > 1})
        if dup:
            probs.append(f"duplicate {kind} id(s) {dup}")
    for ep in doc["endpoints"]:
        if ep.get("origin") and not in_origin_scope(ep["origin"], origins):
            probs.append(f"endpoint {ep['id']} is outside scope")
    for prof in doc["auth_profiles"]:
        ref = prof.get("ref") or ""
        if prof["kind"] in ("bearer", "basic", "cookie", "header") \
                and not ref.startswith(("keyring:", "env:")):
            probs.append(f"auth profile {prof['id']}: ref must be keyring:<identity> or "
                         f"env:<NAME>, never the secret itself (D12)")
        if prof["kind"] == "storage_state" and not ref:
            probs.append(f"auth profile {prof['id']}: a storage_state needs its file as ref")
    endpoints = {e["id"] for e in doc["endpoints"]}
    profiles = {p["id"] for p in doc["auth_profiles"]}
    for case in doc["test_cases"]:
        probs += [f"test case {case['id']}: {p}" for p in
                  case_problems(case, endpoints, profiles, origins)]
    return probs


def load_contract(path: str | Path) -> Contract:
    """The contract at ``path``, validated, or `ContractError`."""
    import yaml
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ContractError(f"cannot read the contract {p}: {type(exc).__name__}") from None
    try:
        doc = json.loads(text) if p.suffix.lower() == ".json" else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError, RecursionError) as exc:
        raise ContractError(f"the contract {p} does not parse: {type(exc).__name__}") from None
    if not isinstance(doc, dict):
        raise ContractError(f"the contract {p} is not a mapping")
    probs = validate(doc)
    if probs:
        raise ContractError(f"the contract {p} is invalid:\n  " + "\n  ".join(probs))
    return Contract(doc, p)
