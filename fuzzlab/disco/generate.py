"""Phase 2: runtime payload synthesis -- an LLM writes test cases per endpoint.

`build_contract` reads a disco inventory endpoint by endpoint, asks a `CaseProvider` for
test cases with the prompt below (`SYSTEM_PROMPT`; the endpoint and its context as JSON),
validates every case, and assembles a Phase 3 contract (`contract.CONTRACT_SCHEMA`).

**Zero prose, structured output.** The provider is constrained to `CASES_SCHEMA` (JSON
only; no markdown, no commentary). Request values are carried as strings -- a body as
JSON text (``body_json``), parameters as name/value pairs -- because a schema-constrained
decoder needs closed shapes; `to_contract_case` turns them back into the contract's form.

**Determinism.** The spec asked for a low temperature. The default model (Claude Opus
5.5) accepts no sampling parameters (a ``temperature`` is a 400), so variance is
bounded the way that model supports: the output schema, a terse system prompt, and
``effort: "low"`` (`AnthropicProvider`). A provider for a model that does take a
temperature passes one itself.

**Every case is checked before it is kept** (`validate_case`), and a dropped case is
counted by reason, never repaired:
- it parses (``body_json`` is JSON) and fits `contract.TEST_CASE_SCHEMA`;
- it references only this endpoint and the producers of its dependencies;
- it names no host outside the scope (`contract.foreign_urls`);
- its auth profiles exist; its ``{{variables}}`` are extracted before use;
- at most ``max_cases`` per endpoint.

**What leaves the machine.** Only the inventory's schemas go to the provider: paths,
types, formats, observed ranges, enums, header *names* and classes, dependency edges.
Captured values were redacted at capture (`capture`), session headers are sent as their
class only, and static header values (a user agent) are left out.

Injection payloads (SQLi, XSS, SSTI...) are not asked of the LLM: the existing oracle
pipeline (``fuzzlab auto``) and maintained rule packs own them (class ``injection`` is
reserved for such a producer).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Protocol

from fuzzlab.disco.contract import (CLASSES, CONTRACT_VERSION, DEFAULT_LIMITS, STATUS_CLASSES,
                                    TEST_CASE_SCHEMA, case_problems, scope_origins)
from fuzzlab.disco.synth import endpoints as inventory_endpoints

#: The model the default provider uses.
DEFAULT_MODEL = "claude-opus-5-5"
#: Classes Phase 2 asks for (``injection`` belongs to a rule-pack producer).
LLM_CLASSES = tuple(c for c in CLASSES if c != "injection")

SYSTEM_PROMPT = """\
You generate test cases for an authorized black-box robustness and logic test of a web API \
running in an isolated, operator-owned test container. Output only the JSON object the \
response schema defines.

INPUT (in the user message, as JSON)
- "endpoint": one inventory entry: method, path template, parameters, request schema with \
observed ranges/formats/enums, response schema, auth requirement, dependencies.
- "context": related endpoints (id, method, path, what they produce), the available auth \
profiles, and the variables dependency steps can produce.

TASK
1. Infer each parameter's likely server-side constraint from its type, format, name, \
observed range and enum. State it in "rationale" (20 words at most).
2. Write cases in these classes, preferring the ones most likely to reveal unhandled input \
or broken business logic:
   - type: the wrong JSON type per field (string, number, boolean, null, array, object).
   - boundary: min-1, min, max, max+1 for observed ranges and lengths; 0, negative, very \
large integers, a float where an integer is expected; empty string or array.
   - structural: omit each required field; add unknown fields; add response-only fields \
to the request (mass assignment); duplicate keys; deep nesting; oversized arrays.
   - syntax: malformed JSON, a truncated body, a mismatched Content-Type, another charset, \
unicode edge cases (combining characters, right-to-left, zero-width, overlong strings). \
Put such bodies in "raw_body" and leave "body_json" empty.
   - logic: swap resource ids between auth profiles (ownership checks); call without \
auth; replay steps out of order; repeat a one-time action; negative or zero quantities or \
prices; state transitions that skip intermediate steps.
3. Reference only this endpoint and the endpoints in context.dependencies. Never introduce \
a host, URL or path that is not in the input.
4. Fill "oracle": the status classes a correctly hardened server returns (for bad input \
usually 4xx without a stack trace) and the anomalies that count as findings.
5. Set safety.destructive to true for a case that deletes or irreversibly changes data.
6. Use a dependency's producer as a setup step when a path parameter or field needs a \
real id: "extract" names a variable and the JSONPath from context, and the request uses \
it as {{variable}}.
7. Write at most {max_cases} cases. Prefer diversity to volume: one case per distinct \
hypothesis."""

_PAIRS = {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"},
                                                     "value": {"type": "string"}},
                    "required": ["name", "value"], "additionalProperties": False}}
_STEP = {"type": "object", "additionalProperties": False,
         "required": ["call", "auth_profile", "path_params", "query", "body_json", "extract"],
         "properties": {"call": {"type": "string"}, "auth_profile": {"type": "string"},
                        "path_params": _PAIRS, "query": _PAIRS,
                        "body_json": {"type": "string"},
                        "extract": {"type": "array", "items": {
                            "type": "object", "additionalProperties": False,
                            "required": ["var", "jsonpath"],
                            "properties": {"var": {"type": "string"},
                                           "jsonpath": {"type": "string"}}}}}}
_RULE = {"type": "object", "additionalProperties": False, "required": ["kind", "value"],
         "properties": {"kind": {"enum": ["status_class", "body_matches", "latency_ms_gt",
                                          "response_schema_drift", "state_check"]},
                        "value": {"type": "string"}}}
#: The structured-output schema the provider is held to. Only what structured outputs
#: accept: closed objects, enums, no array or string bounds (the caps are enforced after
#: parsing: `max_cases`, `contract.TEST_CASE_SCHEMA`).
CASES_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["cases"],
    "properties": {"cases": {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["class", "rationale", "auth_profile", "setup", "request", "oracle",
                     "safety"],
        "properties": {
            "class": {"enum": list(LLM_CLASSES)},
            "rationale": {"type": "string"},
            "auth_profile": {"type": "string"},
            "setup": {"type": "array", "items": _STEP},
            "request": {"type": "object", "additionalProperties": False,
                        "required": ["path_params", "query", "headers", "body_json",
                                     "raw_body", "content_type_override"],
                        "properties": {"path_params": _PAIRS, "query": _PAIRS,
                                       "headers": _PAIRS, "body_json": {"type": "string"},
                                       "raw_body": {"type": "string"},
                                       "content_type_override": {"type": "string"}}},
            "oracle": {"type": "object", "additionalProperties": False,
                       "required": ["expect_status_class", "findings_if"],
                       "properties": {"expect_status_class": {
                           "type": "array", "items": {"enum": list(STATUS_CLASSES)}},
                           "findings_if": {"type": "array", "items": _RULE}}},
            "safety": {"type": "object", "additionalProperties": False,
                       "required": ["destructive", "idempotent"],
                       "properties": {"destructive": {"type": "boolean"},
                                      "idempotent": {"type": "boolean"}}}}}}},
}


@dataclass
class Generation:
    """A provider's answer: the JSON text, or why there is none."""
    text: str | None = None
    refused: str | None = None
    truncated: bool = False


class CaseProvider(Protocol):
    def generate(self, system: str, user: str, schema: dict) -> Generation: ...


class AnthropicProvider:
    """Claude through the Anthropic SDK: structured output (``output_config.format``),
    ``effort: "low"``, and the server-side refusal fallback (``fallbacks: "default"``)
    so a classifier decline is retried on the recommended model instead of returned.
    The key comes from the SDK's own resolution (``ANTHROPIC_API_KEY``, an
    ``ant auth login`` profile) or from the keyring (D12) when ``api_key`` is given."""

    def __init__(self, model: str = DEFAULT_MODEL, *, api_key: str | None = None,
                 effort: str = "low", max_tokens: int = 16000, client=None):
        self.model, self.effort, self.max_tokens = model, effort, max_tokens
        if client is None:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self.client = client

    def generate(self, system: str, user: str, schema: dict) -> Generation:
        resp = self.client.beta.messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort,
                           "format": {"type": "json_schema", "schema": schema}},
            betas=["server-side-fallback-2026-07-01"], fallbacks="default")
        if resp.stop_reason == "refusal":
            details = getattr(resp, "stop_details", None)
            return Generation(refused=str(getattr(details, "category", None) or "refusal"))
        text = next((b.text for b in resp.content if getattr(b, "type", "") == "text"), None)
        return Generation(text=text, truncated=resp.stop_reason == "max_tokens")


# --- inventory -> contract endpoints ---------------------------------------------------

def endpoints_from_inventory(inventory: dict) -> list[dict]:
    """The contract ``endpoints`` for every operation of a disco inventory."""
    out = []
    for template, method, op in inventory_endpoints(inventory):
        x = op["x-disco"]
        deps = {d["target"]: d for d in x.get("dependencies") or []}
        params, query = {}, {}
        for p in op.get("parameters") or []:
            if p["in"] == "path":
                spec = {"type": p["schema"].get("type"), "kind": p["schema"].get("x-kind")}
                dep = deps.get(f"path.{p['name']}")
                if dep:
                    spec["source"] = f"dep:{dep['producer']}.{dep['extract']}"
                params[p["name"]] = spec
            elif p["in"] == "query":
                query[p["name"]] = {"required": p.get("required", False), **p["schema"]}
        body = (op.get("requestBody") or {}).get("content") or {}
        ctype, req_schema = next(iter(body.items()), (None, {"schema": None}))
        ok = sorted((s for s in op.get("responses", {}) if s.startswith("2")))
        res_content = (op["responses"][ok[0]].get("content") or {}) if ok else {}
        res_schema = next(iter(res_content.values()), {}).get("schema")
        static = {name: h["value"] for name, h in x.get("headers", {}).items()
                  if h.get("class") == "static"}
        out.append({"id": op["operationId"], "method": method, "path": template,
                    "origin": x.get("origin"), "content_type": ctype,
                    "path_params": params, "query_params": query,
                    "request_schema": req_schema.get("schema"),
                    "response_schema": res_schema, "headers": static,
                    "auth": x.get("auth", "none"),
                    "provenance": {"observed": x.get("observed", True),
                                   "samples": x.get("samples", 0),
                                   "actions": (x.get("actions") or [])[:10],
                                   "dependencies": x.get("dependencies") or [],
                                   "response_only_fields": x.get("response_only_fields") or []}})
    return out


def prompt_payload(ep: dict, all_eps: dict[str, dict], profiles: list[str]) -> dict:
    """What the provider sees for one endpoint: schemas and relations, no values a
    capture held beyond redacted enums and examples, no header values."""
    prov = ep.get("provenance") or {}
    deps = prov.get("dependencies") or []
    related = sorted({d["producer"] for d in deps})
    return {
        "endpoint": {"id": ep["id"], "method": ep["method"], "path": ep["path"],
                     "content_type": ep.get("content_type"), "path_params": ep["path_params"],
                     "query_params": ep.get("query_params") or {},
                     "request_schema": ep.get("request_schema"),
                     "response_schema": ep.get("response_schema"), "auth": ep.get("auth"),
                     "header_names": sorted(ep.get("headers") or {}),
                     "response_only_fields": prov.get("response_only_fields") or []},
        "context": {
            "dependencies": [{"producer": d["producer"], "extract": d["extract"],
                              "target": d["target"],
                              "producer_method": all_eps[d["producer"]]["method"],
                              "producer_path": all_eps[d["producer"]]["path"],
                              "producer_request_schema":
                                  all_eps[d["producer"]].get("request_schema")}
                             for d in deps if d["producer"] in all_eps],
            "related_endpoints": [{"id": r, "method": all_eps[r]["method"],
                                   "path": all_eps[r]["path"]} for r in related
                                  if r in all_eps],
            "auth_profiles": profiles,
        },
    }


# --- provider output -> contract cases -------------------------------------------------

def _pairs(items) -> dict:
    return {str(p["name"]): p["value"] for p in items or [] if str(p.get("name", ""))}


def _body(text: str):
    """``body_json`` text -> a value; "" -> None. Raises ValueError on bad JSON."""
    if not text or not text.strip():
        return None
    return json.loads(text)


def _rule(rule: dict) -> dict:
    kind, value = rule["kind"], rule["value"]
    if kind == "status_class":
        return {"status_class": value.strip()}
    if kind == "body_matches":
        return {"body_matches": [value]}
    if kind == "latency_ms_gt":
        return {"latency_ms_gt": int(float(value))}
    if kind == "response_schema_drift":
        return {"response_schema_drift": value.strip().lower() in ("true", "1", "yes", "")}
    doc = json.loads(value)
    if not isinstance(doc, dict):
        raise ValueError("a state_check value is a JSON object")
    return {"state_check": doc}


def to_contract_case(raw: dict, endpoint_id: str, case_id: str) -> dict:
    """One provider case in the contract's form (ValueError when it cannot be)."""
    rq = raw["request"]
    request = {"path_params": _pairs(rq.get("path_params")), "query": _pairs(rq.get("query")),
               "headers": _pairs(rq.get("headers"))}
    if rq.get("raw_body"):
        request["raw_body"] = rq["raw_body"]
    else:
        body = _body(rq.get("body_json", ""))
        if body is not None:
            request["body"] = body
    if rq.get("content_type_override"):
        request["content_type_override"] = rq["content_type_override"]
    setup = []
    for step in raw.get("setup") or []:
        s = {"call": step["call"], "path_params": _pairs(step.get("path_params")),
             "query": _pairs(step.get("query")),
             "extract": {e["var"]: e["jsonpath"] for e in step.get("extract") or []}}
        if step.get("auth_profile"):
            s["auth_profile"] = step["auth_profile"]
        body = _body(step.get("body_json", ""))
        if body is not None:
            s["body"] = body
        setup.append(s)
    case = {"id": case_id, "endpoint": endpoint_id, "class": raw["class"],
            "rationale": str(raw.get("rationale", ""))[:400],
            "setup": setup, "request": request,
            "oracle": {"expect_status_class": list(raw["oracle"].get("expect_status_class")
                                                   or []),
                       "findings_if": [_rule(r) for r in raw["oracle"].get("findings_if")
                                       or []]},
            "safety": {"destructive": bool(raw["safety"]["destructive"]),
                       "idempotent": bool(raw["safety"].get("idempotent", False))}}
    if raw.get("auth_profile"):
        case["auth_profile"] = raw["auth_profile"]
    return case


def validate_case(case: dict, *, allowed_endpoints: set[str], profiles: set[str],
                  origins: frozenset[str]) -> str | None:
    """Why a converted case is dropped, or None."""
    from jsonschema import Draft202012Validator
    if any(True for _ in Draft202012Validator(TEST_CASE_SCHEMA).iter_errors(case)):
        return "schema"
    refs = {case["endpoint"]} | {s["call"] for s in case.get("setup") or []} | {
        r["state_check"]["call"] for r in case["oracle"]["findings_if"] if "state_check" in r}
    if refs - allowed_endpoints:
        return "foreign-endpoint"
    probs = case_problems(case, allowed_endpoints, profiles, origins)
    if any("out-of-scope" in p for p in probs):
        return "out-of-scope"
    if probs:
        return "reference"
    return None


@dataclass
class GenerationReport:
    endpoints: int = 0
    asked: int = 0
    kept: int = 0
    dropped: dict[str, int] = field(default_factory=dict)
    refused: dict[str, str] = field(default_factory=dict)

    def drop(self, why: str, n: int = 1) -> None:
        self.dropped[why] = self.dropped.get(why, 0) + n


def build_contract(inventory: dict, provider: CaseProvider | None, *, run_id: str,
                   base_url: str | None = None, scope: list[str] | None = None,
                   auth_profiles: list[dict] | None = None, max_cases: int = 12,
                   only: set[str] | None = None,
                   limits: dict | None = None) -> tuple[dict, GenerationReport]:
    """A contract for ``inventory``; with ``provider`` None, endpoints only (no cases)."""
    servers = [s["url"] for s in inventory.get("servers") or []]
    base = base_url or (servers[0] if servers else None)
    if not base:
        raise ValueError("the inventory names no server; pass a base URL")
    scope = list(scope or servers or [base])
    origins = scope_origins(scope)
    profiles = auth_profiles or [{"id": "anon", "kind": "none"}]
    profile_ids = {p["id"] for p in profiles}
    eps = endpoints_from_inventory(inventory)
    by_id = {e["id"]: e for e in eps}
    report = GenerationReport(endpoints=len(eps))
    cases: list[dict] = []
    system = SYSTEM_PROMPT.replace("{max_cases}", str(max_cases))
    for ep in eps:
        if provider is None or (only and ep["id"] not in only):
            continue
        payload = prompt_payload(ep, by_id, sorted(profile_ids))
        allowed = {ep["id"]} | {d["producer"] for d in payload["context"]["dependencies"]}
        report.asked += 1
        gen = provider.generate(system, json.dumps(payload, sort_keys=True), CASES_SCHEMA)
        if gen.refused:
            report.refused[ep["id"]] = gen.refused
            continue
        try:
            doc = json.loads(gen.text or "")
            raws = doc["cases"] if isinstance(doc, dict) else None
            if not isinstance(raws, list):
                raise ValueError("no cases")
        except (ValueError, KeyError, RecursionError):
            report.drop("truncated" if gen.truncated else "unparseable")
            continue
        kept = 0
        for i, raw in enumerate(raws):
            if kept >= max_cases:
                report.drop("over-cap", len(raws) - i)
                break
            cid = f"tc_{ep['id'][3:]}_{i + 1:04d}"
            try:
                case = to_contract_case(raw, ep["id"], cid)
            except (ValueError, KeyError, TypeError):
                report.drop("unconvertible")
                continue
            why = validate_case(case, allowed_endpoints=allowed, profiles=profile_ids,
                                origins=origins)
            if why:
                report.drop(why)
                continue
            cases.append(case)
            kept += 1
        report.kept += kept
    contract = {"contract_version": CONTRACT_VERSION,
                "run": {"id": run_id, "target": {"base_url": base, "scope_allowlist": scope},
                        "limits": {**DEFAULT_LIMITS, **(limits or {})}, "reset_hook": None},
                "auth_profiles": profiles, "endpoints": eps, "test_cases": cases,
                "results": []}
    return contract, report


def default_run_id() -> str:
    return time.strftime("run-%Y-%m-%d-%H%M%S")
