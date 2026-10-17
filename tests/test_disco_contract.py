"""Phases 2 and 3 offline (D70): the execution contract (FR-FUZZ-51), Phase 2's case
synthesis with a fake LLM provider (FR-MUT-10), and the contract runner (FR-FUZZ-52) against a
fake HTTP session. Every safety gate is asserted at the send, by counting sends
(PA-0083(2))."""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest
import requests
import yaml

from fuzzlab.disco import generate
from fuzzlab.disco.contract import (Contract, ContractError, load_contract, scope_origins,
                                    validate)
from fuzzlab.disco.runner import (LEAK_PATTERNS, Runner, TargetUnreachable, assertion_holds,
                                  jsonpath)

BASE = "http://127.0.0.1:8080"


def contract_doc(**over) -> dict:
    """The spec's example contract, as data."""
    doc = {
        "contract_version": "1.0",
        "run": {"id": "run-2026-10-17-001",
                "target": {"base_url": f"{BASE}/", "scope_allowlist": ["127.0.0.1:8080"]},
                "limits": {"rps": 1000, "timeout_ms": 2000, "max_body_bytes": 4096},
                "reset_hook": None},
        "auth_profiles": [{"id": "user_a", "kind": "bearer", "ref": "env:DISCO_TOKEN_A"},
                          {"id": "anon", "kind": "none"}],
        "endpoints": [
            {"id": "ep_009", "method": "POST", "path": "/api/orders",
             "content_type": "application/json", "auth": "required"},
            {"id": "ep_010", "method": "GET", "path": "/api/orders/{p1}", "auth": "required",
             "response_schema": {"type": "object", "required": ["id", "total"],
                                 "properties": {"id": {"type": "integer"},
                                                "total": {"type": "number"}}}},
            {"id": "ep_017", "method": "POST", "path": "/api/orders/{p1}/items",
             "content_type": "application/json",
             "path_params": {"p1": {"type": "integer", "source": "dep:ep_009.$.id"}},
             "headers": {"Accept": "*/*", "User-Agent": "Browser/1"}, "auth": "required"},
        ],
        "test_cases": [{
            "id": "tc_017_0042", "endpoint": "ep_017", "class": "logic",
            "rationale": "quantity likely unsigned; observed range 1-20",
            "auth_profile": "user_a",
            "setup": [{"call": "ep_009", "auth_profile": "user_a", "body": {"name": "seed"},
                       "extract": {"order_id": "$.id"}}],
            "request": {"path_params": {"p1": "{{order_id}}"}, "query": {}, "headers": {},
                        "body": {"sku": "A-1", "quantity": -5}, "raw_body": None,
                        "content_type_override": None},
            "oracle": {"expect_status_class": ["4xx"],
                       "findings_if": [{"status_class": "5xx"},
                                       {"body_matches": ["(?i)traceback", "SQLSTATE"]},
                                       {"latency_ms_gt": 5000},
                                       {"response_schema_drift": True},
                                       {"state_check": {"call": "ep_010",
                                                        "path_params": {"p1": "{{order_id}}"},
                                                        "assert_jsonpath": "$.total >= 0"}}]},
            "safety": {"destructive": False, "idempotent": False}}],
        "results": [],
    }
    doc.update(over)
    return doc


# --- the contract --------------------------------------------------------------------------

def test_the_spec_example_loads(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(contract_doc()))
    c = load_contract(p)
    assert c.run_id == "run-2026-10-17-001"
    assert c.allowed_origins == {"http://127.0.0.1:8080", "https://127.0.0.1:8080"}


@pytest.mark.parametrize("mutate, problem", [
    (lambda d: d["run"]["target"].update(base_url="http://127.0.0.1:9999/"), "outside"),
    (lambda d: d["test_cases"][0].update(endpoint="ep_404"), "unknown endpoint"),
    (lambda d: d["test_cases"][0]["setup"].clear(), "undefined variable"),
    (lambda d: d["test_cases"][0]["request"]["headers"].update(
        Referer="http://evil.example/x"), "out-of-scope"),
    (lambda d: d["auth_profiles"][0].update(ref="eyJhbGciOiJIUzI1NiJ9.secret"), "D12"),
    (lambda d: d["test_cases"][0].update(auth_profile="root"), "unknown auth profile"),
    (lambda d: d["endpoints"].append(dict(d["endpoints"][0])), "duplicate endpoint"),
    (lambda d: d["test_cases"][0].update(**{"class": "chaos"}), "class"),
    (lambda d: d.update(contract_version="2.0"), "contract_version"),
])
def test_a_contract_that_cannot_be_used_is_refused_with_why(mutate, problem):
    doc = contract_doc()
    mutate(doc)
    assert any(problem in p for p in validate(doc)), validate(doc)


def test_every_reader_failure_is_a_typed_contract_error(tmp_path):
    with pytest.raises(ContractError):
        load_contract(tmp_path / "missing.yaml")
    (tmp_path / "bad.yaml").write_text("a: [")
    with pytest.raises(ContractError):
        load_contract(tmp_path / "bad.yaml")
    (tmp_path / "list.yaml").write_text("- 1")
    with pytest.raises(ContractError):
        load_contract(tmp_path / "list.yaml")
    (tmp_path / "deep.json").write_text("[" * 100_000 + "]" * 100_000)
    with pytest.raises(ContractError):
        load_contract(tmp_path / "deep.json")


def test_a_host_port_entry_admits_both_schemes_on_that_port_only():
    assert scope_origins(["localhost:3000", "https://shop.example/"]) == {
        "http://127.0.0.1:3000", "https://127.0.0.1:3000", "https://shop.example:443"}


# --- the runner ------------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status=200, body=b"{}", headers=None):
        self.status_code = status
        self.headers = headers or {"Content-Type": "application/json"}
        self._body = body

    def iter_content(self, n):
        for i in range(0, len(self._body), n):
            yield self._body[i:i + n]

    def close(self):
        pass


class FakeSession:
    """Answers by (method, path) with a callable or a FakeResponse; records each send."""

    def __init__(self, routes):
        self.routes, self.sent = routes, []

    def request(self, method, url, **kw):
        from urllib.parse import urlsplit
        self.sent.append((method, url, kw))
        ans = self.routes.get((method, urlsplit(url).path))
        if ans is None:
            return FakeResponse(404, b'{"error": "nf"}')
        return ans(url, kw) if callable(ans) else ans


def runner(doc=None, routes=None, **kw):
    c = Contract(doc or contract_doc())
    sess = FakeSession(routes or {})
    return Runner(c, authorized=True, session=sess, sleep=lambda s: None, **kw), sess


def test_the_runner_needs_authorized():
    with pytest.raises(PermissionError):
        Runner(Contract(contract_doc()), authorized=False, session=FakeSession({}))


def test_setup_extracts_and_the_oracle_flags_a_logic_bug(monkeypatch):
    monkeypatch.setenv("DISCO_TOKEN_A", "TOKENSECRET")
    r, sess = runner(routes={
        ("POST", "/api/orders"): FakeResponse(201, b'{"id": 41}'),
        ("POST", "/api/orders/41/items"): FakeResponse(200, b'{"ok": true}'),
        ("GET", "/api/orders/41"): FakeResponse(200, b'{"id": 41, "total": -50}'),
    })
    [res] = r.run()
    assert res["verdict"] == "finding"
    assert set(res["matched"]) == {"expect_status_class", "state_check"}
    method, url, kw = sess.sent[1]
    assert url == f"{BASE}/api/orders/41/items" and json.loads(kw["data"]) == \
        {"sku": "A-1", "quantity": -5}
    assert kw["allow_redirects"] is False and kw["stream"] is True     # PA-0046, PA-0102
    assert kw["headers"]["Authorization"] == "Bearer TOKENSECRET"
    assert kw["headers"]["User-Agent"] == "Browser/1"                  # the captured set


def test_a_5xx_and_a_stack_trace_are_findings_unless_the_baseline_shows_it():
    doc = contract_doc()
    case = doc["test_cases"][0]
    case.update(setup=[], auth_profile="anon")
    case["request"]["path_params"] = {"p1": "7"}
    case["oracle"] = {"expect_status_class": ["4xx"], "findings_if": []}
    second = json.loads(json.dumps(case))
    second["id"] = "tc_017_0043"
    doc["test_cases"] = [case, second]
    bodies = iter([(400, b"bad input, see NullPointerException docs"),
                   (500, b'Traceback (most recent call last):\n  File "x"')])
    r, _ = runner(doc, {("POST", "/api/orders/7/items"):
                        lambda u, kw: FakeResponse(*next(bodies))})
    first, worse = r.run()
    assert first["verdict"] == "finding" and first["matched"] == [
        "leak:\\bNullPointerException\\b"]
    assert "status_class:5xx" in worse["matched"]
    assert any(m.startswith("leak:Traceback") for m in worse["matched"])
    assert len(LEAK_PATTERNS) >= 10


def test_a_destructive_case_is_skipped_and_sends_nothing():
    doc = contract_doc()
    doc["test_cases"][0]["safety"]["destructive"] = True
    r, sess = runner(doc)
    [res] = r.run()
    assert res["verdict"] == "skipped" and sess.sent == []


def test_the_send_gate_refuses_out_of_scope_and_destructive_urls_at_the_send():
    from fuzzlab.disco.runner import Prepared
    from fuzzlab.core.urls import DestructiveUrlRefused
    r, sess = runner()
    with pytest.raises(PermissionError):
        r.send(Prepared("GET", "http://127.0.0.1:9999/x", {}, None))
    with pytest.raises(DestructiveUrlRefused):
        r.send(Prepared("GET", f"{BASE}/logout", {}, None))
    with pytest.raises(DestructiveUrlRefused):
        r.send(Prepared("DELETE", f"{BASE}/api/orders/1", {}, None))
    assert sess.sent == []


def test_credentials_go_only_to_the_base_origin(monkeypatch):
    monkeypatch.setenv("DISCO_TOKEN_A", "TOKENSECRET")
    doc = contract_doc()
    doc["run"]["target"]["scope_allowlist"] += ["127.0.0.1:9090"]
    doc["endpoints"][0]["origin"] = "http://127.0.0.1:9090/"
    r, _ = runner(doc)
    other = r.prepare("ep_009", body={}, auth_profile="user_a")
    own = r.prepare("ep_010", path_params={"p1": 1}, auth_profile="user_a")
    assert "Authorization" not in other.headers and other.url.startswith(
        "http://127.0.0.1:9090/")
    assert own.headers["Authorization"] == "Bearer TOKENSECRET"


def _raising(exc):
    def f(url, kw):
        raise exc
    return f


def test_no_response_is_an_error_for_that_case_and_the_run_goes_on():
    """PA-0153: a reset is no verdict, never the end of the run; SP-34 classifies."""
    doc = contract_doc()
    case = doc["test_cases"][0]
    case.update(setup=[], auth_profile="anon")
    case["request"]["path_params"] = {"p1": "7"}
    case["oracle"] = {"expect_status_class": ["4xx"], "findings_if": []}
    ok = json.loads(json.dumps(case))
    ok["id"] = "tc_ok"
    ok["request"]["path_params"] = {"p1": "8"}
    doc["test_cases"] = [case, ok]
    reset = requests.ConnectionError(ConnectionResetError(104, "reset"))
    r, _ = runner(doc, {("POST", "/api/orders/7/items"): _raising(reset),
                        ("POST", "/api/orders/8/items"): FakeResponse(400, b"{}")})
    first, second = r.run()
    assert first["verdict"] == "error" and "no response" in first["reason"]
    assert second["verdict"] == "pass"


def test_a_refused_target_stops_the_run_loudly():
    from urllib3.exceptions import NewConnectionError
    refused = requests.ConnectionError(NewConnectionError(None, "refused"))
    doc = contract_doc()
    doc["test_cases"][0].update(setup=[], auth_profile="anon")
    doc["test_cases"][0]["request"]["path_params"] = {"p1": "7"}
    r, _ = runner(doc, {("POST", "/api/orders/7/items"): _raising(refused)})
    with pytest.raises(TargetUnreachable):
        r.run()


def test_a_timeout_is_a_finding_only_under_a_latency_rule():
    doc = contract_doc()
    case = doc["test_cases"][0]
    case.update(setup=[], auth_profile="anon")
    case["request"]["path_params"] = {"p1": "7"}
    case["oracle"]["findings_if"] = [{"latency_ms_gt": 100}]
    r, _ = runner(doc, {("POST", "/api/orders/7/items"): _raising(requests.ReadTimeout())})
    assert r.run()[0]["verdict"] == "finding"
    case["oracle"]["findings_if"] = []
    r, _ = runner(doc, {("POST", "/api/orders/7/items"): _raising(requests.ReadTimeout())})
    assert r.run()[0]["verdict"] == "error"


def test_an_endpoint_path_is_origin_absolute_never_under_the_base_sub_path():
    """PA-0300's class: a base URL with a sub-path and a captured (origin-absolute)
    endpoint path give that path once."""
    doc = contract_doc()
    doc["run"]["target"]["base_url"] = f"{BASE}/app/"
    doc["endpoints"][1]["path"] = "/app/api/orders/{p1}"
    r, _ = runner(doc)
    assert r.prepare("ep_010", path_params={"p1": 3}).url == f"{BASE}/app/api/orders/3"


def test_a_body_is_read_up_to_its_cap():
    r, _ = runner(routes={("GET", "/api/orders/1"): FakeResponse(200, b"x" * 100_000)})
    ex = r.send(r.prepare("ep_010", path_params={"p1": 1}))
    assert ex.truncated and len(ex.body) == 4096


def test_sends_are_paced_to_the_rate_limit():
    doc = contract_doc()
    doc["run"]["limits"]["rps"] = 2
    clock = types.SimpleNamespace(t=0.0)
    slept = []
    r = Runner(Contract(doc), authorized=True, session=FakeSession({}),
               clock=lambda: clock.t, sleep=lambda s: slept.append(s))
    for _ in range(3):
        r.send(r.prepare("ep_010", path_params={"p1": 1}))
    assert slept == [0.5, 0.5]


def test_evidence_is_redacted(tmp_path, monkeypatch):
    monkeypatch.setenv("DISCO_TOKEN_A", "TOKENSECRET")
    doc = contract_doc()
    case = doc["test_cases"][0]
    case.update(setup=[])
    case["request"]["path_params"] = {"p1": "7"}
    case["request"]["body"] = {"password": "BODYSECRET", "quantity": 1}
    r, _ = runner(doc, {("POST", "/api/orders/7/items"): FakeResponse(
        400, b'{"token": "RESPSECRET"}', {"Content-Type": "application/json",
                                         "Set-Cookie": "sid=COOKIESECRET"})},
                  evidence_dir=tmp_path)
    [res] = r.run()
    blob = "".join(Path(p).read_text() for p in res["evidence"].values())
    for secret in ("TOKENSECRET", "BODYSECRET", "RESPSECRET", "COOKIESECRET"):
        assert secret not in blob
    assert 'quantity' in blob and '__REDACTED__' in blob          # benign kept


def test_response_schema_drift_and_jsonpath_assertions():
    doc = contract_doc()
    case = doc["test_cases"][0]
    case.update(endpoint="ep_010", setup=[], auth_profile="anon")
    case["request"] = {"path_params": {"p1": "3"}}
    case["oracle"] = {"expect_status_class": ["2xx"],
                      "findings_if": [{"response_schema_drift": True}]}
    r, _ = runner(doc, {("GET", "/api/orders/3"): FakeResponse(200, b'{"id": "three"}')})
    assert r.run()[0]["matched"] == ["response_schema_drift"]
    assert jsonpath({"a": [{"b": 2}]}, "$.a[0].b") == 2
    assert jsonpath({"x y": 1}, '$["x y"]') == 1
    assert assertion_holds({"total": -1}, "$.total >= 0") is False
    assert assertion_holds({"total": 1}, "$.missing >= 0") is None


# --- Phase 2 with a fake provider ---------------------------------------------------------------

def _inventory():
    from tests.test_disco_synth import U1, rec
    from fuzzlab.disco.synth import synthesize
    return synthesize([
        rec("GET", "/api/projects", res=[{"id": 101}], t=1,
            headers={"Cookie": "sid=x", "User-Agent": "UA-SECRET-ISH"}),
        rec("POST", "/api/projects/101/tasks", body={"title": "a", "n": 1},
            res={"id": U1}, status=201, t=2),
        rec("PUT", f"/api/tasks/{U1}", body={"done": True}, res={}, t=3),
    ])


NONE = {"path_params": [], "query": [], "headers": [], "body_json": "", "raw_body": "",
        "content_type_override": ""}


def _case(**over):
    base = {"class": "boundary", "rationale": "n is small", "auth_profile": "anon",
            "setup": [], "request": dict(NONE, body_json='{"n": -1}'),
            "oracle": {"expect_status_class": ["4xx"],
                       "findings_if": [{"kind": "status_class", "value": "5xx"},
                                       {"kind": "body_matches", "value": "(?i)traceback"}]},
            "safety": {"destructive": False, "idempotent": True}}
    base.update(over)
    return base


class FakeProvider:
    def __init__(self, cases_for, refuse=()):
        self.cases_for, self.refuse, self.seen = cases_for, refuse, []

    def generate(self, system, user, schema):
        payload = json.loads(user)
        self.seen.append((system, payload))
        ep = payload["endpoint"]
        if ep["id"] in self.refuse:
            return generate.Generation(refused="cyber")
        return generate.Generation(text=json.dumps({"cases": self.cases_for(ep, payload)}))


def test_cases_are_validated_scope_filtered_and_capped():
    inv = _inventory()

    def cases(ep, payload):
        if ep["method"] != "POST":
            return []
        dep = payload["context"]["dependencies"][0]
        with_setup = _case(setup=[{"call": dep["producer"], "auth_profile": "anon",
                                   "path_params": [], "query": [], "body_json": "",
                                   "extract": [{"var": "pid", "jsonpath": dep["extract"]}]}],
                           request=dict(NONE, path_params=[{"name": "p1", "value": "{{pid}}"}],
                                        body_json='{"title": "", "n": 1}'))
        return [
            _case(request=dict(NONE, path_params=[{"name": "p1", "value": "101"}],
                               body_json='{"n": -1}')),
            with_setup,
            _case(request=dict(NONE, headers=[{"name": "X-Callback",
                                               "value": "http://attacker.example/"}])),
            _case(setup=[{"call": "ep_999", "auth_profile": "anon", "path_params": [],
                          "query": [], "body_json": "", "extract": []}]),
            _case(request=dict(NONE, body_json="{not json")),
            _case(auth_profile="admin"),
            _case(request=dict(NONE, path_params=[{"name": "p1", "value": "{{nope}}"}])),
            _case(), _case(), _case(),
        ]

    contract, report = generate.build_contract(inv, FakeProvider(cases), run_id="r1",
                                               max_cases=4)
    assert validate(contract) == []
    assert report.kept == len(contract["test_cases"]) == 4
    assert report.dropped == {"out-of-scope": 1, "foreign-endpoint": 1, "unconvertible": 1,
                              "reference": 2, "over-cap": 1}
    kept = contract["test_cases"][1]
    assert kept["setup"][0]["extract"] == {"pid": "$[0].id"}
    assert kept["request"]["path_params"] == {"p1": "{{pid}}"}
    assert kept["oracle"]["findings_if"] == [{"status_class": "5xx"},
                                             {"body_matches": ["(?i)traceback"]}]


def test_the_prompt_carries_schemas_never_header_values_or_sessions():
    inv = _inventory()
    prov = FakeProvider(lambda ep, p: [])
    contract, report = generate.build_contract(inv, prov, run_id="r1")
    assert report.asked == len(contract["endpoints"]) == 3
    system, payload = prov.seen[0]
    blob = json.dumps([p for _s, p in prov.seen])
    assert "UA-SECRET-ISH" not in blob and "sid=" not in blob
    assert "header_names" in payload["endpoint"]
    assert "Output only the JSON object" in system and "{max_cases}" not in system


def test_a_declined_or_truncated_endpoint_is_reported_not_guessed():
    class Truncated:
        def generate(self, system, user, schema):
            return generate.Generation(text='{"cases": [', truncated=True)
    inv = _inventory()
    _c, rep = generate.build_contract(inv, Truncated(), run_id="r1")
    assert rep.dropped == {"truncated": 3} and rep.kept == 0
    _c, rep = generate.build_contract(inv, FakeProvider(lambda e, p: [],
                                                        refuse={"ep_001"}), run_id="r1")
    assert rep.refused == {"ep_001": "cyber"}


def test_the_anthropic_provider_asks_for_structured_low_effort_output_with_fallback():
    calls = []

    class Msgs:
        def create(self, **kw):
            calls.append(kw)
            block = types.SimpleNamespace(type="text", text='{"cases": []}')
            return types.SimpleNamespace(stop_reason="end_turn", content=[block])

    client = types.SimpleNamespace(beta=types.SimpleNamespace(messages=Msgs()))
    gen = generate.AnthropicProvider(client=client).generate("sys", "{}", {"type": "object"})
    assert gen.text == '{"cases": []}'
    kw = calls[0]
    assert kw["model"] == "claude-opus-5-5"
    assert kw["output_config"] == {"effort": "low", "format": {"type": "json_schema",
                                                               "schema": {"type": "object"}}}
    assert kw["fallbacks"] == "default" and kw["betas"] == ["server-side-fallback-2026-07-01"]
    assert "temperature" not in kw                     # rejected by the model (a 400)


def test_the_output_schema_uses_only_what_structured_outputs_accept():
    """Closed objects with every property required; no numeric, string or array bounds
    (unsupported; the caps are enforced after parsing)."""
    bad = {"minimum", "maximum", "minLength", "maxLength", "maxItems", "minItems", "pattern",
           "multipleOf"}

    def walk(node, where="$"):
        if isinstance(node, dict):
            assert not bad & set(node), where
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False, where
                assert set(node.get("required", [])) == set(node.get("properties", {})), where
            for k, v in node.items():
                walk(v, f"{where}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{where}[{i}]")
    walk(generate.CASES_SCHEMA)
