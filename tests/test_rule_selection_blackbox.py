"""Rule selection on a black-box target (lane RULESEL; FR-AUD-700..706, FR-CORE-670..672).

- name rules match whole tokens, never a word inside another (BUG-0710, FR-AUD-702);
- whole-body rules read the captured request's own content type (FR-AUD-701,
  FR-CORE-672), and leaf rules never fire on a whole body;
- path traversal and header injection have crawl-observable predicates (FR-AUD-700/703);
- `R-SSJS` fires only on the target's own evidence that it runs JavaScript (FR-AUD-706).
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from fuzzlab.audit.engine import InjectionPoint
from fuzzlab.audit.rules import Rule, load_rules, matches
from fuzzlab.core.fingerprint import server_language
from fuzzlab.core.redaction import media_family

ROOT = Path(__file__).resolve().parents[1]
RULES = {r.id: r for r in load_rules()}
BASE = "http://127.0.0.1:8092"


def _q(name, value_shapes=frozenset(), location="query", method="GET", **kw):
    return InjectionPoint(url=BASE + "/x.php", param=name, method=method,
                          location=location, value_shapes=frozenset(value_shapes), **kw)


def _cats(point, target=None):
    return {r.category for r in RULES.values() if matches(r, point, target)}


def _ids(point, target=None):
    return {r.id for r in RULES.values() if matches(r, point, target)}


# --- BUG-0710: token-anchored names --------------------------------------------------

@pytest.mark.parametrize("rule_id,name", [
    ("R-COMMAND-INJECTION", "description"),      # `ip` inside a word
    ("R-COMMAND-INJECTION", "zip"),
    ("R-COMMAND-INJECTION", "shipping"),
    ("R-FILE-INCLUSION", "payload"),              # `load` inside a word
    ("R-FILE-INCLUSION", "yaml_payload"),
    ("R-SSRF", "thumbnail"),
    ("R-OPEN-REDIRECT", "nextid"),
])
def test_a_rule_word_never_matches_inside_another_word(rule_id, name):
    assert not matches(RULES[rule_id], _q(name))


@pytest.mark.parametrize("rule_id,name", [
    # every same-category answer-key positive the old substring rules matched, and the
    # compounds the rules spell out (measured: tests below and CC-AUD-0702)
    ("R-OPEN-REDIRECT", "forwardurl"), ("R-OPEN-REDIRECT", "destination"),
    ("R-OPEN-REDIRECT", "return_to"), ("R-OPEN-REDIRECT", "redirect_uri"),
    ("R-OPEN-REDIRECT", "returnUrl"), ("R-FILE-INCLUSION", "filename"),
    ("R-FILE-INCLUSION", "directory"), ("R-FILE-INCLUSION", "configfile"),
    ("R-FILE-INCLUSION", "page"), ("R-COMMAND-INJECTION", "hostname"),
    ("R-COMMAND-INJECTION", "dbhost"), ("R-COMMAND-INJECTION", "ip"),
    ("R-COMMAND-INJECTION", "target_ip"), ("R-COMMAND-INJECTION", "ipAddress"),
    ("R-SSRF", "imageUrl"), ("R-SSRF", "webhook"), ("R-PRICE-INTEGRITY", "unitPrice"),
    ("R-CSV-FORMULA-INJECTION", "username"),
])
def test_a_rule_word_matches_a_whole_token_or_the_compound_it_spells(rule_id, name):
    rule = RULES[rule_id]
    point = _q(name, method=(rule.when.get("method_in") or ["GET"])[0])
    assert matches(rule, point)


def test_no_same_category_answer_key_positive_lost_its_name_rule():
    """Measured recall (BUG-0710): every expected-vulnerable answer-key case whose class
    a name rule nominates, and whose name the rule matched before (the old substring
    vocabulary below, frozen here), still matches under token anchoring."""
    from fuzzlab.core.runmode import to_category
    old = {"R-OPEN-REDIRECT": "url|next|redirect|return|dest|goto|continue|target",
           "R-FILE-INCLUSION": "file|path|page|include|template|doc|folder|dir|load",
           "R-COMMAND-INJECTION": "cmd|exec|command|ping|host|dns|domain|ip",
           "R-SSRF": "url|uri|link|src|source|target|endpoint|fetch|proxy|webhook|image"
                     "|avatar",
           "R-PRICE-INTEGRITY": "amount|price|total|cost|charge",
           "R-CSV-FORMULA-INJECTION": "name|comment|note|description|title"}
    lost = []
    for labels in sorted(ROOT.glob("lab/ground-truth*/labels.json")):
        for case in json.loads(labels.read_text())["cases"]:
            name = case["param"].split(".")[-1]
            for rid, rx in old.items():
                rule = RULES[rid]
                if (case.get("expected_vulnerable")
                        and to_category(case["vuln_class"]) == rule.category
                        and re.search(rx, name, re.I)):
                    point = _q(name, method=(rule.when.get("method_in") or ["GET"])[0])
                    if not matches(rule, point):
                        lost.append((case["case_id"], rid, name))
    assert lost == []


def _searches(tree) -> list[int]:
    return [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and n.func.attr in ("search", "match")
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "re"]


def test_the_rule_engine_never_matches_a_name_by_unanchored_search():
    """PA-0710: the engine matches every rule regex with `re.fullmatch` (a whole name or
    a whole token); `re.search`/`re.match` would let a word match inside another."""
    tree = ast.parse((ROOT / "fuzzlab/audit/rules.py").read_text(encoding="utf-8"))
    assert _searches(tree) == []


def test_the_unanchored_search_guard_catches_a_synthetic_offender():
    bad = ast.parse("import re\ndef m(rx, n):\n    return re.search(rx, n, re.I)\n")
    assert _searches(bad) == [3]


def test_name_regex_is_matched_against_the_whole_name():
    rule = Rule(id="T", category="t", transaction_type="T", when={"name_regex": "ip"})
    assert matches(rule, _q("ip")) and not matches(rule, _q("description"))


# --- FR-AUD-700 / 703: crawl-observable path traversal and header injection ----------

def test_a_file_valued_or_file_named_parameter_draws_path_traversal():
    assert "path-traversal" in _cats(_q("page", {"filename"}))          # page=message.txt
    assert "path-traversal" in _cats(_q("directory"))                   # directory=documents
    assert "path-traversal" in _cats(_q("x", {"path"}))
    assert "path-traversal" not in _cats(_q("q"))
    assert "path-traversal" not in _cats(_q("x", {"filename"}, location="fragment"))


def test_a_url_valued_or_redirect_named_parameter_draws_header_injection():
    assert "http-header-injection" in _cats(_q("goto", {"url"}))
    assert "http-header-injection" in _cats(_q("destination"))
    assert "http-header-injection" not in _cats(_q("q"))


# --- FR-AUD-701 / FR-CORE-672: whole-body points --------------------------------------

def _whole(media, entries=(), method="POST", url=BASE + "/api/items"):
    return InjectionPoint(url=url, param="body", method=method, location="body",
                          body_content_type=media, base_entries=tuple(entries) or None,
                          origin="crawl")


def test_a_whole_json_body_draws_the_whole_body_rules_and_no_leaf_rule():
    ids = _ids(_whole("application/json", [(("name",), "a"), (("count",), 1)]))
    assert {"R-MASS-ASSIGNMENT-JSON", "R-INSECURE-DESERIALIZATION-JSON",
            "R-SSTI"} <= ids
    for leaf in ("R-SQLI-PARAM", "R-XSS-REFLECT", "R-LDAP-INJECTION", "R-XPATH-INJECTION",
                 "R-SPEL-INJECTION", "R-SSJS", "R-PRICE-TRUST-JSON",
                 "R-WEAK-TOKEN-ENTROPY-JSON"):
        assert leaf not in ids


def test_price_trust_needs_a_price_leaf_of_the_targets_own_body():
    assert "R-PRICE-TRUST-JSON" in _ids(_whole("application/json",
                                               [(("plan",), "x"), (("unitPrice",), 9)]))
    assert "R-PRICE-TRUST-JSON" not in _ids(_whole("application/json",
                                                   [(("quantity",), 2)]))


def test_weak_token_needs_a_token_or_session_endpoint():
    assert "R-WEAK-TOKEN-ENTROPY-JSON" in _ids(
        _whole("application/json", url=BASE + "/api/session/refresh"))
    assert "R-WEAK-TOKEN-ENTROPY-JSON" in _ids(
        _whole("application/json", url=BASE + "/oauth/token"))
    assert "R-WEAK-TOKEN-ENTROPY-JSON" not in _ids(
        _whole("application/json", url=BASE + "/api/comments"))


def test_a_whole_xml_body_draws_xxe_and_a_multipart_body_upload():
    assert "xxe" in _cats(_whole("application/xml"))
    assert "xxe" in _cats(_whole("application/soap+xml"))
    assert "unrestricted-file-upload" in _cats(_whole("multipart/form-data; boundary=x"))
    assert "xxe" not in _cats(_q("q"))


def test_a_json_leaf_point_keeps_its_leaf_rules_and_draws_no_whole_body_rule():
    leaf = InjectionPoint(url=BASE + "/api/items", param="name", method="POST",
                          location="json", base_entries=((("name",), "a"),))
    ids = _ids(leaf)
    assert "R-SQLI-PARAM" in ids and "R-NOSQLI-JSON" in ids
    assert not ids & {"R-MASS-ASSIGNMENT-JSON", "R-INSECURE-DESERIALIZATION-JSON"}


@pytest.mark.parametrize("ctype,family", [
    ("application/json", "json"), ("application/json; charset=utf-8", "json"),
    ("application/vnd.api+json", "json"), ("application/xml", "xml"),
    ("text/xml", "xml"), ("application/soap+xml", "xml"),
    ("application/x-www-form-urlencoded", "form"),
    ("multipart/form-data; boundary=a", "multipart"), ("text/plain", None), (None, None),
    ("", None), (b"application/json", None)])
def test_media_family(ctype, family):
    assert media_family(ctype) == family


# --- importer and point builder (FR-CORE-672) ----------------------------------------

def _import(tmp_path, requests):
    from tests.test_json_points import _import as imp
    return imp(tmp_path, requests)


def _req(url, body, content_type="application/json", method="POST"):
    from tests.test_json_points import _req as req
    return req(url, body, method=method, content_type=content_type)


def test_a_captured_json_request_gets_a_whole_body_point_with_its_own_media_type(tmp_path):
    from fuzzlab.harness.auto import injection_points_from_store
    from tests.test_json_points import BASE as JB
    store, run, counts = _import(tmp_path, [
        _req(JB + "api/cart", {"item": "pen", "unitPrice": 3},
             content_type="application/vnd.api+json; charset=utf-8")])
    with store:
        pts = {p.param: p for p in injection_points_from_store(store, run, JB, skipped=[])}
    whole = pts["body"]
    assert whole.location == "body" and whole.body_content_type == "application/vnd.api+json"
    assert dict(whole.base_entries)[("unitPrice",)] == 3
    assert pts["item"].location == "json" and pts["item"].body_content_type is None
    assert counts["request_json"] == 1


def test_a_body_with_a_password_leaf_gets_no_whole_body_point(tmp_path):
    from tests.test_json_points import BASE as JB
    from tests.test_json_points import _params
    store, run, _c = _import(tmp_path, [_req(JB + "api/profile",
                                             {"email": "a@b.c", "pass": "x"})])
    with store:
        assert "body" not in _params(store, run)


def test_a_captured_xml_request_is_a_whole_body_point_and_its_body_is_never_stored(tmp_path):
    from fuzzlab.harness.auto import injection_points_from_store
    from tests.test_json_points import BASE as JB
    from tests.test_json_points import _all_text
    doc = "<contact><name>secret-name-1234</name></contact>"
    store, run, counts = _import(tmp_path, [_req(JB + "contact.php", json.dumps(doc),
                                                 content_type="text/xml")])
    with store:
        pts = injection_points_from_store(store, run, JB, skipped=[])
        text = _all_text(store)
    assert [(p.param, p.location, p.body_content_type, p.base_entries) for p in pts] == \
        [("body", "body", "text/xml", None)]
    assert counts["request_xml"] == 1 and "secret-name-1234" not in text


def test_a_captured_xml_request_on_a_destructive_url_is_refused(tmp_path):
    from tests.test_json_points import BASE as JB
    _store, _run, counts = _import(tmp_path, [_req(JB + "logout", json.dumps("<a/>"),
                                                   content_type="application/xml")])
    assert counts["request_refused"] == 1 and counts["request_xml"] == 0


# --- FR-AUD-706: R-SSJS on the target's own evidence ---------------------------------

@pytest.mark.parametrize("headers,want", [
    ({"X-Powered-By": "Express"}, "javascript"),                  # NodeGoat (measured)
    ({"X-Powered-By": "Next.js"}, "javascript"),
    ({"Set-Cookie": "connect.sid=s%3Aabc; Path=/; HttpOnly"}, "javascript"),
    ({"X-Powered-By": "PHP/8.5.11", "Server": "Apache/2.4.68 (Debian)"}, "php"),  # Mutillidae
    ({"Set-Cookie": "PHPSESSID=abc; path=/"}, "php"),
    ({"Set-Cookie": "JSESSIONID=abc; Path=/"}, "java"),
    ({"Server": "nginx"}, None), ({}, None), (None, None),
    ({"X-Powered-By": "Express", "Set-Cookie": "PHPSESSID=1"}, None),   # two: unknown
])
def test_server_language_reads_only_the_answers_own_headers(headers, want):
    assert server_language(headers) == want


def test_ssjs_fires_only_on_evidence_the_server_runs_javascript():
    point = _q("q")
    assert "R-SSJS" in _ids(point, {"server_language": "javascript"})
    assert "R-SSJS" not in _ids(point, {"server_language": "php"})
    assert "R-SSJS" not in _ids(point, {"server_language": None})
    assert "R-SSJS" not in _ids(point)


def test_the_pipeline_reads_the_language_from_its_baseline_probe(tmp_path):
    from fuzzlab.core.runmode import RunPlan
    from fuzzlab.core.store import Store
    from fuzzlab.harness.pipeline import run_pipeline
    from fuzzlab.oracle.probe import Probe

    class _Sender:
        def __init__(self, headers):
            self.headers = headers

        def send(self, url, param, value, timing=False, **kw):
            return Probe(status=200, text="ok", headers=dict(self.headers))

    plan = RunPlan(mode="manual", categories=["server-side-javascript-injection"],
                   scored=False, source="manual")
    out = {}
    for name, headers in (("node", {"X-Powered-By": "Express"}),
                          ("php", {"X-Powered-By": "PHP/8.5.11"})):
        with Store(tmp_path / f"{name}.db") as store:
            run = store.start_run("auto", "127.0.0.1")
            result = run_pipeline([InjectionPoint(url=BASE + "/a", param="q")], store, run,
                                  _Sender(headers), plan)
            fp = json.loads(store.conn.execute(
                "SELECT fingerprint FROM target WHERE run_id=?", (run,)).fetchone()[0])
            out[name] = (result.candidates, fp["server_language"])
    assert out == {"node": (1, "javascript"), "php": (0, "php")}
