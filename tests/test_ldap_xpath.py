"""LDAP filter injection and XPath injection (FR-FUZZ-620, FR-FUZZ-621; CC-FUZZ-0620,
CC-FUZZ-0621): the two boolean differentials, their wiring end to end (labels schema,
category map, rule, strategy registry, scoring), and the evidence they keep.

Fake servers stand for the target, each modelled on what the real Mutillidae II 2.12.8
pages answered (measured live, CC-FUZZ-0620): an OR filter over a small directory, an
XPath login over an XML document, a SQL sink, a page that rejects the probes'
characters, an encoding (level 5) sink, and a noisy page."""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

import pytest

from fuzzlab.oracle.ldap_xpath import (LDAP_ERROR_SIGNATURES, LdapFilterInjectionStrategy,
                                       XPathInjectionStrategy, _corroboration)
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import ENGINE_ROUNDS, FAMILY_COST, SqliBooleanStrategy

REPO = Path(__file__).resolve().parent.parent
ROOMS = ["1F104", "2F204", "Joes Place"]
USERS = [("admin", "adminpass"), ("adrian", "somepassword")]


# --- fake LDAP sink -------------------------------------------------------------------

def _ldap_items(value: str) -> list[tuple[str, str]]:
    """The filter items ``(|(cn=2F204)(cn=<value>))`` holds, or raise on a bad filter
    (unbalanced parentheses), as ldap_search() does."""
    flt = f"(|(cn=2F204)(cn={value}))"
    depth = 0
    for ch in flt:
        depth += ch == "("
        depth -= ch == ")"
        if depth < 0:
            raise ValueError("Bad search filter")
    if depth:
        raise ValueError("Bad search filter")
    return re.findall(r"\((\w+)=([^()]*)\)", flt)


def _ldap_match(attr: str, pattern: str, entry: dict) -> bool:
    vals = entry.get(attr, [])
    if pattern == "*":
        return bool(vals)
    rx = "^" + ".*".join(re.escape(p) for p in pattern.split("*")) + "$"
    return any(re.match(rx, v) for v in vals)


class _LdapServer:
    """Mutillidae's conference-room lookup: an OR filter (``ldap``), the value encoded
    first (``encoded``, level 5), a page that rejects ``*`` and parentheses
    (``reject``), or random answers (``noise``)."""

    def __init__(self, mode="ldap"):
        self.mode, self.values = mode, []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        self.values.append(value)
        if self.mode == "noise":
            return Probe(200, random.choice(["rooms: 2F204", "rooms: 1F104 2F204"]), 0.0)
        if self.mode == "reject" and re.search(r"[*()]", value):
            return Probe(200, "Malicious characters are not allowed", 0.0)
        if self.mode == "encoded":
            value = "".join(c if c.isalnum() else "\\%02x" % ord(c) for c in value)
        try:
            items = _ldap_items(value)
        except ValueError:
            return Probe(200, "Warning: ldap_search(): Search: Bad search filter", 0.0)
        entries_ = [{"cn": [r], "objectClass": ["room"]} for r in ROOMS]
        hits = [e["cn"][0] for e in entries_ if any(_ldap_match(a, p, e) for a, p in items)]
        return Probe(200, "These rooms are available: " + " ".join(hits), 0.0)


def _ldap_cand(**kw):
    return Candidate(url="http://127.0.0.1:9/index.php?page=conference-room-lookup.php",
                     param="default_room_common_name", method="POST", location="body",
                     category="ldap-injection", **kw)


def test_the_ldap_differential_confirms_an_or_filter():
    server = _LdapServer()
    v = LdapFilterInjectionStrategy().confirm(_ldap_cand(), server)
    assert v is not None and v.confirmed and v.vuln_class == "ldap_injection"
    assert v.evidence["family"] == "or-presence"
    assert v.evidence["rounds"] == 1 + ENGINE_ROUNDS and v.evidence["requests"] == FAMILY_COST
    # V and D share their characters: only the filter grammar tells them apart
    keep, disc = v.evidence["keep"], v.evidence["disc"]
    assert set(re.sub(r"[0-9a-f]", "", disc)) <= set(re.sub(r"[0-9a-f]", "", keep)) | {"z", "q", "l"}
    assert keep.endswith("*") and disc.endswith(")(objectClass=*")


@pytest.mark.parametrize("mode", ["encoded", "reject", "noise"])
def test_the_ldap_differential_gives_no_verdict_where_the_filter_is_not_evaluated(mode):
    random.seed(7)
    assert LdapFilterInjectionStrategy().confirm(_ldap_cand(), _LdapServer(mode)) is None


def test_the_ldap_differential_is_skipped_on_a_raw_body_point():
    server = _LdapServer()
    assert LdapFilterInjectionStrategy().confirm(
        _ldap_cand(content_type="application/json"), server) is None
    assert server.values == []


# --- fake XPath sink ------------------------------------------------------------------

_LEN = re.compile(r"string-length\('([^']*)'\)=(\d+)")
_EQ = re.compile(r"'([^']*)'='([^']*)'")


def _xpath_eval(value: str, other: str, *, param: str) -> str:
    """A tiny model of ``//Employee[UserName='U' and Password='P']`` over a document of
    ``<Account>`` elements (Mutillidae after set-up-database.php): a predicate selects
    nothing (wrong element), a union selects every node."""
    u, p = (value, other) if param == "username" else (other, value)
    query = f"//Employee[UserName='{u}' and Password='{p}']"
    if query.count("'") % 2:
        return "Warning: SimpleXMLElement::xpath(): Invalid predicate"
    if "] | //*[" in query:
        union = query.split("] | //*[", 1)[1]
        truth = any(int(n) == len(s) for s, n in _LEN.findall(union)) or \
            any(a == b for a, b in _EQ.findall(union))
        return "<Account>admin</Account><Account>adrian</Account>" if truth else ""
    return ""                                   # no <Employee> element: nothing matches


class _XPathServer:
    def __init__(self, mode="xpath", param="username"):
        self.mode, self.param, self.values = mode, param, []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        self.values.append(value)
        if self.mode == "sql":
            # MariaDB: string-length() is `string - length()` -> unknown column; a quote
            # alone is a syntax error; a balanced literal matches nothing
            if "string-length" in value or value.count("'") % 2:
                return Probe(200, "You have an error in your SQL syntax", 0.0)
            return Probe(200, "Results for " + value + ": 0 records", 0.0)
        if self.mode == "encoded":
            value = value.replace("'", "&apos;")
        out = _xpath_eval(value, "zz", param=self.param)
        return Probe(200, f"Results for {value}. Executed query: ... {out}", 0.0)


def _xp_cand(param="username", **kw):
    return Candidate(url="http://127.0.0.1:9/index.php?page=user-info-xpath.php",
                     param=param, category="xpath-injection", **kw)


@pytest.mark.parametrize("param", ["username", "password"])
def test_the_xpath_differential_confirms_through_a_union(param):
    v = XPathInjectionStrategy().confirm(_xp_cand(param), _XPathServer(param=param))
    assert v is not None and v.confirmed and v.vuln_class == "xpath_injection"
    # the predicate family selects nothing on this document; the union does
    assert v.evidence["family"] == "string-union"
    assert v.evidence["requests"] == 3 + FAMILY_COST


@pytest.mark.parametrize("mode", ["sql", "encoded"])
def test_the_xpath_differential_gives_no_verdict_on_a_sql_or_encoded_sink(mode):
    assert XPathInjectionStrategy().confirm(_xp_cand(), _XPathServer(mode)) is None


def test_the_sql_boolean_probe_does_not_confirm_the_xpath_sink():
    """The classes stay apart: SQL's grammar probes (AND, LIKE) are no XPath."""
    assert SqliBooleanStrategy().confirm(
        Candidate(url="http://127.0.0.1:9/x", param="username", category="sql-injection"),
        _XPathServer()) is None


def test_the_ldap_and_xpath_probes_do_not_cross():
    assert LdapFilterInjectionStrategy().confirm(_ldap_cand(), _XPathServer()) is None
    assert XPathInjectionStrategy().confirm(_xp_cand(), _LdapServer()) is None


def test_an_error_signature_is_corroboration_only():
    """FR-FUZZ-620: an error alone never confirms (the screen fails first), and a
    signature already on the baseline is not counted."""
    assert _corroboration(["x ldap_search(): Search: Bad search filter"], "",
                          LDAP_ERROR_SIGNATURES) == ["Bad search filter", "ldap_search()"]
    assert _corroboration(["Bad search filter"], "Bad search filter",
                          LDAP_ERROR_SIGNATURES) == []

    class _Errors:                     # every probe errors, the base does not
        def send(self, url, param, value, **kw):
            return Probe(200, "ok" if value.isalnum() else "Bad search filter", 0.0)
    assert LdapFilterInjectionStrategy().confirm(_ldap_cand(), _Errors()) is None


# --- wiring (PA-0042, PA-0047: derived from the sources, never restated) ------------------

def test_both_classes_are_wired_end_to_end():
    from fuzzlab.audit.rules import load_rules
    from fuzzlab.core.runmode import to_category
    from fuzzlab.oracle.strategies import category_to_oracle_class, default_strategies
    schema = json.loads((REPO / "fuzzlab/labels/schemas/labels.schema.json").read_text())
    case = schema["$defs"]["case"]["properties"]
    ruled = {r.category for r in load_rules()}
    registered = {s.vuln_class: s for s in default_strategies()}
    for strategy, sink in ((LdapFilterInjectionStrategy, "ldap"),
                           (XPathInjectionStrategy, "xpath")):
        vc, cat = strategy.vuln_class, strategy.category
        assert "-" not in vc and vc in case["vuln_class"]["enum"]          # PA-0047(2)
        assert sink in case["sink_context"]["enum"]
        assert to_category(vc) == cat and category_to_oracle_class(cat) == vc
        assert cat in ruled
        assert isinstance(registered[vc], strategy)


def test_the_mutillidae_key_scores_both_classes_with_positives_and_negatives():
    from fuzzlab.labels import contract
    gt = contract.load(REPO / "lab" / "ground-truth-mutillidae")
    for vc in ("ldap_injection", "xpath_injection"):
        assert any(c.vuln_class == vc for c in gt.positives()), vc
        assert any(c.vuln_class == vc for c in gt.negatives()), vc
