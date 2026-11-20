"""GraphQL variables as injection points (CC-AUD-0600/0601, CC-CRAWL-0600/0601,
FR-AUD-600/601, FR-CRAWL-600/601).

* `tools.apiop.graphql_variable_bindings` / `graphql_variable_types`: which field
  argument a variable feeds, and the type it is declared with, read from the request's
  own document (linear, total on hostile input);
* `audit.graphql_context`: a JSON-leaf point under ``variables`` is judged by the
  argument it feeds; the document leaf and a variable declared Int/Float/Boolean are not
  data points;
* `audit.rules`: a GraphQL variable gets only the generic rules, by its own and its
  argument's name (CC-AUD-0602: no rule reads a target's field names); nothing changes
  for a body that is not a GraphQL request (every other lab's ground-truth points,
  swept).
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from fuzzlab.audit import graphql_context
from fuzzlab.audit.engine import InjectionPoint
from fuzzlab.audit.rules import Rule, RuleError, load_rules, matches, validate_rule
from fuzzlab.core import jsonbody
from fuzzlab.labels import contract
from fuzzlab.tools.apiop import (MAX_BINDINGS, graphql_variable_bindings,
                                 graphql_variable_types)

REPO = Path(__file__).resolve().parent.parent
DVGA_GT = REPO / "lab" / "ground-truth-dvga"

IMPORT = ("mutation ImportPaste ($host: String!, $port: Int!, $path: String!, "
          "$scheme: String!) {\n  importPaste(host: $host, port: $port, path: $path, "
          "scheme: $scheme) {\n    result\n  }\n}")


# --- the reader (CRAWL) ---------------------------------------------------------------

def test_a_variable_is_bound_to_the_field_argument_it_feeds_with_its_siblings():
    got = graphql_variable_bindings(IMPORT)
    assert got["path"] == [("importPaste", "path", ("host", "port", "scheme"))]
    assert set(got) == {"host", "port", "path", "scheme"}


def test_an_alias_a_nested_field_and_an_input_object_resolve_to_the_field_argument():
    got = graphql_variable_bindings(
        "query { a: pastes(filter: $f, limit: 3) { owner(x: {y: [$z]}) { name } } }")
    assert got == {"f": [("pastes", "filter", ("limit",))], "z": [("owner", "x", ())]}


def test_definitions_directives_and_literals_are_not_uses():
    assert graphql_variable_bindings(
        'query Q($c: Boolean, $u: String) { x @include(if: $c) { y(q: "$u") } }') == {}


def test_the_operation_name_selects_the_operation():
    doc = "query A { a(x: $p) } query B { b(y: $p) }"
    assert graphql_variable_bindings(doc, "B") == {"p": [("b", "y", ())]}
    assert graphql_variable_bindings(doc) == {"p": [("a", "x", ()), ("b", "y", ())]}


@pytest.mark.parametrize("text", ["shoes", "", "not graphql {", "{ a(x: $v ", None, 7,
                                  '{ a(x: "unterminated) }'])
def test_a_body_that_is_no_executable_document_has_no_bindings(text):
    assert graphql_variable_bindings(text) is None or graphql_variable_bindings(text) == {}
    assert graphql_variable_types(text) in (None, {})


def test_bindings_are_bounded():
    doc = "{ " + " ".join(f"f{i}(a: $v{i})" for i in range(MAX_BINDINGS + 50)) + " }"
    got = graphql_variable_bindings(doc)
    assert sum(len(v) for v in got.values()) == MAX_BINDINGS


def test_declared_types_are_read_with_their_list_depth():
    assert graphql_variable_types(IMPORT) == {"host": ("String", 0), "port": ("Int", 0),
                                              "path": ("String", 0),
                                              "scheme": ("String", 0)}
    assert graphql_variable_types("query A($x: [[Int!]]!) { a(x: $x) } "
                                  "query B($y: ID) { b(y: $y) }", "B") == {"y": ("ID", 0)}
    assert graphql_variable_types("{ a }") == {}


def test_the_reader_runs_in_linear_time_on_a_long_hostile_document():
    """PA-0559(14): a value the target writes is read in linear time -- a child process
    under a time bound, on runs of every repeated construct."""
    code = textwrap.dedent("""
        import time
        from fuzzlab.tools.apiop import graphql_variable_bindings, graphql_variable_types
        n = 4000
        docs = ["query Q(" + "$a: [" * n + "Int" + "]" * n + ") { a }",
                "{ " + "f(a: {b: " * n + "$v" + "})" * n + " }",
                "{ " + "f(a: $v) " * n + "}",
                "query q(" + "$v: String " * n + ") { " + "x @d(a: $v) " * n + "}",
                "{ " + "query(a: $v) " * n + "}"]
        t = time.monotonic()
        for d in docs:
            graphql_variable_bindings(d)
            graphql_variable_types(d)
        print(time.monotonic() - t)
    """)
    res = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                         text=True, timeout=60)
    assert res.returncode == 0, res.stderr[-2000:]
    assert float(res.stdout.strip()) < 10.0


# --- the audit context ------------------------------------------------------------------

def _gt_point(point) -> InjectionPoint:
    """A ground-truth point as `harness.auto` builds it (FR-FUZZ-54)."""
    entries = None
    location = point.location
    if point.json_body is not None and point.location == "body":
        location = jsonbody.LOCATION
        entries = tuple(jsonbody.leaves(point.json_body) or ())
    return InjectionPoint(url=point.url, param=point.param, method=point.method,
                          location=location, base_entries=entries, origin="ground-truth")


def _dvga_points() -> dict[str, InjectionPoint]:
    return {p.param: _gt_point(p) for p in contract.load(DVGA_GT).points}


def _fired(point, rules=None) -> set[str]:
    return {r.id for r in (rules or load_rules()) if matches(r, point)}


def test_no_rule_names_a_field_argument_or_value_of_any_target():
    """Owner directive (2026-11-20): detection is black-box. No rule's predicate reads a
    GraphQL field or a sibling argument (a lab-derived heuristic was removed, F-602); a
    GraphQL variable gets only the generic rules, judged by its own and its argument's
    name."""
    from fuzzlab.audit.rules import WHEN_KEYS
    assert not {k for k in WHEN_KEYS if k.startswith("graphql")}
    assert not [r.id for r in load_rules() if "GRAPHQL" in r.id]


def test_a_dvga_variable_gets_the_generic_rules_by_its_argument_name():
    pts = _dvga_points()
    cmdi = {r.id for r in load_rules() if r.category == "command-injection"}
    assert _fired(pts["variables.cmd"]) & cmdi          # `cmd`: the generic name rule
    assert _fired(pts["variables.host"]) & cmdi         # `host`
    # no name signal: no command-injection candidate (a stated miss, CC-AUD-0602)
    for param in ("variables.arg", "variables.path", "variables.scheme",
                  "variables.filter", "variables.title", "variables.filename"):
        assert not _fired(pts[param]) & cmdi, param
    assert "R-SQLI-PARAM" in _fired(pts["variables.filter"])


def test_a_variable_is_named_by_the_argument_it_feeds():
    doc = "mutation M($h: String!) { importPaste(host: $h) { result } }"
    pt = InjectionPoint(url="u", param="variables.h", method="POST", location="json",
                        base_entries=((("query",), doc), (("variables", "h"), "127.0.0.1")))
    assert graphql_context.argument_names(pt) == ("host",)
    assert "R-COMMAND-INJECTION" in _fired(pt)


def test_the_document_and_a_non_string_scalar_variable_are_not_data_points():
    doc = ("mutation CreatePaste ($title: String!, $public: Boolean!, $n: Int, "
           "$tags: [Int], $k: ID) { createPaste(title: $title, public: $public, n: $n, "
           "tags: $tags, k: $k) { paste { id } } }")
    entries = ((("query",), doc), (("variables", "title"), "a"),
               (("variables", "public"), True), (("variables", "n"), 1),
               (("variables", "tags"), []), (("variables", "k"), "1"))
    rules = load_rules()
    for param, data in (("query", False), ("variables.public", False), ("variables.n", False),
                        ("variables.title", True), ("variables.tags", True),
                        ("variables.k", True)):
        pt = InjectionPoint(url="u", param=param, method="POST", location="json",
                            base_entries=entries)
        assert (graphql_context.not_a_data_point(pt) is None) is data, param
        assert bool(_fired(pt, rules)) is data, param


def test_a_rest_body_with_a_query_field_is_untouched():
    pt = InjectionPoint(url="u", param="query", method="POST", location="json",
                        base_entries=((("query",), "shoes"),))
    assert graphql_context.not_a_data_point(pt) is None
    assert graphql_context.bindings(pt) == ()
    assert "R-SQLI-PARAM" in _fired(pt)


def is_graphql_request(point) -> bool:
    """A ground-truth point whose JSON body is a GraphQL request: its ``query`` parses
    as an executable GraphQL document (the property, not the lab, BUG-0720)."""
    from fuzzlab.tools.apiop import graphql_variable_types
    body = getattr(point, "json_body", None)
    doc = body.get("query") if isinstance(body, dict) else None
    return isinstance(doc, str) and graphql_variable_types(
        doc, body.get("operationName")) is not None


def test_the_graphql_request_test_is_a_property_of_the_body():
    gql = contract.InjectionPoint("/x", "POST", "variables.id", "body",
                                  json_body={"query": "query Q($id: String) { a(id: $id) }",
                                             "variables": {"id": "1"}})
    rest = contract.InjectionPoint("/x", "POST", "query", "body",
                                   json_body={"query": "shoes", "page": "1"})
    assert is_graphql_request(gql) and not is_graphql_request(rest)


def test_no_other_labs_ground_truth_point_has_a_graphql_context():
    """Nothing changes for a body that is not a GraphQL request: every ground-truth
    point of every lab whose body is not a GraphQL request (as the harness builds it)
    has no binding and is a data point, so its rule outcomes are what they were.
    GraphQL requests are told by their body, never by which lab carries them: a second
    lab's GraphQL points broke a list that named one (BUG-0720)."""
    seen = 0
    for gt in sorted((REPO / "lab").glob("ground-truth*/injection-points.json")):
        for p in contract.load_injection_points(gt.parent):
            if is_graphql_request(p):
                continue
            pt = _gt_point(p)
            assert graphql_context.bindings(pt) == (), (gt.parent.name, p.param)
            assert graphql_context.not_a_data_point(pt) is None, (gt.parent.name, p.param)
            seen += 1
    assert seen > 50


def test_a_regex_that_does_not_compile_is_refused_at_load():
    with pytest.raises(RuleError):
        validate_rule(Rule("R-X", "command-injection", "x", {"name_regex": "("}))
    with pytest.raises(RuleError):
        validate_rule(Rule("R-X", "command-injection", "x", {"graphql_field_regex": "a"}))
