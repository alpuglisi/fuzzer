"""GraphQL schema discovery in a discovery run (FR-CRAWL-671, CC-CRAWL-0670).

The run asks each GraphQL endpoint the app itself used for its schema (one bounded
introspection request through the probe sender), and imports the schema's operations
as captured requests: every import refusal applies (a destructive mutation is never a
point). The schemas here are invented; nothing names a lab.
"""

from __future__ import annotations

import json

from fuzzlab.core.store import Store
from fuzzlab.harness.auto import injection_points_from_store
from fuzzlab.harness.auto_cli import graphql_schema_discovery
from fuzzlab.oracle.probe import Probe
from fuzzlab.tools import gqlschema
from fuzzlab.tools.store_adapter import (
    MAX_SCHEMA_ENDPOINTS,
    _store_request,
    captured_request,
    graphql_endpoints,
    import_graphql_schema,
)

BASE = "http://127.0.0.1:9"


def _t(kind, name=None, of=None):
    return {"kind": kind, "name": name, "ofType": of}


def _schema_answer() -> str:
    string, ident = _t("SCALAR", "String"), _t("SCALAR", "ID")
    return json.dumps({"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "bookSearch", "args": [{"name": "text", "type": string}],
                 "type": _t("LIST", None, _t("OBJECT", "Book"))},
                {"name": "shelf", "args": [{"name": "label", "type": ident}],
                 "type": _t("OBJECT", "Book")},
                {"name": "count", "args": [], "type": _t("SCALAR", "Int")}]},
            {"kind": "OBJECT", "name": "Mutation", "fields": [
                {"name": "addReview", "args": [{"name": "body", "type": string}],
                 "type": _t("SCALAR", "Boolean")},
                {"name": "deleteBook", "args": [{"name": "code", "type": ident}],
                 "type": _t("SCALAR", "Boolean")}]},
            {"kind": "OBJECT", "name": "Book", "fields": [
                {"name": "title", "args": [], "type": string}]},
            {"kind": "SCALAR", "name": "String"}, {"kind": "SCALAR", "name": "ID"},
            {"kind": "SCALAR", "name": "Int"}, {"kind": "SCALAR", "name": "Boolean"}]}}})


def _capture(st, run, url, body, page=BASE + "/app"):
    row = {"url": url, "method": "POST", "content_type": "application/json",
           "body_json": json.dumps(body), "page_url": page}
    reason, kind, leaves = captured_request(row)
    assert reason is None, reason
    counts = {"request_json": 0, "request_form": 0, "parameter": 0}
    _store_request(st, run, counts, kind, "POST", url, leaves, main=BASE, page=page)


class _Sender:
    def __init__(self, answer=None, status=200, raises=None):
        self.answer, self.status, self.raises = answer, status, raises
        self.sent = []

    def send(self, url, param, value, **kw):
        self.sent.append((url, param, value, kw))
        if self.raises is not None:
            raise self.raises
        return Probe(status=self.status, text=self.answer or "")


def _store(tmp_path):
    st = Store(tmp_path / "s.db")
    run = st.start_run("auto", "localhost")
    _capture(st, run, BASE + "/gq",
             {"query": "query Recent { recent { title } }", "variables": {}})
    _capture(st, run, BASE + "/api/cart", {"item": "x", "qty": 1})   # not GraphQL
    return st, run


def test_only_an_endpoint_the_app_sent_a_graphql_document_is_asked(tmp_path):
    st, run = _store(tmp_path)
    with st:
        assert [u for u, _p in graphql_endpoints(st, run)] == ["/gq"]
        sender = _Sender(_schema_answer())
        counts = graphql_schema_discovery(st, run, sender, BASE)
        assert len(sender.sent) == 1                       # one request per endpoint
        url, param, value, kw = sender.sent[0]
        assert url == BASE + "/gq" and param == "query"
        assert value == gqlschema.INTROSPECTION_QUERY
        assert kw["method"] == "POST" and kw["location"] == "json"
        assert counts["graphql_schema_endpoint"] == 1


def test_schema_operations_become_points_and_a_destructive_mutation_never(tmp_path):
    st, run = _store(tmp_path)
    with st:
        counts = graphql_schema_discovery(st, run, _Sender(_schema_answer()), BASE)
        # bookSearch, shelf, addReview built; deleteBook refused by the import rules
        assert counts["graphql_schema_operation"] == 3
        assert counts["graphql_schema_refused"] == 1
        points = injection_points_from_store(st, run, BASE)
        params = {(p.param, next((v for n, v in p.base_entries
                                  if tuple(n) == ("operationName",)), None))
                  for p in points if p.url == BASE + "/gq"}
        assert ("variables.text", "FuzzlabBookSearch") in params
        assert ("variables.label", "FuzzlabShelf") in params
        assert ("variables.body", "FuzzlabAddReview") in params
        assert not any(op == "FuzzlabDeleteBook" for _n, op in params)


def test_no_answer_or_an_unreadable_one_imports_nothing(tmp_path):
    for sender, key in ((_Sender(raises=RuntimeError("refused")), "graphql_schema_send_failed"),
                        (_Sender("nope", status=403), "graphql_schema_not_ok"),
                        (_Sender('{"errors": [{"message": "off"}]}'),
                         "graphql_schema_unreadable")):
        (tmp_path / key).mkdir()
        st, run = _store(tmp_path / key)
        with st:
            before = st.conn.execute("SELECT COUNT(*) FROM parameter").fetchone()[0]
            counts = graphql_schema_discovery(st, run, sender, BASE)
            assert counts[key] == 1
            assert st.conn.execute(
                "SELECT COUNT(*) FROM parameter").fetchone()[0] == before


def test_at_most_max_schema_endpoints_are_asked(tmp_path):
    st = Store(tmp_path / "m.db")
    run = st.start_run("auto", "localhost")
    with st:
        for i in range(MAX_SCHEMA_ENDPOINTS + 2):
            _capture(st, run, f"{BASE}/g{i}", {"query": "{ a }"})
        assert len(graphql_endpoints(st, run)) == MAX_SCHEMA_ENDPOINTS


def test_import_is_pure_on_the_answer(tmp_path):
    st, run = _store(tmp_path)
    with st:
        counts = import_graphql_schema(st, run, BASE + "/gq", _schema_answer(), main=BASE,
                                       kinds=("query",))
        assert counts["graphql_schema_operation"] == 2
        assert counts["graphql_schema_refused"] == 0


def test_a_subpath_base_joins_stored_endpoints_to_its_origin_only(tmp_path):
    """A base URL under a sub-path (``/app/``): a stored endpoint path is absolute
    (``/app/gq``), so it joins the base's origin, never its path (BUG-0113)."""
    st = Store(tmp_path / "sp.db")
    run = st.start_run("auto", "localhost")
    with st:
        _capture(st, run, BASE + "/app/gq", {"query": "{ a }"})
        sender = _Sender(_schema_answer())
        graphql_schema_discovery(st, run, sender, BASE + "/app/")
        assert [u for u, *_x in sender.sent] == [BASE + "/app/gq"]


def test_the_run_summary_prints_the_schema_and_store_render_counts(capsys):
    """CC-LAB-0410's measurement found the counts only in the parameter total."""
    from types import SimpleNamespace

    from fuzzlab.harness import auto_cli
    result = SimpleNamespace(
        plan=SimpleNamespace(mode="automatic", scored=False, categories=[], source="crawl"),
        metrics={}, points_audited=0, candidates=0, negatives=0, findings=0, report=None,
        plugin_outcomes=[], inconclusive=[])
    counts = {"graphql_schema_endpoint": 1, "graphql_schema_operation": 11,
              "graphql_schema_skipped": 8, "store_render": 2, "store_render_skipped": 1,
              "parameter": 3}
    try:
        auto_cli._print_summary(SimpleNamespace(score=False, rank=False, anomaly=False),
                                counts, result)
    except (AttributeError, TypeError, KeyError):
        pass                       # lines after the counts read more of a real result
    out = capsys.readouterr().out
    assert ("graphql schema: 1 endpoint(s) asked, 11 operation(s) imported, 0 refused, "
            "8 skipped") in out
    assert "store->render pairs: 2 stored point(s), 1 skipped" in out
