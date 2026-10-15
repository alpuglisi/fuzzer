"""Capture-and-abort (DISC-CAPTURE; FR-CRAWL-18/19, FR-AUD-23, FR-FUZZ-52, FR-CORE-43).

Synthetic, technology-generic shapes only (no lab's routes, field names or code): a
fetch-JSON SPA, a form-encoded XHR, a multipart upload, GraphQL queries and mutations,
JSON-RPC, and the published long-poll transport protocols. Offline except the last
section, which drives a real loopback server through crawl, import and ``auto``.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from fuzzlab.core import redaction
from fuzzlab.core.store import Store
from fuzzlab.tools import capture, navguard, store_adapter

H = "http://127.0.0.1:8080"


# =====================================================================================
# The crawl-wide predicate (capture.capture_refusal)
# =====================================================================================
@pytest.mark.parametrize("method,url,nav,body,refused", [
    ("GET", f"{H}/catalog", True, None, None),               # a navigation: as before
    ("GET", f"{H}/api/items?page=2", False, None, None),     # a plain read
    ("HEAD", f"{H}/api/items", False, None, None),
    ("GET", f"{H}/api/orders/checkout", False, None, capture.WHY_GET_RULE),
    ("GET", f"{H}/api/account/password-reset", False, None, capture.WHY_GET_RULE),
    ("GET", f"{H}/x/delete?id=3", False, None, capture.WHY_GET_RULE),
    ("POST", f"{H}/api/items", False, b'{"a":1}', capture.WHY_WRITE),
    ("PUT", f"{H}/api/items/1", False, b'{"a":1}', capture.WHY_WRITE),
    ("DELETE", f"{H}/api/items/1", False, b"", capture.WHY_WRITE),
    ("POST", f"{H}/api/items", True, b"a=1", capture.WHY_WRITE),   # a form navigation
    ("POST", f"{H}/api/upload", False, None, capture.WHY_BODY_UNAVAILABLE),
    ("POST", f"{H}/api/big", False, b"x" * (capture.BODY_CAP + 1), capture.WHY_OVER_CAP),
    ("BREW", f"{H}/pot", False, b"", capture.WHY_METHOD),
    ("POST", f"{H}/graphql", False, b'{"query":"{ items { id } }"}', None),
    ("POST", f"{H}/graphql", False, b'{"query":"mutation { add { id } }"}',
     capture.WHY_WRITE),
    ("POST", f"{H}/graphql", False,
     b'{"extensions":{"persistedQuery":{"sha256Hash":"ab"}}}', capture.WHY_WRITE),
])
def test_the_capture_predicate(method, url, nav, body, refused):
    why = capture.capture_refusal(method, url, nav, body)
    if refused is None:
        assert why is None
    else:
        assert why is not None and why.startswith(refused), why


def test_only_the_sessions_own_refresh_endpoint_passes():
    from fuzzlab.core.urls import url_key
    refresh = frozenset({("POST", url_key(f"{H}/auth/refresh"))})
    assert capture.capture_refusal("POST", f"{H}/auth/refresh", False, b"{}",
                                   refresh=refresh) is None
    assert capture.capture_refusal("POST", f"{H}/auth/refresh", False, b"{}") is not None
    assert capture.capture_refusal("POST", f"{H}/auth/refresh2", False, b"{}",
                                   refresh=refresh) is not None


# =====================================================================================
# GraphQL by the published grammar (PA-0103: every ambiguity the lexer resolves)
# =====================================================================================
@pytest.mark.parametrize("doc,kinds", [
    ("{ a }", ["query"]),                                          # shorthand
    ("query Q { a }", ["query"]),
    ("query { mutation subscription }", ["query"]),                # keywords as fields
    ("# mutation { x }\nquery { a }", ["query"]),                  # a comment
    ('query { a(s: "mutation { x }") }', ["query"]),               # a string
    ('query { a(s: """ mutation\n { x } \\""" """) }', ["query"]),  # a block string
    ("query Q($v: In = {x: [1, 2]}) { a(v: $v) }", ["query"]),      # braces in a default
    ("query A { a } mutation B { b }", ["query", "mutation"]),
    ("fragment F on T { id } query { ...F }", ["fragment", "query"]),
    ("subscription { s }", ["subscription"]),
    ("query @dir(a: 1) { a }", ["query"]),
    ("﻿  ,, query { a }", ["query"]),                          # ignored tokens
])
def test_graphql_operations_follow_the_grammar(doc, kinds):
    assert capture.graphql_operations(doc) == kinds


@pytest.mark.parametrize("doc", [
    "", "   ", "type T { a: Int }", "schema { query: Q }", "query { a", "query { a } }",
    'query { a(s: "unterminated) }', 'query { a(s: """unterminated) }', "query { a ` }",
    "query Q", "x" * (capture.BODY_CAP + 1)])
def test_a_document_the_grammar_refuses_is_not_an_operation_list(doc):
    assert capture.graphql_operations(doc) is None


@pytest.mark.parametrize("body,read", [
    ({"query": "{ a }"}, True),
    ({"query": "query { a }", "variables": {"id": 1}, "operationName": "Q"}, True),
    ([{"query": "{ a }"}, {"query": "{ b }"}], True),               # a batch
    ([{"query": "{ a }"}, {"query": "mutation { b }"}], False),
    ({"query": "query A { a } mutation B { b }", "operationName": "A"}, False),
    ({"query": "fragment F on T { id }"}, False),                   # no operation
    ({"query": "subscription { s }"}, False),
    ({"extensions": {"persistedQuery": {}}}, False),
    ({"query": 3}, False), ([], False), ("text", False),
])
def test_a_graphql_read_is_query_operations_only(body, read):
    raw = json.dumps(body).encode() if not isinstance(body, str) else body.encode()
    assert capture.graphql_read_only(raw) is read


def test_the_op_key_names_one_operation_and_ignores_layout():
    assert capture.op_key({"query": "query A { a }", "operationName": "A"}) == "gql:A"
    one = capture.op_key({"query": "query { a  b }"})
    assert one.startswith("gql#") and one == capture.op_key(
        {"query": "# c\nquery {\n a\n b\n}"})
    assert one != capture.op_key({"query": "query { a c }"})
    assert capture.op_key({"jsonrpc": "2.0", "method": "items.list", "id": 1}) == \
        "rpc:items.list"
    assert capture.op_key({"a": 1}) == "" and capture.op_key("x") == ""
    assert capture.op_key([{"query": "{a}", "operationName": "A"},
                           {"jsonrpc": "2.0", "method": "m"}]) == "gql:A+rpc:m"


# =====================================================================================
# Long-poll transports by published markers (DISC-CAPTURE §7)
# =====================================================================================
@pytest.mark.parametrize("url,protocols,proto", [
    (f"{H}/socket.io/?EIO=4&transport=polling&t=N", (), "socket.io"),
    (f"{H}/ws/engine.io/?x=1", (), "socket.io"),
    (f"{H}/rt/?EIO=3&transport=polling", (), "socket.io"),
    (f"{H}/echo/123/abcdefgh/xhr_send", (), "sockjs"),
    (f"{H}/echo/007/s3ss10n/xhr", (), "sockjs"),
    (f"{H}/hub/negotiate?negotiateVersion=1", (), "signalr"),
    (f"{H}/hub?id=x&connectionToken=abc", (), "signalr"),
    (f"{H}/signalr/negotiate?clientProtocol=1.5", (), "signalr"),
    (f"{H}/socket/longpoll?vsn=2.0.0", (), "phoenix"),
    (f"{H}/cable", ("actioncable-v1-json",), "actioncable"),
    # generic app endpoints that only look alike: never transports
    (f"{H}/api/xhr", (), None), (f"{H}/a/b/xhr", (), None),
    (f"{H}/api/negotiate", (), None), (f"{H}/jobs/longpoll", (), None),
    (f"{H}/api/items?transport=bike", (), None), (f"{H}/cable", ("chat",), None),
])
def test_transports_are_recognised_by_published_markers_only(url, protocols, proto):
    assert capture.transport_protocol(url, protocols) == proto


# =====================================================================================
# The route hook (navguard.make_route_handler)
# =====================================================================================
class _Resp:
    status, headers = 200, {"content-type": "application/json"}


class _Req:
    def __init__(self, url, method="POST", body=b'{"a":1}', nav=False, boom=False):
        self.url, self.method, self.headers = url, method, {"content-type": "x/y"}
        self.resource_type = "document" if nav else "fetch"
        self._body, self._boom, self._nav = body, boom, nav
        self.frame = None

    @property
    def post_data_buffer(self):
        if self._boom:
            raise RuntimeError("the driver cannot show it")
        return self._body

    def is_navigation_request(self):
        return self._nav


class _Route:
    def __init__(self, req):
        self.request, self.outcome, self.fetched = req, None, 0

    def fetch(self, **_kw):
        self.fetched += 1
        return _Resp()

    def abort(self, code=None):
        self.outcome = "abort"

    def fulfill(self, **_kw):
        self.outcome = "fulfill"

    def continue_(self):
        self.outcome = "continue"


def _handler(recorded, **kw):
    from fuzzlab.core.urls import in_origin_scope, origin_scope
    scope = origin_scope(H + "/")
    return navguard.make_route_handler(
        in_scope=lambda u: in_origin_scope(u, scope),
        capture_refusal=kw.pop("capture_refusal", capture.capture_refusal),
        capture=lambda req, why: recorded.append((req.method, req.url, why)), **kw)


def test_a_write_is_recorded_and_aborted_never_fetched():
    got = []
    route = _Route(_Req(f"{H}/api/items"))
    _handler(got)(route)
    assert route.outcome == "abort" and route.fetched == 0
    assert got and got[0][:2] == ("POST", f"{H}/api/items")


def test_a_read_goes_out():
    got = []
    route = _Route(_Req(f"{H}/graphql", body=b'{"query":"{ a }"}'))
    _handler(got)(route)
    assert route.outcome == "fulfill" and route.fetched == 1 and got == []


@pytest.mark.parametrize("case", ["classifier raises", "body unreadable", "body None",
                                  "recorder raises"])
def test_capture_fails_closed(case):
    """DISC-CAPTURE §1: an error, an unreadable body or a failing recorder aborts; it
    is never sent."""
    got = []
    req = _Req(f"{H}/api/items", body=None if case == "body None" else b"{}",
               boom=case == "body unreadable")
    kw = {}
    if case == "classifier raises":
        kw["capture_refusal"] = lambda *_a: 1 / 0
    route = _Route(req)
    if case == "recorder raises":
        def bad(_req, _why):
            raise RuntimeError("disk full")
        navguard.make_route_handler(in_scope=lambda u: True,
                                    capture_refusal=capture.capture_refusal,
                                    capture=bad)(route)
    else:
        _handler(got, **kw)(route)
    assert route.outcome == "abort" and route.fetched == 0
    if case == "classifier raises":
        assert got[0][2].startswith(capture.WHY_FAILED)
    if case in ("body unreadable", "body None"):
        assert got[0][2].startswith(capture.WHY_BODY_UNAVAILABLE)


def test_an_out_of_scope_request_is_never_recorded():
    """BUG-0123/0134 confinement first: the hook runs after the scope check."""
    got = []
    route = _Route(_Req("http://127.0.0.1:9999/api/items"))
    _handler(got)(route)
    assert route.outcome == "abort" and got == []


def test_a_write_the_window_refused_is_recorded_a_get_navigation_is_not():
    got = []
    window = lambda m, u, n: "window open"                      # noqa: E731
    _handler(got, window=window)(_Route(_Req(f"{H}/api/w")))
    _handler(got, window=window)(_Route(_Req(f"{H}/next", method="GET", body=None,
                                             nav=True)))
    assert [(m, w.split(":")[0]) for m, _u, w in got] == [("POST", capture.WHY_WINDOW)]


def test_install_capture_script_adds_the_binding_and_the_script():
    calls = []

    class Ctx:
        def expose_binding(self, name, fn):
            calls.append(("binding", name))
            fn({"page": type("P", (), {"url": f"{H}/p"})()}, "/b", "k=v")
            fn(None, object(), object())                          # junk: contained

        def add_init_script(self, script):
            calls.append(("script", "sendBeacon" in script and "fetchLater" in script))
    seen = []
    navguard.install_capture_script(Ctx(), lambda u, b, p: seen.append((u, b, p)))
    assert calls == [("binding", capture.CAPTURE_BINDING), ("script", True)]
    assert seen[0] == ("/b", "k=v", f"{H}/p")


# =====================================================================================
# The redaction boundary for capture records (core.redaction, CC-CORE-0060)
# =====================================================================================
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2lnbmF0dXJl"


def test_known_session_secrets_are_scrubbed_by_value_wherever_they_appear():
    secrets = redaction.known_secrets([f"Bearer {JWT}", "short", "cookievalue123"])
    assert JWT in secrets and "short" not in secrets
    doc = {"t": JWT, "nested": [{"x": f"pre-{JWT}-post"}], JWT: 1, "ok": "keep"}
    out = redaction.scrub_secrets(doc, secrets)
    text = json.dumps(out)
    assert JWT not in text and "keep" in text
    assert not redaction.carries_secret(text, secrets)
    url = redaction.scrub_secrets_text(f"{H}/x?t={JWT}&c=cookievalue123", secrets)
    assert JWT not in url and "cookievalue123" not in url


def test_header_names_keep_values_only_for_the_allowlist():
    out = redaction.redact_header_names(
        {"Authorization": f"Bearer {JWT}", "Cookie": "sid=1", "Content-Type":
         "application/json", "Accept": "*/*", "X-Requested-With": "XMLHttpRequest",
         "X-Custom": "v"}, frozenset({JWT}))
    assert out == [["accept", "*/*"], ["authorization", None],
                   ["content-type", "application/json"], ["cookie", None],
                   ["x-custom", None], ["x-requested-with", "XMLHttpRequest"]]


def test_a_multipart_body_keeps_part_names_and_types_only():
    body = (b"--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nSECRETNOTE\r\n"
            b"--B\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"cv.pdf\"\r\n"
            b"Content-Type: application/pdf\r\n\r\n%PDF-SECRET\r\n--B--\r\n")
    shape, why = redaction.redact_multipart_shape(body, "multipart/form-data; boundary=B")
    assert why is None
    assert shape == [{"name": "note", "content_type": None},
                     {"name": "doc", "content_type": "application/pdf"}]
    assert "SECRET" not in json.dumps(shape) and "cv.pdf" not in json.dumps(shape)
    assert redaction.redact_multipart_shape(body, "multipart/form-data")[0] is None


def test_a_websocket_message_is_redacted_before_it_is_cut():
    """PA-0455: a secret straddling the 256-byte cut is still removed."""
    cut = redaction.WS_HEAD_BYTES
    text = "x" * (cut - 10) + JWT
    opcode, size, head = redaction.redact_ws_message(text, frozenset({JWT}))
    assert (opcode, size) == (1, len(text)) and JWT[:10] not in head
    _o, _s, head = redaction.redact_ws_message('42["login",{"password":"SECRETPW"}]')
    assert "SECRETPW" not in head and head.startswith("42[")
    assert redaction.redact_ws_message("password=hunter2")[2] is None   # fail closed
    assert redaction.redact_ws_message(b"\x00\x01")[2] is None           # binary: no head


# =====================================================================================
# The spider's capture records (StorageManager.record_request)
# =====================================================================================
def _sm(tmp_path):
    from fuzzlab.tools.spider import StorageManager
    return StorageManager(str(tmp_path / "s.db"))


def _rows(tmp_path, sql, params=()):
    con = sqlite3.connect(str(tmp_path / "s.db"))
    try:
        return con.execute(sql, params).fetchall()
    finally:
        con.close()


def test_one_url_with_two_operations_is_two_rows_and_a_repeat_is_one(tmp_path):
    sm = _sm(tmp_path)
    try:
        for name in ("ListItems", "GetItem", "GetItem"):
            body = json.dumps({"query": f"query {name} {{ a }}", "operationName": name,
                               "variables": {"id": 1}}).encode()
            sm.record_request(f"{H}/", "POST", f"{H}/graphql", "application/json", body,
                              "passive", source=capture.SOURCE_CAPTURED)
    finally:
        sm.close()
    assert sorted(_rows(tmp_path, "SELECT op_key FROM discovered_requests")) == [
        ("gql:GetItem",), ("gql:ListItems",)]


def test_a_capture_record_never_holds_a_session_secret(tmp_path):
    sm = _sm(tmp_path)
    secrets = redaction.known_secrets([JWT])
    try:
        assert sm.record_request(f"{H}/#/a?t={JWT}", "POST", f"{H}/api/x?t={JWT}",
                                 "application/json",
                                 json.dumps({"t": JWT, "note": "ok"}).encode(), "passive",
                                 source=capture.SOURCE_CAPTURED,
                                 headers={"Authorization": f"Bearer {JWT}"},
                                 secrets=secrets) is None
    finally:
        sm.close()
    assert JWT not in json.dumps(_rows(tmp_path, "SELECT * FROM discovered_requests"))


def test_a_secret_that_survives_redaction_refuses_the_row(tmp_path, monkeypatch):
    """Fail closed (PA-0101): if scrubbing missed a spelling, nothing is stored."""
    sm = _sm(tmp_path)
    monkeypatch.setattr(redaction, "scrub_secrets", lambda v, s: v)
    monkeypatch.setattr(redaction, "scrub_secrets_text", lambda v, s: v)
    try:
        why = sm.record_request(f"{H}/", "POST", f"{H}/api/x/{JWT}/y", "application/json",
                                b'{"note": "ok"}', "passive", secrets=frozenset({JWT}))
    finally:
        sm.close()
    assert why == "a session secret survived redaction"
    assert _rows(tmp_path, "SELECT * FROM discovered_requests") == []


def test_a_body_that_cannot_be_kept_keeps_the_request(tmp_path):
    sm = _sm(tmp_path)
    try:
        assert sm.record_request(f"{H}/", "POST", f"{H}/api/x", "text/plain",
                                 b"free text", "passive", source=capture.SOURCE_CAPTURED,
                                 keep_without_body=True) is None
        assert sm.last_omitted
    finally:
        sm.close()
    assert _rows(tmp_path, "SELECT method, body_json, source FROM discovered_requests") \
        == [("POST", None, "captured-aborted")]


# =====================================================================================
# Import (store_adapter, FR-AUD-23) and the store's endpoint identity (FR-CORE-43)
# =====================================================================================
def _spider_db(tmp_path, rows, forms=()):
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))
    try:
        for r in rows:
            sm.record_request(f"{H}/", r["method"], H + r["path"], r.get("ct",
                              "application/json"), r.get("body"), r.get("trigger", "passive"),
                              source=r.get("source", capture.SOURCE_CAPTURED),
                              keep_without_body=True)
        for f in forms:
            sm.record_form(f)
    finally:
        sm.close()
    return str(tmp_path / "s.db")


def _import(tmp_path, db):
    store = Store(str(tmp_path / "u.db"))
    run = store.start_run("crawler", "h")
    counts = store_adapter.import_spider(db, store, run)
    return store, run, counts


def _points(store, run):
    return {(r["url"], r["method"], r["op_key"], r["name"], r["location"], r["source"])
            for r in store.conn.execute(
                "SELECT e.url, e.method, e.op_key, e.source, p.name, p.location FROM "
                "parameter p JOIN endpoint e ON e.id = p.endpoint_id WHERE p.run_id = ?",
                (run,))}


def test_graphql_variables_are_the_only_points_and_each_operation_is_an_endpoint(tmp_path):
    rows = [{"method": "POST", "path": "/graphql", "body": json.dumps(
        {"query": f"mutation {n}($q: String) {{ x }}", "operationName": n,
         "variables": {"q": "hello", "filter": {"term": "z"}}}).encode()}
        for n in ("AddItem", "RenameItem")]
    store, run, _counts = _import(tmp_path, _spider_db(tmp_path, rows))
    with store:
        pts = _points(store, run)
        eps = store.conn.execute("SELECT url, method, op_key, source FROM endpoint "
                                 "WHERE run_id = ? ORDER BY op_key", (run,)).fetchall()
    assert [tuple(e) for e in eps] == [
        ("/graphql", "POST", "gql:AddItem", "captured-aborted"),
        ("/graphql", "POST", "gql:RenameItem", "captured-aborted")]
    names = {(op, n, loc) for _u, _m, op, n, loc, _s in pts}
    assert names == {(op, n, "json") for op in ("gql:AddItem", "gql:RenameItem")
                     for n in ("variables.q", "variables.filter.term")}


def test_a_captured_request_wins_over_a_static_form_of_the_same_signature(tmp_path):
    form = {"page_url": f"{H}/contact", "action_url": f"{H}/api/messages", "method": "POST",
            "enctype": "application/x-www-form-urlencoded",
            "entries": [["subject", ""], ["body", ""]],
            "controls": [["subject", "text"], ["body", "textarea"]], "selector": False,
            "options": []}
    rows = [{"method": "POST", "path": "/api/messages", "ct": store_adapter.FORM_URLENCODED,
             "body": b"subject=hi&body=there"}]
    store, run, counts = _import(tmp_path, _spider_db(tmp_path, rows, [form]))
    with store:
        sources = {r[0] for r in store.conn.execute(
            "SELECT source FROM endpoint WHERE run_id = ? AND url = '/api/messages'",
            (run,))}
    assert counts["form_superseded_by_capture"] == 1
    assert sources == {"captured-aborted"}
    con = sqlite3.connect(str(tmp_path / "s.db"))
    assert con.execute("SELECT COUNT(*) FROM discovered_forms").fetchone()[0] == 1
    con.close()                                           # the static row: provenance


def test_multipart_transport_bodiless_and_legacy_rows_import_as_stated(tmp_path):
    mp = (b"--B\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\n"
          b"Content-Type: text/plain\r\n\r\ndata\r\n--B--\r\n")
    rows = [
        {"method": "POST", "path": "/api/upload", "ct": "multipart/form-data; boundary=B",
         "body": mp},
        {"method": "POST", "path": "/socket.io/?EIO=4&transport=polling",
         "body": b'{"a":1}', "source": capture.SOURCE_TRANSPORT},
        {"method": "POST", "path": "/api/ping", "ct": "text/plain", "body": b"free"},
        {"method": "GET", "path": "/api/user/password-policy?lang=en", "body": None},
        {"method": "POST", "path": "/api/seen", "body": b'{"q":"a"}',
         "source": "passive"},                             # a legacy (sent) row
    ]
    store, run, counts = _import(tmp_path, _spider_db(tmp_path, rows))
    with store:
        eps = {(r[0], r[1]): r[2] for r in store.conn.execute(
            "SELECT url, method, source FROM endpoint WHERE run_id = ?", (run,))}
        pts = _points(store, run)
    assert counts["request_transport"] == 1 and not any("socket.io" in u for u, _m in eps)
    assert counts["request_multipart"] == 1 and ("/api/upload", "POST") in eps
    assert not [p for p in pts if p[0] == "/api/upload"]   # multipart: no points yet
    assert counts["request_no_body"] == 1 and ("/api/ping", "POST") in eps
    assert ("/api/user/password-policy", "GET", "", "lang", "query",
            "captured-aborted") in pts
    assert eps[("/api/seen", "POST")] == "request"         # sent: not a captured write


# =====================================================================================
# Admission (harness.auto, FR-FUZZ-52, D67)
# =====================================================================================
def _admission_store(tmp_path):
    rows = [{"method": "POST", "path": "/api/notes", "body": b'{"title":"hello"}'},
            {"method": "POST", "path": "/api/seen", "body": b'{"q":"a"}',
             "source": capture.SOURCE_OBSERVED}]
    return _import(tmp_path, _spider_db(tmp_path, rows))


def test_captured_writes_are_points_by_default_d67(tmp_path):
    from fuzzlab.harness.auto import injection_points_from_store
    store, run, _c = _admission_store(tmp_path)
    with store:
        skipped = []
        pts = injection_points_from_store(store, run, H + "/", skipped=skipped)
    assert {(p.url, p.param) for p in pts} == {(f"{H}/api/notes", "title"),
                                               (f"{H}/api/seen", "q")}
    assert skipped == []


def test_the_opt_out_skips_captured_writes_with_its_reason(tmp_path):
    from fuzzlab.harness.auto import CAPTURED_WRITE_OPT_OUT, injection_points_from_store
    store, run, _c = _admission_store(tmp_path)
    with store:
        skipped = []
        pts = injection_points_from_store(store, run, H + "/", skipped=skipped,
                                          probe_captured_writes=False)
    assert {(p.url, p.param) for p in pts} == {(f"{H}/api/seen", "q")}
    assert skipped == [("/api/notes", "POST", "title", CAPTURED_WRITE_OPT_OUT)]
    assert CAPTURED_WRITE_OPT_OUT == "captured write, not sent: --no-probe-captured-writes"


def test_two_operations_on_one_url_are_two_points(tmp_path):
    from fuzzlab.harness.auto import injection_points_from_store
    rows = [{"method": "POST", "path": "/rpc", "body": json.dumps(
        {"jsonrpc": "2.0", "method": m, "id": 1, "params": {"name": "a"}}).encode()}
        for m in ("items.add", "items.rename")]
    store, run, _c = _import(tmp_path, _spider_db(tmp_path, rows))
    with store:
        pts = injection_points_from_store(store, run, H + "/")
    assert [(p.param, dict(p.base_entries)[("method",)]) for p in pts] == [
        ("params.name", "items.add"), ("params.name", "items.rename")]


def test_the_cli_flag_reaches_the_run():
    from fuzzlab.harness.auto_cli import build_parser
    p = build_parser()
    base = ["--authorized", "--base-url", H + "/", "--store", "u.db"]
    assert p.parse_args(base).no_probe_captured_writes is False
    assert p.parse_args(base + ["--no-probe-captured-writes"]) \
        .no_probe_captured_writes is True


# =====================================================================================
# Store migration 24 (FR-CORE-43)
# =====================================================================================
def _v23(path):
    from fuzzlab.core import migrations
    from tests._downgrade import undo_after
    with Store(path) as store:
        run = store.start_run("t", "h")
        undo_after(store.conn, 23)
        store.conn.execute("DELETE FROM schema_version WHERE version >= 24")
        store.conn.commit()
        assert migrations.current_version(store.conn) == 23
        ep = store.conn.execute("INSERT INTO endpoint (run_id, url, method, source) "
                                "VALUES (?,?,?,?)", (run, "/a", "POST", "form")).lastrowid
        store.conn.execute("INSERT INTO parameter (run_id, endpoint_id, name, location) "
                           "VALUES (?,?,?,?)", (run, ep, "x", "body"))
        store.conn.commit()
    return ep


def test_migration_24_keeps_rows_ids_and_foreign_keys(tmp_path):
    ep = _v23(tmp_path / "s.db")
    with Store(tmp_path / "s.db") as store:
        row = store.conn.execute("SELECT id, url, method, source, op_key FROM endpoint "
                                 "WHERE id = ?", (ep,)).fetchone()
        assert tuple(row) == (ep, "/a", "POST", "form", "")
        assert store.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert store.conn.execute("PRAGMA foreign_key_check").fetchall() == []
        run = store.conn.execute("SELECT MAX(id) FROM run").fetchone()[0]
        store.conn.execute("INSERT INTO endpoint (run_id, url, method, op_key) "
                           "VALUES (?,?,?,?)", (run, "/a", "POST", "gql:X"))
        with pytest.raises(sqlite3.IntegrityError):                 # still enforced
            store.conn.execute("INSERT INTO parameter (run_id, endpoint_id, name, "
                               "location) VALUES (?,?,?,?)", (run, 999999, "y", "body"))


def test_a_failure_inside_migration_24_leaves_v23_and_foreign_keys_on(tmp_path,
                                                                     monkeypatch):
    """PA-0088(1): an injected mid-way failure rolls the rebuild back."""
    from fuzzlab.core import migrations
    _v23(tmp_path / "s.db")

    def boom(_conn):
        raise RuntimeError("injected")
    monkeypatch.setitem(migrations.POST_STEPS, 24, boom)
    con = sqlite3.connect(str(tmp_path / "s.db"))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    with pytest.raises(RuntimeError, match="injected"):
        migrations.migrate(con)
    assert migrations.current_version(con) == 23
    assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    cols = [r[1] for r in con.execute("PRAGMA table_info(endpoint)")]
    assert "op_key" not in cols and con.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE name = 'endpoint_v24'").fetchone()[0] == 0
    con.close()


# =====================================================================================
# The funnel's discovery and admission stages (scripts/funnel_report.py, DISC-CAPTURE §9)
# =====================================================================================
def test_the_funnel_reports_discovered_buildable_and_refused(tmp_path):
    import importlib.util
    from pathlib import Path

    from fuzzlab.labels.contract import Case
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("funnel_report",
                                                  root / "scripts" / "funnel_report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    store, run, _c = _admission_store(tmp_path)
    store.close()

    def case(cid, url, method, param):
        return Case(case_id=cid, url=url, method=method, param=param, location="json",
                    vuln_class="sqli", sink_context="sql", expected_vulnerable=True,
                    rendering="server")
    cases = [case("C1", "/api/notes", "POST", "title"),
             case("C2", "/api/notes", "GET", "title"),      # method-aware
             case("C3", "/api/seen", "POST", "q"),
             case("C4", "/api/none", "POST", "z")]
    rows = {r["case"]: r for r in mod.funnel(str(tmp_path / "u.db"), None, cases=cases)}
    assert (rows["C1"]["discovered"], rows["C1"]["buildable"]) == (True, True)
    assert rows["C1"]["stage"] == "reached"                  # the existing column holds
    assert rows["C2"]["discovered"] is False
    assert rows["C4"]["discovered"] is False and rows["C4"]["stage"] == "not reached"
    out = {r["case"]: r for r in mod.funnel(str(tmp_path / "u.db"), None, cases=cases,
                                            probe_captured_writes=False)}
    assert out["C1"]["buildable"] is False
    assert out["C1"]["refused"] == "captured write, not sent: --no-probe-captured-writes"
    assert out["C3"]["buildable"] is True and out["C3"]["refused"] is None


# =====================================================================================
# The spider's recorder (LocalSpider._capture / _note_ws_drop), offline
# =====================================================================================
def _spider(tmp_path):
    from fuzzlab.tools.spider import LocalSpider
    sp = LocalSpider(H + "/", db_name=str(tmp_path / "s.db"), engine="requests")
    sp._capture_on = True
    return sp


def test_the_recorder_counts_by_reason_caps_transport_churn_and_ws_rows(tmp_path,
                                                                       monkeypatch):
    sp = _spider(tmp_path)
    monkeypatch.setattr(capture, "MAX_WS_RECORDS", 3)
    try:
        poll = _Req(f"{H}/socket.io/?EIO=4&transport=polling&t=a", body=b"2")
        for _ in range(4):                                  # an aborted poller retrying
            sp._capture(poll, "captured, not sent: a POST request")
        sp._capture(_Req(f"{H}/api/items/1", method="DELETE", body=b""),
                    "captured, not sent: a DELETE request")
        sp._capture(_Req(f"{H}/api/x/delete", method="GET", body=None),
                    capture.WHY_GET_RULE + ": a destructive GET")
        for i in range(5):
            sp._note_ws_drop(f"ws://127.0.0.1:8080/ws", f"ping {i}")
        sp._probe = {"blocked": set()}                       # a probe records nothing
        sp._capture(_Req(f"{H}/api/probe-only"), "captured, not sent: a POST request")
    finally:
        sp.storage.close()
    c = sp.spa_counts
    assert (c["transport_seen"], c["transport_recorded"], c["transport_churn"]) == (4, 1, 3)
    assert c["deletes_blocked"] == 1 and c["get_refused_by_rule"] == 1
    assert (c["ws_dropped"], c["ws_dropped_recorded"]) == (5, 3)
    assert f"{H}/api/x/delete" in sp._capture_refused_urls      # never queued
    rows = _rows(tmp_path, "SELECT url, source FROM discovered_requests")
    assert not [u for u, _s in rows if u.endswith("probe-only")]
    assert [s for u, s in rows if "socket.io" in u] == ["transport"]
    assert len(_rows(tmp_path, "SELECT * FROM ws_dropped")) == 3
