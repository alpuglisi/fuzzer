"""Forms phase 3, lane J: JSON body injection points (FR-AUD-22, FR-FUZZ-47, FR-CORE-36).

A single-page app's real inputs are JSON APIs (Juice Shop's ``POST /rest/user/login``).
Lane I's crawler captures the app's own requests into the spider table
``discovered_requests``; this lane imports them as points, one per body leaf, and every
sender rebuilds the whole body with exactly one leaf set to the payload. The table is
created here with raw SQL matching lane I's contract (agreed draft, "Contract — spider
table discovered_requests"), so these tests do not depend on the spider's code.

Also here: an SPA hash route's query (``/#/search?q=x``) is a ``fragment`` point, never a
``query`` one, and the M6 executor places it inside the route's own query.
"""

from __future__ import annotations

import ast
import json
import sqlite3
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

from fuzzlab.audit import InjectionPoint, load_rules, matches
from fuzzlab.core import jsonbody
from fuzzlab.core.forms import first_link_set, is_link_set
from fuzzlab.core.store import Store
from fuzzlab.core.urls import DestructiveUrlRefused, spa_route, to_route_path, url_key
from fuzzlab.harness.auto import (
    header_points_from_store,
    injection_points_from_store,
    isolated_paths_from_store,
    run_auto,
)
from fuzzlab.oracle.probe import Candidate, UnplaceableLocation
from fuzzlab.tools import store_adapter
from fuzzlab.tools.probesender import RequestsProbeSender
from fuzzlab.tools.store_adapter import (
    captured_request,
    credential_change_reason,
    import_spider,
)

ROOT = Path(__file__).resolve().parents[1]
HEX32 = "0123456789abcdef0123456789abcdef"
BASE = "http://localhost/app/"
LOGIN_API = BASE + "rest/user/login"

#: Lane I's contract for the spider table (draft "Contract", FR-CRAWL-13).
REQUESTS_DDL = ("CREATE TABLE IF NOT EXISTS discovered_requests (id INTEGER PRIMARY KEY "
                "AUTOINCREMENT, page_url TEXT, method TEXT, url TEXT, content_type TEXT, "
                "body_json TEXT, source TEXT, signature TEXT UNIQUE)")


# --- helpers -----------------------------------------------------------------------------
def _req(url, body, method="POST", content_type="application/json", page=None,
         source="passive"):
    return {"page_url": page or BASE + "#/", "method": method, "url": url,
            "content_type": content_type,
            "body_json": body if isinstance(body, str) else json.dumps(body),
            "source": source}


def _spider_db(path, requests=(), pages=(), forms=()):
    """A spider DB: pages and forms through the real spider's storage, captured
    requests in lane I's table (raw SQL, the contract)."""
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(path))
    sm.reset()
    for p in pages:
        sm.mark_visited(p, 200, 0)
    for f in forms:
        sm.record_form(f)
    sm.close()
    db = sqlite3.connect(path)
    if requests is None:                 # an old spider DB: lane S's table did not exist
        db.execute("DROP TABLE IF EXISTS discovered_requests")
        db.commit()
        db.close()
        return
    db.execute(REQUESTS_DDL)
    for i, r in enumerate(requests):
        db.execute("INSERT INTO discovered_requests (page_url, method, url, content_type, "
                   "body_json, source, signature) VALUES (?,?,?,?,?,?,?)",
                   (r["page_url"], r["method"], r["url"], r["content_type"],
                    r["body_json"], r["source"], f"sig-{i}"))
    db.commit()
    db.close()


def _import(tmp_path, requests=(), pages=(), forms=(), writes=False, name="u.db"):
    _spider_db(tmp_path / "s.db", requests, pages, forms)
    store = Store(tmp_path / name)
    run = store.start_run("auto", "localhost")
    counts = import_spider(tmp_path / "s.db", store, run, fuzz_json_writes=writes)
    return store, run, counts


def _params(store, run):
    return {r["name"]: dict(r) for r in store.conn.execute(
        "SELECT p.name, p.location, p.example, p.form_id, e.url, e.method FROM parameter p "
        "JOIN endpoint e ON e.id = p.endpoint_id WHERE p.run_id=?", (run,))}


def _forms(store, run):
    return [dict(r) for r in store.conn.execute(
        "SELECT enctype, entries, password_fields FROM form WHERE run_id=?", (run,))]


def _all_text(store) -> str:
    out = []
    for (table,) in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        for row in store.conn.execute(f"SELECT * FROM {table}"):
            out.append(json.dumps([str(v) for v in tuple(row)]))
    return "\n".join(out)


class _JsonWire:
    """A requests-style session (for `RequestsProbeSender`) that records every send and
    answers with ``handler(method, path, body or form, headers)``."""

    def __init__(self, handler=None):
        self.handler = handler or (lambda *a: (200, "{}"))
        self.sent = []
        self.cookies = {}

    def request(self, method, url, **kw):
        headers = dict(kw.get("headers") or {})
        data = kw.get("data")
        if headers.get("Content-Type") == jsonbody.ENCTYPE:
            body = json.loads(data)
        else:
            body = dict(data) if isinstance(data, (list, dict)) else {}
        query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        query.update(dict(kw.get("params") or {}))
        self.sent.append({"method": method, "path": urlsplit(url).path, "body": body,
                          "query": query, "headers": headers})
        status, text = self.handler(method, urlsplit(url).path, body, headers)

        class R:
            status_code, headers = status, {"Content-Type": "application/json"}
        R.text = text
        return R()


# =========================================================================================
# FR-CORE-36: paths, names and bodies
# =========================================================================================
ADVERSARIAL = {
    "a.b": 1, "a\\b": "x", "[0]": True, "]": None, "": "blank-key", "é ü": "u",
    "x": {"y.z": [{"[1]": "deep", "\\.": False}, [], {}], "0": "zero-key"},
    "list": [["n0", "n1"], 2.5, {"k": "v"}],
    "a\\.b": "esc", "a[0]": "bracket", "...": "dots",
}


def test_leaf_names_and_bodies_round_trip_byte_for_byte_over_adversarial_keys(tmp_path):
    store, run, counts = _import(tmp_path, [_req(BASE + "api/things", ADVERSARIAL)])
    with store:
        (form,) = _forms(store, run)
        entries = jsonbody.decode_entries(form["entries"])
        params = _params(store, run)
    assert form["enctype"] == jsonbody.ENCTYPE and counts["request_json"] == 1
    # the stored entries rebuild the captured body exactly, key order and types kept
    assert json.dumps(jsonbody.build(entries)) == json.dumps(ADVERSARIAL)
    names = [jsonbody.display_name(p) for p, _v in entries]
    assert len(set(names)) == len(names)                      # injective
    for (path, _v), name in zip(entries, names):
        assert jsonbody.parse_name(name) == path
        assert jsonbody.display_name(jsonbody.parse_name(name)) == name
    # every string/number/bool leaf is a json point; null and empty containers are not
    want = {jsonbody.display_name(p) for p, v in entries if jsonbody.is_point_value(v)}
    assert set(params) == want and {p["location"] for p in params.values()} == {"json"}
    assert params["a\\.b"]["example"] == "1" and params["\\[0\\]"]["example"] == "true"
    assert params["x.y\\.z[0].\\[1\\]"]["example"] == "deep"


@pytest.mark.parametrize("name", ["a\\", "a[", "a[01]", "a[x]", "a[0]b", "]", "a\\q",
                                  "a[99999999]", "a[-1]", "a[1 ]", None, 7])
def test_malformed_names_parse_to_none(name):
    assert jsonbody.parse_name(name) is None


def test_the_leaf_and_depth_limits_refuse_rather_than_truncate(tmp_path):
    ok = {f"k{i}": "v" for i in range(jsonbody.MAX_LEAVES)}
    over = {**ok, "one_more": "v"}
    deep: dict = {"v": "leaf"}
    for _ in range(jsonbody.MAX_DEPTH):
        deep = {"d": deep}
    store, run, counts = _import(tmp_path, [_req(BASE + "api/a", ok),
                                            _req(BASE + "api/b", over),
                                            _req(BASE + "api/c", deep)])
    with store:
        urls = {r["url"] for r in store.conn.execute("SELECT url FROM endpoint")}
    assert urls == {"/app/api/a"}
    assert (counts["request_json"], counts["request_refused"]) == (1, 2)


@pytest.mark.parametrize("raw", [
    [["a"], "x"], [[["a"], "x"], [["a"], "y"]], [[["a"], "x"], [["a", "b"], "y"]],
    [[[0], "x"]], [[["a", True], "x"]], [[["a"], {"k": 1}]], [[["a"], float("inf")]],
    [[["a", 10 ** 6], "x"]], "[[[\"a\"], NaN]]", "not json", "[]", None])
def test_malformed_stored_entries_are_rejected_at_the_one_parser(raw):
    assert jsonbody.decode_entries(raw if not isinstance(raw, float) else [raw]) is None


# =========================================================================================
# FR-AUD-22: import
# =========================================================================================
def test_a_nested_json_body_becomes_json_points_with_typed_siblings(tmp_path):
    body = {"user": {"email": "a@lab.test", "tags": ["x", "y"]}, "q": "pup", "count": 3,
            "on": True, "none": None}
    store, run, counts = _import(tmp_path, [_req(BASE + "api/search?v=1", body)])
    with store:
        params = _params(store, run)
        (form,) = _forms(store, run)
        pts = injection_points_from_store(store, run, BASE, skipped=[])
    assert set(params) == {"user.email", "user.tags[0]", "user.tags[1]", "q", "count", "on"}
    assert {p["url"] for p in params.values()} == {"/app/api/search?v=1"}   # query kept
    assert params["count"]["example"] == "3" and params["on"]["example"] == "true"
    assert json.loads(form["password_fields"]) == []
    by = {p.param: p for p in pts}
    assert by["count"].location == "json" and by["count"].method == "POST"
    assert dict(by["q"].base_entries)[("count",)] == 3          # types kept
    assert dict(by["q"].base_entries)[("on",)] is True
    assert dict(by["q"].base_entries)[("none",)] is None


def test_a_form_encoded_captured_body_imports_as_form_points(tmp_path):
    store, run, counts = _import(tmp_path, [_req(
        BASE + "profile", {"username": "x", "comment": "hi"},
        content_type="application/x-www-form-urlencoded; charset=UTF-8")])
    with store:
        params = _params(store, run)
        (form,) = _forms(store, run)
        pts = injection_points_from_store(store, run, BASE, skipped=[])
    assert counts["request_form"] == 1 and form["enctype"] == store_adapter.FORM_URLENCODED
    assert set(params) == {"comment"}                          # username: an object selector
    assert params["comment"]["location"] == "body"
    assert pts[0].base_entries == (("username", "x"), ("comment", "hi"))


REFUSED = [
    ("DELETE", BASE + "api/Feedbacks/1", {"x": "y"}, "method DELETE"),
    ("OPTIONS", BASE + "api/Feedbacks", {"x": "y"}, "method OPTIONS"),
    ("TRACE", BASE + "api/Feedbacks", {"x": "y"}, "method TRACE"),
    ("", BASE + "api/Feedbacks", {"x": "y"}, "method (none)"),
    ("PUT", BASE + "rest/products/reviews", {"message": "m"}, "only with --fuzz-json-writes"),
    ("PATCH", BASE + "rest/products/reviews", {"message": "m"}, "only with --fuzz-json-writes"),
    ("POST", BASE + "rest/user/logout", {"x": "y"}, "destructive URL"),
    ("POST", BASE + "api/Feedbacks/remove", {"x": "y"}, "destructive URL"),
    ("POST", BASE + "rest/basket/1/checkout", {"x": "y"}, "transaction URL"),
    ("POST", BASE + "rest/wallet/balance", {"balance": 10}, "transaction URL"),
    ("POST", BASE + "api/Orders", {"x": "y"}, "transaction URL"),
    ("POST", BASE + "rest/deluxe-membership", {"x": "y"}, "transaction URL"),
    # credential change: the one rule forms use (two passwords; a change word; an
    # account-management action token)
    ("POST", BASE + "api/Users", {"email": "e", "password": "", "passwordRepeat": ""},
     "credential-change body (2 password fields)"),
    ("POST", BASE + "rest/user/login", {"email": "e", "newPassword": ""}, "has 'new'"),
    ("POST", BASE + "rest/user/login", {"email": "e", "currentPassword": ""}, "has 'curr'"),
    ("POST", BASE + "rest/user/login", {"email": "e", "old_password": ""}, "has 'old'"),
    ("POST", BASE + "rest/user/login", {"pw": {"confirm_pass": ""}}, "has 'conf'"),
    ("POST", BASE + "api/users/signup", {"email": "e", "password": ""}, "action has"),
    ("POST", BASE + "rest/account/1", {"email": "e", "password": ""}, "action has"),
    ("POST", BASE + "api/prefs", {"language": "de"}, "settings field"),
    ("POST", BASE + "api/prefs", {"user": {"role": "admin"}}, "settings field"),
    ("POST", BASE + "api/Feedbacks", {"comment": "please delete it"}, "destructive entry"),
    ("POST", BASE + "api/Feedbacks", {"drop": "x"}, "destructive entry"),
]


@pytest.mark.parametrize("method,url,body,why", REFUSED,
                         ids=[f"{m or 'none'}-{w.split()[0]}-{i}"
                              for i, (m, _u, _b, w) in enumerate(REFUSED)])
def test_each_refusal_is_never_imported(tmp_path, method, url, body, why):
    reason, _kind, _leaves = captured_request(_req(url, body, method=method))
    assert reason is not None and why in reason
    store, run, counts = _import(tmp_path, [_req(url, body, method=method)])
    with store:
        assert _forms(store, run) == [] and _params(store, run) == {}
    assert (counts["request"], counts["request_refused"]) == (1, 1)


@pytest.mark.parametrize("row,why", [
    (_req(BASE + "api/x", "x=1", content_type="text/plain"), "unsupported content type"),
    (_req(BASE + "api/x", "{not json", content_type="application/json"), "malformed"),
    (_req(BASE + "api/x", "[1, 2]"), "not a JSON object"),
    (_req(BASE + "api/x", "{}"), "an empty body"),
    (_req(BASE + "api/x", '{"a": NaN}'), "malformed"),
    (_req(BASE + "api/x", '{"a": 1}' + " " * 3, content_type=None), "unsupported"),
    (_req(BASE + "api/x", {"a": 1}, content_type="application/x-www-form-urlencoded"),
     "not an object of strings"),
    (_req("http://evil.test/api/x", {"a": "b"}), "another origin"),
])
def test_malformed_unsupported_and_cross_origin_requests_are_refused(row, why):
    reason, _k, _l = captured_request(row)
    assert reason is not None and why in reason


def test_put_and_patch_import_only_with_the_flag_and_a_safe_url(tmp_path):
    rows = [_req(BASE + "rest/products/reviews", {"message": "m", "author": "a"},
                 method="PATCH"),
            _req(BASE + "rest/products/reviews/delete", {"message": "m"}, method="PUT")]
    store, run, counts = _import(tmp_path, rows, writes=True)
    with store:
        params = _params(store, run)
    assert set(params) == {"message", "author"} and params["message"]["method"] == "PATCH"
    assert (counts["request_json"], counts["request_refused"]) == (1, 1)


def test_the_credential_change_rule_is_one_function_shared_with_forms():
    """PA-0003: the body rule calls the form rule's core, never a copy of its words."""
    src = (ROOT / "fuzzlab/tools/store_adapter.py").read_text()
    tree = ast.parse(src)
    fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

    def calls(fn):
        return {getattr(c.func, "id", getattr(c.func, "attr", None))
                for c in ast.walk(fns[fn]) if isinstance(c, ast.Call)}
    assert "credential_change_rule" in calls("credential_change_reason")
    assert "credential_change_rule" in calls("body_refusal")
    users = [n for n, fn in fns.items() if any(isinstance(x, ast.Name) and x.id in (
        "_CHANGE_SUBSTRINGS", "_CHANGE_TOKENS") for x in ast.walk(fn))]
    assert users == ["credential_change_rule"]
    # and the forms' own wording is unchanged
    form = {"action_url": BASE + "login.php", "entries": [],
            "controls": [("p1", "password"), ("p2", "password")]}
    assert credential_change_reason(form) == "credential-change form (2 password controls)"


def test_a_password_leaf_on_any_segment_is_isolated_sent_empty_and_never_a_point(tmp_path):
    body = {"email": "fuzzlab@example.invalid", "auth": {"password": "hunter2"},
            "q": "x"}
    store, run, counts = _import(tmp_path, [_req(LOGIN_API, body)])
    with store:
        (form,) = _forms(store, run)
        params = _params(store, run)
        isolated = isolated_paths_from_store(store, run, BASE)
        skipped: list = []
        pts = injection_points_from_store(store, run, BASE, skipped=skipped,
                                          isolated=set())
        dropped = injection_points_from_store(store, run, BASE, skipped=skipped)
        text = _all_text(store)
    assert json.loads(form["password_fields"]) == ["auth.password"]
    assert dict(jsonbody.decode_entries(form["entries"]))[("auth", "password")] == ""
    assert set(params) == {"email", "q"}
    assert isolated == {url_key(LOGIN_API)}
    assert {p.param for p in pts} == {"email", "q"}
    assert dropped == []                     # a caller that cannot isolate gets none
    assert "hunter2" not in text


def test_the_password_gate_holds_without_the_sensitive_name_pin(tmp_path, monkeypatch):
    """Every credential token is also a sensitive token today, so two gates keep a
    password leaf from being a point; each must hold alone (mutation check)."""
    import fuzzlab.core.redaction as redaction
    monkeypatch.setattr(redaction, "is_sensitive_name", lambda name: False)
    # captured already blank (lane I blanks passwords), so no "value changed" pin either
    store, run, _c = _import(tmp_path, [_req(LOGIN_API, {"email": "e", "pass": ""})])
    with store:
        params = _params(store, run)
        (form,) = _forms(store, run)
    assert set(params) == {"email"} and json.loads(form["password_fields"]) == ["pass"]


def test_object_selectors_sensitive_and_identifier_leaves_are_pinned(tmp_path):
    body = {"UserId": 1, "captchaId": 5, "captcha": "12", "comment": "hi",
            "auth": {"token": "abc"}, "apiKey": 12345, "ref": HEX32, "rating": 4,
            "BasketId": "7", "owner": "me"}
    store, run, _c = _import(tmp_path, [_req(BASE + "api/Feedbacks", body)])
    with store:
        (form,) = _forms(store, run)
        params = _params(store, run)
        text = _all_text(store)
    assert set(params) == {"captcha", "comment", "rating"}
    stored = dict(jsonbody.decode_entries(form["entries"]))
    assert stored[("UserId",)] == 1 and stored[("BasketId",)] == "7"   # sent as captured
    assert stored[("auth", "token")] == "" and stored[("ref",)] == ""  # blanked, typed
    assert stored[("apiKey",)] is None
    assert HEX32 not in text and "12345" not in text


def test_the_json_producer_goes_through_redaction():
    """PA-0100: the function that INSERTs a captured request's form row calls
    `redact_leaf` (the link-set producer's guard, for this producer)."""
    tree = ast.parse((ROOT / "fuzzlab/tools/store_adapter.py").read_text())
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        consts = [n.value for n in ast.walk(fn) if isinstance(n, ast.Constant)
                  and isinstance(n.value, str)]
        if any("INSERT INTO form" in c for c in consts) and any(
                isinstance(n, ast.Attribute) and n.attr == "ENCTYPE" for n in ast.walk(fn)):
            called = {getattr(c.func, "id", getattr(c.func, "attr", None))
                      for c in ast.walk(fn) if isinstance(c, ast.Call)}
            assert "redact_leaf" in called
            return
    pytest.fail("no JSON form-row producer found")


def test_old_spider_dbs_import_unchanged(tmp_path):
    """No ``discovered_requests`` table: no request keys, no JSON rows; and an empty
    table changes nothing either."""
    from bs4 import BeautifulSoup

    from fuzzlab.core.forms import form_record
    html = "<form method=post action='/app/s.php'><input name=title><button>Go</button></form>"
    form = form_record(BeautifulSoup(html, "html.parser").find("form"), BASE + "p.php")
    pages = [BASE + "p.php?id=1&cat=2", BASE + "q.php?x=1"]
    old_store, old_run, old = _import(tmp_path, None, pages, [form], name="old.db")
    (tmp_path / "s.db").unlink()
    new_store, new_run, new = _import(tmp_path, [], pages, [form], name="new.db")
    assert not any(k.startswith("request") for k in old)
    assert {k: v for k, v in new.items() if not k.startswith("request")} == old
    for table in ("page", "endpoint", "parameter", "form"):
        q = f"SELECT * FROM {table} ORDER BY id"
        assert [tuple(r)[2:] for r in old_store.conn.execute(q)] == \
               [tuple(r)[2:] for r in new_store.conn.execute(q)]
    old_store.close()
    new_store.close()


def test_json_rows_never_reach_form_skip_logic(tmp_path, monkeypatch):
    def boom(form):
        raise AssertionError("form_skip_reason saw a captured request")
    monkeypatch.setattr(store_adapter, "form_skip_reason", boom)
    store, run, counts = _import(tmp_path, [_req(LOGIN_API, {"email": "e", "password": ""})])
    store.close()
    assert counts["request_json"] == 1


def test_every_reader_of_form_enctype_handles_json_rows(tmp_path):
    """`core.forms` is the one reader (guard in test_forms_phase2): a JSON row is never
    a link set, so it never becomes a header point's query."""
    store, run, _c = _import(tmp_path, [_req(BASE + "api/s", {"q": "secretish"},
                                             method="GET")], pages=[BASE + "api/s"])
    with store:
        rows = store.conn.execute("SELECT enctype FROM form").fetchall()
        assert rows and not any(is_link_set(r) for r in rows)
        assert first_link_set(store.conn, run, "/app/api/s") is None
        pts = header_points_from_store(store, run, BASE, ["User-Agent"])
    assert [p.url for p in pts] == [BASE + "api/s"]


# =========================================================================================
# FR-AUD-22: rules on JSON leaves
# =========================================================================================
def test_name_rules_match_the_last_key_and_location_rules_name_json():
    rules = {r.id: r for r in load_rules()}

    def point(name, location="json"):
        return InjectionPoint(url=BASE + "api/x", param=name, method="POST",
                              location=location)
    assert matches(rules["R-OPEN-REDIRECT"], point("user.returnUrl"))
    assert matches(rules["R-OPEN-REDIRECT"], point("redirect[0]"))
    assert not matches(rules["R-OPEN-REDIRECT"], point("returnUrl.label"))
    assert not matches(rules["R-COMMAND-INJECTION"], point("ip.x"))
    assert matches(rules["R-COMMAND-INJECTION"], point("ip.x", location="body"))  # unchanged
    assert matches(rules["R-SQLI-PARAM"], point("email"))
    assert matches(rules["R-SSTI"], point("email"))
    # reflected XSS is not nominated on a JSON leaf (stated in FR-AUD-22: a JSON response
    # is not rendered as HTML, and the structural check does not read the content type)
    assert not matches(rules["R-XSS-REFLECT"], point("comment"))


def test_value_shapes_apply_to_the_leaf_example(tmp_path):
    body = {"target": {"host": "db.lab.example"}, "next": "http://lab.example.com/home"}
    store, run, _c = _import(tmp_path, [_req(BASE + "api/check", body)])
    with store:
        pts = {p.param: p for p in injection_points_from_store(store, run, BASE,
                                                               skipped=[])}
    assert pts["target.host"].value_shapes == {"hostname"}
    assert pts["target.host"].base_value == "127.0.0.1"
    assert pts["next"].value_shapes == {"url"}


def test_a_json_url_leaf_gets_the_seed_only_without_an_identifier_in_host_or_path(tmp_path):
    from fuzzlab.audit.value_shape import redirect_seed
    clean = "http://lab.example.com/home"
    host_id = f"http://{HEX32}.example.com/home"
    path_id = f"http://lab.example.com/{HEX32}/home"
    body = {"a": {"next": clean}, "b": {"next": host_id}, "c": {"next": path_id}}
    store, run, _c = _import(tmp_path, [_req(BASE + "api/go", body)])
    with store:
        pts = {p.param: p for p in injection_points_from_store(store, run, BASE,
                                                               skipped=[])}
        text = _all_text(store)
    assert pts["a.next"].redirect_seed == clean
    assert set(pts) == {"a.next"}            # the others are identifier-like: pinned
    assert HEX32 not in text
    assert redirect_seed(host_id) is None and redirect_seed(path_id) is None


# =========================================================================================
# FR-FUZZ-47: binding and sending
# =========================================================================================
def test_json_siblings_are_redacted_and_neutral_when_a_third_leaf_is_probed(tmp_path):
    body = {"returnUrl": "http://lab.example.com/next", "ref": HEX32, "comment": "hello"}
    store, run, _c = _import(tmp_path, [_req(BASE + "api/Feedbacks", body)])
    wire = _JsonWire()
    with store:
        run_auto(base_url=BASE, store=store, run_id=run, sender=RequestsProbeSender(
            session=wire), mode="manual", selected_categories=["sql-injection"],
            points_source="crawl")
    probing_comment = [s["body"] for s in wire.sent if s["body"].get("comment") != "hello"]
    assert probing_comment
    for sent in probing_comment:
        assert sent["returnUrl"] == "http://127.0.0.1/" and sent["ref"] == ""
    assert all(s["headers"]["Content-Type"] == "application/json" and s["query"] == {}
               for s in wire.sent)
    assert HEX32 not in json.dumps(wire.sent) and "lab.example.com" not in json.dumps(
        wire.sent)


def test_the_bound_sender_sets_exactly_the_probed_leaf_and_keeps_types():
    from fuzzlab.oracle.oracle import _FormBoundSender
    inner = _JsonWire()
    entries = ((("a", "b", 0), "x"), (("a", "b", 1), "old"), (("n",), 5), (("t",), True),
               (("z",), None), (("e",), {}))
    cand = Candidate(url=BASE + "api/x", param="a.b[1]", method="POST", location="json",
                     base_entries=tuple((list(p), v) for p, v in entries))   # evidence form
    bound = _FormBoundSender(RequestsProbeSender(session=inner), cand)
    bound.send(BASE + "api/x", "a.b[1]", "zq'mark", method="POST", location="json")
    assert inner.sent[-1]["body"] == {"a": {"b": ["x", "zq'mark"]}, "n": 5, "t": True,
                                      "z": None, "e": {}}
    bound.send(BASE + "api/x", "n", "1 AND 1=1", method="POST", location="json")
    assert inner.sent[-1]["body"]["n"] == "1 AND 1=1"           # the payload is a string
    assert inner.sent[-1]["body"]["a"]["b"][1] == "old"
    with pytest.raises(UnplaceableLocation):
        bound.send(BASE + "api/x", "a[", "v", method="POST", location="json")
    with pytest.raises(UnplaceableLocation):                     # a path through a leaf
        bound.send(BASE + "api/x", "n.deeper", "v", method="POST", location="json")
    assert len(inner.sent) == 2


def _seam_over(transport):
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.tools.probesender import SeamProbeSender
    return SeamProbeSender(HttpClient(RequestBudget(100), ["h"], transport=transport))


def _every_sender():
    """``(name, make(record) -> send(url, method))`` for every sender with a send gate."""
    from fuzzlab.greybox.run import RequestsCorrelatingSender

    def seam(record):
        s = _seam_over(lambda m, u, h, b, t: record.append(u) or (200, {}, b"ok"))
        return lambda url, method: s.send(url, "p", "v", method=method, location="body")

    def plain(record):
        w = _JsonWire(lambda *a: (record.append(a) or 200, "ok"))
        s = RequestsProbeSender(session=w)
        return lambda url, method: s.send(url, "p", "v", method=method, location="body")

    def greybox(record):
        w = _JsonWire(lambda *a: (record.append(a) or 200, "ok"))
        s = RequestsCorrelatingSender(session=w, id_factory=lambda: "c")
        return lambda url, method: s.send_correlated(url, "p", "v", method=method,
                                                     location="body")
    return [("seam", seam), ("requests", plain), ("greybox", greybox)]


@pytest.mark.parametrize("name,make", _every_sender(), ids=[n for n, _m in _every_sender()])
def test_every_sender_refuses_a_crawl_sourced_delete_at_send_time(name, make):
    record: list = []
    send = make(record)
    with pytest.raises(DestructiveUrlRefused):
        send("http://h/api/Feedbacks/1", "DELETE")
    with pytest.raises(DestructiveUrlRefused):
        send("http://h/api/Feedbacks/1", "delete")
    assert record == []
    send("http://h/api/Feedbacks/1", "PUT")                       # other methods pass
    assert len(record) == 1


def test_an_explicitly_enumerated_delete_is_allowed():
    from fuzzlab.core.urls import check_send_url, url_key
    check_send_url("http://h/api/x", frozenset({url_key("http://h/api/x")}), method="DELETE")
    with pytest.raises(DestructiveUrlRefused):
        check_send_url("http://h/api/x", frozenset(), method="DELETE")


def test_greybox_refuses_a_json_point_and_never_gets_one_from_the_store(tmp_path):
    from fuzzlab.greybox.run import RequestsCorrelatingSender, points_from_store
    wire = _JsonWire()
    with pytest.raises(UnplaceableLocation):
        RequestsCorrelatingSender(session=wire, id_factory=lambda: "c").send_correlated(
            BASE + "api/x", "q", "v", method="POST", location="json")
    assert wire.sent == []
    store, run, _c = _import(tmp_path, [_req(BASE + "api/x", {"q": "v"})])
    with store:
        skipped: list = []
        assert points_from_store(store, run, BASE, skipped=skipped) == []
    assert skipped == [("/app/api/x", "POST", "q", "JSON body point (greybox cannot place it)")]


def test_the_m6_executor_refuses_a_json_point_before_any_browser():
    from fuzzlab.oracle.browser import ExecRequest
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor
    obs = PlaywrightBrowserExecutor().run(ExecRequest(url=BASE + "api/x", param="q",
                                                      value="v", location="json"), "t")
    assert not obs.executed and "unplaceable" in obs.detail


def test_the_location_feature_treats_json_as_body():
    from fuzzlab.core.features import CANDIDATE_FEATURE_NAMES, extract_candidate_v1
    i = CANDIDATE_FEATURE_NAMES.index("loc_body")
    for loc, want in (("json", 1.0), ("body", 1.0), ("query", 0.0), ("header", 0.0)):
        assert extract_candidate_v1({"location": loc, "param": "q"}, None, 1)[i] == want


# =========================================================================================
# Oracle: a mechanism that cannot place a point gives no verdict
# =========================================================================================
class _Strat:
    def __init__(self, name, outcome):
        self.vuln_class, self.mechanism, self.category = "sqli", name, "sql-injection"
        self.arm = f"sqli:{name}"
        self._outcome = outcome
        self.calls = 0

    def applies(self, c):
        return True

    def confirm(self, c, s):
        self.calls += 1
        if self._outcome == "raise":
            raise UnplaceableLocation("no")
        return self._outcome


def test_an_unplaceable_mechanism_does_not_stop_the_others_and_never_labels():
    from fuzzlab.oracle import Oracle
    from fuzzlab.oracle.probe import Verdict
    cand = Candidate(url=BASE + "x", param="p", location="json", category="sql-injection")
    hit = Verdict(True, "sqli", "b", {})
    a, b = _Strat("a", "raise"), _Strat("b", hit)
    assert Oracle(strategies=[a, b]).confirm_outcome(cand, None) == (hit, None)
    a, b = _Strat("a", "raise"), _Strat("b", None)
    assert Oracle(strategies=[a, b]).confirm_outcome(cand, None) == (None, None)
    only = Oracle(strategies=[_Strat("a", "raise")]).confirm_outcome(cand, None)
    assert only[0] is None and only[1].inconclusive and only[1].mechanism == "unplaceable"


# =========================================================================================
# R/J: an SPA route's query is a fragment point, placed in the route's query by M6
# =========================================================================================
def test_an_spa_route_query_is_a_fragment_point_never_a_query_point(tmp_path):
    pages = ["http://localhost/#/search?q=pup", "http://localhost/#!/item?id=4",
             "http://localhost/plain.php#top?x=1"]
    store, run, counts = _import(tmp_path, pages=pages)
    with store:
        params = _params(store, run)
        no_browser: list = []
        assert injection_points_from_store(store, run, BASE, skipped=no_browser) == []
        pts = injection_points_from_store(store, run, BASE, skipped=[],
                                          browser_available=True)
        header = header_points_from_store(store, run, BASE, ["User-Agent"])
        links = store.conn.execute("SELECT COUNT(*) c FROM form").fetchone()["c"]
    assert {(n, p["location"], p["url"]) for n, p in params.items()} == {
        ("q", "fragment", "/#/search"), ("id", "fragment", "/#!/item")}
    assert counts["fragment_parameter"] == 2 and links == 0
    assert {r[3] for r in no_browser} == {"client-only/DOM (needs browser execution, M6)"}
    assert {(p.url, p.param, p.location) for p in pts} == {
        ("http://localhost/#/search", "q", "fragment"),
        ("http://localhost/#!/item", "id", "fragment")}
    assert all("?" not in p.url for p in header)


def test_link_sets_and_header_queries_read_only_the_real_query(tmp_path):
    """Lane A's builders read `urlsplit(url).query` only: a route query never joins a
    link set (pinned for forms phase 3)."""
    page = BASE + "p.php?a=1&b=2#/x?q=evil"
    store, run, _c = _import(tmp_path, pages=[page])
    with store:
        assert first_link_set(store.conn, run, "/app/p.php") == [("a", "1"), ("b", "2")]
        (pt,) = header_points_from_store(store, run, BASE, ["User-Agent"])
        params = _params(store, run)
    assert pt.url == BASE + "p.php?a=1&b=2"
    assert {(n, p["location"]) for n, p in params.items()} == {
        ("a", "query"), ("b", "query"), ("q", "fragment")}


def test_a_destructive_spa_route_is_never_a_point(tmp_path):
    store, run, _c = _import(tmp_path, pages=["http://localhost/#/logout?next=x"])
    with store:
        skipped: list = []
        assert injection_points_from_store(store, run, BASE, skipped=skipped,
                                           browser_available=True) == []
    assert skipped and "destructive" in skipped[0][3]


def test_route_helpers():
    assert spa_route("http://h/#/search?q=x") == ("/search", "q=x")
    assert spa_route("http://h/#!/a") == ("!/a", "")
    assert spa_route("http://h/p#top") is None and spa_route("http://h/") is None
    assert to_route_path("http://h/app/#/search?q=x") == "/app/#/search"
    assert to_route_path("http://h/app/p.php?x=1#top") == "/app/p.php"


def test_a_crawled_fragment_payload_never_reaches_the_server(tmp_path):
    """With a browser, DOM XSS loads the route with the payload in its query; every
    other xss mechanism is refused (PA-0115), never sent as a query parameter."""
    from fuzzlab.oracle.browser import ExecObservation
    seen = []

    class Executor:
        def run(self, request, token):
            seen.append(request)
            return ExecObservation(False)
    wire = _JsonWire()
    store, run, _c = _import(tmp_path, pages=["http://localhost/#/search?q=pup"])
    with store:
        result = run_auto(base_url=BASE, store=store, run_id=run,
                          sender=RequestsProbeSender(session=wire), mode="manual",
                          selected_categories=["xss"], points_source="crawl",
                          browser=Executor())
    assert seen and {(r.url, r.location) for r in seen} == {
        ("http://localhost/#/search", "fragment")}
    assert all("q" not in s["query"] for s in wire.sent)
    assert result.findings == 0


def test_the_executor_places_a_fragment_inside_the_hash_route(monkeypatch):
    from fuzzlab.oracle.browser import ExecRequest
    from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor, _with_fragment
    gotos = _fake_playwright(monkeypatch)
    PlaywrightBrowserExecutor().run(ExecRequest(url="http://h:3000/#/search", param="q",
                                                value="<x y>", location="fragment"), "t")
    assert gotos == ["http://h:3000/#/search?q=%3Cx%20y%3E"]
    assert _with_fragment("http://h/#!/s?page=2", "q", "v") == "http://h/#!/s?page=2&q=v"
    assert _with_fragment("http://h/p.php#top", "q", "v w") == "http://h/p.php#q=v+w"


def _fake_playwright(monkeypatch) -> list:
    """A fake Playwright recording `page.goto` targets (the executor runs on-host)."""
    import sys
    import types
    gotos: list = []

    class Page:
        def on(self, *a):
            pass

        def goto(self, url, **kw):
            gotos.append(url)

        def evaluate(self, js):
            return []

        def wait_for_timeout(self, ms):              # the settle poll (BUG-0126)
            pass

    class Context:
        request = types.SimpleNamespace(post=lambda *a, **k: None)

        def add_init_script(self, s):
            pass

        def route(self, pattern, handler):
            pass

        def new_page(self):
            return Page()

    class Browser:
        def new_context(self, **kw):
            return Context()

        def close(self):
            pass

    class PW:
        chromium = types.SimpleNamespace(launch=lambda **kw: Browser())

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    fake = types.ModuleType("playwright.sync_api")
    fake.sync_playwright = PW
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake)
    monkeypatch.setattr("fuzzlab.tools.browserexec.PlaywrightBrowserExecutor.SETTLE_MS", 0)
    return gotos


# =========================================================================================
# End to end: a JSON login API (Juice Shop's shape) through `fuzzlab auto`'s run_auto
# =========================================================================================
from tests.test_login_form_isolation import (  # noqa: E402
    FakeApp,
    _main_sid,
    _seam,
    _sid_of,
)

SQLITE_ERROR = b'{"error":{"message":"SQLITE_ERROR: unrecognized token: \\"\'\\""}}'


class JsonLoginApp(FakeApp):
    """`FakeApp` plus a public JSON login API that re-binds the session of whoever sends
    an injection to it (the worst case), and a registration API."""

    LOGIN = "/app/rest/user/login"

    def transport(self, method, url, headers, body, timeout):
        if headers.get("Content-Type") != jsonbody.ENCTYPE:
            return super().transport(method, url, headers, body, timeout)
        sid = _sid_of(headers.get("Cookie"))
        data = json.loads(body or b"{}")
        self.requests.append((method, urlsplit(url).path, sid, data, dict(headers)))
        return self.page(method, url, sid, data)

    def page(self, method, url, sid, data):
        if urlsplit(url).path == self.LOGIN and method == "POST":
            email = data.get("email") if isinstance(data, dict) else None
            if not isinstance(email, str):
                return 400, {}, b'{"error":"bad request"}'
            if "'" in email:
                if sid in self.sessions:
                    self.sessions[sid] = "victim"     # the injection logged it in
                return 500, {"Content-Type": "application/json"}, SQLITE_ERROR
            return 401, {"Content-Type": "text/plain"}, b"Invalid email or password."
        return super().page(method, url, sid, data)


def _login_requests():
    return [_req(LOGIN_API, {"email": "fuzzlab@example.invalid", "password": ""},
                 page=BASE + "#/login", source="submit"),
            _req(BASE + "api/Users", {"email": "fuzzlab@example.invalid", "password": "",
                                      "passwordRepeat": "", "securityAnswer": "x"},
                 page=BASE + "#/register", source="submit")]


def test_a_json_login_sqli_is_confirmed_on_an_isolated_session_only(tmp_path):
    app = JsonLoginApp()
    store, run, counts = _import(tmp_path, _login_requests())
    with store:
        assert (counts["request_json"], counts["request_refused"]) == (1, 1)
        _mgr, _client, sender = _seam(app)
        result = run_auto(base_url=BASE, store=store, run_id=run, sender=sender,
                          mode="manual", selected_categories=["sql-injection"],
                          points_source="crawl")
        found = {(r["url"], r["param"], r["vuln_class"]) for r in store.conn.execute(
            "SELECT url, param, vuln_class FROM finding WHERE run_id=?", (run,))}
        evaluated = {r["param"] for r in store.conn.execute(
            "SELECT DISTINCT param FROM evaluation WHERE run_id=?", (run,))}
    assert ("/app/rest/user/login", "email", "sqli") in found
    assert evaluated == {"email"}                       # password never a point
    main = _main_sid(app)
    to_api = [r for r in app.requests if r[1] == JsonLoginApp.LOGIN]
    assert to_api and all(r[2] != main for r in to_api)      # never the run's session
    assert all(r[3]["password"] == "" for r in to_api)        # sent empty, never fuzzed
    assert all(r[4]["Content-Type"] == "application/json" for r in to_api)
    assert app.sessions[main] == "admin"                     # the run's session survives
    assert not any(r[1] == "/app/api/Users" for r in app.requests)
    assert result.metrics["isolated_sessions"]["paths"] == 1


def test_a_json_login_sqli_is_confirmed_anonymously_by_the_plain_sender(tmp_path):
    app = JsonLoginApp()

    def handler(method, path, body, headers):
        status, _h, text = app.page(method, "http://localhost" + path, None, body)
        return status, text.decode()
    wire = _JsonWire(handler)
    store, run, _c = _import(tmp_path, _login_requests())
    with store:
        run_auto(base_url=BASE, store=store, run_id=run,
                 sender=RequestsProbeSender(session=wire), mode="manual",
                 selected_categories=["sql-injection"], points_source="crawl")
        found = {(r["param"], r["vuln_class"]) for r in store.conn.execute(
            "SELECT param, vuln_class FROM finding WHERE run_id=?", (run,))}
    assert ("email", "sqli") in found
    assert all("Cookie" not in s["headers"] for s in wire.sent)
    assert all(s["body"]["password"] == "" for s in wire.sent)


def test_the_auto_cli_passes_the_json_writes_flag_to_the_import(tmp_path, monkeypatch):
    from fuzzlab.harness import auto_cli
    seen = {}

    class Stop(Exception):
        pass

    def fake_import(db, store, run_id, **kw):
        seen.update(kw)
        raise Stop
    (tmp_path / "s.db").write_bytes(b"")
    monkeypatch.setattr(auto_cli, "import_spider", fake_import)
    for flag, want in (([], False), (["--fuzz-json-writes"], True)):
        with pytest.raises(Stop):
            auto_cli.main(["--base-url", "http://127.0.0.1:3000", "--spider-db",
                           str(tmp_path / "s.db"), "--store", str(tmp_path / "u.db"),
                           "--mode", "manual", "--categories", "sql-injection",
                           "--authorized", *flag])
        assert seen["fuzz_json_writes"] is want


# =========================================================================================
# Review follow-ups (reviewers A and B): J2-J4, B1-B4
# =========================================================================================
def _unplaceable_fragment_run(tmp_path):
    """A crawl-style fragment point (an SPA route's ``next``), no browser, xss only (the
    one category a fragment point draws, CC-AUD-0036): without a browser every mechanism
    is HTTP-only, so the crawl guard refuses it everywhere."""
    from fuzzlab.core.runmode import RunPlan
    from fuzzlab.harness.auto import _CountingSender, _FragmentGuard
    from fuzzlab.harness.pipeline import run_pipeline
    wire = _JsonWire()
    point = InjectionPoint(url="http://localhost/#/go", param="next", method="GET",
                           location="fragment", origin="crawl")
    plan = RunPlan(mode="manual", categories=["xss"], scored=False,
                   source="manual")
    store = Store(tmp_path / "f.db")
    run = store.start_run("auto", "localhost")
    sender = RequestsProbeSender(session=wire)
    result = run_pipeline([point], store, run, _FragmentGuard(_CountingSender(sender)),
                          plan)
    return store, run, result, wire


def test_a_fragment_point_no_mechanism_can_place_is_inconclusive_never_a_negative(
        tmp_path, capsys):
    """J2 (reviewer A): the status, the CLI line, and the ML dataset's exclusion."""
    from types import SimpleNamespace

    from fuzzlab.core.oracle_status import INCONCLUSIVE, UNLABELLED
    from fuzzlab.harness import auto_cli
    from fuzzlab.ml.dataset import build_dataset
    store, run, result, wire = _unplaceable_fragment_run(tmp_path)
    with store:
        statuses = [r["oracle_status"] for r in store.conn.execute(
            "SELECT oracle_status FROM candidate WHERE run_id=?", (run,))]
        stored = {r["key"]: r["value"] for r in store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run,))}
        assert build_dataset(store, run).ids == []          # never a training label
    assert statuses and set(statuses) == {INCONCLUSIVE} and INCONCLUSIVE in UNLABELLED
    assert wire.sent == []                                   # nothing went over HTTP
    m = result.metrics
    assert m["oracle_inconclusive"] == len(statuses) == m["oracle_unplaceable"]
    assert m["oracle_rejected"] == 0                         # never a negative
    assert stored["pipeline_oracle_unplaceable"] == len(statuses)
    assert stored["pipeline_oracle_inconclusive_unplaceable"] == len(statuses)
    (item,) = result.inconclusive
    assert item["mechanism"] == "unplaceable" and "browser only" in item["reason"]
    capsys.readouterr()
    auto_cli._print_summary(SimpleNamespace(score=False, rank=False, anomaly=False),
                            None, result)
    out = capsys.readouterr().out
    assert ("inconclusive (1 candidate key(s) could not be decided: a cost cap stopped a "
            "started check, or no mechanism could place the point; unlabelled, "
            "FR-FUZZ-45/47):") in out
    assert ("- fragment /#/go [next]: unplaceable (no mechanism could place the point: "
            "a fragment point is placed by the browser only)") in out
    assert "not started" not in out                         # no empty cap detail
    assert f"unplaceable: {len(statuses)} candidate(s) no mechanism could place" in out


def test_the_run_page_names_the_undecided_mechanism(tmp_path):
    """J2: the web run page shows which kind (`unplaceable` vs a capped mechanism), from
    what the pipeline wrote."""
    pytest.importorskip("fastapi")
    from fuzzlab.core.config import load_config
    from fuzzlab.web.app import create_app
    from fuzzlab.web.results import inconclusive_by
    from tests._webclient import web_client
    store, run, _result, _w = _unplaceable_fragment_run(tmp_path)
    with store:
        metrics = {r["key"]: r["value"] for r in store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run,))}
    assert inconclusive_by(metrics) == [("unplaceable", 1)]
    assert inconclusive_by({"pipeline_oracle_inconclusive_boolean-differential": 2.0,
                            "pipeline_oracle_inconclusive": 2.0, "x": "y"}) == [
        ("boolean-differential", 2)]
    cfg = load_config(overrides={"store_path": str(tmp_path / "f.db"),
                                 "target_base_url": "http://localhost"}, environ={})
    page = web_client(create_app(cfg)).get(f"/runs/{run}").text
    text = " ".join(page.split())
    assert ("inconclusive 1 (could not be decided: a cost cap stopped a started check, "
            "or no mechanism could place the point:") in text
    assert 'data-field="inconclusive-unplaceable">unplaceable 1</span>' in text


def test_server_side_rules_never_fire_on_a_fragment_point():
    """B1 (reviewer B): only client-side categories (DOM/reflected XSS, open redirect)
    on a fragment point; every other rule excludes the location, whatever the name or
    value shape."""
    client_side = {"xss"}                    # open redirect too is off fragments (CC-AUD-0036)
    rules = load_rules()
    for rule in rules:
        if rule.category in client_side:
            continue
        excluded = ("fragment" in rule.when.get("location_not_in", ())
                    or ("location_in" in rule.when
                        and "fragment" not in rule.when["location_in"]))
        assert excluded, rule.id
    for name, shapes in (("url", {"url"}), ("host", {"hostname"}), ("file", {"filename"}),
                         ("sort", set()), ("price", set()), ("title", set()), ("q", set())):
        for method in ("GET", "POST"):
            point = InjectionPoint(url="http://h/#/x", param=name, method=method,
                                   location="fragment", origin="crawl",
                                   value_shapes=frozenset(shapes))
            fired = {r.category for r in rules if matches(r, point)}
            assert fired <= client_side, (name, fired)
    # a query point with the same name still gets them (the exclusion is location-only)
    q = InjectionPoint(url="http://h/x", param="host", location="query", origin="crawl")
    assert "command-injection" in {r.category for r in rules if matches(r, q)}


def test_the_location_not_in_predicate_is_validated():
    from fuzzlab.audit.rules import Rule, RuleError, validate_rule
    validate_rule(Rule("ok", "x", "t", {"location_not_in": ["fragment"]}))
    with pytest.raises(RuleError):
        validate_rule(Rule("bad", "x", "t", {"location_not_in": "fragment"}))


def _masking_handlers(source: str) -> list[int]:
    """Lines of handlers that catch `UnplaceableLocation` (a `ValueError`) -- bare,
    `BaseException`, `Exception`, `ValueError`, or the class itself, alone or in a
    tuple -- around a probe send (`_send`, `send`, `send_correlated`)."""
    broad = {"BaseException", "Exception", "ValueError", "UnplaceableLocation"}

    def names(node):
        if node is None:
            return {"BaseException"}
        if isinstance(node, ast.Tuple):
            return {n for e in node.elts for n in names(e)}
        return {getattr(node, "id", None) or getattr(node, "attr", None)}

    def sends(stmts):
        return any(isinstance(c, ast.Call)
                   and (getattr(c.func, "id", None) or getattr(c.func, "attr", None))
                   in ("_send", "send", "send_correlated")
                   for s in stmts for c in ast.walk(s))
    out = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Try) and sends(node.body):
            out += [h.lineno for h in node.handlers if names(h.type) & broad]
    return out


def test_no_strategy_masks_an_unplaceable_send():
    """B3 (reviewer B): a strategy that swallowed `UnplaceableLocation` would turn
    "cannot place" into "not vulnerable"."""
    src = (ROOT / "fuzzlab/oracle/strategies.py").read_text()
    assert _masking_handlers(src) == []


def test_the_masking_guard_catches_a_synthetic_offender():
    """PA-0034(2): the guard flags each masking shape, and only those."""
    tpl = ("class S:\n    def confirm(self, c, sender):\n        try:\n"
           "            self._send(sender, c, 'v')\n        except {exc}:\n"
           "            return None\n")
    for exc, flagged in (("ValueError", True), ("Exception", True),
                         ("(TypeError, ValueError)", True), ("UnplaceableLocation", True),
                         ("KeyError", False), ("(TypeError, KeyError)", False)):
        assert bool(_masking_handlers(tpl.replace("{exc}", exc))) is flagged, exc
    bare = tpl.replace("except {exc}:", "except:")
    assert _masking_handlers(bare) == [5]
    no_send = "try:\n    int('x')\nexcept ValueError:\n    pass\n"
    assert _masking_handlers(no_send) == []


def test_a_leaf_absent_from_a_captured_body_is_refused_never_appended():
    """B4 (reviewer B): with entries, an unknown leaf raises (UnplaceableLocation at the
    sender); with none, the leaf is the whole body."""
    entries = [(("email",), "e"), (("password",), "")]
    with pytest.raises(jsonbody.JsonPlacementError):
        jsonbody.replace_leaf(entries, "role", "admin")
    with pytest.raises(jsonbody.JsonPlacementError):
        jsonbody.body_for("role", "admin", entries)
    assert jsonbody.body_for("a.b", "v") == b'{"a":{"b":"v"}}'
    wire = _JsonWire()
    with pytest.raises(UnplaceableLocation):
        RequestsProbeSender(session=wire).send(BASE + "api/x", "role", "admin",
                                               method="POST", location="json",
                                               entries=entries)
    assert wire.sent == []
    from fuzzlab.oracle.oracle import _FormBoundSender
    cand = Candidate(url=BASE + "api/x", param="email", method="POST", location="json",
                     base_entries=tuple((list(p), v) for p, v in entries))
    with pytest.raises(UnplaceableLocation):
        _FormBoundSender(RequestsProbeSender(session=wire), cand).send(
            BASE + "api/x", "role", "admin", method="POST", location="json")
    assert wire.sent == []


def test_the_same_parameter_on_two_routes_gives_two_findings(tmp_path):
    """J4 (reviewer A): a fragment finding keeps its route (`to_route_path`)."""
    from fuzzlab.oracle.browser import ExecObservation

    class Fires:
        def run(self, request, token):
            return ExecObservation(True, "fake")
    pages = ["http://localhost/#/search?q=pup", "http://localhost/#/track-result?q=1"]
    store, run, _c = _import(tmp_path, pages=pages)
    with store:
        run_auto(base_url=BASE, store=store, run_id=run,
                 sender=RequestsProbeSender(session=_JsonWire()), mode="manual",
                 selected_categories=["xss"], points_source="crawl", browser=Fires())
        found = sorted((r["url"], r["param"], r["vuln_class"]) for r in store.conn.execute(
            "SELECT url, param, vuln_class FROM finding WHERE run_id=?", (run,)))
    assert found == [("/#/search", "q", "xss-dom"), ("/#/track-result", "q", "xss-dom")]


def test_a_non_fragment_finding_url_is_unchanged():
    from fuzzlab.oracle.oracle import finding_url
    assert finding_url(Candidate(url="http://h/app/p.php?x=1#/a?q=1", param="x")) == \
        "/app/p.php"
    assert finding_url(Candidate(url="http://h/app/#/a", param="q",
                                 location="fragment")) == "/app/#/a"


# --- forms phase 3 merge: one SPA-route definition and one leaf rule (PA-0003) ---------
@pytest.mark.parametrize("url,is_route", [
    ("http://h/#/search?q=x", True), ("http://h/#!/x", True), ("http://h/#top", False),
    ("http://h/#", False), ("http://h/", False), ("http://h/#//cdn", True),
])
def test_one_spa_route_definition_serves_every_lane(url, is_route):
    from fuzzlab.core.redaction import redact_spa_fragment
    from fuzzlab.core.urls import spa_route
    from fuzzlab.tools.spa import spa_fragment
    assert (spa_route(url) is not None) is is_route
    assert (spa_fragment(url) is not None) is is_route
    secret = url.split("#")[0] + "#/r?token=9f86d081884c7d659a2feaa0c55ad015"
    assert "9f86d081884c7d659a2feaa0c55ad015" not in redact_spa_fragment(secret)


def test_one_leaf_rule_serves_capture_and_import():
    from fuzzlab.core.redaction import redact_captured_body, redact_leaf
    from fuzzlab.tools.store_adapter import redact_leaf as importer_leaf
    cases = [(["cardNum"], 4716190207394368), (["quantity"], 3), (["password"], "x"),
             (["t"], "9f86d081884c7d659a2feaa0c55ad015"), (["ok"], True), (["n"], 1.5)]
    for segs, value in cases:
        assert importer_leaf(segs, value) == redact_leaf(segs, value)
        body = json.dumps({segs[0]: value}).encode()
        captured, _why = redact_captured_body(body, "application/json")
        assert captured[segs[0]] == redact_leaf(segs, value), segs


def test_an_unknown_location_is_a_rule_error():
    from fuzzlab.audit.rules import Rule, RuleError, validate_rule
    for key in ("location_in", "location_not_in"):
        with pytest.raises(RuleError, match="unknown value"):
            validate_rule(Rule(id="R-X", category="sql-injection", transaction_type="x",
                               when={key: ["fragmnet"]}))


def test_open_redirect_rules_never_fire_on_a_fragment_point():
    from fuzzlab.audit import load_rules
    for rule in load_rules():
        if rule.category == "open-redirect":
            assert "fragment" in rule.when.get("location_not_in", []), rule.id


def test_the_crawlers_table_is_the_contract_the_importer_reads(tmp_path):
    """Forms phase 3 integration: lane S writes `discovered_requests`, lane J reads it;
    the columns are the agreed contract on both sides."""
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))
    sm.reset()
    sm.close()
    db = sqlite3.connect(tmp_path / "s.db")
    cols = [r[1] for r in db.execute("PRAGMA table_info(discovered_requests)")]
    db.close()
    assert cols == ["id", "page_url", "method", "url", "content_type", "body_json",
                    "source", "signature"]
