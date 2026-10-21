"""Captured requests are kept per API operation, never per top-level key set
(FR-CRAWL-37, BUG-0546, audit defect 9).

The spider's capture writer (`StorageManager.record_request`) stored one row per
method, canonical path and sorted top-level body keys, and dropped every later request
with that key set. A dispatcher endpoint (GraphQL, JSON-RPC, an ``action``/``op``/``cmd``
field) lost every operation but the first, and a request that differed only below the
top level lost what it added.

Now two requests are one operation only when their method, canonical path, media type
and every operation selector match (`tools.apiop.operation_key`), and a request is a
duplicate only when a stored row of its operation has its exact typed key paths (every
depth, plus query names). One that adds a key path or a type to the operation's merged
schema (`apiop.operation_schema`) is always stored with its own body; another
combination of known inputs is stored up to `apiop.MAX_CONTEXT_ROWS` rows. Every test
here drives the real write site.

Review round 1: every non-empty string value of a selector field is a selector (B1: a
value with whitespace, or over 64 characters, was data and merged two operations); the
PA-0002 sweep pins every instance it does not fix, checked by a guard over BUG-0546's
sweep rows (B2).
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from fuzzlab.tools import apiop
from tests._spa_fixture import db_rows

REPO = Path(__file__).resolve().parents[1]
JSON = "application/json"
FORM = "application/x-www-form-urlencoded"
GQL = "http://127.0.0.1:8080/graphql"
API = "http://127.0.0.1:8080/api"


@pytest.fixture
def store(tmp_path):
    from fuzzlab.tools.spider import StorageManager
    db = str(tmp_path / "s.db")
    sm = StorageManager(db)

    def record(url, body, ct=JSON, method="POST"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return sm.record_request("http://127.0.0.1:8080/", method, url, ct, raw, "passive")

    def rows():
        return db_rows(db, "SELECT url, body_json FROM discovered_requests ORDER BY id")

    record.rows = rows
    record.db = db
    yield record
    sm.close()


def _bodies(rows):
    return [json.loads(b) for _u, b in rows]


# --- the defect: a dispatcher's operations collapsed into its first one -------------

def test_two_graphql_operations_on_one_endpoint_stay_two_operations(store):
    get_user = {"query": "query GetUser($n: String) { user(name: $n) { email } }",
                "operationName": "GetUser", "variables": {"n": "alice"}}
    list_posts = {"query": "query ListPosts { posts { title } }",
                  "operationName": "ListPosts", "variables": {"n": "alice"}}
    assert store(GQL, get_user) is None
    assert store(GQL, list_posts) is None              # was "duplicate": same keys
    # an anonymous operation is told by its root fields
    assert store(GQL, {"query": "{ me { name } }"}) is None
    assert store(GQL, {"query": "{ shop { name } }"}) is None
    # one document, two operations: operationName chooses
    doc = "query A { a } mutation B($x: Int) { b(x: $x) }"
    assert store(GQL, {"query": doc, "operationName": "A"}) is None
    assert store(GQL, {"query": doc, "operationName": "B"}) is None
    # aliases, fragments and comments do not change the operation
    again = {"query": "# again\nquery GetUser($n: String) { u: user(name: $n) "
                      "{ ...E } } fragment E on User { email }",
             "operationName": "GetUser", "variables": {"n": "bob"}}
    assert store(GQL, again) == "duplicate"
    assert [b.get("operationName") for b in _bodies(store.rows())] == \
        ["GetUser", "ListPosts", None, None, "A", "B"]


def test_two_json_bodies_differing_only_in_a_nested_key_keep_both(store):
    from fuzzlab.tools.store_adapter import captured_request
    assert store(API, {"data": {"q": "x"}}) is None
    assert store(API, {"data": {"name": "x"}}) is None     # was "duplicate"
    rows = store.rows()
    schema = apiop.operation_schema(rows)
    assert {("body", "data", "q", "string"),
            ("body", "data", "name", "string")} <= schema    # the merged schema
    # each row is a body the app sent, and each is imported with its own leaf
    assert _bodies(rows) == [{"data": {"q": "x"}}, {"data": {"name": "x"}}]
    leaves = [captured_request({"method": "POST", "url": u, "content_type": JSON,
                                "body_json": b, "page_url": "http://127.0.0.1:8080/"})
              for u, b in rows]
    assert [(why, [name for name, *_ in found]) for why, _k, found in leaves] == \
        [(None, ["data.q"]), (None, ["data.name"])]
    # both inputs together are another context of the operation: kept, once
    assert store(API, {"data": {"name": "y", "q": "z"}}) is None
    assert store(API, {"data": {"q": "a", "name": "b"}}) == "duplicate"
    # a type is part of the schema at every depth: a new one is kept
    assert store(API, {"data": {"q": 5}}) is None
    assert store(API, {"data": {"q": 7}}) == "duplicate"
    assert store(API, {"data": None}) is None
    assert store(API, {"data": {"q": [{"deep": True}]}}) is None
    assert len(store.rows()) == 6
    assert ("body", "data", "q", 0, "deep", "boolean") in \
        apiop.operation_schema(store.rows())


def test_the_audits_nested_command_is_not_a_duplicate(store):
    assert store("http://127.0.0.1:8080/api", {"data": {"q": "x"}}) is None
    assert store("http://127.0.0.1:8080/api", {"data": {"cmd": "x"}}) is None
    assert _bodies(store.rows()) == [{"data": {"q": "x"}}, {"data": {"cmd": "x"}}]


def test_json_rpc_methods_stay_apart(store):
    def rpc(method, **params):
        return {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    assert store(API, rpc("user.get", name="a")) is None
    assert store(API, rpc("user.find", name="a")) is None   # was "duplicate"
    assert store(API, rpc("user.get", name="b")) == "duplicate"
    # a batch is told by every call's method
    assert store(API, [rpc("a.b"), rpc("c.d")]) is None
    assert store(API, [rpc("a.b"), rpc("e.f")]) is None
    assert store(API, [rpc("a.b"), rpc("c.d")]) == "duplicate"
    assert [b["method"] if isinstance(b, dict) else [c["method"] for c in b]
            for b in _bodies(store.rows())] == \
        ["user.get", "user.find", ["a.b", "c.d"], ["a.b", "e.f"]]


def test_an_action_op_or_cmd_field_in_the_body_or_query_keeps_operations_apart(store):
    assert store(API + "?action=list", {"q": "x"}) is None
    assert store(API + "?action=search", {"q": "x"}) is None   # was "duplicate"
    assert store(API + "?action=search", {"q": "y"}) == "duplicate"
    assert store(API, b"op=view&title=a", FORM) is None
    assert store(API, b"op=edit&title=a", FORM) is None
    assert store(API, b"_method=PUT&title=a", FORM) is None    # a method override
    assert store(API, {"cmd": 3, "arg": "a"}) is None
    assert store(API, {"cmd": 4, "arg": "a"}) is None
    # free text in a field so named is kept as a selector too: a data field misjudged
    # as one costs a row, never an input (FR-CRAWL-37)
    assert store(API, {"command": "ls -la /tmp", "arg": "a"}) is None
    assert store(API, {"command": "cat a.txt", "arg": "a"}) is None   # was "duplicate"
    # a boolean is no selector: the flag's two values are one operation
    assert store(API, {"op": True, "flag": 1}) is None
    assert store(API, {"op": False, "flag": 1}) == "duplicate"
    assert len(store.rows()) == 10


CART = "http://127.0.0.1:8080/cart"


def test_a_selector_value_with_whitespace_or_over_64_characters_keeps_operations_apart(store):
    """A submit button's label is a common dispatcher value (``name=action value="Add
    to cart"``, sent by a FormData built with its submitter): every non-empty string
    value of a selector field is a selector (review round 1, B1)."""
    # (1) form-encoded body
    assert store(CART, b"action=Add+to+cart&item=1", FORM) is None
    assert store(CART, b"action=Remove+from+cart&item=1", FORM) is None   # was "duplicate"
    assert store(CART, b"action=Add+to+cart&item=2", FORM) == "duplicate"
    # (2) JSON body; a run of whitespace is folded to one space
    assert store(CART, {"action": "Add to cart", "item": 1}) is None
    assert store(CART, {"action": "Delete item", "item": 1}) is None      # was "duplicate"
    assert store(CART, {"action": "Add  to\tcart", "item": 7}) == "duplicate"
    # (3) the query
    assert store(CART + "?action=Add+to+cart", {"item": 1}) is None
    assert store(CART + "?action=Remove+item", {"item": 1}) is None       # was "duplicate"
    # (4) a value over 64 characters is keyed by the digest of its folded text
    assert store(API, {"action": "x" * 65, "u": "a"}) is None
    assert store(API, {"action": "y" * 65, "u": "a"}) is None             # was "duplicate"
    assert store(API, {"action": "x" * 65, "u": "b"}) == "duplicate"
    assert [(u, json.loads(b).get("action")) for u, b in store.rows()] == [
        (CART, "Add to cart"), (CART, "Remove from cart"), (CART, "Add to cart"),
        (CART, "Delete item"), (CART + "?action=Add+to+cart", None),
        (CART + "?action=Remove+item", None), (API, "x" * 65), (API, "y" * 65)]
    # the selector itself: a short folded value by its text, a long one by its digest
    import hashlib
    assert apiop.operation_selectors({"action": "Add \n to  cart"}) == [
        ["field", ["$", "action"], "Add to cart"]]
    long_value = "z" * (apiop.MAX_SELECTOR_CHARS + 1)
    assert apiop.operation_selectors({"action": long_value}) == [
        ["field", ["$", "action"],
         "sha256:" + hashlib.sha256(long_value.encode("utf-8")).hexdigest()]]
    assert apiop.operation_selectors({"action": ""}) == []                # no value
    assert apiop.operation_selectors({"action": True}) == []              # a flag


def test_the_media_type_and_a_new_query_name_are_kept(store):
    assert store(API, {"a": "x"}) is None
    assert store(API, b"a=x", FORM) is None                     # was "duplicate"
    assert store(API + "?page=2", {"a": "x"}) is None           # adds a query name
    assert store(API + "?page=3", {"a": "y"}) == "duplicate"
    assert [u for u, _b in store.rows()] == [API, API, API + "?page=2"]


def test_a_graphql_document_over_the_token_cap_is_told_by_its_text(store):
    def huge(name):
        return "{ " + " ".join(f"{name}{i}(a: 1) {{ x }}"
                               for i in range(apiop.MAX_GRAPHQL_TOKENS // 9 + 10)) + " }"
    assert store(GQL, {"query": huge("f")}) is None
    assert store(GQL, {"query": huge("g")}) is None              # another document
    assert store(GQL, {"query": huge("f").replace(" }", "\n}")}) == "duplicate"
    # a search text in a "query" field is no GraphQL document and selects nothing
    assert store(API, {"query": "red shoes"}) is None
    assert store(API, {"query": "blue {hats}"}) == "duplicate"


# --- the PA-0002 sweep: instances of the class in other items' code (PA-0531(4)) ---

@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0546 sweep: StorageManager.record_form keys a form by its action, method and "
    "control names only, so a second form told apart by a hidden dispatcher field's "
    "value is dropped (owner: lane SPIDER, tools/spider.py::StorageManager.record_form)"))
def test_two_forms_told_apart_by_a_hidden_action_value_are_both_kept(tmp_path):
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "s.db"))

    def form(value):
        return {"page_url": "http://127.0.0.1:8080/",
                "action_url": "http://127.0.0.1:8080/index.php", "method": "post",
                "enctype": FORM, "entries": [["action", value], ["title", ""]],
                "controls": [["action", "hidden"], ["title", "text"]],
                "selector": False, "options": {}}
    try:
        assert sm.record_form(form("edit")) is True
        assert sm.record_form(form("publish")) is True
    finally:
        sm.close()


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=(
    "BUG-0546 sweep: disco.synth keys an endpoint by origin, method, path template and "
    "content family, so a GraphQL endpoint's operations become one inventory operation "
    "(owner: disco synth, fuzzlab/disco/synth.py::synthesize, FR-CRAWL-20)"))
def test_the_disco_inventory_keeps_two_graphql_operations_apart():
    from fuzzlab.disco.capture import make_record
    from fuzzlab.disco.synth import synthesize
    bodies = [{"query": "query GetUser { user { email } }", "operationName": "GetUser"},
              {"query": "query ListPosts { posts { title } }", "operationName": "ListPosts"}]
    records = [make_record(kind="http", t=float(i), action_id="act-1", method="POST",
                           url=GQL, req_headers={"Content-Type": JSON},
                           req_body=json.dumps(b).encode(), status=200,
                           res_headers={"Content-Type": JSON}, res_body=b'{"data": {}}',
                           latency_ms=5)
               for i, b in enumerate(bodies)]
    paths = synthesize(records)["paths"]
    assert sum(len(item) for item in paths.values()) == 2


# Was a strict xfail from the BUG-0546 sweep: the importer stored a captured request's
# parameter only when no earlier captured request on its endpoint had that name (the first
# won), so a second GraphQL operation's variables were bound to the first operation's form.
# It is fixed by the audit defect 8 lane (BUG-0530, CC-AUD-0056: `_store_request` keeps one
# row per request context, SP-57), and the pin was removed at that lane's 2053f22 merge.
def test_each_captured_graphql_operation_gets_its_own_points_on_import(store, tmp_path):
    from fuzzlab.core.store import Store
    from fuzzlab.tools.store_adapter import import_spider
    get_user = {"query": "query GetUser($n: String) { user(name: $n) { email } }",
                "operationName": "GetUser", "variables": {"n": "alice"}}
    search = {"query": "query SearchPosts($n: String) { posts(title: $n) { body } }",
              "operationName": "SearchPosts", "variables": {"n": "hello"}}
    assert store(GQL, get_user) is None
    assert store(GQL, search) is None                     # two rows: this lane's fix
    with Store(tmp_path / "u.db") as st:
        run = st.start_run("auto", "localhost")
        counts = import_spider(store.db, st, run)
        forms = [r["id"] for r in st.conn.execute(
            "SELECT id FROM form WHERE run_id=? ORDER BY id", (run,))]
        params = {(r["form_id"], r["name"]) for r in st.conn.execute(
            "SELECT form_id, name FROM parameter WHERE run_id=?", (run,))}
    assert counts["request_json"] == 2 and len(forms) == 2   # both are form rows
    assert (forms[0], "variables.n") in params
    assert (forms[1], "variables.n") in params            # SearchPosts' own input


def test_two_endpoints_on_pages_of_one_dom_template_are_both_audited(tmp_path):
    """BUG-0546's sweep pin for the DOM-template stage, fixed by BUG-0547 (DEDUP10,
    `core.dedup.fold_points`): kept as a regression test."""
    from fuzzlab.audit import InjectionPoint
    from fuzzlab.core.runmode import RunPlan
    from fuzzlab.core.store import Store
    from fuzzlab.harness.pipeline import run_pipeline
    from fuzzlab.oracle.probe import Probe

    class Alike:
        """A target that answers every request alike (nothing is confirmed)."""

        def send(self, url, param, value, timing=False, **kw):
            return Probe(200, "<html><body>ok</body></html>", headers={"Server": "test"})

    page = "<html><body><h1>{}</h1><form><input><button>go</button></form></body></html>"
    points = [InjectionPoint("http://127.0.0.1:8080/safe?q=1", "q"),
              InjectionPoint("http://127.0.0.1:8080/admin?cmd=ls", "cmd")]
    plan = RunPlan("automatic", ["sql-injection"], scored=False, source="user")
    with Store(tmp_path / "p.db") as st:
        run = st.start_run("pipeline", "localhost")
        result = run_pipeline(points, st, run, Alike(), plan,
                              pages_html={p.url: page.format(i)
                                          for i, p in enumerate(points)})
    assert result.points_audited == 2


BUG_DOC = REPO / "docs" / "bugs" / \
    "BUG-0546-captured-api-requests-were-deduplicated-by-their-top-level-keys.md"
#: What a sweep row may say instead of naming its pin.
_SETTLED = ("fixed here", "fixed by", "not instances", "not an instance")
_PIN = re.compile(r"tests/test_captured_operations\.py::(\w+)")


def sweep_rows_without_a_pin(doc: str, module: dict) -> list[str]:
    """The rows of a bug doc's ``## PA-0002 sweep`` section that neither say the
    instance is fixed or is not one (`_SETTLED`) nor name a strict xfail of this module
    that exists (PA-0531(4), PA-0546(5)); each row by its first line."""
    parts = re.split(r"(?m)^## PA-0002 sweep", doc, maxsplit=1)
    section = parts[1].partition("\n## ")[0] if len(parts) == 2 else ""
    rows = re.split(r"\n(?=- )", section)[1:]
    out = []
    for row in rows:
        text = " ".join(row.split()).lower()
        if any(word in text for word in _SETTLED):
            continue
        pins = _PIN.findall(row)
        if not pins or not all(
                any(m.name == "xfail" and m.kwargs.get("strict") is True
                    for m in getattr(module.get(name), "pytestmark", ()))
                for name in pins):
            out.append(row.splitlines()[0])
    return out


def test_the_bug_0546_sweep_pins_every_instance_it_does_not_fix():
    assert re.search(r"(?m)^## PA-0002 sweep", BUG_DOC.read_text())
    assert sweep_rows_without_a_pin(BUG_DOC.read_text(), globals()) == []


def test_the_sweep_guard_catches_a_prose_deferral():
    head = "# BUG\n\n## PA-0002 sweep (instances)\n"
    tail = "\n## Recurrence review\n- `x`: another lane's item; not pinned here.\n"
    pinned = ("- `a.py::f`: an instance, pinned by\n  "
              "`tests/test_captured_operations.py::"
              "test_two_forms_told_apart_by_a_hidden_action_value_are_both_kept`.\n")
    offenders = [
        # 34d4fd1's rows: a prose deferral, and an instance with no pin and no reason
        "- `tools/store_adapter.py::_store_request`: first wins. That is audit defect 8,\n"
        "  another lane's item; not pinned here.\n",
        "- `core/dedup.py` (DOM templates): audit defect 10, another lane's item.\n",
        # a pin that does not exist, and a test that is no strict xfail
        "- `b.py`: pinned by `tests/test_captured_operations.py::test_no_such_pin`.\n",
        "- `c.py`: pinned by `tests/test_captured_operations.py::"
        "test_json_rpc_methods_stay_apart`.\n",
    ]
    for row in offenders:
        assert sweep_rows_without_a_pin(head + pinned + row + tail, globals()) == \
            [row.splitlines()[0]], row
    clean = (pinned + "- `spider.py::record_request`: fixed here.\n"
             "- `formnav.signature`: forms for submission caps. Not instances.\n")
    assert sweep_rows_without_a_pin(head + clean + tail, globals()) == []


def test_contexts_are_capped_per_operation_and_a_new_input_never_is(store):
    import itertools
    names = [f"k{i}" for i in range(7)]
    assert store(API, {"data": {n: "v" for n in names}}) is None     # every input once
    subsets = [c for r in range(1, len(names)) for c in itertools.combinations(names, r)]
    assert len(subsets) > apiop.MAX_CONTEXT_ROWS
    got = [store(API, {"data": {n: "v" for n in c}}) for c in subsets]
    assert got[:apiop.MAX_CONTEXT_ROWS - 1] == [None] * (apiop.MAX_CONTEXT_ROWS - 1)
    assert set(got[apiop.MAX_CONTEXT_ROWS - 1:]) == {"operation over its context cap"}
    assert len(store.rows()) == apiop.MAX_CONTEXT_ROWS
    # past the cap, an exact repeat is still a duplicate and a new input is still kept
    assert store(API, {"data": {"k0": "w"}}) == "duplicate"
    assert store(API, {"data": {"k0": "v", "new": "v"}}) is None
    assert store(API, {"data": {"k0": 1}}) is None                    # a new type
    assert len(store.rows()) == apiop.MAX_CONTEXT_ROWS + 2


def test_a_row_is_signed_by_its_operation_and_shape(store):
    body = {"query": "query ListPosts { posts { title } }", "operationName": "ListPosts"}
    assert store(GQL + "?v=1", body) is None
    ((sig,),) = db_rows(store.db, "SELECT signature FROM discovered_requests")
    op = apiop.operation_key("POST", GQL + "?v=1", JSON, body)
    assert sig == apiop.row_signature(op, apiop.request_shape(body, GQL + "?v=1"))
    assert sig.startswith(apiop.signature_prefix(op))
    assert json.loads(op)[3] == [
        ["field", ["$", "operationName"], "ListPosts"],
        ["graphql", ["$", "query"], [["query", "ListPosts", ["posts"]]]]]


# --- the guard: every writer of the table keys through the operation (PA-0546) -----

#: What a writer of `discovered_requests` must call: the operation, the request's
#: shape, its operation's merged schema, and the signature built from both.
_KEYING = {"operation_key", "request_shape", "operation_schema", "row_signature"}


def capture_writers_off_the_operation(source: str) -> list[tuple[str, int]]:
    """Functions that INSERT INTO discovered_requests without keying the row through
    `tools.apiop` (every name in `_KEYING` called in the same function)."""
    out = []
    for fn in ast.walk(ast.parse(source)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(isinstance(n, ast.Constant) and isinstance(n.value, str)
                   and "INTO discovered_requests" in n.value for n in ast.walk(fn)):
            continue
        called = {n.func.attr if isinstance(n.func, ast.Attribute) else
                  getattr(n.func, "id", None) for n in ast.walk(fn)
                  if isinstance(n, ast.Call)}
        if not _KEYING <= called:
            out.append((fn.name, fn.lineno))
    return out


def test_every_captured_request_writer_keys_through_the_operation():
    found = {}
    for path in sorted((REPO / "fuzzlab").rglob("*.py")):
        for name, line in capture_writers_off_the_operation(path.read_text()):
            found[f"{path.relative_to(REPO)}:{name}"] = line
    assert found == {}
    src = (REPO / "fuzzlab" / "tools" / "spider.py").read_text()
    assert "INSERT INTO discovered_requests" in src            # the guard sees it


def test_the_operation_guard_catches_synthetic_offenders():
    head = "def capture(cur, url, doc, method):\n"
    insert = "    cur.execute('INSERT INTO discovered_requests (signature) VALUES (?)', (sig,))\n"
    offenders = [
        # BUG-0546's writer: method, path and sorted top-level keys
        "    sig = json.dumps([method, url_key(url), sorted(doc)])\n",
        # an operation without the merged schema: drops what a request adds
        "    sig = apiop.row_signature(apiop.operation_key(method, url, '', doc),"
        " apiop.request_shape(doc, url))\n",
        # a shape compared against no stored schema
        "    op = operation_key(method, url, '', doc)\n"
        "    sig = row_signature(op, request_shape(doc, url))\n",
        # the schema read, but the row keyed by its own text
        "    operation_schema([]); request_shape(doc, url); operation_key(method, url, '', doc)\n"
        "    sig = json.dumps(doc)\n",
    ]
    for body in offenders:
        assert capture_writers_off_the_operation(head + body + insert) == \
            [("capture", 1)], body
    clean = ("    op = apiop.operation_key(method, url, '', doc)\n"
             "    shape = apiop.request_shape(doc, url)\n"
             "    if shape <= apiop.operation_schema([]):\n        return\n"
             "    sig = apiop.row_signature(op, shape)\n")
    assert capture_writers_off_the_operation(head + clean + insert) == []
    # a function that writes no capture row is never judged
    assert capture_writers_off_the_operation(
        "def f(cur):\n    cur.execute('INSERT INTO discovered_pages (url) VALUES (1)')\n") \
        == []
