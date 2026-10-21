"""A captured body holding a lone surrogate is stored losslessly, keyed totally, and
every request the capture writer cannot store is counted (BUG-0554, FR-CRAWL-42).

``{"q":"\\ud800"}`` is valid JSON (a script that slices an emoji in half sends one:
measured, Chromium's ``JSON.stringify`` writes the half as that escape), and `json.loads`
decodes the escape to a lone surrogate code point. The spider's capture writer
(`StorageManager.record_request`) stored ``json.dumps(doc, ensure_ascii=False)`` and
keyed the row with `tools.apiop` texts written the same way and a strict
``.encode("utf-8")``: SQLite's bind and the encode raised ``UnicodeEncodeError``, the
browser guard's observer catch logged it at info, and the request was lost, uncounted.

Now the stored text and the operation key write each surrogate as its JSON escape
(`apiop.storable_json`, byte-identical for any other text), every digest encodes with
``surrogatepass``, the writer never raises (a write the store refuses comes back as a
reason its caller counts in ``requests_not_recorded``), and the importer refuses and
counts such a body instead of failing the whole import on it. Every test drives the
real write site, or the real importers on rows it wrote.
"""

from __future__ import annotations

import ast
import json
import re
import sqlite3
from pathlib import Path

import pytest

from fuzzlab.tools import apiop
from tests._spa_fixture import db_rows

REPO = Path(__file__).resolve().parents[1]
JSON = "application/json"
API = "http://127.0.0.1:8080/api"
PAGE = "http://127.0.0.1:8080/"


@pytest.fixture
def store(tmp_path):
    from fuzzlab.tools.spider import StorageManager
    db = str(tmp_path / "s.db")
    sm = StorageManager(db)

    def record(url, raw, ct=JSON, method="POST"):
        return sm.record_request(PAGE, method, url, ct, raw, "passive")

    def rows():
        return db_rows(db, "SELECT url, body_json, signature FROM discovered_requests "
                           "ORDER BY id")

    record.rows, record.db, record.sm = rows, db, sm
    yield record
    sm.close()


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


# --- the defect: the write raised and the request was lost ----------------------------

def test_a_body_holding_a_lone_surrogate_is_stored_losslessly(store):
    sent = [
        b'{"a\\ud800": 1}',                         # in a key
        b'{"action": "x\\ud800"}',                  # in an operation selector's value
        b'{"q": "\\ud800"}',                        # in a value
        b'{"data": {"k\\udc00": ["\\ud83d", 1]}}',  # nested, an array, a high half
    ]
    assert [store(API, raw) for raw in sent] == [None] * 4     # raised before
    rows = store.rows()
    # lossless: each row reads back as exactly the body the app sent
    assert [json.loads(body) for _u, body, _s in rows] == [json.loads(r) for r in sent]
    # and SQLite holds it as text (the escape), not as a surrogate it cannot encode
    assert rows[2][1] == '{"q": "\\ud800"}'
    assert all(_encodable(body) and _encodable(sig) for _u, body, sig in rows)
    # keyed as any other text: the same request is a duplicate, a new input is kept
    assert [store(API, raw) for raw in sent] == ["duplicate"] * 4
    assert store(API, b'{"a\\ud801": 1}') is None              # another key path
    assert store(API, b'{"action": "x\\ud801"}') is None       # another operation
    assert store(API, b'{"q": "\\udfff"}') == "duplicate"      # a value is not a key
    assert len(store.rows()) == 6


def test_text_without_a_surrogate_is_stored_and_keyed_byte_for_byte_as_before(store):
    """No stored text or signature changes for any body that could be stored before:
    a resumed crawl over an older spider DB keeps its rows' identities."""
    import hashlib

    from fuzzlab.core.urls import url_key
    docs = [{"q": "café", "e": "😀", "sep": "a b", "action": "réserver"},
            {"data": {"naïve": ["ü", 2]}, "op": "x"}]
    for doc in docs:
        assert store(API, json.dumps(doc).encode()) is None
    rows = store.rows()
    assert [body for _u, body, _s in rows] == \
        [json.dumps(d, ensure_ascii=False) for d in docs]
    for doc, (_u, _b, sig) in zip(docs, rows):
        # the signature as BUG-0546's writer computed it
        op = json.dumps(["POST", url_key(API), JSON, apiop.operation_selectors(doc)],
                        ensure_ascii=False)
        text = json.dumps(sorted(json.dumps(list(p), ensure_ascii=False)
                                 for p in apiop.request_shape(doc, API)),
                          ensure_ascii=False)
        assert sig == op[:-1] + ", " + json.dumps(
            hashlib.sha256(text.encode("utf-8")).hexdigest()) + "]"


def test_the_operation_keys_and_digests_are_total_on_lone_surrogates():
    big = "# \ud800\n{ " + "f " * (apiop.MAX_GRAPHQL_TOKENS + 1) + "}"
    graphql = apiop.graphql_operations(big)                    # raised: strict encode
    assert graphql[0][0] == "document"
    assert apiop.graphql_operations(big.replace("\ud800", "\ud801")) != graphql
    for doc in ({"action": "x\ud800"}, {"cmd": "y" * 70 + "\udc00"}, {"query": big},
                {"data": [{"method": "\ud83d"}]}):
        op = apiop.operation_key("POST", API, JSON, doc)
        assert _encodable(op) and _encodable(apiop.signature_prefix(op))
        assert json.loads(op)[3] == apiop.operation_selectors(doc)  # lossless key
        sig = apiop.row_signature(op, apiop.request_shape(doc, API))
        assert _encodable(sig) and sig.startswith(apiop.signature_prefix(op))
    shapes = [apiop.request_shape({k: 1}, API) for k in ("a\ud800", "a\ud801", "a")]
    sigs = {apiop.row_signature("[]", s) for s in shapes}      # raised: strict encode
    assert len(sigs) == 3
    for value in ({"q": "\ud800"}, ["\udfff", {"k\ud800": None}], "plain é"):
        assert json.loads(apiop.storable_json(value)) == value
        assert _encodable(apiop.storable_json(value))


def test_a_marker_next_to_a_lone_surrogate_is_still_scrubbed(store):
    """The probe-marker scrub reads the raw text: in the stored text an escape's hex
    digits would end the token before the marker and hide it from the scrub."""
    from fuzzlab.tools import spa
    m = spa.mint_markers(1)[0]
    raw = json.dumps({"q": "\ud800" + m, "r": m + "\udc00"}).encode()
    assert store(API, raw) is None
    (_u, body, _s), = store.rows()
    assert spa.MARKER_PREFIX not in body
    assert json.loads(body) == {"q": "\ud800" + spa.MARKER_PLACEHOLDER,
                                "r": spa.MARKER_PLACEHOLDER + "\udc00"}


class _Req:
    def __init__(self, url, body, method="POST"):
        self.url, self.method, self.resource_type = url, method, "fetch"
        self.post_data_buffer = body
        self.headers = {"content-type": JSON}


def test_a_write_the_store_refuses_is_counted_never_raised(tmp_path, caplog):
    """The passive capture path: a lone surrogate is captured, and a write the store
    still refuses (here a lock another connection holds) is counted in
    ``requests_not_recorded`` with its reason. Before, both raised out of `_observe`
    into the guard's observer catch, which only logs."""
    import logging

    from fuzzlab.tools.spider import LocalSpider
    db = str(tmp_path / "s.db")
    sp = LocalSpider(PAGE, db_name=db, engine="requests")
    other = sqlite3.connect(db, isolation_level=None)
    try:
        sp._current_url = PAGE
        sp._observe(_Req(API, b'{"q": "\\ud800"}'), None, scripts=True)
        assert sp.spa_counts["requests_captured"] == 1           # raised before
        sp.storage.conn.execute("PRAGMA busy_timeout = 0")
        other.execute("BEGIN EXCLUSIVE")
        with caplog.at_level(logging.INFO):
            sp._observe(_Req(API + "/2", b'{"n": 1}'), None, scripts=True)
        assert sp.spa_counts["requests_not_recorded"] == 1       # raised before
        assert "not recorded (write failed (OperationalError))" in caplog.text
        other.execute("ROLLBACK")
        # the writer's connection is still usable: the same request is stored now
        assert sp.storage.record_request(PAGE, "POST", API + "/2", JSON, b'{"n": 1}',
                                         "passive") is None
    finally:
        other.close()
        sp.storage.close()
    assert [u for u, in db_rows(db, "SELECT url FROM discovered_requests ORDER BY id")] \
        == [API, API + "/2"]


# --- the consumers of the rows the fix lets through -----------------------------------

def test_the_spider_import_refuses_and_counts_a_captured_lone_surrogate(store, tmp_path):
    """The importer read such a row and raised at its own bind, failing the whole
    import; it now refuses it (counted) and imports the rest. The trace of the import
    (`observe_spider`, a field name holding a surrogate) is written too."""
    from fuzzlab.core import trace
    from fuzzlab.core.store import Store
    from fuzzlab.tools.store_adapter import import_spider
    assert store(API + "/a", b'{"q": "\\ud800", "n": "a"}') is None
    assert store(API + "/b", b'{"k\\udc00": "v"}') is None
    assert store(API + "/c", b'{"comment": "hi"}') is None
    with Store(tmp_path / "u.db") as st:
        run = st.start_run("spider", "localhost")
        rec = trace.TraceRecorder(st, run)
        with trace.recording(rec):
            counts = import_spider(store.db, st, run)
        rec.close()
        events = st.conn.execute("SELECT body FROM trace_event WHERE run_id = ? AND "
                                 "kind = 'observe.exchange'", (run,)).fetchall()
        params = {n for n, in st.conn.execute("SELECT name FROM parameter")}
    assert (counts["request"], counts["request_json"], counts["request_refused"]) == \
        (3, 1, 2)
    assert params == {"comment"}
    assert len(events) == 3
    assert ["k\udc00", "json"] in json.loads(
        next(b for b, in events if "/b" in json.loads(b)["url"]))["params"]


def test_the_disco_import_refuses_and_counts_a_lone_surrogate_instead_of_failing(
        tmp_path):
    """The same importer decision serves disco's capture (`import_disco`), which already
    reached the failing bind before the spider could store such a row."""
    from fuzzlab.core.store import Store
    from fuzzlab.disco.capture import append_record, make_record
    from fuzzlab.tools.store_adapter import import_disco
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    for path, body in (("/api/a", b'{"q": "\\ud800"}'), ("/api/b", b'{"comment": "hi"}')):
        append_record(run_dir / "capture.jsonl", make_record(
            kind="http", t=1.0, action_id="act-1", method="POST",
            url="http://127.0.0.1:3000" + path, req_headers={"Content-Type": JSON},
            req_body=body, status=200, res_headers={"Content-Type": JSON},
            res_body=b"{}"))
    (run_dir / "actions.jsonl").write_text("", encoding="utf-8")
    with Store(tmp_path / "u.db") as st:
        run = st.start_run("disco", "localhost")
        counts = import_disco(run_dir, st, run)                  # raised before
        params = {n for n, in st.conn.execute("SELECT name FROM parameter")}
    assert (counts["request"], counts["request_json"], counts["request_refused"]) == \
        (2, 1, 1)
    assert params == {"comment"}


# --- the PA-0002 sweep's pins (BUG-0554) ------------------------------------------------

@pytest.mark.xfail(strict=True, raises=UnicodeEncodeError,
                   reason="BUG-0554 sweep: core/redaction.py::redact_json_body re-encodes "
                          "a rewritten body with a strict .encode('utf-8'). Owner: the "
                          "storage boundary, core/redaction.py (CORE); needs a CC-CORE "
                          "number")
def test_the_redaction_boundary_rewrites_a_body_holding_a_lone_surrogate():
    """A body with a sensitive field and a lone surrogate: the boundary must blank the
    field and keep the escape (the bytes the app sent), not raise. Today it raises; the
    proxy history stores the flow as `OMIT_FAILED`, `core.http`'s exchange log raises
    out of the send, and the spider's capture refuses it as "redaction failed"
    (counted, not stored)."""
    from fuzzlab.core.redaction import redact_body
    out = redact_body(b'{"password": "x", "q": "\\ud800"}', JSON)
    assert json.loads(out)["q"] == "\ud800" and json.loads(out)["password"] != "x"


# --- the guards --------------------------------------------------------------------------

def _callee(call: ast.Call) -> str | None:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)


def _unsafe_text_call(node) -> bool:
    """``json.dumps(..., ensure_ascii=False)`` (a lone surrogate stays raw) or a strict
    ``.encode()`` / ``.encode("utf-8")`` (no ``errors``): text a lone surrogate makes
    raise at a bind or an encode."""
    if not isinstance(node, ast.Call):
        return False
    if _callee(node) == "dumps":
        return any(k.arg == "ensure_ascii" and isinstance(k.value, ast.Constant)
                   and k.value.value is False for k in node.keywords)
    if isinstance(node.func, ast.Attribute) and node.func.attr == "encode":
        if len(node.args) > 1 or any(k.arg == "errors" for k in node.keywords):
            return False
        return not node.args or (isinstance(node.args[0], ast.Constant) and str(
            node.args[0].value).lower().replace("-", "").replace("_", "") == "utf8")
    return False


def _producers(trees) -> set[str]:
    """Functions that return such text directly (one level of indirection)."""
    out = set()
    for tree in trees:
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    isinstance(n, ast.Return) and _unsafe_text_call(n.value)
                    for n in ast.walk(fn)):
                out.add(fn.name)
    return out


def _text_nodes(node):
    """``node`` and what it holds, except inside a ``loads(...)`` call (its result is a
    value again, not text)."""
    yield node
    if isinstance(node, ast.Call) and _callee(node) == "loads":
        return
    for child in ast.iter_child_nodes(node):
        yield from _text_nodes(child)


def unsafe_text_binds(sources: dict[str, str]) -> list[tuple[str, str, int]]:
    """``(path, function, line)`` of each SQLite ``execute``/``executemany`` whose
    parameters hold, directly or through a name the function assigned, text a lone
    surrogate makes raise: `_unsafe_text_call`, or a call to a function returning one."""
    trees = {path: ast.parse(src) for path, src in sources.items()}
    producers = _producers(trees.values())

    def unsafe(node) -> bool:
        return _unsafe_text_call(node) or (
            isinstance(node, ast.Call) and _callee(node) in producers)

    out = []
    for path, tree in trees.items():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            tainted = {t.id for n in ast.walk(fn) if isinstance(n, ast.Assign)
                       and any(unsafe(v) for v in _text_nodes(n.value))
                       for t in n.targets if isinstance(t, ast.Name)}
            for call in ast.walk(fn):
                if not (isinstance(call, ast.Call)
                        and _callee(call) in ("execute", "executemany")):
                    continue
                params = [n for a in call.args[1:] + [k.value for k in call.keywords]
                          for n in _text_nodes(a)]
                if any(unsafe(n) or (isinstance(n, ast.Name) and n.id in tainted)
                       for n in params):
                    out.append((path, fn.name, call.lineno))
    return out


#: Binds the guard flags whose text cannot hold a lone surrogate, with why.
_ALLOWED = {
    # its leaves passed `captured_request`'s storable-text refusal first (BUG-0554)
    ("fuzzlab/tools/store_adapter.py", "_store_request"),
    # a lab's own constant seed password (`SEED_PASSWORD`), never a target's text
    ("fuzzlab/labgen/conformance/django_live_boot.py", "_seed_db"),
}


def test_no_sqlite_bind_takes_text_a_lone_surrogate_makes_raise():
    sources = {str(p.relative_to(REPO)): p.read_text(encoding="utf-8")
               for p in sorted((REPO / "fuzzlab").rglob("*.py"))}
    found = {(path, fn) for path, fn, _line in unsafe_text_binds(sources)}
    assert found - _ALLOWED == set()
    assert _ALLOWED <= found                                     # no stale allowance


def test_the_capture_keying_never_encodes_strictly():
    """`tools.apiop` (whose texts the capture writer binds) and the writer itself: no
    strict encode, no ``ensure_ascii=False`` text bound."""
    src = (REPO / "fuzzlab" / "tools" / "apiop.py").read_text(encoding="utf-8")
    assert [n.lineno for n in ast.walk(ast.parse(src))
            if _unsafe_text_call(n) and _callee(n) == "encode"] == []
    spider = (REPO / "fuzzlab" / "tools" / "spider.py").read_text(encoding="utf-8")
    writer = [fn for fn in ast.walk(ast.parse(spider))
              if isinstance(fn, ast.FunctionDef) and fn.name == "record_request"]
    assert len(writer) == 1
    assert any(isinstance(n, ast.Constant) and isinstance(n.value, str)
               and "INSERT INTO discovered_requests" in n.value for n in ast.walk(writer[0]))
    assert not any(_unsafe_text_call(n) and _callee(n) == "encode"
                   for fn in writer for n in ast.walk(fn))


def test_the_guards_catch_synthetic_offenders():
    sql = "'INSERT INTO t (a) VALUES (?)'"
    offenders = [
        # BUG-0554's writer: the body text bound as json.dumps(..., ensure_ascii=False)
        f"def w(cur, doc):\n    cur.execute({sql}, (json.dumps(doc, ensure_ascii=False),))\n",
        # through a name
        f"def w(cur, doc):\n    t = json.dumps(doc, ensure_ascii=False)\n"
        f"    cur.execute({sql}, (t,))\n",
        # through a producer (BUG-0554's `jsonbody.encode_entries` shape)
        f"def enc(e):\n    return json.dumps(e, ensure_ascii=False)\n"
        f"def w(cur, e):\n    cur.executemany({sql}, [(enc(e),)])\n",
        # a strict digest of target text bound as a key (BUG-0554's `row_signature`)
        f"def w(cur, t):\n    cur.execute({sql}, "
        f"(hashlib.sha256(t.encode('utf-8')).hexdigest(),))\n",
        f"def w(cur, t):\n    k = t.encode()\n    cur.execute({sql}, (k,))\n",
    ]
    for src in offenders:
        assert [fn for _p, fn, _l in unsafe_text_binds({"x.py": src})] == ["w"], src
    clean = (f"def w(cur, doc, t):\n    cur.execute({sql}, (storable_json(doc),))\n"
             f"    cur.execute({sql}, (json.dumps(doc),))\n"
             f"    cur.execute({sql}, (t.encode('utf-8', 'surrogatepass'),))\n"
             f"    cur.execute({sql}, (t.encode('latin-1'),))\n"
             # the scrub's round trip: a value again, then stored through the escape
             f"    d = json.loads(json.dumps(doc, ensure_ascii=False))\n"
             f"    cur.execute({sql}, (storable_json(d),))\n")
    assert unsafe_text_binds({"x.py": clean}) == []
    # the keying-module check: BUG-0554's two strict encodes
    for line in ("hashlib.sha256(text.encode('utf-8')).hexdigest()",
                 "hashlib.sha256(folded.encode()).hexdigest()"):
        assert [_callee(n) for n in ast.walk(ast.parse(line)) if _unsafe_text_call(n)] \
            == ["encode"]
    assert not any(_unsafe_text_call(n) for n in ast.walk(ast.parse(
        "hashlib.sha256(t.encode('utf-8', 'surrogatepass'))")))


BUG_DOC = REPO / "docs" / "bugs" / \
    "BUG-0554-a-captured-body-holding-a-lone-surrogate-was-lost-at-the-write.md"
#: What a sweep row may say instead of naming its pin (PA-0546(5)).
_SETTLED = ("fixed here", "fixed by", "not instances", "not an instance")
_PIN = re.compile(r"tests/test_capture_surrogates\.py::(\w+)")


def sweep_rows_without_a_pin(doc: str, module: dict) -> list[str]:
    """The rows of BUG-0554's ``## PA-0002 sweep`` section that neither settle the row
    (`_SETTLED`) nor name a strict xfail of this module that exists; each by its first
    line (PA-0546(5), the guard BUG-0546 wrote for its own sweep, applied here)."""
    parts = re.split(r"(?m)^## PA-0002 sweep", doc, maxsplit=1)
    section = parts[1].partition("\n## ")[0] if len(parts) == 2 else ""
    out = []
    for row in re.split(r"\n(?=- )", section)[1:]:
        if any(word in " ".join(row.split()).lower() for word in _SETTLED):
            continue
        pins = _PIN.findall(row)
        if not pins or not all(
                any(m.name == "xfail" and m.kwargs.get("strict") is True
                    for m in getattr(module.get(name), "pytestmark", ()))
                for name in pins):
            out.append(row.splitlines()[0])
    return out


def test_the_bug_0554_sweep_settles_or_pins_every_row():
    doc = BUG_DOC.read_text(encoding="utf-8")
    assert re.search(r"(?m)^## PA-0002 sweep", doc)
    assert sweep_rows_without_a_pin(doc, globals()) == []
    head, tail = "# BUG\n\n## PA-0002 sweep\n", "\n## Recurrence review\n- x\n"
    for row in ("- `a.py::f`: another lane's item.\n",
                "- `b.py`: pinned by `tests/test_capture_surrogates.py::test_no_such`.\n",
                "- `c.py`: pinned by `tests/test_capture_surrogates.py::"
                "test_a_body_holding_a_lone_surrogate_is_stored_losslessly`.\n"):
        assert sweep_rows_without_a_pin(head + row + tail, globals()) == \
            [row.splitlines()[0]], row
