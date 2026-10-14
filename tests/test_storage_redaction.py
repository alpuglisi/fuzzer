"""One fail-closed storage-redaction boundary for every producer of persisted traffic
(BUG-0099 / BUG-0100, FR-CORE-6 / FR-PROXY-11, PA-0100 / PA-0101).

BUG-0099: the core HTTP client's recorder persisted URL tokens and body secrets with no
redaction at all. BUG-0100: the JSON redactor kept a body as received whenever it could
not parse it (a 5,000-digit integer, a trailing comma) and crashed on deep nesting.
"""

from __future__ import annotations

import ast
import gzip
from pathlib import Path

import pytest

from fuzzlab.core.redaction import (MAX_JSON_DEPTH, OMIT_TOO_LARGE, OMIT_UNSAFE,
                                    mentions_sensitive_name, redact_body)
from fuzzlab.core.store import Store

REPO = Path(__file__).resolve().parent.parent
JSON = "application/json"


# --- BUG-0100: fail closed --------------------------------------------------------

@pytest.mark.parametrize("body", [
    b'{"padding":' + b"9" * 5000 + b',"password":"SECRET"}',   # past the int-digit limit
    b'{"password":"SECRET",}',                                  # trailing comma
    b'{password: "SECRET"}',                                    # unquoted key
    b"{'password':'SECRET'}",                                   # single quotes
    b"password=SECRET&user=a",                                  # a form labelled JSON
    b'{"a":"unterminated, password=SECRET',                     # unterminated string
    b'{"password":"SECRET","x":' + b"[" * 1100 + b"]" * 1100 + b"}",   # parser depth
    b'{"password":"SECRET","x":' + b"[" * (MAX_JSON_DEPTH + 5)
    + b"]" * (MAX_JSON_DEPTH + 5) + b"}",                       # over MAX_JSON_DEPTH
])
def test_an_unparseable_or_deep_json_body_with_a_secret_is_omitted(body):
    out = redact_body(body, JSON)
    assert b"SECRET" not in out and out == OMIT_UNSAFE


@pytest.mark.parametrize("body", [
    b'{"ok": 1,}',                                              # malformed, nothing secret
    b'{"x":' + b"[" * 2000 + b"]" * 2000 + b"}",               # deep, nothing secret
    b"{'name': 'fuzz' ",
])
def test_a_malformed_body_with_no_sensitive_name_stays_readable(body):
    assert redact_body(body, JSON) == body


def test_an_oversized_body_is_omitted(monkeypatch):
    import fuzzlab.core.redaction as r
    monkeypatch.setattr(r, "MAX_REDACT_BYTES", 100)
    assert r.redact_body(b'{"a":"' + b"x" * 200 + b'"}', JSON) == OMIT_TOO_LARGE
    assert r.redact_body(b"a=" + b"x" * 200, "application/x-www-form-urlencoded") == \
        OMIT_TOO_LARGE


@pytest.mark.parametrize("ct", ["text/plain", "", "application/octet-stream"])
def test_untyped_json_and_form_bodies_are_sniffed(ct):
    """B-S2: text/plain is the CORS-simple type; a declared type is not a bypass."""
    assert b"SECRET" not in redact_body(b'{"password":"SECRET","a":1}', ct)
    assert b"SECRET" not in redact_body(b"user=a&password=SECRET", ct)
    assert redact_body(b"hello world", ct) == b"hello world"
    assert redact_body(b"{not json at all", ct) == b"{not json at all"   # not JSON


def test_the_scan_sees_every_token_shape():
    for text in (b"password", b"x.password", b"'apiKey'", b'"access_token"', b"pw-reset"):
        assert mentions_sensitive_name(text), text
    assert not mentions_sensitive_name(b"author sidebar tokenizer passage")


def test_history_flush_survives_a_deep_body(tmp_path):
    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    deep = b'{"x":' + b"[" * 3000 + b"]" * 3000 + b"}"
    raw = (b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n"
           b"Content-Length: " + str(len(deep)).encode() + b"\r\n\r\n" + deep)
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=10)
        h.record(FlowRecord("POST", "http://h/a", "h", 200, raw_request=raw,
                            raw_response=b"HTTP/1.1 200 OK\r\n\r\n", req_body=deep))
        assert h.flush() == 1


# --- BUG-0099: the core HTTP client records through the boundary ------------------

def test_the_http_client_records_no_secret(tmp_path):
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient, Request

    def transport(method, url, headers, body, timeout):
        return 200, {"content-TYPE": "application/json"}, b'{"token":"RESPONSE_SECRET"}'
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("t", "x")
        c = HttpClient(RequestBudget(10), ["lab.example"], store=store, run_id=run,
                       transport=transport)
        c.send(Request("POST", "https://lab.example/login?token=URL_SECRET&q=pup",
                       headers={"CONTENT-TYPE": "application/json"},
                       body=b'{"password":"BODY_SECRET","user":"alice"}'))
        blob = b"\n".join((v if isinstance(v, bytes) else str(v).encode())
                          for t in ("flow", "body")
                          for r in store.conn.execute(f"SELECT * FROM {t}") for v in tuple(r))
    for s in (b"URL_SECRET", b"BODY_SECRET", b"RESPONSE_SECRET"):
        assert s not in blob, s
    assert b"q=pup" in blob and b"alice" in blob                  # benign content kept


# --- the producer guard (PA-0100, B-S6) -------------------------------------------

#: Sites allowed to persist traffic without the redaction boundary, with the reason.
ALLOWED = {
    # (relative path, function name)
}
_REDACTORS = {"redact", "redact_url", "redact_body", "redact_body_for", "_prepare",
              "_prep", "redact_json_body", "redact_form_body"}
#: The crawler's captured requests (forms phase 3, FR-CRAWL-13): a producer must call
#: **both** capture redactors of `core.redaction` (the body and the URLs).
_CAPTURE_REDACTORS = {"redact_captured_body", "redact_url_identifiers"}


def traffic_producers(source: str) -> list[tuple[str, int]]:
    """Functions that INSERT INTO flow / flow_fts but call no redactor, or INSERT INTO
    discovered_requests without calling both capture redactors."""
    tree = ast.parse(source)
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        consts = [n.value for n in ast.walk(fn)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        flow = any("INSERT INTO flow" in c for c in consts)
        capture = any("INSERT INTO discovered_requests" in c for c in consts)
        if not flow and not capture:
            continue
        called = {(n.func.attr if isinstance(n.func, ast.Attribute) else
                   getattr(n.func, "id", None)) for n in ast.walk(fn)
                  if isinstance(n, ast.Call)}
        if (flow and not called & _REDACTORS) or \
                (capture and not _CAPTURE_REDACTORS <= called):
            out.append((fn.name, fn.lineno))
    return out


def _all_producers():
    found = {}
    for p in sorted((REPO / "fuzzlab").rglob("*.py")):
        rel = str(p.relative_to(REPO))
        for name, line in traffic_producers(p.read_text()):
            if (rel, name) not in ALLOWED:
                found[f"{rel}:{name}"] = line
    return found


def test_every_traffic_producer_goes_through_the_redaction_boundary():
    """HistoryWriter's insert is fed only prepared (redacted) values; HttpClient's
    `_record` redacts in place. A third producer must do the same or be allowed."""
    offenders = {k: v for k, v in _all_producers().items()
                 if not k.endswith(("history.py:_insert",))}
    assert offenders == {}


def test_history_insert_is_only_ever_fed_prepared_records():
    src = (REPO / "fuzzlab" / "proxy" / "history.py").read_text()
    calls = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and n.func.attr == "_insert"]
    assert len(calls) == 1                               # inside flush, on `prepared`


def test_the_guard_catches_a_synthetic_producer():
    offender = ('def save(conn, url, body):\n'
                '    conn.execute("INSERT INTO flow (url) VALUES (?)", (url,))\n')
    assert traffic_producers(offender) == [("save", 1)]
    clean = ('def save(conn, url, body):\n'
             '    conn.execute("INSERT INTO flow (url) VALUES (?)", (redact_url(url),))\n')
    assert traffic_producers(clean) == []


def test_the_guard_catches_a_synthetic_capture_producer():
    """PA-0034(2) for the crawler's capture writer (FR-CRAWL-13): one redactor is not
    enough, and neither is a flow redactor."""
    insert = '    conn.execute("INSERT INTO discovered_requests (url, body_json) VALUES (?,?)",'
    for args in ("(url, body))", "(redact_url_identifiers(url), body))",
                 "(url, redact_captured_body(body, ct)))",
                 "(redact_url(url), redact_body(body, ct)))"):
        offender = f"def capture(conn, url, body, ct):\n{insert}\n        {args}\n"
        assert traffic_producers(offender) == [("capture", 1)], args
    clean = (f"def capture(conn, url, body, ct):\n{insert}\n"
             "        (redact_url_identifiers(url), redact_captured_body(body, ct)))\n")
    assert traffic_producers(clean) == []


def test_the_spiders_capture_writer_is_seen_by_the_guard():
    """Not vacuous: the guard finds the real writer and it passes."""
    src = (REPO / "fuzzlab" / "tools" / "spider.py").read_text()
    assert "INSERT INTO discovered_requests" in src
    assert traffic_producers(src) == []
    broken = src.replace("redact_captured_body(body, content_type)", "(body, None)")
    assert [name for name, _line in traffic_producers(broken)] == ["record_request"]


def test_a_gzip_body_with_a_secret_is_omitted_by_history(tmp_path):
    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    gz = gzip.compress(b'{"password":"GZSECRET"}')
    raw = (b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n"
           b"Content-Encoding: gzip\r\nContent-Length: " + str(len(gz)).encode()
           + b"\r\n\r\n" + gz)
    with Store(tmp_path / "s.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=1)
        h.record(FlowRecord("POST", "http://h/a", "h", 200, raw_request=raw,
                            raw_response=b"HTTP/1.1 200 OK\r\n\r\n", req_body=gz))
        fid = store.conn.execute("SELECT id FROM flow").fetchone()["id"]
        stored = h.raw_request(fid)
    assert gz not in stored and OMIT_UNSAFE in stored and b"Content-Encoding" not in stored
