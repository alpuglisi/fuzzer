"""Text bodies through the one storage-redaction boundary (BUG-0527, FR-CORE-506, PA-0527;
the owner's external audit, defect 26).

`core.redaction.redact_body` scrubbed JSON, form-urlencoded and multipart bodies and
returned every other body unchanged. An HTML page's CSRF field, a ``<meta name=
"csrf-token">``, an inline state object's token, a SOAP password, a ``.env`` served as
text and a script's API key were therefore persisted in cleartext by every producer that
redacts through it: the disco capture (`disco.capture.make_record`), proxy history (the
raw message through `proxy.redact.redact`, a stored body through `redact_body_for`), the
core HTTP client's recorder and the contract runner's evidence files.

Each test plants one canary per binding shape (PA-0085(2), PA-0091(1)) and searches every
persisted copy, through the real producer; benign content must stay (PA-0085(2)). The
shapes are the ones real frameworks emit (Django's ``csrfmiddlewaretoken`` and its error
pages were measured by rendering Django in-process; Flask's error pages likewise;
Laravel's ``_token`` and Rails' ``authenticity_token`` are those frameworks' helpers'
output).

The proxy's framed bodies stay fail-closed (CC-PROXY-0028): a chunked or compressed body
is stored byte-exact when every plausible reading of it is clean (so a clean desync probe
stays byte-exact), else replaced by a typed omission marker; no decoded copy is stored.
Each test names the revert it must fail against (PA-0034(2)); a complexity claim is tested
on the counters the redactor exposes, with a generous absolute smoke alarm (PA-0135).
"""

from __future__ import annotations

import base64
import codecs
import contextlib
import gzip
import json
import random
import re
import signal
import zlib
from pathlib import Path

import pytest

from fuzzlab.core.store import Store

DATA = Path(__file__).parent / "data" / "body_redaction"

HTML = b"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="csrf-token" content="CANARY_META_CSRF">
<meta name="_csrf" content="CANARY_META_SPRING">
<meta http-equiv="refresh" content="30;url=/poll?session=CANARY_REFRESH_URL">
<title>Login</title>
<script nonce="CANARY_CSP_NONCE">window.__INITIAL_STATE__ = {"user":{"name":"alice","apiKey":"CANARY_STATE_APIKEY"},"csrfToken":"CANARY_STATE_CSRF","items":[1,2]};</script>
<script>var config = {authToken: 'CANARY_JS_SQ', tokens: ["CANARY_JS_LIST"]};</script>
<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"session":{"accessToken":"CANARY_NEXT"}}}}</script>
</head><body>
<form method="post" action="/login?next=/home&amp;token=CANARY_ACTION_URL">
<input type="hidden" name="csrfmiddlewaretoken" value="CANARY_DJANGO">
<input type="hidden" name="_token" value="CANARY_LARAVEL" autocomplete="off">
<input type=hidden name=authenticity_token value=CANARY_RAILS_UNQUOTED>
<input type="hidden" name="__RequestVerificationToken" value="CANARY_ASPNET" />
<input type="hidden" name="__VIEWSTATE" value="CANARYvsWEPDwUKMTY1NDU2MTA1MmRk9a8">
<input type="password" name="login_input" value="CANARY_PASSWORD_TYPE">
<input name="api_key" value='CANARY_SINGLE_QUOTED'>
<input type="text" name="username" value="alice">
<input type="hidden" name="product_id" value="42">
<textarea name="private_key">CANARY_TEXTAREA</textarea>
<div data-csrf-token="CANARY_DATA_ATTR"></div>
<a href="/reset?token=CANARY_HREF_URL&amp;lang=en">reset</a>
</form></body></html>
"""
XML = (b'<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/'
       b'envelope/"><soap:Header><wsse:Security><wsse:UsernameToken><wsse:Username>bob'
       b'</wsse:Username><wsse:Password>CANARY_XML_PW</wsse:Password></wsse:UsernameToken>'
       b'</wsse:Security></soap:Header><soap:Body><getUser><userName>alice</userName>'
       b'<sessionId>CANARY_XML_SESSION</sessionId></getUser></soap:Body></soap:Envelope>')
ENV = (b"APP_NAME=puppy\nDB_PASSWORD=CANARY_ENV_PW\nSECRET_KEY=CANARY_ENV_SECRET\n"
       b"APP_DEBUG=false\n")
JS = (b'const firebaseConfig = {apiKey: "CANARY_JS_APIKEY", projectId: "pup-fort"};\n'
      b'fetch("/api/Users/whoami", {headers: {Authorization: "Bearer CANARY_JS_BEARER"}});\n')
#: A real page with nothing bound to a sensitive name (Django's production 404).
CLEAN_PAGE = (DATA / "django_404.html").read_bytes()

#: (label, body, declared Content-Type, benign content that must be kept)
CASES = [
    ("html", HTML, "text/html; charset=utf-8",
     [b"alice", b'name="product_id" value="42"', b"/home", b"lang=en", b"<title>Login"]),
    ("html-as-text-plain", HTML, "text/plain", [b"alice", b"lang=en"]),
    ("html-untyped", HTML, "", [b"alice", b"lang=en"]),
    ("xml", XML, "text/xml", [b"<userName>alice</userName>"]),
    ("plain-env", ENV, "text/plain", [b"APP_NAME=puppy", b"APP_DEBUG=false"]),
    ("javascript", JS, "application/javascript", [b'fetch("/api/Users/whoami"', b"pup-fort"]),
]
IDS = [c[0] for c in CASES]
_CANARY = re.compile(rb"CANARY[A-Za-z0-9_+/]*")


def _canaries(blob: bytes) -> list[str]:
    return sorted({m.decode() for m in _CANARY.findall(blob)})


def _gunzip_members(data: bytes, cap: int = 64 << 20) -> bytes:
    """Every gzip member from the start of ``data``, decoded in turn (linear: fed in
    growing pieces, never re-copying the rest; output bounded by ``cap``)."""
    mv, off, out, total = memoryview(data), 0, [], 0
    while off < len(data) and bytes(mv[off:off + 2]) == b"\x1f\x8b" and total <= cap:
        d, piece = zlib.decompressobj(16 + zlib.MAX_WBITS), 256
        try:
            while not d.eof and off < len(data):
                chunk = mv[off:off + piece]
                got = d.decompress(chunk, cap - total + 1)
                out.append(got)
                total += len(got)
                off += len(chunk) - len(d.unused_data) - len(d.unconsumed_tail)
                if total > cap:
                    break
                piece = min(piece * 2, 1 << 16)
        except zlib.error:
            break
    return b"".join(out)


def _store_blob(store, tables=("flow", "body", "flow_fts")) -> bytes:
    """Every persisted copy, plus every stored gzip member decompressed: a compressed
    copy hides nothing."""
    blobs = []
    for table in tables:
        for row in store.conn.execute(f"SELECT * FROM {table}").fetchall():
            for v in tuple(row):
                blobs.append(v if isinstance(v, bytes) else str(v).encode())
    for b in list(blobs):
        i = b.find(b"\x1f\x8b")
        if i != -1:
            blobs.append(_gunzip_members(b[i:]))
    return b"\n".join(blobs)


def _chunked(payload: bytes, size: int = 64) -> bytes:
    return b"".join(b"%x\r\n" % len(payload[i:i + size]) + payload[i:i + size] + b"\r\n"
                    for i in range(0, len(payload), size)) + b"0\r\n\r\n"


def _response(ctype: str, framing: bytes, payload: bytes) -> bytes:
    """A response with ``framing`` header lines (``Transfer-``/``Content-Encoding``)."""
    head = b"HTTP/1.1 200 OK\r\n" + (b"Content-Type: " + ctype.encode() + b"\r\n" if ctype
                                     else b"") + framing
    if b"Transfer-Encoding" not in framing:
        head += b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
    return head + b"\r\n" + payload


def _history(db: Path, resp: bytes) -> tuple[bytes, bytes]:
    """(every persisted copy, the stored raw response) of one proxied response."""
    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    with Store(db) as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=1)
        h.record(FlowRecord("GET", "http://127.0.0.1:8080/x", "127.0.0.1:8080", 200,
                            raw_request=b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n",
                            raw_response=resp))
        fid = store.conn.execute("SELECT id FROM flow").fetchone()["id"]
        return _store_blob(store), h.raw_response(fid)


def _stored_body(raw: bytes) -> bytes:
    return raw.split(b"\r\n\r\n", 1)[1]


def _marker(coding: str, why: str) -> bytes:
    return f"__BODY_OMITTED__ (framed {coding} body: {why})".encode()


# --- every producer that redacts through `core.redaction.redact_body` -------------------

@pytest.mark.parametrize("label,body,ctype,benign", CASES, ids=IDS)
def test_no_text_body_secret_reaches_the_capture_file(tmp_path, label, body, ctype, benign):
    """T1. SP-35: the disco capture's one producer, written and read back. Must fail
    against restoring the owner's ``return body`` default."""
    from fuzzlab.disco.capture import append_record, make_record
    out = tmp_path / "capture.jsonl"
    for direction in ("request", "response"):
        headers = {"Content-Type": ctype} if ctype else {}
        append_record(out, make_record(
            kind="http", t=1.0, action_id=None, method="POST",
            url="http://127.0.0.1:8080/login", status=200,
            req_headers=headers if direction == "request" else {},
            req_body=body if direction == "request" else None,
            res_headers=headers if direction == "response" else {},
            res_body=body if direction == "response" else None))
    text = out.read_bytes()
    assert _canaries(text) == []
    for kept in benign:                                 # once per direction
        assert text.count(kept.replace(b'"', b'\\"')) == 2 * body.count(kept), kept


@pytest.mark.parametrize("framing", ["identity", "gzip"])
@pytest.mark.parametrize("label,body,ctype,benign", CASES, ids=IDS)
def test_no_text_body_secret_reaches_proxy_history(tmp_path, label, body, ctype, benign,
                                                   framing):
    """T2. FR-PROXY-11: the raw response (`proxy.redact.redact`) and the separately
    stored body (`redact_body_for`), in every table. Identity: redacted in place, the
    benign list kept. Gzip (S1): a framed body that redaction would change is a typed
    omission, never a decoded copy. Must fail against the ``return body`` default."""
    from fuzzlab.proxy.history import FlowRecord, HistoryWriter
    payload = gzip.compress(body, mtime=0) if framing == "gzip" else body
    resp = _response(ctype, b"Content-Encoding: gzip\r\n" if framing == "gzip" else b"",
                     payload)
    with Store(tmp_path / "h.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=1)
        h.record(FlowRecord("GET", "http://127.0.0.1:8080/login", "127.0.0.1:8080", 200,
                            raw_request=b"GET /login HTTP/1.1\r\nHost: h\r\n\r\n",
                            raw_response=resp, resp_body=payload))
        assert _canaries(_store_blob(store)) == []
        stored = _stored_body(h.raw_response(
            store.conn.execute("SELECT id FROM flow").fetchone()["id"]))
    if framing == "identity":
        for kept in benign:
            assert kept in stored, kept
    else:
        assert stored == _marker("gzip", "redaction would change it")


@pytest.mark.parametrize("label,body,ctype,benign", CASES, ids=IDS)
def test_no_text_body_secret_reaches_the_http_client_store(tmp_path, label, body, ctype,
                                                           benign):
    """T3. FR-CORE-6: the core HTTP client's recorder (`HttpClient._record`)."""
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient, Request

    def transport(method, url, headers, req_body, timeout):
        return 200, ({"Content-Type": ctype} if ctype else {}), body
    with Store(tmp_path / "s.db") as store:
        c = HttpClient(RequestBudget(10), ["lab.example"], store=store,
                       run_id=store.start_run("t", "x"), transport=transport)
        c.send(Request("GET", "https://lab.example/login"))
        blob = _store_blob(store, ("flow", "body"))
    assert _canaries(blob) == []
    for kept in benign:
        assert kept in blob, kept


@pytest.mark.parametrize("label,body,ctype,benign", CASES, ids=IDS)
def test_no_text_body_secret_reaches_the_contract_runners_evidence(tmp_path, monkeypatch,
                                                                   label, body, ctype, benign):
    """T4. The disco contract runner's evidence files (`Runner._evidence`); the benign
    list is kept (JSON-escaped in the file)."""
    from tests.test_disco_contract import FakeResponse, contract_doc, runner
    monkeypatch.setenv("DISCO_TOKEN_A", "TOKENSECRET")
    doc = contract_doc()
    doc["run"]["limits"]["max_body_bytes"] = 1 << 16
    case = doc["test_cases"][0]
    case.update(setup=[])
    case["request"]["path_params"] = {"p1": "7"}
    # FakeResponse defaults an empty header dict to JSON: the untyped case names another
    # header so the response really has no Content-Type
    headers = {"Content-Type": ctype} if ctype else {"X-Fixture": "untyped"}
    r, _ = runner(doc, {("POST", "/api/orders/7/items"): FakeResponse(200, body, headers)},
                  evidence_dir=tmp_path)
    [res] = r.run()
    blob = b"".join(Path(p).read_bytes() for p in res["evidence"].values())
    assert _canaries(blob) == [] and b"TOKENSECRET" not in blob
    for kept in benign:
        assert kept.replace(b'"', b'\\"') in blob, kept


def test_a_secret_straddling_the_runners_read_cap_is_never_kept(tmp_path, monkeypatch):
    """T5. PA-0455(2): the runner reads at most ``max_body_bytes``; a cut inside a CSRF
    value leaves a quoted value with no end, which must not be stored as a partial
    secret."""
    from tests.test_disco_contract import FakeResponse, contract_doc, runner
    monkeypatch.setenv("DISCO_TOKEN_A", "TOKENSECRET")
    cut = HTML.index(b"CANARY_DJANGO") + len(b"CANARY_DJ")
    doc = contract_doc()
    doc["run"]["limits"]["max_body_bytes"] = cut
    case = doc["test_cases"][0]
    case.update(setup=[])
    case["request"]["path_params"] = {"p1": "7"}
    r, _ = runner(doc, {("POST", "/api/orders/7/items"): FakeResponse(
        200, HTML, {"Content-Type": "text/html"})}, evidence_dir=tmp_path)
    [res] = r.run()
    blob = b"".join(Path(p).read_bytes() for p in res["evidence"].values())
    assert _canaries(blob) == []


def test_a_bound_value_with_no_end_fails_closed():
    """T6. PA-0101(1): a sensitive name whose value cannot be delimited is not stored as
    received."""
    from fuzzlab.core.redaction import redact_body
    for body, ctype in [(b'<input type="hidden" name="csrf" value="CANARY_NOEND' + b"x" * 300,
                         "text/html"),
                        (b'var cfg = {apiKey: "CANARY_NOEND_JS' + b"y" * 300,
                         "application/javascript"),
                        (b"<password>CANARY_NOEND_XML" + b"z" * 300, "application/xml")]:
        out = redact_body(body, ctype)
        assert _canaries(out) == [] and out.startswith(b"__BODY_OMITTED__"), ctype


def test_a_real_django_csrf_field_is_redacted():
    """T7. The shape measured from Django's rendered admin login page (``{% csrf_token
    %}``: a hidden ``csrfmiddlewaretoken`` with a 64-character masked token)."""
    from fuzzlab.core.redaction import redact_body
    token = b"CANARYwERkd6pqCAW5oTFiSlFQKH1gVwOjyfZ0aB1cD2eF3gH4iJ5kL6mN7oP8qR9s"
    page = (b'<form action="/admin/login/?next=/admin/" method="post" id="login-form">'
            b'<input type="hidden" name="csrfmiddlewaretoken" value="' + token + b'">'
            b'<input type="text" name="username" autofocus autocapitalize="none" '
            b'autocomplete="username" maxlength="150" required id="id_username"></form>')
    out = redact_body(page, "text/html; charset=utf-8")
    assert token not in out and b'name="username"' in out and b'id="id_username"' in out


@pytest.mark.parametrize("ctype", ["text/plain", "application/octet-stream", ""])
def test_a_truncated_sniffed_json_body_is_never_kept(ctype):
    """T20. A second instance of BUG-0527's pass-through (found by the AU-OUTCOME
    reviewer): a body sniffed as JSON that does not parse was returned as received; the
    same body, complete, is redacted. Must fail against the failed ``json?`` sniff's
    ``return body``."""
    from fuzzlab.core.redaction import redact_body
    body = b'{"access_token": "abc123secret", "user": {"id": 1'
    out = redact_body(body, ctype)
    assert b"abc123secret" not in out
    assert b"abc123secret" not in redact_body(body + b"}}", ctype)      # the complete one


# --- the kinds, the shapes and the bounds of the text pass ---------------------------------

_T9_BODY = (b'<form><input type="hidden" name="csrf_token" value="CANARY_T9_ATTR"></form>\n'
            b"password=CANARY_T9_KV\n")
#: Declared out of policy: stored as received (residual R4).
_T9_BINARY = ["image/png", "audio/mpeg", "video/mp4", "font/woff2", "application/pdf",
              "application/zip", "application/gzip", "application/wasm",
              "application/x-protobuf", "application/grpc", "application/vnd.ms-fontobject"]
_T9_KNOWN = ["text/html", "application/xhtml+xml", "text/vnd.turbo-stream.html", "text/xml",
             "application/xml", "image/svg+xml", "application/rss+xml",
             "application/javascript", "text/javascript", "application/x-javascript",
             "application/ecmascript", "text/ecmascript", "text/css", "text/plain",
             "text/markdown", "text/csv", "text/yaml", "application/yaml",
             "application/x-yaml", "message/http", "text/event-stream",
             "application/x-ndjson", "application/octet-stream", "application/x-sh",
             "application/x-httpd-php", "application/json", "application/ld+json",
             "application/problem+json", "application/x-www-form-urlencoded",
             "multipart/form-data", ""]
_T9_MALFORMED = ["text/html;;", '"text/html"', "TEXT/HTML ; charset=", "text/html\x00", ";",
                 "/", "html", " ", "text/", "/html", "text/html; charset=utf-8; foo",
                 "application/json;", "multipart/form-data; boundary=", "*/*", "text/*",
                 "text/html, application/json", "application/x-www-form-urlencoded; x"]


def _t9_generated(n: int = 24) -> list[str]:
    rnd, alpha = random.Random(527), "abcdefghijklmnopqrstuvwxyz0123456789.-+"

    def word():
        return "".join(rnd.choice(alpha) for _ in range(rnd.randint(1, 12)))
    shapes = [lambda: f"{word()}/{word()}", lambda: f"application/x-{word()}",
              lambda: f"text/{word()}", lambda: f"{word()}/{word()}+{word()}",
              lambda: f"{word()}", lambda: f"{word()}/{word()}; charset={word()}"]
    return [shapes[i % len(shapes)]() for i in range(n)]


@pytest.mark.parametrize("ctype", _T9_KNOWN + _T9_MALFORMED + _t9_generated(), ids=repr)
def test_no_media_type_passes_a_bound_secret_through_unless_declared_binary(ctype):
    """T9 (PA-0527(1)(2)): every known, malformed and generated unknown Content-Type gets a
    rule; none passes a bound secret through. Must fail against any pass-through branch
    in the dispatch."""
    from fuzzlab.core.redaction import redact_body
    assert ctype.split(";")[0].strip().lower() not in _T9_BINARY
    assert _canaries(redact_body(_T9_BODY, ctype)) == []


@pytest.mark.parametrize("ctype", _T9_BINARY)
def test_a_declared_binary_body_is_stored_as_received(ctype):
    """T9 (control): the closed out-of-policy list (R4). Must fail against a text pass
    over declared binary types."""
    from fuzzlab.core.redaction import redact_body
    assert redact_body(_T9_BODY, ctype) == _T9_BODY


#: The budget is checked after each charge, so one C-level span over a whole body (charged
#: 1 per 256 characters) may land past the cap.
_ONE_SPAN = (8 << 20) // 256 + 1


def _cap_fill(unit: bytes, head: bytes, tail: bytes) -> bytes:
    from fuzzlab.core.redaction import MAX_REDACT_BYTES
    room = MAX_REDACT_BYTES - 64 - len(head) - len(tail)
    return head + unit * (room // len(unit)) + tail


_T12_TAIL = b'\n<input type="hidden" name="csrf" value="CANARY_T12">'
#: The reviewers' crafted 8 MiB bodies (rev 2 took 7.4-55 s on them) and this lane's.
_T12_SHAPES = {
    "lex-tag-equals-60k": (b'<a name="csrf" ' + b"=" * 60000 + b">", b"<html>", "text/html"),
    "lex-tag-equals-4k": (b'<a name="csrf" ' + b"=" * 4000 + b">", b"<html>", "text/html"),
    "bind-attr-walk-slashes": (b"/" * 120 + b" token ", b"<html>", "text/html"),
    "type-hidden-no-tag": (b"type=hidden ", b"<html>" + b"x" * 70000, "text/html"),
    "type-hidden-tag-60k-back": (b"<i " + b"type=hidden " * 5000 + b">", b"<html>",
                                 "text/html"),
    "token-amp-one-line": (b"token=1&", b"", "text/plain"),
    "token-list-js": (b"token:[" + b"1," * 2000 + b"1],", b"<html>",
                      "application/javascript"),
    "csrf-after-8-lt": (b'<b title="' + b"<x>" * 8 + b'" name="csrf" value="v">', b"<html>",
                        "text/html"),
    "many-hidden-inputs": (b'<input type="hidden" name="a" value="x1y2z3w4v5u6t7s8">',
                           b"<html>", "text/html"),
    "json-leaves": (b'{"note":"token: x","q":"a&key=b"},', b"[", "text/plain"),
    "benign-html": (b"<p>The quick brown fox jumps over the lazy dog.</p>\n", b"<html>",
                    "text/html"),
}


@pytest.mark.parametrize("shape", list(_T12_SHAPES))
def test_the_text_pass_does_bounded_work_on_crafted_bodies(shape):
    """T12 (M6): one budget charges every Python step and every C-level span; a crafted
    body at the size cap ends redacted or as an omission within it, never as a kept
    secret; a large benign page is not omitted. Must fail against an uncharged loop
    (the counters exceed the cap) and, on the old owner, the pass-through."""
    from fuzzlab.core.redaction import redact_body
    unit, head, ctype = _T12_SHAPES[shape]
    # the canary sits where the old owner never looks: after the body's last line, or
    # (sniffed JSON) inside a string leaf that holds markup
    leaf = b'{"html":"<input name=\\"csrf\\" value=\\"CANARY_T12\\">"}]'
    body = _cap_fill(unit, head, _T12_TAIL if shape != "json-leaves" else leaf)
    out = redact_body(body, ctype)
    assert _canaries(out) == []
    if shape == "benign-html":
        assert not out.startswith(b"__BODY_OMITTED__")
    from fuzzlab.core.redaction import TEXT_MAX_HITS, TEXT_OPS_CAP
    stats: dict = {}
    redact_body(body, ctype, stats=stats)
    assert stats["ops"] <= TEXT_OPS_CAP + _ONE_SPAN and stats["hits"] <= TEXT_MAX_HITS + 1


class _SmokeAlarm(BaseException):
    """Not an `Exception`: the redactor's totality guard (``except Exception`` ->
    `OMIT_FAILED`, PA-0096) must not swallow the alarm and pass the test."""


@contextlib.contextmanager
def _smoke_alarm(seconds: int = 20):
    """PA-0135(1): a generous absolute alarm, never a ratio. A linear pass takes well under
    a second on these bodies; a quadratic scan takes minutes (B1: 64 s at 352 KiB, 392 s
    at 1 MiB). SIGALRM interrupts a running regex scan."""
    def fire(*_a):
        raise _SmokeAlarm(f"over the {seconds} s smoke alarm")
    old = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _sized(unit: bytes, head: bytes, size: int, tail: bytes) -> bytes:
    return head + unit * ((size - len(head) - len(tail)) // len(unit)) + tail


def _base64_state(size: int) -> bytes:
    """A realistic state attribute: concatenated base64 JSON objects (every one starts
    with ``eyJ``), as SPAs embed them (reviewer A measured ~9 s/MiB on rev 3)."""
    blobs, n, i = [], 0, 0
    while n < size:
        b = base64.b64encode(json.dumps({"id": i, "name": f"item{i}", "tags": ["a", "b"]},
                                        separators=(",", ":")).encode())
        blobs.append(b)
        n, i = n + len(b), i + 1
    return b'<html><body><div data-state="' + b"".join(blobs)[:size] + b'"></div>'


#: One shape per scan that runs over a whole body (B1), at 1 MiB or more.
_T12_SCANS = {
    "unclosed-script-openers": lambda: _sized(b"<script>x", b"<html>", 1 << 20, _T12_TAIL),
    "unclosed-style-openers": lambda: _sized(b"<style ", b"<html>", 1 << 20, _T12_TAIL),
    "eyJ-run": lambda: _sized(b"eyJ", b"<p>", 1 << 20, _T12_TAIL),
    "base64-json-state": lambda: _base64_state(4 << 20) + _T12_TAIL,
    "skeleton-identifier-tags": lambda: _cap_fill(
        b"<Ab1Cd2Ef3Gh4Ij5Kl6>", b'<html><input name="csrf" value="CANARY_T12unterminated', b""),
    "pem-begin-run": lambda: _cap_fill(b"-----BEGIN RSA PRIVATE KEY-----\n",
                                       b"-----BEGIN RSA PRIVATE KEY-----\nCANARYpemT12\n",
                                       b"-----END RSA PRIVATE KEY-----"),
    # the bare-DSN look back runs once per '@' (bounded by the hit cap); Bearer per match
    "dsn-at-dense": lambda: _sized(b"a:b@c(", b"", 1 << 20, b"\npassword=CANARY_T12"),
    "bearer-dense": lambda: _sized(b"Bearer abcdefgh12 ", b"", 1 << 20, b"\npassword=CANARY_T12"),
}


@pytest.mark.parametrize("shape", list(_T12_SCANS))
def test_every_whole_body_scan_is_linear(shape):
    """T12 (B1): the raw-text index, the JWT scan, the skeleton and the PEM scan read a
    body of 1-8 MiB in one linear pass each: under the smoke alarm, within the
    operations cap, the skeleton reading at most `TEXT_SKELETON_SCAN` characters. Must
    fail against the revision-3 lazy `_RAWTEXT` regex, the revision-3 `_JWT` regex
    (each over the alarm) and an unbounded skeleton (over its scan count), and, on the
    old owner, the pass-through (the canary is kept)."""
    from fuzzlab.core.redaction import redact_body
    body = _T12_SCANS[shape]()
    ctype = "text/plain" if shape in ("pem-begin-run", "dsn-at-dense", "bearer-dense") \
        else "text/html"
    with _smoke_alarm():
        out = redact_body(body, ctype)
    assert _canaries(out) == [] and not out.startswith(b"__BODY_OMITTED__ (redaction failed)")
    from fuzzlab.core.redaction import TEXT_MAX_HITS, TEXT_OPS_CAP, TEXT_SKELETON_SCAN
    stats: dict = {}
    with _smoke_alarm():
        redact_body(body, ctype, stats=stats)
    assert stats["ops"] <= TEXT_OPS_CAP + _ONE_SPAN and stats["hits"] <= TEXT_MAX_HITS + 1
    assert stats.get("skeleton_scanned", 0) <= TEXT_SKELETON_SCAN


def test_a_real_login_page_changes_only_in_its_token():
    """T14: Django's admin login page, rendered in-process (its token replaced by a
    canary): exactly the token's span becomes the placeholder; every other byte is
    kept. Must fail against a re-encoding splice or a false binding."""
    from fuzzlab.core.redaction import redact_body
    page = (DATA / "django_admin_login.html").read_bytes()
    [token] = set(re.findall(rb'name="csrfmiddlewaretoken" value="([^"]+)"', page))
    assert redact_body(page, "text/html; charset=utf-8") == page.replace(token,
                                                                         b"__REDACTED__")


_T18_QUERY = rb"(?:^|[?&]|&amp;)(tag|token|q)="
_T18_JSON = rb'"(tag|token|q)":'


@pytest.mark.parametrize("body,ctype,names", [
    (b"tag=a&token=CANARY_R1&tag=b&q=pup&token=CANARY_R2", "application/x-www-form-urlencoded",
     _T18_QUERY),
    (b"tag=a&token=CANARY_R1&tag=b&q=pup&token=CANARY_R2", "text/plain", _T18_QUERY),
    (b"tag=a&token=CANARY_R1&tag=b&q=pup&token=CANARY_R2", "", _T18_QUERY),
    (b"GET /x?tag=a&token=CANARY_R1&tag=b&q=pup&token=CANARY_R2 200\n", "text/plain",
     _T18_QUERY),
    (b'<a href="/x?tag=a&amp;token=CANARY_R1&amp;tag=b&amp;q=pup&amp;token=CANARY_R2">x</a>',
     "text/html", _T18_QUERY),
    # M1: repeated JSON keys, and a name that closes its own string ("token:") binds
    # nothing
    ((b'{"tag":"a","token":"CANARY_R1","tag":"b","q":"pup","token":"CANARY_R2",'
      b'"label":"token:"}'), "text/plain", _T18_JSON),
], ids=["form", "sniffed-form", "untyped-form", "text-line", "html-href", "sniffed-json"])
def test_repeated_names_and_their_order_survive_redaction(body, ctype, names):
    """T18. Request identity (audit defects 8 and 14) needs every entry: redaction
    rewrites a value in place and never drops, merges or reorders a sibling entry,
    repeated names included. Must fail against end-of-line grammar over a sniffed form,
    and against a sniffed-JSON redactor that round-trips through a dict."""
    from fuzzlab.core.redaction import redact_body
    out = redact_body(body, ctype)
    assert _canaries(out) == []
    assert re.findall(names, out) == [b"tag", b"token", b"tag", b"q", b"token"], out
    if names == _T18_JSON:
        assert json.loads(out)["label"] == "token:"


def test_scripts_keep_identifiers_and_redact_bound_literals():
    """T19 (decision 4, M1): in a script a bound quoted or numeric literal is replaced;
    an identifier is code and stays; a name whose own string closes after it (string
    concatenation) binds nothing, so the code after it (a mined API call) is kept. Must
    fail against "any unquoted token", and against a value that runs past the closing
    quote."""
    from fuzzlab.core.redaction import redact_body
    from fuzzlab.disco.synth import _JS_CALL
    js = (b"var token = tokens; let key = keys[i];\n"
          b'const pin = 1234; var apiKey = "CANARY_T19_APIKEY"; var o = {secret: 0x1F};\n'
          b"var u = '/a?token=' + t; fetch('/api/Users');\n"
          b"x.token = getToken();\n"
          # B5: ES2022 private fields; ADOPT: `default` is a keyword, not prose
          b'class A{#token="CANARY_T19_PRIV1";#apiKey=\'CANARY_T19_PRIV2\'}\n'
          b'this.#accessToken = "CANARY_T19_PRIV3";\n'
          b'export default token = "CANARY_T19_DEFAULT";\n')
    out = redact_body(js, "application/javascript")
    assert _canaries(out) == [] and b"1234" not in out and b"0x1F" not in out
    for kept in (b"var token = tokens;", b"let key = keys[i];", b"x.token = getToken();",
                 b"var u = '/a?token=' + t;"):
        assert kept in out, kept
    assert [m.group(3) for m in _JS_CALL.finditer(out.decode())] == ["/api/Users"]


_T34_JSON = [
    b'{"error":"invalid auth: {\\"reason\\":\\"expired\\"}","id":7}',
    b'{"log":"token: [1,2,3] rejected","id":7}',
    b'{"q":"sort=price&token=CANARY_T34_QUERY","id":7}',
    b'{"msg":"Error code: 404 Not Found","id":7}',
    b'[{"name":"Rex","note":"pin: {see desk}"}]',
    b'{"html":"<input type=\\"hidden\\" name=\\"_token\\" value=\\"CANARY_T34_HTML\\">","n":1}',
    b'{"items":[{"id":1,"name":"pup"}],"total":1}',
    b'{"tag":"a","token":"CANARY_T34_R1","tag":"b","token":"CANARY_T34_R2"}',
    b'{"access_token": "abc123secret", "user": {"id": 1}}',
    # ADOPT: an unbalanced bracket after a sensitive word binds to the leaf's end; the
    # body is not omitted. A number keeps its written text.
    b'{"log":"token: [CANARY_T34_OPEN, 2","id":7}',
    b'{"n":1e400,"token":"CANARY_T34_NUM"}',
]


def _json_keys(text: bytes) -> list:
    keys: list = []

    def walk(v):
        if isinstance(v, list) and v and all(isinstance(p, tuple) for p in v):
            for k, x in v:
                keys.append(k)
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    walk(json.loads(text, object_pairs_hook=list))
    return keys


@pytest.mark.parametrize("ctype", ["text/plain", ""])
@pytest.mark.parametrize("body", _T34_JSON, ids=lambda b: b[:24].decode())
def test_a_parseable_sniffed_json_body_stays_valid_json_with_every_entry(body, ctype):
    """T34 (M2): a sniffed JSON body that parses has its string leaves redacted, so it
    stays valid JSON with every key, in order. Must fail against the text pass run over
    a parseable body (it breaks the JSON) and against a dict round trip (it merges
    repeated keys)."""
    from fuzzlab.core.redaction import redact_body
    out = redact_body(body, ctype)
    assert _canaries(out) == [] and b"abc123secret" not in out
    assert _json_keys(out) == _json_keys(body)
    if b"1e400" in body:
        assert b"1e400" in out                         # never re-serialised as Infinity


_T35 = [
    ("turbo-stream", "text/vnd.turbo-stream.html",
     (b'<turbo-stream action="replace" target="f"><template><input type="hidden" '
      b'name="authenticity_token" value="CANARY_T35_TURBO"></template></turbo-stream>')),
    ("fragment-untyped", "", b'<section><input name="csrf" value="CANARY_T35_FRAG"></section>'),
    ("fragment-text-plain", "text/plain",
     b'<label>x</label><input name="csrf_token" value="CANARY_T35_PLAIN">'),
    ("js-erb-escaped-quotes", "application/javascript",
     (b'$("#f").html("<input type=\\"hidden\\" name=\\"authenticity_token\\" '
      b'value=\\"CANARY_T35_ERB\\">");')),
    ("inner-html", "application/javascript",
     b"el.innerHTML = '<meta name=\"csrf-token\" content=\"CANARY_T35_INNER\">';"),
    ("html-in-json-sniffed", "text/plain",
     b'{"html":"<input type=\\"hidden\\" name=\\"_token\\" value=\\"CANARY_T35_LW\\">"}'),
    ("html-in-json-declared", "application/json",
     (b'{"effects":{"html":"<input type=\\"hidden\\" name=\\"_token\\" '
      b'value=\\"CANARY_T35_LWD\\">"}}')),
    ("spring-property", "application/xml",
     (b'<beans><bean id="ds"><property name="password" value="CANARY_T35_SPRING"/>'
      b'<property name="url" value="jdbc:x"/></bean></beans>')),
    ("dotnet-appsettings", "application/xml",
     (b'<configuration><appSettings><add key="ApiKey" value="CANARY_T35_NET"/>'
      b"</appSettings></configuration>")),
    ("saml-attribute", "text/xml",
     (b'<saml:Attribute Name="password"><saml:AttributeValue>CANARY_T35_SAML'
      b"</saml:AttributeValue></saml:Attribute>")),
    ("utf8-bom-html-untyped", "",
     b"\xef\xbb\xbf<!DOCTYPE html><html><input type=hidden name=csrf value=CANARY_T35_BOM>"),
    ("properties-entry", "application/xml",
     (b'<properties><entry key="db.password">CANARY_T35_ENTRY</entry>'
      b'<entry key="db.url">jdbc:x</entry></properties>')),
]


@pytest.mark.parametrize("label,ctype,body", _T35, ids=[c[0] for c in _T35])
def test_markup_rules_run_wherever_markup_occurs(label, ctype, body):
    """T35 (M3): the html rules run on any ``*html*`` type, on any body holding
    ``<input``/``<meta``/``<textarea``, through ``\\"``-escaped quotes and inside JSON
    string leaves; the xml rules pair ``name=``/``key=``/``Name=`` with ``value=`` and an
    element's content. Must fail against markup rules keyed on the declared type only."""
    from fuzzlab.core.redaction import redact_body
    out = redact_body(body, ctype)
    assert _canaries(out) == []
    if label.startswith("html-in-json"):
        json.loads(out)
    if label in ("spring-property", "properties-entry"):
        assert b"jdbc:x" in out


@pytest.mark.parametrize("label,ctype,body", [
    ("jwt-in-prose", "text/html",
     b"<p>Your session: eyJhbGciOiJub25lIn0.CANARYjwtPayloadAAAA.CANARYjwtSigBBBB</p>"),
    ("pem-private-key", "text/plain",
     (b"-----BEGIN PRIVATE KEY-----\nCANARYpemLINEone\nCANARYpemLINEtwo\n"
      b"-----END PRIVATE KEY-----\n")),
    ("userinfo-href", "text/html",
     b'<a href="https://admin:CANARY_T36_USERINFO@db.example/x">db</a>'),
    ("userinfo-js-string", "application/javascript",
     b'const dsn = "postgres://app:CANARY_T36_DSN@db.example:5432/x";'),
    # a statement before the call: one line alone sniffs as a form and is redacted today
    ("query-in-script-string", "application/javascript",
     b'const a = 1;\nfetch("/api/x?api_key=CANARY_T36_QS&q=1");\n'),
    ("query-in-template-literal", "application/javascript",
     b"const a = 1;\nfetch(`/api/y?access_token=CANARY_T36_TPL&sig=CANARY_T36_SIG`);\n"),
    ("google-key-in-url", "application/javascript",
     b'loadScript("https://maps.example/js?key=AIzaCANARYmapsKEY0123");'),
    ("pgp-private-key-block", "text/plain",
     (b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBCANARYpgpBODY\n"
      b"-----END PGP PRIVATE KEY BLOCK-----\n")),
    ("putty-ppk", "text/plain",
     (b"PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: lab\n"
      b"Private-Lines: 1\nAAAACANARYppkLINE\nPrivate-MAC: ab\n")),
    ("bare-dsn", "text/plain", b"APP=x\nDB_DSN=root:CANARY_T36_BAREDSN@tcp(db:3306)/app\n"),
    ("matrix-value-ends-at-query", "text/html",
     b'<a href="/shop;jsessionid=CANARY_T36_JSID?item=1">x</a>'),
], ids=lambda v: v if isinstance(v, str) and "/" not in v and v else None)
def test_credential_shapes_with_no_binding_name_are_redacted(label, ctype, body):
    """T36 (M4): a JWT, a PEM private-key block, URL userinfo (the owner's userinfo
    shape, PA-0003) and a URL query inside a script string or template literal are
    redacted wherever they occur. Must fail against a pass with name bindings only."""
    from fuzzlab.core.redaction import redact_body
    out = redact_body(body, ctype)
    assert _canaries(out) == []
    if label.startswith("userinfo"):
        assert b"db.example" in out
    if label.startswith("query"):
        assert b"fetch(" in out
    if label == "bare-dsn":
        assert b"@tcp(db:3306)/app" in out and b"APP=x" in out
    if label == "matrix-value-ends-at-query":
        assert b"?item=1" in out


def _multipart_body() -> bytes:
    return (b"--XyZ\r\nContent-Disposition: form-data; name=\"page\"\r\nContent-Type: text/html"
            b"\r\n\r\n<input name=\"csrf\" value=\"CANARY_T37_PART\">\r\n--XyZ\r\n"
            b"Content-Disposition: form-data; name=\"q\"\r\n\r\npup\r\n--XyZ--\r\n")


_T37 = [
    ("tag-search-exhausted", "text/html",
     b'<b title="' + b"<x>" * 40 + b'" name="csrf" value="CANARY_T37_TAGS">'),
    ("utf16-bom", "text/html",
     codecs.BOM_UTF16_LE + '<input name="csrf" value="CANARY_T37_U16">'.encode("utf-16-le")),
    ("utf16-no-bom-untyped", "", '{"token":"CANARY_T37_U16NB","n":1}'.encode("utf-16-le")),
    ("utf16-declared-charset", "text/html; charset=utf-16",
     '<input name="csrf" value="CANARY_T37_U16CS">'.encode("utf-16-le")),
    ("utf32-bom", "text/html",
     codecs.BOM_UTF32_LE + '<input name="csrf" value="CANARY_T37_U32">'.encode("utf-32-le")),
    ("declared-form-mismatch", "application/x-www-form-urlencoded",
     b'<input name="csrf" value="CANARY_T37_FORM">'),
    ("multipart-part-content", "multipart/form-data; boundary=XyZ", _multipart_body()),
    ("yaml-block-scalar", "application/yaml",
     b"tls:\n  private_key: |\n    CANARY_T37_YAML1\n    CANARY_T37_YAML2\nname: pup\n"),
    ("properties-continuation", "text/plain",
     b"db.password=CANARY_T37_PROP1\\\n    CANARY_T37_PROP2\nother=1\n"),
]


@pytest.mark.parametrize("label,ctype,body", _T37, ids=[c[0] for c in _T37])
def test_unprovable_and_unusual_shapes_fail_closed(label, ctype, body):
    """T37 (M5): an exhausted backward tag search omits; UTF-16/32 (a BOM, a NUL-heavy
    sniff, a declared charset) is decoded and redacted or omitted, never stored as
    received; a declared form or multipart body that does not match its shape gets the
    text pass, each part by its own type; a YAML block scalar and a ``.properties``
    continuation are one value. Must fail against binding nothing on an exhausted
    search, against storing a wide encoding as received, and against a one-line value."""
    from fuzzlab.core.redaction import redact_body
    out = redact_body(body, ctype)
    assert _canaries(out.replace(b"\0", b"")) == []
    if label == "utf16-declared-charset":
        assert not out.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE))
    if label == "multipart-part-content":
        assert b"pup" in out
    if label == "yaml-block-scalar":
        assert b"name: pup" in out
    if label == "properties-continuation":
        assert b"other=1" in out


# --- the proxy's framed bodies: fail-closed (S1, CC-PROXY-0028) ---------------------------

def test_a_framed_body_is_byte_exact_when_clean_and_a_typed_omission_otherwise(tmp_path):
    """T15 (S1): a clean chunked and gzip body is stored byte-exact (the desync
    primitive's bytes stay as on the wire); one that redaction would change is replaced
    by a typed marker with ``Transfer-``/``Content-Encoding`` dropped and a consistent
    ``Content-Length``; the marker never embeds the target's coding name. Must fail
    against judging the decoded payload with the old owner (it is judged clean)."""
    from fuzzlab.proxy.message import RawMessage
    clean = _response("text/html", b"Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n",
                      _chunked(gzip.compress(CLEAN_PAGE, mtime=0)))
    assert _history(tmp_path / "a.db", clean)[1] == clean
    blob, raw = _history(tmp_path / "b.db", _response(
        "text/html", b"Content-Encoding: gzip\r\n", gzip.compress(HTML, mtime=0)))
    assert _canaries(blob) == []
    msg = RawMessage.from_bytes(raw)
    assert msg.body == _marker("gzip", "redaction would change it")
    assert msg.get("Content-Encoding") is None and msg.get("Transfer-Encoding") is None
    assert msg.get("Content-Length") == str(len(msg.body)).encode()
    _blob, raw = _history(tmp_path / "c.db", _response(
        "text/html", b"Content-Encoding: Gzip;q=<script>\r\n", gzip.compress(CLEAN_PAGE)))
    assert _stored_body(raw) == _marker("other", "coding not supported here")


@pytest.mark.parametrize("encoding,payload", [
    ("gzip", gzip.compress(b"q=puppies", mtime=0)
     + gzip.compress(b"&password=CANARY_MEMBER2", mtime=0)),
    ("deflate", zlib.compress(b"q=1") + b"&password=CANARY_TRAILING"),
], ids=["gzip", "deflate"])
def test_every_gzip_member_and_trailing_byte_is_judged(tmp_path, encoding, payload):
    """T21. The decoder read one gzip member (or one deflate stream) and ignored the rest,
    so a clean first member let a secret in a second member, or in trailing bytes, be
    stored byte-exact."""
    resp = _response("application/x-www-form-urlencoded",
                     b"Content-Encoding: " + encoding.encode() + b"\r\n", payload)
    blob, _raw = _history(tmp_path / "f.db", resp)
    assert _canaries(blob) == []


def test_a_decompression_bomb_is_a_typed_omission_with_bounded_memory(tmp_path):
    """T22. Audit defect 21's class: a body whose decoded size passes the cap ends as a
    typed omission, never as the stored bomb and never as unbounded memory."""
    import tracemalloc

    from fuzzlab.core.redaction import MAX_REDACT_BYTES
    bomb = gzip.compress(b"\0" * (4 * MAX_REDACT_BYTES), compresslevel=9, mtime=0)
    resp = _response("text/html", b"Content-Encoding: gzip\r\n", bomb)
    tracemalloc.start()
    try:
        _blob, raw = _history(tmp_path / "f.db", resp)
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert _stored_body(raw) == _marker("gzip", "decoded body over the cap")
    assert peak < 4 * MAX_REDACT_BYTES


def test_many_gzip_members_are_capped_with_bounded_work(tmp_path):
    """T29 (S1): 120,001 members, the last holding a secret, end at the member cap; the
    decoder is fed by offset, so the input it touches is bounded by the members it
    reads, never re-copying the rest of the body per member (reviewer B's members.py).
    Must fail against the one-member decoder (stored as received) and against an
    ``unused_data`` loop (the bytes fed grow with the body)."""
    from fuzzlab.proxy.message import RawMessage
    empty = gzip.compress(b"", mtime=0)
    payload = empty * 120_000 + gzip.compress(b"password=CANARY_LAST_MEMBER", mtime=0)
    resp = _response("text/html", b"Content-Encoding: gzip\r\n", payload)
    blob, raw = _history(tmp_path / "f.db", resp)
    assert _canaries(blob) == []
    assert _stored_body(raw) == _marker("gzip", "over the member cap")
    from fuzzlab.proxy.redact import (
        FRAME_FIRST_PIECE,
        FRAME_MEMBER_CAP,
        FramingStats,
        judge_framed,
    )
    stats = FramingStats()
    judge_framed(RawMessage.from_bytes(resp), payload, stats=stats)
    assert stats.members == FRAME_MEMBER_CAP + 1
    assert stats.fed <= (FRAME_MEMBER_CAP + 1) * FRAME_FIRST_PIECE


def test_the_decoded_cap_reached_at_a_member_boundary_stops_the_next_member(monkeypatch):
    """T30 (S1): the members before decode to exactly the cap; the next member is a bomb.
    It is asked for at most one byte (``max_length >= 1``: zlib reads 0 as unbounded),
    so the total produced is the cap plus one. Must fail against the one-member decoder
    (stored as received) and against ``max_length = cap - total``."""
    import fuzzlab.proxy.redact as r
    from fuzzlab.proxy.message import RawMessage
    monkeypatch.setattr(r, "MAX_REDACT_BYTES", 1000)
    payload = (gzip.compress(b"a" * 1000, mtime=0)
               + gzip.compress(b"\0" * 10_000_000 + b"password=CANARY_PAST_CAP", mtime=0))
    resp = _response("text/html", b"Content-Encoding: gzip\r\n", payload)
    out = RawMessage.from_bytes(r.redact(resp))
    assert out.body == _marker("gzip", "decoded body over the cap")
    stats = r.FramingStats()
    r.judge_framed(RawMessage.from_bytes(resp), payload, stats=stats)
    assert stats.produced <= 1001


@pytest.mark.parametrize("framing,payload,expect", [
    (b"Content-Encoding: gzip\r\nContent-Encoding: gzip\r\n",
     gzip.compress(gzip.compress(b"<p>x</p>", mtime=0), mtime=0),
     _marker("gzip+gzip", "duplicate Content-Encoding headers")),
    (b"Transfer-Encoding: gzip, chunked\r\n",
     _chunked(gzip.compress(b"<p>password=CANARY_TE_GZIP</p>", mtime=0)),
     _marker("other", "redaction would change it")),
], ids=["duplicate-content-encoding", "transfer-gzip-then-chunked"])
def test_ambiguous_framing_is_judged_in_every_reading(tmp_path, framing, payload, expect):
    """T31 (S1, B2): duplicate ``Content-Encoding`` headers (read with ``get_all``) are a
    typed omission; a ``Transfer-Encoding`` list is read as chunked and its transfer
    gzip undone, so a secret inside it is found. Must fail against reading the first
    header only, and against a chunked reading that stops before the transfer gzip."""
    blob, raw = _history(tmp_path / "f.db", _response("text/html", framing, payload))
    assert _canaries(blob) == []
    assert _stored_body(raw) == expect


def _gzip_with_fname(payload: bytes, fname: bytes) -> bytes:
    member = bytearray(gzip.compress(payload, mtime=0))
    member[3] |= 0x08                                  # FNAME
    member[10:10] = fname + b"\0"
    return bytes(member)


@pytest.mark.parametrize("framing,payload,why", [
    (b"Transfer-Encoding: chunked\r\n", b"3\r\nabc\r\n0\r\nX-Token: CANARY_TRAILER\r\n\r\n",
     "a trailer or suffix holds a secret"),
    (b"Transfer-Encoding: chunked\r\n", b"3;token=CANARY_CHUNK_EXT\r\nabc\r\n0\r\n\r\n",
     "a chunk extension holds a secret"),
    (b"Content-Encoding: gzip\r\n", _gzip_with_fname(b"<p>x</p>", b"password=CANARY_FNAME"),
     "a gzip header field holds a secret"),
], ids=["trailer", "chunk-extension", "gzip-fname"])
def test_framing_bytes_that_hold_a_secret_are_omitted(tmp_path, framing, payload, why):
    """T32 (S1): the bytes kept byte-exact around a clean payload are judged too: a
    trailer, a chunk extension, a gzip header's FNAME/FCOMMENT/FEXTRA. Must fail against
    judging the decoded payload only."""
    blob, raw = _history(tmp_path / "f.db", _response("text/html", framing, payload))
    assert _canaries(blob) == []
    coding = "chunked" if b"chunked" in framing else "gzip"
    assert _stored_body(raw) == _marker(coding, why)


#: Precomputed (brotli 1.2.0 quality 5; zstandard 0.25 level 3), so the test runs where
#: the codec is not installed: there the body must be omitted.
_BR_CLEAN = (b'\x1bD\x00\x00DO\x96*I\xb1\x99\xceU\xa5\n\x8d\xc61\x0e\\\xb6\xc7\x85\x16Yo'
             b'\xf0\x90\x95\xe8M\xf5\x81%A0=\x04\xb1\xe8\xeeZ\x893\xfcj\xfe\x8c\xcb\xa0\xed'
             b'\xeb\xd2\x05\xbf}\x8f\x14\r\x01')
_BR_DIRTY = (b'\x1b_\x00\x00D\xe7\x96:\xa1\x10\xa8\xf8\x8d\xb1\x19\rh1\x11\x9c6\x8bz\xc0'
             b'\xc5\x8f#\xdd[\xa1\x17L\xe4\xc4Zp\x90vT\x12\x84\xd2C\xe1V\xfc\x02"\xee.\xb4'
             b'\xfe;\x96\xef\xd6,f\x0e\x91\xf4\x1e\x950\x9e\x95\x85d;')
_ZSTD_CLEAN = (b"(\xb5/\xfd E)\x02\x00<html><body><p>Hello, author!</p><a href='/x?q=1'>x"
               b"</a></body></html>")
_ZSTD_DIRTY = (b'(\xb5/\xfd `\xe5\x02\x00B\x05\x14\x1a\x80\xa7\x0e\x00\xf0\xd3\x1f\xfeS\xe7P'
               b'(&\x15\x0e>\xa0K\x9dO\xeaZ\x08\x9a;\x02,\xfd\xa11fY\x89\x15P\xec\x1c\x01\x1b'
               b'\xac\x04HJQ#\xb2\x1d\x8a\xbe\xc3PP\xd4\xdef\xd1\xd9\xceE\xa8\xa8\x8d\xe4\xcb#'
               b'\xc6\x8c\xcb~\x14o9q\x05aY\xfa\xc3\r\x02\x00P\x0ci\x86!\x98\x01')
_ZSTD_SKIP = _ZSTD_CLEAN + b"P*M\x18\x18\x00\x00\x00password=CANARY_T33_SKIP"


@pytest.mark.parametrize("coding,module,clean,dirty", [
    ("br", "brotli", _BR_CLEAN, _BR_DIRTY),
    ("zstd", "zstandard", _ZSTD_CLEAN, _ZSTD_DIRTY),
], ids=["br", "zstd"])
def test_br_and_zstd_bodies_are_judged_decoded_or_omitted(tmp_path, coding, module, clean,
                                                          dirty):
    """T33 (S1, PA-0005): with the codec importable (the ``proxy-codecs`` extra) a br or
    zstd body is decoded and judged like gzip; without it, it is omitted. A zstd
    skippable frame (content the decoder skips) is omitted. Must fail against storing an
    undecodable body by a name scan of its compressed bytes."""
    import importlib.util
    framing = b"Content-Encoding: " + coding.encode() + b"\r\n"
    _b, raw_clean = _history(tmp_path / "a.db", _response("text/html", framing, clean))
    _b, raw_dirty = _history(tmp_path / "b.db", _response("text/html", framing, dirty))
    if importlib.util.find_spec(module) is None:
        assert _stored_body(raw_clean) == _marker(coding, "coding not supported here")
        assert _stored_body(raw_dirty) == _marker(coding, "coding not supported here")
        return
    assert _stored_body(raw_clean) == clean
    assert _stored_body(raw_dirty) == _marker(coding, "redaction would change it")
    if coding == "zstd":
        _b, raw = _history(tmp_path / "c.db", _response("text/html", framing, _ZSTD_SKIP))
        assert _stored_body(raw) == _marker("zstd", "a skippable frame may hold content")


#: 9 MiB of zeros, over the 8 MiB decoded cap (brotli 1.2.0 quality 11, zstandard level 19).
_BR_BOMB = base64.b64decode("y///P/gnAOKxQCD3/q/+/x//BEAcFgHo3j8A")
_ZSTD_BOMB = base64.b64decode(
    "KLUv/YBoAACQAEwAAAgAAQD8/zkQAgIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACAB"
    "AAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQ"
    "AAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEA"
    "ACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAA"
    "AgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAADABAA")


@pytest.mark.parametrize("coding,module,bomb", [("br", "brotli", _BR_BOMB),
                                                ("zstd", "zstandard", _ZSTD_BOMB)],
                         ids=["br", "zstd"])
def test_a_br_or_zstd_bomb_is_a_typed_omission(tmp_path, coding, module, bomb):
    """T33b (ADOPT): a br or zstd body decoding past the cap ends at the decoded cap
    (``output_buffer_limit``, ``read(cap + 1)``), or, without the codec, as unsupported.
    Must fail against an undecoded body stored as received."""
    import importlib.util
    framing = b"Content-Encoding: " + coding.encode() + b"\r\n"
    _b, raw = _history(tmp_path / "a.db", _response("text/html", framing, bomb))
    why = ("decoded body over the cap" if importlib.util.find_spec(module)
           else "coding not supported here")
    assert _stored_body(raw) == _marker(coding, why)


def test_the_chunk_cap_bounds_the_chunked_reading(tmp_path):
    """T43 (ADOPT): at most 65,536 chunks are read; one more and the body is a typed
    omission (bounded Python steps). Must fail against an uncapped chunk loop."""
    body = b"1\r\nx\r\n" * 65_537 + b"0\r\n\r\n"
    _b, raw = _history(tmp_path / "f.db", _response("text/html",
                                                    b"Transfer-Encoding: chunked\r\n", body))
    assert _stored_body(raw) == _marker("chunked", "over the chunk cap")


def _desync_request(te_lines: bytes, body: bytes) -> bytes:
    return (b"POST / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/x-www-"
            b"form-urlencoded\r\nContent-Length: 4\r\n" + te_lines + b"\r\n" + body)


_SMUGGLED = b"0\r\n\r\nGPOST / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"
_T45 = [
    ("cl-te-clean-suffix", b"Transfer-Encoding: chunked\r\n", _SMUGGLED),
    ("te-cl-smuggled-in-chunk", b"Transfer-Encoding: chunked\r\n",
     (b"5c\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
      b"Content-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n")),
    ("te-te-duplicate-header", b"Transfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n",
     _SMUGGLED),
    ("te-xchunked", b"Transfer-Encoding: xchunked\r\n", _SMUGGLED),
    ("te-chunked-identity", b"Transfer-Encoding: chunked, identity\r\n", _SMUGGLED),
    ("cl-te-suffix-path-keys", b"Transfer-Encoding: chunked\r\n",
     b"0\r\n\r\nGET /api/keys HTTP/1.1\r\nX: x"),
    ("cl-te-suffix-host-auth", b"Transfer-Encoding: chunked\r\n",
     b"0\r\n\r\nGET / HTTP/1.1\r\nHost: auth.lab\r\n\r\n"),
]


@pytest.mark.parametrize("label,te,body", _T45, ids=[c[0] for c in _T45])
def test_a_clean_desync_probe_stays_byte_exact(label, te, body):
    """T45 (B2, control): every plausible reading of a desync probe (chunked when a
    ``chunked`` token is present, and identity) is clean, so the stored request keeps
    the probe's bytes (the desync primitive replays them). Must fail against refusing a
    TE list or an unknown TE, and against judging the suffix with the name scan."""
    from fuzzlab.proxy.message import RawMessage
    from fuzzlab.proxy.redact import redact
    raw = _desync_request(te, body)
    assert RawMessage.from_bytes(redact(raw)).body == body


def test_a_precompressed_file_named_like_a_secret_stays_byte_exact(tmp_path):
    """T45 (B2, control): a gzip member's FNAME is judged by the text pass, so a
    precompressed ``auth.js`` (no binding, no credential) stays byte-exact. Must fail
    against the name scan over header fields."""
    payload = _gzip_with_fname(b"function a(){return 1}", b"auth.js")
    resp = _response("application/javascript", b"Content-Encoding: gzip\r\n", payload)
    assert _history(tmp_path / "f.db", resp)[1] == resp


@pytest.mark.parametrize("label,body", [
    ("userinfo", b'{"url":"postgres://app:CANARY_T46_DSN@db/x","n":[1,2'),
    # no sensitive word anywhere: today's name scan keeps these as received
    ("jwt-leaf", b'{"data":"eyJhbGciOiJub25lIn0.CANARYbodyT46seg.c2lnbmF0dXJl","n":[1,2'),
    ("bare-dsn-leaf", b'{"conn":"root:CANARY_T46_BARE@tcp(db:3306)/app","n":[1,2'),
], ids=["userinfo", "jwt-leaf", "bare-dsn-leaf"])
def test_an_unparseable_declared_json_body_takes_the_text_pass(label, body):
    """T46 (B3): a declared-JSON body that does not parse (the contract runner cuts at
    ``max_body_bytes``) takes the text pass in data grammar, as a failed ``json?``
    sniff does: credential shapes are redacted in place and the body is not omitted.
    Must fail against keeping an unparseable JSON body with no sensitive name."""
    from fuzzlab.core.redaction import redact_body
    out = redact_body(body, "application/json")
    assert _canaries(out) == [] and not out.startswith(b"__BODY_OMITTED__")
    assert out.endswith(b'"n":[1,2')


def test_the_runners_cut_json_evidence_keeps_no_credential_shape(tmp_path, monkeypatch):
    """T46 (B3): the runner's read cap cuts a declared-JSON answer after a DSN's
    userinfo; the evidence keeps no credential."""
    from tests.test_disco_contract import FakeResponse, contract_doc, runner
    monkeypatch.setenv("DISCO_TOKEN_A", "TOKENSECRET")
    answer = b'{"url":"postgres://app:CANARY_T46_CUT@db/x","items":[' + b'{"id":1},' * 200 + b"{}]}"
    doc = contract_doc()
    doc["run"]["limits"]["max_body_bytes"] = 120
    case = doc["test_cases"][0]
    case.update(setup=[])
    case["request"]["path_params"] = {"p1": "7"}
    r, _ = runner(doc, {("POST", "/api/orders/7/items"): FakeResponse(
        200, answer, {"Content-Type": "application/json"})}, evidence_dir=tmp_path)
    [res] = r.run()
    blob = b"".join(Path(p).read_bytes() for p in res["evidence"].values())
    assert _canaries(blob) == []


@pytest.mark.parametrize("label,ctype,body", [
    ("html-pre-bearer", "text/html",
     b"<html><pre>Authorization: Bearer CANARY_T47_PRE</pre></html>"),
    ("html-pre-basic", "text/html",
     b"<html><pre>Authorization: Basic CANARYT47basicQ0FOQVJZ==</pre></html>"),
    ("message-http-digest", "message/http",
     b'GET / HTTP/1.1\r\nAuthorization: Digest username="a", response="CANARY_T47_DIG"\r\n\r\n'),
    ("bare-bearer-in-attribute", "text/html", b'<input name="q" value="Bearer CANARY_T47_ATTR">'),
], ids=["html-pre-bearer", "html-pre-basic", "message-http-digest", "bare-bearer-in-attribute"])
def test_an_auth_scheme_takes_its_credential_with_it(label, ctype, body):
    """T47 (B4): after an auth-scheme word (``Bearer``, ``Basic``, ``Digest``, ``Token``,
    ...) bound to a sensitive name, the value includes the next token; a ``Bearer``
    credential is redacted wherever it occurs. Must fail against replacing the scheme
    word only."""
    from fuzzlab.core.redaction import redact_body
    out = redact_body(body, ctype)
    assert _canaries(out) == []
    if label.startswith("html-pre"):
        assert out.endswith(b"</pre></html>")


def test_page_text_keeps_no_credential_after_an_auth_scheme(tmp_path):
    """T47 (B4): the spider's page text (one-token grammar)."""
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "spider.db"))
    sm.mark_visited("http://127.0.0.1:8080/help", 200, 1, "Help",
                    "Debug Authorization: Bearer CANARY_T47_PAGE and Bearer CANARY_T47_BARE; "
                    "X-Auth-Token: Token CANARY_T47_TOKEN end")
    [content] = sm.conn.execute("SELECT content FROM discovered_pages").fetchone()
    assert _canaries(content.encode()) == [] and content.endswith("end")


# --- sibling sinks of the class that do not call the boundary (PA-0002) ------------------

def test_the_spiders_stored_page_text_keeps_no_textarea_secret(tmp_path):
    """T23. CC-CRAWL-0051: the static engine's page text (`_parse_html`, bs4 `get_text`)
    kept a ``<textarea>``'s content in ``discovered_pages.content``."""
    from fuzzlab.tools.spider import StorageManager, _parse_html
    sm = StorageManager(str(tmp_path / "spider.db"))
    title, text, _links = _parse_html(HTML.decode(), "http://127.0.0.1:8080/login")
    sm.mark_visited("http://127.0.0.1:8080/login", 200, 1, title, (text or "")[:8000])
    rows = sm.conn.execute("SELECT title, content FROM discovered_pages").fetchall()
    assert _canaries(repr([tuple(r) for r in rows]).encode()) == []
    assert "reset" in rows[0][1]                              # benign page text kept


def test_the_spider_stores_page_text_and_title_redacted_from_either_engine(tmp_path):
    """T38 (M7): ``mark_visited`` redacts the title and the text it is given, whichever
    engine produced them (the browser's ``page.title()`` and ``innerText`` included),
    in the one-token grammar (``get_text(" ")`` joins a page into one line). Must fail
    against redacting in `_parse_html` only."""
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "spider.db"))
    sm.mark_visited("http://127.0.0.1:8080/help", 200, 1, "Reset password=CANARY_T38_TITLE",
                    "Help Your password=CANARY_T38_PROSE token: CANARY_T38_WORD stays here")
    title, content = sm.conn.execute("SELECT title, content FROM discovered_pages").fetchone()
    assert _canaries(f"{title} {content}".encode()) == []
    assert content.startswith("Help Your") and content.endswith("stays here")


@pytest.mark.xfail(strict=True, reason=(
    "S2, PA-0054(3): the spider's page URLs (discovered_pages.url, found_from) keep a "
    "sensitive query value until AU-SPIDER redacts them; fixing it here would change what "
    "`fuzzlab audit` and the importer send"))
def test_the_spiders_page_urls_keep_no_token(tmp_path):
    """T39 (S2): pinned residual, offline."""
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "spider.db"))
    sm.mark_visited("http://127.0.0.1:8080/reset?token=CANARY_T39_URL&lang=en", 200, 1, "t",
                    "x", found_from="http://127.0.0.1:8080/mail?token=CANARY_T39_FROM")
    rows = sm.conn.execute("SELECT url, found_from FROM discovered_pages").fetchall()
    assert _canaries(repr([tuple(r) for r in rows]).encode()) == []


@pytest.mark.xfail(strict=True, reason=(
    "S2, PA-0054(3): discovered_forms.sig is built from the raw action URL until "
    "AU-SPIDER; CC-CRAWL-0051 covers page text and title only"))
def test_the_spiders_form_signature_keeps_no_url_token(tmp_path):
    """T24 (S2): pinned residual, offline. ``record_form`` stores redacted page and
    action URLs, but builds ``discovered_forms.sig`` from the raw action URL."""
    from bs4 import BeautifulSoup

    from fuzzlab.core.forms import form_record
    from fuzzlab.tools.spider import StorageManager
    sm = StorageManager(str(tmp_path / "spider.db"))
    for form in BeautifulSoup(HTML.decode(), "html.parser").find_all("form"):
        sm.record_form(form_record(form, "http://127.0.0.1:8080/login"))
    rows = sm.conn.execute("SELECT page_url, action_url, sig FROM discovered_forms")
    assert b"CANARY_ACTION_URL" not in repr([tuple(r) for r in rows.fetchall()]).encode()


def test_the_auditors_findings_keep_no_secret(tmp_path):
    """T25. CC-AUD-0057: ``findings.page_url`` / ``html_context`` kept a JWT's first 60
    characters, every input's HTML (hidden CSRF values, a password value, a textarea), a
    form's first 150 characters, the page URL's token and example parameter values. The
    target identifiers (paths and names: the dedup key) are kept as they are."""
    from fuzzlab.tools import fetcher as F
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUllKV1QifQ.c2lnQ0FOQVJZ"
    page = HTML.decode().replace(
        "</form>", f'<input type="hidden" name="jwt_blob" value="{jwt}"></form>')

    class Fetcher:
        def fetch(self, url):
            return 200, "text/html; charset=utf-8", page, []
    conn = F.setup_results_db(str(tmp_path / "audit.db"))
    url = "http://127.0.0.1:8080/login?token=CANARY_URL_TOKEN&page=CANARYpageAB12cd34&page=2"
    F.audit_page(url, "link", Fetcher(), [(n, "c", "r") for n in F.RULES], conn, set(),
                 verbose=False)
    stored = repr(conn.execute("SELECT page_url, target_identifier, html_context "
                               "FROM findings").fetchall())
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] > 0   # not vacuous
    assert _canaries(stored.encode()) == [] and "eyJzdWIiOiJDQU5BUllKV1Qi" not in stored
    targets = {r[0] for r in conn.execute("SELECT target_identifier FROM findings")}
    assert {"login?token", "login?page", "login", "login:csrfmiddlewaretoken",
            "login:jwt_blob"} <= targets


def test_the_auditors_dedup_key_and_the_importers_join_survive_redaction(tmp_path):
    """T40 (M8, control): a second audit of the same page bumps each finding's count
    (the dedup key ``target_identifier`` is unchanged), and `import_audit` joins every
    finding to the page's path endpoint. Must fail against blanking identifiers in
    ``page_url`` or ``target_identifier`` (only ``html_context`` gets that rule)."""
    from fuzzlab.tools import fetcher as F
    from fuzzlab.tools.store_adapter import import_audit

    class Fetcher:
        def fetch(self, url):
            return 200, "text/html; charset=utf-8", HTML.decode(), []
    db = tmp_path / "audit.db"
    conn = F.setup_results_db(str(db))
    url = "http://127.0.0.1:8080/orders/8f3a9c2e7b1d4a6f/view?token=CANARY_T40&page=2"
    for _ in range(2):
        F.audit_page(url, "link", Fetcher(), [(n, "c", "r") for n in F.RULES], conn, set(),
                     verbose=False)
    rows = conn.execute("SELECT target_identifier, occurrences FROM findings").fetchall()
    conn.close()
    assert rows and all(r[1] == 2 for r in rows)
    targets = {r[0] for r in rows}
    assert {"orders/8f3a9c2e7b1d4a6f/view?token", "orders/8f3a9c2e7b1d4a6f/view?page",
            "login:csrfmiddlewaretoken"} <= targets
    with Store(tmp_path / "s.db") as store:
        counts = import_audit(db, store, store.start_run("import", "x"))
        paths = {r[0] for r in store.conn.execute("SELECT url FROM endpoint")}
    assert counts["candidate"] == len(rows)
    assert paths == {"/orders/8f3a9c2e7b1d4a6f/view"}


def test_the_auditor_redacts_a_quoted_field_before_cutting_it(tmp_path):
    """T41 (M8, PA-0455(1)): a field's HTML is redacted before its 150-character cut, so
    a value straddling the cut is replaced and the context keeps the field. Must fail
    against cutting first (the cut value has no end and the whole context is lost)."""
    from fuzzlab.tools import fetcher as F
    page = ('<html><form action="/save" method="post"><input type="hidden" data-a="'
            + "a" * 60 + '" name="csrf" value="CANARY_T41_' + "x" * 80 + '"></form></html>')

    class Fetcher:
        def fetch(self, url):
            return 200, "text/html", page, []
    conn = F.setup_results_db(str(tmp_path / "audit.db"))
    F.audit_page("http://127.0.0.1:8080/save", "link", Fetcher(), [("Input Names", "c", "r")],
                 conn, set(), verbose=False)
    [context] = [r[0] for r in conn.execute("SELECT html_context FROM findings")]
    assert _canaries(context.encode()) == []
    assert 'name="csrf"' in context and "__REDACTED__" in context


def test_the_auditor_redacts_a_target_blank_href_before_its_cut(tmp_path):
    """T49 (ADOPT): ``Unsafe target blank`` uses the link's href, cut at 120 characters,
    as its ``target_identifier``: it is redacted first (query values, identifier-like
    values and a query-shaped fragment such as an implicit-flow ``#access_token=``)."""
    from fuzzlab.tools import fetcher as F
    href = ("https://idp.example/cb?lang=en&state=8f3a9c2e7b1d4a6f#access_token="
            "CANARY_T49_FRAGMENT&token_type=bearer&expires_in=3600")
    page = f'<html><a target="_blank" href="{href}">open</a></html>'

    class Fetcher:
        def fetch(self, url):
            return 200, "text/html", page, []
    conn = F.setup_results_db(str(tmp_path / "audit.db"))
    F.audit_page("http://127.0.0.1:8080/p", "link", Fetcher(), [(n, "c", "r") for n in F.RULES],
                 conn, set(), verbose=False)
    stored = repr(conn.execute("SELECT target_identifier, html_context FROM findings").fetchall())
    assert "idp.example/cb" in stored                          # not vacuous
    assert _canaries(stored.encode()) == [] and "8f3a9c2e7b1d4a6f" not in stored


def test_the_importer_stores_no_sensitive_parameter_example(tmp_path):
    """T26. CC-AUD-0057: a crawled link's ``token=`` value became ``parameter.example`` in
    the main store (`store_adapter._import_page_url`)."""
    from fuzzlab.tools.spider import StorageManager
    from fuzzlab.tools.store_adapter import import_spider
    db = tmp_path / "spider.db"
    StorageManager(str(db)).mark_visited(
        "http://127.0.0.1:8080/reset?token=CANARY_LINK_TOKEN&lang=en", 200, 1, "t", "x")
    with Store(tmp_path / "s.db") as store:
        import_spider(db, store, store.start_run("import", "x"),
                      base_url="http://127.0.0.1:8080/")
        rows = store.conn.execute("SELECT name, example FROM parameter").fetchall()
    assert _canaries(repr([tuple(r) for r in rows]).encode()) == []
    assert ("lang", "en") in [tuple(r) for r in rows]                   # benign kept


# --- controls: what must not change --------------------------------------------------------

@pytest.mark.parametrize("label,body,ctype,benign", CASES, ids=IDS)
def test_the_spider_never_records_a_text_request_body(label, body, ctype, benign):
    """C1. FR-CRAWL-13: the crawler's captured requests are JSON or form only; a text body
    is refused before anything is stored (unchanged by BUG-0527)."""
    from fuzzlab.core.redaction import redact_captured_body
    assert redact_captured_body(body, ctype) == (None, "not a JSON or form-encoded body")


def test_a_clean_text_body_stays_byte_identical():
    """C2. Must fail against a re-encoding splice or a false binding."""
    from fuzzlab.core.redaction import redact_body
    for body, ctype in [((b"<html><body><p>Hello, author!</p><a href='/x?q=1'>x</a>"
                          b"</body></html>"), "text/html"),
                        (b"<items><item id='1'>pup</item></items>", "application/xml"),
                        (b'fetch("/api/Products"); const author = "bob";',
                         "application/javascript"),
                        (b"hello world\nline two\n", "text/plain")]:
        assert redact_body(body, ctype) == body, ctype


@pytest.mark.parametrize("name", ["django_404.html", "django_500.html",
                                  "django_debug_404.html", "flask_404.html", "flask_500.html"])
def test_a_real_error_page_stays_byte_identical(name):
    """C2 (ADOPT): real error pages, rendered in-process (Django 4/5xx in production and
    debug mode, Flask's), have nothing bound to a sensitive name and are kept
    byte-identical. Must fail against a false binding in prose."""
    from fuzzlab.core.redaction import redact_body
    page = (DATA / name).read_bytes()
    assert redact_body(page, "text/html; charset=utf-8") == page


def test_what_the_consumers_read_from_a_text_body_survives():
    """C3. The disco synthesizer mines a script's API calls (`synth._JS_CALL`) and the
    harvest's extractor reads an HTML document's links (`linkextract.html_urls`): both
    read the same from the redacted body, except for a redacted query value."""
    from fuzzlab.core.linkextract import html_urls
    from fuzzlab.core.redaction import redact_body
    from fuzzlab.disco.synth import _JS_CALL
    calls = [m.group(3) for m in _JS_CALL.finditer(redact_body(JS, "application/javascript")
                                                   .decode())]
    assert calls == ["/api/Users/whoami"]
    base = "http://127.0.0.1:8080/login"
    before = {u.split("?", 1)[0] for u in html_urls(HTML.decode(), base)}
    after = {u.split("?", 1)[0] for u in html_urls(redact_body(HTML, "text/html")
                                                  .decode("utf-8", "replace"), base)}
    assert after == before
