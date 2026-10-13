"""Every persisted copy of proxied traffic is free of secrets (BUG-0084, FR-PROXY-11,
PA-0085).

`redact.py` promised "common token query parameters" but redacted only headers:
`flow.url`, the stored raw request and response, and the full-text index all kept URL
tokens, body passwords and redirect tokens.
"""

from __future__ import annotations

import gzip
import json

import pytest

from fuzzlab.core.obs import _redact as obs_redact
from fuzzlab.core.redaction import is_sensitive_name
from fuzzlab.core.store import Store
from fuzzlab.proxy.history import FlowRecord, HistoryWriter
from fuzzlab.proxy.redact import REDACTED, redact

SECRETS = [b"eyJSECRETTOKEN", b"hunter2", b"SESSIONSECRET", b"nested-pw", b"mp-secret",
           b"resp-access", b"apikey-123"]


def _persisted(store) -> bytes:
    """Every place a flow is persisted: its row, the body table, the FTS index."""
    blobs = []
    for table in ("flow", "body", "flow_fts"):
        for row in store.conn.execute(f"SELECT * FROM {table}").fetchall():
            for v in tuple(row):
                blobs.append(v if isinstance(v, bytes) else str(v).encode())
    return b"\n".join(blobs)


def test_no_secret_reaches_any_persisted_copy(tmp_path):
    req = (b"POST /login?access_token=eyJSECRETTOKEN&q=puppies HTTP/1.1\r\n"
           b"Host: 127.0.0.1:8080\r\nAuthorization: Bearer abc\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 31\r\n\r\n"
           b"username=alice&password=hunter2")
    resp = (b"HTTP/1.1 302 Found\r\nLocation: /home?session=SESSIONSECRET&tab=1\r\n"
            b"Content-Type: application/json\r\nContent-Length: 47\r\n\r\n"
            b'{"user":{"pw":"nested-pw"},"author":"bob","n":1}')
    with Store(tmp_path / "h.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=1)
        h.record(FlowRecord("POST", "http://127.0.0.1:8080/login?access_token=eyJSECRETTOKEN"
                            "&q=puppies", "127.0.0.1:8080", 302, raw_request=req,
                            raw_response=resp, req_body=b"username=alice&password=hunter2",
                            resp_body=b'{"access_token":"resp-access"}'))
        blob = _persisted(store)
        assert not any(s in blob for s in SECRETS)
        assert h.search("hunter2") == [] and h.search("eyJSECRETTOKEN") == []
        # benign content stays readable
        assert b"q=puppies" in blob and b"username=alice" in blob and b'"author":"bob"' in blob
        assert b"tab=1" in blob


def test_benign_messages_are_byte_identical():
    raw = (b"POST /search?q=1&author=x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json"
           b"\r\nContent-Length: 18\r\n\r\n{\"author\":  \"bob\"}")
    assert redact(raw) == raw


def test_content_length_follows_a_redacted_body():
    raw = (b"POST /l HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded"
           b"\r\nContent-Length: 10\r\n\r\npassword=x")
    out = redact(raw)
    body = out.split(b"\r\n\r\n", 1)[1]
    assert body == b"password=" + REDACTED and f"Content-Length: {len(body)}".encode() in out


def test_multipart_fields_are_redacted_but_files_are_not():
    body = (b'--XX\r\nContent-Disposition: form-data; name="user"\r\n\r\nalice\r\n'
            b'--XX\r\nContent-Disposition: form-data; name="password"\r\n\r\nmp-secret\r\n'
            b'--XX\r\nContent-Disposition: form-data; name="token"; filename="t.txt"\r\n\r\n'
            b'file-bytes\r\n--XX--\r\n')
    raw = (b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=XX"
           b"\r\n\r\n" + body)
    out = redact(raw)
    assert b"mp-secret" not in out and b"alice" in out and b"file-bytes" in out


def test_chunked_and_compressed_bodies_are_stored_as_received():
    """A stated residual: the proxy never rewrites framing it does not control."""
    gz = gzip.compress(b"password=hunter2")
    raw = (b"POST /l HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded"
           b"\r\nContent-Encoding: gzip\r\n\r\n" + gz)
    assert redact(raw).endswith(gz)
    chunked = (b"POST /l HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-"
               b"urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n10\r\npassword=hunter2\r\n0"
               b"\r\n\r\n")
    assert redact(chunked) == chunked


@pytest.mark.parametrize("name", ["password", "user_password", "accessToken", "api_key",
                                  "APIKey", "X-Auth-Token", "PHPSESSID", "JSESSIONID",
                                  "csrf_token", "key", "code", "client_secret", "sid"])
def test_sensitive_names(name):
    assert is_sensitive_name(name)


@pytest.mark.parametrize("name", ["author", "authority", "sidebar", "inside", "tokenizer",
                                  "keyword", "monkey", "barcode", "zipcode", "passage",
                                  "consider", "decode", "promo_code", "hotkey", "q", "id"])
def test_benign_names(name):
    assert not is_sensitive_name(name)


def test_logs_use_the_same_predicate():
    """A behaviour change, listed: by token now, so `author` is no longer redacted and
    `api_key` / `key` are."""
    out = obs_redact({"author": "bob", "api_key": "k", "key": "k2", "password": "p",
                      "nested": {"session_id": "s"}})
    assert out == {"author": "bob", "api_key": "***", "key": "***", "password": "***",
                   "nested": {"session_id": "***"}}
    assert json.dumps(out)


def test_the_redaction_opt_out_keeps_raw_bytes(tmp_path):
    """`redact_secrets=False` (the lab-local opt-out for replaying JWT/session flows)
    persists the bytes as captured — the on/off switch has an observable effect
    (PA-0089)."""
    req = b"GET /a?token=keepme HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\n\r\n"
    with Store(tmp_path / "raw.db") as store:
        h = HistoryWriter(store, store.start_run("proxy", "x"), batch_size=1,
                          redact_secrets=False)
        h.record(FlowRecord("GET", "http://h/a?token=keepme", "h", 200, raw_request=req,
                            raw_response=b"HTTP/1.1 200 OK\r\n\r\n"))
        fid = store.conn.execute("SELECT id, url FROM flow").fetchone()
        assert fid["url"].endswith("token=keepme") and h.raw_request(fid["id"]) == req
