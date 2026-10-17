"""The capture layer (D70, FR-CRAWL-18): ``capture.jsonl``'s one producer and one
reader, and the recorder addon that is the proxy's scope firewall.

The recorder is driven here with fake mitmproxy flows (the real proxy runs in
``tests/test_disco_e2e.py``)."""

from __future__ import annotations

import json
import types

import pytest

from fuzzlab.core.redaction import PLACEHOLDER
from fuzzlab.disco import capture, mitm, recorder
from fuzzlab.disco.capture import (ACTION_HEADER, MAX_BODY_CHARS, append_record, make_record,
                                   read_capture)

SECRETS = ("COOKIESECRET", "BEARERSECRET", "SETCOOKIESECRET", "BODYPASSWORD", "QUERYTOKEN",
           "LISTSECRET", "CSRFSECRET")


def _secret_record():
    return make_record(
        kind="http", t=1.0, action_id="act-1", method="post",
        url="http://127.0.0.1:8080/api/login?token=QUERYTOKEN&q=pup",
        req_headers={"Cookie": "sid=COOKIESECRET", "Authorization": "Bearer BEARERSECRET",
                     "X-CSRF-Token": "CSRFSECRET", "Content-Type": "application/json",
                     ACTION_HEADER: "act-1", "Accept": "*/*"},
        req_body=json.dumps({"user": "alice", "password": "BODYPASSWORD",
                             "tokens": ["LISTSECRET"]}).encode(),
        status=200, res_headers={"Set-Cookie": "sid=SETCOOKIESECRET; HttpOnly",
                                 "Content-Type": "application/json"},
        res_body=b'{"id": "9f8e7d6c-5b4a-4928-8170-6f5e4d3c2b1a", "name": "alice"}',
        latency_ms=12, profile="user_a")


# --- redaction at the write (PA-0100, PA-0085) -------------------------------------------

def test_no_secret_reaches_the_capture_file_and_benign_content_stays(tmp_path):
    out = tmp_path / "capture.jsonl"
    append_record(out, _secret_record())
    text = out.read_text()
    for secret in SECRETS:
        assert secret not in text, secret
    rec = read_capture(out).records[0]
    assert rec.req_headers["cookie"] == rec.req_headers["authorization"] == PLACEHOLDER
    assert rec.res_headers["set-cookie"] == PLACEHOLDER
    assert "alice" in rec.req_body and "q=pup" in rec.url              # benign kept
    assert "9f8e7d6c-5b4a-4928-8170-6f5e4d3c2b1a" in rec.res_body      # identifiers kept
    assert rec.req_headers["accept"] == "*/*"


def test_the_action_tag_is_the_record_s_action_id_never_a_header():
    rec = _secret_record()
    assert rec.action_id == "act-1" and ACTION_HEADER not in rec.req_headers
    assert rec.profile == "user_a" and rec.method == "POST"


def test_a_secret_straddling_the_body_cut_is_still_removed():
    """PA-0455(2): redaction runs on the whole body before it is cut."""
    pad = "x" * (MAX_BODY_CHARS - 20)
    body = json.dumps({"note": pad, "password": "STRADDLESECRET" * 4}).encode()
    rec = make_record(kind="http", t=1.0, action_id=None, method="POST", url="http://h/",
                      req_headers={"Content-Type": "application/json"}, req_body=body)
    assert rec.req_truncated and len(rec.req_body) == MAX_BODY_CHARS
    assert "STRADDLE" not in rec.req_body


def test_an_unparseable_json_body_with_a_secret_is_omitted():
    """PA-0101: the redactor fails closed."""
    rec = make_record(kind="http", t=1.0, action_id=None, method="POST", url="http://h/",
                      req_headers={"Content-Type": "application/json"},
                      req_body=b'{"password": "BROKENSECRET", ')
    assert "BROKENSECRET" not in (rec.req_body or "")


def test_only_make_record_output_is_appended(tmp_path):
    with pytest.raises(TypeError):
        append_record(tmp_path / "c.jsonl", {"url": "http://h/"})
    with pytest.raises(ValueError):
        make_record(kind="smtp", t=1.0, action_id=None, method="X", url="u",
                    req_headers={}, req_body=None)


# --- the one reader (PA-0108, PA-0454) -----------------------------------------------------

def test_malformed_lines_are_quarantined_never_repaired(tmp_path):
    good = _secret_record().to_json()
    deep = "[" * 100_000 + "]" * 100_000
    lines = [good, "not json", deep, json.dumps({**json.loads(good), "status": "200"}),
             json.dumps({**json.loads(good), "v": 99}),
             json.dumps({**json.loads(good), "req_headers": {"a": 1}}),
             json.dumps({**json.loads(good), "t": True}), "", good]
    p = tmp_path / "c.jsonl"
    p.write_text("\n".join(lines) + "\n")
    read = read_capture(p)
    assert len(read.records) == 2 and read.quarantined == 6


def test_an_oversized_line_is_quarantined(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "MAX_LINE_BYTES", 100)
    p = tmp_path / "c.jsonl"
    p.write_text(_secret_record().to_json() + "\n")
    assert read_capture(p).quarantined == 1


def test_no_capture_is_not_an_empty_capture(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_capture(tmp_path / "missing.jsonl")


# --- the recorder: the proxy's scope firewall -----------------------------------------------

class _Headers(dict):
    """mitmproxy's Headers enough for the addon: get / del / items."""


class _Flow:
    def __init__(self, url, *, method="GET", headers=None, body=b"", status=200,
                 res_body=b'{"ok":1}', host=None, port=None):
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        self.killed = False
        self.metadata = {}
        self.error = None
        self.request = types.SimpleNamespace(
            url=url, method=method, host=host or parts.hostname,
            port=port or parts.port or (443 if parts.scheme == "https" else 80),
            headers=_Headers(headers or {}), timestamp_start=100.0,
            get_content=lambda strict=False: body)
        self.response = types.SimpleNamespace(
            status_code=status, headers=_Headers({"Content-Type": "application/json"}),
            timestamp_end=100.05, get_content=lambda strict=False: res_body)

    def kill(self):
        self.killed = True


def _recorder(tmp_path, scope="http://127.0.0.1:8080/", keep_tag=False):
    rec = recorder.Recorder()
    rec.origins = recorder.parse_scope(scope)
    rec.out = str(tmp_path / "c.jsonl")
    rec.stats_path = str(tmp_path / "s.json")
    rec.keep_tag = keep_tag
    rec.profile = "anon"
    return rec


def _drive(rec, flow):
    rec.request(flow)
    if not flow.killed:
        rec.response(flow)


def test_an_out_of_scope_request_is_killed_counted_and_never_recorded(tmp_path):
    rec = _recorder(tmp_path)
    for url in ("http://127.0.0.1:8081/x", "https://127.0.0.1:8080/x",
                "http://example.com/x", "http://127.0.0.2:8080/x"):
        flow = _Flow(url)
        _drive(rec, flow)
        assert flow.killed, url
    inside = _Flow("http://localhost:8080/api/a")           # a loopback alias, same origin
    _drive(rec, inside)
    rec.stop()
    assert not inside.killed
    assert rec.blocked == {"127.0.0.1": 2, "example.com": 1, "127.0.0.2": 1}
    recs = read_capture(tmp_path / "c.jsonl").records
    assert [r.url for r in recs] == ["http://localhost:8080/api/a"]
    assert json.loads((tmp_path / "s.json").read_text())["blocked"]["example.com"] == 1


def test_an_empty_scope_refuses_everything(tmp_path):
    rec = _recorder(tmp_path, scope="")
    flow = _Flow("http://127.0.0.1:8080/")
    _drive(rec, flow)
    assert flow.killed


def test_a_tunnel_is_opened_for_an_in_scope_host_port_under_either_scheme(tmp_path):
    """Measured: the Playwright driver CONNECT-tunnels a plain-http lab origin. A tunnel
    names no scheme, so it is opened when host:port is in scope under either; every
    request inside is then checked on its real origin."""
    rec = _recorder(tmp_path)
    tunnel = _Flow("http://127.0.0.1:8080/", host="127.0.0.1", port=8080)
    rec.http_connect(tunnel)
    assert not tunnel.killed
    other = _Flow("http://127.0.0.1:9999/", host="127.0.0.1", port=9999)
    rec.http_connect(other)
    assert other.killed
    inner = _Flow("https://127.0.0.1:8080/api")              # the wrong scheme inside
    _drive(rec, inner)
    assert inner.killed


def test_the_tag_is_read_and_stripped_unless_kept(tmp_path):
    rec = _recorder(tmp_path)
    flow = _Flow("http://127.0.0.1:8080/api", headers={ACTION_HEADER: "act-7"})
    _drive(rec, flow)
    assert ACTION_HEADER not in flow.request.headers          # the target never sees it
    kept = _recorder(tmp_path / "k", keep_tag=True)
    (tmp_path / "k").mkdir()
    flow2 = _Flow("http://127.0.0.1:8080/api", headers={ACTION_HEADER: "act-8"})
    _drive(kept, flow2)
    assert flow2.request.headers[ACTION_HEADER] == "act-8"
    rec.stop()
    kept.stop()
    assert read_capture(tmp_path / "c.jsonl").records[0].action_id == "act-7"


def test_a_full_queue_drops_and_counts_never_blocks(tmp_path, monkeypatch):
    rec = _recorder(tmp_path)
    monkeypatch.setattr(rec, "start", lambda: None)            # no writer: the queue fills
    rec._queue = __import__("queue").Queue(maxsize=2)
    for _ in range(5):
        _drive(rec, _Flow("http://127.0.0.1:8080/api"))
    assert rec.dropped == 3


def test_mitmdump_runs_loopback_lazy_and_with_the_recorder():
    ns = mitm.build_parser().parse_args(["--port", "5", "--scope", "http://127.0.0.1:1/",
                                         "--out", "o", "--stats", "s", "--confdir", "c"])
    args = mitm.mitmdump_args(ns)
    assert args[:4] == ["--listen-host", "127.0.0.1", "--listen-port", "5"]
    assert "connection_strategy=lazy" in args
    assert args[args.index("-s") + 1].endswith("disco/recorder.py")
    ns.listen_host = "0.0.0.0"
    with pytest.raises(ValueError):
        mitm.mitmdump_args(ns)
