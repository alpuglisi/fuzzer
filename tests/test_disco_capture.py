"""The capture layer (D70, FR-CRAWL-18): ``capture.jsonl``'s one producer and one
reader, and the recorder addon that is the proxy's scope firewall.

The recorder is driven here with fake mitmproxy flows (the real proxy runs in
``tests/test_disco_e2e.py``)."""

from __future__ import annotations

import asyncio
import json
import queue
import threading
import types

import pytest

from fuzzlab.core.redaction import PLACEHOLDER
from fuzzlab.disco import capture, mitm, recorder
from tests._browser import skip_or_fail
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
            raw_content=body, get_content=lambda strict=False: body)
        self.response = types.SimpleNamespace(
            status_code=status, headers=_Headers({"Content-Type": "application/json"}),
            timestamp_end=100.05, raw_content=res_body,
            get_content=lambda strict=False: res_body)

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


def _respond(rec, flow):
    """The request and response hooks, as mitmproxy calls them; the response hook's
    return (None, or an awaitable mitmproxy would await)."""
    rec.request(flow)
    killed = getattr(flow, "killed", None)          # a real flow: killed is an error
    if not (killed if killed is not None else flow.error is not None):
        return rec.response(flow)
    return None


def _drive(rec, flow):
    wait = _respond(rec, flow)
    if wait is not None:
        _await_all([wait])


def _await_all(waits):
    async def _all():
        await asyncio.gather(*[w for w in waits if w is not None])
    asyncio.run(_all())


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


def test_a_full_queue_holds_the_flow_back_then_drops_and_counts_never_blocking(
        tmp_path, monkeypatch):
    """BUG-0548: a full queue no longer drops at once. The hook returns an awaitable
    (mitmproxy awaits it: that flow waits, the loop runs on); one still without room
    after `BACKPRESSURE_WAIT_S` is dropped and counted."""
    monkeypatch.setattr(recorder, "BACKPRESSURE_WAIT_S", 0.05)
    rec = _recorder(tmp_path)
    monkeypatch.setattr(rec, "start", lambda: None)            # no writer: the queue fills
    rec._queue = queue.Queue(maxsize=2)
    waits = [_respond(rec, _Flow("http://127.0.0.1:8080/api")) for _ in range(5)]
    assert waits[:2] == [None, None] and all(asyncio.iscoroutine(w) for w in waits[2:])
    assert rec.dropped == 0 and rec.waited == 3
    _await_all(waits[2:])
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


# --- off the proxy's loop: the hook takes, the writer works (BUG-0548, audit defect 22) ----

def _mitm():
    try:
        from mitmproxy import http
        from mitmproxy.test import tflow
    except ImportError as exc:                     # pragma: no cover - installed with disco
        skip_or_fail(f"mitmproxy unavailable: {exc}")
    return http, tflow


def _real_flow(url="http://127.0.0.1:8080/api/x", *, method="POST", req_body=b"",
               req_headers=None, res_body=b"", res_headers=None):
    """A real mitmproxy flow: ``raw_content`` is the body as sent (``Response.make``
    encodes it per its ``Content-Encoding``)."""
    http, tflow = _mitm()
    return tflow.tflow(req=http.Request.make(method, url, req_body, req_headers or {}),
                       resp=http.Response.make(200, res_body, res_headers or {}))


def _stats(tmp_path) -> dict:
    return json.loads((tmp_path / "s.json").read_text())


def test_the_proxy_hook_takes_the_exchange_and_the_writer_does_all_the_work(
        tmp_path, monkeypatch):
    """The hooks run on the loop that carries every browser request. A hook only takes
    the exchange (the bodies as sent); decoding, redaction and serialisation all run on
    the writer thread, and the record is what it was."""
    hook = threading.current_thread()
    where: list[tuple[str, threading.Thread]] = []
    real_redact, real_json = capture.redact_body, capture.CaptureRecord.to_json

    def redact(body, ctype):
        where.append(("redact", threading.current_thread()))
        return real_redact(body, ctype)

    def to_json(self):
        where.append(("json", threading.current_thread()))
        return real_json(self)

    monkeypatch.setattr(capture, "redact_body", redact)
    monkeypatch.setattr(capture.CaptureRecord, "to_json", to_json)
    doc = json.dumps({"user": "alice", "password": "HOOKSECRET", "pad": "p" * 50_000})
    flow = _real_flow(req_body=doc.encode(), req_headers={"Content-Type": "application/json"},
                      res_body=doc.encode(), res_headers={"Content-Type": "application/json",
                                                          "Content-Encoding": "gzip"})
    assert flow.response.raw_content[:2] == b"\x1f\x8b"         # gzip as sent
    rec = _recorder(tmp_path)
    _drive(rec, flow)
    rec.stop()
    assert {what for what, _t in where} == {"redact", "json"}
    assert [what for what, t in where if t is hook] == []
    [got] = read_capture(tmp_path / "c.jsonl").records
    assert "HOOKSECRET" not in (tmp_path / "c.jsonl").read_text()
    assert json.loads(got.res_body)["user"] == "alice" and not got.res_truncated
    assert json.loads(got.req_body)["password"] == PLACEHOLDER
    assert _stats(tmp_path)["recorded"] == 1


def _sized_flows(n, size=100_000):
    return [_real_flow(f"http://127.0.0.1:8080/api/{i}", method="GET",
                       res_body=json.dumps({"n": i, "pad": "x" * size}).encode(),
                       res_headers={"Content-Type": "application/json"}) for i in range(n)]


def test_past_its_byte_budget_the_queue_holds_the_browser_back_and_loses_nothing(
        tmp_path, monkeypatch):
    """The queue holds at most `QUEUE_MAX_BYTES`, not only `QUEUE_MAX` records. Past
    it, an exchange waits -- its hook returns an awaitable, the loop never waits -- and
    so does every exchange after it, even one that would fit, so records keep their
    order. Once the writer makes room, every one is recorded whole."""
    monkeypatch.setattr(recorder, "QUEUE_MAX_BYTES", 250_000)
    rec = _recorder(tmp_path)
    rec.start = lambda: None                       # no writer yet: the queue fills
    waits = [_respond(rec, flow) for flow in _sized_flows(4)]
    small = _real_flow("http://127.0.0.1:8080/api/small", method="GET")
    waits.append(_respond(rec, small))             # fits, but must not overtake
    assert waits[:2] == [None, None] and all(asyncio.iscoroutine(w) for w in waits[2:])
    assert rec.queued_bytes <= recorder.QUEUE_MAX_BYTES and rec.waited == 3
    del rec.start
    rec.start()
    _await_all(waits)
    rec.stop()
    recs = read_capture(tmp_path / "c.jsonl").records
    assert [r.url.rsplit("/", 1)[1] for r in recs] == ["0", "1", "2", "3", "small"]
    assert all(r.res_body is not None and not r.res_truncated for r in recs[:4])
    stats = _stats(tmp_path)
    assert (stats["omitted"]["backlog"], stats["dropped"], stats["recorded"],
            stats["waited"], stats["queued"]) == (0, 0, 5, 3, 0)
    assert rec.queued_bytes == 0


def test_an_exchange_still_without_room_after_its_wait_keeps_its_record_not_its_body(
        tmp_path, monkeypatch):
    """Backpressure is bounded (`BACKPRESSURE_WAIT_S`): a writer that cannot keep up
    loses bodies, counted, never records or order."""
    monkeypatch.setattr(recorder, "QUEUE_MAX_BYTES", 250_000)
    monkeypatch.setattr(recorder, "BACKPRESSURE_WAIT_S", 0.05)
    rec = _recorder(tmp_path)
    rec.start = lambda: None
    _await_all([_respond(rec, flow) for flow in _sized_flows(5)])
    assert rec.omitted["backlog"] == 3 and rec.dropped == 0
    del rec.start
    rec.start()
    rec.stop()
    recs = read_capture(tmp_path / "c.jsonl").records
    assert [r.url.rsplit("/", 1)[1] for r in recs] == ["0", "1", "2", "3", "4"]
    assert [r.res_body is not None for r in recs] == [True, True, False, False, False]
    assert all(r.res_truncated for r in recs[2:]) and not recs[0].res_truncated
    stats = _stats(tmp_path)
    assert (stats["omitted"]["backlog"], stats["dropped"], stats["recorded"]) == (3, 0, 5)


def test_the_line_moves_without_its_waiters_and_is_written_at_shutdown(tmp_path,
                                                                       monkeypatch):
    """The line is data: a waiter mitmproxy never resumes holds no one back, and what
    still waits at shutdown is complete (only the browser was held back), so it is
    written, in order."""
    monkeypatch.setattr(recorder, "QUEUE_MAX_BYTES", 250_000)
    rec = _recorder(tmp_path)
    rec.start = lambda: None
    waits = [_respond(rec, flow) for flow in _sized_flows(5)]  # 2 queued, 3 in line
    del rec.start
    rec.start()
    _await_all([waits[3]])                         # the head's awaitable never runs
    rec.stop()
    for w in waits[2:]:
        w.close()
    recs = read_capture(tmp_path / "c.jsonl").records
    assert [r.url.rsplit("/", 1)[1] for r in recs] == ["0", "1", "2", "3", "4"]
    assert all(r.res_body is not None for r in recs)
    stats = _stats(tmp_path)
    assert (stats["recorded"], stats["dropped"], stats["queued"]) == (5, 0, 0)


def test_a_waiting_exchange_whose_flow_is_cancelled_is_counted_and_holds_no_one_back(
        tmp_path, monkeypatch):
    """mitmproxy cancels a waiting flow (its client went away, or shutdown): that
    exchange is counted ``dropped``, and the exchanges behind it are still queued."""
    monkeypatch.setattr(recorder, "QUEUE_MAX_BYTES", 250_000)
    rec = _recorder(tmp_path)
    rec.start = lambda: None
    waits = [_respond(rec, flow) for flow in _sized_flows(4)]

    async def _cancel_the_first_waiter():
        first, second = (asyncio.ensure_future(w) for w in waits[2:])
        await asyncio.sleep(0.02)
        first.cancel()
        del rec.start
        rec.start()                                # the writer makes room
        await second
        with pytest.raises(asyncio.CancelledError):
            await first

    asyncio.run(_cancel_the_first_waiter())
    rec.stop()
    assert [r.url.rsplit("/", 1)[1] for r in read_capture(tmp_path / "c.jsonl").records] \
        == ["0", "1", "3"]
    assert (_stats(tmp_path)["dropped"], _stats(tmp_path)["recorded"]) == (1, 3)


def test_a_body_too_large_or_undecodable_is_never_held_whole_and_its_record_says_so(
        tmp_path, monkeypatch):
    """A body over the capture ceiling as sent is never held past the hook; a small one
    that decodes past it (a gzip bomb), or in a coding with no bounded decoder, is cut
    by SP-60's reader on the writer. Each is recorded with no body, marked truncated
    and counted; redaction never sees a part of a body (PA-0455)."""
    monkeypatch.setattr(capture, "MAX_CAPTURE_BODY_BYTES", 64 * 1024)
    json_ct = {"Content-Type": "application/json"}
    big = json.dumps({"password": "BIGSECRET", "pad": "x" * 70_000}).encode()
    bomb = json.dumps({"password": "BOMBSECRET", "pad": "0" * 2_000_000}).encode()
    taken = capture.snapshot(kind="http", t=1.0, action_id=None, method="GET",
                             url="http://h/", req_headers={}, req_body=None,
                             res_headers=json_ct, res_body=big)
    assert (taken.res_body, taken.res_omitted) == (None, "too_large") and taken.size < 1000
    flows = {
        "big": _real_flow("http://127.0.0.1:8080/big", method="GET", res_body=big,
                          res_headers=json_ct),
        "bomb": _real_flow("http://127.0.0.1:8080/bomb", method="GET", res_body=bomb,
                           res_headers={**json_ct, "Content-Encoding": "gzip"}),
        "zstd": _real_flow("http://127.0.0.1:8080/zstd", method="GET",
                           res_headers={**json_ct, "Content-Encoding": "zstd"}),
        "fine": _real_flow("http://127.0.0.1:8080/fine", method="GET", res_body=b'{"ok": 1}',
                           res_headers=json_ct)}
    flows["zstd"].response.raw_content = b"(\xb5/\xfd" + b"ZSTDSECRET"
    assert len(flows["bomb"].response.raw_content) < capture.MAX_CAPTURE_BODY_BYTES
    rec = _recorder(tmp_path)
    for flow in flows.values():
        _drive(rec, flow)
    rec.stop()
    recs = {r.url.rsplit("/", 1)[1]: r for r in read_capture(tmp_path / "c.jsonl").records}
    for name in ("big", "bomb", "zstd"):
        assert recs[name].res_body is None and recs[name].res_truncated, name
    assert recs["fine"].res_body == '{"ok": 1}' and not recs["fine"].res_truncated
    assert "SECRET" not in (tmp_path / "c.jsonl").read_text()
    assert _stats(tmp_path)["omitted"] == {"too_large": 1, "backlog": 0, "undecodable": 2}


def test_a_stats_refresh_is_never_counted_as_a_lost_record(tmp_path, monkeypatch):
    """A refusal asks the writer to rewrite the stats. With the queue full that request
    waits; it is not a record, so it is never counted ``dropped``."""
    monkeypatch.setattr(recorder, "BACKPRESSURE_WAIT_S", 0.05, raising=False)
    rec = _recorder(tmp_path)
    rec.start = lambda: None
    rec._queue = queue.Queue(maxsize=1)
    _drive(rec, _Flow("http://127.0.0.1:8080/a"))             # fills the queue
    refused = _Flow("http://example.com/x")
    _drive(rec, refused)
    assert refused.killed and rec.dropped == 0
    _drive(rec, _Flow("http://127.0.0.1:8080/b"))             # a record lost: counted
    assert rec.dropped == 1
    del rec.start
    rec.start()
    rec.stop()
    stats = _stats(tmp_path)
    assert (stats["blocked"], stats["dropped"], stats["recorded"]) == ({"example.com": 1}, 1, 1)


def test_a_record_that_cannot_be_built_is_counted_and_the_writer_goes_on(tmp_path,
                                                                         monkeypatch):
    """PA-0086(2): the work moved to the writer thread, so one exchange's failure there
    is contained, logged and counted; the next exchange is still written."""
    real = capture._body_text

    def body_text(body, ctype, *rest):
        if body and b"POISON" in body:
            raise RuntimeError("cannot build")
        return real(body, ctype, *rest)

    monkeypatch.setattr(capture, "_body_text", body_text)
    rec = _recorder(tmp_path)
    _drive(rec, _Flow("http://127.0.0.1:8080/a", res_body=b'{"x": "POISON"}'))
    _drive(rec, _Flow("http://127.0.0.1:8080/b"))
    rec.stop()
    assert [r.url for r in read_capture(tmp_path / "c.jsonl").records] == [
        "http://127.0.0.1:8080/b"]
    assert (_stats(tmp_path)["dropped"], _stats(tmp_path)["recorded"]) == (1, 1)


def test_the_proxy_process_hands_the_gil_to_its_loop_within_the_switch_interval(
        tmp_path, monkeypatch):
    """The writer's work holds the GIL; at CPython's 5 ms default the loop waits that
    long at each wake-up (measured: loop lag median 6.1 ms with the work on a thread,
    2.2 ms at 1 ms). mitmdump's process sets the shorter interval when it runs."""
    import sys
    calls = []
    monkeypatch.setattr(sys, "setswitchinterval", calls.append)
    rec = _recorder(tmp_path)
    rec.running()
    rec.stop()
    assert calls == [recorder.SWITCH_INTERVAL_S] and recorder.SWITCH_INTERVAL_S <= 0.001


def test_a_proxy_stop_outlasts_the_recorders_drain(tmp_path, monkeypatch):
    """PA-0138(3): the writer may be behind at the stop, so the consumer that waits for
    the proxy (procutil's grace before its kill) waits longer than the recorder drains;
    otherwise the backlog and the final stats would be lost to the kill, uncounted."""
    from fuzzlab import procutil
    from fuzzlab.disco import proxyproc
    seen = {}

    def start(argv_for, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("not started")

    monkeypatch.setattr(procutil, "start_server_on_free_port", start)
    with pytest.raises(RuntimeError):
        proxyproc.CaptureProxy(["http://127.0.0.1:1/"], out=tmp_path / "c.jsonl").start()
    assert seen["grace"] == proxyproc.STOP_GRACE_S >= recorder.DRAIN_TIMEOUT_S + 10


def test_the_target_is_asked_only_for_codings_the_writer_decodes_bounded(tmp_path):
    """The writer decodes through SP-60, which has no bounded ``zstd`` decoder; asking
    for it would lose those bodies, so the proxy narrows ``Accept-Encoding``
    (`bodyread.advertise`, PA-0536(1))."""
    rec = _recorder(tmp_path)
    flow = _real_flow(method="GET", req_headers={"Accept-Encoding": "gzip, deflate, br, zstd"})
    rec.request(flow)
    sent = {t.strip() for t in flow.request.headers["accept-encoding"].split(",")}
    assert "zstd" not in sent and {"gzip", "deflate"} <= sent
    rec.stop()
