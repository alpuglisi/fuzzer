"""Each HTTP try is its own evidence (FR-FUZZ-61), and a PRG follow-up is recorded
whether or not it was an observation (BUG-0510).

`RequestsProbeSender` re-sends an idempotent probe once after a connection reset
(BUG-0147). The trace counted that re-send on the exchange (``resent``) but drew one
request. Now each sender records every try where it happens (`Probe.attempts`,
`ProbeUnobserved.attempts`), and `TracingSender` writes each earlier try as an
``exchange`` event of role ``retry`` whose ``parent`` is the exchange it retried. What is
sent, how often, and every verdict are unchanged: the counts below are the server's own.

The loopback servers here are raw sockets. Every response says ``Connection: close`` and
is written only after the whole request was read, so each request has its own
connection and a reset is deterministic: ``SO_LINGER`` 0 after reading the request.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import struct
import threading
from collections import Counter
from urllib.parse import urlsplit

import pytest
import requests
from urllib3.exceptions import ProtocolError

from fuzzlab.core import trace
from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.http import HttpClient
from fuzzlab.core.store import Store
from fuzzlab.harness.tracing import TracingSender
from fuzzlab.oracle.probe import (
    ATTEMPT_OUTCOMES,
    PRG_OBSERVED,
    PRG_UNOBSERVED,
    Probe,
    ProbeUnobserved,
    attempts_of,
)
from fuzzlab.report import diagram
from fuzzlab.tools.probesender import RequestsProbeSender, SeamProbeSender

RESET = "reset"


def _response(status: int, body: bytes = b"ok", headers=()) -> bytes:
    head = f"HTTP/1.1 {status} X\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)
    return (head + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() \
        + body


class _Server:
    """A loopback server whose ``plan(method, path, nth)`` decides each request: the
    bytes to answer with, or `RESET`. ``nth`` counts that path's earlier requests.
    ``requests`` is every request it read, in order."""

    def __init__(self, plan):
        self.plan = plan
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        self.requests: list[tuple[str, str]] = []
        self._seen: Counter = Counter()
        self._lock = threading.Lock()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    @staticmethod
    def _read(conn: socket.socket) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return data
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                length = int(value.strip())
        while len(rest) < length:
            chunk = conn.recv(65536)
            if not chunk:
                break
            rest += chunk
        return head

    def _one(self, conn: socket.socket) -> None:
        head = self._read(conn)
        if not head:
            conn.close()
            return
        method, target = head.split(b"\r\n", 1)[0].decode().split(" ")[:2]
        path = urlsplit(target).path
        with self._lock:
            nth = self._seen[path]
            self._seen[path] += 1
            self.requests.append((method, path))
        action = self.plan(method, path, nth)
        if action == RESET:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            conn.close()
            return
        conn.sendall(action)
        conn.close()

    def close(self) -> None:
        self.sock.close()


def _reset_first(method, path, nth):           # every try of a probe: reset, then 200
    return RESET if nth % 2 == 0 else _response(200, b"<html>ok</html>")


def _reset_always(method, path, nth):
    return RESET


def _prg(next_plan):
    """POST answers a 303 to ``/next``; ``/next`` follows ``next_plan``."""
    def plan(method, path, nth):
        if method == "POST":
            return _response(303, b"", [("Location", "/next")])
        return next_plan(method, path, nth)
    return plan


def _again(method, path, nth):                 # the follow-up is redirected once more
    return _response(302, b"", [("Location", "/again")])


@pytest.fixture
def serve():
    servers = []

    def start(plan):
        servers.append(_Server(plan))
        return servers[-1]
    yield start
    for s in servers:
        s.close()


@pytest.fixture
def recorded(tmp_path):
    """A store, a run and its active recorder; ``events()`` reads the exchanges."""
    store = Store(tmp_path / "t.db")
    run_id = store.start_run("auto", "h")
    rec = trace.TraceRecorder(store, run_id)

    def events():
        rec.flush()
        return [(r["key"], r["seq"], r["scope"], json.loads(r["body"])) for r in
                store.conn.execute("SELECT key, seq, scope, body FROM trace_event WHERE "
                                   "run_id=? AND kind='exchange' ORDER BY seq",
                                   (run_id,))]
    with trace.recording(rec):
        yield store, run_id, events
    rec.close()
    store.close()


def _shape(attempts):
    return [(a["n"], a["outcome"], a["status"]) for a in attempts]


# ------------------------------------------------------- the anonymous sender itself


def test_a_reset_then_a_response_is_two_attempts_at_the_try_loop(serve):
    server = serve(_reset_first)
    probe = RequestsProbeSender(timeout=5.0).send(server.url + "/p", "q", "x")
    assert probe.status == 200 and probe.resent == 1        # unchanged behaviour
    assert _shape(probe.attempts) == [(1, "unobserved", None), (2, "response", 200)]
    assert probe.attempts[0]["error"] == "ConnectionError"
    assert len(server.requests) == len(probe.attempts) == 2
    for a in probe.attempts:                     # no URL, header or body: names only
        assert set(a) == {"n", "outcome", "status", "elapsed_ms", "error"}
        assert a["outcome"] in ATTEMPT_OUTCOMES and a["elapsed_ms"] >= 0


def test_a_get_that_never_answers_carries_both_attempts_on_its_unobserved(serve):
    server = serve(_reset_always)
    with pytest.raises(ProbeUnobserved) as info:
        RequestsProbeSender(timeout=5.0).send(server.url + "/p", "q", "x")
    assert info.value.resent == 1
    assert _shape(info.value.attempts) == [(1, "unobserved", None), (2, "unobserved", None)]
    assert len(server.requests) == 2


def test_a_post_is_still_sent_once_and_has_one_attempt(serve):
    server = serve(_reset_always)
    with pytest.raises(ProbeUnobserved) as info:
        RequestsProbeSender(timeout=5.0).send(server.url + "/p", "q", "x", method="POST",
                                              location="body")
    assert _shape(info.value.attempts) == [(1, "unobserved", None)]
    assert len(server.requests) == 1


def test_a_refused_connection_is_re_raised_unchanged_and_carries_its_attempt():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(requests.ConnectionError) as info:
        RequestsProbeSender(timeout=2.0).send(f"http://127.0.0.1:{port}/p", "q", "x")
    assert not isinstance(info.value, ProbeUnobserved)      # still loud (BUG-0147)
    assert _shape(attempts_of(info.value)) == [(1, "error", None)]


def test_a_request_that_never_left_the_client_has_no_attempt():
    """``requests`` refuses a header value with a line break before connecting."""
    with pytest.raises(ValueError) as info:
        RequestsProbeSender(timeout=2.0).send("http://127.0.0.1:9/p", "X-Probe",
                                              "a\r\nb", location="header")
    assert attempts_of(info.value) == []


def test_a_test_double_without_attempts_keeps_working():
    assert Probe(200, "ok").attempts == [] and Probe(200, "ok").prg_sent is None
    assert ProbeUnobserved("x").attempts == [] and ProbeUnobserved("x", 1).resent == 1


# ------------------------------------------------------- through the trace wrapper


def test_each_earlier_try_is_a_retry_event_parented_to_its_exchange(serve, recorded):
    store, run_id, events = recorded
    server = serve(_reset_first)
    with trace.test_scope("t1"), trace.strategy_scope("s"):
        probe = TracingSender(RequestsProbeSender(timeout=5.0)).send(
            server.url + "/p", "q", "x")
        cited = trace.collected()
    assert probe.status == 200
    (rkey, rseq, rscope, retry), (key, seq, scope, main) = events()
    assert retry["role"] == "retry" and retry["parent"] == key and retry["attempt"] == 1
    assert retry["outcome"] == "unobserved" and retry["status"] is None
    assert retry["error"] == "ConnectionError" and retry["url"] == main["url"]
    assert main["role"] == "probe" and main["outcome"] == "response"
    assert main["status"] == 200 and main["attempts"] == 2 and main["resent"] == 1
    assert rseq < seq and rscope == scope == "test:t1"       # the tries' own order
    assert cited == [rkey, key]                  # a finding cites every try of its run
    assert len(server.requests) == 2 == 1 + sum(1 for *_x, b in events()
                                                if b["role"] == "retry")
    # the exchange's own sequence shows both tries; the retry is never a reply
    seq_doc = diagram.sequence(store.conn, run_id, key)
    assert [(s["type"], s.get("kind")) for s in seq_doc["steps"]] == [
        ("message", "request"), ("lost", "no-response"),
        ("message", "request"), ("message", "response")]
    assert seq_doc["steps"][1]["evidence"] == [rkey]
    test_doc = diagram.sequence(store.conn, run_id, "test:t1")
    assert {k for s in test_doc["steps"] for k in s["evidence"]} >= {rkey, key}


def test_a_probe_that_never_answers_keeps_its_outcome_and_shows_its_retry(serve,
                                                                           recorded):
    _store, _run, events = recorded
    serve_ = serve(_reset_always)
    with pytest.raises(ProbeUnobserved):
        TracingSender(RequestsProbeSender(timeout=5.0)).send(serve_.url + "/p", "q", "x")
    (_rk, _rs, _sc, retry), (key, _s, _c, main) = events()
    assert retry["parent"] == key and retry["outcome"] == "unobserved"
    assert main["outcome"] == "unobserved" and main["attempts"] == 2
    assert main["resent"] == 1


def test_one_attempt_adds_a_count_and_no_retry_event(serve, recorded):
    _store, _run, events = recorded
    server = serve(lambda m, p, n: _response(200))
    TracingSender(RequestsProbeSender(timeout=5.0)).send(server.url + "/p", "q", "x")
    ((_k, _s, _c, main),) = events()
    assert main["attempts"] == 1 and main["outcome"] == "response"


def test_a_follow_ups_retry_is_parented_to_the_follow_up(serve, recorded):
    store, run_id, events = recorded
    server = serve(_prg(_reset_first))
    probe = TracingSender(RequestsProbeSender(timeout=5.0)).send(
        server.url + "/f", "q", "x", method="POST", location="body", prg=True)
    assert probe.prg == PRG_OBSERVED and probe.follow_up_sends == 2     # unchanged
    assert _shape(probe.attempts) == [(1, "response", 303)]
    assert _shape(probe.followed.attempts) == [(1, "unobserved", None),
                                               (2, "response", 200)]
    rows = events()
    roles = [b["role"] for *_x, b in rows]
    assert roles == ["probe", "retry", "follow-up"]
    (mkey, *_a, main), (_rk, *_b, retry), (fkey, *_c, follow) = rows
    assert follow["parent"] == mkey and retry["parent"] == fkey
    assert follow["outcome"] == "response" and follow["status"] == 200
    assert follow["attempts"] == 2 and main["attempts"] == 1
    # each exchange's own re-sends; the run counter (`Probe.resent`) keeps both
    assert probe.resent == 1 and main["resent"] == 0 and follow["resent"] == 1
    assert len(server.requests) == 3 == len(rows)
    # the probe's own sequence holds its follow-up's retry, numbered, drawn lost
    doc = diagram.sequence(store.conn, run_id, mkey)
    assert [s["evidence"] for s in doc["steps"] if s["type"] != "note"] == [
        [mkey], [mkey], [_rk], [_rk], [fkey], [fkey]]
    assert doc["steps"][2]["label"].startswith("[retry, try 1] GET ")
    assert doc["steps"][3]["type"] == "lost"


@pytest.mark.parametrize("plan, outcome, status, tries", [
    (_again, "response", 302, 1),                # answered by another redirect
    (_reset_always, "unobserved", None, 2),      # never answered, re-sent once
])
def test_a_follow_up_that_was_no_observation_is_still_recorded(serve, recorded, plan,
                                                               outcome, status, tries):
    """BUG-0510: the follow-up went out, so it is an exchange, observed or not."""
    _store, _run, events = recorded
    server = serve(_prg(plan))
    probe = TracingSender(RequestsProbeSender(timeout=5.0)).send(
        server.url + "/f", "q", "x", method="POST", location="body", prg=True)
    assert probe.prg == PRG_UNOBSERVED and probe.followed is None       # unchanged
    rows = events()
    (mkey, *_a, _main) = rows[0]
    (*_b, follow) = rows[-1]
    assert follow["role"] == "follow-up" and follow["parent"] == mkey
    assert follow["outcome"] == outcome and follow["status"] == status
    assert follow["attempts"] == tries and follow["url"].endswith("/next")
    assert len(rows) == len(server.requests) == 1 + tries


def test_the_runs_request_count_is_unchanged_by_the_trace(serve, recorded):
    from fuzzlab.harness.auto import _CountingSender
    counts = []
    for wrap in (lambda s: s, TracingSender):
        server = serve(lambda m, p, n: _reset_first(m, p, n) if p == "/p"
                       else _response(200))
        counted = _CountingSender(wrap(RequestsProbeSender(timeout=5.0)))
        counted.send(server.url + "/p", "q", "x")
        counted.send(server.url + "/f", "q", "x", method="POST", location="body")
        counts.append((counted.count, len(server.requests)))
    assert counts[0] == counts[1] == (3, 3)


# ------------------------------------------------------- the authenticated seam

_RESET = requests.ConnectionError(ProtocolError(
    "Connection aborted.", ConnectionResetError(104, "Connection reset by peer")))


def _seam_client(transport, session=None):
    return HttpClient(RequestBudget(100), ["127.0.0.1"], session=session,
                      transport=transport)


def test_the_seam_records_its_one_try_per_dispatch():
    calls = []

    def transport(method, url, headers, body, timeout):
        calls.append(url)
        return 200, {}, b"ok"
    probe = SeamProbeSender(_seam_client(transport)).send("http://127.0.0.1:9/p", "q", "x")
    assert _shape(probe.attempts) == [(1, "response", 200)] and len(calls) == 1


def test_the_seams_reset_in_its_transport_is_an_unobserved_attempt():
    def transport(method, url, headers, body, timeout):
        raise _RESET
    with pytest.raises(ProbeUnobserved) as info:
        SeamProbeSender(_seam_client(transport)).send("http://127.0.0.1:9/p", "q", "x")
    assert _shape(info.value.attempts) == [(1, "unobserved", None)]


def test_the_seams_default_transport_sends_exactly_the_tries_it_records():
    """BUG-0549 review round 1 (PA-0510(2)): through the seam's default, pooled
    transport against a keep-alive peer that closes a connection unanswered at its
    second request. The transport resent that probe below the sender, so the server got
    a request no try recorded. Wanted: the requests the server received equal the
    recorded tries, and the unanswered one is an unobserved try."""
    from tests._keepalive_peer import KeepAlivePeer, echo

    def reply(conn, k, req):
        return None if k == 1 else echo(conn, k, req)

    with KeepAlivePeer(reply) as peer:
        client = HttpClient(RequestBudget(100), ["127.0.0.1"], timeout=5)
        try:
            sender = SeamProbeSender(client)
            tries = []
            for value in ("a", "b", "c"):
                try:
                    tries += sender.send(peer.url + "/p", "q", value).attempts
                except ProbeUnobserved as exc:
                    tries += exc.attempts
            assert len(peer.seen) == len(tries) == 3
            assert _shape(tries) == [(1, "response", 200), (1, "unobserved", None),
                                     (1, "response", 200)]
        finally:
            client.close()


def test_the_seams_timeout_still_raises_and_carries_its_attempt():
    def transport(method, url, headers, body, timeout):
        raise requests.ReadTimeout()
    with pytest.raises(requests.ReadTimeout) as info:            # unchanged
        SeamProbeSender(_seam_client(transport)).send("http://127.0.0.1:9/p", "q", "x")
    assert _shape(attempts_of(info.value)) == [(1, "timeout", None)]


def test_a_login_on_the_seams_way_that_got_no_response_is_no_attempt():
    """The session's ``prepare`` (a login with its own fetcher) met the reset: the
    probe itself never reached the transport. The same exception instance was raised
    through a transport first, so its traceback holds a stale transport frame: only
    a transport frame of this send counts."""
    def resetting(*a):
        raise _RESET
    with pytest.raises(ProbeUnobserved):
        SeamProbeSender(_seam_client(resetting)).send("http://127.0.0.1:9/p", "q", "x")
    calls = []

    class Session:
        def prepare(self, request, identity):
            raise _RESET

        def observe(self, *a):
            pass

    def transport(*a):
        calls.append(a)
        return 200, {}, b"ok"
    with pytest.raises(ProbeUnobserved) as info:                 # unchanged
        SeamProbeSender(_seam_client(transport, Session())).send(
            "http://127.0.0.1:9/p", "q", "x")
    assert info.value.attempts == [] and calls == []


def test_the_seams_follow_up_with_no_response_is_recorded_as_sent(recorded):
    _store, _run, events = recorded

    def transport(method, url, headers, body, timeout):
        if method == "POST":
            return 303, {"Location": "/next"}, b""
        raise _RESET
    probe = TracingSender(SeamProbeSender(_seam_client(transport))).send(
        "http://127.0.0.1:9/f", "q", "x", method="POST", location="body", prg=True)
    assert probe.status == 303 and probe.prg == PRG_UNOBSERVED       # unchanged
    assert probe.prg_sent["outcome"] == "unobserved"
    (mkey, *_a, main), (*_b, follow) = events()
    assert main["attempts"] == 1 and follow["parent"] == mkey
    assert follow["outcome"] == "unobserved" and follow["attempts"] == 1
    assert follow["error"] == "ConnectionError"


def test_the_seams_isolated_copy_path_records_only_the_try_that_went_out():
    """FR-FUZZ-44: a copy whose re-login is rejected falls back to an anonymous send.
    The copy's send never reached the transport; the anonymous one is the probe's one
    attempt."""
    from tests.test_login_form_isolation import BASE, FakeApp, _probe_form, _seam
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([BASE + "sqli_3.php"])

    def sends():
        return sum(1 for r in app.requests if r[1] == "/app/sqli_3.php")
    before = sends()
    probe = _probe_form(sender, login="x")                     # on the copy
    assert _shape(probe.attempts) == [(1, "response", 200)] and sends() == before + 1
    app.reject_copies = True
    app.sessions.pop(app.issued[1])
    _probe_form(sender, login="x")                             # the copy logs out
    before = sends()
    probe = _probe_form(sender, login="x")                     # re-login rejected
    assert sends() == before + 1                               # one try went out
    assert _shape(probe.attempts) == [(1, "response", probe.status)]
    assert probe.status == 302                                 # anonymous: the login page


# ------------------------------------------------------- end to end: run_auto


def _plan_app(method, path, nth):
    if path == "/flaky":
        return _reset_first(method, path, nth)
    if path == "/dead":
        return RESET
    return _response(200, b"<html>page</html>")


def _auto_run(tmp_path, serve, *, traced: bool) -> dict:
    from fuzzlab.harness.auto import run_auto
    from fuzzlab.tools import store_adapter
    tmp_path.mkdir()
    server = serve(_plan_app)
    db = tmp_path / "spider.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE discovered_pages (url TEXT, status_code INT, source TEXT)")
    con.executemany("INSERT INTO discovered_pages VALUES (?,200,'link')",
                    [(server.url + "/flaky?q=1",), (server.url + "/dead?d=1",),
                     (server.url + "/ok?o=1",)])
    con.commit()
    con.close()
    store = Store(tmp_path / "s.db")
    run_id = store.start_run("auto", "h")
    rec = trace.TraceRecorder(store, run_id) if traced else None
    try:
        with trace.recording(rec):
            store_adapter.import_spider(db, store, run_id)
            before = len(server.requests)
            result = run_auto(base_url=server.url + "/", store=store, run_id=run_id,
                              sender=RequestsProbeSender(timeout=5.0), mode="manual",
                              selected_categories=["sql-injection"],
                              points_source="crawl", trace_events=traced)
    finally:
        if rec is not None:
            rec.close()
    rows = [(r["key"], r["seq"], r["scope"], json.loads(r["body"])) for r in
            store.conn.execute("SELECT key, seq, scope, body FROM trace_event WHERE "
                               "run_id=? AND kind='exchange' ORDER BY seq", (run_id,))]
    out = {"requests": result.metrics["requests"],
           "server": len(server.requests) - before, "rows": rows, "store": store,
           "run": run_id,
           "verdicts": (result.candidates, result.negatives, result.findings,
                        len(result.inconclusive))}
    return out


def test_run_auto_records_every_try_and_changes_no_count_or_verdict(tmp_path, serve):
    plain = _auto_run(tmp_path / "plain", serve, traced=False)
    traced = _auto_run(tmp_path / "traced", serve, traced=True)
    try:
        assert plain["rows"] == []
        # what was sent, how often, and the verdicts: identical with the trace on
        assert traced["requests"] == plain["requests"]
        assert traced["server"] == plain["server"] == traced["requests"]
        assert traced["verdicts"] == plain["verdicts"]
        rows = traced["rows"]
        sent = [r for r in rows if r[3]["outcome"] != "not_sent"]
        assert len(sent) == traced["server"]           # one event per real try
        by_key = {k: (seq, scope, b) for k, seq, scope, b in rows}
        retries = [r for r in rows if r[3]["role"] == "retry"]
        assert retries
        for key, seq, scope, body in rows:
            if body["role"] == "retry":
                pseq, pscope, parent = by_key[body["parent"]]
                assert parent["role"] != "retry" and seq < pseq and scope == pscope
                assert body["outcome"] == "unobserved" and body["attempt"] == 1
                continue
            mine = [r for r in retries if r[3]["parent"] == key]
            assert len(mine) == body.get("attempts", 1) - 1
        flaky = [b for _k, _s, _c, b in rows
                 if b["role"] != "retry" and "/flaky" in b["url"]]
        dead = [b for _k, _s, _c, b in rows if b["role"] != "retry" and "/dead" in b["url"]]
        assert flaky and all(b["outcome"] == "response" and b["attempts"] == 2
                             for b in flaky)
        assert dead and all(b["outcome"] == "unobserved" and b["attempts"] == 2
                            for b in dead)
        st = diagram.status(traced["store"].conn, traced["run"])
        assert st["state"] == "complete" and st["recorder"]["dropped"] == 0
    finally:
        plain["store"].close()
        traced["store"].close()
