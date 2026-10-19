"""A probe that gets no response is "not observed", never the end of the run (BUG-0147).

The Go lab's response-splitting twin hand-wrote a keep-alive-looking 302 (no
``Connection: close``) and then closed the connection. When its close ran after the
client had already sent its PRG follow-up on that pooled connection (under load), the
follow-up met a reset. ``RequestsProbeSender`` caught only timeouts, so the reset
raised out of the oracle and ended the whole multi-target run. The servers here
reproduce that order deterministically: they reset (``SO_LINGER`` 0) only once the
next request has arrived on the same connection.
"""

from __future__ import annotations

import ast
import json
import re
import socket
import struct
import threading
import time
from pathlib import Path

import pytest
import requests
from urllib3.exceptions import ProtocolError

from fuzzlab.core.http import Response
from fuzzlab.oracle.oracle import UNOBSERVED, Oracle
from fuzzlab.oracle.probe import (
    PRG_OBSERVED,
    PRG_UNOBSERVED,
    Candidate,
    Probe,
    ProbeUnobserved,
    Verdict,
)
from fuzzlab.oracle.strategies import PeerAccounts
from fuzzlab.tools.probesender import RequestsProbeSender, SeamProbeSender

ROOT = Path(__file__).resolve().parent.parent
KEEP_ALIVE_302 = b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"
OK_CLOSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"


def _reset(conn: socket.socket) -> None:
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()


class _Server:
    """One behaviour per mode, per accepted connection (``n`` = its index):

    - ``late``: the first connection answers the keep-alive 302, then resets once the
      follow-up is on it (the late close); later connections answer 200.
    - ``late_dead``: as ``late``, but every later connection resets too.
    - ``reset``: every connection resets on its first request, with no response.
    - ``chunked_cut``: a chunked body cut off mid-chunk.
    - ``bad_gzip``: a gzip body that is not gzip.
    - ``slow_body``: the head, then a body that never finishes.
    """

    def __init__(self, mode: str):
        self.mode = mode
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        self.requests: list[bytes] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        n = 0
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn, n), daemon=True).start()
            n += 1

    def _one(self, conn: socket.socket, n: int) -> None:
        self.requests.append(conn.recv(65536).split(b"\r\n", 1)[0])
        mode = self.mode
        if mode == "reset" or (mode == "late_dead" and n > 0):
            _reset(conn)
        elif mode in ("late", "late_dead") and n == 0:
            conn.sendall(KEEP_ALIVE_302)
            conn.settimeout(5)
            try:
                if conn.recv(65536, socket.MSG_PEEK):      # the follow-up came on it
                    self.requests.append(b"<on the closing connection>")
            except OSError:
                pass
            _reset(conn)
        elif mode == "late":
            conn.sendall(OK_CLOSE)
            conn.close()
        elif mode == "chunked_cut":
            conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nabc")
            conn.close()
        elif mode == "bad_gzip":
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 9\r\n"
                         b"Connection: close\r\n\r\nnot-gzip!")
            conn.close()
        elif mode == "slow_body":
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nab")
            time.sleep(3)
            conn.close()

    def close(self) -> None:
        self.sock.close()


@pytest.fixture
def server(request):
    s = _Server(request.param)
    yield s
    s.close()


# --------------------------------------------------------------- the anonymous sender


@pytest.mark.parametrize("server", ["late"], indirect=True)
def test_a_follow_up_on_a_closing_connection_is_retried_on_a_fresh_one(server):
    """The BUG-0147 failure itself: the follow-up met a reset on the reused connection.
    It is a GET, so it is re-sent once on a fresh connection and observed."""
    probe = RequestsProbeSender(timeout=5.0).send(server.url + "/channels/redirect",
                                                   "destination", "${603*129}", prg=True)
    assert b"<on the closing connection>" in server.requests
    assert server.requests.count(b"GET /next HTTP/1.1") == 1     # the retry
    assert probe.status == 302 and probe.prg == PRG_OBSERVED
    assert probe.followed is not None and probe.followed.status == 200
    assert probe.follow_up_sends == 2           # the follow-up and its re-send, counted


@pytest.mark.parametrize("server", ["late_dead"], indirect=True)
def test_a_follow_up_that_never_gets_a_response_is_unobserved_not_raised(server):
    """The probe keeps its own response; only the follow-up is unobserved."""
    probe = RequestsProbeSender(timeout=5.0).send(server.url + "/channels/redirect",
                                                   "destination", "x", prg=True)
    assert probe.status == 302 and probe.prg == PRG_UNOBSERVED
    assert probe.follow_up_sends == 2           # the follow-up and its re-send, both counted


@pytest.mark.parametrize("server", ["reset"], indirect=True)
def test_a_get_with_no_response_is_retried_once_then_named_without_the_payload(server):
    with pytest.raises(ProbeUnobserved) as info:
        RequestsProbeSender(timeout=5.0).send(server.url + "/p", "q", "PAYLOAD-123")
    assert len(server.requests) == 2            # one retry, no more
    assert info.value.resent == 1               # the counters still count it
    assert "PAYLOAD-123" not in str(info.value) and server.url not in str(info.value)
    assert "ConnectionResetError" in str(info.value)
    assert isinstance(info.value.__cause__, requests.ConnectionError)


@pytest.mark.parametrize("server", ["reset"], indirect=True)
def test_a_post_with_no_response_is_never_re_sent(server):
    with pytest.raises(ProbeUnobserved):
        RequestsProbeSender(timeout=5.0).send(server.url + "/p", "q", "x", method="POST",
                                              location="body")
    assert len(server.requests) == 1


@pytest.mark.parametrize("server", ["chunked_cut", "bad_gzip"], indirect=True)
def test_a_cut_off_or_undecodable_body_is_unobserved_and_never_re_sent(server):
    """The server answered (part of) it: a GET is not re-sent, and the error is named
    by its cause, not by a wrapper."""
    with pytest.raises(ProbeUnobserved) as info:
        RequestsProbeSender(timeout=5.0).send(server.url + "/p", "q", "x")
    assert len(server.requests) == 1 and info.value.resent == 0
    name = str(info.value)
    assert not re.search(r"\((ChunkedEncodingError|ContentDecodingError)\)", name), name


@pytest.mark.parametrize("server", ["slow_body"], indirect=True)
def test_a_body_that_times_out_is_a_timeout_not_unobserved(server):
    """A delay is a timing strategy's evidence: the full timeout, status 0."""
    probe = RequestsProbeSender(timeout=0.5).send(server.url + "/p", "q", "x",
                                                  method="POST", location="body")
    assert probe.status == 0 and probe.elapsed == 0.5


@pytest.mark.parametrize("server", ["reset"], indirect=True)
def test_the_runs_request_count_includes_a_re_send(server):
    from fuzzlab.harness.auto import _CountingSender
    counted = _CountingSender(RequestsProbeSender(timeout=5.0))
    with pytest.raises(ProbeUnobserved):
        counted.send(server.url + "/p", "q", "x")
    assert counted.count == 2 == len(server.requests)


def test_a_target_that_cannot_be_reached_fails_loudly():
    """Refused (or DNS, TLS, proxy) is not one probe's event: a dead target must never
    turn every candidate into a quiet inconclusive."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(requests.ConnectionError) as info:
        RequestsProbeSender(timeout=2.0).send(f"http://127.0.0.1:{port}/p", "q", "x")
    assert not isinstance(info.value, ProbeUnobserved)


# ------------------------------------------------------------ the authenticated seam

_RESET = requests.ConnectionError(ProtocolError(
    "Connection aborted.", ConnectionResetError(104, "Connection reset by peer")))


class _Client:
    """POST answers a 302; anything else raises ``exc``."""

    def __init__(self, exc):
        self.exc = exc

    def send(self, req):
        if req.method == "POST":
            return Response(302, {"Location": "/next"}, b"", 1.0)
        raise self.exc


def test_the_seam_maps_a_reset_and_still_raises_a_timeout_as_before():
    with pytest.raises(ProbeUnobserved):
        SeamProbeSender(_Client(_RESET)).send("http://127.0.0.1:9/p", "q", "x")
    with pytest.raises(requests.ReadTimeout):       # unchanged: no status-0 stand-in
        SeamProbeSender(_Client(requests.ReadTimeout())).send("http://127.0.0.1:9/p",
                                                               "q", "x")


def test_the_seam_follow_up_with_no_response_is_unobserved():
    probe = SeamProbeSender(_Client(_RESET)).send(
        "http://127.0.0.1:9/p", "q", "x", method="POST", location="body", prg=True)
    assert probe.status == 302 and probe.prg == PRG_UNOBSERVED


def test_the_seams_own_login_with_no_response_is_unobserved():
    class Manager:
        def ensure(self, *a, **kw):
            raise _RESET

    sender = SeamProbeSender(_Client(KeyError("never sent")), identity="alice",
                             manager=Manager(), base_url="http://127.0.0.1:9/")
    with pytest.raises(ProbeUnobserved):
        sender.send("http://127.0.0.1:9/p", "q", "x")


def test_the_seam_never_swallows_another_error():
    with pytest.raises(KeyError):
        SeamProbeSender(_Client(KeyError("defect"))).send("http://127.0.0.1:9/p", "q", "x")


# ------------------------------------------------------------ the oracle (PA-0137(3))


class _Strategy:
    def __init__(self, arm: str, vuln_class: str):
        self.arm, self.mechanism, self.vuln_class = arm, arm, vuln_class

    def applies(self, candidate):
        return candidate.vuln_class == self.vuln_class

    def confirm(self, candidate, sender):
        probe = sender.send(candidate.url, candidate.param, "x")
        if probe.status == 200 and "HIT" in probe.text:
            return Verdict(True, self.vuln_class, self.arm, {"hit": True})
        return Verdict(False, self.vuln_class, self.arm)


class _Sender:
    """No response from /dead; a hit everywhere else."""

    def send(self, url, param, value, **kw):
        if url.endswith("/dead"):
            raise ProbeUnobserved("no response: ConnectionError (ConnectionResetError)")
        return Probe(status=200, text="HIT", elapsed=0.01)


def test_a_probe_with_no_response_is_inconclusive_and_the_next_candidate_still_runs():
    oracle = Oracle(strategies=[_Strategy("a", "xss")])
    dead = Candidate("http://127.0.0.1:9/dead", "q", vuln_class="xss")
    live = Candidate("http://127.0.0.1:9/live", "q", vuln_class="xss")
    confirmed, inconclusive = oracle.confirm_outcome(dead, _Sender())
    assert confirmed is None
    assert inconclusive is not None and inconclusive.inconclusive
    assert inconclusive.mechanism == UNOBSERVED and inconclusive.evidence["mechanism"] == "a"
    confirmed, _ = oracle.confirm_outcome(live, _Sender())
    assert confirmed is not None and confirmed.confirmed


def test_another_mechanism_still_confirms_after_one_got_no_response():
    class Dead(_Strategy):
        def confirm(self, candidate, sender):
            raise ProbeUnobserved("no response: ConnectionError (ConnectionResetError)")

    oracle = Oracle(strategies=[Dead("a", "xss"), _Strategy("b", "xss")])
    confirmed, _ = oracle.confirm_outcome(
        Candidate("http://127.0.0.1:9/live", "q", vuln_class="xss"), _Sender())
    assert confirmed is not None and confirmed.mechanism == "b"


def test_under_a_scheduler_the_arm_is_charged_its_probes_with_no_reward():
    class Scheduler:
        def __init__(self):
            self.updates: list = []

        def order(self, ctx, arms):
            return list(arms)

        def update(self, ctx, arm, reward, cost=1.0):
            self.updates.append((arm, reward, cost))

    sched = Scheduler()
    Oracle(strategies=[_Strategy("a", "xss")], scheduler=sched).confirm_outcome(
        Candidate("http://127.0.0.1:9/dead", "q", vuln_class="xss"), _Sender())
    assert sched.updates == [("a", 0.0, 1)]


def test_any_other_error_still_propagates():
    class Broken(_Strategy):
        def confirm(self, candidate, sender):
            raise ValueError("a defect")

    with pytest.raises(ValueError):
        Oracle(strategies=[Broken("a", "xss")]).confirm_outcome(
            Candidate("http://127.0.0.1:9/x", "q", vuln_class="xss"), _Sender())


# ------------------------------------------- every default mechanism (structural guard)


class _Listener:
    """An out-of-band listener that never sees a callback."""

    def __init__(self, running: bool = True):
        self.running = running

    def register(self):
        return "tok"

    def callback_url(self, token, scheme="http"):
        assert self.running
        return f"http://127.0.0.1:9/cb/{token}"

    def wait_for(self, token, timeout=0.0):
        return None

    def proof(self, token):
        return "fzlproof-never"


class _DeadSender:
    def __init__(self):
        self.sent = 0

    def send(self, url, param, value, **kw):
        self.sent += 1
        raise ProbeUnobserved("no response: ConnectionError (ConnectionResetError)")


def _candidates(strategy) -> list[Candidate]:
    vc, cat = strategy.vuln_class, getattr(strategy, "category", None)
    base = "http://127.0.0.1:9/p"
    return [Candidate(base, "q", vuln_class=vc, category=cat),
            Candidate(base, "q", vuln_class=vc, category=cat, base_entries=(("q", "7"),)),
            Candidate(base + "/{q}", "q", location="path", vuln_class=vc, category=cat,
                      base_entries=(("q", "7"),)),
            Candidate(base, "q", method="POST", location="body", vuln_class=vc, category=cat),
            Candidate(base, "body", method="POST", location="body", vuln_class=vc,
                      category=cat, content_type="application/xml"),
            Candidate(base, "body", method="POST", location="body", vuln_class=vc,
                      category=cat, content_type="application/json"),
            Candidate(base, "q", method="POST", location="json", vuln_class=vc,
                      category=cat, base_entries=((("q",), "x"), (("p",), "y")))]


#: Default mechanisms that refuse before sending anything when their own dependency is
#: absent here (UnplaceableLocation): no probe, so no transport failure to handle.
EXEMPT = {"DomXssStrategy": "needs a browser", "StoredXssStrategy": "needs a browser",
          "GreyboxConfirmationStrategy": "needs a coverage or DB-fault source"}
#: Mechanisms that use the out-of-band listener.
LISTENER_USERS = {"CommandInjectionOobStrategy", "SsrfInBandMarkerStrategy",
                  "SsrfOobStrategy", "XxeInBandMarkerStrategy", "XxeOobStrategy"}


@pytest.mark.parametrize("running", [True, False], ids=["listener-up", "listener-stopped"])
def test_no_default_mechanism_turns_a_probe_without_response_into_a_negative(running):
    """PA-0153(3): every mechanism's external work -- the HTTP send and the
    out-of-band listener -- fails into "no verdict", never a negative or a crash.

    Every default mechanism except the named exemptions must send for at least one
    candidate shape, and every shape it sends for must come back inconclusive. A shape
    a mechanism declines without sending (a JSON-only check on a query point) is its
    ordinary "not mine", not a transport failure. With the listener stopped, every
    listener user is inconclusive (no verdict) for every shape it applies to."""
    from fuzzlab.oracle.strategies import default_strategies
    peer = PeerAccounts(sender=_DeadSender(), owner="alice", peer_name="bob",
                        anonymous=_DeadSender())
    strategies = default_strategies(oob=_Listener(running), peer=peer)
    names = {type(s).__name__ for s in strategies}
    assert EXEMPT.keys() <= names and LISTENER_USERS <= names
    exercised = set()
    for strategy in strategies:
        name = type(strategy).__name__
        for cand in _candidates(strategy):
            if not strategy.applies(cand):
                continue
            sender = _DeadSender()
            confirmed, inconclusive = Oracle(strategies=[strategy]).confirm_outcome(
                cand, sender)
            assert confirmed is None, name
            if sender.sent or (not running and name in LISTENER_USERS):
                exercised.add(name)
                assert inconclusive is not None and inconclusive.inconclusive, (
                    f"{name} turned a probe with no response into a negative")
    expected = names - EXEMPT.keys() if running else LISTENER_USERS
    assert expected <= exercised, expected - exercised


# ------------------------------------------------------------ a whole pipeline run

class _PipelineSender:
    """blog_post.php never answers; product.php is error-based SQLi (as
    `test_pipeline.PipelineSender`)."""

    def send(self, url, param, value, timing=False, **kw):
        if "/blog_post.php" in url:
            raise ProbeUnobserved("no response: ConnectionError (ConnectionResetError)")
        if "'" in value or '"' in value:
            return Probe(500, "You have an error in your SQL syntax")
        return Probe(200, "<html>product page</html>")


def test_a_point_with_no_response_never_ends_the_pipeline(tmp_path):
    """Two SQLi points in one run; the first (also the baseline's point) never
    answers. The run goes on, the second is confirmed, the first is INCONCLUSIVE (not
    CHECKED, so never an ML negative), and its reason names no URL."""
    from fuzzlab.audit import InjectionPoint
    from fuzzlab.core.runmode import RunPlan
    from fuzzlab.core.store import Store
    from fuzzlab.harness.pipeline import run_pipeline
    points = [InjectionPoint("http://localhost/blog_post.php", "id", "GET", "query"),
              InjectionPoint("http://localhost/product.php", "id", "GET", "query")]
    plan = RunPlan("automatic", ["sql-injection"], scored=False, source="user")
    with Store(tmp_path / "u.db") as store:
        run = store.start_run("pipeline", "h")
        result = run_pipeline(points, store, run, _PipelineSender(), plan)
        found = {r["url"] for r in store.conn.execute(
            "SELECT url FROM finding WHERE run_id=?", (run,))}
        status = {json.loads(r["evidence"])["url"].rsplit("/", 1)[-1]: r["status"]
                  for r in store.conn.execute(
                      "SELECT evidence, oracle_status status FROM candidate "
                      "WHERE run_id=?", (run,))}
        targets = store.conn.execute("SELECT base_url, dbms FROM target WHERE run_id=?",
                                     (run,)).fetchall()
    assert any(url.endswith("/product.php") for url in found)
    assert not any(url.endswith("/blog_post.php") for url in found)
    assert status == {"blog_post.php": "inconclusive", "product.php": "checked"}
    assert result.metrics["oracle_inconclusive"] == 1
    assert result.metrics["oracle_rejected"] == 0     # no negative from blog_post.php
    assert [tuple(t) for t in targets] == [("http://localhost", None)]   # unprobed
    detail, = [item for item in result.inconclusive if item["url"].endswith("/blog_post.php")]
    assert detail["mechanism"] == UNOBSERVED
    assert "no response" in detail["reason"] and "http" not in detail["reason"]


# ------------------------------------------------------------ the lab apps (sweep)

#: A hand-written HTTP/1.x status line in a lab template or the proxy.
_STATUS_LINE = re.compile(r"HTTP/1\.[01] [0-9]{3}")


def _raw_responders() -> list[Path]:
    paths = [p for p in (ROOT / "fuzzlab" / "labgen").rglob("*.j2")
             if _STATUS_LINE.search(p.read_text(encoding="utf-8", errors="replace"))]
    return paths + [ROOT / "fuzzlab" / "proxy" / "server.py"]


def _head(text: str, start: int) -> str:
    """The response head starting at ``start``: up to its blank line (``\\r\\n\\r\\n``,
    written escaped in the source), across string pieces."""
    end = text.find("\\r\\n\\r\\n", start)
    if end < 0:                                 # pieces joined over lines: the blank
        m = re.compile(r'^\s*b?"\\r\\n"', re.MULTILINE).search(text, start)   # line is a
        end = m.start() if m else -1            # piece on a line of its own
    return text[start:end] if end >= 0 else text[start:start + 300]


def test_every_hand_written_response_that_closes_says_so():
    """A server that writes its own response and then closes the connection must say
    ``Connection: close`` in that response's head, or a client reuses the closing
    connection (BUG-0147)."""
    found = _raw_responders()
    assert any(p.name == "raw_socket_response_write.go.j2" for p in found)
    for path in found:
        text = path.read_text(encoding="utf-8")
        for m in _STATUS_LINE.finditer(text):
            if text[m.start():].startswith(("HTTP/1.1 200 Connection Established",)):
                continue                        # a CONNECT tunnel stays open by design
            assert "Connection: close" in _head(text, m.start()), (
                f"{path.relative_to(ROOT)}: {text[m.start():m.start() + 60]!r}")


def test_the_response_guard_reads_only_its_own_head(tmp_path):
    text = ('w(b"HTTP/1.1 501 X\\r\\nContent-Length: 0\\r\\n\\r\\n")\n'
            'w(b"HTTP/1.1 502 Y\\r\\nConnection: close\\r\\n\\r\\n")\n')
    assert "Connection: close" not in _head(text, text.index("HTTP/1.1 501"))
    assert "Connection: close" in _head(text, text.index("HTTP/1.1 502"))
    pieces = ('r := "HTTP/1.1 302 Found\\r\\n" +\n\t"Location: " + v + "\\r\\n" +\n'
              '\t"Content-Length: 0\\r\\n" +\n\t"\\r\\n"\nnext := "Connection: close"\n')
    assert "Location" in _head(pieces, 5)       # read past the Location piece's CRLF
    assert "Connection: close" not in _head(pieces, 5)   # but never past the blank line


# ------------------------------------------------------------ every HTTP sender (guard)

#: Senders that issue HTTP themselves. Each maps a transport failure (BUG-0147) and is
#: proven above, except greybox's correlating sender, which records every request
#: error as its own status-0 attempt (its contract; M10 reads coverage and DB faults).
#: A new one fails the guard below until it is listed and tested.
HTTP_SENDERS = {("fuzzlab/tools/probesender.py", "RequestsProbeSender"): "_unobserved(",
                ("fuzzlab/tools/probesender.py", "SeamProbeSender"): "_unobserved(",
                ("fuzzlab/greybox/run.py", "RequestsCorrelatingSender"): "RequestException"}
_SEND_METHODS = {"send", "send_correlated"}


def http_senders(path: Path, rel: str) -> dict[tuple[str, str], str]:
    """Classes with a probe-sending method (``send``/``send_correlated`` taking ``url,
    param, value``) that issue HTTP themselves: the class source mentions ``requests``,
    a ``.request(`` call or a client's ``.send(req``. A pure wrapper that only
    delegates to an inner sender does not."""
    found = {}
    for cls in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(cls, ast.ClassDef):
            continue
        methods = [fn for fn in cls.body if isinstance(fn, ast.FunctionDef)
                   and fn.name in _SEND_METHODS
                   and [a.arg for a in fn.args.args[:4]] == ["self", "url", "param", "value"]]
        if not methods:
            continue
        src = ast.unparse(cls)
        if re.search(r"\brequests\.|\.request\(|client\.send\(", src):
            found[(rel, cls.name)] = src
    return found


def test_every_http_sender_maps_a_transport_failure():
    found = {}
    for p in sorted((ROOT / "fuzzlab").rglob("*.py")):
        found |= http_senders(p, str(p.relative_to(ROOT)))
    assert set(found) == set(HTTP_SENDERS), (
        "a sender that issues HTTP itself maps transport failures (probesender."
        f"_unobserved) and is tested here (BUG-0147, PA-0153): {set(found) ^ set(HTTP_SENDERS)}")
    for key, marker in HTTP_SENDERS.items():
        assert marker in found[key], key        # in the class itself, not the file


def test_the_sender_guard_finds_a_new_sender(tmp_path):
    p = tmp_path / "s.py"
    p.write_text("class New:\n    def send(self, url, param, value, timing=False):\n"
                 "        return requests.get(url)\n"
                 "class Wrap:\n    def send(self, url, param, value, timing=False):\n"
                 "        return self._inner.send(url, param, value)\n")
    assert set(http_senders(p, "s.py")) == {("s.py", "New")}


def test_an_out_of_band_callback_still_confirms_after_a_probe_got_no_response():
    """The OOB mechanisms never read the HTTP response: a payload that reached the
    target before its connection reset still proves itself by its callback."""
    from fuzzlab.oracle.strategies import (
        CommandInjectionOobStrategy,
        SsrfOobStrategy,
        XxeOobStrategy,
    )

    class Hit(_Listener):
        def wait_for(self, token, timeout=0.0):
            return type("H", (), {"path": "/cb/tok", "remote_addr": "127.0.0.1"})()

    for cls, cand in ((CommandInjectionOobStrategy, Candidate("http://127.0.0.1:9/p", "q")),
                      (SsrfOobStrategy, Candidate("http://127.0.0.1:9/p", "q")),
                      (XxeOobStrategy, Candidate("http://127.0.0.1:9/p", "body",
                                                 method="POST", location="body"))):
        verdict = cls(Hit()).confirm(cand, _DeadSender())
        assert verdict is not None and verdict.confirmed, cls.__name__
        with pytest.raises(ProbeUnobserved):               # no callback: no verdict
            cls(_Listener()).confirm(cand, _DeadSender())


def test_a_copy_login_with_no_response_is_a_failed_login_never_a_half_made_copy():
    """Reviewer A (round 1, N2): the copy's login got a reset. The copy is released,
    the path is failed with a fixed reason and sent anonymously, and the run goes on."""
    from tests import test_login_form_isolation as iso
    app = iso.FakeApp()
    mgr, _client, sender = iso._seam(app)
    real = mgr.isolated_copy

    def resetting_copy(identity, **kw):
        copy = real(identity, **kw)
        copy.ensure = lambda *a, **k: (_ for _ in ()).throw(_RESET)
        return copy

    mgr.isolated_copy = resetting_copy
    sender.isolate([iso.BASE + "sqli_3.php"])
    probe = iso._probe_form(sender)                  # no raise: sent anonymously
    assert probe.status in (200, 302)
    report = sender.isolation_report()
    assert [f["reason"] for f in report["failures"]] == ["isolated login got no response"]
    assert mgr._copies == []                         # released, never kept half-made
