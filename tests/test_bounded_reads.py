"""Bounded reads (BUG-0536; audit defects 21, 23 and 27; SP-60).

- **21.** Every ``requests`` reader of a target's body reads it through one bounded
  reader (`core.bodyread`): a wire-byte and a decoded-byte ceiling and a wall-clock
  deadline checked inside the read loop. An incomplete body is a typed marker the
  caller sees (``BodyIncomplete``; SP-34 maps it to ``ProbeUnobserved``), never a short
  or a late body taken as whole. Each reader is driven against a loopback peer that
  drips its body (each byte well inside the read timeout) and one that sends a gzip
  body decoding past the ceiling.
- **23.** ``JsonlTail`` caps the line it is reading while it reads: an unterminated line
  over ``MAX_LINE_BYTES`` is quarantined once, its bytes dropped, and the rest of the
  line discarded across reads until its newline; the work is linear (an exposed copy
  count, PA-0135).
- **27.** A contract's ``body_matches`` patterns run in a worker process killed at a time
  limit: a catastrophic pattern makes the case an ``error`` (inconclusive), never a hang
  and never a no-match.

Written first: on 4ee8007 each test below fails for its stated reason (the drip and the
bomb come back as normal bodies; the over-cap line is held whole and never quarantined;
the pathological match runs until the smoke alarm). The copy-count test needs the count
the fix exposes; its oracle is proven on a deliberately quadratic tail.
"""

from __future__ import annotations

import ast
import contextlib
import functools
import gzip
import json
import signal
import socket
import threading
import time
import tracemalloc
from pathlib import Path

import pytest
import requests

from fuzzlab.core.net import require_loopback
from fuzzlab.oracle.probe import ProbeUnobserved

ROOT = Path(__file__).resolve().parent.parent

# --- loopback peers (defect 21) -------------------------------------------------------------

#: A dripped body: this many bytes, one every `GAP` seconds -- each well inside the
#: readers' read timeout (`TIMEOUT`), so only a wall-clock deadline can cut it.
DRIP_BYTES = 120
GAP = 0.05
TIMEOUT = 0.25
#: A dripped chunk-size line: this many ``0`` before its ``1``.
SIZELINE_BYTES = 40
#: A status line and headers dripped a byte every `GAP` s (about 4 s in all).
HEAD_DRIP = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Pad: " + b"a" * 30
             + b"\r\nContent-Length: 2\r\n\r\n")
#: A gzip body that decodes to this many bytes (past the default decoded ceiling).
BOMB_DECODED = 40 << 20


@functools.cache
def _bomb() -> bytes:
    return gzip.compress(bytes(BOMB_DECODED), 9)


class _Peer:
    """A loopback HTTP peer answering every request of one connection the same way:

    - ``drip``: a 200 with ``Content-Length: DRIP_BYTES``, then the body one byte every
      `GAP` s; ``sent`` counts the bytes it got out before the client hung up;
    - ``bomb``: a 200 whose gzip body decodes to `BOMB_DECODED` bytes;
    - ``sizeline``: a chunked 200 whose first chunk-size line is dripped
      (``0`` x `SIZELINE_BYTES`, then ``1``): a framing line, not body bytes;
    - ``head``: the status line and headers themselves dripped a byte at a time
      (`HEAD_DRIP`), then a 2-byte body;
    - ``silent``: reads the request and answers nothing until the client hangs up;
    - ``echo``: a 200 whose body is the request's ``Accept-Encoding`` (also kept in
      ``accept``).
    """

    def __init__(self, mode: str):
        self.mode = mode
        self.requests = 0
        self.sent = 0
        self.accept: list[str] = []
        self.done = threading.Event()
        self.sock = socket.socket()
        self.sock.bind((require_loopback("127.0.0.1"), 0))
        self.sock.listen(8)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}/p"
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        try:
            while (head := conn.recv(65536)):
                self.requests += 1
                if self.mode == "silent":
                    continue                     # until the client closes (recv b"")
                if self.mode == "echo":
                    value = next((ln.split(b":", 1)[1].strip() for ln in head.split(b"\r\n")
                                  if ln.lower().startswith(b"accept-encoding:")), b"")
                    self.accept.append(value.decode())
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n"
                                 % len(value) + value)
                    continue
                if self.mode == "head":
                    for i in range(len(HEAD_DRIP)):
                        time.sleep(GAP)
                        conn.sendall(HEAD_DRIP[i:i + 1])
                        self.sent += 1
                    conn.sendall(b"ok")
                    continue
                if self.mode == "drip":
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                                 b"Content-Length: %d\r\n\r\n" % DRIP_BYTES)
                    for _ in range(DRIP_BYTES):
                        time.sleep(GAP)
                        conn.sendall(b"x")
                        self.sent += 1
                elif self.mode == "bomb":
                    body = _bomb()
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                                 b"Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n"
                                 % len(body) + body)
                else:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                                 b"Transfer-Encoding: chunked\r\n\r\n")
                    for _ in range(SIZELINE_BYTES):
                        time.sleep(GAP)
                        conn.sendall(b"0")
                        self.sent += 1
                    conn.sendall(b"1\r\nx\r\n0\r\n\r\n")
        except OSError:
            pass
        finally:
            conn.close()
            self.done.set()

    def close(self) -> None:
        self.sock.close()


@pytest.fixture
def peer(request):
    p = _Peer(request.param)
    yield p
    p.close()


def _client(timeout: float):
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    return HttpClient(RequestBudget(1000), ["127.0.0.1"], timeout=timeout)


def _incomplete(exc: BaseException) -> str | None:
    """The reason of a typed incomplete-body marker, or None."""
    if type(exc).__name__ in ("BodyIncomplete", "_GreyboxUnobserved"):
        return exc.reason
    if isinstance(exc, ProbeUnobserved) and "incomplete body" in str(exc):
        return str(exc).rsplit("(", 1)[-1].rstrip(")")
    return None


def _core_seam(url):
    from fuzzlab.core.http import Request
    return _client(TIMEOUT).send(Request("GET", url)).body


def _static_fetch(url):
    from fuzzlab.tools.navguard import get_checked
    with requests.Session() as session:
        return get_checked(session, url, TIMEOUT, lambda _u: True).content


def _anonymous_probe(url):
    from fuzzlab.tools.probesender import RequestsProbeSender
    return RequestsProbeSender(timeout=TIMEOUT).send(url, "q", "x").text


def _seam_probe(url):
    from fuzzlab.tools.probesender import SeamProbeSender
    return SeamProbeSender(_client(TIMEOUT)).send(url, "q", "x").text


class _GreyboxUnobserved(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _greybox(url):
    """Only greybox's typed marker counts; a bare status-0 probe (its "request error"
    try, whose text the run loop would score) is read as the body it pretends to be."""
    from fuzzlab.greybox import run as greybox
    probe, _cid = greybox.RequestsCorrelatingSender(timeout=TIMEOUT, id_factory=lambda: "c") \
        .send_correlated(url, "q", "x")
    unobserved = getattr(greybox, "UnobservedProbe", None)
    if unobserved is not None and isinstance(probe, unobserved) and probe.reason:
        raise _GreyboxUnobserved(probe.reason)
    return probe.text


def _run_contract(peer, timeout_ms: int = 1000) -> list[dict]:
    """One case, ``GET /p`` on the peer, through the real contract runner and its own
    session."""
    from fuzzlab.disco.contract import Contract
    from fuzzlab.disco.runner import Runner
    origin = peer.url.rsplit("/", 1)[0]
    doc = {"contract_version": "1.0",
           "run": {"id": "r", "target": {"base_url": origin + "/",
                                         "scope_allowlist": [origin.split("//", 1)[1]]},
                   "limits": {"rps": 1000, "timeout_ms": timeout_ms,
                              "max_body_bytes": 65536},
                   "reset_hook": None},
           "auth_profiles": [{"id": "anon", "kind": "none"}],
           "endpoints": [{"id": "ep_1", "method": "GET", "path": "/p"}],
           "test_cases": [{"id": "tc_1", "endpoint": "ep_1", "class": "type",
                           "auth_profile": "anon", "request": {},
                           "oracle": {"expect_status_class": ["2xx"], "findings_if": []},
                           "safety": {"destructive": False}}],
           "results": []}
    return Runner(Contract(doc), authorized=True).run()


#: Every reader of a target's body over ``requests`` that audit defect 21 named, plus the
#: senders its sweep found (greybox), with the marker each must give an incomplete body:
#: the typed ``BodyIncomplete`` at the transport, SP-34's ``ProbeUnobserved`` at the
#: oracle's senders, greybox's typed ``UnobservedProbe`` (never its bare status-0 try).
READERS = {"core seam transport": (_core_seam, "BodyIncomplete"),
           "static fetch (navguard)": (_static_fetch, "BodyIncomplete"),
           "anonymous probe sender": (_anonymous_probe, "ProbeUnobserved"),
           "seam probe sender": (_seam_probe, "ProbeUnobserved"),
           "greybox sender": (_greybox, "_GreyboxUnobserved")}


def _outcome(reader, url, marker="BodyIncomplete"):
    try:
        body = reader(url)
    except (requests.RequestException, ProbeUnobserved, _GreyboxUnobserved) as exc:
        if type(exc).__name__ != marker:
            return f"error {type(exc).__name__}: {exc}"
        reason = _incomplete(exc)
        return f"incomplete ({reason})" if reason else f"error {type(exc).__name__}"
    return f"a normal body of {len(body)} bytes"


@pytest.mark.parametrize("peer", ["drip"], indirect=True)
@pytest.mark.parametrize("reader", sorted(READERS))
def test_a_dripped_body_is_cut_at_its_deadline_and_never_taken_whole(peer, reader):
    """Defect 21: a ``requests`` timeout is per receive. The peer drips the body a byte
    every 50 ms, under the 0.25 s read timeout, and finishes after 6 s: before the fix
    every reader waited it out and returned a normal 120-byte body. Wanted: the deadline
    (a multiple of the read timeout) cuts the read, the caller sees it incomplete, and the
    connection is dropped (the peer could not send the whole body)."""
    got = _outcome(READERS[reader][0], peer.url, READERS[reader][1])
    assert got == "incomplete (deadline)", got
    assert peer.done.wait(10), "the peer kept sending"
    assert peer.sent < DRIP_BYTES and peer.requests == 1, (peer.sent, peer.requests)


@pytest.mark.parametrize("peer", ["bomb"], indirect=True)
@pytest.mark.parametrize("reader", sorted(READERS))
def test_a_gzip_bomb_stops_at_the_decoded_ceiling_and_is_never_taken_whole(peer, reader):
    """Defect 21: a 40 KiB gzip body decoding to 40 MiB was decoded whole and returned as
    a normal body. Wanted: decoding stops at the decoded ceiling, typed incomplete."""
    got = _outcome(READERS[reader][0], peer.url, READERS[reader][1])
    assert got == "incomplete (decoded)", got
    assert peer.requests == 1
    from fuzzlab.core import bodyread              # the bomb is what it claims to be
    assert len(_bomb()) < bodyread.MAX_WIRE_BYTES < BOMB_DECODED
    assert bodyread.MAX_DECODED_BYTES < BOMB_DECODED


@pytest.mark.parametrize("peer", ["drip"], indirect=True)
def test_the_contract_runner_cuts_a_dripped_body_at_its_deadline(peer):
    """BUG-0528's residual R6: the runner's own read checked ``timeout_ms`` only between
    ``iter_content`` steps, so a drip held it until the peer stopped (measured there: 3 s
    for a 1 s deadline). Through the one reader the deadline cuts it: an ``error``, and
    the peer could not send its whole body."""
    [res] = _run_contract(peer)
    assert res["verdict"] == "error" and "timed out" in res["reason"], res
    assert peer.done.wait(10)
    assert peer.sent < DRIP_BYTES, peer.sent


@pytest.mark.parametrize("peer", ["bomb"], indirect=True)
def test_decoding_never_holds_more_than_the_ceiling(peer, monkeypatch):
    """Memory, not only the marker: with a 1 MiB ceiling the read of the 40 MiB bomb
    allocates a small multiple of the ceiling at its peak."""
    from fuzzlab.core import bodyread
    monkeypatch.setattr(bodyread, "MAX_DECODED_BYTES", 1 << 20)
    _bomb()                                    # built before the trace starts
    tracemalloc.start()
    try:
        got = _outcome(_core_seam, peer.url)
        _now, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert got == "incomplete (decoded)", got
    assert peak < 6 << 20, peak


@pytest.mark.parametrize("peer", ["drip"], indirect=True)
def test_the_wire_ceiling_cuts_a_body_before_its_deadline(peer, monkeypatch):
    from fuzzlab.core import bodyread
    monkeypatch.setattr(bodyread, "MAX_WIRE_BYTES", 10)
    assert _outcome(_core_seam, peer.url) == "incomplete (wire)"


def test_a_whole_body_reads_as_before_through_every_coding():
    """Pin: identity, gzip (two members), zlib- and raw-deflate and brotli bodies read
    whole, decoded, with their text, as requests did."""
    import zlib
    from fuzzlab.core import bodyread
    text = ("héllo " * 5000).encode()
    raw_deflate = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    bodies = {"identity": text, "gzip": gzip.compress(text[:7]) + gzip.compress(text[7:]),
              "deflate": zlib.compress(text),
              "x-gzip": gzip.compress(text)}
    raw = raw_deflate.compress(text) + raw_deflate.flush()
    cases = [(k, v) for k, v in bodies.items()] + [("deflate", raw)]
    try:
        import brotli
        cases.append(("br", brotli.compress(text)))
    except ImportError:            # pragma: no cover - brotli ships with requests' extras
        pass
    for coding, body in cases:
        resp = _Canned(body, coding)
        got = bodyread.read_body(resp, deadline=time.monotonic() + 30)
        assert got.complete and got.data == text and got.wire == len(body), coding


def _codings(body: bytes) -> dict[str, bytes]:
    import zlib
    raw = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
    out = {"gzip": gzip.compress(body), "deflate": zlib.compress(body),
           "raw deflate": raw.compress(body) + raw.flush()}
    try:
        import brotli
        out["br"] = brotli.compress(body)
    except ImportError:            # pragma: no cover
        pass
    return out


@pytest.mark.parametrize("cut", [0, 1, 4096])
def test_decoding_stops_exactly_at_the_ceiling_whatever_the_coding(cut):
    """The drain loop at the boundary: a 1 MiB compressible body, fed in 777-byte
    receives, is complete with a ceiling of exactly its size and incomplete
    (``decoded``) one byte -- or a page -- below it, holding exactly the ceiling."""
    from fuzzlab.core import bodyread
    body = b"".join(b"%08d fuzzlab " % i for i in range(1 << 20 >> 4))[:1 << 20]
    for name, wire in _codings(body).items():
        resp = _Canned(wire, "deflate" if "deflate" in name else name)
        cap = len(body) - cut
        got = bodyread.read_body(resp, deadline=time.monotonic() + 60,
                                 limits=bodyread.Limits(wire=1 << 30, decoded=cap))
        if cut:
            assert (got.complete, got.reason, got.data) == (False, "decoded", body[:cap]), name
        else:
            assert got.complete and got.data == body, name


class _Raw:
    """A urllib3-like raw stream over ``data``: ``read1`` hands out small pieces."""

    def __init__(self, data: bytes, piece: int = 777):
        self.data, self.at, self.piece = data, 0, piece

    def read1(self, amt=None, decode_content=None):
        assert decode_content is False
        out = self.data[self.at:self.at + min(self.piece, amt or self.piece)]
        self.at += len(out)
        return out


class _Canned:
    def __init__(self, body: bytes, coding: str = "identity"):
        self.raw = _Raw(body)
        self.headers = {"Content-Encoding": coding} if coding != "identity" else {}

    def close(self):
        pass


def test_an_undecodable_or_unbounded_coding_is_never_a_body():
    """A corrupt gzip is a decoding error (SP-34: not observed); a coding the reader
    cannot bound (zstd, a chain) is incomplete -- fail closed, never passed through as
    text."""
    from fuzzlab.core import bodyread
    with pytest.raises(requests.exceptions.ContentDecodingError):
        bodyread.read_body(_Canned(b"not gzip at all", "gzip"), deadline=time.monotonic() + 9)
    for coding in ("zstd", "gzip, br"):
        got = bodyread.read_body(_Canned(b"whatever", coding), deadline=time.monotonic() + 9)
        assert not got.complete and got.reason == "encoding", coding
    unknown = bodyread.read_body(_Canned(b"as sent", "compress"), deadline=time.monotonic() + 9)
    assert unknown.complete and unknown.data == b"as sent"     # requests' own pass-through


def _codings_sent(peer, send) -> set[str]:
    send(peer.url)
    return {t.split(";")[0].strip() for t in peer.accept[-1].split(",") if t.strip()}


@pytest.mark.parametrize("peer", ["echo"], indirect=True)
def test_a_bounded_send_advertises_only_codings_it_can_bound(peer, monkeypatch):
    """Review item 2: urllib3's default ``Accept-Encoding`` names ``br`` with any Brotli
    (brotlicffi included) and ``zstd`` on Python 3.14; the reader refuses both there, so
    every answer would be incomplete. A host with both and no bounded Brotli is
    simulated: every bounded send -- the core seam, the probe sender, the static fetch
    and the contract runner -- asks for gzip and deflate only."""
    from fuzzlab.core import bodyread
    from fuzzlab.core.http import Request
    monkeypatch.setattr(requests.utils, "DEFAULT_ACCEPT_ENCODING", "gzip, deflate, br, zstd")
    monkeypatch.setattr(bodyread, "_bounded_brotli", lambda: None)
    assert "zstd" in requests.Session().headers["Accept-Encoding"]       # the premise
    want = {"gzip", "deflate"}
    assert _codings_sent(peer, _core_seam) == want
    assert _codings_sent(peer, _anonymous_probe) == want
    assert _codings_sent(peer, _static_fetch) == want
    _run_contract(peer)
    assert {t.strip() for t in peer.accept[-1].split(",")} == want
    # a caller's own bounded choice is kept; one naming an unbounded coding is not
    seam = _client(TIMEOUT)
    assert _codings_sent(peer, lambda u: seam.send(Request(
        "GET", u, headers={"Accept-Encoding": "gzip"}))) == {"gzip"}
    assert _codings_sent(peer, lambda u: seam.send(Request(
        "GET", u, headers={"accept-encoding": "br, zstd"}))) == want


@pytest.mark.parametrize("peer", ["echo"], indirect=True)
def test_brotli_is_advertised_when_it_can_be_bounded(peer):
    from fuzzlab.core import bodyread
    want = {"gzip", "deflate"} | ({"br"} if bodyread._bounded_brotli() else set())
    assert _codings_sent(peer, _core_seam) == want
    assert bodyread.advertise({"Accept-Encoding": "*"}) == {
        "Accept-Encoding": bodyread.accept_encoding()}


def test_a_response_already_read_is_its_kept_body_never_an_empty_one():
    """Review 4(a): its raw stream is spent, so a read returned b"" as a complete body.
    Its kept content is the body; a body read and not kept is an error."""
    from fuzzlab.core import bodyread
    resp = requests.Response()
    resp.raw, resp.headers = _Raw(b""), requests.structures.CaseInsensitiveDict()
    resp._content, resp._content_consumed = b"kept", True
    got = bodyread.read_body(resp, deadline=time.monotonic() + 9)
    assert (got.complete, got.data) == (True, b"kept")
    resp._content = False
    with pytest.raises(RuntimeError):
        bodyread.read_body(resp, deadline=time.monotonic() + 9)


@pytest.mark.parametrize("peer", ["sizeline"], indirect=True)
def test_a_dripped_chunk_size_line_is_cut_at_the_deadline(peer):
    """Review R1: ``http.client`` reads a chunk-size line in one call (measured: a
    dripped one held ``read1`` and ``iter_content`` alike for 2.01 s), so the read loop
    alone saw the deadline only once the line was whole. The watchdog shuts the socket
    at the deadline: the peer cannot send the whole line."""
    assert _outcome(_core_seam, peer.url) == "incomplete (deadline)"
    assert peer.done.wait(10)
    assert peer.sent < SIZELINE_BYTES, peer.sent


@pytest.mark.parametrize("peer", ["head"], indirect=True)
@pytest.mark.parametrize("reader", sorted(READERS))
def test_a_dripped_status_line_and_headers_are_cut_at_the_deadline(peer, reader):
    """Review R1 (measured by the reviewer: 6 s against a 1 s deadline): before the
    response exists, ``http.client`` reads the status line and headers line by line, each
    receive inside the read timeout. One process-wide watchdog shuts the socket of a
    bounded send still open at its deadline: incomplete (``deadline``), and the peer
    could not send its whole head."""
    got = _outcome(READERS[reader][0], peer.url, READERS[reader][1])
    assert got == "incomplete (deadline)", got
    assert peer.done.wait(10)
    assert peer.sent < len(HEAD_DRIP), peer.sent


@pytest.mark.parametrize("peer", ["head"], indirect=True)
def test_the_contract_runner_cuts_a_dripped_head_at_its_deadline(peer):
    """The runner streams and reads itself; its session is watched, so the same
    watchdog cuts a dripped head at ``timeout_ms`` (a ``deadline`` timeout)."""
    [res] = _run_contract(peer)
    assert res["verdict"] == "error" and "timed out" in res["reason"], res
    assert peer.done.wait(10)
    assert peer.sent < len(HEAD_DRIP), peer.sent


@pytest.mark.parametrize("peer", ["silent"], indirect=True)
def test_a_send_with_no_timeout_is_still_cut_at_its_deadline(peer, monkeypatch):
    """Review 4(d): with ``timeout=None`` the socket has no timeout at all; the deadline
    (`DEFAULT_SECONDS`, narrowed here) is enforced by the watchdog alone."""
    from fuzzlab.core import bodyread
    from fuzzlab.core.http import Request
    monkeypatch.setattr(bodyread, "DEFAULT_SECONDS", 1.0)
    with _smoke_alarm(30):
        with pytest.raises(requests.RequestException) as info:
            _client(None).send(Request("GET", peer.url))
    assert _incomplete(info.value) == "deadline", repr(info.value)
    assert peer.done.wait(10)


@pytest.mark.xfail(strict=True, reason=(
    "BUG-0536 sweep: the session manager's login fetcher "
    "(fuzzlab/session/manager.py::_requests_fetch_factory) reads r.text unbounded; "
    "fuzzlab/session/* is AU-SESS403's (lane boundary), fixed there with "
    "bodyread.bound(requests.Session())"))
@pytest.mark.parametrize("peer", ["bomb"], indirect=True)
def test_the_session_managers_login_fetch_is_bounded(peer):
    from fuzzlab.session.manager import _requests_fetch_factory
    fetcher = _requests_fetch_factory()()
    with pytest.raises(requests.RequestException) as info:
        fetcher.get(peer.url)
    assert _incomplete(info.value) == "decoded"


# --- what a caller does with an incomplete body ---------------------------------------------

@pytest.mark.parametrize("peer", ["bomb"], indirect=True)
def test_greybox_never_scores_records_or_adopts_an_incomplete_probe(peer, monkeypatch,
                                                                    tmp_path):
    """Review item 1 (measured by the reviewer: `_screening` gave 0.5): greybox made an
    incomplete body a status-0 probe whose error text it then scored as a boolean
    divergence, recorded, accepted as a mutation variant and could adopt as the point's
    baseline. Here the baseline and every mutation variant meet the gzip bomb; the one
    attack answers 500 bytes. Wanted: the incomplete ones are counted, never an attempt
    or a variant, and the attack is scored with no baseline (screening 0)."""
    from fuzzlab.core import bodyread
    from fuzzlab.core.store import Store
    from fuzzlab.greybox.run import (GreyboxPoint, ProbeSpec, RequestsCorrelatingSender,
                                     mutation_variant_probes, run_greybox)
    from fuzzlab.oracle.probe import Probe
    monkeypatch.setattr(bodyread, "MAX_DECODED_BYTES", 1 << 20)
    attack = ProbeSpec("sqli-error", "1' OR 1=1 -- -", "sqli")
    probes = (ProbeSpec("baseline", "1", "baseline"), attack)
    variants = len(mutation_variant_probes([attack], max_variants=2))
    assert variants >= 1
    real = RequestsCorrelatingSender(timeout=5.0, id_factory=lambda: "c")

    class Sender:                    # the attack answered; everything else meets the bomb
        def send_correlated(self, url, param, value, **kw):
            if value == attack.value:
                return Probe(200, "y" * 500), "attack"
            return real.send_correlated(url, param, value, **kw)

    class Nothing:
        def lines_for(self, cid):
            return {}

        def fault_for(self, cid):
            from fuzzlab.greybox.dbfault import DbFault
            return DbFault(faulted=False)

    with Store(tmp_path / "g.db") as store:
        run_id = store.start_run("greybox", "h")
        summary = run_greybox(base_url=peer.url, store=store, run_id=run_id,
                              points=[GreyboxPoint(peer.url, "q", "GET", "query", "sqli")],
                              sender=Sender(), coverage_source=Nothing(),
                              dbfault_source=Nothing(), probes=probes,
                              mutation_variants=True, max_mutation_variants=2)
        rows = [json.loads(r[0]) for r in store.conn.execute(
            "SELECT features_json FROM attempt WHERE run_id=?", (run_id,))]
        accepted = store.conn.execute("SELECT COUNT(*) FROM payload_variant WHERE "
                                      "run_id=?", (run_id,)).fetchone()[0]
    assert summary.get("unobserved") == 1 + variants, summary
    assert [r["payload_kind"] for r in rows] == ["sqli"], rows
    assert rows[0]["screening"] == 0.0, rows          # no incomplete baseline adopted
    assert summary["mutation_variants_recorded"] == 0 and accepted == 0


def test_a_blind_sqli_payload_with_a_failed_repeat_is_never_a_row():
    """Review 4(b): a request error on repeat 2 kept repeat 1's latency and wrote a
    row from it (``repeats`` 1). The payload's samples are incomplete: no row."""
    import types

    from fuzzlab.core.bodyread import BodyIncomplete
    from fuzzlab.tools.blind_sqli_fuzzer import Answer, run_fuzzing_cycle
    answers = [Answer(5.4, 200, 100), BodyIncomplete("deadline")]

    class Get:
        def get(self, url, param, value, timeout):
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

    args = types.SimpleNamespace(sigma=3.0, min_delay=2.0, repeats=2, timeout=5, pause=0)
    base = {"avg_time": 0.3, "std_dev_time": 0.01, "avg_size": 100, "samples": 10}
    payloads = [{"text": "1' AND SLEEP(5)-- -", "family": "time", "is_malicious": 1,
                 "expected_delay": 5}]
    assert run_fuzzing_cycle(Get(), "http://127.0.0.1:9/item", "id", base, payloads,
                             args) == []


# --- the guard: every requests session fuzzlab makes is bounded (SP-60) ---------------------

_SENDS = {"request", "get", "post", "put", "patch", "delete", "head", "options"}

#: file -> (requests.Session() / requests.<verb>() calls not bounded at the call, reason).
#: Exact counts: a new unbounded site fails, and so does a stale entry.
UNBOUNDED_ALLOWED: dict[str, tuple[int, str]] = {
    "fuzzlab/disco/runner.py": (1, "its session is bodyread.watched; Runner.send streams each "
                                   "answer inside a bodyread.watch and reads it through "
                                   "read_body with the contract's own limits"),
    "fuzzlab/tools/fetcher.py": (1, "its one read is navguard.get_checked, which bounds the "
                                    "session it is given (AUD component: this item has no "
                                    "CC-AUD number)"),
    "fuzzlab/session/manager.py": (1, "AU-SESS403's file: pinned by "
                                      "test_the_session_managers_login_fetch_is_bounded"),
    "fuzzlab/lab_fixtures/external.py": (2, "lab provisioning of the operator's own pinned "
                                            "containers and the pinned-size bWAPP download, "
                                            "never a crawl or probe (LAB component)"),
    "fuzzlab/labgen/identifier_sqli_oracle.py": (2, "the conformance oracle of an app this "
                                                    "project generated and booted, never a "
                                                    "target (LAB component)"),
}


def unbounded_sites(src: str) -> list[int]:
    """Line numbers of ``requests.Session()`` and ``requests.<verb>(...)`` calls (however
    ``requests`` is imported) that are not the argument of a ``bound(...)`` call."""
    tree = ast.parse(src)
    names = {"requests"}
    direct: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.asname or a.name for a in node.names if a.name == "requests"}
        elif isinstance(node, ast.ImportFrom) and node.module in ("requests",
                                                                   "requests.sessions"):
            direct |= {a.asname or a.name for a in node.names
                       if a.name in _SENDS | {"Session", "session"}}
    bounded = {id(arg) for node in ast.walk(tree) if isinstance(node, ast.Call)
               and (getattr(node.func, "attr", None) or getattr(node.func, "id", None))
               == "bound" for arg in node.args}
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or id(node) in bounded:
            continue
        f = node.func
        hit = (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
               and f.value.id in names and f.attr in _SENDS | {"Session"}) or \
            (isinstance(f, ast.Name) and f.id in direct)
        if hit:
            out.append(node.lineno)
    return out


def test_every_requests_session_fuzzlab_makes_is_bounded():
    found = {}
    for path in sorted((ROOT / "fuzzlab").rglob("*.py")):
        sites = unbounded_sites(path.read_text(encoding="utf-8"))
        if sites:
            found[path.relative_to(ROOT).as_posix()] = len(sites)
    expected = {k: n for k, (n, _why) in UNBOUNDED_ALLOWED.items()}
    assert found == expected, (
        "every requests.Session() / requests.<verb>() a module of fuzzlab makes reads "
        "bodies through core.bodyread (bodyread.bound(requests.Session()), SP-60, "
        f"BUG-0536), or is listed here with its reason: {found} != {expected}")


def test_the_session_guard_catches_synthetic_offenders():
    offenders = ("import requests\ns = requests.Session()\n",
                 "import requests as rq\nrq.get('http://h/')\n",
                 "from requests import Session\nSession()\n",
                 "from requests import post as p\np('http://h/')\n",
                 "import requests\nx = bodyread.bounded(requests.Session())\n")
    for src in offenders:
        assert unbounded_sites(src) == [2], src
    for src in ("import requests\ns = bodyread.bound(requests.Session())\n",
                "import requests\ns = bound(requests.Session())\n",
                "import requests\nr = requests.Response()\n"):
        assert unbounded_sites(src) == [], src


# --- defect 23: JsonlTail --------------------------------------------------------------------

def _good(n: int) -> bytes:
    from fuzzlab.disco.capture import make_record
    return make_record(kind="http", t=float(n), action_id=None, method="GET",
                       url=f"http://h/{n}", req_headers={}, req_body=None).to_json().encode()


def test_an_unterminated_line_over_the_cap_is_quarantined_once_and_never_held(
        tmp_path, monkeypatch):
    """Defect 23 (reproduced: 4 194 404 bytes held past a 4 194 304 cap, nothing
    yielded): the cap was checked only on a complete line. Wanted: the line is
    quarantined once as soon as it passes the cap, its bytes dropped, the rest of it
    discarded across reads, and reading resumes at the next line."""
    from fuzzlab.disco import capture
    monkeypatch.setattr(capture, "MAX_LINE_BYTES", 1000)
    path = tmp_path / "capture.jsonl"
    path.write_bytes(_good(1) + b"\n" + b"x" * 1100)
    tail = capture.CaptureTail(path)
    assert [i for i, _r in tail.read()] == [0] and tail.quarantined == 1
    assert len(tail._lines._rest) <= 1000
    with path.open("ab") as fh:
        fh.write(b"y" * 5000)
    assert tail.read() == [] and tail.quarantined == 1 and len(tail._lines._rest) == 0
    with path.open("ab") as fh:
        fh.write(b"z\n" + _good(2) + b"\n")
    assert [i for i, _r in tail.read()] == [1] and tail.quarantined == 1
    whole = capture.read_capture(path)                   # the import agrees
    assert len(whole.records) == 2 and whole.quarantined == 1


def test_a_line_of_exactly_the_cap_is_kept_and_one_byte_more_is_not(tmp_path, monkeypatch):
    """Pin the old boundary: a line (newline included) over the cap is quarantined; an
    unterminated last line of exactly the cap is read (``final``)."""
    from fuzzlab.disco import capture
    line = _good(1)
    monkeypatch.setattr(capture, "MAX_LINE_BYTES", len(line))
    (tmp_path / "a").write_bytes(line + b"\n" + _good(2) + b"\n")
    assert capture.read_capture(tmp_path / "a").quarantined == 2
    (tmp_path / "b").write_bytes(line)
    assert len(capture.read_capture(tmp_path / "b").records) == 1


def test_the_action_log_numbers_an_over_cap_line_as_one_malformed_line(tmp_path, monkeypatch):
    from fuzzlab.disco import capture
    from fuzzlab.tools.observe import DiscoActionLines
    monkeypatch.setattr(capture, "MAX_LINE_BYTES", 100)
    path = tmp_path / "actions.jsonl"
    path.write_bytes(b'{"seq": 1}\n' + b"q" * 250)
    lines = DiscoActionLines(path)
    assert lines.read() == [(1, {"seq": 1}), (2, None)]
    with path.open("ab") as fh:
        fh.write(b"q" * 250 + b'\n{"seq": 2}\n')
    assert lines.read() == [(3, {"seq": 2})]


def test_an_over_cap_line_costs_bounded_memory(tmp_path, monkeypatch):
    """16 MiB without a newline, a 64 KiB cap: the reader's peak allocation stays a
    small multiple of one file read, not the line."""
    from fuzzlab.disco import capture
    monkeypatch.setattr(capture, "MAX_LINE_BYTES", 64 << 10)
    path = tmp_path / "capture.jsonl"
    path.write_bytes(b"x" * (16 << 20))
    tail = capture.CaptureTail(path)
    tracemalloc.start()
    try:
        tail.read()
        _now, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert tail.quarantined == 1 and peak < 4 << 20, peak


def _copy_factor(tail, path: Path, line_bytes: int, appends: int) -> float:
    """Bytes the tail copied per byte it read, for one long line appended in ``appends``
    pieces with a read after each (the live trace's poll)."""
    piece = b"x" * (line_bytes // appends)
    for _ in range(appends):
        with path.open("ab") as fh:
            fh.write(piece)
        tail.read()
    with path.open("ab") as fh:
        fh.write(b"\n")
    tail.read()
    return tail.copied / (len(piece) * appends + 1)


def test_reading_a_long_line_in_small_pieces_copies_each_byte_a_bounded_number_of_times(
        tmp_path, monkeypatch):
    """Defect 23: ``_rest + data`` copied the held bytes again on every read: quadratic
    in the line (PA-0135: an operation count, never a timing ratio)."""
    from fuzzlab.disco import capture
    monkeypatch.setattr(capture, "READ_CHUNK", 4096)
    path = tmp_path / "c.jsonl"
    path.write_bytes(b"")
    assert _copy_factor(capture.JsonlTail(path), path, 2 << 20, 512) <= 3


def test_the_copy_oracle_flags_a_quadratic_tail(tmp_path, monkeypatch):
    """PA-0135(3): the oracle above, on the pre-fix algorithm (``_rest + data`` per read,
    counted honestly), reports the quadratic copying."""
    from fuzzlab.disco import capture

    class Quadratic(capture.JsonlTail):
        held = b""

        def lines(self, final=False):
            with open(self.path, "rb") as fh:
                fh.seek(self.offset)
                while True:
                    data = fh.read(capture.READ_CHUNK)
                    if not data:
                        break
                    self.offset += len(data)
                    buf = self.held + data           # the held bytes, copied again
                    self.copied += len(buf)
                    cut = buf.rfind(b"\n") + 1
                    self.held = buf[cut:]
                    if cut:
                        for ln in buf[:cut - 1].split(b"\n"):
                            yield ln + b"\n"

    monkeypatch.setattr(capture, "READ_CHUNK", 4096)
    path = tmp_path / "c.jsonl"
    path.write_bytes(b"")
    assert _copy_factor(Quadratic(path), path, 2 << 20, 512) > 100


# --- defect 27: contract regexes -------------------------------------------------------------

class _SmokeAlarm(Exception):
    pass


@contextlib.contextmanager
def _smoke_alarm(seconds: float):
    """A generous absolute bound (PA-0135, PA-0526): ``re`` checks signals while it
    backtracks, so the alarm interrupts a runaway match in this thread."""
    def ring(_signum, _frame):
        raise _SmokeAlarm(f"still running after {seconds} s")
    old = signal.signal(signal.SIGALRM, ring)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _judge_body(pattern: str, body: bytes, monkeypatch) -> dict:
    from fuzzlab.disco import runner as runner_mod
    from tests.test_disco_runner_outcomes import ORDER, Resp, one_case, run_one
    monkeypatch.setattr(runner_mod, "MATCH_SECONDS", 2.0, raising=False)
    doc = one_case(oracle={"expect_status_class": ["2xx"],
                           "findings_if": [{"body_matches": [pattern]}]}, auth="anon")
    _r, [res] = run_one(doc, {ORDER: lambda u, kw: Resp(
        200, [body], headers={"Content-Type": "text/plain"})})
    return res


def test_a_catastrophic_pattern_is_an_error_never_a_hang_nor_a_no_match(monkeypatch):
    """Defect 27: ``(a+)+$`` against ``a`` x 36 + ``!`` backtracks about 2^36 times (the
    audit measured 1.09 s at 24). The runner matched it in its own thread, unbounded.
    Wanted: the match is killed at its limit and the case is an ``error``
    (inconclusive), well inside a 60 s smoke alarm."""
    with _smoke_alarm(60):
        res = _judge_body(r"(a+)+$", b"a" * 36 + b"!", monkeypatch)
    assert res["verdict"] == "error" and "body_matches" in res["reason"], res
    assert "matched" in res and res["matched"] == []


def test_body_matches_still_match_and_miss_through_the_worker(monkeypatch):
    """Pin: a pattern that matches is a finding; one that does not is a pass."""
    hit = _judge_body(r"(?i)TRACEBACK", b"debug: a traceback follows", monkeypatch)
    assert hit["verdict"] == "finding" and hit["matched"] == ["body_matches"], hit
    miss = _judge_body(r"SQLSTATE\[", b'{"id": 3}', monkeypatch)
    assert miss["verdict"] == "pass", miss


_RE_FUNCS = {"search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split",
             "compile"}


def in_process_patterns(src: str) -> list[str]:
    """Calls of ``re`` (however imported) whose pattern is not a literal: a search on a
    pattern, or a compile -- which covers ``re.compile(rx).search(t)`` and a compiled
    pattern kept in a name. Allowed: compiling the reviewed ``LEAK_PATTERNS``
    constants (``[re.compile(p) for p in LEAK_PATTERNS]``)."""
    tree = ast.parse(src)
    modules, funcs = {"re"}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {a.asname or a.name for a in node.names if a.name == "re"}
        elif isinstance(node, ast.ImportFrom) and node.module == "re":
            funcs |= {a.asname or a.name for a in node.names if a.name in _RE_FUNCS}
    allowed = {id(elt) for comp in ast.walk(tree) if isinstance(comp, ast.ListComp)
               and any(isinstance(g.iter, ast.Name) and g.iter.id == "LEAK_PATTERNS"
                       for g in comp.generators) for elt in [comp.elt]}
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call) or id(n) in allowed:
            continue
        f = n.func
        hit = (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
               and f.value.id in modules and f.attr in _RE_FUNCS) or \
            (isinstance(f, ast.Name) and f.id in funcs)
        if hit and not (n.args and isinstance(n.args[0], ast.Constant)):
            out.append(ast.unparse(n))
    return out


def test_the_matcher_never_runs_a_contract_pattern_in_the_runners_process():
    """Every ``body_matches`` search goes through the bounded worker: no ``re`` search
    or compile of a non-literal pattern in `runner.py` (the runner's own
    ``LEAK_PATTERNS`` are reviewed constants, compiled once)."""
    src = (ROOT / "fuzzlab/disco/runner.py").read_text(encoding="utf-8")
    assert in_process_patterns(src) == [], "a contract pattern matched in-process"


def test_the_matcher_guard_catches_synthetic_offenders():
    """PA-0034(2), review 4(c): the first guard saw only ``re.<fn>(rx, ...)``."""
    offenders = ("import re\nre.search(rx, text)\n",
                 "import re\nre.compile(rx).search(text)\n",
                 "import re\npat = re.compile(rule['body_matches'][0])\npat.match(t)\n",
                 "import re as regex\nregex.fullmatch(p, t)\n",
                 "from re import finditer as fi\nfi(p, t)\n")
    for src in offenders:
        assert len(in_process_patterns(src)) == 1, src
    for src in ("import re\nre.search(r'\\{p\\d+\\}', path)\n",
                "import re\n_LEAK = [re.compile(p) for p in LEAK_PATTERNS]\n",
                "import re\nre.escape(x)\n"):
        assert in_process_patterns(src) == [], src


@pytest.mark.xfail(strict=True, raises=_SmokeAlarm, reason=(
    "BUG-0536 sweep, residual R3: disco/formfill.py::_fits runs a page's own `pattern` "
    "attribute (target-controlled) with re.fullmatch on a generated value, in the "
    "explorer's thread; bounded only by the value's length. Flagged to the owner"))
def test_formfill_never_runs_a_pages_pattern_unbounded():
    from fuzzlab.disco.formfill import _fits
    with _smoke_alarm(5):
        assert _fits("a" * 32 + "!", {"pattern": "(a+)+"}) is False


def test_the_worker_payload_is_json_and_its_answer_is_shape_checked(monkeypatch):
    """A worker that answers anything but one boolean per pattern and text is no answer
    (None), never a match or a miss."""
    from fuzzlab.disco import runner as runner_mod
    assert runner_mod.search_bounded(["a", "b"], ["xa", "yb"]) == [[True, False],
                                                                  [False, True]]
    assert runner_mod.search_bounded([], ["x"]) == []

    class Done:
        returncode, stdout = 0, json.dumps([[True]])
    monkeypatch.setattr("fuzzlab.procutil.run_bounded", lambda *a, **k: Done())
    assert runner_mod.search_bounded(["a", "b"], ["x"]) is None
