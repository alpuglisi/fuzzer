"""Bounded reads of a target's HTTP response body (SP-60, FR-CORE-536; BUG-0536).

The one owner of reading a response body from a target over ``requests``. A body is read
under three limits, each checked inside the read loop:

- **wire bytes** (`MAX_WIRE_BYTES`): the body as it crossed the wire, after transfer
  coding (chunks) and before content coding -- a gzip body's compressed bytes;
- **decoded bytes** (`MAX_DECODED_BYTES`): after content decoding, which is incremental
  with an output ceiling per step (zlib's ``max_length``, Brotli's
  ``output_buffer_limit``), so a small compressed body never expands past the ceiling in
  memory;
- **a wall-clock deadline**: each read is one receive (urllib3's ``read1``), and the
  deadline is checked before each; a body that ends after it is late too. A ``requests``
  timeout is per receive, not a total (measured: a body dripped a byte every 50 ms under
  a 1 s timeout took 1.96 s in one ``iter_content`` step; ``read1`` returned each byte).
  What ``http.client`` reads in one call -- the status line, the headers, a chunked
  body's chunk-size and trailer lines -- is cut by **one process-wide watchdog thread**
  (`watch`): a socket a watched exchange still uses at its deadline is shut down
  (``SHUT_RDWR``), so the blocked receive returns and the exchange is incomplete
  (``deadline``). A send with no timeout is covered the same way.

`read_body` returns a typed `Body`: ``complete``, or the ``reason`` it is not (`REASONS`). An
incomplete body is never a short one: `bound`'s adapter raises `BodyIncomplete` (a
``requests.RequestException``, so every transport-failure handler sees it, and SP-34's
``probesender._unobserved`` makes it "not observed"); the contract runner reads `Body`
itself (FR-FUZZ-52).

`bound(session)` applies `read_body` to every response a ``requests.Session`` gets, with a
deadline of `DEADLINE_TIMEOUTS` x the request's read timeout (`DEFAULT_SECONDS` without
one), watched. Every session fuzzlab makes for a target is bounded where it is made
(``tests/test_bounded_reads.py`` guard); the contract runner's session is `watched` and
reads with `read_body` under its own limits.

Content codings, as urllib3 decodes them: identity; ``gzip`` / ``x-gzip`` (several
members; bytes after a whole member ignored); ``deflate`` (zlib-wrapped or raw); ``br``
with a Brotli that bounds its output (``Decompressor.process(..., output_buffer_limit)``,
Brotli >= 1.2). A coding urllib3 has no decoder for is passed through undecoded, as
urllib3 does. ``br`` without such a Brotli, ``zstd`` and a chain of codings are
incomplete (``"encoding"``): fail closed, never handed on as text. So a bounded send
**advertises only what it can decode** (`advertise`): urllib3's default
``Accept-Encoding`` names ``br`` with any Brotli and ``zstd`` on Python 3.14, and a
request naming such a coding gets `accept_encoding` instead; a bounded one is kept.

Stated limit: the connect (and a TLS handshake) is bounded by the connect timeout only --
a socket shutdown does not interrupt a connect -- so a send with no timeout to a host
that never answers its SYN is not cut.
"""

from __future__ import annotations

import contextlib
import functools
import heapq
import itertools
import socket
import threading
import time
import zlib
from dataclasses import dataclass
from typing import Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

#: Body bytes as they crossed the wire (content-coded), at most.
MAX_WIRE_BYTES = 16 << 20
#: Body bytes after content decoding, at most.
MAX_DECODED_BYTES = 32 << 20
#: A response must arrive whole within this many of its request's read timeouts ...
DEADLINE_TIMEOUTS = 4
#: ... or within this many seconds when the request has none.
DEFAULT_SECONDS = 60.0
#: The most one receive asks for.
READ_SIZE = 64 << 10

#: Why a body is incomplete.
REASONS = {"wire": "over the wire-byte ceiling",
           "decoded": "over the decoded-byte ceiling",
           "deadline": "the deadline passed before it ended",
           "encoding": "a content coding with no bounded decoder"}


@dataclass(frozen=True)
class Limits:
    wire: int
    decoded: int


def default_limits() -> Limits:
    """The module's ceilings, read when called (tests narrow them)."""
    return Limits(MAX_WIRE_BYTES, MAX_DECODED_BYTES)


@dataclass(frozen=True)
class Body:
    """What `read_body` read: ``data`` (at most the decoded ceiling), ``complete``, the
    ``reason`` (a `REASONS` key) when it is not, and the ``wire`` bytes received."""
    data: bytes
    complete: bool
    reason: str | None = None
    wire: int = 0


class BodyIncomplete(requests.exceptions.RequestException):
    """A body read stopped before its end (``reason``: a `REASONS` key). Never a short
    body: the response is closed and its connection dropped. The message names the
    reason only, never a URL or a byte of the body."""

    def __init__(self, reason: str, *, wire: int = 0, decoded: int = 0):
        super().__init__(f"incomplete body: {REASONS[reason]}")
        self.reason, self.wire, self.decoded = reason, wire, decoded


# --- content decoding, one bounded step at a time ------------------------------------------

class _DecodeFailed(Exception):
    pass


class _Identity:
    def step(self, data: bytes, limit: int) -> bytes:
        return data

    def more(self) -> bool:
        return False


class _Inflate:
    """gzip (every member; bytes after a whole member are ignored) or deflate (zlib-
    wrapped, else raw, decided on its first bytes), as urllib3 decodes them. ``step``
    returns at most ``limit`` bytes; input it could not use yet is kept for ``more``."""

    def __init__(self, gzip: bool):
        self._gzip = gzip
        self._d = zlib.decompressobj(16 + zlib.MAX_WBITS if gzip else zlib.MAX_WBITS)
        self._first = None if gzip else bytearray()    # deflate: kept until it decodes
        self._tail = b""
        self._members = 0
        self._done = False

    def more(self) -> bool:
        return bool(self._tail) and not self._done

    def step(self, data: bytes, limit: int) -> bytes:
        if self._tail:
            data, self._tail = self._tail + data, b""
        if self._done or not data:
            return b""
        if self._d.eof:
            if not self._gzip:
                self._done = True                       # after a deflate stream's end
                return b""
            self._members += 1
            self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        if self._first is not None:
            self._first += data
        try:
            out = self._d.decompress(data, limit)
        except zlib.error as exc:
            if self._first is not None:                 # not zlib-wrapped: raw deflate
                first, self._first = bytes(self._first), None
                self._d = zlib.decompressobj(-zlib.MAX_WBITS)
                return self.step(first, limit)
            if self._members:                           # trailing bytes after a member
                self._done = True
                return b""
            raise _DecodeFailed(exc) from exc
        if out and self._first is not None:
            self._first = None
        self._tail = self._d.unconsumed_tail or (self._d.unused_data if self._d.eof
                                                 else b"")
        return out


class _Brotli:
    """Brotli >= 1.2: ``output_buffer_limit`` bounds each step (measured: a piece is at
    most about twice the limit, or 32 KiB); pending output is drained with empty
    input until a step gives nothing."""

    def __init__(self, module):
        self._mod = module
        self._d = module.Decompressor()
        self._pending = False

    def more(self) -> bool:
        return self._pending and not self._d.is_finished()

    def step(self, data: bytes, limit: int) -> bytes:
        try:
            out = self._d.process(data, output_buffer_limit=limit)
        except self._mod.error as exc:
            raise _DecodeFailed(exc) from exc
        self._pending = bool(out)
        return out


@functools.cache
def _bounded_brotli():
    """The ``brotli`` module when it can bound its output, else None (``brotlicffi``,
    which urllib3 also uses, is not one: it has no output limit)."""
    try:
        import brotli
        brotli.Decompressor().process(b"", output_buffer_limit=1)
        return brotli
    except (ImportError, TypeError, AttributeError):
        return None


def accept_encoding() -> str:
    """The ``Accept-Encoding`` a bounded send advertises: the codings `read_body` decodes
    under a ceiling."""
    return "gzip, deflate, br" if _bounded_brotli() is not None else "gzip, deflate"


def _decodable(value) -> bool:
    allowed = {"gzip", "x-gzip", "deflate", "identity"}
    if _bounded_brotli() is not None:
        allowed.add("br")
    tokens = [t.split(";")[0].strip().lower() for t in str(value).split(",")]
    return all(t in allowed for t in tokens if t)


def advertise(headers):
    """Make ``headers`` (a mutable mapping, changed in place and returned) ask only for
    codings `read_body` can bound: an ``Accept-Encoding`` that names another (``zstd``,
    ``br`` without a bounded Brotli, ``*``) is replaced by `accept_encoding`, a missing
    one is set, and a bounded one a caller set is kept."""
    key = next((k for k in list(headers) if str(k).lower() == "accept-encoding"), None)
    if key is not None and _decodable(headers[key]):
        return headers
    if key is not None:
        del headers[key]
    headers["Accept-Encoding"] = accept_encoding()
    return headers


#: Codings urllib3 decodes (and so requests advertises) that this reader cannot bound.
_UNBOUNDED = frozenset({"zstd"})


def _decoder(headers):
    """The decoder for a response's ``Content-Encoding``, or None (incomplete:
    ``encoding``)."""
    coding = next((str(v) for k, v in (headers or {}).items()
                   if str(k).lower() == "content-encoding"), "")
    codings = [c.strip().lower() for c in coding.split(",") if c.strip()]
    codings = [c for c in codings if c != "identity"]
    if not codings:
        return _Identity()
    if len(codings) > 1:
        return None
    c = codings[0]
    if c in ("gzip", "x-gzip"):
        return _Inflate(gzip=True)
    if c == "deflate":
        return _Inflate(gzip=False)
    if c == "br":
        module = _bounded_brotli()
        return _Brotli(module) if module is not None else None
    if c in _UNBOUNDED:
        return None
    return _Identity()                                  # urllib3 passes it through too


def _feed(dec, data: bytes, out: bytearray, cap: int) -> bool:
    """Decode ``data`` into ``out``, never past ``cap`` (+ one step); False when the
    decoded body is over ``cap``."""
    piece = dec.step(data, cap - len(out) + 1)
    while True:
        if len(out) + len(piece) > cap:
            out += piece[:cap - len(out)]
            return False
        out += piece
        if not dec.more():
            return True
        piece = dec.step(b"", cap - len(out) + 1)


# --- reading ---------------------------------------------------------------------------------

def _receiver(resp):
    """One receive of the undecoded body, with urllib3's errors as ``requests`` names
    them (as ``Response.iter_content`` does); or None when ``resp`` has no raw stream."""
    raw = getattr(resp, "raw", None)
    read = getattr(raw, "read1", None)
    if read is None:
        read = getattr(raw, "read", None)
    if read is None:
        return None
    from urllib3.exceptions import DecodeError, ProtocolError, ReadTimeoutError, SSLError

    def receive() -> bytes:
        try:
            return read(READ_SIZE, decode_content=False)
        except ProtocolError as exc:
            raise requests.exceptions.ChunkedEncodingError(exc) from exc
        except DecodeError as exc:
            raise requests.exceptions.ContentDecodingError(exc) from exc
        except ReadTimeoutError as exc:
            raise requests.exceptions.ConnectionError(exc) from exc
        except SSLError as exc:
            raise requests.exceptions.SSLError(exc) from exc
    return receive


def read_body(resp, *, deadline: float, limits: Limits | None = None,
              clock: Callable[[], float] = time.monotonic) -> Body:
    """Read ``resp``'s body (a streamed ``requests.Response``) under ``limits`` (default
    `default_limits`) and ``deadline`` (an instant of ``clock``). A complete body also
    becomes ``resp.content``. Raises what the read raises (a cut or reset connection, a
    read timeout, an undecodable body: ``requests`` exceptions, as ``iter_content``
    names them). Never closes ``resp``: its caller does, on every exit.

    A response with no raw stream (an adapter's or a test's) is read through
    ``iter_content``: its chunks are already decoded, and count on the smaller
    ceiling. A response whose body was already read is its kept ``content`` (under the
    decoded ceiling), never an empty body read from a spent stream; one read and not
    kept raises ``RuntimeError``."""
    lim = limits or default_limits()
    if getattr(resp, "_content_consumed", False) is True:
        kept = getattr(resp, "_content", None)
        if not isinstance(kept, bytes):
            raise RuntimeError("read_body: the body was already read and not kept")
        if len(kept) > lim.decoded:
            return Body(kept[:lim.decoded], False, "decoded", len(kept))
        return Body(kept, True, None, len(kept))
    out = bytearray()
    wire = 0

    def incomplete(reason: str) -> Body:
        return Body(bytes(out), False, reason, wire)

    receive = _receiver(resp)
    if receive is None:
        cap = min(lim.wire, lim.decoded)
        over = "decoded" if lim.decoded <= lim.wire else "wire"
        for chunk in resp.iter_content(READ_SIZE):
            wire += len(chunk)
            if len(out) + len(chunk) > cap:
                out += chunk[:cap - len(out)]
                return incomplete(over)
            out += chunk
            if clock() > deadline:
                return incomplete("deadline")
        return Body(bytes(out), True, None, wire)
    dec = _decoder(getattr(resp, "headers", None))
    if dec is None:
        return incomplete("encoding")
    try:
        while True:
            if clock() >= deadline:
                return incomplete("deadline")
            chunk = receive()
            if not chunk:
                break
            wire += len(chunk)
            if wire > lim.wire:
                return incomplete("wire")
            if not _feed(dec, chunk, out, lim.decoded):
                return incomplete("decoded")
    except _DecodeFailed as exc:
        raise requests.exceptions.ContentDecodingError(exc.__cause__ or exc) \
            from exc.__cause__
    if clock() > deadline:                              # ended, but late
        return incomplete("deadline")
    body = Body(bytes(out), True, None, wire)
    if isinstance(resp, requests.Response):
        resp._content = body.data                       # what .content / .text return
        resp._content_consumed = True
    return body


def deadline_for(timeout) -> float:
    """The deadline of a request sent now with ``requests``' ``timeout`` (a number, a
    ``(connect, read)`` pair, or None)."""
    if isinstance(timeout, tuple):
        timeout = timeout[1] if len(timeout) > 1 else timeout[0]
    try:
        seconds = float(timeout) * DEADLINE_TIMEOUTS
    except (TypeError, ValueError):
        seconds = DEFAULT_SECONDS
    return time.monotonic() + seconds


# --- the watchdog: one thread for every watched exchange ---------------------------------

class _Watch:
    """One exchange's deadline (``time.monotonic``), the sockets it armed, and whether
    the watchdog cut it (``fired``)."""

    def __init__(self, deadline: float):
        self.deadline = deadline
        self.fired = False
        self.entries: list[list] = []
        self.socks: set[int] = set()


class _Watchdog:
    """One process-wide daemon thread (started on first use): at a watched exchange's
    deadline, shuts down (``SHUT_RDWR``) every socket it armed and has not released, so
    a receive blocked in ``http.client`` returns. Entries are ``[socket, watch]``; a
    released one has no socket and is dropped when it reaches the top of the heap."""

    def __init__(self):
        self._cond = threading.Condition()
        self._heap: list = []
        self._seq = itertools.count()
        self._thread: threading.Thread | None = None

    def arm(self, sock, watch: _Watch) -> list:
        with self._cond:
            entry = [sock, watch]
            heapq.heappush(self._heap, (watch.deadline, next(self._seq), entry))
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, daemon=True,
                                                name="fuzzlab-bodyread-watchdog")
                self._thread.start()
            self._cond.notify()
        return entry

    def release(self, entry: list) -> None:
        with self._cond:
            entry[0] = None

    def _run(self) -> None:
        with self._cond:
            while True:
                while self._heap and self._heap[0][2][0] is None:
                    heapq.heappop(self._heap)
                if not self._heap:
                    self._cond.wait()
                    continue
                wait = self._heap[0][0] - time.monotonic()
                if wait > 0:
                    self._cond.wait(wait)
                    continue
                _deadline, _seq, entry = heapq.heappop(self._heap)
                sock, watch = entry
                entry[0] = None
                watch.fired = True
                try:     # the plain socket's shutdown: an SSL socket's own drops its state
                    socket.socket.shutdown(sock, socket.SHUT_RDWR)
                except OSError:
                    pass                                 # already closed


_WATCHDOG = _Watchdog()
_LOCAL = threading.local()


@contextlib.contextmanager
def watch(deadline: float):
    """While open, every socket a watched connection (`WatchedAdapter`) uses on this
    thread is shut down at ``deadline`` (``time.monotonic``) if it is still in use;
    the yielded watch's ``fired`` says it was. Released on exit."""
    w = _Watch(deadline)
    outer = getattr(_LOCAL, "watch", None)
    _LOCAL.watch = w
    try:
        yield w
    finally:
        _LOCAL.watch = outer
        for entry in w.entries:
            _WATCHDOG.release(entry)


def _arm(sock) -> None:
    w = getattr(_LOCAL, "watch", None)
    if w is None or sock is None or id(sock) in w.socks:
        return
    w.socks.add(id(sock))
    w.entries.append(_WATCHDOG.arm(sock, w))


def _watched(base):
    """``base`` (a urllib3 connection class) arming its socket under the thread's
    `watch`: when it connects, and before it sends and reads (a reused connection)."""
    class Watched(base):
        def connect(self):
            super().connect()
            _arm(self.sock)

        def request(self, *args, **kwargs):
            _arm(self.sock)
            return super().request(*args, **kwargs)

        def getresponse(self, *args, **kwargs):
            _arm(self.sock)
            return super().getresponse(*args, **kwargs)
    Watched.__name__ = Watched.__qualname__ = "Watched" + base.__name__
    return Watched


class _WatchedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _watched(HTTPConnection)


class _WatchedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _watched(HTTPSConnection)


_WATCHED_POOLS = {"http": _WatchedHTTPPool, "https": _WatchedHTTPSPool}


class WatchedAdapter(HTTPAdapter):
    """An ``HTTPAdapter`` whose connections are watched (`watch`), direct or through an
    http(s) proxy (a SOCKS proxy keeps its own pools, unwatched)."""

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = _WATCHED_POOLS

    def proxy_manager_for(self, proxy, **kwargs):
        manager = super().proxy_manager_for(proxy, **kwargs)
        if not str(proxy).lower().startswith("socks"):
            manager.pool_classes_by_scheme = _WATCHED_POOLS
        return manager


class BoundedAdapter(WatchedAdapter):
    """A `WatchedAdapter` whose every response body is read by `read_body` before
    ``send`` returns, under one deadline (`deadline_for`) the watchdog also enforces on
    the status line and headers: whole, or `BodyIncomplete` (the response closed, its
    connection dropped). Its requests advertise only codings it can bound
    (`advertise`)."""

    def send(self, request, stream=False, timeout=None, verify=True, cert=None,
             proxies=None):
        advertise(request.headers)
        deadline = deadline_for(timeout)
        with watch(deadline) as w:
            try:
                resp = super().send(request, stream=True, timeout=timeout, verify=verify,
                                    cert=cert, proxies=proxies)
            except requests.RequestException as exc:
                if w.fired:
                    raise BodyIncomplete("deadline") from exc
                raise
            try:
                body = read_body(resp, deadline=deadline)
            except BaseException as exc:
                resp.close()
                if w.fired and isinstance(exc, requests.RequestException):
                    raise BodyIncomplete("deadline") from exc
                raise
        if not body.complete:
            resp.close()
            raise BodyIncomplete(body.reason, wire=body.wire, decoded=len(body.data))
        return resp


def _mount(session, cls):
    # the class itself, not ``requests.Session``: a test may replace that name with a
    # factory of an in-memory site, which is used as given (it reads nothing)
    if not isinstance(session, requests.sessions.Session):
        return session
    for prefix in ("https://", "http://"):
        if not isinstance(session.adapters.get(prefix), cls):
            session.mount(prefix, cls())
    return session


def bound(session):
    """``session`` (a ``requests.Session``) with every body it reads bounded: its http
    and https adapters are `BoundedAdapter`. Idempotent; returns ``session``. Any other
    object (a test's in-memory stand-in) is returned as given."""
    return _mount(session, BoundedAdapter)


def watched(session):
    """``session`` with watched connections (`WatchedAdapter`), for a caller that streams
    and reads with `read_body` itself inside a `watch` (the contract runner). Keeps a
    `BoundedAdapter`. Returns ``session``."""
    return _mount(session, WatchedAdapter)
