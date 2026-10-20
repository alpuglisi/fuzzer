"""Bounded reads of a target's HTTP response body (SP-57, FR-CORE-536; BUG-0536).

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

`read` returns a typed `Body`: ``complete``, or the ``reason`` it is not (`REASONS`). An
incomplete body is never a short one: `bound`'s adapter raises `BodyIncomplete` (a
``requests.RequestException``, so every transport-failure handler sees it, and SP-34's
``probesender._unobserved`` makes it "not observed"); the contract runner reads `Body`
itself (FR-FUZZ-52).

`bound(session)` applies `read` to every response a ``requests.Session`` gets, with a
deadline of `DEADLINE_TIMEOUTS` x the request's read timeout (`DEFAULT_SECONDS` without
one). Every session fuzzlab makes for a target is bounded where it is made
(``tests/test_bounded_reads.py`` guard).

Content codings, as urllib3 decodes them: identity; ``gzip`` / ``x-gzip`` (several
members; bytes after a whole member ignored); ``deflate`` (zlib-wrapped or raw); ``br``
with a Brotli that bounds its output (``Decompressor.process(..., output_buffer_limit)``,
Brotli >= 1.2). A coding urllib3 has no decoder for is passed through undecoded, as
urllib3 does. ``br`` without such a Brotli, ``zstd`` (decoded by urllib3 only with
``backports.zstd``, which fuzzlab does not declare) and a chain of codings are
incomplete (``"encoding"``): fail closed, never handed on as text.

Stated limit (measured): framing lines -- the status line and the headers, before the
response exists, and a chunked body's chunk-size and trailer lines -- are read by
``http.client`` in one call each (up to 64 KiB a line, 100 headers) and are bounded only
by the per-receive timeout. The late read is still incomplete (the deadline is checked
when it returns); its liveness is pinned by a strict xfail.
"""

from __future__ import annotations

import time
import zlib
from dataclasses import dataclass
from typing import Callable

import requests
from requests.adapters import HTTPAdapter

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
    """What `read` read: ``data`` (at most the decoded ceiling), ``complete``, the
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


def _bounded_brotli():
    """The ``brotli`` module when it can bound its output, else None."""
    try:
        import brotli
        brotli.Decompressor().process(b"", output_buffer_limit=1)
        return brotli
    except (ImportError, TypeError, AttributeError):
        return None


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


def read(resp, *, deadline: float, limits: Limits | None = None,
         clock: Callable[[], float] = time.monotonic) -> Body:
    """Read ``resp``'s body (a streamed ``requests.Response``) under ``limits`` (default
    `default_limits`) and ``deadline`` (an instant of ``clock``). A complete body also
    becomes ``resp.content``. Raises what the read raises (a cut or reset connection, a
    read timeout, an undecodable body: ``requests`` exceptions, as ``iter_content``
    names them). Never closes ``resp``: its caller does, on every exit.

    A response with no raw stream (an adapter's or a test's) is read through
    ``iter_content``: its chunks are already decoded, and count on the smaller
    ceiling."""
    lim = limits or default_limits()
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


class BoundedAdapter(HTTPAdapter):
    """An ``HTTPAdapter`` whose every response body is read by `read` before ``send``
    returns: whole, or `BodyIncomplete` (the response closed, its connection dropped)."""

    def send(self, request, stream=False, timeout=None, verify=True, cert=None,
             proxies=None):
        deadline = deadline_for(timeout)
        resp = super().send(request, stream=True, timeout=timeout, verify=verify,
                            cert=cert, proxies=proxies)
        try:
            body = read(resp, deadline=deadline)
        except BaseException:
            resp.close()
            raise
        if not body.complete:
            resp.close()
            raise BodyIncomplete(body.reason, wire=body.wire, decoded=len(body.data))
        return resp


def bound(session):
    """``session`` (a ``requests.Session``) with every body it reads bounded: its http
    and https adapters are `BoundedAdapter`. Idempotent; returns ``session``."""
    for prefix in ("https://", "http://"):
        if not isinstance(session.adapters.get(prefix), BoundedAdapter):
            session.mount(prefix, BoundedAdapter())
    return session
