"""HTTP/1 message framing over raw bytes: where a request or a response ends (SP-63;
FR-PROXY-401, FR-PROXY-402; BUG-0543).

The one owner of the proxy's HTTP/1 framing decision. Two drivers read through it and
frame nothing themselves: the listener (`server`, a client's requests, asyncio) and the
upstream sender (`socketsender.recv_http_response`, a response, a blocking socket).

`MessageReader` is sans-I/O. A driver feeds it each receive (`feed`) and says when the
peer closed (`eof`); the reader says when the message is whole (`done`). A message is
never whole on a guess: it ends where its framing says, and a peer that closes first
gives `Incomplete`, never a short message.

**Framing** (RFC 9112 §6.1-6.3, §7.1):

- *Request.* ``Transfer-Encoding`` and ``Content-Length`` together, a transfer coding
  other than ``chunked`` alone, ``Transfer-Encoding`` on HTTP/1.0, an invalid
  ``Content-Length`` or conflicting values, or a malformed request line: `FramingError`
  (the listener answers 400 and forwards nothing). Identical duplicate values are one
  length. ``raw_length=True`` (the listener's explicit raw mode) frames conflicting
  values by the first, as the D4 raw path did, and changes nothing else.
- *Response* (given the request's method): HEAD, 1xx, 204, 304 and a 2xx to CONNECT have
  no body; ``Transfer-Encoding`` with ``Content-Length`` is a `FramingError`; chunked
  last is chunked, any other coding is close-delimited; a valid ``Content-Length`` is the
  length; neither is close-delimited (ends only at the peer's close). Interim responses
  (1xx but 101) are read and passed over, at most `MAX_INTERIM` of them; the message is
  the final response.
- *Chunked* bodies are parsed, never guessed: ``1*HEXDIG`` chunk sizes (extensions after
  ``;`` allowed, at most `MAX_LINE` bytes a line), CRLF after each chunk's data, and the
  trailer section up to its empty line. ``dechunk=True`` keeps the payload (a request,
  re-framed by `MessageReader.message` with a ``Content-Length``; trailer fields are
  dropped, as RFC 9110 §6.5.1 allows); otherwise the body is kept byte-exact.

**Bounds** are checked as bytes arrive (PA-0536): a head over ``limits.head`` and a body
over ``limits.body`` wire bytes (chunk framing and trailers counted) raise `OverLimit`
before more is kept; a declared length or chunk size over the body bound raises at once.
A driver owns the deadlines. Each byte is copied into a buffer a bounded number of times;
`MessageReader.copied` counts them (PA-0102(2), PA-0135(2)).
"""

from __future__ import annotations

from dataclasses import dataclass

from fuzzlab.proxy.message import RawMessage

#: The longest chunk-size or trailer line, chunk extensions included.
MAX_LINE = 8 * 1024
#: The most interim (1xx) responses passed over before the final one.
MAX_INTERIM = 8

NONE, LENGTH, CHUNKED, CLOSE = "none", "length", "chunked", "close"

_DIGITS = frozenset(b"0123456789")
_HEX = frozenset(b"0123456789abcdefABCDEF")
#: Longer than any real length: a value with more digits is over every bound.
_HUGE = 10 ** 19


class FramingError(ValueError):
    """The message cannot be framed. A request is answered 400 and never forwarded; a
    response is a 502 (RFC 9112 §6.3)."""


class OverLimit(ValueError):
    """A part of the message (``part``: ``head`` or ``body``) passed its bound while it
    was read; nothing more of it is kept."""

    def __init__(self, part: str, limit: int):
        self.part, self.limit = part, limit
        super().__init__(f"headers exceed {limit} bytes" if part == "head"
                         else f"body exceeds {limit} bytes")


class Incomplete(EOFError):
    """The peer closed before the message's framed end."""


@dataclass(frozen=True)
class Framing:
    kind: str            # NONE | LENGTH | CHUNKED | CLOSE
    length: int = 0      # LENGTH only


@dataclass(frozen=True)
class FrameLimits:
    head: int            # one head: start line, fields and the blank line
    body: int            # body bytes as they cross the wire


# --- the framing decision ------------------------------------------------------------------

def _content_length(msg: RawMessage, *, first: bool = False) -> int | None:
    values = []
    for v in msg.get_all("Content-Length"):
        for part in v.split(b","):
            p = part.strip(b" \t\r")
            if not p or not set(p) <= _DIGITS:
                raise FramingError("an invalid Content-Length")
            p = p.lstrip(b"0") or b"0"
            values.append(_HUGE if len(p) > 18 else int(p))
    if not values:
        return None
    if len(set(values)) > 1 and not first:
        raise FramingError("conflicting Content-Length values")
    return values[0]


def _codings(msg: RawMessage) -> list[bytes]:
    return [p for v in msg.get_all("Transfer-Encoding")
            for p in (c.strip(b" \t\r").lower() for c in v.split(b",")) if p]


def request_framing(msg: RawMessage, *, raw_length: bool = False) -> Framing:
    """How a request's body is framed; `FramingError` when it cannot be."""
    if msg.get_all("Transfer-Encoding"):
        if msg.get_all("Content-Length"):
            raise FramingError("both Transfer-Encoding and Content-Length")
        if msg.start_line.rsplit(b" ", 1)[-1] == b"HTTP/1.0":
            raise FramingError("Transfer-Encoding in an HTTP/1.0 request")
        if _codings(msg) != [b"chunked"]:
            raise FramingError("a request's transfer coding is not chunked alone")
        return Framing(CHUNKED)
    n = _content_length(msg, first=raw_length)
    return Framing(LENGTH, n) if n else Framing(NONE)


def response_status(msg: RawMessage) -> int:
    """A response's status code; `FramingError` for a malformed status line."""
    parts = msg.start_line.split(b" ", 2)
    if (len(parts) < 2 or not parts[0].startswith(b"HTTP/") or len(parts[1]) != 3
            or not set(parts[1]) <= _DIGITS):
        raise FramingError("a malformed status line")
    return int(parts[1])


def response_framing(msg: RawMessage, method: bytes, status: int) -> Framing:
    """How a response to ``method`` with ``status`` is framed; `FramingError` when it
    cannot be."""
    if (method == b"HEAD" or 100 <= status < 200 or status in (204, 304)
            or (method == b"CONNECT" and 200 <= status < 300)):
        return Framing(NONE)
    if msg.get_all("Transfer-Encoding"):
        if msg.get_all("Content-Length"):
            raise FramingError("both Transfer-Encoding and Content-Length")
        codings = _codings(msg)
        return Framing(CHUNKED) if codings and codings[-1] == b"chunked" else Framing(CLOSE)
    n = _content_length(msg)
    if n is None:
        return Framing(CLOSE)
    return Framing(LENGTH, n) if n else Framing(NONE)


def _chunk_size(line: bytes) -> int:
    size = line.split(b";", 1)[0].rstrip(b" \t")
    if not size or len(size) > 16 or not set(size) <= _HEX:
        raise FramingError("a bad chunk size")
    return int(size, 16)


def closes_connection(request: bytes, response: bytes) -> bool:
    """Whether a connection ends after this exchange: the response is close-delimited, a
    101 or unframeable, or either side said ``Connection: close``."""
    req, resp = RawMessage.from_bytes(request), RawMessage.from_bytes(response)
    for m in (req, resp):
        if any(t.strip().lower() == b"close"
               for v in m.get_all("Connection") for t in v.split(b",")):
            return True
    try:
        status = response_status(resp)
        return status == 101 or response_framing(resp, req.method, status).kind == CLOSE
    except FramingError:
        return True


# --- the reader --------------------------------------------------------------------------

class MessageReader:
    """One HTTP/1 request or response, read incrementally (sans-I/O).

    ``feed`` each receive; ``eof`` when the peer closed. Once ``done``: ``head`` (the
    final head, blank line included), ``status`` (a response), ``framing``, ``body``
    (byte-exact, or the payload when ``dechunk``) and ``leftover`` (bytes past the end:
    a pipelined next message). ``received`` counts bytes fed; ``copied`` counts bytes
    copied into buffers.
    """

    def __init__(self, role: str, limits: FrameLimits, *, method: bytes = b"GET",
                 dechunk: bool = False, raw_length: bool = False):
        if role not in ("request", "response"):
            raise ValueError(f"role {role!r}")
        self.role, self.limits, self.method = role, limits, method
        self.dechunk, self.raw_length = dechunk, raw_length
        self.done = False
        self.received = self.copied = self.interim = 0
        self.head = b""
        self.msg: RawMessage | None = None
        self.status: int | None = None
        self.framing: Framing | None = None
        self.body = bytearray()
        self.leftover = b""
        self._buf = bytearray()          # head bytes so far
        self._scan = 0
        self._state = "head"             # head | LENGTH | CLOSE | CHUNKED
        self._chunk = "size"             # size | data | crlf | trailer
        self._remaining = 0
        self._line = bytearray()
        self._wire = 0

    # -- driving -------------------------------------------------------------------------
    def feed(self, data: bytes) -> None:
        if not data:
            return
        self.received += len(data)
        data = bytes(data)
        while data:
            if self.done:
                self.leftover += data
                self.copied += len(data)
                return
            data = self._head(data) if self._state == "head" else self._body(data)

    def eof(self) -> None:
        """The peer closed: ends a close-delimited body, else raises `Incomplete`."""
        if self.done:
            return
        if self._state == CLOSE:
            self.done = True
            return
        raise Incomplete(f"the peer closed before the message's end "
                         f"({self.received} bytes read)")

    def message(self) -> bytes:
        """The whole message as it is passed on: byte-exact, except that a de-chunked
        request carries its payload with a ``Content-Length`` in place of
        ``Transfer-Encoding`` (its trailer fields dropped)."""
        if self.dechunk and self.framing is not None and self.framing.kind == CHUNKED:
            msg = self.msg.without_header("Transfer-Encoding").with_header(
                "Content-Length", str(len(self.body)))
            return msg.with_body(bytes(self.body)).raw
        return self.head + bytes(self.body)

    # -- the head ------------------------------------------------------------------------
    def _head(self, data: bytes) -> bytes:
        if self.role == "request" and not self._buf:
            data = data.lstrip(b"\r\n")          # empty lines before a request-line
            if not data:
                return b""
        self._buf += data
        self.copied += len(data)
        end = self._buf.find(b"\r\n\r\n", max(0, self._scan - 3))
        if end < 0:
            if len(self._buf) > self.limits.head:
                raise OverLimit("head", self.limits.head)
            self._scan = len(self._buf)
            return b""
        end += 4
        if end > self.limits.head:
            raise OverLimit("head", self.limits.head)
        head, rest = bytes(self._buf[:end]), bytes(self._buf[end:])
        self.copied += len(self._buf)
        self._buf, self._scan = bytearray(), 0
        self._start(head)
        return rest

    def _start(self, head: bytes) -> None:
        msg = RawMessage(head)
        if self.role == "request":
            parts = msg.start_line.split(b" ")
            if len(parts) != 3 or not parts[0] or not parts[2].startswith(b"HTTP/1."):
                raise FramingError("a malformed request line")
            fr = request_framing(msg, raw_length=self.raw_length)
        else:
            status = response_status(msg)
            if 100 <= status < 200 and status != 101:
                self.interim += 1                       # passed over: read the next head
                if self.interim > MAX_INTERIM:
                    raise FramingError("too many interim responses")
                return
            self.status = status
            fr = response_framing(msg, self.method, status)
        self.head, self.msg, self.framing = head, msg, fr
        if fr.kind == NONE:
            self.done = True
            return
        if fr.kind == LENGTH:
            if fr.length > self.limits.body:
                raise OverLimit("body", self.limits.body)
            self._remaining = fr.length
        self._state = fr.kind

    # -- the body ------------------------------------------------------------------------
    def _wire_bytes(self, n: int) -> None:
        self._wire += n
        if self._wire > self.limits.body:
            raise OverLimit("body", self.limits.body)

    def _keep(self, piece, payload: bool) -> None:
        """Keep ``piece`` in the body: framing bytes only when kept byte-exact."""
        if payload or not self.dechunk:
            self.body += piece
            self.copied += len(piece)

    def _body(self, data: bytes) -> bytes:
        if self._state == LENGTH:
            n = min(self._remaining, len(data))
            self._wire_bytes(n)
            self._keep(memoryview(data)[:n], True)
            self._remaining -= n
            if not self._remaining:
                self.done = True
            return data[n:]
        if self._state == CLOSE:
            self._wire_bytes(len(data))
            self._keep(data, True)
            return b""
        return self._chunked(data)

    def _chunked(self, data: bytes) -> bytes:
        mv, i, n = memoryview(data), 0, len(data)
        while i < n:
            if self._chunk in ("size", "trailer"):
                j = data.find(b"\n", i)
                end = n if j < 0 else j + 1
                if len(self._line) + end - i > MAX_LINE:
                    raise FramingError(f"a chunk line over {MAX_LINE} bytes")
                self._wire_bytes(end - i)
                self._line += mv[i:end]
                self.copied += end - i
                self._keep(mv[i:end], False)
                i = end
                if j < 0:
                    break
                line, self._line = bytes(self._line), bytearray()
                if not line.endswith(b"\r\n"):
                    raise FramingError("a chunk line not ended by CRLF")
                line = line[:-2]
                if self._chunk == "trailer":
                    if not line:                         # the empty line: the end
                        self.done = True
                        return data[i:]
                    continue                             # a trailer field
                size = _chunk_size(line)
                if size > self.limits.body - self._wire:
                    raise OverLimit("body", self.limits.body)
                self._chunk, self._remaining = ("data", size) if size else ("trailer", 0)
            elif self._chunk == "data":
                take = min(self._remaining, n - i)
                self._wire_bytes(take)
                self._keep(mv[i:i + take], True)
                self._remaining -= take
                i += take
                if not self._remaining:
                    self._chunk = "crlf"
            else:                                        # the CRLF after a chunk's data
                take = min(2 - len(self._line), n - i)
                self._wire_bytes(take)
                self._line += mv[i:i + take]
                self.copied += take
                self._keep(mv[i:i + take], False)
                i += take
                if len(self._line) == 2:
                    if bytes(self._line) != b"\r\n":
                        raise FramingError("chunk data not followed by CRLF")
                    self._line, self._chunk = bytearray(), "size"
        return b""
