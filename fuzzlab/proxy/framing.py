"""HTTP/1 message framing over raw bytes: where a request or a response ends (SP-63;
FR-PROXY-401, FR-PROXY-402; BUG-0543).

The one owner of the proxy's HTTP/1 framing decision. Two drivers read through it and
frame nothing themselves: the listener (`server`, a client's requests, asyncio) and the
upstream sender (`socketsender.recv_http_response`, a response, a blocking socket).

`MessageReader` is sans-I/O. A driver feeds it each receive (`feed`) and says when the
peer closed (`eof`); the reader says when the message is whole (`done`). A message is
never whole on a guess: it ends where its framing says, and a peer that closes first
gives `Incomplete`, never a short message.

**Heads** are parsed once, strictly, from the bytes up to the first CRLF CRLF (`parse_head`,
RFC 9112 §2.2, §5): every line ends in CRLF (a bare CR or LF anywhere is refused, so no
other line ending can end the head or a field), the start line is not empty, and every
field line is ``token ":" value`` (no obs-fold, no whitespace before the colon, no NUL).
A request head that fails is `FramingError` (400); a response head, a 502. The framing
below reads its fields from that same parse.

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
#: RFC 9110 §5.6.2 tchar: what a method and a field name are made of.
_TCHAR = frozenset(b"!#$%&'*+-.^_`|~0123456789"
                   b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
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


# --- the head --------------------------------------------------------------------------------

@dataclass(frozen=True)
class Head:
    """A head as `parse_head` read it: ``raw`` (through the blank line), ``start_line``
    and ``fields`` (lower-cased name, value without surrounding whitespace), in order,
    duplicates kept."""
    raw: bytes
    start_line: bytes
    fields: tuple[tuple[bytes, bytes], ...]

    def get_all(self, name: str | bytes) -> list[bytes]:
        key = (name.encode("latin-1") if isinstance(name, str) else name).lower()
        return [v for n, v in self.fields if n == key]

    @property
    def method(self) -> bytes:
        return self.start_line.split(b" ", 1)[0]


def _http1_version(v: bytes) -> bool:
    return len(v) == 8 and v.startswith(b"HTTP/1.") and v[7] in _DIGITS


def parse_head(head: bytes, role: str) -> Head:
    """Parse a head (start line through the blank line) strictly, or raise
    `FramingError`: a bare CR or LF, an empty start line, an obs-folded field line, a
    field line with no colon or a name that is not a token (whitespace before the colon
    included), a NUL in a value, or a malformed request or status line."""
    if not head.endswith(b"\r\n\r\n"):
        raise FramingError("a head not ended by CRLF CRLF")
    lines = head[:-4].split(b"\r\n")
    if any(b"\r" in line or b"\n" in line for line in lines):
        raise FramingError("a bare CR or LF in the head")
    start = lines[0]
    if not start:
        raise FramingError("an empty start line")
    fields = []
    for line in lines[1:]:
        if line[:1] in (b" ", b"\t"):
            raise FramingError("an obs-folded field line")
        name, colon, value = line.partition(b":")
        if not colon or not name or not set(name) <= _TCHAR:
            raise FramingError("a malformed field line")
        if b"\0" in value:
            raise FramingError("a NUL in a field value")
        fields.append((name.lower(), value.strip(b" \t")))
    parsed = Head(head, start, tuple(fields))
    if role == "request":
        parts = start.split(b" ")
        if (len(parts) != 3 or not parts[0] or not set(parts[0]) <= _TCHAR
                or not parts[1] or b"\t" in parts[1] or not _http1_version(parts[2])):
            raise FramingError("a malformed request line")
    else:
        response_status(parsed)
    return parsed


def _head_of(message: bytes) -> bytes:
    end = message.find(b"\r\n\r\n")
    return message[:end + 4] if end >= 0 else message


# --- the framing decision ------------------------------------------------------------------

def _content_length(msg: Head, *, first: bool = False) -> int | None:
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


def _codings(msg: Head) -> list[bytes]:
    return [p for v in msg.get_all("Transfer-Encoding")
            for p in (c.strip(b" \t\r").lower() for c in v.split(b",")) if p]


def request_framing(msg: Head, *, raw_length: bool = False) -> Framing:
    """How a request's body is framed (``msg`` from `parse_head`); `FramingError` when
    it cannot be."""
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


def response_status(msg: Head) -> int:
    """A response's status code; `FramingError` for a malformed status line."""
    parts = msg.start_line.split(b" ", 2)
    if (len(parts) < 2 or not _http1_version(parts[0]) or len(parts[1]) != 3
            or not set(parts[1]) <= _DIGITS):
        raise FramingError("a malformed status line")
    return int(parts[1])


def response_framing(msg: Head, method: bytes, status: int) -> Framing:
    """How a response to ``method`` with ``status`` is framed (``msg`` from
    `parse_head`); `FramingError` when it cannot be."""
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
    try:
        req = parse_head(_head_of(bytes(request)), "request")
        resp = parse_head(_head_of(bytes(response)), "response")
    except FramingError:
        return True
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
            i = 0                                # empty lines (CRLF) before a request-
            while data.startswith(b"\r\n", i):   # line are ignored (RFC 9112 §2.2)
                i += 2
            data = data[i:]
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
        parsed = parse_head(head, self.role)        # the one parse framing reads
        if self.role == "request":
            fr = request_framing(parsed, raw_length=self.raw_length)
        else:
            status = response_status(parsed)
            if 100 <= status < 200 and status != 101:
                self.interim += 1                       # passed over: read the next head
                if self.interim > MAX_INTERIM:
                    raise FramingError("too many interim responses")
                return
            self.status = status
            fr = response_framing(parsed, self.method, status)
        # RawMessage only for `message`'s surgery: the strict parse above leaves no bare
        # LF, so its own split agrees with this head's end
        self.head, self.msg, self.framing = head, RawMessage(head), fr
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
