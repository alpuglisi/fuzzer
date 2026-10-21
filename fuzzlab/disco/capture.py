"""``capture.jsonl``: the discovery layer's one record format, one producer, one parser.

Every line is one JSON object describing one exchange the capture proxy saw (an HTTP
request with its response, or a WebSocket message). The proxy (`recorder`) is the only
producer and builds each record with `make_record`; `synth` and the CLI read records
only through `read_capture`.

**Redaction at the write (PA-0100, PA-0085, PA-0101, PA-0455).** A record is built from
what crossed the wire and redacted before it exists, through the same storage boundary
proxy history uses (`core.redaction`):
- the URL's sensitively named query values (`redact_url`);
- request and response bodies (`redact_body`: sensitively named JSON / form / multipart
  fields replaced; a body it cannot prove clean is omitted, fail closed);
- the value of every header whose name is sensitive (``cookie``, ``set-cookie``,
  ``authorization``, a CSRF header, ...: `is_sensitive_name`) -- the name is kept, so the
  synthesizer can still say an endpoint needs a session.

Identifier values are **kept**: path templating and producer -> consumer dependency edges
are inferred from them, and they are lab data, not credentials (the policy proxy history
already follows). A body is truncated only after it is redacted, and a truncated body is
marked so no schema is inferred from half a document.

**Off the proxy's event loop (BUG-0548, audit defect 22).** The proxy's hooks run on the
loop that carries every browser request, so a hook only *takes* an exchange
(`snapshot`): references to what crossed the wire -- the header pairs and each body as
it was sent (content-coded) -- in time that does not depend on the bodies, never a
decoded, redacted or serialised copy. The recorder's writer thread then builds the
record (`build_record`): it decodes each body through SP-60's reader under
`MAX_CAPTURE_BODY_BYTES` (`decode_body`), and `make_record` redacts, cuts and the
record is serialised there. A body over that size -- as sent, or once decoded -- or in
a coding with no bounded decoder is never held whole: redaction needs the whole body
(PA-0455), so its record has **no body** and says ``*_truncated`` (fail closed).

**Reading (PA-0108, PA-0454).** `read_capture` types every line before use: a line over
`MAX_LINE_BYTES`, JSON that does not parse (deep nesting included) or a field of the
wrong type is quarantined and counted, never repaired into a record that was not seen.
The line cap holds while a line is read, not only once it is whole (`JsonlTail`,
BUG-0536): an over-cap line is never held, and the reading work is linear.

**Reading while it is written (FR-CRAWL-30).** `read_capture` is `CaptureTail` read to
the end: one loop. A `CaptureTail` reads only what was appended since its last read and
returns only complete lines, holding a partial one until its newline arrives (measured:
a reader can see half a line); its records are numbered as `read_capture` numbers them
(well-formed records only). Lines are split on ``\n`` bytes only (`JsonlTail`, never
``splitlines``: ``ensure_ascii=False`` lets U+2028 and U+0085 into a record), and each
complete line is decoded alone, never a chunk (a cut can fall inside a character).
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from requests.exceptions import RequestException

from fuzzlab.core import bodyread
from fuzzlab.core.redaction import (MAX_REDACT_BYTES, PLACEHOLDER, is_sensitive_name,
                                    redact_body, redact_url)

#: The record format version (``v``); a reader refuses another.
CAPTURE_VERSION = 1
#: A stored body is cut to this many characters, after redaction.
MAX_BODY_CHARS = 200_000
#: A body larger than this, as sent or once decoded, is not captured (BUG-0548): it is
#: never held past the proxy hook, and decoding stops at it. Redaction omits a larger
#: body anyway (`core.redaction.MAX_REDACT_BYTES`), so this is the same ceiling.
MAX_CAPTURE_BODY_BYTES = MAX_REDACT_BYTES
#: A line longer than this is quarantined by the reader.
MAX_LINE_BYTES = 4 * 1024 * 1024
#: The request header that carries the UI action a request belongs to.
ACTION_HEADER = "x-disco-action"

KINDS = ("http", "ws")


def redact_headers(headers) -> dict[str, str]:
    """Header ``name -> value`` (names lower-cased; repeated names joined with ``, ``)
    with every sensitively named header's value replaced by the placeholder."""
    out: dict[str, str] = {}
    for name, value in _pairs(headers):
        key = str(name).lower()
        value = PLACEHOLDER if is_sensitive_name(key) else str(value)
        out[key] = f"{out[key]}, {value}" if key in out else value
    return out


def _latin1(value):
    return value.decode("latin-1") if isinstance(value, bytes) else value


def _raw_pairs(headers):
    """The ``(name, value)`` pairs as given: mitmproxy's ``fields`` (bytes), a mapping's
    items, or an iterable of pairs."""
    if headers is None:
        return ()
    fields = getattr(headers, "fields", None)          # mitmproxy Headers: raw pairs
    if fields is not None:
        return fields
    if hasattr(headers, "items"):
        return headers.items()
    return headers


def _pairs(headers):
    return [(_latin1(k), _latin1(v)) for k, v in _raw_pairs(headers)]


def _content_type(headers: dict[str, str]) -> str | None:
    return headers.get("content-type") or None


def _body_text(body: bytes | None, content_type: str | None,
               omitted: bool = False) -> tuple[str | None, bool]:
    """The redacted body as text and whether it was truncated. Redaction runs on the
    whole body first (PA-0455): a secret straddling the cut is never kept. A body that
    was not captured whole (``omitted``) has no text and is marked truncated."""
    if omitted:
        return None, True
    if not body:
        return None, False
    clean = redact_body(bytes(body), content_type or "")
    text = clean.decode("utf-8", errors="replace")
    if len(text) > MAX_BODY_CHARS:
        return text[:MAX_BODY_CHARS], True
    return text, False


@dataclass(frozen=True)
class CaptureRecord:
    """One exchange. ``status`` is None when the exchange got no response (``error``
    names the error class); ``ws_direction`` is set for a WebSocket message."""
    kind: str
    t: float
    action_id: str | None
    method: str
    url: str
    req_headers: dict[str, str]
    req_ctype: str | None
    req_body: str | None
    status: int | None = None
    res_headers: dict[str, str] = field(default_factory=dict)
    res_ctype: str | None = None
    res_body: str | None = None
    res_truncated: bool = False
    req_truncated: bool = False
    latency_ms: int | None = None
    error: str | None = None
    ws_direction: str | None = None
    profile: str | None = None
    v: int = CAPTURE_VERSION

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, ensure_ascii=False)


def make_record(*, kind: str, t: float, action_id: str | None, method: str, url: str,
                req_headers, req_body: bytes | None, status: int | None = None,
                res_headers=None, res_body: bytes | None = None,
                latency_ms: int | None = None, error: str | None = None,
                ws_direction: str | None = None, profile: str | None = None,
                req_omitted: bool = False, res_omitted: bool = False) -> CaptureRecord:
    """The one way a record is built: everything that crossed the wire goes through
    `core.redaction` here, before the record exists (see the module docstring). A body
    that was not captured whole (``*_omitted``) is recorded as none, marked truncated."""
    if kind not in KINDS:
        raise ValueError(f"unknown capture kind {kind!r}")
    rq = redact_headers(req_headers)
    rs = redact_headers(res_headers)
    rq.pop(ACTION_HEADER, None)                 # carried as action_id, never a header
    req_text, req_cut = _body_text(req_body, _content_type(rq), req_omitted)
    res_text, res_cut = _body_text(res_body, _content_type(rs), res_omitted)
    return CaptureRecord(kind=kind, t=float(t), action_id=action_id or None,
                         method=str(method).upper(), url=redact_url(str(url)),
                         req_headers=rq, req_ctype=_content_type(rq), req_body=req_text,
                         req_truncated=req_cut, status=status, res_headers=rs,
                         res_ctype=_content_type(rs), res_body=res_text,
                         res_truncated=res_cut, latency_ms=latency_ms, error=error,
                         ws_direction=ws_direction, profile=profile or None)


# --- the proxy's hand-off: taken on its loop, built on the writer (BUG-0548) ------------

#: Why a body was not captured: over `MAX_CAPTURE_BODY_BYTES` as sent (``too_large``),
#: over the recorder's queue budget (``backlog``), or not decodable whole under the
#: ceiling (``undecodable``: over it once decoded, a coding with no bounded decoder,
#: corrupt).
OMIT_REASONS = ("too_large", "backlog", "undecodable")


@dataclass(frozen=True, slots=True)
class HeldExchange:
    """One exchange as a proxy hook took it (`snapshot`): the header pairs and each body
    exactly as they crossed the wire -- references to immutable values, taken in time
    that does not depend on the bodies' sizes. ``coded``: the bodies carry their
    ``Content-Encoding`` (HTTP; a WebSocket message is already decoded).
    ``*_omitted`` names why a body was not taken (`OMIT_REASONS`); ``size`` is the
    bytes the exchange holds (URL, header pairs, bodies)."""
    kind: str
    t: float
    action_id: str | None
    method: str
    url: str
    req_headers: tuple
    req_body: bytes | None
    status: int | None = None
    res_headers: tuple = ()
    res_body: bytes | None = None
    latency_ms: int | None = None
    error: str | None = None
    ws_direction: str | None = None
    profile: str | None = None
    coded: bool = True
    req_omitted: str | None = None
    res_omitted: str | None = None
    size: int = 0

    def without_bodies(self, reason: str) -> "HeldExchange":
        """This exchange holding no body: each one it held is omitted for ``reason``."""
        if self.req_body is None and self.res_body is None:
            return self
        bare = replace(self, req_body=None, res_body=None,
                       req_omitted=reason if self.req_body is not None else self.req_omitted,
                       res_omitted=reason if self.res_body is not None else self.res_omitted)
        return replace(bare, size=_held_size(bare))

    def omissions(self) -> list[str]:
        return [r for r in (self.req_omitted, self.res_omitted) if r is not None]


def _held_pairs(headers) -> tuple:
    """The header pairs, held: mitmproxy's ``fields`` is already an immutable tuple of
    immutable pairs (a reference, no copy); anything else is copied as pairs."""
    raw = _raw_pairs(headers)
    return raw if isinstance(raw, tuple) else tuple((k, v) for k, v in raw)


def _held_body(body) -> tuple[bytes | None, str | None]:
    """``body`` held as sent, or ``(None, "too_large")`` past `MAX_CAPTURE_BODY_BYTES`:
    its size is all that is read of it."""
    if body is None or len(body) == 0:
        return None, None
    if len(body) > MAX_CAPTURE_BODY_BYTES:
        return None, "too_large"
    return (body if isinstance(body, bytes) else bytes(body)), None


def _held_size(ex: HeldExchange) -> int:
    pairs = sum(len(k) + len(v) for k, v in ex.req_headers) + \
        sum(len(k) + len(v) for k, v in ex.res_headers)
    return (len(ex.url) + len(ex.method) + pairs + len(ex.req_body or b"")
            + len(ex.res_body or b""))


def snapshot(*, kind: str, t: float, action_id: str | None, method: str, url: str,
             req_headers, req_body, status: int | None = None, res_headers=None,
             res_body=None, latency_ms: int | None = None, error: str | None = None,
             ws_direction: str | None = None, profile: str | None = None,
             coded: bool = True) -> HeldExchange:
    """What a proxy hook hands the writer (`build_record` turns it into the record). The
    bodies are as sent (``raw_content``: content-coded); nothing here decodes, redacts or
    serialises, so the hook's time does not grow with a body."""
    rq_body, rq_omit = _held_body(req_body)
    rs_body, rs_omit = _held_body(res_body)
    ex = HeldExchange(kind=kind, t=t, action_id=action_id, method=str(method),
                      url=str(url), req_headers=_held_pairs(req_headers), req_body=rq_body,
                      status=status, res_headers=_held_pairs(res_headers), res_body=rs_body,
                      latency_ms=latency_ms, error=error, ws_direction=ws_direction,
                      profile=profile, coded=coded, req_omitted=rq_omit,
                      res_omitted=rs_omit)
    return replace(ex, size=_held_size(ex))


class _HeldStream:
    """SP-60's raw stream (``read1``) over a body already in memory."""

    def __init__(self, data: bytes):
        self._view, self._at = memoryview(data), 0

    def read1(self, amt=None, decode_content=False):
        piece = self._view[self._at:self._at + (amt or bodyread.READ_SIZE)]
        self._at += len(piece)
        return bytes(piece)


class _Held:
    def __init__(self, data: bytes, headers):
        coding = [v for k, v in _pairs(headers) if str(k).lower() == "content-encoding"]
        self.raw = _HeldStream(data)
        self.headers = {"Content-Encoding": ", ".join(coding)} if coding else {}


def decode_body(body: bytes, headers) -> bytes | None:
    """``body`` as sent, decoded per ``headers``' ``Content-Encoding`` through SP-60's
    reader (`core.bodyread.read_body`) under `MAX_CAPTURE_BODY_BYTES`; None when it
    cannot be had whole there (over the ceiling once decoded, a coding with no bounded
    decoder, a corrupt body) -- never a part of it."""
    cap = MAX_CAPTURE_BODY_BYTES
    try:
        got = bodyread.read_body(_Held(body, headers), deadline=math.inf,
                                 limits=bodyread.Limits(wire=cap, decoded=cap))
    except RequestException:
        return None
    return got.data if got.complete else None


def build_record(ex: HeldExchange) -> tuple[CaptureRecord, int]:
    """The record of a hook's `snapshot`, built off the proxy's loop (the recorder's
    writer): each body decoded (`decode_body`), then `make_record`. Also returns how many
    bodies could not be decoded whole (each recorded as none, marked truncated)."""
    bodies, undecodable = [], 0
    for raw, headers in ((ex.req_body, ex.req_headers), (ex.res_body, ex.res_headers)):
        if raw is not None and ex.coded:
            raw = decode_body(raw, headers)
            undecodable += raw is None
            bodies.append((raw, raw is None))
        else:
            bodies.append((raw, False))
    (req_body, req_cut), (res_body, res_cut) = bodies
    rec = make_record(kind=ex.kind, t=ex.t, action_id=ex.action_id, method=ex.method,
                      url=ex.url, req_headers=ex.req_headers, req_body=req_body,
                      status=ex.status, res_headers=ex.res_headers, res_body=res_body,
                      latency_ms=ex.latency_ms, error=ex.error,
                      ws_direction=ex.ws_direction, profile=ex.profile,
                      req_omitted=req_cut or ex.req_omitted is not None,
                      res_omitted=res_cut or ex.res_omitted is not None)
    return rec, undecodable


def append_record(path: str | os.PathLike, rec: CaptureRecord) -> None:
    """Append one record and flush it (persisted as produced, PA-0012)."""
    if not isinstance(rec, CaptureRecord):          # only make_record's output is written
        raise TypeError("append_record takes a CaptureRecord from make_record")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(rec.to_json() + "\n")
        fh.flush()


# --- the one reader ------------------------------------------------------------------

_STR_OR_NONE = ("action_id", "req_ctype", "req_body", "res_ctype", "res_body", "error",
                "ws_direction", "profile")


def _typed(doc) -> CaptureRecord | None:
    """``doc`` as a record, or None when any field has the wrong type or value."""
    if not isinstance(doc, dict) or doc.get("v") != CAPTURE_VERSION:
        return None
    if doc.get("kind") not in KINDS:
        return None
    if not isinstance(doc.get("method"), str) or not isinstance(doc.get("url"), str):
        return None
    if not isinstance(doc.get("t"), (int, float)) or isinstance(doc.get("t"), bool):
        return None
    for name in _STR_OR_NONE:
        if doc.get(name) is not None and not isinstance(doc[name], str):
            return None
    for name in ("req_headers", "res_headers"):
        hdrs = doc.get(name, {})
        if not isinstance(hdrs, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in hdrs.items()):
            return None
    for name in ("status", "latency_ms"):
        val = doc.get(name)
        if val is not None and (not isinstance(val, int) or isinstance(val, bool)):
            return None
    for name in ("res_truncated", "req_truncated"):
        if not isinstance(doc.get(name, False), bool):
            return None
    known = {f for f in CaptureRecord.__dataclass_fields__}
    return CaptureRecord(**{k: v for k, v in doc.items() if k in known})


#: Bytes a `JsonlTail` reads at once.
READ_CHUNK = 1 << 20


class _Overlong(bytes):
    """The type of `OVERLONG`."""


#: What `JsonlTail` yields in place of a line over `MAX_LINE_BYTES` (an empty ``bytes``,
#: compared by identity): once per such line, where it stands among the lines.
OVERLONG = _Overlong()


class JsonlTail:
    """The complete lines appended to ``path`` since the last `read`, as bytes with their
    ``\n`` (the lines binary iteration gives). A line whose newline has not arrived is
    held; ``read(final=True)`` also returns it (the writer is done). Shared with the
    explorer's action log (`tools.observe.DiscoActionLines`). A missing file raises
    ``FileNotFoundError``.

    **Bounded while reading (BUG-0536, audit defect 23).** A line over `MAX_LINE_BYTES`
    (its newline included) is never held: as soon as the line it is reading passes the
    cap, `OVERLONG` is yielded once in its place, its bytes are dropped, and the rest of
    the line is discarded -- across reads -- up to its newline; reading resumes at the
    next line. At most `MAX_LINE_BYTES` + `READ_CHUNK` bytes are held. The work is
    linear: the held part of a line grows in one ``bytearray`` and is copied out once;
    ``copied`` counts every byte copied (PA-0135(2))."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.offset = 0
        self._rest = bytearray()
        self._discarding = False
        self.copied = 0

    def read(self, final: bool = False) -> list[bytes]:
        return list(self.lines(final))

    def lines(self, final: bool = False):
        """`read`, one line at a time (a large file is never held whole)."""
        cap = MAX_LINE_BYTES
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            while True:
                data = fh.read(READ_CHUNK)
                if not data:
                    break
                self.offset += len(data)
                yield from self._split(data, cap)
        if final:
            if self._rest:                          # never over the cap: it would be
                rest = bytes(self._rest)            # discarding instead
                self._rest.clear()
                self.copied += len(rest)
                yield rest
            self._discarding = False

    def _split(self, data: bytes, cap: int):
        start, end_of_data = 0, len(data)
        view = memoryview(data)
        while start < end_of_data:
            nl = data.find(b"\n", start)
            if nl < 0:                              # the line goes on past this read
                if not self._discarding:
                    if len(self._rest) + end_of_data - start > cap:
                        self._rest.clear()
                        self._discarding = True
                        yield OVERLONG
                    else:
                        self._rest += view[start:]
                        self.copied += end_of_data - start
                return
            end = nl + 1
            if self._discarding:                    # its newline: the next line starts
                self._discarding = False
            elif len(self._rest) + end - start > cap:
                self._rest.clear()
                yield OVERLONG
            elif self._rest:
                self._rest += view[start:end]
                line = bytes(self._rest)
                self._rest.clear()
                self.copied += end - start + len(line)
                yield line
            else:
                self.copied += end - start
                yield data[start:end]
            start = end


def _parse_line(raw: bytes) -> CaptureRecord | None:
    """One complete line as a record, or None (quarantined): over `MAX_LINE_BYTES`, not
    UTF-8, not JSON (deep nesting included), or a field of the wrong type."""
    if len(raw) > MAX_LINE_BYTES:
        return None
    try:
        return _typed(json.loads(raw.decode("utf-8")))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None


class CaptureTail:
    """``capture.jsonl`` read as it grows: `read` returns ``(index, record)`` for each
    well-formed record completed since the last read; ``index`` is its position among the
    file's well-formed records, the number `read_capture` gives it. ``quarantined``
    counts malformed lines."""

    def __init__(self, path: str | os.PathLike):
        self._lines = JsonlTail(path)
        self.count = 0
        self.quarantined = 0

    def read(self, final: bool = False) -> list[tuple[int, CaptureRecord]]:
        out = []
        for raw in self._lines.lines(final):
            if raw is OVERLONG:                     # over MAX_LINE_BYTES (BUG-0536)
                self.quarantined += 1
                continue
            if not raw.strip():
                continue
            rec = _parse_line(raw)
            if rec is None:
                self.quarantined += 1
                continue
            out.append((self.count, rec))
            self.count += 1
        return out


@dataclass
class CaptureRead:
    records: list[CaptureRecord]
    quarantined: int = 0


def read_capture(path: str | os.PathLike) -> CaptureRead:
    """Every well-formed record of ``path``, in order; malformed lines are counted in
    ``quarantined``. A missing file raises ``FileNotFoundError`` (no capture is not an
    empty capture). The whole file through `CaptureTail`: one reader."""
    tail = CaptureTail(path)
    records = [rec for _i, rec in tail.read(final=True)]
    return CaptureRead(records=records, quarantined=tail.quarantined)
