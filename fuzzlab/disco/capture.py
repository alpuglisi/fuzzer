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

**Reading (PA-0108, PA-0454).** `read_capture` types every line before use: a line over
`MAX_LINE_BYTES`, JSON that does not parse (deep nesting included) or a field of the
wrong type is quarantined and counted, never repaired into a record that was not seen.

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
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from fuzzlab.core.redaction import PLACEHOLDER, is_sensitive_name, redact_body, redact_url

#: The record format version (``v``); a reader refuses another.
CAPTURE_VERSION = 1
#: A stored body is cut to this many characters, after redaction.
MAX_BODY_CHARS = 200_000
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


def _pairs(headers):
    if headers is None:
        return []
    fields = getattr(headers, "fields", None)          # mitmproxy Headers: raw pairs
    if fields is not None:
        return [(k.decode("latin-1") if isinstance(k, bytes) else k,
                 v.decode("latin-1") if isinstance(v, bytes) else v) for k, v in fields]
    if hasattr(headers, "items"):
        return list(headers.items())
    return list(headers)


def _content_type(headers: dict[str, str]) -> str | None:
    return headers.get("content-type") or None


def _body_text(body: bytes | None, content_type: str | None) -> tuple[str | None, bool]:
    """The redacted body as text and whether it was truncated. Redaction runs on the
    whole body first (PA-0455): a secret straddling the cut is never kept."""
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
                ws_direction: str | None = None, profile: str | None = None) -> CaptureRecord:
    """The one way a record is built: everything that crossed the wire goes through
    `core.redaction` here, before the record exists (see the module docstring)."""
    if kind not in KINDS:
        raise ValueError(f"unknown capture kind {kind!r}")
    rq = redact_headers(req_headers)
    rs = redact_headers(res_headers)
    rq.pop(ACTION_HEADER, None)                 # carried as action_id, never a header
    req_text, req_cut = _body_text(req_body, _content_type(rq))
    res_text, res_cut = _body_text(res_body, _content_type(rs))
    return CaptureRecord(kind=kind, t=float(t), action_id=action_id or None,
                         method=str(method).upper(), url=redact_url(str(url)),
                         req_headers=rq, req_ctype=_content_type(rq), req_body=req_text,
                         req_truncated=req_cut, status=status, res_headers=rs,
                         res_ctype=_content_type(rs), res_body=res_text,
                         res_truncated=res_cut, latency_ms=latency_ms, error=error,
                         ws_direction=ws_direction, profile=profile or None)


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


class JsonlTail:
    """The complete lines appended to ``path`` since the last `read`, as bytes with their
    ``\n`` (the lines binary iteration gives). A line whose newline has not arrived is
    held; ``read(final=True)`` also returns it (the writer is done). Shared with the
    explorer's action log (`tools.observe.DiscoActionLines`). A missing file raises
    ``FileNotFoundError``."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.offset = 0
        self._rest = b""

    def read(self, final: bool = False) -> list[bytes]:
        return list(self.lines(final))

    def lines(self, final: bool = False):
        """`read`, one line at a time (a large file is never held whole)."""
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            while True:
                data = fh.read(READ_CHUNK)
                if not data:
                    break
                self.offset += len(data)
                buf = self._rest + data
                cut = buf.rfind(b"\n") + 1
                self._rest = buf[cut:]
                if cut:
                    for ln in buf[:cut - 1].split(b"\n"):
                        yield ln + b"\n"
        if final and self._rest:
            rest, self._rest = self._rest, b""
            yield rest


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
