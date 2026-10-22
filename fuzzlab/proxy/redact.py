"""Secret redaction for persisted proxy data (NFR-PROXY-safe, FR-PROXY-11).

The proxy forwards **byte-exact** bytes on the wire (the raw path), but what it
*persists* — flow history (its rows, stored bodies and full-text index) — must not
carry credentials or tokens in cleartext. Before anything is written, this module
redacts:

- **headers:** the values of sensitive headers (`SENSITIVE_HEADERS`, plus any header
  whose name `core.redaction.is_sensitive_name` flags);
- **URL values:** sensitively named ones wherever `core.redaction.redact_url` finds
  them (a query, ``;`` pairs and path parameters, a query-shaped fragment, nested
  values), with or without a query (BUG-0556 review round 1), in the request target
  (read whitespace-tolerantly: a doubled space or a tab between its parts) and in
  **every value** of every URL-bearing header, duplicates included (review round 2,
  N6): ``Location``, ``Content-Location``, ``Referer``, ``Origin``, ``Destination``,
  ``X-Original-URL``, ``X-Rewrite-URL``, ``Ping-From``, ``Ping-To``, any other header
  whose value is a URL (a scheme's ``://`` or a ``/`` first), each ``<URI>`` of
  ``Link``, and ``Refresh``'s URL as the HTML declarative-refresh steps read it
  (``url=``, ``url = ``, quoted, or bare after the delay). Layered (BUG-0556 r6): the
  pushed tree's own `redact` runs first (`core.redaction_floor`, frozen at 7393c90),
  and this walk on its output only;
- **bodies:** sensitively named fields of form-urlencoded, JSON (any depth) and
  multipart (non-file) bodies, in requests and responses alike. A sensitive JSON key's
  **whole value** is replaced, whatever its type (list, object, scalar; BUG-0090).

Sensitivity is by name **token** (`core.redaction`, BUG-0084), so benign fields such as
``author`` stay readable. Body redaction is the shared, fail-closed storage boundary in
`core.redaction` (BUG-0099/0100): unparseable or oversized bodies that may hold a secret
are replaced by an omission marker, and untyped / ``text/plain`` bodies are sniffed. A
chunked or ``Content-Encoding``-compressed body is decoded (bounded, gzip / deflate) and
checked: a clean one is stored byte-exact, one carrying a secret (or undecodable with a
redactable type) is replaced by the marker with ``Transfer-Encoding`` /
``Content-Encoding`` dropped and ``Content-Length`` set — closing the former residual.
A JSON body is re-serialised only when it holds a sensitive key, so every other body
stays byte-identical. ``Content-Length`` is recomputed when a redacted body changes length,
if it was consistent before.

Trade-off: a Repeater tab seeded from history carries the placeholders, so replaying a
JWT / session / CSRF flow needs a fresh capture or ``HistoryWriter(redact_secrets=
False)`` (lab-local opt-out).
"""

from __future__ import annotations

import re
import zlib

from fuzzlab.core import redaction_floor as _floor
from fuzzlab.core.redaction import (MAX_REDACT_BYTES, OMIT_UNSAFE, PLACEHOLDER, _walk_names,
                                    body_kind, is_sensitive_name, mentions_sensitive_name,
                                    redact_body)
from fuzzlab.core.redaction import redact_query  # noqa: F401  (re-exported: one boundary)
from fuzzlab.core.redaction import redact_url  # noqa: F401  (re-exported: history's URL)
from fuzzlab.proxy.message import RawMessage

REDACTED = PLACEHOLDER.encode()

# Header names whose values are secrets. Compared case-insensitively.
SENSITIVE_HEADERS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
)
#: Headers whose whole value is a URL (an origin, for ``Origin``: a well-formed one holds
#: no path, so it comes back byte-identical; a malformed one is walked like any URL).
#: ``Refresh`` and ``Link`` carry a URL inside a larger value (`_redact_refresh`,
#: `_LINK_URI`); any other header whose value starts as a URL is walked too
#: (`_URL_VALUE`). BUG-0556 review round 2, N6.
_URL_HEADERS = frozenset({"location", "content-location", "referer", "origin",
                          "destination", "x-original-url", "x-rewrite-url",
                          "ping-from", "ping-to"})
_URL_VALUE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://|/")
#: A ``Link`` header's URI references, each between ``<`` and ``>`` (RFC 8288).
_LINK_URI = re.compile(r"<([^>]*)>")
#: ``Refresh``'s delay and the optional ``url=`` before its URL, as the HTML "shared
#: declarative refresh steps" skip them: whitespace, digits and dots, whitespace, an
#: optional ``;`` or ``,``, whitespace, and ``url`` (any case), whitespace, ``=`` and
#: whitespace when present. What follows is the URL, quoted or to the end.
_REFRESH_PREFIX = re.compile(
    r"[ \t]*[0-9.]*[ \t]*[;,]?[ \t]*(?:[Uu][Rr][Ll][ \t]*=[ \t]*)?")


def _redact_refresh(value: str) -> str:
    """``Refresh``'s URL passed to the walk (`_walk_names`), whichever spelling holds it
    (review round 2, N6: only ``url=`` with no spaces was read). It reads the quoted URL
    only; what 7393c90 read (every ``url=`` run to whitespace, a closing quote and the
    tail after it included) its floor has redacted first (BUG-0556 r6, R3)."""
    prefix = _REFRESH_PREFIX.match(value).group(0)
    rest = value[len(prefix):]
    if rest[:1] in ("'", '"'):
        end = rest.find(rest[0], 1)
        end = len(rest) if end < 0 else end
        return prefix + rest[0] + _walk_names(rest[1:end]) + rest[end:]
    url = rest.rstrip(" \t")
    return prefix + _walk_names(url) + rest[len(url):]


def _redact_header_value(name: str, value: str) -> str:
    """One header value with the URL it bears passed to the walk (`_walk_names`;
    unchanged when the header bears none, or the URL holds no sensitively named
    value)."""
    if name == "refresh":
        return _redact_refresh(value)
    if name == "link":
        return _LINK_URI.sub(lambda m: "<" + _walk_names(m.group(1)) + ">", value)
    if name in _URL_HEADERS or _URL_VALUE.match(value):
        return _walk_names(value)
    return value


def _target_span(line: bytes) -> tuple[int, int]:
    """Where a request line's target is: after the method and the whitespace that
    follows it, up to the whitespace before a final ``HTTP/`` version (or the line's
    end). Spaces and tabs are both whitespace, and a run of them is one separator, so a
    malformed line (``GET  /a;jsessionid=… HTTP/1.1``) is read whole (review round 2,
    N6: ``split(b" ")[1]`` read it as empty). ``(0, 0)`` when there is none. Linear."""
    i = 0
    while i < len(line) and line[i] not in b" \t":
        i += 1
    j = i
    while j < len(line) and line[j] in b" \t":
        j += 1
    if i == 0 or j == i or j >= len(line):
        return 0, 0
    end = len(line)
    while end > j and line[end - 1] in b" \t":
        end -= 1
    last = max(line.rfind(b" ", j, end), line.rfind(b"\t", j, end))
    if last >= j and line[last + 1:end].startswith(b"HTTP/"):
        end = last
        while end > j and line[end - 1] in b" \t":
            end -= 1
    return j, end


def _dechunk(body: bytes, limit: int) -> bytes | None:
    """The payload of a chunked body (trailers ignored), or ``None`` if malformed or
    longer than ``limit``."""
    out, i = bytearray(), 0
    while True:
        j = body.find(b"\r\n", i)
        if j == -1:
            return None
        try:
            size = int(body[i:j].split(b";", 1)[0].strip(), 16)
        except ValueError:
            return None
        if size == 0:
            return bytes(out)
        if len(out) + size > limit or j + 2 + size > len(body):
            return None
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2


def _decompress(data: bytes, encoding: str, limit: int) -> bytes | None:
    """``data`` decoded per ``Content-Encoding`` (gzip / x-gzip / deflate), bounded to
    ``limit`` bytes of output; ``None`` if unknown, malformed or too large."""
    enc = encoding.strip().lower()
    if enc in ("", "identity"):
        return data
    modes = {"gzip": (16 + zlib.MAX_WBITS,), "x-gzip": (16 + zlib.MAX_WBITS,),
             "deflate": (zlib.MAX_WBITS, -zlib.MAX_WBITS)}.get(enc)
    if modes is None:
        return None                                       # br, zstd, chains: not decoded
    for wbits in modes:
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(data, limit + 1)
        except zlib.error:
            continue
        if len(out) > limit or d.unconsumed_tail:
            return None                                   # a decompression bomb
        return out
    return None


def _framed_payload(msg: RawMessage, body: bytes) -> bytes | None:
    """``body`` with its transfer and content codings removed (bounded), or ``None``."""
    data = body
    if (te := _header(msg, "Transfer-Encoding")) and "chunked" in te.lower():
        data = _dechunk(data, MAX_REDACT_BYTES)
        if data is None:
            return None
    return _decompress(data, _header(msg, "Content-Encoding"), MAX_REDACT_BYTES)


def _framed_body_unsafe(msg: RawMessage, body: bytes) -> bool:
    """For a chunked / compressed body: True when it must not be stored as received —
    its decoded payload carries a secret, or it cannot be decoded while its type is
    redactable (fail closed, BUG-0100). A clean one is kept byte-exact."""
    ct = _header(msg, "Content-Type")
    payload = _framed_payload(msg, body)
    if payload is None:
        return body_kind(b"", ct) is not None or mentions_sensitive_name(body)
    return redact_body(payload, ct) != payload


def _header(msg: RawMessage, name: str) -> str:
    v = msg.get(name)
    return v.decode("latin-1", "replace") if v is not None else ""


def redact(raw: bytes, extra_headers: tuple[str, ...] = ()) -> bytes:
    """Return ``raw`` with its secrets replaced by a placeholder (see the module
    docstring). Benign headers, parameters and fields are left untouched.

    Layered (BUG-0556 r6, `core.redaction.LAYERED`): the pushed tree's own `redact`
    runs first (`core.redaction_floor.redact`, frozen at 7393c90: the sensitive headers,
    the request target's query, ``Location``, ``Content-Location`` and ``Refresh``'s
    every ``url=`` run, a duplicate of a rewritten one collapsed into it, the bodies),
    then the walk (`_walk`) on its output only. Where the floor raises (a URL
    ``urlsplit`` rejects in the request line or one of those headers), so does this:
    the history writer withholds the flow (``_prepare_contained``), as on 7393c90."""
    out = _floor.redact(raw, extra_headers)
    return _walk(out, extra_headers)


def _walk(raw: bytes, extra_headers: tuple[str, ...] = ()) -> bytes:
    """`redact`'s walk (the 144d234 redactor), on its floor's output."""
    msg = RawMessage.from_bytes(raw)
    names = set(SENSITIVE_HEADERS) | {h.lower() for h in extra_headers}
    for line in msg.header_lines():
        i = line.find(b":")
        if i != -1 and is_sensitive_name(line[:i].decode("latin-1", "replace")):
            names.add(line[:i].decode("latin-1", "replace").lower())
    for name in names:
        if msg.get(name) is not None:
            # Replace every occurrence (duplicates included) with the placeholder.
            n = len(msg.get_all(name))
            msg = msg.without_header(name)
            for _ in range(n):
                msg = msg.with_appended_header(name, REDACTED)
    # the request target (a response's start line has none) and every URL-bearing
    # header value, each passed whole to the walk (`_walk_names`: `redact_url` past its
    # floor, which `redact` ran on the whole message first), never gated on a '?': a
    # ';jsessionid=' path parameter or a query-shaped fragment holds a secret with no
    # query (Tomcat URL rewriting; BUG-0556 review round 1). The walk returns a URL
    # holding no value byte-identical, so a clean message is unchanged.
    line = msg.start_line
    if not line.startswith(b"HTTP/"):
        start, end = _target_span(line)
        target = line[start:end].decode("latin-1")
        new_target = _walk_names(target)
        if new_target != target:
            msg = msg.with_request_line(line[:start] + new_target.encode("latin-1")
                                        + line[end:])
    # every value of every URL-bearing header, rewritten in place: duplicates
    # included, order and the other lines kept byte-exact (review round 2, N6: only the
    # first value was read, and a changed one replaced every duplicate)
    lines, changed = [], False
    for hline in msg.header_lines():
        i = hline.find(b":")
        name = hline[:i].decode("latin-1").strip().lower() if i != -1 else ""
        if i != -1 and name not in names:
            raw_value = hline[i + 1:].decode("latin-1")
            value = raw_value.strip(" \t")
            new = _redact_header_value(name, value)
            if new != value:
                lead = raw_value[:len(raw_value) - len(raw_value.lstrip(" \t"))]
                trail = raw_value[len(raw_value.rstrip(" \t")):]
                hline = hline[:i + 1] + (lead + new + trail).encode("latin-1")
                changed = True
        lines.append(hline)
    if changed:
        msg = msg._rebuild(msg.start_line, lines, msg.body)
    # bodies. Chunked / compressed: decoded (bounded) and checked; a body that is not
    # provably clean is replaced by the marker with framing made consistent (B-S3),
    # a clean one is kept byte-exact.
    if msg.body and (msg.get("Transfer-Encoding") is not None
                     or msg.get("Content-Encoding") is not None):
        if _framed_body_unsafe(msg, msg.body):
            msg = msg.without_header("Transfer-Encoding").without_header(
                "Content-Encoding").with_body(OMIT_UNSAFE)
            msg = msg.with_header("Content-Length", str(len(OMIT_UNSAFE)))
    elif msg.body:
        old = msg.body
        new = redact_body(old, _header(msg, "Content-Type"))
        if new != old:
            msg = msg.with_body(new)
            declared = _header(msg, "Content-Length").strip()
            if declared.isdigit() and int(declared) == len(old):
                msg = msg.with_header("Content-Length", str(len(new)))
    return msg.raw


def redact_body_for(raw: bytes, body: bytes) -> bytes:
    """``body`` (stored apart from its message) redacted by the content type and framing
    of the message ``raw`` it belongs to (FR-PROXY-11)."""
    if not body:
        return body
    msg = RawMessage.from_bytes(raw or b"")
    if msg.get("Transfer-Encoding") is not None or msg.get("Content-Encoding") is not None:
        return OMIT_UNSAFE if _framed_body_unsafe(msg, body) else body
    return redact_body(body, _header(msg, "Content-Type"))
