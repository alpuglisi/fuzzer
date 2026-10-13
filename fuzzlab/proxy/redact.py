"""Secret redaction for persisted proxy data (NFR-PROXY-safe, FR-PROXY-11).

The proxy forwards **byte-exact** bytes on the wire (the raw path), but what it
*persists* — flow history (its rows, stored bodies and full-text index) — must not
carry credentials or tokens in cleartext. Before anything is written, this module
redacts:

- **headers:** the values of sensitive headers (`SENSITIVE_HEADERS`, plus any header
  whose name `core.redaction.is_sensitive_name` flags);
- **URL query parameters:** sensitively named ones, in the request target and in
  ``Location`` / ``Content-Location`` / ``Refresh`` response headers;
- **bodies:** sensitively named fields of form-urlencoded, JSON (any depth) and
  multipart (non-file) bodies, in requests and responses alike. A sensitive JSON key's
  **whole value** is replaced, whatever its type (list, object, scalar; BUG-0090).

Sensitivity is by name **token** (`core.redaction`, BUG-0084), so benign fields such as
``author`` stay readable. A body whose bytes the proxy cannot safely rewrite — chunked
or ``Content-Encoding``-compressed — is stored as received: a stated residual. A JSON
body is re-serialised only when it holds a sensitive key, so every other body stays
byte-identical. ``Content-Length`` is recomputed when a redacted body changes length,
if it was consistent before.

Trade-off: a Repeater tab seeded from history carries the placeholders, so replaying a
JWT / session / CSRF flow needs a fresh capture or ``HistoryWriter(redact_secrets=
False)`` (lab-local opt-out).
"""

from __future__ import annotations

import json
import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from fuzzlab.core.redaction import is_sensitive_name
from fuzzlab.proxy.message import RawMessage

REDACTED = b"__REDACTED__"
_TEXT = REDACTED.decode()

# Header names whose values are secrets. Compared case-insensitively.
SENSITIVE_HEADERS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
)
_URL_HEADERS = ("location", "content-location", "refresh")


def redact_query(query: str) -> str:
    """``query`` with each sensitively named parameter's value replaced."""
    if not query:
        return query
    out = []
    for part in query.split("&"):
        name, eq, _value = part.partition("=")
        out.append(f"{name}={_TEXT}" if eq and is_sensitive_name(unquote_plus(name))
                   else part)
    return "&".join(out)


def redact_url(url: str) -> str:
    """``url`` (absolute or origin-form) with sensitive query values replaced."""
    if "?" not in (url or ""):
        return url
    parts = urlsplit(url)
    new = redact_query(parts.query)
    return url if new == parts.query else urlunsplit(parts._replace(query=new))


def _redact_json(value):
    # A sensitive key's whole value is the secret, whatever its shape: a scalar, a list
    # or a nested object is replaced by the placeholder (BUG-0090, PA-0091).
    if isinstance(value, dict):
        return {k: (_TEXT if is_sensitive_name(str(k)) else _redact_json(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_json(v) for v in value]
    return value


def _redact_multipart(body: bytes, content_type: str) -> bytes:
    m = re.search(r'boundary="?([^";]+)"?', content_type, re.I)
    if not m:
        return body
    delim = b"--" + m.group(1).encode("latin-1")
    parts = body.split(delim)
    for i, part in enumerate(parts):
        head, sep, data = part.partition(b"\r\n\r\n")
        name = re.search(rb'\bname="([^"]*)"', head)
        if sep and name and b"filename=" not in head \
                and is_sensitive_name(name.group(1).decode("latin-1")):
            parts[i] = head + sep + REDACTED + (b"\r\n" if data.endswith(b"\r\n") else b"")
    return delim.join(parts)


def redact_body(body: bytes, content_type: str) -> bytes:
    """``body`` with sensitively named fields replaced, per its content type."""
    if not body:
        return body
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct == "application/x-www-form-urlencoded":
        text = body.decode("latin-1")
        new = redact_query(text)
        return body if new == text else new.encode("latin-1")
    if ct == "application/json" or ct.endswith("+json"):
        try:
            doc = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return body
        new = _redact_json(doc)
        if new == doc:
            return body                              # byte-identical when nothing matched
        return json.dumps(new, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if ct.startswith("multipart/form-data"):
        return _redact_multipart(body, content_type or "")
    return body


def _original_name(msg: RawMessage, name: str) -> bytes:
    """The header's name as the message spells it (keep the persisted copy faithful)."""
    for line in msg.header_lines():
        i = line.find(b":")
        if i != -1 and line[:i].lower() == name.encode():
            return line[:i]
    return name.encode()


def _header(msg: RawMessage, name: str) -> str:
    v = msg.get(name)
    return v.decode("latin-1", "replace") if v is not None else ""


def redact(raw: bytes, extra_headers: tuple[str, ...] = ()) -> bytes:
    """Return ``raw`` with its secrets replaced by a placeholder (see the module
    docstring). Benign headers, parameters and fields are left untouched."""
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
    # the request target's query (a response's start line has none)
    target = msg.target.decode("latin-1", "replace")
    if not msg.start_line.startswith(b"HTTP/") and "?" in target:
        new_target = redact_url(target)
        if new_target != target:
            parts = msg.start_line.split(b" ")
            parts[1] = new_target.encode("latin-1")
            msg = msg.with_request_line(b" ".join(parts))
    for name in _URL_HEADERS:
        value = _header(msg, name)
        if "?" in value:
            new = redact_url(value) if name != "refresh" else re.sub(
                r"(url=)(\S+)", lambda m: m.group(1) + redact_url(m.group(2)), value,
                flags=re.I)
            if new != value:
                msg = msg.with_header(_original_name(msg, name), new)
    # bodies: never rewrite framing we do not control
    if msg.body and msg.get("Transfer-Encoding") is None \
            and msg.get("Content-Encoding") is None:
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
        return body
    return redact_body(body, _header(msg, "Content-Type"))
