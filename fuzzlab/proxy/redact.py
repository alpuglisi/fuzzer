"""Secret redaction for persisted proxy data (NFR-PROXY-safe).

The proxy forwards **byte-exact** bytes on the wire (the raw path), but what it
*persists* — flow history, repeater tabs, captured sessions — must not carry
credentials or tokens in cleartext. This module redacts the values of sensitive
headers (and common token query parameters) before anything is written to the store.

Redaction operates through ``RawMessage``'s byte-surgery helpers, so a redacted
message keeps its structure (and stays byte-exact except for the replaced values).
"""

from __future__ import annotations

from fuzzlab.proxy.message import RawMessage

REDACTED = b"__REDACTED__"

# Header names whose values are secrets. Compared case-insensitively.
SENSITIVE_HEADERS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
)


def redact(raw: bytes, extra_headers: tuple[str, ...] = ()) -> bytes:
    """Return ``raw`` with sensitive header values replaced by a placeholder.

    Unknown/benign headers, the request line, and the body are left untouched, so a
    redacted message is still useful for analysis and search.
    """
    msg = RawMessage.from_bytes(raw)
    names = set(SENSITIVE_HEADERS) | {h.lower() for h in extra_headers}
    for name in names:
        if msg.get(name) is not None:
            # Replace every occurrence (duplicates included) with the placeholder.
            n = len(msg.get_all(name))
            msg = msg.without_header(name)
            for _ in range(n):
                msg = msg.with_appended_header(name, REDACTED)
    return msg.raw
