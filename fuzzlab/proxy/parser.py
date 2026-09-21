"""Parsed HTTP/1.1 path — the ``h11`` view over raw bytes (D4).

This is the *convenience* path: it validates and normalizes, so callers get a clean
structured request/response. It is deliberately separate from ``RawMessage`` (the
byte-exact path). The split is the whole point of the hybrid design (D4): traffic that
``h11`` rejects or would normalize — a duplicate/conflicting ``Content-Length``, an
obs-fold, a smuggling primitive — is exactly what the raw path preserves for study.

``h11`` is sans-I/O, so parsing here is pure: feed bytes in, read events out. No
sockets. HTTP/2 and WebSocket parsing (``h2``/``wsproto``) are Phase 9.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import h11


class ParseError(ValueError):
    """The parsed path rejected the message (the raw path may still carry it)."""


@dataclass
class ParsedRequest:
    method: bytes
    target: bytes
    http_version: bytes
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> bytes | None:
        key = name.lower().encode("latin-1")
        for n, v in self.headers:
            if n.lower() == key:
                return v
        return None


@dataclass
class ParsedResponse:
    status_code: int
    http_version: bytes
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    body: bytes = b""


def _drain(conn: h11.Connection, raw: bytes):
    """Feed ``raw`` (then EOF) and yield events until data runs out."""
    conn.receive_data(raw)
    conn.receive_data(b"")  # signal EOF so close-delimited bodies complete
    events = []
    while True:
        try:
            ev = conn.next_event()
        except h11.RemoteProtocolError as exc:  # framing/validation failure
            raise ParseError(str(exc)) from exc
        if ev is h11.NEED_DATA or ev is h11.PAUSED:
            break
        if isinstance(ev, h11.ConnectionClosed):
            break
        events.append(ev)
        if isinstance(ev, h11.EndOfMessage):
            break
    return events


def parse_request(raw: bytes) -> ParsedRequest:
    """Parse a request via ``h11``; raise ``ParseError`` if it is not well-formed.

    Conflicting framing (e.g. two different ``Content-Length`` values) is rejected
    here — use ``RawMessage`` to forward such a request byte-for-byte.
    """
    conn = h11.Connection(our_role=h11.SERVER)
    req = None
    body = bytearray()
    for ev in _drain(conn, bytes(raw)):
        if isinstance(ev, h11.Request):
            req = ev
        elif isinstance(ev, h11.Data):
            body += ev.data
    if req is None:
        raise ParseError("no complete request in bytes")
    return ParsedRequest(
        method=bytes(req.method),
        target=bytes(req.target),
        http_version=bytes(req.http_version),
        headers=[(bytes(n), bytes(v)) for n, v in req.headers],
        body=bytes(body),
    )


def parse_response(raw: bytes, request_method: str | bytes = b"GET") -> ParsedResponse:
    """Parse a response via ``h11``.

    A response's framing depends on the request method (e.g. HEAD has no body), so the
    method that produced it is supplied; it defaults to GET.
    """
    method = request_method if isinstance(request_method, bytes) \
        else request_method.encode("latin-1")
    client = h11.Connection(our_role=h11.CLIENT)
    # Prime the client so it expects a response (sans-I/O; bytes discarded).
    client.send(h11.Request(method=method, target="/",
                            headers=[("host", "proxy.local")]))
    client.send(h11.EndOfMessage())
    resp = None
    body = bytearray()
    for ev in _drain(client, bytes(raw)):
        if isinstance(ev, h11.Response):
            resp = ev
        elif isinstance(ev, h11.Data):
            body += ev.data
    if resp is None:
        raise ParseError("no complete response in bytes")
    return ParsedResponse(
        status_code=int(resp.status_code),
        http_version=bytes(resp.http_version),
        headers=[(bytes(n), bytes(v)) for n, v in resp.headers],
        body=bytes(body),
    )


def is_valid_request(raw: bytes) -> bool:
    """True if the parsed path accepts ``raw`` (well-formed, unambiguous framing)."""
    try:
        parse_request(raw)
        return True
    except ParseError:
        return False
