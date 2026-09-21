"""Async proxy server + the sans-I/O flow engine (FR-PROXY-1/2, wiring T6.6).

Two layers:

* :class:`ProxyEngine` — the **sans-I/O** flow pipeline: scope check → match-and-replace
  → interception → forward (via an injected upstream **sender** seam) → history. It is
  fully offline-testable (no sockets), and it is where FR-PROXY-5/6/3 come together.
* :class:`AsyncProxyServer` — the asyncio socket layer over the engine. Its
  **plain-HTTP** path (absolute-form requests from a browser configured to use the
  proxy) is exercised offline over loopback. **CONNECT + TLS interception**
  (``parse_connect`` + the local CA) is the on-host last mile: the sandbox has no
  working TLS/`cryptography`, so live HTTPS serving and browser trust run on the host.

Per D5 the proxy is optional and out of the timing path; timing-sensitive fuzzing
sends directly, not through here.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urlsplit

from fuzzlab.proxy.history import FlowRecord, HistoryWriter
from fuzzlab.proxy.intercept import Interceptor
from fuzzlab.proxy.matchreplace import MatchReplaceEngine
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.repeater import Sender
from fuzzlab.proxy.scope import Scope


@dataclass
class Target:
    host: str
    port: int
    use_tls: bool
    request: bytes                    # request rewritten to origin-form for upstream


def parse_connect(raw: bytes) -> tuple[str, int] | None:
    """Parse a ``CONNECT host:port HTTP/1.1`` request; return ``(host, port)`` or None."""
    line = RawMessage.from_bytes(raw).start_line.split(b" ")
    if len(line) < 2 or line[0].upper() != b"CONNECT":
        return None
    authority = line[1].decode("latin-1", "replace")
    host, _, port = authority.partition(":")
    return host, int(port) if port.isdigit() else 443


def target_from_request(raw: bytes, use_tls: bool = False,
                        default_port: int | None = None) -> Target:
    """Resolve a request's upstream target and rewrite it to origin-form.

    Browsers proxying plain HTTP send **absolute-form** (``GET http://h:p/x HTTP/1.1``);
    after a CONNECT the tunnelled requests are **origin-form** (``GET /x HTTP/1.1`` with
    a ``Host`` header). Both are handled; the upstream always receives origin-form.
    """
    msg = RawMessage.from_bytes(raw)
    target = msg.target.decode("latin-1", "replace")
    if target.startswith(("http://", "https://")):
        parts = urlsplit(target)
        use_tls = parts.scheme == "https"
        host = parts.hostname or ""
        port = parts.port or (443 if use_tls else 80)
        origin = parts.path or "/"
        if parts.query:
            origin += "?" + parts.query
        line = b" ".join([msg.method, origin.encode("latin-1"),
                          msg.start_line.split(b" ")[-1]])
        return Target(host, port, use_tls, msg.with_request_line(line).raw)
    # origin-form: host from the Host header
    host_hdr = (msg.get("Host") or b"").decode("latin-1", "replace")
    host, _, port = host_hdr.partition(":")
    port_n = int(port) if port.isdigit() else (default_port or (443 if use_tls else 80))
    return Target(host, port_n, use_tls, raw)


@dataclass
class ProxyEngine:
    """The sans-I/O flow pipeline (scope → match-replace → intercept → forward → log)."""

    scope: Scope
    sender: Sender                                   # (host, port, use_tls, raw)->resp
    matchreplace: MatchReplaceEngine | None = None
    interceptor: Interceptor | None = None
    history: HistoryWriter | None = None
    identity: str | None = None

    async def handle_request(self, raw: bytes, host: str, port: int,
                             use_tls: bool = False) -> bytes | None:
        """Process one request; return the raw response, or ``None`` if dropped.

        Out-of-scope traffic is forwarded **untouched and unrecorded** (FR-PROXY-5):
        the proxy stays transparent for hosts the user did not name.
        """
        msg = RawMessage.from_bytes(raw)
        path = msg.target.decode("latin-1", "replace")
        if not self.scope.in_scope(_authority(host, port), path) \
                and not self.scope.in_scope(host, path):
            return self.sender(host, port, use_tls, raw)     # transparent bypass

        if self.matchreplace is not None:
            msg = self.matchreplace.apply(msg)
        if self.interceptor is not None:
            decided = await self.interceptor.handle(msg, "request", host)
            if decided is None:
                return None                                  # dropped by the user
            msg = decided

        resp = self.sender(host, port, use_tls, msg.raw)     # byte-exact forward
        if self.history is not None:
            self._record(msg, resp, host, port, use_tls)
        return resp

    def _record(self, msg: RawMessage, resp: bytes, host: str, port: int,
                use_tls: bool) -> None:
        scheme = "https" if use_tls else "http"
        status = None
        if resp:
            sl = RawMessage.from_bytes(resp).start_line.split(b" ")
            if len(sl) >= 2 and sl[1].isdigit():
                status = int(sl[1])
        self.history.record(FlowRecord(
            method=msg.method.decode("latin-1", "replace"),
            url=f"{scheme}://{_authority(host, port)}"
                f"{msg.target.decode('latin-1', 'replace')}",
            host=_authority(host, port), status=status, identity=self.identity,
            in_scope=True, raw_request=msg.raw, raw_response=resp,
        ))


class AsyncProxyServer:
    """asyncio socket layer over :class:`ProxyEngine` (plain-HTTP path offline-testable)."""

    def __init__(self, engine: ProxyEngine, host: str = "127.0.0.1", port: int = 0):
        self.engine = engine
        self.host = host
        self.port = port
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> "AsyncProxyServer":
        self._server = await asyncio.start_server(self._on_client, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _on_client(self, reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
        try:
            raw = await _read_http_message(reader)
            if not raw:
                return
            if parse_connect(raw) is not None:
                # Live CONNECT/TLS interception is on-host (needs the local CA + TLS).
                writer.write(b"HTTP/1.1 501 Not Implemented\r\n"
                             b"Content-Length: 0\r\n\r\n")
                await writer.drain()
                return
            tgt = target_from_request(raw)
            resp = await self.engine.handle_request(tgt.request, tgt.host, tgt.port,
                                                    tgt.use_tls)
            if resp is not None:
                writer.write(resp)
                await writer.drain()
        finally:
            writer.close()


async def _read_http_message(reader: asyncio.StreamReader) -> bytes:
    """Read one HTTP message: head up to CRLFCRLF, then any Content-Length body."""
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        return b""
    msg = RawMessage.from_bytes(head)
    length = msg.get("Content-Length")
    if length is not None and length.isdigit():
        n = int(length)
        body = await reader.readexactly(n) if n else b""
        return head + body
    return head


def _authority(host: str, port: int) -> str:
    return f"{host}:{port}"
