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
import ssl
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from fuzzlab.proxy.history import FlowRecord, HistoryWriter
from fuzzlab.proxy.intercept import Interceptor
from fuzzlab.proxy.matchreplace import MatchReplaceEngine
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.repeater import Sender
from fuzzlab.proxy.scope import Scope

if TYPE_CHECKING:
    from fuzzlab.proxy.ca import LocalCA


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
    """asyncio socket layer over :class:`ProxyEngine`.

    The **plain-HTTP** path (absolute-form requests from a proxy-configured browser) is
    offline-testable over loopback. **CONNECT + TLS interception** is enabled by passing
    a :class:`~fuzzlab.proxy.ca.LocalCA`; without one, CONNECT still answers 501 (the
    offline default). The CONNECT path terminates TLS with a CA-minted leaf and forwards
    tunnelled requests through the same engine — on-host (needs a working ``cryptography``
    for minting and a browser that trusts the CA).
    """

    def __init__(self, engine: ProxyEngine, host: str = "127.0.0.1", port: int = 0,
                 ca: "LocalCA | None" = None):
        self.engine = engine
        self.host = host
        self.port = port
        self.ca = ca
        self._server: asyncio.AbstractServer | None = None
        self._conns: set[asyncio.Task] = set()

    async def start(self) -> "AsyncProxyServer":
        self._server = await asyncio.start_server(self._on_client, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        # Cancel in-flight connections; otherwise wait_closed() blocks on keep-alive
        # sockets (Python 3.12+ waits for active connections), hanging shutdown.
        for task in list(self._conns):
            task.cancel()
        try:
            await asyncio.wait_for(self._server.wait_closed(), timeout=3.0)
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001 - shutdown is best-effort
            pass
        self._server = None

    async def _on_client(self, reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._conns.add(task)
        try:
            raw = await _read_http_message(reader)
            if not raw:
                return
            connect = parse_connect(raw)
            if connect is not None:
                if self.ca is None:
                    # No local CA wired: TLS interception is off (offline default).
                    writer.write(b"HTTP/1.1 501 Not Implemented\r\n"
                                 b"Content-Length: 0\r\n\r\n")
                    await writer.drain()
                    return
                await self._handle_connect(reader, writer, connect)
                return
            tgt = target_from_request(raw)
            resp = await self.engine.handle_request(tgt.request, tgt.host, tgt.port,
                                                    tgt.use_tls)
            if resp is not None:
                writer.write(resp)
                await writer.drain()
        except asyncio.CancelledError:
            pass                                     # shutting down; drop this connection
        finally:
            try:
                writer.close()
            except OSError:
                pass
            if task is not None:
                self._conns.discard(task)

    async def _handle_connect(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter,
                              connect: tuple[str, int]) -> None:
        """Terminate CONNECT: reply 200, TLS-serve with a CA-minted leaf, forward.

        After the TLS upgrade the tunnelled requests are origin-form for ``host``; each
        is forwarded through the same engine with ``use_tls=True`` (the real upstream is
        HTTPS). On-host only — minting and the handshake need a working ``cryptography``.
        """
        host, port = connect
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        try:
            ctx = _leaf_server_context(self.ca, host)
        except Exception:  # noqa: BLE001 - minting/crypto failure must not crash the loop
            return
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()
        try:
            tls_transport = await loop.start_tls(
                transport, protocol, ctx, server_side=True)
        except (ssl.SSLError, OSError):
            return
        if tls_transport is None:
            return
        # Rebind writes to the upgraded (TLS) transport; the same StreamReader keeps
        # being fed decrypted bytes by the wrapped protocol.
        writer._transport = tls_transport  # noqa: SLF001 - documented start_tls-with-streams idiom
        while True:
            raw = await _read_http_message(reader)
            if not raw:
                break
            resp = await self.engine.handle_request(raw, host, port, use_tls=True)
            if resp is None:
                break
            writer.write(resp)
            await writer.drain()


def _leaf_server_context(ca: "LocalCA", host: str) -> ssl.SSLContext:
    """A server-side TLS context using ``host``'s CA-minted leaf cert (on-host)."""
    cert_path, key_path = ca.leaf_cert_files(host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


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
