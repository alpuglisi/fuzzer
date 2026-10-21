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
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from fuzzlab.core import bodyread
from fuzzlab.proxy import framing
from fuzzlab.proxy.authority import join_authority, split_authority
from fuzzlab.proxy.history import FlowRecord, HistoryWriter
from fuzzlab.proxy.intercept import Interceptor
from fuzzlab.proxy.matchreplace import MatchReplaceEngine
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.repeater import Sender
from fuzzlab.proxy.scope import Scope
from fuzzlab.proxy.socketsender import MAX_HEAD_BYTES

if TYPE_CHECKING:
    from fuzzlab.proxy.ca import LocalCA

#: What the listener answers when it will not take a request (FR-PROXY-401/403). Each
#: closes its connection and says so (PA-0153(4)).
_BAD_REQUEST = (b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
                b"Connection: close\r\n\r\n")
_REQUEST_TIMEOUT = (b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\n\r\n")
_TOO_LARGE = (b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n"
              b"Connection: close\r\n\r\n")
_HEADERS_TOO_LARGE = (b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                      b"Content-Length: 0\r\nConnection: close\r\n\r\n")
_UNAVAILABLE = (b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                b"Connection: close\r\n\r\n")
#: An upstream that failed, was cut, or closed without answering (FR-PROXY-402).
_BAD_GATEWAY = (b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                b"Connection: close\r\n\r\n")


@dataclass(frozen=True)
class InboundLimits:
    """Bounds on what clients send the listener (FR-PROXY-403), each enforced while
    reading. Defaults: a head as large as an upstream one (`MAX_HEAD_BYTES`); a body of
    SP-60's wire ceiling (`bodyread.MAX_WIRE_BYTES`); one request whole within SP-60's
    default deadline (`bodyread.DEFAULT_SECONDS`); 64 connections at once. Worst-case
    buffered bytes: connections x (head + body + one upstream response)."""
    max_header_bytes: int = MAX_HEAD_BYTES
    max_body_bytes: int = bodyread.MAX_WIRE_BYTES
    request_deadline: float = bodyread.DEFAULT_SECONDS
    max_connections: int = 64

    def __post_init__(self):
        for name in ("max_header_bytes", "max_body_bytes", "max_connections"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if not self.request_deadline > 0:
            raise ValueError("request_deadline must be positive")


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
    host, port = split_authority(line[1].decode("latin-1", "replace"), 443)
    return host, port


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
    host, port_n = split_authority(host_hdr, default_port or (443 if use_tls else 80))
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
    #: Flows the history could not take because handing one over raised, by the
    #: error's class. A history failure is counted here and never reaches the flow: the
    #: client still gets the upstream's answer, or the 502 of the upstream's own failure
    #: (FR-PROXY-404, BUG-0543 integration). `fuzzlab proxy` prints them when it stops.
    history_failures: Counter = field(default_factory=Counter, init=False,
                                      compare=False)

    async def handle_request(self, raw: bytes, host: str, port: int,
                             use_tls: bool = False) -> bytes | None:
        """Process one request; return the raw response, or ``None`` if dropped.

        Out-of-scope traffic is forwarded **untouched and unrecorded** (FR-PROXY-5):
        the proxy stays transparent for hosts the user did not name.
        """
        msg = RawMessage.from_bytes(raw)
        path = msg.target.decode("latin-1", "replace")
        # one decision, on the most specific key (BUG-0086): a port-less rule already
        # matches any port, and a second, bare-host check let a port-specific exclude
        # be overridden by a host-wide include
        if not self.scope.in_scope(_authority(host, port), path):
            # blocking socket I/O never runs on the event loop (BUG-0101)
            return await asyncio.to_thread(self.sender, host, port, use_tls, raw)

        started = time.time()                    # the flow's own time (FR-PROXY-13)
        decisions: list[str] = []                # the operator's, when a message was held
        if self.matchreplace is not None:
            msg = self.matchreplace.apply(msg)
        if self.interceptor is not None:
            held = bool(self.interceptor.enabled)
            decided = await self.interceptor.handle(msg, "request", host)
            if decided is None:
                return None                                  # dropped by the user
            if held:
                decisions.append("request edited" if decided.raw != msg.raw
                                 else "request forwarded")
            msg = decided

        try:
            resp = await asyncio.to_thread(self.sender, host, port, use_tls,
                                           msg.raw)                   # byte-exact forward
        except Exception as exc:
            # an in-scope flow whose upstream failed is recorded with no response and
            # its error class (FR-PROXY-13); the connection still answers 502
            if self.history is not None:
                self._record(msg, b"", host, port, use_tls, t=started,
                             error=type(exc).__name__, decisions=decisions)
            raise
        # Optional response interception (Burp-style "intercept responses"): only when
        # the interceptor opts in, so the default path stays byte-exact (the wrap+`.raw`
        # round-trips the exact bytes). A dropped response sends nothing to the client.
        if self.interceptor is not None and getattr(self.interceptor,
                                                    "intercept_responses", False):
            held = bool(self.interceptor.enabled)
            decided = await self.interceptor.handle(
                RawMessage.from_bytes(resp), "response", host)
            if decided is None:
                return None
            if held:
                decisions.append("response edited" if decided.raw != resp
                                 else "response forwarded")
            resp = decided.raw
        if self.history is not None:
            self._record(msg, resp, host, port, use_tls, t=started, decisions=decisions)
        return resp

    def _record(self, msg: RawMessage, resp: bytes, host: str, port: int,
                use_tls: bool, *, t: float | None = None, error: str | None = None,
                decisions: list[str] | None = None) -> None:
        """Hand one in-scope flow to the history with bounded work on the event loop
        (BUG-0550, FR-PROXY-404): the method, target and status come from each
        message's first line only, and `HistoryWriter.submit` only queues the flow; the
        writer's own thread redacts, hashes and stores it. Never store or redaction work
        here (PA-0550).

        A history that raises never changes the flow (PA-0086(2), PA-0554(2)): the
        failure is counted in `history_failures` by its class, and the client gets the
        upstream's answer, or the upstream's own failure, as without a history. Before
        this, one raise turned a relayed 200 into a 502 (BUG-0543 integration)."""
        try:
            scheme = "https" if use_tls else "http"
            req = _first_line_of(msg.raw)
            status = None
            if resp:
                sl = _first_line_of(resp).start_line.split(b" ")
                if len(sl) >= 2 and sl[1].isdigit():
                    status = int(sl[1])
            authority = _authority(host, port)
            self.history.submit(FlowRecord(
                method=req.method.decode("latin-1", "replace"),
                url=f"{scheme}://{authority}{req.target.decode('latin-1', 'replace')}",
                host=authority, status=status, identity=self.identity,
                in_scope=True, raw_request=msg.raw, raw_response=resp, t=t, error=error,
                intercept="; ".join(decisions) if decisions else None,
            ))
        except Exception as exc:  # noqa: BLE001 - a flow's history never fails its traffic
            self.history_failures[type(exc).__name__] += 1


def _first_line_of(raw: bytes) -> RawMessage:
    """A message holding ``raw`` up to just past its first line end: its `start_line`
    (so `method`, `target`) equals the whole message's, read without scanning or
    copying the rest (the body) on the event loop (BUG-0550)."""
    end = raw.find(b"\n")
    return RawMessage.from_bytes(raw if end < 0 else raw[:end + 2])


class AsyncProxyServer:
    """asyncio socket layer over :class:`ProxyEngine`.

    The **plain-HTTP** path (absolute-form requests from a proxy-configured browser) is
    offline-testable over loopback. **CONNECT + TLS interception** is enabled by passing
    a :class:`~fuzzlab.proxy.ca.LocalCA`; without one, CONNECT still answers 501 (the
    offline default). The CONNECT path terminates TLS with a CA-minted leaf and forwards
    tunnelled requests through the same engine — on-host (needs a working ``cryptography``
    for minting and a browser that trusts the CA).

    Every request is read whole before it is forwarded, framed by SP-63
    (`framing.MessageReader`): a chunked body is de-chunked (trailer included) and sent
    with a ``Content-Length``; an unframeable request is answered 400 and never
    forwarded (FR-PROXY-401). Reading is bounded by `InboundLimits` (FR-PROXY-403): head
    and body sizes while they arrive (431 / 413), a deadline for each whole request
    (408), and a connection cap over which a client is answered 503. ``counts`` counts
    each refusal.
    """

    def __init__(self, engine: ProxyEngine, host: str = "127.0.0.1", port: int = 0,
                 ca: "LocalCA | None" = None, *, limits: InboundLimits | None = None,
                 raw_framing: bool = False):
        self.engine = engine
        self.host = host
        self.port = port
        self.ca = ca
        self.limits = limits or InboundLimits()
        #: the explicit raw mode (D4): conflicting Content-Length values frame by the
        #: first and the request is forwarded byte-exact, not refused (SP-63)
        self.raw_framing = raw_framing
        self._server: asyncio.AbstractServer | None = None
        self._conns: set[asyncio.Task] = set()
        self.errors: list[str] = []               # contained per-connection failures
        #: what the listener refused (FR-PROXY-403): a connection over the cap (503), an
        #: unframeable request (400), one over a size bound (413 / 431), one cut at the
        #: request deadline (408), a connection idle at it (closed, nothing received)
        self.counts: dict[str, int] = dict.fromkeys(
            ("refused", "malformed", "oversized", "timed_out", "idle"), 0)

    async def start(self) -> "AsyncProxyServer":
        from fuzzlab.core.net import require_loopback
        require_loopback(self.host, "the proxy")      # defence in depth (BUG-0080)
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
        if len(self._conns) >= self.limits.max_connections:
            self.counts["refused"] += 1           # over the cap: refused, never queued
            try:
                writer.write(_UNAVAILABLE)
                writer.close()
            except (OSError, RuntimeError):
                pass
            return
        task = asyncio.current_task()
        if task is not None:
            self._conns.add(task)
        written = False
        conn = _Inbound(reader)
        try:
            raw = await self._next_request(conn, writer)
            if raw is None:
                return
            connect = parse_connect(raw)
            if connect is not None:
                if self.ca is None:
                    # No local CA wired: TLS interception is off (offline default).
                    writer.write(b"HTTP/1.1 501 Not Implemented\r\n"
                                 b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    return
                written = True        # it answers 200 first: never a 502 into the tunnel
                await self._handle_connect(conn, writer, connect)
                return
            tgt = target_from_request(raw)
            resp = await self.engine.handle_request(tgt.request, tgt.host, tgt.port,
                                                    tgt.use_tls)
            if resp is not None:
                written = True
                writer.write(resp or _BAD_GATEWAY)   # closed unanswered: 502, not empty
                await writer.drain()
        except asyncio.CancelledError:
            pass                                     # shutting down; drop this connection
        except Exception as exc:                     # noqa: BLE001 - per connection
            # one connection's failure never takes the proxy down (BUG-0085): 502 when
            # nothing was sent yet, otherwise just close
            self.errors.append(repr(exc))
            if not written:
                try:
                    writer.write(_BAD_GATEWAY)
                    await writer.drain()
                except (OSError, RuntimeError):
                    pass
        finally:
            try:
                writer.close()
            except OSError:
                pass
            if task is not None:
                self._conns.discard(task)

    async def _next_request(self, conn: "_Inbound",
                            writer: asyncio.StreamWriter) -> bytes | None:
        """Read one whole request from ``conn`` within `InboundLimits` (SP-63 framing)
        and return it as it is forwarded: byte-exact, or de-chunked with a
        ``Content-Length``. ``None`` when there is none: the client closed, or the
        listener answered why not (400 / 408 / 413 / 431, counted); nothing is
        forwarded then."""
        lim = self.limits
        rd = framing.MessageReader(
            "request", framing.FrameLimits(lim.max_header_bytes, lim.max_body_bytes),
            dechunk=True, raw_length=self.raw_framing)
        try:
            async with asyncio.timeout(lim.request_deadline):   # the whole request
                if conn.leftover:
                    rd.feed(conn.take())
                while not rd.done:
                    data = await conn.reader.read(bodyread.READ_SIZE)
                    if not data:
                        if rd.received:
                            rd.eof()        # raises: a request never ends at a close
                        return None
                    rd.feed(data)
        except TimeoutError:
            if not rd.received:
                self.counts["idle"] += 1
                return None
            self.counts["timed_out"] += 1
            await _answer(conn, writer, _REQUEST_TIMEOUT)
            return None
        except framing.OverLimit as exc:
            self.counts["oversized"] += 1
            await _answer(conn, writer,
                          _HEADERS_TOO_LARGE if exc.part == "head" else _TOO_LARGE)
            return None
        except framing.FramingError:
            self.counts["malformed"] += 1
            await _answer(conn, writer, _BAD_REQUEST)
            return None
        except framing.Incomplete:
            return None                         # cut by the client: nothing forwarded
        conn.leftover = rd.leftover
        return rd.message()

    async def _handle_connect(self, conn: "_Inbound",
                              writer: asyncio.StreamWriter,
                              connect: tuple[str, int]) -> None:
        """Terminate CONNECT: reply 200, TLS-serve with a CA-minted leaf, forward.

        After the TLS upgrade the tunnelled requests are origin-form for ``host``; each
        is read whole (`_next_request`) and forwarded through the same engine with
        ``use_tls=True`` (the real upstream is HTTPS). The tunnel ends after a response
        that ends its connection (`framing.closes_connection`). On-host only — minting
        and the handshake need a working ``cryptography``.
        """
        host, port = connect
        if conn.leftover:
            return                  # bytes sent before the tunnel existed: not TLS
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
            raw = await self._next_request(conn, writer)
            if raw is None:
                break
            try:
                resp = await self.engine.handle_request(raw, host, port, use_tls=True)
            except Exception as exc:                 # noqa: BLE001 - per request
                self.errors.append(repr(exc))        # contained, as outside (BUG-0085)
                resp = b""
            if resp is None:
                break                                # dropped by the operator
            if not resp:
                # a failed, cut or unanswered upstream is a 502 inside the tunnel: an
                # empty close on a reused connection is retried by the browser
                await _answer(conn, writer, _BAD_GATEWAY)
                break
            writer.write(resp)
            await writer.drain()
            if framing.closes_connection(raw, resp):
                break


def _leaf_server_context(ca: "LocalCA", host: str) -> ssl.SSLContext:
    """A server-side TLS context using ``host``'s CA-minted leaf cert (on-host)."""
    cert_path, key_path = ca.leaf_cert_files(host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


class _Inbound:
    """One client connection: its reader and the bytes received past the last request
    (a pipelined next one)."""

    def __init__(self, reader: asyncio.StreamReader):
        self.reader = reader
        self.leftover = b""

    def take(self) -> bytes:
        data, self.leftover = self.leftover, b""
        return data


#: How long a refused connection is drained before it is closed (a lingering close).
_LINGER_SECONDS = 1.0


async def _answer(conn: _Inbound, writer: asyncio.StreamWriter, response: bytes) -> None:
    """Write one of the listener's own refusals; its connection is closed after it.

    A lingering close: the write side is shut (FIN) and what the client still sends is
    read and discarded for at most `_LINGER_SECONDS`, so closing over unread bytes does
    not reset the connection before the client has read the refusal."""
    try:
        writer.write(response)
        await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
        async with asyncio.timeout(_LINGER_SECONDS):
            while await conn.reader.read(bodyread.READ_SIZE):
                pass
    except (OSError, RuntimeError, TimeoutError):
        pass


def _authority(host: str, port: int) -> str:
    return join_authority(host, port)
