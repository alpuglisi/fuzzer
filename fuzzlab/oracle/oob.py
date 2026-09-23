"""Out-of-band (OOB) callback tracking for the oracle (M8).

Some injection classes leave no observable difference in the direct HTTP
response — blind SSRF, blind command injection, blind XXE. The only signal is
that the *target itself* later makes an outbound request (or DNS lookup)
carrying a canary we embedded in the payload. M8 confirms those classes by
handing the target a unique callback URL and checking whether anything ever
requested it.

Dual-use safety (mirrors the proxy/desync/WAF gating in this project, per
`CLAUDE.md` Safety and PA sweep conventions): a real listener socket exists
only once something explicitly constructs and starts an `OobListener` — the
oracle strategy that uses it (`CommandInjectionOobStrategy` and friends in
`strategies.py`) takes the listener by injection and silently no-ops
(returns ``None``, fail-closed) when none is given, exactly like the M6
`BrowserExecutor` seam. `OobListener` itself refuses to bind to anything but
loopback (``127.0.0.1``/``localhost``) — it is a local, per-run, in-memory
callback tracker for this lab, never a publicly reachable, Burp-Collaborator-
style interaction service: no DNS component, no persistence beyond the
process, and no relaying of received data anywhere.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_TOKEN_RE = re.compile(r"/cb/([0-9a-f]+)")


@dataclass
class OobHit:
    """One recorded out-of-band callback."""
    token: str
    path: str
    remote_addr: str
    received_at: float = field(default_factory=time.time)


class OobListener:
    """A local, loopback-only HTTP callback tracker.

    ``register()`` mints a unique token; ``callback_url(token)`` gives the URL
    to embed in a payload. Any HTTP request whose path carries a registered
    token is recorded as a hit; ``wait_for(token, timeout)`` polls for one.
    Nothing listens until ``start()`` is called (default-off).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        if host not in _LOOPBACK_HOSTS:
            raise ValueError(
                f"OobListener is loopback-only (lab-only); refusing host={host!r}")
        self._host = host
        self._requested_port = port
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._hits: dict[str, list[OobHit]] = {}

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def port(self) -> int:
        if self._server is not None:
            return self._server.server_address[1]
        return self._requested_port

    def start(self) -> None:
        """Bind the loopback listener and start serving in a background thread.

        Idempotent — calling it again while already running is a no-op.
        """
        if self._server is not None:
            return
        handler = _make_handler(self)
        self._server = HTTPServer((self._host, self._requested_port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def register(self) -> str:
        """Mint a fresh, unguessable token to embed in one probe's payload."""
        token = secrets.token_hex(8)
        with self._lock:
            self._hits[token] = []
        return token

    def callback_url(self, token: str, scheme: str = "http") -> str:
        if not self.running:
            raise RuntimeError("OobListener.start() must run before minting callback URLs")
        return f"{scheme}://{self._host}:{self.port}/cb/{token}"

    def record(self, token: str, path: str, remote_addr: str) -> None:
        """Record a hit for ``token`` (called by the HTTP handler)."""
        with self._lock:
            if token in self._hits:
                self._hits[token].append(OobHit(token=token, path=path, remote_addr=remote_addr))

    def hits(self, token: str) -> list[OobHit]:
        with self._lock:
            return list(self._hits.get(token, ()))

    def wait_for(self, token: str, timeout: float = 1.5, poll: float = 0.02) -> OobHit | None:
        """Poll for the first hit on ``token``, up to ``timeout`` seconds."""
        deadline = time.monotonic() + timeout
        while True:
            hits = self.hits(token)
            if hits:
                return hits[0]
            if time.monotonic() >= deadline:
                return None
            time.sleep(poll)


def _make_handler(listener: OobListener):
    class _Handler(BaseHTTPRequestHandler):
        def _handle(self, *, write_body: bool) -> None:
            m = _TOKEN_RE.search(self.path)
            body = b""
            if m:
                token = m.group(1)
                listener.record(token, self.path, self.client_address[0])
                # Echo the token back in the response body -- lets a caller
                # confirm SSRF in-band (a single request, no wait_for poll)
                # when the target reflects the fetched resource's body back,
                # not only via the out-of-band hit `record()` above already
                # confirms. Purely additive: `wait_for`/`hits()` never read
                # this body, so this changes nothing for an existing
                # OOB-only caller (e.g. `CommandInjectionOobStrategy`).
                body = token.encode("ascii")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body and write_body:
                self.wfile.write(body)

        def do_GET(self) -> None:      # noqa: N802 - BaseHTTPRequestHandler naming
            self._handle(write_body=True)

        def do_POST(self) -> None:     # noqa: N802
            self._handle(write_body=True)

        def do_HEAD(self) -> None:     # noqa: N802 - HEAD must never carry a body
            self._handle(write_body=False)

        def log_message(self, fmt, *args) -> None:  # silence default stderr access log
            pass

    return _Handler
