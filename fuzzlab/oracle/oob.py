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
`BrowserExecutor` seam. It is a per-run, in-memory callback tracker: no DNS
component, no persistence beyond the process, and no relaying of received data
anywhere.

Reaching a remote target (D73, FR-FUZZ-70): by default the listener binds loopback
only, which a target on another machine cannot reach. Two operator opt-ins make it
reachable: ``public_url`` -- the externally reachable base URL that forwards to this
listener (a tunnel, ``ssh -R``, a port forward), embedded in payloads in place of the
bind address -- and ``public_bind=True``, which lets ``host`` be a non-loopback
address (e.g. ``0.0.0.0`` on a host with a public IP). Without ``public_bind`` a
non-loopback host is refused through the one listener gate (`core.net.require_loopback`,
PA-0081).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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

    def __init__(self, host: str = "127.0.0.1", port: int = 0, *,
                 public_url: str | None = None, public_bind: bool = False):
        from fuzzlab.core.net import require_loopback
        if not public_bind:                            # the one gate (BUG-0080, PA-0081)
            require_loopback(host, "OobListener (pass public_bind=True to expose it)")
        elif not (host or "").strip():
            raise ValueError("OobListener: public_bind needs an explicit host")
        self._host = host
        self._public_url = normalize_public_url(public_url) if public_url else None
        self._requested_port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._hits: dict[str, list[OobHit]] = {}
        self._secret = secrets.token_bytes(16)       # per-listener proof key (BUG-0089)

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
        # one thread per connection (daemon, never joined at close): an idle or slow
        # connection cannot delay a real callback (reviewer A, round 2), and `stop` stays
        # bounded by the handler's socket timeout
        self._server = ThreadingHTTPServer((self._host, self._requested_port), handler)
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

    def proof(self, token: str) -> str:
        """What the callback serves for ``token``: an HMAC of it under this listener's
        secret. It appears **nowhere in the callback URL**, so a response can only
        contain it if the target really fetched the URL. A page that merely reflects
        the URL (e.g. "could not fetch …/cb/<token>") used to confirm SSRF/XXE in-band,
        because the body was the token itself (BUG-0089)."""
        mac = hmac.new(self._secret, token.encode("ascii"), hashlib.sha256)
        return "fzlproof" + mac.hexdigest()[:24]

    @property
    def public_url(self) -> str | None:
        return self._public_url

    def callback_url(self, token: str, scheme: str = "http") -> str:
        """The URL a payload embeds: under ``public_url`` when one is set (what a remote
        target can reach), else this listener's own bind address and port."""
        if not self.running:
            raise RuntimeError("OobListener.start() must run before minting callback URLs")
        if self._public_url:
            return f"{self._public_url}/cb/{token}"
        host = f"[{self._host}]" if ":" in self._host else self._host
        return f"{scheme}://{host}:{self.port}/cb/{token}"

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


def normalize_public_url(url: str) -> str:
    """``scheme://host[:port][/path]`` with no trailing ``/``, query or fragment: the
    base a callback URL is built under. Raises ``ValueError`` otherwise."""
    from urllib.parse import urlsplit
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"an OOB public URL is http(s)://host[:port][/path], not {url!r}")
    if parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError(f"an OOB public URL has no credentials, query or fragment: {url!r}")
    parts.port                                        # raises ValueError on a bad port
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


def _make_handler(listener: OobListener):
    class _Handler(BaseHTTPRequestHandler):
        #: per-connection socket timeout: an idle connection (connected, never sending)
        #: blocked the old one-at-a-time serve loop and `OobListener.stop` forever
        #: (BUG-0128 sweep, PA-0128); it still ends idle handler threads
        timeout = 5

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
                body = listener.proof(token).encode("ascii")
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
