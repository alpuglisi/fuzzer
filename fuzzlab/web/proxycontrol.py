"""In-process proxy controller for the unified serve mode (Phase 0.4).

Live interception holds ``asyncio.Future`` objects (see `proxy/intercept.py`), which
are **not** shareable across processes. So live pause/edit/drop/forward requires the
proxy engine to run **in the web app's own event loop** — not as the separate
`fuzzlab proxy` process. This controller builds the proxy engine (Scope +
MatchReplace + Interceptor + SocketSender + optional HistoryWriter + LocalCA) and
owns its lifecycle; the FastAPI app's lifespan calls :meth:`start`/:meth:`stop`, and
the Phase-2 Proxy-tab routes reach the live interceptor through this controller.

Lab-only: the caller (``fuzzlab web --with-proxy``) requires ``--authorized`` before
wiring one, mirroring the standalone proxy CLI. Building/starting binds a loopback
listener but sends nothing until a proxied client drives in-scope traffic through it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8888
    scope_hosts: tuple[str, ...] = ("127.0.0.1",)
    ca_dir: str | None = None          # set → CONNECT/TLS interception; None → 501
    store_path: str | None = None      # set → record flow history
    identity: str | None = None
    verify_tls: bool = True
    intercept: bool = False            # start with interception held-on?


class ProxyController:
    """Owns an in-process :class:`AsyncProxyServer` + its :class:`Interceptor`."""

    def __init__(self, config: ProxyConfig | None = None) -> None:
        self.config = config or ProxyConfig()
        self.engine = None
        self.server = None
        self.interceptor = None
        self._store = None
        self._history = None
        self._running = False

    def build(self) -> "ProxyController":
        """Construct the engine + server (no sockets bound yet). Imports are lazy."""
        from fuzzlab.proxy.intercept import Interceptor
        from fuzzlab.proxy.matchreplace import MatchReplaceEngine
        from fuzzlab.proxy.scope import Scope
        from fuzzlab.proxy.server import AsyncProxyServer, ProxyEngine
        from fuzzlab.proxy.socketsender import SocketSender

        scope = Scope()
        for host in self.config.scope_hosts:
            scope.include(host)
        self.interceptor = Interceptor(enabled=self.config.intercept)
        matchreplace = MatchReplaceEngine()
        sender = SocketSender(verify_tls=self.config.verify_tls)

        history = None
        if self.config.store_path:
            from fuzzlab.core.store import Store
            from fuzzlab.proxy.history import HistoryWriter
            self._store = Store(self.config.store_path)
            run_id = self._store.start_run("proxy", self.config.host)
            # batch_size=1: each flow is persisted immediately so the panel sees it live.
            self._history = history = HistoryWriter(self._store, run_id, batch_size=1)

        ca = None
        if self.config.ca_dir:
            from fuzzlab.proxy.ca import LocalCA
            ca = LocalCA(self.config.ca_dir)

        self.engine = ProxyEngine(
            scope=scope, sender=sender, matchreplace=matchreplace,
            interceptor=self.interceptor, history=history,
            identity=self.config.identity)
        self.server = AsyncProxyServer(
            self.engine, host=self.config.host, port=self.config.port, ca=ca)
        return self

    async def start(self) -> "ProxyController":
        if self.engine is None:
            self.build()
        await self.server.start()          # binds the listener (same event loop)
        self._running = True
        return self

    async def stop(self) -> None:
        if self.server is not None:
            await self.server.stop()
        if self._history is not None:
            self._history.flush()
        if self._store is not None:
            self._store.close()
        self._running = False

    # --- control surface for the Phase-2 Proxy tab -------------------------
    @property
    def running(self) -> bool:
        return self._running

    def status(self) -> dict[str, Any]:
        return {
            "configured": True,
            "running": self._running,
            "host": self.config.host,
            "port": self.server.port if (self.server and self._running) else self.config.port,
            "intercept": bool(self.interceptor.enabled) if self.interceptor else False,
            "intercept_responses": bool(getattr(self.interceptor, "intercept_responses",
                                                False)) if self.interceptor else False,
            "pending": len(self.interceptor.pending()) if self.interceptor else 0,
            "scope_hosts": list(self.config.scope_hosts),
            "tls": bool(self.config.ca_dir),
        }

    def set_intercept(self, on: bool) -> bool:
        if self.interceptor is None:
            return False
        self.interceptor.set_enabled(on)
        return self.interceptor.enabled

    def set_intercept_responses(self, on: bool) -> bool:
        if self.interceptor is None:
            return False
        self.interceptor.set_intercept_responses(on)
        return self.interceptor.intercept_responses

    def pending_view(self) -> list[dict[str, Any]]:
        """JSON-safe view of held flows: id/direction/host + the raw message text."""
        if self.interceptor is None:
            return []
        out = []
        for flow in self.interceptor.pending():
            msg = flow.message
            out.append({
                "id": flow.id,
                "direction": flow.direction,
                "host": flow.host,
                "method": msg.method.decode("latin-1", "replace") if flow.direction == "request" else "",
                "target": msg.target.decode("latin-1", "replace") if flow.direction == "request" else "",
                "raw": msg.raw.decode("latin-1", "replace"),
            })
        return out

    def forward(self, flow_id: int, raw_text: str | None = None) -> bool:
        """Release a held flow, optionally with an edited raw message (latin-1 bytes)."""
        if self.interceptor is None or self.interceptor.get(flow_id) is None:
            return False
        from fuzzlab.proxy.message import RawMessage
        msg = RawMessage.from_bytes(raw_text.encode("latin-1")) if raw_text else None
        self.interceptor.forward(flow_id, msg)
        return True

    def drop(self, flow_id: int) -> bool:
        if self.interceptor is None or self.interceptor.get(flow_id) is None:
            return False
        self.interceptor.drop(flow_id)
        return True
