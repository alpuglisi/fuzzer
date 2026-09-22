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

import json
import threading
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

    # --- scope (which hosts are intercepted vs transparently bypassed) --------
    def scope_view(self) -> list[dict[str, Any]]:
        if self.engine is None:
            return []
        return [{"index": i, "host": r.host, "path_regex": r.path_regex,
                 "exclude": r.exclude} for i, r in enumerate(self.engine.scope.rules)]

    def scope_add(self, host: str, path_regex: str | None = None,
                  exclude: bool = False) -> bool:
        if self.engine is None:
            return False
        if exclude:
            self.engine.scope.exclude(host, path_regex or None)
        else:
            self.engine.scope.include(host, path_regex or None)
        return True

    def scope_remove(self, index: int) -> bool:
        if self.engine is None or not (0 <= index < len(self.engine.scope.rules)):
            return False
        del self.engine.scope.rules[index]
        return True

    # --- match-replace (ordered byte rewrites) -------------------------------
    @staticmethod
    def _text(v) -> str:
        return v.decode("latin-1", "replace") if isinstance(v, (bytes, bytearray)) else str(v)

    def matchreplace_view(self) -> list[dict[str, Any]]:
        if self.engine is None or self.engine.matchreplace is None:
            return []
        out = []
        for i, r in enumerate(self.engine.matchreplace.rules):
            out.append({"index": i, "target": r.target, "match": self._text(r.match),
                        "replace": self._text(r.replace), "header_name": r.header_name,
                        "is_regex": r.is_regex, "enabled": r.enabled})
        return out

    def matchreplace_add(self, target: str, match: str, replace: str = "",
                         header_name: str | None = None, is_regex: bool = False) -> bool:
        """Append a rule. Raises ValueError on a bad target / missing header_name."""
        if self.engine is None or self.engine.matchreplace is None:
            return False
        from fuzzlab.proxy.matchreplace import MatchReplaceRule
        self.engine.matchreplace.add(MatchReplaceRule(
            target=target, match=match, replace=replace,
            header_name=header_name or None, is_regex=bool(is_regex)))
        return True

    def matchreplace_remove(self, index: int) -> bool:
        mr = self.engine.matchreplace if self.engine else None
        if mr is None or not (0 <= index < len(mr.rules)):
            return False
        del mr.rules[index]
        return True

    def matchreplace_toggle(self, index: int, enabled: bool) -> bool:
        mr = self.engine.matchreplace if self.engine else None
        if mr is None or not (0 <= index < len(mr.rules)):
            return False
        mr.rules[index].enabled = bool(enabled)
        return True


class RepeaterController:
    """Replay tabs for the Repeater sub-tab (Phase 2.3).

    Independent of the in-process proxy: a saved raw request can be replayed against a
    target from the panel whether or not interception is running. Tabs persist in
    ``repeater_tab``; listing reads every tab (cross-session), while creating/sending
    open a persistent store + one ``repeater`` run on first write (creating the store
    file only on that explicit user action). Sending forwards to a real upstream, so the
    caller gates it on ``authorized``. A ``sender`` may be injected for tests.

    ``sqlite3`` connections are thread-affine (``check_same_thread=True``): a connection
    may only be used from the OS thread that created it (BUG-0018). This controller is a
    single long-lived object shared across requests, and requests are not guaranteed to
    land on the same thread every time (e.g. an ASGI test client that spins up a fresh
    event-loop thread per call, or any future multi-threaded serving setup) — so the
    persistent store/``Repeater`` are kept **per calling thread** (``threading.local``)
    rather than as one shared instance attribute. All threads still share a single
    ``repeater`` run row (``self._run_id``, created once under ``self._run_lock``) so
    tabs created from any thread appear together.
    """

    def __init__(self, cfg, sender=None) -> None:
        self.cfg = cfg
        self._sender = sender
        self._run_id = None
        self._run_lock = threading.Lock()
        self._local = threading.local()

    def _path(self) -> str:
        return self.cfg.get("store_path", "fuzzlab.db")

    def _thread_store(self):
        """This calling thread's persistent store, if one was already created (else None)."""
        return getattr(self._local, "store", None)

    def _writer(self):
        """Persistent store + Repeater for the *calling thread*, created lazily on first
        write. See the class docstring for why this is per-thread rather than shared.
        """
        rep = getattr(self._local, "rep", None)
        if rep is None:
            from fuzzlab.core.store import Store
            from fuzzlab.proxy.history import HistoryWriter
            from fuzzlab.proxy.repeater import Repeater
            sender = self._sender
            if sender is None:
                from fuzzlab.proxy.socketsender import SocketSender
                sender = SocketSender(verify_tls=False)
            store = Store(self._path())
            with self._run_lock:
                if self._run_id is None:
                    self._run_id = store.start_run(
                        "repeater", self.cfg.get("target_base_url", ""))
            run_id = self._run_id
            rep = Repeater(store, run_id, sender,
                           history=HistoryWriter(store, run_id, batch_size=1))
            self._local.store = store
            self._local.rep = rep
        return rep

    @staticmethod
    def _tab_dict(row) -> dict[str, Any]:
        return {
            "id": row["id"], "name": row["name"], "host": row["host"],
            "port": row["port"], "use_tls": bool(row["use_tls"]),
            "raw": bytes(row["raw_request"]).decode("latin-1", "replace"),
        }

    def list_tabs(self) -> list[dict[str, Any]]:
        """All saved tabs, newest first. Read-only; never creates the store."""
        from fuzzlab.web import results
        thread_store = self._thread_store()
        if thread_store is None and not results.store_exists(self._path()):
            return []
        from fuzzlab.core.store import Store
        own = thread_store or Store(self._path())
        try:
            rows = own.conn.execute(
                "SELECT id, name, host, port, use_tls, raw_request FROM repeater_tab "
                "ORDER BY id DESC").fetchall()
            return [self._tab_dict(r) for r in rows]
        finally:
            if own is not thread_store:
                own.close()

    def create_tab(self, name: str, host: str, port: int, raw: str,
                   use_tls: bool = False) -> dict[str, Any]:
        tab = self._writer().create_tab(name or "tab", host, int(port),
                                        raw.encode("latin-1"), use_tls=bool(use_tls))
        return {"id": tab.id, "name": tab.name, "host": tab.host, "port": tab.port,
                "use_tls": tab.use_tls, "raw": tab.raw_request.decode("latin-1", "replace")}

    def create_from_flow(self, flow_id: int) -> dict[str, Any] | None:
        """Seed a tab from a recorded flow's request (redacted bytes; edit to re-add auth)."""
        from fuzzlab.web import results
        thread_store = self._thread_store()
        if thread_store is None and not results.store_exists(self._path()):
            return None
        from fuzzlab.core.store import Store
        own = thread_store or Store(self._path())
        try:
            row = own.conn.execute(
                "SELECT url, host, req_raw_sha FROM flow WHERE id=?", (flow_id,)).fetchone()
            if row is None:
                return None
            raw = own.get_body(row["req_raw_sha"]) if row["req_raw_sha"] else b""
        finally:
            if own is not thread_store:
                own.close()
        host, _, port_s = (row["host"] or "").partition(":")
        use_tls = str(row["url"] or "").startswith("https")
        port = int(port_s) if port_s.isdigit() else (443 if use_tls else 80)
        name = f"flow #{flow_id}"
        return self.create_tab(name, host or "127.0.0.1", port,
                               raw.decode("latin-1", "replace"), use_tls=use_tls)

    def create_from_finding(self, finding_id: int) -> dict[str, Any] | None:
        """Seed a tab from a finding's location + oracle-recorded payload (the R2
        "send to Repeater" pivot, docs/UI_LAYOUT_REDESIGN.md #6/#9). Unlike
        :meth:`create_from_flow`, no raw bytes are stored for a finding — the request
        is reconstructed from ``url``/``method``/``param`` and ``evidence['payload']``
        via :func:`results.build_finding_raw_request`. ``None`` if the finding (or the
        store) does not exist."""
        from fuzzlab.web import results
        thread_store = self._thread_store()
        if thread_store is None and not results.store_exists(self._path()):
            return None
        from fuzzlab.core.store import Store
        own = thread_store or Store(self._path())
        try:
            row = own.conn.execute(
                "SELECT f.url, f.method, f.param, f.evidence, t.base_url "
                "FROM finding f LEFT JOIN target t ON t.run_id = f.run_id "
                "WHERE f.id=?", (finding_id,)).fetchone()
            if row is None:
                return None
            try:
                evidence = json.loads(row["evidence"]) if row["evidence"] else {}
            except (ValueError, TypeError):
                evidence = {}
        finally:
            if own is not thread_store:
                own.close()
        base_url = row["base_url"] or self.cfg.get("target_base_url", "")
        raw, host, port, use_tls = results.build_finding_raw_request(
            row["url"], row["method"], row["param"], evidence.get("payload", ""), base_url)
        return self.create_tab(f"finding #{finding_id}", host, port, raw, use_tls=use_tls)

    def send(self, tab_id: int, raw: str | None = None) -> dict[str, Any] | None:
        """Replay a tab (optionally edited); returns the raw response as text."""
        rep = self._writer()
        if rep.get_tab(tab_id) is None:
            return None
        resp = rep.send(tab_id, raw.encode("latin-1") if raw is not None else None)
        return {"response": resp.decode("latin-1", "replace")}
