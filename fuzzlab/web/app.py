"""Local web control panel and launcher (component #12, decision D11).

The no-auto-run entry point: bringing up the environment opens this panel and
*nothing* is sent to the target until the user chooses a mode. It offers:

- **automatic** — run the discovery -> confirm pipeline against the lab, then review
  results;
- **manual** — leave the lab running and hand the user ready-to-run, pre-wired
  commands (with a category picker for D14 manual selection);
- **review** — browse past runs from the store: oracle findings, negatives, the
  target fingerprint, request metrics, and the score.

Safety (D11): the server binds to loopback only and is served separately from the
vulnerable target. It never proxies to, or fetches from, the target on its own; it
only *reads* results the tools already wrote to the store.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, TYPE_CHECKING

# FastAPI is imported at module scope (not lazily) so the route handlers' `Request`
# annotations resolve under `from __future__ import annotations`. Importing this
# module implies the web extra; `core` never imports it, so core stays web-free.
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from fuzzlab.core.config import Config, load_config
from fuzzlab.web import commandspec, results
from fuzzlab.web.proxycontrol import RepeaterController
from fuzzlab.web.runner import Runner, build_argv, display_command
from fuzzlab.web.sse import sse_response

if TYPE_CHECKING:
    from fuzzlab.web.proxycontrol import ProxyController

_HERE = os.path.dirname(os.path.abspath(__file__))
_TEMPLATES_DIR = os.path.join(_HERE, "templates")
_STATIC_DIR = os.path.join(_HERE, "static")

# A pipeline runner takes the config and returns a summary dict. Injected so the
# panel is testable and does not itself send traffic.
PipelineRunner = Callable[[Config], dict[str, Any]]


@dataclass
class LauncherState:
    """In-memory launcher state. 'idle' until the user chooses a mode."""
    mode: str = "idle"                 # idle | automatic | manual
    last_result: dict[str, Any] | None = None
    history: list[str] = field(default_factory=list)


def _tool_commands(cfg: Config) -> list[dict[str, str]]:
    base = cfg.get("target_base_url", "http://localhost")
    store = cfg.get("store_path", "fuzzlab.db")
    return [
        {"name": "crawler", "cmd": f"fuzzlab crawl --start {base} --store {store}"},
        {"name": "auditor",
         "cmd": f"fuzzlab audit --store {store} --base-url {base}/"},
        {"name": "fuzzer",
         "cmd": f"fuzzlab fuzz --url {base}/product.php --param id "
                f"--store {store} --authorized"},
        {"name": "auto",
         "cmd": f"fuzzlab auto --base-url {base} --store {store} "
                f"--ground-truth lab/ground-truth --authorized"},
    ]


def _known_categories() -> list[str]:
    try:
        from fuzzlab.audit import known_categories
        return known_categories()
    except Exception:  # noqa: BLE001 - the panel must render even if rules fail to load
        return []


# --- store-backed results (read-only; never creates the store file) -----------

def _read_runs(cfg: Config) -> list[dict]:
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return []
    from fuzzlab.core.store import Store
    with Store(path) as store:
        return results.list_runs(store)


def _read_detail(cfg: Config, run_id: int) -> dict | None:
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return None
    from fuzzlab.core.store import Store
    with Store(path) as store:
        return results.run_detail(store, run_id)


def _read_flows(cfg: Config, query: str | None = None) -> list[dict]:
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return []
    from fuzzlab.core.store import Store
    from fuzzlab.web import proxyview
    with Store(path) as store:
        return proxyview.list_flows(store, query=query)


def _read_flow(cfg: Config, flow_id: int) -> dict | None:
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return None
    from fuzzlab.core.store import Store
    from fuzzlab.web import proxyview
    with Store(path) as store:
        return proxyview.flow_detail(store, flow_id)


# --- template context builders (rendering lives in templates/, via jinja2) ----

def _activities() -> list[dict]:
    """Every launchable activity's spec, for the Launcher forms."""
    try:
        from fuzzlab.web.commandspec import all_specs
        return [s.to_dict() for s in all_specs()]
    except Exception:  # noqa: BLE001 - the panel must render even if a spec fails
        return []


def _active_plugins() -> list[dict]:
    """The entry-point plugins that a run with ``--plugins`` would attach."""
    try:
        from fuzzlab.plugins.manager import PluginManager
        return [{"name": p.name, "version": p.version, "priority": p.priority}
                for p in PluginManager.from_entry_points().active()]
    except Exception:  # noqa: BLE001 - discovery must never break the panel
        return []


def _index_context(cfg: Config, state: LauncherState, runs: list[dict]) -> dict[str, Any]:
    return {
        "target": cfg.get("target_base_url", ""),
        "scope": ", ".join(cfg.get("scope_hosts", [])),
        "mode": state.mode,
        "authorized": bool(cfg.get("authorized", False)),
        "categories": _known_categories(),
        "commands": _tool_commands(cfg),
        "activities": _activities(),
        "plugins": _active_plugins(),
        "runs": runs,
        "last_result": None if state.last_result is None else str(state.last_result),
    }


def create_app(cfg: Config | None = None, pipeline: PipelineRunner | None = None,
               proxy: "ProxyController | None" = None):
    """Build the FastAPI app (loopback-only, read-only over the store).

    ``proxy`` (optional) is an in-process :class:`ProxyController`; when given, the app
    starts it on lifespan startup and stops it on shutdown, so live interception shares
    this event loop (Phase 0.4). ``None`` (the default) leaves the proxy tab dormant.
    """
    cfg = cfg or load_config()
    state = LauncherState()
    runner = Runner()
    repeater_ctl = RepeaterController(cfg)

    @asynccontextmanager
    async def _lifespan(_app):
        if proxy is not None:
            await proxy.start()
        try:
            yield
        finally:
            if proxy is not None:
                await proxy.stop()

    app = FastAPI(title="fuzzlab control panel", docs_url=None, redoc_url=None,
                  lifespan=_lifespan)
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
    templates = Jinja2Templates(directory=_TEMPLATES_DIR)

    def _resolve(name: str):
        """Look up a launchable activity's spec, or None if unknown."""
        try:
            return commandspec.spec(name)
        except KeyError:
            return None

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(
            request, "index.html", _index_context(cfg, state, _read_runs(cfg)))

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        return {
            "mode": state.mode,                     # 'idle' until a choice is made
            "target": cfg.get("target_base_url"),
            "scope_hosts": cfg.get("scope_hosts"),
            "authorized": cfg.get("authorized"),
            "store_path": cfg.get("store_path"),
            "auto_run": False,                       # invariant: never auto-run
        }

    @app.get("/api/manual")
    def manual() -> dict[str, Any]:
        state.mode = "manual"
        state.history.append("manual selected")
        return {"mode": "manual", "commands": _tool_commands(cfg),
                "categories": _known_categories()}

    @app.post("/api/run/automatic")
    def run_automatic():
        if not cfg.get("authorized"):
            return JSONResponse(
                {"error": "not authorized; set authorized:true (lab-only)"},
                status_code=403)
        state.mode = "automatic"
        state.history.append("automatic selected")
        if pipeline is None:
            state.last_result = {"status": "pipeline not wired (use the CLI: fuzzlab auto)"}
        else:
            state.last_result = pipeline(cfg)
        return {"mode": "automatic", "result": state.last_result}

    @app.get("/api/runs")
    def runs() -> dict[str, Any]:
        return {"runs": _read_runs(cfg)}

    @app.get("/api/runs/{run_id}")
    def run(run_id: int):
        detail = _read_detail(cfg, run_id)
        if detail is None:
            return JSONResponse({"error": f"run {run_id} not found"}, status_code=404)
        return detail

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_html(request: Request, run_id: int):
        detail = _read_detail(cfg, run_id)
        if detail is None:
            return templates.TemplateResponse(
                request, "not_found.html", {"run_id": run_id}, status_code=404)
        return templates.TemplateResponse(request, "run.html", {"detail": detail})

    # --- launcher: dry-run preview, gated execution, live output (Phase 0.3) ---

    @app.post("/api/launch/dry-run")
    async def launch_dry_run(request: Request):
        body = await request.json()
        spec = _resolve(body.get("command"))
        if spec is None:
            return JSONResponse({"error": f"unknown command {body.get('command')!r}"},
                                status_code=400)
        values = body.get("values") or {}
        # A dry run plans and reports the exact command and never sends traffic (FR-UI-5).
        return {
            "command": spec.name,
            "argv": build_argv(spec, values),
            "display": display_command(spec, values),
            "sends_traffic": spec.sends_traffic,
            "needs_authorized": spec.needs_authorized,
            "would_execute": not (spec.sends_traffic and not cfg.get("authorized")),
        }

    @app.post("/api/launch")
    async def launch(request: Request):
        body = await request.json()
        spec = _resolve(body.get("command"))
        if spec is None:
            return JSONResponse({"error": f"unknown command {body.get('command')!r}"},
                                status_code=400)
        # No-auto-run gate: a traffic-sending activity runs only when authorized.
        if spec.sends_traffic and not cfg.get("authorized"):
            return JSONResponse(
                {"error": "not authorized; set authorized:true (lab-only)"},
                status_code=403)
        argv = build_argv(spec, body.get("values") or {})
        token = await runner.launch(argv)
        state.history.append(f"launched {spec.name}")
        return {"token": token, "argv": argv}

    @app.get("/api/launch/{token}/stream")
    async def launch_stream(token: str):
        return sse_response(runner.stream(token))

    @app.post("/api/launch/{token}/stop")
    async def launch_stop(token: str):
        return {"stopped": runner.stop(token)}

    @app.get("/api/plugins")
    def plugins():
        return {"plugins": _active_plugins()}

    # --- in-process proxy status/control (Phase 0.4; full workbench in Phase 2) ---

    @app.get("/api/proxy/status")
    def proxy_status():
        if proxy is None:
            return {"configured": False, "running": False}
        return proxy.status()

    @app.get("/api/proxy/flows")
    def proxy_flows(q: str | None = None):
        return {"flows": _read_flows(cfg, query=q or None)}

    @app.get("/api/proxy/flows/{flow_id}")
    def proxy_flow(flow_id: int):
        detail = _read_flow(cfg, flow_id)
        if detail is None:
            return JSONResponse({"error": f"flow {flow_id} not found"}, status_code=404)
        return detail

    def _need_proxy():
        return JSONResponse(
            {"error": "no in-process proxy (start with `fuzzlab web --with-proxy`)"},
            status_code=409)

    @app.post("/api/proxy/intercept")
    async def proxy_intercept(request: Request):
        if proxy is None:
            return _need_proxy()
        body = await request.json()
        if "on" in body:
            proxy.set_intercept(bool(body["on"]))
        if "responses" in body:
            proxy.set_intercept_responses(bool(body["responses"]))
        return proxy.status()

    @app.get("/api/proxy/intercept/pending")
    def proxy_pending():
        if proxy is None:
            return _need_proxy()
        return {"pending": proxy.pending_view()}

    @app.post("/api/proxy/intercept/{flow_id}/forward")
    async def proxy_forward(flow_id: int, request: Request):
        if proxy is None:
            return _need_proxy()
        raw = None
        try:                                    # body optional: {"raw": "..."} to edit
            raw = (await request.json()).get("raw")
        except Exception:  # noqa: BLE001 - empty/non-JSON body → forward unedited
            pass
        return {"forwarded": proxy.forward(flow_id, raw)}

    @app.post("/api/proxy/intercept/{flow_id}/drop")
    def proxy_drop(flow_id: int):
        if proxy is None:
            return _need_proxy()
        return {"dropped": proxy.drop(flow_id)}

    # --- repeater (replay tabs; independent of the in-process proxy) -----------

    # These handlers are async so they run on the event-loop thread; the controller
    # holds a persistent SQLite connection, which must be touched from one thread only
    # (sync handlers would run in Starlette's threadpool).
    @app.get("/api/proxy/repeater/tabs")
    async def repeater_tabs():
        return {"tabs": repeater_ctl.list_tabs()}

    @app.post("/api/proxy/repeater/tabs")
    async def repeater_create(request: Request):
        b = await request.json()
        return repeater_ctl.create_tab(b.get("name", ""), b.get("host", "127.0.0.1"),
                                       b.get("port", 80), b.get("raw", ""),
                                       bool(b.get("use_tls")))

    @app.post("/api/proxy/repeater/from-flow/{flow_id}")
    async def repeater_from_flow(flow_id: int):
        tab = repeater_ctl.create_from_flow(flow_id)
        if tab is None:
            return JSONResponse({"error": f"flow {flow_id} not found"}, status_code=404)
        return tab

    @app.post("/api/proxy/repeater/tabs/{tab_id}/send")
    async def repeater_send(tab_id: int, request: Request):
        if not cfg.get("authorized"):     # replay sends traffic to the target
            return JSONResponse(
                {"error": "not authorized; set authorized:true (lab-only)"},
                status_code=403)
        raw = None
        try:
            raw = (await request.json()).get("raw")
        except Exception:  # noqa: BLE001 - empty/non-JSON body → send the saved request
            pass
        out = repeater_ctl.send(tab_id, raw)
        if out is None:
            return JSONResponse({"error": f"tab {tab_id} not found"}, status_code=404)
        return out

    return app


def serve(cfg: Config | None = None, pipeline: PipelineRunner | None = None,
          proxy: "ProxyController | None" = None) -> None:
    """Serve the panel on loopback only (never exposed).

    When ``proxy`` is given it runs in this same uvicorn event loop (so live
    interception's futures work); its own loopback listener is separate from the panel's.
    """
    import ipaddress

    import uvicorn

    cfg = cfg or load_config()
    host = cfg.get("web_host", "127.0.0.1")
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError(f"refusing to bind web panel to non-loopback host {host!r}")
    if proxy is not None and not ipaddress.ip_address(proxy.config.host).is_loopback:
        raise ValueError(
            f"refusing to bind proxy to non-loopback host {proxy.config.host!r}")
    uvicorn.run(create_app(cfg, pipeline, proxy), host=host,
                port=int(cfg.get("web_port", 8787)))


def web_main(argv: list[str] | None = None) -> int:
    """CLI for ``fuzzlab web`` — optionally start the in-process proxy (Phase 0.4).

    The panel itself is read-only and needs no authorization; ``--with-proxy`` runs the
    intercepting proxy in this process (for the live Proxy tab) and, because that forwards
    traffic to upstreams, requires ``--authorized`` (lab-only), mirroring `fuzzlab proxy`.
    """
    import argparse
    from urllib.parse import urlparse

    p = argparse.ArgumentParser(prog="fuzzlab web")
    p.add_argument("--with-proxy", action="store_true",
                   help="also run the intercepting proxy in-process (live Proxy tab); "
                        "requires --authorized")
    p.add_argument("--proxy-host", default="127.0.0.1", help="proxy listen host (loopback)")
    p.add_argument("--proxy-port", type=int, default=8888, help="proxy listen port")
    p.add_argument("--proxy-scope", action="append",
                   help="host to intercept (repeatable; default: the target host)")
    p.add_argument("--proxy-ca-dir", default=None,
                   help="local CA dir to enable CONNECT/TLS interception")
    p.add_argument("--proxy-no-verify-tls", action="store_true",
                   help="do not verify upstream TLS certs (self-signed lab origins)")
    p.add_argument("--intercept", action="store_true",
                   help="start with interception ON (hold flows for edit/drop/forward)")
    p.add_argument("--authorized", action="store_true",
                   help="required to run the in-process proxy (it forwards traffic)")
    args = p.parse_args(argv)

    cfg = load_config()
    proxy = None
    if args.with_proxy:
        if not args.authorized:
            p.error("refusing to run the in-process proxy without --authorized (lab-only)")
        from fuzzlab.web.proxycontrol import ProxyConfig, ProxyController
        default_host = urlparse(cfg.get("target_base_url", "")).hostname or "127.0.0.1"
        scope = tuple(args.proxy_scope or [default_host])
        proxy = ProxyController(ProxyConfig(
            host=args.proxy_host, port=args.proxy_port, scope_hosts=scope,
            ca_dir=args.proxy_ca_dir, store_path=cfg.get("store_path"),
            verify_tls=not args.proxy_no_verify_tls, intercept=args.intercept))
    serve(cfg, proxy=proxy)
    return 0
