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
from dataclasses import dataclass, field
from typing import Any, Callable

# FastAPI is imported at module scope (not lazily) so the route handlers' `Request`
# annotations resolve under `from __future__ import annotations`. Importing this
# module implies the web extra; `core` never imports it, so core stays web-free.
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from fuzzlab.core.config import Config, load_config
from fuzzlab.web import commandspec, results
from fuzzlab.web.runner import Runner, build_argv, display_command
from fuzzlab.web.sse import sse_response

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


# --- template context builders (rendering lives in templates/, via jinja2) ----

def _activities() -> list[dict]:
    """Every launchable activity's spec, for the Launcher preview. Read-only."""
    try:
        from fuzzlab.web.commandspec import all_specs
        return [s.to_dict() for s in all_specs()]
    except Exception:  # noqa: BLE001 - the panel must render even if a spec fails
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
        "runs": runs,
        "last_result": None if state.last_result is None else str(state.last_result),
    }


def create_app(cfg: Config | None = None, pipeline: PipelineRunner | None = None):
    """Build the FastAPI app (loopback-only, read-only over the store)."""
    cfg = cfg or load_config()
    state = LauncherState()
    runner = Runner()
    app = FastAPI(title="fuzzlab control panel", docs_url=None, redoc_url=None)
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

    return app


def serve(cfg: Config | None = None, pipeline: PipelineRunner | None = None) -> None:
    """Serve the panel on loopback only (never exposed)."""
    import ipaddress

    import uvicorn

    cfg = cfg or load_config()
    host = cfg.get("web_host", "127.0.0.1")
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError(f"refusing to bind web panel to non-loopback host {host!r}")
    uvicorn.run(create_app(cfg, pipeline), host=host, port=int(cfg.get("web_port", 8787)))
