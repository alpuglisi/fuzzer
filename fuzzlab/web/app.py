"""Local web control panel and launcher (component #12, decision D11).

This is the no-auto-run entry point: bringing up the environment opens this panel
and *nothing* is sent to the target until the user chooses a mode. It offers:

- **automatic** — run the discovery -> fuzz pipeline and the integration harness
  against the lab, then show results;
- **manual** — leave the lab running and hand the user ready-to-run, pre-wired
  commands for each tool.

Safety (D11): the server binds to loopback only and is served separately from the
vulnerable target. It never proxies to, or fetches from, the target on its own.

Phase 0 ships this minimal panel; the full dashboard (live runs, results tables)
is elaborated later. The automatic-mode pipeline is injected as a callable so the
panel stays honest while the tools move onto the store (T0.8).
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Any, Callable

from fuzzlab.core.config import Config, load_config

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
        {"name": "crawler", "cmd": f"python -m fuzzlab.tools.spider --start {base}"},
        {"name": "auditor", "cmd": "python -m fuzzlab.tools.fetcher"},
        {"name": "fuzzer",
         "cmd": f"python -m fuzzlab.tools.blind_sqli_fuzzer "
                f"--url {base}/product.php --param id --authorized"},
        {"name": "store", "cmd": f"datasette {store}"},
    ]


def _page(cfg: Config, state: LauncherState) -> str:
    base = html.escape(cfg.get("target_base_url", ""))
    authorized = cfg.get("authorized", False)
    scope = ", ".join(html.escape(h) for h in cfg.get("scope_hosts", []))
    cmds = "".join(
        f"<li><b>{html.escape(c['name'])}</b>: <code>{html.escape(c['cmd'])}</code></li>"
        for c in _tool_commands(cfg)
    )
    result = ""
    if state.last_result is not None:
        result = f"<pre class='result'>{html.escape(str(state.last_result))}</pre>"
    warn = "" if authorized else (
        "<p class='warn'>Not authorized: set <code>authorized: true</code> in config "
        "to enable automatic mode. Lab-only.</p>"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>fuzzlab launcher</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font-family: system-ui, sans-serif; max-width: 760px; margin: 2rem auto;
        padding: 0 16px; line-height: 1.5; }}
 h1 {{ font-size: 1.4rem; }}
 .card {{ border: 1px solid #8884; border-radius: 10px; padding: 1rem; margin: 1rem 0; }}
 button {{ font-size: 1rem; padding: .5rem 1rem; border-radius: 8px; cursor: pointer; }}
 code {{ background: #8882; padding: .1rem .3rem; border-radius: 4px; }}
 .warn {{ color: #b00; }}
 .result {{ background: #8882; padding: .5rem; border-radius: 8px; white-space: pre-wrap; }}
 .muted {{ color: #8888; font-size: .9rem; }}
</style></head>
<body>
 <h1>fuzzlab &mdash; launcher</h1>
 <p class="muted">Local control panel. Lab-only. Nothing is sent to the target
   until you choose a mode (no auto-run).</p>
 <div class="card">
   <div>Target: <code>{base}</code></div>
   <div>Scope: <code>{scope}</code></div>
   <div>Mode: <code>{html.escape(state.mode)}</code></div>
 </div>
 {warn}
 <div class="card">
   <h2>Automatic</h2>
   <p>Run crawler &rarr; auditor &rarr; fuzzer and the integration harness against
      the lab, then show results.</p>
   <form method="post" action="/api/run/automatic">
     <button type="submit"{'' if authorized else ' disabled'}>Run automatically</button>
   </form>
 </div>
 <div class="card">
   <h2>Manual</h2>
   <p>Leave the lab running and use the tools by hand. Pre-wired commands:</p>
   <ul>{cmds}</ul>
 </div>
 {result}
</body></html>"""


def create_app(cfg: Config | None = None, pipeline: PipelineRunner | None = None):
    """Build the FastAPI app. Import is lazy so ``core`` has no web dependency."""
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse

    cfg = cfg or load_config()
    state = LauncherState()
    app = FastAPI(title="fuzzlab launcher", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _page(cfg, state)

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        return {
            "mode": state.mode,                     # 'idle' until a choice is made
            "target": cfg.get("target_base_url"),
            "scope_hosts": cfg.get("scope_hosts"),
            "authorized": cfg.get("authorized"),
            "auto_run": False,                       # invariant: never auto-run
        }

    @app.get("/api/manual")
    def manual() -> dict[str, Any]:
        state.mode = "manual"
        state.history.append("manual selected")
        return {"mode": "manual", "commands": _tool_commands(cfg)}

    @app.post("/api/run/automatic")
    def run_automatic():
        if not cfg.get("authorized"):
            return JSONResponse(
                {"error": "not authorized; set authorized:true (lab-only)"},
                status_code=403,
            )
        state.mode = "automatic"
        state.history.append("automatic selected")
        if pipeline is None:
            state.last_result = {"status": "pipeline not wired yet (T0.8)"}
        else:
            state.last_result = pipeline(cfg)
        return {"mode": "automatic", "result": state.last_result}

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
