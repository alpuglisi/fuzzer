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

import html
from dataclasses import dataclass, field
from typing import Any, Callable

from fuzzlab.core.config import Config, load_config
from fuzzlab.web import results

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


# --- HTML rendering -----------------------------------------------------------

_STYLE = """
 :root { color-scheme: light dark; }
 body { font-family: system-ui, sans-serif; max-width: 860px; margin: 2rem auto;
        padding: 0 16px; line-height: 1.5; }
 h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; }
 .card { border: 1px solid #8884; border-radius: 10px; padding: 1rem; margin: 1rem 0; }
 button { font-size: 1rem; padding: .5rem 1rem; border-radius: 8px; cursor: pointer; }
 code { background: #8882; padding: .1rem .3rem; border-radius: 4px; }
 .warn { color: #b00; } .ok { color: #0a0; } .bad { color: #b00; }
 .muted { color: #8888; font-size: .9rem; }
 .result { background: #8882; padding: .5rem; border-radius: 8px; white-space: pre-wrap; }
 table { border-collapse: collapse; width: 100%; }
 th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #8883;
          font-size: .95rem; vertical-align: top; }
 a { color: inherit; }
"""


def _doc(title: str, body: str) -> str:
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<title>{html.escape(title)}</title>"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<style>{_STYLE}</style></head><body>{body}</body></html>")


def _runs_table(runs: list[dict]) -> str:
    if not runs:
        return ("<p class='muted'>No runs recorded yet. Run a tool with "
                "<code>--store</code>, or use automatic mode, then refresh.</p>")
    rows = "".join(
        f"<tr><td><a href='/runs/{r['id']}'>#{r['id']}</a></td>"
        f"<td>{html.escape(str(r['tool']))}</td>"
        f"<td><code>{html.escape(str(r['target'] or ''))}</code></td>"
        f"<td>{html.escape(str(r['started_at'] or ''))}</td>"
        f"<td>{r['findings']}</td></tr>"
        for r in runs)
    return ("<table><thead><tr><th>run</th><th>tool</th><th>target</th>"
            f"<th>started</th><th>findings</th></tr></thead><tbody>{rows}</tbody></table>")


def _page(cfg: Config, state: LauncherState, runs: list[dict]) -> str:
    base = html.escape(cfg.get("target_base_url", ""))
    authorized = cfg.get("authorized", False)
    scope = ", ".join(html.escape(h) for h in cfg.get("scope_hosts", []))
    cmds = "".join(
        f"<li><b>{html.escape(c['name'])}</b>: <code>{html.escape(c['cmd'])}</code></li>"
        for c in _tool_commands(cfg))
    cats = ", ".join(html.escape(c) for c in _known_categories())
    warn = "" if authorized else (
        "<p class='warn'>Not authorized: set <code>authorized: true</code> in config "
        "to enable automatic mode. Lab-only.</p>")
    result = ""
    if state.last_result is not None:
        result = f"<pre class='result'>{html.escape(str(state.last_result))}</pre>"
    body = f"""
 <h1>fuzzlab &mdash; control panel</h1>
 <p class="muted">Local, lab-only. Nothing is sent to the target until you choose a
   mode (no auto-run). This panel only reads results the tools wrote.</p>
 <div class="card">
   <div>Target: <code>{base}</code></div>
   <div>Scope: <code>{scope}</code></div>
   <div>Mode: <code>{html.escape(state.mode)}</code></div>
 </div>
 {warn}
 <div class="card">
   <h2>Automatic</h2>
   <p>Run the discovery &rarr; oracle-confirm pipeline against the lab, then review
      results below.</p>
   <form method="post" action="/api/run/automatic">
     <button type="submit"{'' if authorized else ' disabled'}>Run automatically</button>
   </form>
 </div>
 <div class="card">
   <h2>Manual</h2>
   <p>Leave the lab running and use the tools by hand. Selectable categories (D14):
      <code>{cats}</code> &mdash; add <code>--categories &lt;list&gt;</code> to scope.</p>
   <ul>{cmds}</ul>
 </div>
 <div class="card">
   <h2>Review runs</h2>
   {_runs_table(runs)}
 </div>
 {result}"""
    return _doc("fuzzlab control panel", body)


def _finding_rows(findings: list[dict]) -> str:
    if not findings:
        return "<p class='muted'>No findings for this run.</p>"
    rows = "".join(
        f"<tr><td>{html.escape(f['vuln_class'] or '')}</td>"
        f"<td><code>{html.escape(f['url'] or '')}</code></td>"
        f"<td>{html.escape(f['method'] or '')}</td>"
        f"<td>{html.escape(f['param'] or '')}</td>"
        f"<td>{html.escape(f['confidence'] or '')}</td></tr>"
        for f in findings)
    return ("<table><thead><tr><th>class</th><th>url</th><th>method</th>"
            f"<th>param</th><th>mechanism</th></tr></thead><tbody>{rows}</tbody></table>")


def _run_page(detail: dict) -> str:
    c = detail["counts"]
    fp = detail["target_fingerprint"] or {}
    score = detail["score"]
    score_html = "<p class='muted'>Unscored (no ground truth).</p>"
    if score:
        cls = "ok" if score.get("fp", 0) == 0 else "bad"
        score_html = (f"<p class='{cls}'>Score: TP={int(score.get('tp',0))} "
                      f"FP={int(score.get('fp',0))} FN={int(score.get('fn',0))} "
                      f"TN={int(score.get('tn',0))} "
                      f"(precision={score.get('precision','?')}, "
                      f"recall={score.get('recall','?')})</p>")
    metrics = "".join(
        f"<li><code>{html.escape(str(k))}</code>: {html.escape(str(v))}</li>"
        for k, v in sorted(detail["metrics"].items()))
    body = f"""
 <p><a href="/">&larr; all runs</a></p>
 <h1>Run #{detail['id']} &mdash; {html.escape(str(detail['tool']))}</h1>
 <p class="muted">Target <code>{html.escape(str(detail['target'] or ''))}</code>,
   started {html.escape(str(detail['started_at'] or ''))}.</p>
 <div class="card">{score_html}
   <div>Fingerprint: DBMS <code>{html.escape(str(fp.get('dbms') or '?'))}</code>,
     framework <code>{html.escape(str(fp.get('framework') or '?'))}</code>,
     WAF <code>{html.escape(str(fp.get('waf') or '?'))}</code></div>
   <div class="muted">candidates {c['candidates']} &middot; negatives {c['negatives']}
     &middot; evaluations {c['evaluations']} &middot; attempts {c['attempts']}
     &middot; pages {c['pages']}</div>
 </div>
 <div class="card"><h2>Findings ({len(detail['findings'])})</h2>
   {_finding_rows(detail['findings'])}</div>
 {_scores_card(detail)}
 <div class="card"><h2>Metrics</h2><ul>{metrics or '<li class=muted>none</li>'}</ul></div>"""
    return _doc(f"fuzzlab run #{detail['id']}", body)


def _scores_card(detail: dict) -> str:
    scored = detail.get("scored") or []
    model = detail.get("model")
    if not model and not scored:
        return ""
    name = f"{model['name']} v{model['version']}" if model else "none"
    if not scored:
        return (f"<div class='card'><h2>Model scores (advisory)</h2>"
                f"<p class='muted'>Model: <code>{html.escape(name)}</code>. "
                f"No scored candidates for this run.</p></div>")
    rows = "".join(
        f"<tr><td><code>{html.escape(s['url'] or '')}</code></td>"
        f"<td>{html.escape(s['param'] or '')}</td>"
        f"<td>{html.escape(s['category'] or '')}</td>"
        f"<td>{s['score']}</td><td>{html.escape(s['decision'])}</td></tr>"
        for s in scored)
    return (f"<div class='card'><h2>Model scores (advisory)</h2>"
            f"<p class='muted'>Model: <code>{html.escape(name)}</code>. Scores rank "
            f"candidates and the conformal gate triages them (flag / abstain / drop); "
            f"they never confirm — the oracle owns findings.</p>"
            f"<table><thead><tr><th>url</th><th>param</th><th>category</th>"
            f"<th>score</th><th>decision</th></tr></thead><tbody>{rows}</tbody></table></div>")


def create_app(cfg: Config | None = None, pipeline: PipelineRunner | None = None):
    """Build the FastAPI app. Import is lazy so ``core`` has no web dependency."""
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse

    cfg = cfg or load_config()
    state = LauncherState()
    app = FastAPI(title="fuzzlab control panel", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _page(cfg, state, _read_runs(cfg))

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
    def run_html(run_id: int):
        detail = _read_detail(cfg, run_id)
        if detail is None:
            return HTMLResponse(_doc("not found",
                                     f"<p>Run {html.escape(str(run_id))} not found. "
                                     f"<a href='/'>Back</a></p>"), status_code=404)
        return _run_page(detail)

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
