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
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from fuzzlab.core.config import Config, load_config
from fuzzlab.web import commandspec, mlview, results
from fuzzlab.web.proxycontrol import RepeaterController
from fuzzlab.web.runner import Runner, build_argv, display_command
from fuzzlab.web.sse import sse_response

if TYPE_CHECKING:
    from fuzzlab.web.proxycontrol import ProxyController

_HERE = os.path.dirname(os.path.abspath(__file__))
_TEMPLATES_DIR = os.path.join(_HERE, "templates")
_STATIC_DIR = os.path.join(_HERE, "static")


# --- control-plane hardening (component #12, CC-UI-0026, R-13) ---------------
#
# The panel is loopback-only (D11) but still reachable by any web page the operator's
# browser visits, so it needs its own CSRF/DNS-rebinding defenses even with no ambient
# credential (cookieless; SameSite wouldn't help — see below). Two INDEPENDENT gates are
# required because each attack defeats the other's single defense on its own:
#
#   (a) Host allow-list, checked on *every* request. This is the only defense against
#       DNS rebinding (a hostile page's origin resolves to 127.0.0.1 after the browser
#       already trusted it): the attacker's JS runs same-origin per the browser but the
#       Host header the server actually receives is wrong. Rolled ourselves rather than
#       Starlette's TrustedHostMiddleware, which matches host only and strips/ignores
#       the port — useless here since the port is exactly what pins this app apart from
#       the lab target sharing the same loopback address.
#   (b) On state-changing methods (POST/PUT/DELETE): Origin must equal the allow-list
#       *and* Sec-Fetch-Site must be "same-origin" — REJECTING "same-site" too. A "site"
#       is scheme+registrable-domain and port-independent, so this control plane and the
#       deliberately-vulnerable lab it drives are same-site on 127.0.0.1 (only the port
#       differs) — same-site alone is not enough here (classic CSRF sends a correct Host
#       but a cross-site/attacker Origin; DNS rebinding sends a correct-looking
#       Sec-Fetch-Site/Origin but a wrong Host — only the pair catches both).
#
# No CSRF token / session store: there's no ambient credential (no cookies) for a forged
# request to ride on, so header validation alone suffices, and staying cookieless avoids
# ever needing SameSite (which, per the same-site landmine above, would not help anyway).
# Loopback is treated as a secure context, so modern browsers reliably send
# Sec-Fetch-*/Origin; the Referer fallback below covers older/non-browser clients only.
#
# Implemented as a raw ASGI middleware (not `BaseHTTPMiddleware`) so it never buffers or
# otherwise interferes with the SSE launch-output stream (`/api/launch/{token}/stream`).

_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")

# Headers applied to every response, success or denial (security posture must not
# depend on the outcome of the gate that decides whether to serve the request at all).
_SECURITY_RESPONSE_HEADERS: list[tuple[bytes, bytes]] = [
    (b"content-security-policy", _CSP.encode("latin-1")),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"same-origin"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
]

# Content-Types that indicate a plain, no-JS <form method="post"> submission (e.g. the
# panel's "Run automatic" quick-action) rather than a script-driven `fetch()`/XHR call.
# The X-Fuzzlab-Client custom-header gate below is skipped for these — a native form can
# never set a custom header, JS or not, so requiring it there would just break the
# no-JS-friendly form with no security gain; Origin + Sec-Fetch-Site already defend that
# path (a cross-site page's auto-submitted form fails the same-origin check).
_FORM_CONTENT_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data")


def _security_allowlist(cfg: Config) -> tuple[frozenset[str], frozenset[str]]:
    """The exact Host-header value(s) and Origin(s) this control plane accepts, derived
    from its own loopback bind config (single source of truth for both gates below)."""
    host = str(cfg.get("web_host", "127.0.0.1"))
    port = int(cfg.get("web_port", 8787))
    host_port = f"{host}:{port}".lower()
    return frozenset({host_port}), frozenset({f"http://{host_port}"})


def _origin_of(url: str) -> str | None:
    """``scheme://host[:port]`` of a URL (e.g. a Referer), or None if unparseable."""
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}".lower()


async def _deny(send, status: int, reason: str) -> None:
    """Send a minimal, fail-closed denial response carrying the same security headers
    as any other response, bypassing the wrapped app entirely."""
    body = reason.encode("utf-8")
    headers = [
        (b"content-type", b"text/plain; charset=utf-8"),
        (b"content-length", str(len(body)).encode("latin-1")),
        (b"cache-control", b"no-store"),
        *_SECURITY_RESPONSE_HEADERS,
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _inject_response_headers(send, path: str):
    """Wrap an ASGI `send` so every response (not just denials) carries the CSP/frame/
    sniff/referrer/COOP/CORP headers, plus `Cache-Control: no-store` off `/static/`."""
    async def _send(message):
        if message["type"] == "http.response.start":
            headers = list(message.get("headers", []))
            headers.extend(_SECURITY_RESPONSE_HEADERS)
            if not path.startswith("/static/"):
                headers.append((b"cache-control", b"no-store"))
            message = {**message, "headers": headers}
        await send(message)
    return _send


class SecurityGateMiddleware:
    """Guards the control plane's state-changing surface against being driven by a
    hostile web page (component #12, CC-UI-0026, R-13/NFR-UI-localhost). See the module
    banner above for the two-gate rationale. Fail-closed: any ambiguity is a denial."""

    def __init__(self, app, *, allowed_hosts: frozenset[str], allowed_origins: frozenset[str]):
        self._app = app
        self._hosts = allowed_hosts
        self._origins = allowed_origins

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}

        # Gate (a): Host allow-list, every request — the DNS-rebinding defense.
        host = headers.get("host")
        if host is None or host.lower() not in self._hosts:
            await _deny(send, 421, "unrecognized Host (DNS-rebinding guard)")
            return

        # Gate (b): state-changing methods only.
        if scope["method"] in ("POST", "PUT", "DELETE"):
            if not self._state_change_allowed(headers, scope["path"]):
                await _deny(send, 403, "cross-origin/cross-site request rejected")
                return

        await self._app(scope, receive, _inject_response_headers(send, scope["path"]))

    def _state_change_allowed(self, headers: dict[str, str], path: str) -> bool:
        origin = headers.get("origin")
        sec_fetch_site = headers.get("sec-fetch-site")
        referer = headers.get("referer")

        if sec_fetch_site is not None:
            # Fetch Metadata present (reliable on loopback's secure context): same-
            # origin ONLY — same-site is rejected too (the same-site landmine above).
            if sec_fetch_site != "same-origin":
                return False
            if origin is None or origin.lower() not in self._origins:
                return False
        else:
            # No Fetch Metadata: an older browser or a non-browser client (e.g. a
            # script hitting the API directly). Fall back to Origin, then Referer.
            ok = origin is not None and origin.lower() in self._origins
            if not ok and referer is not None:
                ref_origin = _origin_of(referer)
                ok = ref_origin is not None and ref_origin in self._origins
            if not ok:
                return False

        if path.startswith("/api/"):
            content_type = headers.get("content-type", "")
            is_form = content_type.split(";", 1)[0].strip().lower() in _FORM_CONTENT_TYPES
            if not is_form and headers.get("x-fuzzlab-client") != "1":
                return False
        return True


# U0 (CC-UI-0025): single source of truth for the sidebar nav — real per-section
# routes, grouped Workbench / Analysis per FR-UI-7/8. `href` is a real URL (no
# hash), `id` is compared against the per-request `active` section to render
# server-side `aria-current="page"` (R-01/R-11); nothing here is JS-switched.
NAV: list[dict[str, Any]] = [
    {"group": "Workbench", "links": [
        # U1/CC-UI-0028: Overview is now the landing route ("/"); Launcher moved to
        # its own route ("/launcher") so the dashboard doesn't overload it (R-10).
        {"id": "overview", "label": "Overview", "href": "/", "icon": "◆"},
        {"id": "launcher", "label": "Launcher", "href": "/launcher", "icon": "▸"},
        {"id": "proxy", "label": "Proxy", "href": "/proxy", "icon": "⇄"},
        {"id": "results", "label": "Results", "href": "/results", "icon": "▤"},
    ]},
    {"group": "Analysis", "links": [
        {"id": "ml", "label": "ML", "href": "/ml", "icon": "◈"},
        {"id": "diagnostics", "label": "Diagnostics", "href": "/diagnostics", "icon": "◍"},
    ]},
]

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


def _read_ml(cfg: Config, run_id: int | None = None) -> dict:
    """The whole read-only ML overview (U4/CC-UI-0031, CC-ML-0010) — every panel from
    already-stored model internals; `{"available_any": False}` when the store has
    nothing to show yet (no model trained, no bandit posteriors, ...)."""
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return {"run_id": run_id, "available_any": False}
    from fuzzlab.core.store import Store
    with Store(path) as store:
        overview = mlview.ml_overview(store, run_id)
    overview["available_any"] = any(
        isinstance(v, dict) and v.get("available") for v in overview.values())
    return overview


def _read_flows(cfg: Config, query: str | None = None) -> list[dict]:
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return []
    from fuzzlab.core.store import Store
    from fuzzlab.web import proxyview
    with Store(path) as store:
        return proxyview.list_flows(store, query=query)


def _read_overview(cfg: Config) -> dict:
    """The Overview dashboard's aggregate (U1/CC-UI-0028); empty-store safe, never
    creates the store file."""
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return {
            "total_findings": 0, "severity": dict.fromkeys(
                ("critical", "high", "medium", "low", "info"), 0),
            "total_runs": 0, "runs_last_7d": 0, "recent_runs": [], "last_run": None,
            "detection_quality": None, "efficiency": None,
        }
    from fuzzlab.core.store import Store
    with Store(path) as store:
        return results.overview_summary(store)


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


# Launcher master-list grouping: an ordered, human-meaningful grouping of activities for
# the Launch view's activity picker. Names not listed fall into "Other" (so a new tool still
# appears). Order within a group follows this list, then registry order for the remainder.
_ACTIVITY_GROUPS: list[tuple[str, tuple[str, ...]]] = [
    ("Discovery", ("crawl", "audit")),
    ("Attack", ("auto", "fuzz", "greybox-run", "mutate-run", "proxy")),
    ("Analysis", ("report", "session")),
]


def _group_activities(activities: list[dict]) -> list[dict]:
    """Bucket activities into the ordered launcher groups; drop empty groups, and append an
    'Other' group for any activity not named above so nothing is ever hidden from the picker."""
    by_name = {a["name"]: a for a in activities}
    grouped: list[dict] = []
    claimed: set[str] = set()
    for label, names in _ACTIVITY_GROUPS:
        acts = [by_name[n] for n in names if n in by_name]
        claimed.update(a["name"] for a in acts)
        if acts:
            grouped.append({"label": label, "acts": acts})
    # Leftover activities bucket by an explicit spec `group` (X0: e.g. "Lab /
    # authoring"), else "Other" — preserving registry order and group
    # first-appearance order.
    order: list[str] = []
    buckets: dict[str, list[dict]] = {}
    for a in activities:
        if a["name"] in claimed:
            continue
        label = a.get("group") or "Other"
        if label not in buckets:
            buckets[label] = []
            order.append(label)
        buckets[label].append(a)
    for label in order:
        grouped.append({"label": label, "acts": buckets[label]})
    return grouped


def _active_plugins() -> list[dict]:
    """The entry-point plugins that a run with ``--plugins`` would attach."""
    try:
        from fuzzlab.plugins.manager import PluginManager
        return [{"name": p.name, "version": p.version, "priority": p.priority}
                for p in PluginManager.from_entry_points().active()]
    except Exception:  # noqa: BLE001 - discovery must never break the panel
        return []


def _shell_context(cfg: Config, active: str | None = None) -> dict[str, Any]:
    """Chrome shared by every page (sidebar + top context bar): the target, scope,
    authorization state, and the nav/active section the topbar/sidebar render.
    Merged into each TemplateResponse so the shell is identical on every route —
    each section's own route (U0/CC-UI-0025), a run detail, and the not-found page."""
    return {
        "target": cfg.get("target_base_url", ""),
        "scope": ", ".join(cfg.get("scope_hosts", [])),
        "authorized": bool(cfg.get("authorized", False)),
        "nav": NAV,
        "active": active,
    }


def _launcher_context(cfg: Config, state: LauncherState) -> dict[str, Any]:
    activities = _activities()
    return {
        **_shell_context(cfg, active="launcher"),
        "mode": state.mode,
        "categories": _known_categories(),
        "commands": _tool_commands(cfg),
        "activities": activities,
        "activity_groups": _group_activities(activities),
        "plugins": _active_plugins(),
        "last_result": None if state.last_result is None else str(state.last_result),
    }


def _results_context(cfg: Config, runs: list[dict]) -> dict[str, Any]:
    return {**_shell_context(cfg, active="results"), "runs": runs}


def _overview_context(cfg: Config) -> dict[str, Any]:
    return {**_shell_context(cfg, active="overview"), **_read_overview(cfg)}


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
    # Control-plane hardening (CC-UI-0026, R-13) — see the class/module docs above.
    # Added first so it wraps every route below, including /static.
    allowed_hosts, allowed_origins = _security_allowlist(cfg)
    app.add_middleware(SecurityGateMiddleware, allowed_hosts=allowed_hosts,
                       allowed_origins=allowed_origins)
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
    templates = Jinja2Templates(directory=_TEMPLATES_DIR)

    def _resolve(name: str):
        """Look up a launchable activity's spec, or None if unknown."""
        try:
            return commandspec.spec(name)
        except KeyError:
            return None

    # --- section routes (U0/CC-UI-0025): real per-section MPA routes replacing the
    # old hash-switched single page; each is independently deep-linkable and no-JS
    # renders its full content (R-01). Sidebar `active` state (aria-current) is
    # computed server-side per route via `_shell_context`/`_launcher_context`.

    @app.get("/", response_class=HTMLResponse)
    def overview_page(request: Request):
        # U1/CC-UI-0028: Overview is the landing route; read-only over the store
        # (renders with an empty store and with seeded runs, R-10).
        return templates.TemplateResponse(
            request, "sections/overview.html", _overview_context(cfg))

    @app.get("/launcher", response_class=HTMLResponse)
    def launcher(request: Request):
        return templates.TemplateResponse(
            request, "sections/launcher.html", _launcher_context(cfg, state))

    @app.get("/proxy", response_class=HTMLResponse)
    def proxy_page(request: Request, repeater_tab: int | None = None):
        # `repeater_tab` is an opaque hint carried across the PRG "send to Repeater"
        # pivot (R-07) — never bytes, just the tab id; the page falls back to the
        # default (no pre-selection) if it doesn't resolve to a live tab.
        ctx = {**_shell_context(cfg, active="proxy"), "repeater_tab": repeater_tab}
        return templates.TemplateResponse(request, "sections/proxy.html", ctx)

    @app.get("/results", response_class=HTMLResponse)
    def results_page(request: Request):
        return templates.TemplateResponse(
            request, "sections/results.html", _results_context(cfg, _read_runs(cfg)))

    @app.get("/ml", response_class=HTMLResponse)
    def ml_page(request: Request):
        return templates.TemplateResponse(
            request, "sections/ml.html", _shell_context(cfg, active="ml"))

    @app.get("/diagnostics", response_class=HTMLResponse)
    def diagnostics_page(request: Request):
        return templates.TemplateResponse(
            request, "sections/diagnostics.html", _shell_context(cfg, active="diagnostics"))

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
                request, "not_found.html",
                {"run_id": run_id, **_shell_context(cfg, active="results")}, status_code=404)
        return templates.TemplateResponse(
            request, "run.html", {"detail": detail, **_shell_context(cfg, active="results")})

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

    # --- ML tab (U4/CC-UI-0031, CC-ML-0010): read-only, advisory (R-06) ---------

    @app.get("/api/ml/data")
    def ml_data(run_id: int | None = None):
        return _read_ml(cfg, run_id)

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

    # --- scope + match-replace (in-process proxy only) ------------------------

    @app.get("/api/proxy/scope")
    def scope_list():
        if proxy is None:
            return _need_proxy()
        return {"scope": proxy.scope_view()}

    @app.post("/api/proxy/scope")
    async def scope_add(request: Request):
        if proxy is None:
            return _need_proxy()
        b = await request.json()
        if not b.get("host"):
            return JSONResponse({"error": "host required"}, status_code=400)
        proxy.scope_add(b["host"], b.get("path_regex") or None, bool(b.get("exclude")))
        return {"scope": proxy.scope_view()}

    @app.delete("/api/proxy/scope/{index}")
    def scope_remove(index: int):
        if proxy is None:
            return _need_proxy()
        return {"removed": proxy.scope_remove(index), "scope": proxy.scope_view()}

    @app.get("/api/proxy/matchreplace")
    def mr_list():
        if proxy is None:
            return _need_proxy()
        return {"rules": proxy.matchreplace_view()}

    @app.post("/api/proxy/matchreplace")
    async def mr_add(request: Request):
        if proxy is None:
            return _need_proxy()
        b = await request.json()
        try:
            proxy.matchreplace_add(b.get("target", ""), b.get("match", ""),
                                   b.get("replace", ""), b.get("header_name") or None,
                                   bool(b.get("is_regex")))
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return {"rules": proxy.matchreplace_view()}

    @app.delete("/api/proxy/matchreplace/{index}")
    def mr_remove(index: int):
        if proxy is None:
            return _need_proxy()
        return {"removed": proxy.matchreplace_remove(index),
                "rules": proxy.matchreplace_view()}

    @app.post("/api/proxy/matchreplace/{index}/toggle")
    async def mr_toggle(index: int, request: Request):
        if proxy is None:
            return _need_proxy()
        b = await request.json()
        return {"toggled": proxy.matchreplace_toggle(index, bool(b.get("enabled"))),
                "rules": proxy.matchreplace_view()}

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

    # --- "send to Repeater" pivot, PRG + 303 (R-07) ----------------------------
    # A real <form method="post"> so the pivot works as a plain navigation (no JS
    # required to trigger it): POST creates the tab server-side, then a 303
    # redirect to GET /proxy carries only the opaque tab id in the query string —
    # never raw request bytes (those stay server-side; redaction is render-time).
    @app.post("/proxy/repeater/from-flow")
    async def repeater_from_flow_prg(request: Request):
        # Parsed by hand (urlencoded `application/x-www-form-urlencoded`, the
        # browser's default for a plain <form>) rather than Starlette's
        # `request.form()`, which pulls in `python-multipart` even for this
        # single-field case — an extra dependency this one field doesn't earn.
        from urllib.parse import parse_qsl
        body = (await request.body()).decode("utf-8", errors="replace")
        form = dict(parse_qsl(body))
        try:
            flow_id = int(form.get("flow_id", ""))
        except (TypeError, ValueError):
            return RedirectResponse(url="/proxy", status_code=303)
        tab = repeater_ctl.create_from_flow(flow_id)
        if tab is None:
            return RedirectResponse(url="/proxy", status_code=303)
        return RedirectResponse(url=f"/proxy?repeater_tab={tab['id']}", status_code=303)

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
