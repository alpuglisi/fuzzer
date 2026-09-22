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
from fuzzlab.web import (commandspec, diagview, findingsview, results,
                         savedviews, storeview)
from fuzzlab.web.proxycontrol import RepeaterController
from fuzzlab.web.runner import Runner, build_argv, display_command
from fuzzlab.web.sse import sse_response

if TYPE_CHECKING:
    from fuzzlab.web.proxycontrol import ProxyController

_HERE = os.path.dirname(os.path.abspath(__file__))
_TEMPLATES_DIR = os.path.join(_HERE, "templates")
_STATIC_DIR = os.path.join(_HERE, "static")


# --- U6: control-plane hardening (component #12, R-13/CC-UI-0026) -------------
#
# A single global ASGI middleware (not `BaseHTTPMiddleware`, which historically
# buffers/interferes with streaming responses like the launcher's SSE stream)
# that closes the loopback control panel's remaining web-attacker surface:
# DNS-rebinding (a wrong Host header) and CSRF/cross-site POSTs driven by a
# hostile page the person merely has open in another tab. Two independent
# gates, per the resolved R-13 research note in
# docs/UI_IMPLEMENTATION_PLAN.md §U6 (both are required — each defeats an
# attack the other alone misses):
#
#   (a) **Host allow-list**, on every request. Starlette's own
#       ``TrustedHostMiddleware`` strips the port before comparing, so a
#       rebinding attack that resolves an attacker domain to 127.0.0.1 but
#       keeps the (wrong) port would sail through it; this checks the *exact*
#       ``host:port`` instead. The expected value is read from the ASGI
#       ``scope["server"]`` tuple — the local address this connection was
#       actually accepted on (uvicorn sets it from the socket, never from
#       anything client-supplied) — so it self-adjusts to whatever host/port
#       the app is actually bound to for that connection (needed since e.g.
#       browser-driven tests bind an ephemeral port) without trusting the
#       client at all. A mismatch is fail-closed: HTTP 421.
#   (b) On state-changing methods (POST/PUT/DELETE): **Origin exact-match**
#       plus **`Sec-Fetch-Site: same-origin`** — deliberately rejecting
#       `same-site` too, because the deliberately-vulnerable lab this panel
#       drives runs on a sibling loopback port, which is *same-site* but must
#       never be treated as trusted. Browsers without Fetch Metadata (or a
#       plain HTML form submit) fall back to an exact-prefix **Referer**
#       check. `/api/*` routes additionally require the custom
#       `X-Fuzzlab-Client: 1` header, which a cross-origin page cannot attach
#       without triggering a CORS preflight it cannot satisfy (no server-side
#       CORS is configured — cookieless by design; SameSite cookies would not
#       help here since the lab is same-site, D11/no-auto-run). Any failure
#       here is fail-closed: HTTP 403. This is independent of the existing
#       `authorized` gate (still read only from server-side `Config`, never
#       from the request body) and of target validation on send/replay paths
#       (`RepeaterController`/`ProxyController` — read separately; unaffected
#       by this middleware).
#
# Every response, including a rejected one, also gets a tight offline
# security-header set (CSP/nosniff/frame-options/referrer-policy/COOP/CORP),
# plus `Cache-Control: no-store` on `/api/*`, `/results` and `/runs/*`
# responses so a shared/forward proxy or browser cache never retains findings.
_SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"content-security-policy",
     b"default-src 'none'; script-src 'self'; style-src 'self'; "
     b"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
     b"base-uri 'none'; object-src 'none'"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"same-origin"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
]
_NO_STORE_PREFIXES = ("/api/", "/results", "/runs/")
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE"})


def _no_store_path(path: str) -> bool:
    return path.startswith(_NO_STORE_PREFIXES) or path == "/results"


def _inject_security_headers(message: dict[str, Any], path: str) -> dict[str, Any]:
    """Return an ``http.response.start`` message with the fixed security-header
    set applied (replacing any same-named header a route already set)."""
    drop = {name for name, _ in _SECURITY_HEADERS}
    if _no_store_path(path):
        drop.add(b"cache-control")
    kept = [(n, v) for n, v in message.get("headers", []) if n.lower() not in drop]
    kept.extend(_SECURITY_HEADERS)
    if _no_store_path(path):
        kept.append((b"cache-control", b"no-store"))
    message["headers"] = kept
    return message


async def _deny(send: Callable, status: int, reason: str, path: str) -> None:
    """Send a minimal, fail-closed plain-text rejection (still carrying the
    same security headers as any other response)."""
    body = reason.encode("utf-8")
    start = {
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("latin-1"))],
    }
    await send(_inject_security_headers(start, path))
    await send({"type": "http.response.body", "body": body})


def _header_map(scope: dict[str, Any]) -> dict[str, str]:
    """Case-insensitive view of the ASGI scope's raw (bytes, bytes) headers."""
    out: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", []):
        out[raw_name.decode("latin-1").lower()] = raw_value.decode("latin-1")
    return out


def _expected_host(scope: dict[str, Any]) -> str | None:
    """The ``host:port`` this connection was actually accepted on (from the
    ASGI server, never from a client-supplied header) — the ground truth the
    Host header is checked against."""
    server = scope.get("server")
    if not server or server[0] is None:
        return None
    host, port = server
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}" if port else host


def _origin_check(headers: dict[str, str], expected_origin: str) -> tuple[bool, str]:
    """Origin/Sec-Fetch-Site/Referer gate for a state-changing request. See the
    module-level comment above for why both Fetch-Metadata and Referer paths
    are needed, and why `same-site` must be rejected alongside `same-site`."""
    sec_fetch_site = headers.get("sec-fetch-site")
    origin = headers.get("origin")
    if sec_fetch_site is not None:
        if sec_fetch_site.lower() != "same-origin":
            return False, "cross-origin request (Sec-Fetch-Site)"
        if origin is None or origin.rstrip("/").lower() != expected_origin.lower():
            return False, "Origin mismatch"
        return True, ""
    # No Fetch Metadata (plain form POST / non-browser client): fall back to
    # an exact-prefix Referer check; an Origin header, if present, must still
    # agree (browsers attach Origin to same-origin POSTs too).
    referer = headers.get("referer")
    if referer is None:
        return False, "no Sec-Fetch-Site and no Referer"
    ref = referer.lower()
    exp = expected_origin.lower()
    if ref != exp and not ref.startswith(exp + "/"):
        return False, "Referer mismatch"
    if origin is not None and origin.rstrip("/").lower() != exp:
        return False, "Origin mismatch"
    return True, ""


class ControlPlaneHardening:
    """Global ASGI middleware: Host allow-list + Origin/Sec-Fetch-Site/Referer
    CSRF gate + security headers on every response (U6, R-13). See the
    module-level comment block above for the full rationale."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "/")
        headers = _header_map(scope)
        expected_host = _expected_host(scope)

        host_header = headers.get("host")
        if expected_host is None or host_header is None or \
                host_header.lower() != expected_host.lower():
            await _deny(send, 421, "misdirected request: bad Host header", path)
            return

        if scope.get("method") in _STATE_CHANGING_METHODS:
            scheme = scope.get("scheme") or "http"
            expected_origin = f"{scheme}://{expected_host}"
            ok, reason = _origin_check(headers, expected_origin)
            if ok and path.startswith("/api/") and headers.get("x-fuzzlab-client") != "1":
                ok, reason = False, "missing X-Fuzzlab-Client header"
            if not ok:
                await _deny(send, 403, f"forbidden: {reason}", path)
                return

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                message = _inject_security_headers(message, path)
            await send(message)

        await self.app(scope, receive, send_wrapper)

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


def _read_findings(cfg: Config) -> list[dict]:
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return []
    from fuzzlab.core.store import Store
    with Store(path) as store:
        return findingsview.list_findings(store)


def _read_finding(cfg: Config, finding_id: int) -> dict | None:
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return None
    from fuzzlab.core.store import Store
    with Store(path) as store:
        return findingsview.finding_detail(store, finding_id)


def _views_store(cfg: Config):
    """Open (creating if needed) the store for saved-view reads/writes.

    Unlike the read-only helpers above, saved views ARE something this panel
    itself writes (a UI-view-preference table, not a result table — see
    fuzzlab/web/savedviews.py), so, unlike ``_read_*``, this may create the
    store file on first save. Callers use it as a context manager.
    """
    from fuzzlab.core.store import Store
    return Store(cfg.get("store_path", "fuzzlab.db"))


# --- U5: diagnostics charts + store explorer (read-only) ---------------------

_CHART_TABLE_CAP = 200  # R-12's offscreen-fallback-table row cap


def _diagnostics_charts(cfg: Config) -> list[dict[str, Any]]:
    """One entry per populated `metric_series` (source, key), each carrying its
    server-downsampled data (R-05's render order) plus a capped flat row list
    for the chart's offscreen `<table>` fallback (R-09/R-11) — so the page is
    informative even with JS disabled, and `diagnostics.js` only has to hand
    the same `data` straight to the shared `createChart` wrapper."""
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return []
    from fuzzlab.core.store import Store
    charts: list[dict[str, Any]] = []
    with Store(path) as store:
        for i, s in enumerate(diagview.list_series(store)):
            data = diagview.series_data(store, s["source"], s["key"])
            table_rows: list[dict[str, Any]] = []
            for series in data["series"]:
                if series.get("y") is not None:
                    for x, y in zip(series["x"], series["y"]):
                        table_rows.append({"run_id": series["run_id"], "x": x, "y": y})
                else:
                    for x, mn, mx in zip(series["x"], series["min"], series["max"]):
                        table_rows.append({"run_id": series["run_id"], "x": x,
                                           "min": mn, "max": mx})
            charts.append({
                "id": f"chart-{i}",
                "source": s["source"],
                "key": s["key"],
                "mode": s["mode"],
                "runs": s["runs"],
                "points": s["points"],
                "data": data,
                "table_rows": table_rows[:_CHART_TABLE_CAP],
            })
    return charts


_DEFAULT_STORE_TABLE = "run"


def _diagnostics_store_explorer(cfg: Config, table: str | None,
                                limit: int, offset: int) -> dict[str, Any]:
    """The store explorer's context: every browsable table (name-only, for the
    picker) and the selected table's redacted page of rows (storeview does the
    redaction — this is purely wiring)."""
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return {"tables": [], "table": None}
    from fuzzlab.core.store import Store
    with Store(path) as store:
        tables = storeview.list_tables(store)
        names = [t["name"] for t in tables]
        if not names:
            return {"tables": [], "table": None}
        chosen = table if table in names else (
            _DEFAULT_STORE_TABLE if _DEFAULT_STORE_TABLE in names else names[0])
        rows = storeview.table_rows(store, chosen, limit=limit, offset=offset)
        return {"tables": names, "table": rows}


def _diagnostics_context(cfg: Config, table: str | None, limit: int, offset: int) -> dict[str, Any]:
    return {
        "charts": _diagnostics_charts(cfg),
        "store": _diagnostics_store_explorer(cfg, table, limit, offset),
    }


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


# --- MPA routing (U0): one source-of-truth nav list, real per-section routes ---
#
# Each entry is (section id, label, href, icon); the id doubles as the template's
# `data-section` hook and, when it matches the current route's `active` id (computed
# in the route handler below — never derived from the request path), drives the
# server-rendered `aria-current="page"` + `.active` class in base.html's nav loop.
# `group` buckets entries under the sidebar's two headers (Workbench / Analysis), in
# the order given here — the same "single list, no per-page duplication" pattern the
# launcher's `_ACTIVITY_GROUPS` above already uses for activities.
NAV: list[dict[str, str]] = [
    {"id": "overview", "label": "Overview", "href": "/", "icon": "◧",
     "group": "Workbench"},
    {"id": "launcher", "label": "Launcher", "href": "/launch", "icon": "▸",
     "group": "Workbench"},
    {"id": "proxy", "label": "Proxy", "href": "/proxy", "icon": "⇄",
     "group": "Workbench"},
    {"id": "findings", "label": "Findings", "href": "/findings", "icon": "⚑",
     "group": "Workbench"},
    {"id": "results", "label": "Results", "href": "/results", "icon": "▤",
     "group": "Workbench"},
    {"id": "ml", "label": "ML", "href": "/ml", "icon": "◈",
     "group": "Analysis"},
    {"id": "diagnostics", "label": "Diagnostics", "href": "/diagnostics", "icon": "◍",
     "group": "Analysis"},
]


def _nav_groups() -> list[tuple[str, list[dict[str, str]]]]:
    """Group NAV into (label, items) pairs, preserving first-appearance order —
    the shape base.html's sidebar loop renders the two `.side-sep` headers from."""
    groups: list[tuple[str, list[dict[str, str]]]] = []
    by_label: dict[str, list[dict[str, str]]] = {}
    for item in NAV:
        label = item["group"]
        if label not in by_label:
            by_label[label] = []
            groups.append((label, by_label[label]))
        by_label[label].append(item)
    return groups


_NAV_GROUPS = _nav_groups()


def _shell_context(cfg: Config, active: str) -> dict[str, Any]:
    """Chrome shared by every page (sidebar + top context bar): the target, scope,
    authorization state the topbar chips render, and the nav's active section.
    Merged into each TemplateResponse so the shell is identical on every section
    route, a run detail, and the not-found page. ``active`` is computed by the route
    handler (never guessed from the request path) and compared against NAV's ids in
    the nav loop for server-rendered active state (R-01 in
    docs/UI_IMPLEMENTATION_PLAN.md)."""
    return {
        "target": cfg.get("target_base_url", ""),
        "scope": ", ".join(cfg.get("scope_hosts", [])),
        "authorized": bool(cfg.get("authorized", False)),
        "nav_groups": _NAV_GROUPS,
        "active": active,
    }


def _launcher_context(cfg: Config, state: LauncherState) -> dict[str, Any]:
    """Context for the Launcher section route (``/``): activities, the manual/CLI
    reference, and the last dry-run/automatic result. No result-table data (that's
    the Results route) — the launcher only ever *launches* or previews."""
    activities = _activities()
    return {
        "mode": state.mode,
        "categories": _known_categories(),
        "commands": _tool_commands(cfg),
        "activities": activities,
        "activity_groups": _group_activities(activities),
        "plugins": _active_plugins(),
        "last_result": None if state.last_result is None else str(state.last_result),
    }


# --- Overview dashboard (U1): one aggregate read, no per-run joins on load ----
#
# The store has no severity column yet (the oracle writes `vuln_class` +
# `confidence` as its confirmation *mechanism*, e.g. "error-signature" — not a
# risk level; see `fuzzlab/oracle/oracle.py`). Severity-by-vuln-class below is a
# UI-only display heuristic (OWASP/CVSS-style convention), never a stored fact,
# until a real severity field lands on `finding` (flagged for U2/backend).
_SEVERITY_BY_VULN_CLASS: dict[str, str] = {
    "sqli": "Critical",
    "command-injection": "Critical",
    "ssti": "Critical",
    "file-inclusion": "High",
    "xss-reflected": "Medium",
    "xss-dom": "Medium",
    "xss-stored": "Medium",
    "open-redirect": "Low",
}
_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


def _severity_of(vuln_class: str | None) -> str:
    return _SEVERITY_BY_VULN_CLASS.get(vuln_class or "", "Info")


def _overview_context(cfg: Config) -> dict[str, Any]:
    """Context for the Overview dashboard (``/``): one aggregate read over the
    store — counts, pre-aggregated findings-by-severity, and the latest ~10 runs
    joined with their finding counts (one query, no N+1). Read-only; writes no
    result tables (FR-UI-11). Empty store or 0 runs -> the onboarding-card state;
    an unscored store -> em-dashes in the quality/efficiency tiles, never ``0``."""
    empty: dict[str, Any] = {"has_store": False, "kpi": None, "recent_runs": []}
    path = cfg.get("store_path", "fuzzlab.db")
    if not results.store_exists(path):
        return empty
    from fuzzlab.core.store import Store
    with Store(path) as store:
        run_count = store.conn.execute("SELECT COUNT(*) c FROM run").fetchone()["c"]
        if run_count == 0:
            return empty
        runs_7d = store.conn.execute(
            "SELECT COUNT(*) c FROM run WHERE started_at >= datetime('now','-7 days')"
        ).fetchone()["c"]
        finding_count = store.conn.execute(
            "SELECT COUNT(*) c FROM finding").fetchone()["c"]

        severity_totals: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
        for row in store.conn.execute(
                "SELECT vuln_class, COUNT(*) c FROM finding GROUP BY vuln_class"):
            severity_totals[_severity_of(row["vuln_class"])] += row["c"]
        severity_bars = [{"severity": s, "count": severity_totals[s]}
                         for s in _SEVERITY_ORDER if severity_totals[s]]

        recent_runs = [dict(row) for row in store.conn.execute(
            "SELECT r.id AS id, r.tool AS tool, r.config_hash AS target, "
            "r.started_at AS started_at, COUNT(f.id) AS findings "
            "FROM run r LEFT JOIN finding f ON f.run_id = r.id "
            "GROUP BY r.id ORDER BY r.id DESC LIMIT 10")]
        newest_run = recent_runs[0] if recent_runs else None

        # Detection quality: latest run the harness actually scored (an "f1" row
        # in run_metrics means `integration.record_metrics` ran for it).
        detection_quality = None
        f1_row = store.conn.execute(
            "SELECT run_id, value FROM run_metrics WHERE key='f1' "
            "ORDER BY run_id DESC LIMIT 1").fetchone()
        if f1_row is not None:
            mcc_row = store.conn.execute(
                "SELECT value FROM run_metrics WHERE run_id=? AND key='mcc'",
                (f1_row["run_id"],)).fetchone()
            detection_quality = {
                "run_id": f1_row["run_id"], "f1": round(f1_row["value"], 3),
                "mcc": round(mcc_row["value"], 3) if mcc_row else None}

        # Efficiency: latest run with a recorded requests-per-finding (automatic
        # mode only; see `fuzzlab/harness/pipeline.py`).
        efficiency = None
        rpf_row = store.conn.execute(
            "SELECT run_id, value FROM run_metrics "
            "WHERE key='pipeline_requests_per_finding' AND value IS NOT NULL "
            "ORDER BY run_id DESC LIMIT 1").fetchone()
        if rpf_row is not None:
            req_row = store.conn.execute(
                "SELECT value FROM run_metrics WHERE run_id=? AND key='pipeline_requests'",
                (rpf_row["run_id"],)).fetchone()
            efficiency = {
                "run_id": rpf_row["run_id"],
                "requests_per_finding": round(rpf_row["value"], 2),
                "total_requests": int(req_row["value"]) if req_row else None}

    return {
        "has_store": True,
        "recent_runs": recent_runs,
        "kpi": {
            "findings_total": finding_count,
            "severity_bars": severity_bars,
            "runs_total": run_count,
            "runs_7d": runs_7d,
            "newest_run": newest_run,
            "detection_quality": detection_quality,
            "efficiency": efficiency,
        },
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
    # U6: global control-plane hardening (Host allow-list + Origin/CSRF gate +
    # security headers) — added before any route so it wraps every response,
    # including static files and the SSE stream.
    app.add_middleware(ControlPlaneHardening)
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
    templates = Jinja2Templates(directory=_TEMPLATES_DIR)

    def _resolve(name: str):
        """Look up a launchable activity's spec, or None if unknown."""
        try:
            return commandspec.spec(name)
        except KeyError:
            return None

    # --- MPA section routes (U0): one real route per sidebar section, each its own
    # template + per-section JS/CSS. `active` is passed explicitly so the shared shell
    # renders the correct `aria-current="page"` without inferring it from the path. ---

    @app.get("/", response_class=HTMLResponse)
    def overview_page(request: Request):
        return templates.TemplateResponse(
            request, "sections/overview.html",
            {**_shell_context(cfg, "overview"), **_overview_context(cfg)})

    @app.get("/launch", response_class=HTMLResponse)
    def launcher_page(request: Request):
        return templates.TemplateResponse(
            request, "sections/launcher.html",
            {**_shell_context(cfg, "launcher"), **_launcher_context(cfg, state)})

    @app.get("/proxy", response_class=HTMLResponse)
    def proxy_page(request: Request, repeater_tab: int | None = None):
        # `repeater_tab` is a cross-section pivot HINT (R-07: "treat every
        # ?...=ID as a hint — fall back to default; never 404"), landed here by
        # the Findings "send to Repeater" PRG redirect (see
        # POST /findings/{id}/send-to-repeater below). Passed through so a
        # future Proxy-owned (U3) pass can pre-select that tab; unused today is
        # not an error — the page still renders normally either way.
        ctx = {**_shell_context(cfg, "proxy"), "repeater_tab_hint": repeater_tab}
        return templates.TemplateResponse(request, "sections/proxy.html", ctx)

    @app.get("/findings", response_class=HTMLResponse)
    def findings_page(request: Request):
        return templates.TemplateResponse(
            request, "sections/findings.html", _shell_context(cfg, "findings"))

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    def finding_html(request: Request, finding_id: int):
        detail = _read_finding(cfg, finding_id)
        if detail is None:
            return templates.TemplateResponse(
                request, "not_found.html",
                {"finding_id": finding_id, **_shell_context(cfg, "findings")},
                status_code=404)
        # Plain Jinja2 (unlike Flask) has no `tojson` filter, and the evidence
        # blob is untrusted (an oracle-recorded value from the target) —
        # pre-serialize it here so the template renders it through an ordinary
        # `{{ }}` (autoescaped: `<`/`&`/etc become entities, matching the
        # never-innerHTML rule for untrusted fields) rather than any
        # HTML-unsafe filter.
        import json as _json
        detail["evidence_pretty"] = _json.dumps(detail.get("evidence") or {}, indent=2)
        return templates.TemplateResponse(
            request, "sections/finding_detail.html",
            {"finding": detail, **_shell_context(cfg, "findings")})

    @app.get("/results", response_class=HTMLResponse)
    def results_page(request: Request):
        return templates.TemplateResponse(
            request, "sections/results.html",
            {**_shell_context(cfg, "results"), "runs": _read_runs(cfg)})

    @app.get("/ml", response_class=HTMLResponse)
    def ml_page(request: Request):
        return templates.TemplateResponse(
            request, "sections/ml.html", _shell_context(cfg, "ml"))

    @app.get("/diagnostics", response_class=HTMLResponse)
    def diagnostics_page(request: Request, table: str | None = None,
                         limit: int = 50, offset: int = 0):
        return templates.TemplateResponse(
            request, "sections/diagnostics.html",
            {**_shell_context(cfg, "diagnostics"),
             **_diagnostics_context(cfg, table, limit, offset)})

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

    @app.get("/api/findings")
    def api_findings() -> dict[str, Any]:
        return {"findings": _read_findings(cfg)}

    @app.get("/api/findings/{finding_id}")
    def api_finding(finding_id: int):
        detail = _read_finding(cfg, finding_id)
        if detail is None:
            return JSONResponse({"error": f"finding {finding_id} not found"},
                                status_code=404)
        return detail

    # --- send-to-repeater pivot (Findings -> Proxy, R-07 PRG+303) --------------
    #
    # Findings have no recorded `flow` (they come from the oracle's own probe
    # traffic, not the proxy's history), so there is nothing to call
    # `RepeaterController.create_from_flow` with. Instead this synthesizes a
    # best-effort raw request from the finding's own recorded url/method/param
    # (never from the URL bar — real bytes stay server-side, per R-07) and
    # seeds a tab from it, then 303s to `/proxy?repeater_tab=ID` exactly like
    # the plan's `/proxy/repeater/from-flow` pattern: a real POST (guarded by
    # disable-on-submit in findings.js) -> RedirectResponse(303) -> a plain GET
    # the browser can refresh safely. The request is a SEED to edit before
    # sending, not a byte-exact replay (findings don't carry raw bytes).
    @app.post("/findings/{finding_id}/send-to-repeater")
    async def finding_to_repeater(finding_id: int):
        detail = _read_finding(cfg, finding_id)
        if detail is None:
            return JSONResponse({"error": f"finding {finding_id} not found"},
                                status_code=404)
        from urllib.parse import urlparse
        base = cfg.get("target_base_url", "http://127.0.0.1")
        parsed = urlparse(base)
        host = parsed.hostname or "127.0.0.1"
        use_tls = parsed.scheme == "https"
        port = parsed.port or (443 if use_tls else 80)
        method = (detail.get("method") or "GET").upper()
        path = detail.get("url") or "/"
        param = detail.get("param")
        body = ""
        if method in ("GET", "HEAD", "DELETE") and param:
            sep = "&" if "?" in path else "?"
            path = f"{path}{sep}{param}=1"
        elif param:
            body = f"{param}=1"
        raw = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            + (f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\n" if body else "")
            + "\r\n" + body
        )
        tab = repeater_ctl.create_tab(f"finding #{finding_id}", host, port, raw,
                                      use_tls=use_tls)
        return RedirectResponse(f"/proxy?repeater_tab={tab['id']}", status_code=303)

    # --- saved views (U2): per-DataTable filter/sort/column presets, durable ---
    #
    # `table` scopes views to one DataTable-backed section (`findings` today;
    # any future section reuses the same four routes with its own `table`
    # value). This is the panel's own write surface (saved_views is a
    # UI-view-preference table — see fuzzlab/web/savedviews.py), so unlike the
    # read-only `_read_*` helpers, a POST here may create the store file.
    @app.get("/api/views")
    def views_list(table: str) -> dict[str, Any]:
        path = cfg.get("store_path", "fuzzlab.db")
        if not results.store_exists(path):
            return {"views": []}
        with _views_store(cfg) as store:
            return {"views": savedviews.list_views(store, table)}

    @app.post("/api/views")
    async def views_create(request: Request, table: str):
        body = await request.json()
        name = (body.get("name") or "").strip()
        if not name:
            return JSONResponse({"error": "name required"}, status_code=400)
        spec = body.get("spec") or {}
        with _views_store(cfg) as store:
            view = savedviews.create_view(store, table, name, spec,
                                          bool(body.get("pinned")))
        return view

    @app.put("/api/views/{view_id}")
    async def views_update(view_id: int, request: Request):
        body = await request.json()
        with _views_store(cfg) as store:
            view = savedviews.update_view(
                store, view_id, name=body.get("name"), spec=body.get("spec"),
                pinned=body.get("pinned"))
        if view is None:
            return JSONResponse({"error": f"view {view_id} not found"}, status_code=404)
        return view

    @app.delete("/api/views/{view_id}")
    def views_delete(view_id: int):
        path = cfg.get("store_path", "fuzzlab.db")
        if not results.store_exists(path):
            return JSONResponse({"error": f"view {view_id} not found"}, status_code=404)
        with _views_store(cfg) as store:
            ok = savedviews.delete_view(store, view_id)
        if not ok:
            return JSONResponse({"error": f"view {view_id} not found"}, status_code=404)
        return {"deleted": view_id}

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_html(request: Request, run_id: int):
        # A run's detail page is reached from the Results list, so it highlights
        # "results" in the nav even though it isn't itself a NAV entry.
        detail = _read_detail(cfg, run_id)
        if detail is None:
            return templates.TemplateResponse(
                request, "not_found.html",
                {"run_id": run_id, **_shell_context(cfg, "results")}, status_code=404)
        return templates.TemplateResponse(
            request, "run.html", {"detail": detail, **_shell_context(cfg, "results")})

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

    # --- U5: diagnostics charts + store explorer (read-only APIs) --------------

    def _open_store_or_none():
        path = cfg.get("store_path", "fuzzlab.db")
        if not results.store_exists(path):
            return None
        from fuzzlab.core.store import Store
        return Store(path)

    @app.get("/api/diagnostics/series")
    def diagnostics_series():
        store = _open_store_or_none()
        if store is None:
            return {"series": []}
        with store:
            return {"series": diagview.list_series(store)}

    @app.get("/api/diagnostics/series/data")
    def diagnostics_series_data(source: str, key: str, run_ids: str | None = None,
                                max_points: int = 1000):
        store = _open_store_or_none()
        if store is None:
            return JSONResponse({"error": "no store"}, status_code=404)
        ids = [int(x) for x in run_ids.split(",") if x.strip()] if run_ids else None
        with store:
            return diagview.series_data(store, source, key, ids, max_points)

    @app.get("/api/store/tables")
    def store_tables():
        store = _open_store_or_none()
        if store is None:
            return {"tables": []}
        with store:
            return {"tables": storeview.list_tables(store)}

    @app.get("/api/store/{table}")
    def store_table(table: str, limit: int = 100, offset: int = 0):
        store = _open_store_or_none()
        if store is None:
            return JSONResponse({"error": "no store"}, status_code=404)
        with store:
            rows = storeview.table_rows(store, table, limit=limit, offset=offset)
        if rows is None:
            return JSONResponse({"error": f"unknown table {table!r}"}, status_code=404)
        return rows

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
