"""Shared helper: build an authenticated HTTP client for the requests-based tools.

Wires a tool's HTTP through the `core/` seam with the session manager as the addon,
so a tool run as an identity stays authenticated (detection-only login, per-host
credentials). Standalone (no identity) tools keep using plain requests; this is
only for the authenticated path.

Module-level imports stay light (stdlib only); the heavy wiring is inside
``make_authenticated_client`` so importing ``with_query_param`` costs nothing.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def with_query_param(url: str, name: str, value) -> str:
    """Return ``url`` with query parameter ``name`` set to ``value``."""
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[name] = str(value)
    return urlunparse(parts._replace(query=urlencode(query)))


def _build(target_url: str, timeout: float, store_path: str | None = None):
    """Build the session manager + an HttpClient sharing it, scoped to the target.

    The target host is added to scope (the tool's `--authorized`/`--url`/`--base-url`
    is the authorization). Credentials come from the per-host credential store (D12).
    When ``store_path`` is given, non-secret session state is persisted there (T1.7).
    """
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.config import load_config
    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.core.http import HttpClient
    from fuzzlab.session.manager import SessionManager

    cfg = load_config()
    host = urlparse(target_url).hostname or ""
    scope = list(cfg.get("scope_hosts", []))
    if host and host not in scope:
        scope.append(host)
    creds = CredentialStore.open(cfg)
    store = None
    if store_path:
        from fuzzlab.core.store import Store
        store = Store(store_path)
    manager = SessionManager(creds, scope_hosts=scope, store=store)
    budget = RequestBudget(int(cfg.get("budget_total", 5000)))
    client = HttpClient(budget, scope, session=manager, timeout=timeout)
    return manager, client


def make_authenticated_client(target_url: str, identity: str, timeout: float = 15.0,
                              store_path: str | None = None):
    """A `core/` HttpClient with the session manager attached (for requests-path tools)."""
    return _build(target_url, timeout, store_path)[1]


def make_auth(target_url: str, timeout: float = 15.0, store_path: str | None = None):
    """Return ``(session_manager, http_client)`` for a target — the manager is used
    for Playwright cookie injection, the client for the requests/static path."""
    return _build(target_url, timeout, store_path)


def make_session_manager(target_url: str, timeout: float = 15.0,
                         store_path: str | None = None):
    """Just the session manager for a target (Playwright cookie injection)."""
    return _build(target_url, timeout, store_path)[0]
