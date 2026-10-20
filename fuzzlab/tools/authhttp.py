"""Shared helper: build an authenticated HTTP client for the requests-based tools.

Wires a tool's HTTP through the `core/` seam with the session manager as the addon,
so a tool run as an identity stays authenticated (detection-only login, per-host
credentials). Standalone (no identity) tools keep using plain requests; this is
only for the authenticated path.

Module-level imports stay light (stdlib only); the heavy wiring is inside
``make_authenticated_client``. Placing a value in a query is not done here: every
sender uses ``core.urls`` (``place_query_param``, ``bind_query``, ``with_query``; SP-42,
FR-FUZZ-64, BUG-0531).
"""

from __future__ import annotations

from urllib.parse import urlparse


def scope_hosts_for(target_url: str) -> list[str]:
    """The scope a session-using CLI runs with: the config's ``scope_hosts`` plus the
    target's host (the tool's `--authorized` target is the authorization)."""
    from fuzzlab.core.config import load_config
    host = urlparse(target_url).hostname or ""
    scope = list(load_config().get("scope_hosts", []))
    if host and host not in scope:
        scope.append(host)
    return scope


def _build(target_url: str, timeout: float, store_path: str | None = None,
           auth_origins=()):
    """Build the session manager + an HttpClient sharing it, scoped to the target."""
    manager, client, _budget, _scope = _build_parts(target_url, timeout, store_path,
                                                    auth_origins=auth_origins)
    return manager, client


def _build_parts(target_url: str, timeout: float, store_path: str | None = None,
                 auth_origins=()):
    """``(manager, client, budget, scope)``: the session manager + an HttpClient sharing
    it, scoped to the target, and the request budget and scope they were built with.

    The target host is added to scope (the tool's `--authorized`/`--url`/`--base-url`
    is the authorization). Credentials come from the per-host credential store (D12).
    When ``store_path`` is given, non-secret session state is persisted there (T1.7).
    ``auth_origins`` (``--auth-origin``, FR-SESS-20) are the operator's authorised auth
    origins: credential destinations and session origins.
    """
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.config import load_config
    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.core.http import HttpClient
    from fuzzlab.session.manager import SessionManager

    cfg = load_config()
    scope = scope_hosts_for(target_url)
    creds = CredentialStore.open(cfg)
    store = None
    if store_path:
        from fuzzlab.core.store import Store
        store = Store(store_path)
    manager = SessionManager(creds, scope_hosts=scope, store=store,
                             auth_origins=list(auth_origins or ()))
    budget = RequestBudget(int(cfg.get("budget_total", 5000)))
    client = HttpClient(budget, scope, session=manager, timeout=timeout)
    return manager, client, budget, scope


def make_authenticated_client(target_url: str, identity: str, timeout: float = 15.0,
                              store_path: str | None = None):
    """A `core/` HttpClient with the session manager attached (for requests-path tools)."""
    return _build(target_url, timeout, store_path)[1]


def make_auth(target_url: str, timeout: float = 15.0, store_path: str | None = None):
    """Return ``(session_manager, http_client)`` for a target — the manager is used
    for Playwright cookie injection, the client for the requests/static path."""
    return _build(target_url, timeout, store_path)


def make_session_manager(target_url: str, timeout: float = 15.0,
                         store_path: str | None = None, auth_origins=()):
    """Just the session manager for a target (Playwright cookie injection)."""
    return _build(target_url, timeout, store_path, auth_origins=auth_origins)[0]


def make_auth_with_isolation(target_url: str, timeout: float = 15.0, auth_origins=()):
    """``(manager, client, isolated_client)``: as `make_auth`, plus a factory that builds
    an isolated copy's `HttpClient` (FR-FUZZ-44). The factory shares only the run's
    request budget and scope — isolated sends spend the run's budget — and attaches
    the copy as the session addon; nothing else is shared."""
    from fuzzlab.core.http import HttpClient
    manager, client, budget, scope = _build_parts(target_url, timeout,
                                                  auth_origins=auth_origins)

    def isolated_client(copy_manager):
        return HttpClient(budget, list(scope), session=copy_manager, timeout=timeout)

    return manager, client, isolated_client
