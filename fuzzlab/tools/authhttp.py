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


def make_authenticated_client(target_url: str, identity: str, timeout: float = 15.0):
    """Build a `core/` HttpClient with the session manager attached for a target.

    The target host is added to scope (the tool's `--authorized`/`--url` is the
    authorization). Credentials come from the per-host credential store (D12).
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
    manager = SessionManager(creds, scope_hosts=scope)
    budget = RequestBudget(int(cfg.get("budget_total", 5000)))
    return HttpClient(budget, scope, session=manager, timeout=timeout)
