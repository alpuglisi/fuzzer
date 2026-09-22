"""Shared TestClient helper for the web control panel's tests.

U6's control-plane hardening (CC-UI-0026, R-13) adds a Host allow-list on every
request and, on POST/PUT/DELETE, an Origin + Sec-Fetch-Site + custom-header check
(see ``fuzzlab.web.app.SecurityGateMiddleware``). A bare ``TestClient(app)`` uses
httpx's default ``http://testserver`` base URL and sends none of those headers, so
every existing web test needs a client that looks like a legitimate same-origin
browser request against the app's actual (default) loopback bind. Centralized here
rather than repeated per test file.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

# Matches the Config defaults (web_host/web_port) used by every test in this suite
# that does not itself override them.
WEB_BASE_URL = "http://127.0.0.1:8787"

# Satisfies both U6 gates: Origin/Sec-Fetch-Site pass the same-origin check, and
# X-Fuzzlab-Client satisfies the /api/* custom-header requirement. Harmless on GET.
SAME_ORIGIN_HEADERS = {
    "Origin": WEB_BASE_URL,
    "Sec-Fetch-Site": "same-origin",
    "X-Fuzzlab-Client": "1",
}


def web_client(app, **kwargs) -> TestClient:
    """A ``TestClient`` for ``app`` that clears U6's control-plane gate by default.

    Extra ``**kwargs`` (e.g. ``follow_redirects=False``) pass straight through to
    ``TestClient``.
    """
    return TestClient(app, base_url=WEB_BASE_URL, headers=SAME_ORIGIN_HEADERS, **kwargs)
