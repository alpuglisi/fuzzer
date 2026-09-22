"""Shared TestClient construction for the web control panel (U6).

``ControlPlaneHardening`` (fuzzlab/web/app.py) now gates every request on an
exact Host match and, for POST/PUT/DELETE, on Origin + `Sec-Fetch-Site` (plus
`X-Fuzzlab-Client` on `/api/*`). httpx's TestClient does not send any of these
browser-only headers on its own, so every web test's client needs a base_url
that matches what the app treats as its own address (the ASGI ``scope
["server"]`` tuple) and a default header set that satisfies the same-origin
gate — otherwise every existing POST/PUT/DELETE test starts failing not
because the feature broke, but because the *test* now looks like a forged
cross-origin request. Centralizing it here (rather than re-deriving the right
headers in each test file) is exactly the "shared TestClient fixture" the
control-plane hardening lane's brief calls for.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

#: Same-origin base every test client uses; matches what ControlPlaneHardening
#: computes from the ASGI transport's default scope (host "testserver" has no
#: fixed port semantics we can rely on for Origin, so pin an explicit host:port
#: instead — any value works, since the middleware self-derives its own
#: expectation from the transport, not from app config).
BASE_URL = "http://127.0.0.1:8787"

#: Headers a same-origin fetch() call from the panel's own pages would send;
#: applied to every request (harmless on GET, required on state-changing
#: ones) so a single client "just works" against the U6 gate.
SAME_ORIGIN_HEADERS = {
    "Origin": BASE_URL,
    "Sec-Fetch-Site": "same-origin",
    "X-Fuzzlab-Client": "1",
}


def web_client(app) -> TestClient:
    """A TestClient for a fuzzlab web ``app`` that passes U6's same-origin gate
    by default. Tests that specifically exercise the gate (wrong Host, cross-
    origin Origin, missing X-Fuzzlab-Client, etc.) override headers/base_url
    per-request rather than using this helper."""
    client = TestClient(app, base_url=BASE_URL)
    client.headers.update(SAME_ORIGIN_HEADERS)
    return client
