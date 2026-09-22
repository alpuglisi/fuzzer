"""Tests for the control-plane hardening middleware (component #12, CC-UI-0026, R-13).

Two independent gates guard every request against a hostile web page driving this
loopback control panel: (a) a Host allow-list on every request (DNS-rebinding), and
(b) on state-changing methods, Origin == allow-list + Sec-Fetch-Site == same-origin
(same-site rejected too), a custom X-Fuzzlab-Client header on /api/*, and a Referer
fallback for clients that send no Fetch Metadata. See ``fuzzlab.web.app`` for the
implementation and rationale (``SecurityGateMiddleware``).
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from tests._webclient import WEB_BASE_URL, web_client  # noqa: E402

# A raw client with NO default headers, so each test controls exactly what a forged or
# legitimate request would send.
_ATTACKER_ORIGIN = "http://evil.example"
_SAME_SITE_SIBLING_PORT = "http://127.0.0.1:9999"     # same-site, different port -- the
                                                       # R-13 "same-site landmine": this is
                                                       # exactly where the lab itself lives.


def _cfg():
    return load_config(overrides={"target_base_url": "http://localhost"}, environ={})


def _bare_client():
    return TestClient(create_app(_cfg()), base_url=WEB_BASE_URL)


# --- gate (a): Host allow-list, every request -------------------------------

def test_wrong_host_rejected_on_a_get():
    c = _bare_client()
    r = c.get("/", headers={"Host": "attacker.example"})
    assert r.status_code == 421


def test_dns_rebinding_wrong_host_but_perfect_fetch_metadata_still_rejected():
    # Simulates DNS rebinding: the attacker page's origin now resolves to our loopback
    # address, so the browser happily sends a matching Origin + same-origin Sec-Fetch-
    # Site -- but the Host header the server actually receives is the rebound name.
    # Only the Host allow-list (gate a) catches this.
    c = _bare_client()
    r = c.post(
        "/api/launch/dry-run",
        json={"command": "nope"},
        headers={
            "Host": "rebound.attacker.example",
            "Origin": WEB_BASE_URL,
            "Sec-Fetch-Site": "same-origin",
            "X-Fuzzlab-Client": "1",
        },
    )
    assert r.status_code == 421


def test_correct_host_passes_the_host_gate():
    c = web_client(create_app(_cfg()))
    assert c.get("/").status_code == 200


# --- gate (b): state-changing methods ---------------------------------------

def test_cross_origin_post_rejected_classic_csrf():
    # Classic CSRF: correct Host (it's the real server), but the request comes from a
    # forged cross-origin page, so Origin and Sec-Fetch-Site both give it away.
    c = _bare_client()
    r = c.post(
        "/api/launch/dry-run",
        json={"command": "nope"},
        headers={
            "Origin": _ATTACKER_ORIGIN,
            "Sec-Fetch-Site": "cross-site",
            "X-Fuzzlab-Client": "1",
        },
    )
    assert r.status_code == 403


def test_same_site_sibling_port_post_rejected():
    # The R-13 "same-site landmine": the deliberately-vulnerable lab is same-site with
    # this panel (same registrable domain, different port). same-site must NOT be
    # accepted -- only same-origin.
    c = _bare_client()
    r = c.post(
        "/api/launch/dry-run",
        json={"command": "nope"},
        headers={
            "Origin": _SAME_SITE_SIBLING_PORT,
            "Sec-Fetch-Site": "same-site",
            "X-Fuzzlab-Client": "1",
        },
    )
    assert r.status_code == 403


def test_same_origin_but_missing_custom_header_rejected_on_api():
    # A cross-origin fetch() with a JSON content-type still needs a CORS preflight for
    # the custom header; without it (e.g. a "simple request" a forged page could send
    # without preflight at all if we didn't require this) the /api/* surface rejects.
    c = _bare_client()
    r = c.post(
        "/api/launch/dry-run",
        json={"command": "nope"},
        headers={"Origin": WEB_BASE_URL, "Sec-Fetch-Site": "same-origin"},
    )
    assert r.status_code == 403


def test_same_origin_with_custom_header_passes_and_reaches_the_handler():
    c = _bare_client()
    r = c.post(
        "/api/launch/dry-run",
        json={"command": "nope"},
        headers={
            "Origin": WEB_BASE_URL,
            "Sec-Fetch-Site": "same-origin",
            "X-Fuzzlab-Client": "1",
        },
    )
    # The gate let it through; the handler itself now rejects the unknown command --
    # proof the request reached application logic, not just "any non-403".
    assert r.status_code == 400


def test_no_fetch_metadata_falls_back_to_origin():
    # A non-browser client (e.g. a script) sends no Sec-Fetch-Site at all; Origin alone
    # (when present and allow-listed) is enough.
    c = _bare_client()
    r = c.post("/api/launch/dry-run", json={"command": "nope"},
              headers={"Origin": WEB_BASE_URL, "X-Fuzzlab-Client": "1"})
    assert r.status_code == 400


def test_no_fetch_metadata_and_no_origin_falls_back_to_referer():
    c = _bare_client()
    r = c.post(
        "/api/launch/dry-run",
        json={"command": "nope"},
        headers={"Referer": WEB_BASE_URL + "/", "X-Fuzzlab-Client": "1"},
    )
    assert r.status_code == 400


def test_no_fetch_metadata_untrusted_referer_rejected():
    c = _bare_client()
    r = c.post(
        "/api/launch/dry-run",
        json={"command": "nope"},
        headers={"Referer": _ATTACKER_ORIGIN + "/", "X-Fuzzlab-Client": "1"},
    )
    assert r.status_code == 403


def test_form_post_same_origin_without_custom_header_passes():
    # The panel's own no-JS "Run automatic" <form> can never set a custom header --
    # form-encoded /api/* POSTs are exempt from the custom-header check and rely on
    # Origin + Sec-Fetch-Site alone (which a forged cross-site <form> auto-submit still
    # fails, since it can't fake a same-origin Sec-Fetch-Site).
    c = _bare_client()
    r = c.post(
        "/api/run/automatic",
        data={"unused": "1"},
        headers={"Origin": WEB_BASE_URL, "Sec-Fetch-Site": "same-origin"},
    )
    # Reaches the handler (which then 403s for its own, separate reason: not
    # authorized) rather than being blocked by the security gate for a missing header.
    assert r.status_code == 403
    assert "authorized" in r.json()["error"]


def test_form_post_cross_site_still_rejected_by_the_gate():
    c = _bare_client()
    r = c.post(
        "/api/run/automatic",
        data={"unused": "1"},
        headers={"Origin": _SAME_SITE_SIBLING_PORT, "Sec-Fetch-Site": "same-site"},
    )
    assert r.status_code == 403
    # The gate's own denial body, not the route's JSON error.
    assert "rejected" in r.text


def test_get_never_needs_origin_or_custom_header():
    c = _bare_client()
    assert c.get("/api/status").status_code == 200


# --- response headers --------------------------------------------------------

def test_security_headers_present_on_success():
    r = web_client(create_app(_cfg())).get("/")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "same-origin"
    assert r.headers["cross-origin-opener-policy"] == "same-origin"
    assert r.headers["cross-origin-resource-policy"] == "same-origin"
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert r.headers["cache-control"] == "no-store"


def test_security_headers_present_on_denial_too():
    c = _bare_client()
    r = c.get("/", headers={"Host": "attacker.example"})
    assert r.status_code == 421
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_static_assets_are_not_marked_no_store():
    # Cache-Control: no-store applies to API/results, not the static bundle.
    r = web_client(create_app(_cfg())).get("/static/css/shell.css")
    assert r.status_code == 200
    assert r.headers.get("cache-control") != "no-store"
