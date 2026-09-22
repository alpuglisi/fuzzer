"""Tests for U6's control-plane hardening middleware (`fuzzlab/web/app.py`,
R-13 resolved in docs/UI_IMPLEMENTATION_PLAN.md §U6): a Host allow-list on
every request, an Origin/Sec-Fetch-Site/Referer CSRF gate on state-changing
methods (with `/api/*` additionally requiring the `X-Fuzzlab-Client` header),
and a fixed security-header set on every response.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import ControlPlaneHardening, create_app  # noqa: E402

from tests._web_client import BASE_URL, web_client  # noqa: E402


def _cfg(**over):
    return load_config(overrides={"target_base_url": "http://localhost", **over}, environ={})


# --- Host allow-list ---------------------------------------------------------

def test_matching_host_passes():
    r = web_client(create_app(_cfg())).get("/api/status")
    assert r.status_code == 200


def test_wrong_host_is_rejected():
    # TestClient's default base_url ("http://testserver") sends a Host header
    # that does not match the app's own bound address (from ASGI scope
    # ["server"]) — exactly the DNS-rebinding shape this gate exists for.
    r = TestClient(create_app(_cfg())).get("/api/status")
    assert r.status_code == 421


def test_wrong_host_rejected_even_for_a_get_that_would_otherwise_succeed():
    c = TestClient(create_app(_cfg()))
    assert c.get("/").status_code == 421
    assert c.get("/static/tokens.css").status_code == 421


# --- Origin / Sec-Fetch-Site / X-Fuzzlab-Client on POST/PUT/DELETE ----------

def test_same_origin_api_post_with_client_header_passes():
    c = web_client(create_app(_cfg(authorized=False)))
    r = c.post("/api/run/automatic")
    assert r.status_code == 403                      # reaches the route: not-authorized gate
    assert r.json()["error"].startswith("not authorized")


def test_cross_site_post_is_rejected():
    c = web_client(create_app(_cfg()))
    r = c.post("/api/run/automatic",
               headers={"Origin": "http://evil.example",
                        "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


def test_same_site_but_cross_origin_post_is_rejected():
    # The lab landmine (R-13): a sibling loopback port is *same-site* but must
    # still be rejected — only `same-origin` is accepted.
    c = web_client(create_app(_cfg()))
    r = c.post("/api/run/automatic",
               headers={"Origin": "http://127.0.0.1:9999",
                        "Sec-Fetch-Site": "same-site"})
    assert r.status_code == 403


def test_same_origin_but_wrong_origin_header_is_rejected():
    c = web_client(create_app(_cfg()))
    r = c.post("/api/run/automatic",
               headers={"Origin": "http://127.0.0.1:9999",
                        "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 403


def test_api_post_without_client_header_is_rejected():
    c = TestClient(create_app(_cfg()), base_url=BASE_URL)
    r = c.post("/api/run/automatic",
               headers={"Origin": BASE_URL, "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 403


def test_no_fetch_metadata_and_no_referer_is_rejected():
    c = TestClient(create_app(_cfg()), base_url=BASE_URL)
    r = c.post("/api/run/automatic", headers={"X-Fuzzlab-Client": "1"})
    assert r.status_code == 403


def test_referer_fallback_passes_for_a_plain_form_post():
    # A non-fetch client (plain HTML form submit, or a non-browser tool) that
    # sends no Sec-Fetch-Site at all still passes via the Referer fallback —
    # exercised here against a route outside /api/* (added on a bare
    # ControlPlaneHardening-wrapped app) so the /api/* client-header
    # requirement doesn't also gate it, since no such route exists in the real
    # app (every POST/PUT/DELETE route happens to live under /api/*).
    app = FastAPI()

    @app.post("/form-submit")
    def _submit():
        return {"ok": True}

    app.add_middleware(ControlPlaneHardening)
    c = TestClient(app, base_url=BASE_URL)
    r = c.post("/form-submit", headers={"Referer": BASE_URL + "/some-page"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_referer_fallback_rejects_a_foreign_referer():
    app = FastAPI()

    @app.post("/form-submit")
    def _submit():
        return {"ok": True}

    app.add_middleware(ControlPlaneHardening)
    c = TestClient(app, base_url=BASE_URL)
    r = c.post("/form-submit", headers={"Referer": "http://evil.example/"})
    assert r.status_code == 403


def test_delete_and_put_are_gated_too():
    app = create_app(_cfg())
    # missing X-Fuzzlab-Client -> rejected by the gate itself
    without_header = TestClient(app, base_url=BASE_URL)
    r = without_header.delete("/api/proxy/scope/0",
                              headers={"Origin": BASE_URL, "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 403
    # full same-origin headers -> passes the gate and reaches the route
    # (409: no in-process proxy configured for this app instance)
    r2 = web_client(app).delete("/api/proxy/scope/0")
    assert r2.status_code == 409


# --- authorized gate independence (cross-check from the U6 brief) ----------

def test_authorized_gate_is_not_flippable_from_the_request_body():
    c = web_client(create_app(_cfg(authorized=False)))
    r = c.post("/api/run/automatic", json={"authorized": True, "cfg": {"authorized": True}})
    assert r.status_code == 403


# --- security headers on every response -------------------------------------

_EXPECTED_HEADERS = {
    "content-security-policy": "default-src 'none'; script-src 'self'; "
        "style-src 'self'; connect-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "same-origin",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}


@pytest.mark.parametrize("path", ["/", "/proxy", "/results", "/api/status",
                                  "/static/tokens.css", "/does-not-exist"])
def test_security_headers_present_on_every_response(path):
    r = web_client(create_app(_cfg())).get(path)
    for name, value in _EXPECTED_HEADERS.items():
        assert r.headers.get(name) == value, f"{name!r} missing/wrong on {path}"


def test_security_headers_present_on_a_rejected_response_too():
    r = TestClient(create_app(_cfg())).get("/api/status")   # wrong Host -> 421
    assert r.status_code == 421
    for name, value in _EXPECTED_HEADERS.items():
        assert r.headers.get(name) == value


@pytest.mark.parametrize("path", ["/api/status", "/results"])
def test_cache_control_no_store_on_api_and_results(path):
    r = web_client(create_app(_cfg())).get(path)
    assert r.headers.get("cache-control") == "no-store"


def test_cache_control_not_forced_on_static_assets():
    r = web_client(create_app(_cfg())).get("/static/tokens.css")
    assert r.headers.get("cache-control") != "no-store"
