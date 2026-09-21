"""Tests for the auditor's static-fetch migration onto the seam (Option A)."""

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.http import HttpClient
from fuzzlab.session.manager import SessionManager
from fuzzlab.tools.fetcher import ContentFetcher
from tests.test_session_manager import CookieLoginFetcher, _factory, _store


def test_static_fetch_authenticated_via_seam():
    captured = {}

    def transport(method, url, headers, body, timeout):
        captured["headers"] = dict(headers)
        captured["url"] = url
        return 200, {"Content-Type": "text/html"}, b"<html>secret admin page</html>"

    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    client = HttpClient(RequestBudget(50), ["localhost"], session=mgr, transport=transport)
    fetcher = ContentFetcher(engine="requests", seam_client=client, identity="admin")

    status, content_type, html, xhr = fetcher.fetch("http://localhost/profile.php")
    assert status == 200
    assert content_type == "text/html"
    assert "secret admin page" in html
    assert xhr == []
    # The auditor fetched the page authenticated.
    assert captured["headers"].get("Cookie") == "PHPSESSID=sess1"


def test_static_fetch_standalone_uses_raw_requests():
    fetcher = ContentFetcher(engine="requests")   # no seam -> raw requests path

    class R:
        status_code = 200
        text = "<html>anon</html>"
        headers = {"Content-Type": "text/html"}

    fetcher.session.get = lambda url, timeout=None: R()
    status, content_type, html, xhr = fetcher.fetch("http://localhost/index.php")
    assert status == 200 and "anon" in html and content_type == "text/html"
