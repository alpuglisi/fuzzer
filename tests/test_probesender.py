"""Tests for the oracle probe senders (authenticated + standalone)."""

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.http import HttpClient
from fuzzlab.oracle.probe import Probe
from fuzzlab.session.manager import SessionManager
from fuzzlab.tools.probesender import RequestsProbeSender, SeamProbeSender
from tests.test_session_manager import CookieLoginFetcher, _factory, _store


class _FakeSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None, timeout=None, headers=None,
                allow_redirects=None):
        self.calls.append({"method": method, "url": url, "params": params,
                           "data": data, "headers": headers,
                           "allow_redirects": allow_redirects})

        class R:
            status_code = 200
            text = "<html>ok</html>"
            headers = {"Content-Type": "text/html"}
        return R()


def test_requests_probe_sender_get_query():
    session = _FakeSession()
    p = RequestsProbeSender(session=session).send("http://localhost/x", "id", "1'")
    assert isinstance(p, Probe) and p.status == 200 and "ok" in p.text and p.elapsed >= 0
    assert session.calls[0]["method"] == "GET"


def test_requests_probe_sender_never_follows_redirects():
    """BUG-0042/PA-0044: this sender's own `Probe` is what a
    `ConfirmationStrategy` (e.g. `OpenRedirectStrategy`) inspects directly
    -- silently following a redirect would report the wrong response (and,
    against a real target, a self-referencing `Location` value crashes
    outright with `requests.exceptions.TooManyRedirects`). Every call must
    pass `allow_redirects=False` explicitly, matching `fuzzlab.core.http`'s
    own `SeamProbeSender` path."""
    session = _FakeSession()
    RequestsProbeSender(session=session).send("http://localhost/x", "id", "1'")
    assert session.calls[0]["allow_redirects"] is False
    assert session.calls[0]["params"] == {"id": "1'"} and session.calls[0]["data"] is None


def test_requests_probe_sender_post_body():
    session = _FakeSession()
    RequestsProbeSender(session=session).send(
        "http://localhost/login.php", "username", "x' OR 1=1--",
        method="POST", location="body")
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["data"] == {"username": "x' OR 1=1--"} and call["params"] is None


def test_seam_probe_sender_authenticates_and_returns_full_response():
    captured = {}

    def transport(method, url, headers, body, timeout):
        captured["headers"] = dict(headers)
        captured["url"] = url
        return 200, {"Content-Type": "text/html"}, b"<html>secret</html>"

    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    client = HttpClient(RequestBudget(50), ["localhost"], session=mgr, transport=transport)
    p = SeamProbeSender(client, "admin").send("http://localhost/p.php", "id", "1 AND 1=1")
    assert p.status == 200 and "secret" in p.text
    assert captured["url"] == "http://localhost/p.php?id=1+AND+1%3D1"
    assert captured["headers"].get("Cookie") == "PHPSESSID=sess1"   # authenticated


def test_requests_probe_sender_header_location():
    # CC-FUZZ-0028/FR-FUZZ-15: a header-carried candidate sends `value` as a
    # request header named the literal `param`, no query/body change.
    session = _FakeSession()
    RequestsProbeSender(session=session).send(
        "http://localhost/generated/labgen-go-0001", "X-Signature-256", "deadbeef",
        method="POST", location="header")
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["headers"] == {"X-Signature-256": "deadbeef"}
    assert call["params"] is None and call["data"] is None


def test_requests_probe_sender_whole_body_json():
    # CC-FUZZ-0028/FR-FUZZ-15: a whole-body point with a declared content type
    # sends `value` as the raw body, not form-encoded `{param: value}`.
    session = _FakeSession()
    RequestsProbeSender(session=session).send(
        "http://localhost/api/playback/resume", "body", '["java.util.HashMap",{}]',
        method="POST", location="body", content_type="application/json")
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["data"] == b'["java.util.HashMap",{}]'
    assert call["headers"] == {"Content-Type": "application/json"}
    assert call["params"] is None


def test_requests_probe_sender_body_without_content_type_stays_form_encoded():
    # No declared content type (e.g. TrackerNest's XXE/insecure-deserialization
    # body points) -- unaffected, still the pre-existing form-encoded behavior.
    session = _FakeSession()
    RequestsProbeSender(session=session).send(
        "http://localhost/issues/import", "body", "<x/>", method="POST", location="body")
    call = session.calls[0]
    assert call["data"] == {"body": "<x/>"}


def test_seam_probe_sender_header_location():
    captured = {}

    def transport(method, url, headers, body, timeout):
        captured.update(method=method, url=url, body=body, headers=dict(headers))
        return 200, {"Content-Type": "text/html"}, b"<html>ok</html>"

    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    client = HttpClient(RequestBudget(50), ["localhost"], session=mgr, transport=transport)
    SeamProbeSender(client, "admin").send(
        "http://localhost/generated/labgen-go-0001", "X-Signature-256", "deadbeef",
        method="POST", location="header")
    assert captured["method"] == "POST"
    assert captured["url"] == "http://localhost/generated/labgen-go-0001"
    assert captured["headers"].get("X-Signature-256") == "deadbeef"
    assert captured["body"] is None


def test_seam_probe_sender_whole_body_json():
    captured = {}

    def transport(method, url, headers, body, timeout):
        captured.update(method=method, url=url, body=body, headers=dict(headers))
        return 200, {"Content-Type": "application/json"}, b'{"status":"ok"}'

    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    client = HttpClient(RequestBudget(50), ["localhost"], session=mgr, transport=transport)
    SeamProbeSender(client, "admin").send(
        "http://localhost/api/playback/resume", "body", '["java.util.HashMap",{}]',
        method="POST", location="body", content_type="application/json")
    assert captured["body"] == b'["java.util.HashMap",{}]'
    assert captured["headers"].get("Content-Type") == "application/json"


def test_seam_probe_sender_post_body():
    captured = {}

    def transport(method, url, headers, body, timeout):
        captured.update(method=method, url=url, body=body, headers=dict(headers))
        return 200, {"Content-Type": "text/html"}, b"<html>ok</html>"

    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    client = HttpClient(RequestBudget(50), ["localhost"], session=mgr, transport=transport)
    SeamProbeSender(client, "admin").send("http://localhost/login.php", "username",
                                          "x' OR 1=1--", method="POST", location="body")
    assert captured["method"] == "POST"
    assert captured["url"] == "http://localhost/login.php"          # no query string
    assert captured["body"] == b"username=x%27+OR+1%3D1--"          # form-encoded body
    assert captured["headers"].get("Cookie") == "PHPSESSID=sess1"   # authenticated
