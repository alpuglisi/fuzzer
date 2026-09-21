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

    def request(self, method, url, params=None, data=None, timeout=None):
        self.calls.append({"method": method, "url": url, "params": params, "data": data})

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
