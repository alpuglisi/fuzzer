"""Tests for the oracle probe senders (authenticated + standalone)."""

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.http import HttpClient
from fuzzlab.oracle.probe import Probe
from fuzzlab.session.manager import SessionManager
from fuzzlab.tools.probesender import RequestsProbeSender, SeamProbeSender
from tests.test_session_manager import CookieLoginFetcher, _factory, _store


def test_requests_probe_sender_returns_probe():
    class FakeSession:
        def get(self, url, params=None, timeout=None):
            class R:
                status_code = 200
                text = "<html>ok</html>"
                headers = {"Content-Type": "text/html"}
            return R()
    p = RequestsProbeSender(session=FakeSession()).send("http://localhost/x", "id", "1'")
    assert isinstance(p, Probe)
    assert p.status == 200 and "ok" in p.text and p.elapsed >= 0


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
