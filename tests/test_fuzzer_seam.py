"""Tests for the fuzzer's migration onto the core HTTP seam (Option A)."""

from fuzzlab.core.budget import RequestBudget
from fuzzlab.core.http import HttpClient
from fuzzlab.core.urls import place_query_param
from fuzzlab.session.manager import SessionManager
from fuzzlab.tools.blind_sqli_fuzzer import RequestsSender, SeamSender
from tests.test_session_manager import CookieLoginFetcher, _factory, _store


def test_place_query_param():
    # The fuzzer's query placement is the one owner (SP-42, FR-FUZZ-64, BUG-0531):
    # an absent name is appended, a present one is replaced in place, the rest kept.
    assert place_query_param("http://h/p.php", "id", "1") == "http://h/p.php?id=1"
    out = place_query_param("http://h/p.php?a=b", "id", "1' OR 1=1")
    assert out == "http://h/p.php?a=b&id=1%27+OR+1%3D1"
    out = place_query_param("http://h/p.php?id=7&a=b", "id", "1' OR 1=1")
    assert out == "http://h/p.php?id=1%27+OR+1%3D1&a=b"


class FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, params=None, timeout=None, allow_redirects=None):
        self.calls.append((url, params, timeout, allow_redirects))

        class R:
            status_code = 200
            text = "<html>ok</html>"
        return R()


def test_requests_sender_unchanged_standalone_behavior():
    sess = FakeSession()
    sender = RequestsSender(sess)
    latency, status, size = sender.get("http://localhost/p.php", "id", "1", 15)
    assert status == 200 and size == len("<html>ok</html>") and latency >= 0
    # BUG-0044/PA-0046: never silently follow a redirect -- a followed hop
    # would add an unrelated round trip into this timing-sensitive
    # measurement.
    # BUG-0531: the value is placed in the URL by `place_query_param`, never handed to
    # requests' `params=` (which appends a second occurrence).
    assert sess.calls == [("http://localhost/p.php?id=1", None, 15, False)]


def test_seam_sender_authenticates_and_measures():
    captured = {}

    def transport(method, url, headers, body, timeout):
        captured["url"] = url
        captured["headers"] = dict(headers)
        return 200, {"Content-Type": "text/html"}, b"<html>welcome admin</html>"

    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    client = HttpClient(RequestBudget(50), ["localhost"], session=mgr, transport=transport)
    sender = SeamSender(client, "admin")

    latency, status, size = sender.get("http://localhost/product.php", "id",
                                       "1 AND SLEEP(5)", 15)
    assert status == 200
    assert size == len(b"<html>welcome admin</html>")
    assert latency >= 0
    # The fuzzed value reached the target as a query param on the fuzzed URL...
    assert captured["url"] == "http://localhost/product.php?id=1+AND+SLEEP%285%29"
    # ...and the request was authenticated by the session manager.
    assert captured["headers"].get("Cookie") == "PHPSESSID=sess1"
