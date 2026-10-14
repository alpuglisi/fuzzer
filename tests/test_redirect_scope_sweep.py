"""BUG-0123 PA-0002 sweep: two non-browser senders followed redirects unchecked.

* ``SessionManager._post_credentials`` checked only the first ``Location`` after the
  login POST, then let the HTTP client follow every later hop anywhere.
* labgen's ``default_http_runner`` (the identifier-SQLi oracle) let ``requests`` follow
  any redirect off the loopback lab, and an absolute ``endpoint_path`` replaced the
  checked base URL.

Each hop is now checked where it is fetched (PA-0123(1)).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.session.manager import FetchResponse, SessionAuthError, SessionManager

FORM = ('<form method=post action="{action}"><input name=user>'
        '<input type=password name=pw></form>')


class _Cred:
    username, password = "alice", "S3CRET"


class _Creds:
    def require(self, host, identity):
        return _Cred()


class _Web:
    """A fetcher that never follows redirects: ``routes`` maps a URL to a response."""

    def __init__(self, routes, post):
        self.routes, self.log, self.post_resp = routes, [], post

    def get(self, url, headers=None, allow_redirects=True):
        assert allow_redirects is False          # no hop is followed unchecked
        self.log.append(("GET", url))
        return self.routes.get(url, FetchResponse(200, {}, "<p>home</p>"))

    def post(self, url, data=None, headers=None, allow_redirects=True):
        self.log.append(("POST", url))
        return self.post_resp

    def cookies(self):
        return {"s": "1"}


def _302(to):
    return FetchResponse(302, {"Location": to, "Set-Cookie": "s=1"}, "")


def _login(web):
    mgr = SessionManager(_Creds(), scope_hosts=["lab.example"], fetch_factory=lambda: web)
    try:
        return mgr.ensure("lab.example", "user", "https://lab.example/")
    except SessionAuthError:
        return None


def _routes(**extra):
    routes = {"https://lab.example/login":
              FetchResponse(200, {}, FORM.format(action="/login"))}
    routes.update(extra)
    return routes


def test_the_post_login_redirect_chain_is_walked_by_hand():
    web = _Web(_routes(**{"https://lab.example/next": _302("/portal")}),
               post=_302("/next"))
    _login(web)
    log = web.log
    i = log.index(("POST", "https://lab.example/login"))
    # each hop fetched without redirects (_Web asserts it), in order, after the POST
    assert log[i + 1:i + 3] == [("GET", "https://lab.example/next"),
                                ("GET", "https://lab.example/portal")]


# Another port on an in-scope host stays allowed here: the session's scope is the
# operator's ``scope_hosts`` (FR-SESS-12), host-level by design, a stated exception
# to PA-0123(2) recorded in BUG-0123.
@pytest.mark.parametrize("hop", ["https://attacker.example/x",
                                 "http://lab.example/x"])                # a downgrade
def test_a_later_post_login_hop_out_of_scope_is_never_fetched(hop):
    web = _Web(_routes(**{"https://lab.example/next": _302(hop)}), post=_302("/next"))
    _login(web)
    assert ("GET", hop) not in web.log
    assert ("GET", "https://lab.example/next") in web.log      # the checked first hop


def test_a_post_login_redirect_to_a_destructive_url_is_never_fetched():
    web = _Web(_routes(), post=_302("/logout.php"))
    _login(web)
    assert ("GET", "https://lab.example/logout.php") not in web.log


# --- labgen: the identifier-SQLi oracle's runner ---------------------------------------
def _server(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_the_oracle_runner_never_follows_a_redirect_off_its_origin():
    from fuzzlab.labgen.identifier_sqli_oracle import default_http_runner
    hits = []

    class Other(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    other = _server(Other)
    target = f"http://127.0.0.1:{other.server_address[1]}"

    class Lab(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.startswith("/same"):
                body = b"landed"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(302)
            self.send_header("Location", "/same" if self.path.startswith("/in")
                             else f"{target}/leak")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    lab = _server(Lab)
    base = f"http://127.0.0.1:{lab.server_address[1]}"
    try:
        same = default_http_runner(f"{base}/in", {}, None, 5)
        off = default_http_runner(f"{base}/out", {}, None, 5)
    finally:
        lab.shutdown()
        other.shutdown()
    assert (same.status_code, same.body) == (200, "landed")    # same-origin: followed
    assert off.status_code == 302 and hits == []               # off-origin: never


def test_an_absolute_endpoint_path_cannot_replace_the_checked_base():
    from fuzzlab.labgen.identifier_sqli_oracle import (IdentifierSqliOracleRequest,
                                                       _build_url)
    req = IdentifierSqliOracleRequest(target_base_url="http://127.0.0.1:8000",
                                      endpoint_path="http://203.0.113.9/x",
                                      param_name="sort", column_a="a", column_b="b")
    with pytest.raises(ValueError, match="origin"):
        _build_url(req, "a")
