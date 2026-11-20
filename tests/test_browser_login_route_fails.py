"""BUG-0670 caller sweep (CC-SESS-0640): a login route that fails to load is one
candidate gone, never the end of the browser login's route search.

Since BUG-0670 an empty HTTP error answer fails a guarded navigation onto the browser's
error page on every binary (as the full Chromium always did). The browser login's route
search (`browserlogin._drive`) let that raise out of its loop, so a stale login link
answering an empty 404 hid the next route, which holds the form. Now the failed route
is ended by `end_failed_load` and noted, and the search goes on.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.core.net import require_loopback


class _App:
    """``/`` links ``/signin`` (404, empty body) before ``/login`` (the form, whose
    POST sets ``sid``)."""

    def __init__(self):
        require_loopback("127.0.0.1")              # PA-0130
        self.posts: list[str] = []
        app = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body=b"", headers=()):
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - http.server API
                path = self.path.split("?", 1)[0]
                html = [("Content-Type", "text/html")]
                if path == "/signin":
                    return self._send(404)
                if path == "/login":
                    return self._send(200, b"<html><body><form method='post' "
                                           b"action='/login'><input name='user'>"
                                           b"<input type='password' name='pw'>"
                                           b"<input type='submit' value='Log in'>"
                                           b"</form></body></html>", html)
                return self._send(200, b"<html><body><a href='/signin'>Sign in</a> "
                                       b"<a href='/login'>Log in</a></body></html>", html)

            def do_POST(self):  # noqa: N802 - http.server API
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                app.posts.append(self.path)
                return self._send(200, b"<html><body>welcome</body></html>",
                                  [("Content-Type", "text/html"),
                                   ("Set-Cookie", "sid=abc; Path=/")])

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def app():
    a = _App()
    yield a
    a.close()


class _Cred:
    username, password = "alice", "Pw-route-0670!"


def test_a_login_route_that_fails_to_load_does_not_end_the_search(app):
    from tests._browser import require_modules
    require_modules(module_level=False)

    from fuzzlab.session import browserlogin
    obs = browserlogin.run(lambda *a, **k: True, app.base, _Cred(), timeout_ms=10000)
    assert app.posts == ["/login"]
    assert obs.login_url.endswith("/login") and obs.cookies.get("sid") == "abc"
