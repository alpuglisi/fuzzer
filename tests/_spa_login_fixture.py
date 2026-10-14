"""A fake single-page app with a JSON login, for FR-SESS-19 / FR-CRAWL-14 tests.

Juice Shop's shape, served by a test-started loopback ``ThreadingHTTPServer`` (port 0):
a hash-routed shell (``/#/login``), an Angular-like route table in ``/app.js``, a login
view whose button POSTs JSON to ``/rest/user/login``, which answers
``{"authentication": {"token": <JWT>}}``; the app then keeps the token in
``localStorage`` and a ``token`` cookie and sends it as ``Authorization: Bearer`` on
its own requests (every app request also carries ``X-From-App: 1``). ``/api/me`` is
protected (401 without a live token); ``/rest/user/whoami`` answers 200 either way,
with a different body. Every request received is recorded. Nothing talks to any other
host: a "leak" goes to a second test-started loopback server (`Recorder`).

``variant`` selects the login view: ``ok``; ``other`` (the login posts to another
port) and ``other_sha`` (it posts sha256(password) there); ``users`` (a "Log in"
form posting to ``/api/Users``); ``signup`` (a "Sign up" button posting to
``/rest/join``); ``captcha`` (an extra text field); ``mixed`` (a register form and a
change-password form before the real login).
"""

from __future__ import annotations

import base64
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER = "alice@juice.invalid"
#: the dashboard text only an authenticated app shows
PROTECTED = "PROTECTED-DASHBOARD-CONTENT"

_APP_JS = r"""
const routes = [{path:'login', component: 'Login'}, {path:'search'}, {path:'dashboard'},
                {path:'notes'}, {path:'feedback'}, {path:'contact'}];
const CFG = __CFG__;
const P = CFG.prefix;
const tok = () => localStorage.getItem('token');
const api = (url, opt) => { opt = opt || {};
  opt.headers = Object.assign({'X-From-App': '1'}, opt.headers || {});
  if (tok()) opt.headers['Authorization'] = 'Bearer ' + tok();
  return fetch(url, opt); };
const post = (url, body) => api(url, {method: 'POST', headers: {'Content-Type':
  'application/json'}, body: JSON.stringify(body)}).catch(() => {});
if (CFG.poll) { let polls = 0;
  setInterval(() => { if (++polls <= 400) api(P + 'rest/ping').catch(() => {}); }, 50); }
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const loginDiv = (label, extra) => "<div id='lf'><input id='email' type='text' " +
  "formcontrolname='email'><input id='password' type='password'>" + (extra || '') +
  "<input type='checkbox' id='rememberMe'><button id='loginButton' aria-label='" +
  label + "'><mat-icon>exit_to_app</mat-icon> " + label + "</button></div>";
const LOGIN_VIEWS = {
  ok: loginDiv('Log in'), other: loginDiv('Log in'), other_sha: loginDiv('Log in'),
  users: loginDiv('Log in'), signup: loginDiv('Sign up'),
  captcha: loginDiv('Log in', "<input id='captcha' type='text'>"),
  mixed: "<form id='reg'><input name='email' type='email'><input name='password' " +
    "type='password'><input name='passwordRepeat' type='password'>" +
    "<button type='submit'>Register</button></form>" +
    "<form id='chg'><input name='current' type='password'><input name='new' " +
    "type='password'><input name='repeat' type='password'><button type='submit'>" +
    "Change</button></form>" + loginDiv('Log in'),
};
const TARGETS = {users: P + 'api/Users', signup: P + 'rest/join',
  other: 'http://127.0.0.1:' + CFG.other + '/rest/user/login',
  other_sha: 'http://127.0.0.1:' + CFG.other + '/rest/user/login'};
async function doLogin() {
  const email = document.getElementById('email').value;
  let pass = document.getElementById('password').value;
  if (CFG.variant === 'other_sha')
    pass = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pass)));
  const r = await fetch(TARGETS[CFG.variant] || P + 'rest/user/login', {method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-From-App': '1'},
    body: JSON.stringify({email: email, password: pass})}).catch(() => null);
  if (!r || r.status !== 200) return;
  const j = await r.json();
  localStorage.setItem('token', j.authentication.token);
  document.cookie = 'token=' + j.authentication.token + '; path=/';
  location.hash = '#/search';
}
const views = {
  '': () => '<p>home</p>',
  'login': () => LOGIN_VIEWS[CFG.variant],
  'search': () => { api(P + 'rest/user/whoami').catch(() => {});
    api(P + 'api/me').catch(() => {}); api(P + 'rest/products').catch(() => {});
    return '<p>search</p>'; },
  'dashboard': () => { api(P + 'api/me').then(r => r.json()).then(j => {
      document.getElementById('me').textContent = j.secret || 'anonymous'; })
      .catch(() => {});
    return "<p id='me'>loading</p>"; },
  'notes': () => "<div><input name='note'><button id='nb'>Save</button></div>",
  'feedback': () => "<div><input name='comment'><button id='fb'>Send</button></div>",
  'contact': () => "<div><input name='topic'><button id='cb'>Submit</button></div>",
};
function render() {
  const name = location.hash.replace(/^#!?\/?/, '').split('?')[0];
  document.getElementById('app').innerHTML = (views[name] || (() => '<p>?</p>'))();
  const b = document.getElementById('loginButton'); if (b) b.onclick = doLogin;
  const nb = document.getElementById('nb'); if (nb) nb.onclick = () => {
    post(P + 'api/notes', {note: 'x'});
    if (CFG.clear_ls) localStorage.removeItem('token'); };
  const fb = document.getElementById('fb'); if (fb) fb.onclick = () =>
    post(P + 'api/feedback', {comment: 'x'});
  const cb = document.getElementById('cb'); if (cb) cb.onclick = () =>
    post(P + 'api/contact', {topic: 'x'});
  for (const f of document.querySelectorAll('form')) f.onsubmit = e => {
    e.preventDefault();
    post(P + (f.id === 'reg' ? 'api/Users' : 'rest/user/change-password'), {x: 1}); };
}
window.addEventListener('hashchange', render);
render();
"""

_INDEX = ("<!doctype html><html><head><title>juice</title>"
          "<script src='app.js' defer></script></head><body>"
          "<nav><a href='#/dashboard'>Dashboard</a></nav><div id='app'></div>"
          "</body></html>")


def _jwt(jti: str) -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'HS256'})}.{seg({'exp': 9999999999, 'jti': jti})}.sig"


class LoginSpa:
    """The recording fake SPA. ``requests`` holds ``(method, path, headers, body)``, the
    header names lower-cased."""

    def __init__(self, password: str, *, variant: str = "ok", other_port: int = 9,
                 clear_ls: bool = False, revoke_on_feedback: bool = False,
                 poll: bool = False, probe_delay: float = 0.0, prefix: str = "/"):
        self.password = password
        self.variant = variant
        self.other_port = other_port
        self.clear_ls = clear_ls
        self.revoke_on_feedback = revoke_on_feedback
        self.poll = poll
        self.probe_delay = probe_delay
        #: the app's mount point (PA-0113: an app under a sub-path, ``/app/``)
        self.prefix = prefix
        self.requests: list[tuple[str, str, dict, bytes]] = []
        self.tokens: set[str] = set()
        self.revoked: set[str] = set()
        self._lock = threading.Lock()
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with lab._lock:
                    lab.requests.append((self.command, self.path,
                                         {k.lower(): v for k, v in self.headers.items()},
                                         body))
                lab.route(self, body)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle  # noqa: N815

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    # -- the app ---------------------------------------------------------------------
    def script(self) -> str:
        cfg = {"variant": self.variant, "other": self.other_port,
               "clear_ls": self.clear_ls, "poll": self.poll, "prefix": self.prefix}
        return _APP_JS.replace("__CFG__", json.dumps(cfg))

    def live(self, headers) -> bool:
        auth = headers.get("Authorization") or ""
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
        return token in self.tokens and token not in self.revoked

    def route(self, h, body: bytes) -> None:
        path = h.path.split("?", 1)[0]
        if self.prefix != "/":
            if not path.startswith(self.prefix):
                return _send(h, 404, "text/plain", b"no")
            path = "/" + path[len(self.prefix):]
        if path == "/":
            return _send(h, 200, "text/html", _INDEX.encode())
        if path == "/app.js":
            return _send(h, 200, "application/javascript", self.script().encode())
        if path == "/rest/user/login" and h.command == "POST":
            try:
                doc = json.loads(body or b"{}")
            except ValueError:
                doc = {}
            if doc.get("email") == USER and doc.get("password") == self.password:
                token = _jwt(uuid.uuid4().hex)
                self.tokens.add(token)
                return _send(h, 200, "application/json", json.dumps(
                    {"authentication": {"token": token, "bid": 1, "umail": USER}}).encode())
            return _send(h, 401, "application/json", b'{"error":"Invalid email or password."}')
        if path == "/api/me":
            if self.probe_delay and not h.headers.get("X-From-App"):
                time.sleep(self.probe_delay)
            if self.live(h.headers):
                return _send(h, 200, "application/json",
                             json.dumps({"email": USER, "secret": PROTECTED}).encode())
            return _send(h, 401, "application/json", b'{"error":"Unauthorized"}')
        if path == "/rest/user/whoami":
            user = {"email": USER} if self.live(h.headers) else {}
            return _send(h, 200, "application/json", json.dumps({"user": user}).encode())
        if path == "/api/feedback" and self.revoke_on_feedback:
            self.revoked |= set(self.tokens)
        if path.startswith(("/rest/", "/api/")):
            status = 201 if h.command == "POST" and path == "/api/Users" else 200
            return _send(h, status, "application/json", b'{"ok":true}')
        return _send(h, 404, "text/plain", b"no")

    # -- inspection --------------------------------------------------------------------
    @property
    def base(self) -> str:
        """The app's URL (its mount point included)."""
        return f"http://127.0.0.1:{self.server.server_address[1]}{self.prefix}"

    def seen(self, method: str | None = None, prefix: str = "") -> list:
        """Requests received, by method and path prefix (relative to the mount point)."""
        mount = self.prefix.rstrip("/")
        with self._lock:
            return [r for r in self.requests if (method is None or r[0] == method)
                    and r[1].startswith(mount + prefix)]

    def revoke_all(self) -> None:
        self.revoked |= set(self.tokens)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _send(h, status: int, ctype: str, data: bytes) -> None:
    h.send_response(status)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(data)))
    h.end_headers()
    h.wfile.write(data)
