"""A fake single-page app for the forms-phase-3 tests (FR-CRAWL-12/13).

Served by a test-started loopback ``ThreadingHTTPServer``; every request it receives is
recorded (method, path, the Cookie and Authorization headers, body). Nothing here talks
to any other host.

* **hash mode** (``HashSpa``): an Angular-style route table in ``/main.js`` (``{path:'x'``),
  a hash router, and one view per route. Views exercise each FR-CRAWL-13 rule: a login
  form whose failed login clears the ``token`` cookie, a profile form that clears it on
  submit, a contact form, transaction / upload / 2FA / registration forms, an
  ``Archive`` button that sends a DELETE, a route whose load sends a DELETE, and a
  footer form shown on every view (one submission per signature). Destructive and
  parameterised routes exist and must never render.
* **history mode** (``HistorySpa``): Vue- and React-style declarations in ``/app.js``,
  every path served the app shell.
"""

from __future__ import annotations

import glob
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: The identifier-like value the app puts in its requests (blanked when stored).
IDENT = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
#: Secrets the app sends that must never reach the spider DB.
SECRETS = ("SECRETPASSWORDVALUE", "SECRETAUTHTOKEN", "SECRETBEARER", "SOCKSECRET",
           "SECRETAPIKEY")

_FOOTER = ("<div class='q'><input name='question'><button>Ask</button></div>")

_HASH_JS = r"""
const routes = [
  {path:'login', component: 'Login'},
  {path:'about', component: 'About'},
  {path:'profile', component: 'Profile'},
  {path:'contact', component: 'Contact'},
  {path:'checkout', component: 'Checkout'},
  {path:'upload', component: 'Upload'},
  {path:'2fa', component: 'TwoFa'},
  {path:'register', component: 'Register'},
  {path:'archive', component: 'Archive'},
  {path:'items', component: 'Items'},
  {path:'logout', component: 'Logout'},
  {path:'delete-account', component: 'Gone'},
  {path:'product/:id', component: 'Product'},
  {path:'**', component: 'NotFound'}
];
// not routes: socket.io's own client option and a protocol-relative URL (never
// counted as found, never visited)
const io = {path:'/socket.io', transports: ['polling']};
const cdn = {path:'//cdn.example/app'};
const OTHER = __OTHER__;
const IDENT = '__IDENT__';
const json = (url, method, body, headers) => fetch(url, {method: method,
  headers: Object.assign({'Content-Type': 'application/json'}, headers || {}),
  body: JSON.stringify(body)}).catch(() => {});
const mark = code => fetch('/rest/marker/' + code).catch(() => {});
const clearToken = () => { document.cookie = 'token=; Max-Age=0; path=/'; };
const views = {
  '': {html: '<p>home</p>'},
  'login': {html: "<div id='lf'><input id='email' type='text'>" +
      "<input id='password' type='password'><button id='loginButton'>Log in</button></div>",
    init: () => { mark('login');
      // background polling with DELETE, only where the session cookie is (the
      // authenticated crawl's own context): never allowed through, even while another
      // context is clicking a named route's button
      if (document.cookie.split('; ').some(c => c.startsWith('token=') && c.length > 6))
        { let polls = 0;                      // bounded: 120 x 100 ms
          poller = setInterval(() => { if (++polls > 120) return;
            fetch('/api/poll/1', {method: 'DELETE'}).catch(() => {}); }, 100); }
      document.getElementById('loginButton').onclick = () => {
        fetch('/rest/user/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({email: document.getElementById('email').value,
                                password: document.getElementById('password').value})})
          .then(r => { if (r.status !== 200) clearToken(); }).catch(() => {});
        fetch('http://127.0.0.1:' + OTHER + '/leak-anon').catch(() => {});
      }; }},
  'about': {html: '<p>about</p>', init: () => { mark('about');
      json('/rest/track', 'POST', {event: 'view', email: 'user@example.invalid',
        password: 'SECRETPASSWORDVALUE', authToken: {value: 'SECRETAUTHTOKEN'},
        tokens: ['SECRETAUTHTOKEN'], ref: IDENT, count: 3, pin: 1234});
      fetch('/api/form', {method: 'POST', headers: {'Content-Type':
        'application/x-www-form-urlencoded', 'Authorization': 'Bearer SECRETBEARER'},
        body: 'name=bob&api_key=SECRETAPIKEY&ref=' + IDENT + '&name=alice'}).catch(() => {});
      fetch('/rest/version?sid=' + IDENT + '&lang=en').catch(() => {});
      fetch('/socket.io/?EIO=4&transport=polling&t=Nabc&sid=' + IDENT).catch(() => {});
      fetch('/socket.io/?EIO=4&transport=polling&sid=' + IDENT, {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: '{"token":"SOCKSECRET"}'})
        .catch(() => {});
      json('/rest/big', 'POST', {blob: 'x'.repeat(70 * 1024)});
      let deep = {leaf: 1}; for (let i = 0; i < 10; i++) deep = {d: deep};
      json('/rest/deep', 'POST', deep);
    }},
  'profile': {html: "<form id='pf'><input name='username'>" +
      "<button type='submit'>Save</button></form>", init: () => { mark('profile');
      document.getElementById('pf').onsubmit = e => { e.preventDefault(); clearToken();
        json('/api/profile', 'PATCH', {username: 'fuzzlab'}); }; }},
  'contact': {html: "<form id='cf'><textarea name='comment'></textarea>" +
      "<input name='rating' type='number'><button type='submit'>Submit</button></form>",
    init: () => { mark('contact');
      document.getElementById('cf').onsubmit = e => { e.preventDefault();
        const f = e.target;
        json('/api/Feedbacks', 'POST', {comment: f.comment.value,
          rating: Number(f.rating.value), captchaId: IDENT, UserId: 7});
        fetch('http://127.0.0.1:' + OTHER + '/leak').catch(() => {}); }; }},
  'checkout': {html: "<form><input name='address'><button>Place order</button></form>",
    init: () => mark('checkout')},
  'upload': {html: "<form><input type='file' name='f'><input name='title'>" +
      "<button>Upload</button></form>", init: () => mark('upload')},
  '2fa': {html: "<div><input name='totp' autocomplete='one-time-code'>" +
      "<button>Verify</button></div>", init: () => mark('2fa')},
  'register': {html: "<form><input name='email' type='email'>" +
      "<input name='password' type='password'><input name='passwordRepeat' type='password'>" +
      "<button>Register</button></form>", init: () => mark('register')},
  'archive': {html: "<div><input name='note'><button id='ab'>Archive</button></div>",
    init: () => { mark('archive'); document.getElementById('ab').onclick = () =>
      fetch('/api/Notes/3', {method: 'DELETE'}).catch(() => {}); }},
  'items': {html: '<p>items</p>', init: () => { mark('items');
      fetch('/api/Items/7', {method: 'DELETE'}).catch(() => {}); }},
  'logout': {html: '<p>bye</p>', init: () => mark('L')},
  'delete-account': {html: '<p>gone</p>', init: () => mark('D')},
  'product/:id': {html: '<p>product</p>', init: () => mark('P')},
};
let poller = null;
function current() { return location.hash.replace(/^#!?\/?/, '').split('?')[0]; }
function render() {
  if (poller) { clearInterval(poller); poller = null; }
  const v = views[current()] || {html: '<p>not found</p>'};
  // the login view has no footer form, so a named login route's only click is the
  // anonymous context's (the cross-context DELETE test)
  document.getElementById('app').innerHTML = v.html +
    (current() === 'login' ? '' : `__FOOTER__`);
  const q = document.querySelector('.q button');
  if (q) q.onclick = () => json('/api/questions', 'POST', {question:
    document.querySelector('.q input').value});
  if (v.init) v.init();
}
window.addEventListener('hashchange', render);
render();
"""

_HASH_INDEX = ("<!doctype html><html><head><title>spa</title>"
               "<script src='/main.js' defer></script></head><body>"
               "<nav><a href='#/about'>About</a></nav><div id='app'></div></body></html>")

_HISTORY_JS = r"""
const router = new VueRouter({mode: 'history', routes: [
  { path: '/about', component: About },
  { path: '/users/:id', component: User },
  { path: '/signout', component: Bye },
]});
const tree = React.createElement(Routes, null, '<Route path="/contact" element={x} />');
fetch('/rest/marker/' + location.pathname.replace(/\//g, '_')).catch(() => {});
"""

_HISTORY_INDEX = ("<!doctype html><html><head><title>hist</title><base href='/'>"
                  "<script src='/app.js'></script></head><body><p>shell</p></body></html>")


class _Lab:
    """A recording loopback server; ``requests`` holds ``(method, path, cookie,
    authorization, body)`` for each request received."""

    index = ""
    script = ("", "")              # (path, body)
    history = False

    def __init__(self, other_port: int = 9):
        self.requests: list[tuple[str, str, str, str, bytes]] = []
        self.other_port = other_port
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):  # noqa: C901 - one fake app
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                lab.requests.append((self.command, self.path,
                                     self.headers.get("Cookie", ""),
                                     self.headers.get("Authorization", ""), body))
                path = self.path.split("?", 1)[0]
                if path == lab.script[0]:
                    self._send(200, "application/javascript", lab.script_body().encode())
                elif path == "/rest/user/login":
                    self._send(401, "application/json", b'{"error":"Invalid"}')
                elif path.startswith(("/rest/", "/api/", "/socket.io/")):
                    self._send(200, "application/json", b'{"ok":true}')
                elif path == "/" or lab.history:
                    self._send(200, "text/html", lab.index.encode())
                else:
                    self._send(404, "text/plain", b"no")

            def _send(self, status, ctype, data):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = _handle  # noqa: N815

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def script_body(self) -> str:
        return self.script[1]

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/"

    def seen(self, method: str | None = None, prefix: str = "") -> list:
        return [r for r in self.requests
                if (method is None or r[0] == method) and r[1].startswith(prefix)]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class HashSpa(_Lab):
    index = _HASH_INDEX
    script = ("/main.js", "")

    def script_body(self) -> str:
        return (_HASH_JS.replace("__OTHER__", str(self.other_port))
                .replace("__IDENT__", IDENT).replace("__FOOTER__", _FOOTER))


class HistorySpa(_Lab):
    index = _HISTORY_INDEX
    script = ("/app.js", _HISTORY_JS)
    history = True


_ICON_JS = r"""
const routes = [{path:'signin'}, {path:'account'}, {path:'leave'}, {path:'basket'},
                {path:'icononly'}, {path:'find'}, {path:'hidden'}, {path:'hidden2'},
                {path:'rowdel'}, {path:'invisible'}];
const post = (url, body) => fetch(url, {method: 'POST', headers: {'Content-Type':
  'application/json'}, body: JSON.stringify(body)}).catch(() => {});
const views = {
  '': '<p>home</p>',
  // Juice Shop's login button (the live-run false refusal): submitted
  'signin': "<div><input id='email' type='text'><input id='password' type='password'>" +
    "<button id='b' aria-label='Login'><mat-icon>exit_to_app</mat-icon> Log in</button></div>",
  // icon-only, a destructive aria-label: refused
  'account': "<div><input name='q'><button id='b' aria-label='Log out'>" +
    "<mat-icon>exit_to_app</mat-icon></button></div>",
  // icon-only with a neutral icon and a destructive aria-label: refused (on the label)
  'leave': "<div><input name='q2'><button id='b' aria-label='Sign out'>" +
    "<mat-icon>person</mat-icon></button></div>",
  // an icon plus destructive text: refused on "Remove"
  'basket': "<div><input name='note'><button id='b'><span class='material-icons'>" +
    "delete</span> Remove</button></div>",
  // icon-only, no aria-label: judged on its raw text (fail closed)
  'icononly': "<div><input name='x'><button id='b'><mat-icon>delete</mat-icon></button></div>",
  // a Font Awesome icon and ordinary text: submitted
  'find': "<div><input name='y'><button id='b'><i class='fa fa-trash'></i> Search</button></div>",
  // reviewer B: aria-hidden hides real text, it is not an icon -- both refused
  'hidden': "<div><input name='h'><button id='b' aria-label='Item 3'>" +
    "<span aria-hidden='true'>Delete</span></button></div>",
  'hidden2': "<div><input name='h2'><button id='b'><span aria-hidden='true'>Delete</span>" +
    " item</button></div>",
  // a destructive glyph with neutral text: refused on the icon (fail closed)
  'rowdel': "<div><input name='h3'><button id='b'><mat-icon>delete</mat-icon> Item 3" +
    "</button></div>",
  // shown but never actionable (not covered): not submittable, never dispatched
  'invisible': "<div><input name='v'><button id='b' style='visibility:hidden'>Go</button></div>",
};
function render() {
  const name = location.hash.replace(/^#!?\/?/, '');
  document.getElementById('app').innerHTML = views[name] || '<p>?</p>';
  const b = document.getElementById('b');
  if (b) b.onclick = () => post('/api/clicked/' + name, {route: name});
}
window.addEventListener('hashchange', render);
render();
"""


class IconSpa(_Lab):
    """Buttons whose labels carry icon ligatures (the live Juice Shop false refusal)."""
    index = _HASH_INDEX.replace("/main.js", "/icons.js").replace("#/about", "#/find")
    script = ("/icons.js", _ICON_JS)


_OVERLAY_JS = r"""
const routes = [{path:'signin'}, {path:'signin-stuck'}, {path:'danger'}, {path:'swap'}];
const post = (url, body) => fetch(url, {method: 'POST', headers: {'Content-Type':
  'application/json'}, body: JSON.stringify(body)}).catch(() => {});
const login = "<div class='lf'><input id='email' type='text'>" +
  "<input id='password' type='password'><button id='b' aria-label='Login'>Log in</button></div>";
const views = {
  '': '<p>home</p>',
  'signin': login,                 // the overlay closes on Escape
  // the overlay ignores Escape: the dispatch path (another label: its own signature)
  'signin-stuck': login.replace('>Log in<', '>Sign in<'),
  'danger': "<div><input name='reason'><button id='b'>Delete account</button></div>",
  // reviewer B: the app re-renders on Escape and the vetted node now reads otherwise
  'swap': "<div><input name='topic'><button id='b'>Go</button></div>",
};
function render() {
  const name = location.hash.replace(/^#!?\/?/, '');
  const app = document.getElementById('app');
  app.innerHTML = views[name] || '<p>?</p>';
  const b = document.getElementById('b');
  if (b) b.onclick = () => post('/api/submit/' + name, {route: name});
  if (!views[name] || name === '') return;
  // a first-visit welcome dialog over everything (Juice Shop's mat-dialog pattern)
  const ov = document.createElement('div');
  ov.id = 'overlay';
  ov.setAttribute('style', 'position:fixed;left:0;top:0;width:100vw;height:100vh;' +
    'z-index:1000;background:rgba(0,0,0,0.4)');
  ov.innerHTML = "<div class='dlg'><p>Welcome</p><button id='dismiss'>Dismiss</button></div>";
  document.body.appendChild(ov);
  document.getElementById('dismiss').onclick = () => post('/api/overlay-dismissed', {});
  if (name !== 'signin-stuck')
    document.addEventListener('keydown', e => { if (e.key === 'Escape') ov.remove(); });
  if (name === 'swap')
    document.addEventListener('keydown', e => {
      const x = document.getElementById('b');
      if (e.key === 'Escape' && x && location.hash.endsWith('swap'))
        x.textContent = 'Delete everything';
    });
}
window.addEventListener('hashchange', () => {
  const old = document.getElementById('overlay'); if (old) old.remove(); render(); });
render();
"""


class OverlaySpa(_Lab):
    """Forms covered by a modal overlay that intercepts pointer events (the live Juice
    Shop click timeout): closable by Escape, not closable, and over a destructive form."""
    index = _HASH_INDEX.replace("/main.js", "/overlay.js").replace("#/about", "#/signin")
    script = ("/overlay.js", _OVERLAY_JS)


class Recorder(_Lab):
    """Another loopback service: anything it receives is a scope escape."""


def chromium_or_skip(monkeypatch):
    """Playwright importable and a pinned Chromium named, or skip -- a failure under
    ``FUZZLAB_REQUIRE_BROWSER=1`` (PA-0065)."""
    from tests._browser import skip_or_fail
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as exc:
        skip_or_fail(f"playwright unavailable: {exc}")
    exe = sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome"))[-1:]
    if exe:
        monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", exe[0])


def run_crawl(spider):
    """Crawl, turning a launch failure into a skip (a failure when required)."""
    from tests._browser import skip_or_fail
    if spider.engine != "playwright":
        skip_or_fail("playwright engine unavailable")
    try:
        spider.crawl()
    except Exception as exc:  # noqa: BLE001 - a launch failure is a skip, not a pass
        skip_or_fail(f"chromium could not launch: {exc}")


def db_rows(path, sql: str) -> list:
    import sqlite3
    con = sqlite3.connect(path)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def db_text(path) -> str:
    """Every value in every table of the spider DB, plus the raw file bytes."""
    import sqlite3
    con = sqlite3.connect(path)
    try:
        dump = "\n".join(con.iterdump())
    finally:
        con.close()
    with open(path, "rb") as fh:
        raw = fh.read().decode("latin-1")
    return dump + raw


def bodies(rows) -> list:
    return [json.loads(r) for r in rows]
