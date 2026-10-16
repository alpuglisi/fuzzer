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

import base64
import glob
import hashlib
import json
import socket
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
    #: extra server-rendered pages: path -> HTML
    pages: dict = {}
    #: custom answers: path -> ``fn(handler)`` that writes the whole response
    responders: dict = {}

    def __init__(self, other_port: int = 9):
        self.requests: list[tuple[str, str, str, str, bytes]] = []
        #: text messages received on the ``/ws`` WebSocket (forms phase 4, W3)
        self.ws_messages: list[str] = []
        self.other_port = other_port
        self._closing = threading.Event()
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):  # noqa: C901 - one fake app
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                lab.requests.append((self.command, self.path,
                                     self.headers.get("Cookie", ""),
                                     self.headers.get("Authorization", ""), body))
                path = self.path.split("?", 1)[0]
                if path in lab.responders:
                    lab.responders[path](self)
                elif path == "/ws" and \
                        (self.headers.get("Upgrade") or "").lower() == "websocket":
                    self._websocket()
                elif path in lab.pages:
                    self._send(200, "text/html", lab.pages[path].encode())
                elif path == lab.script[0]:
                    self._send(200, "application/javascript", lab.script_body().encode())
                elif path == "/rest/user/login":
                    self._send(401, "application/json", b'{"error":"Invalid"}')
                elif path.startswith(("/rest/", "/api/", "/socket.io/")):
                    self._send(200, "application/json", b'{"ok":true}')
                elif path == "/" or lab.history:
                    self._send(200, "text/html", lab.index.encode())
                else:
                    self._send(404, "text/plain", b"no")

            def _websocket(self):
                """A minimal RFC 6455 server: the handshake, then text frames from
                the client recorded until it closes or the lab does."""
                key = self.headers.get("Sec-WebSocket-Key", "")
                accept = base64.b64encode(hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", accept.decode())
                self.end_headers()
                self.wfile.flush()
                self.close_connection = True
                sock = self.connection
                sock.settimeout(0.2)
                buf = b""

                def take(n):
                    nonlocal buf
                    while len(buf) < n:
                        if lab._closing.is_set():
                            return None
                        try:
                            chunk = sock.recv(4096)
                        except (socket.timeout, TimeoutError):
                            continue
                        except OSError:
                            return None
                        if not chunk:
                            return None
                        buf += chunk
                    out, buf = buf[:n], buf[n:]
                    return out
                while True:
                    head = take(2)
                    if head is None:
                        return
                    opcode, size = head[0] & 0x0F, head[1] & 0x7F
                    if size == 126:
                        size = int.from_bytes(take(2) or b"\0\0", "big")
                    elif size == 127:
                        size = int.from_bytes(take(8) or b"\0" * 8, "big")
                    mask = take(4) if head[1] & 0x80 else b"\0\0\0\0"
                    data = take(size) if size else b""
                    if mask is None or data is None:
                        return
                    data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
                    if opcode == 8:
                        return
                    if opcode == 1:
                        lab.ws_messages.append(data.decode("utf-8", "replace"))

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
        self._closing.set()                  # WebSocket handlers end within 0.2 s
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


# =====================================================================================
# Forms phase 4 (FR-CRAWL-15/16): reveal navigation, the reveal window, G1
# =====================================================================================
_REVEAL_JS = r"""
const routes = [{path:'menu'}, {path:'cards'}, {path:'covered'}];
const mark = code => fetch('/rest/marker/' + code).catch(() => {});
const post = (url, body) => fetch(url, {method: 'POST', headers: {'Content-Type':
  'application/json'}, body: JSON.stringify(body || {})}).catch(() => {});
let ws = null;
const views = {
  '': '<p>home</p>',
  // Juice Shop's account mat-menu: its profile item navigates by script (no href)
  'menu': "<button id='acct' aria-haspopup='menu' aria-label='Show/hide account menu'>" +
    "<mat-icon>account_circle</mat-icon> Account</button>",
  'cards': [1, 2, 3, 4].map(n => `<div class='product-card' role='button' tabindex='0'
      data-n='${n}'><img alt='' src='/rest/img/${n}'> Apple Juice ${n}</div>`).join('') +
    // B6: a card with an interactive descendant is not one target
    "<div class='product-card wide' role='button' tabindex='0' data-n='bad'>Banana " +
    "<button id='add'>Add to basket</button></div>" +
    // a card whose text fails the gate
    "<div class='product-card' role='button' tabindex='0' data-n='del'>Delete all</div>",
  // a card under a transparent overlay that takes pointer clicks: only the card's own
  // el.click() reaches the card (a coordinate click would hit the overlay)
  'covered': "<div class='tile' role='button' tabindex='0' id='ct'>Orange Juice</div>" +
    "<div id='veil' style='position:fixed;left:0;top:0;width:100vw;height:100vh;" +
    "z-index:10'></div>",
  // not a declared route: reached only through the menu's link item
  'secret-link': '<p>reached through a menu link</p>',
};
function openMenu() {
  mark('menu-opened');
  post('/api/reveal-post', {opened: true});                          // W2: a write
  fetch('/api/order-history').catch(() => {});                        // transaction GET
  fetch('/rest/user/change-password?new=x').catch(() => {});          // account GET
  fetch('/rest/products?password=x').catch(() => {});                 // credential GET
  mark('plain-get');                                                  // allowed
  if (ws && ws.readyState === 1) ws.send('reveal-msg');               // W3
  const box = document.createElement('div');
  box.className = 'cdk-overlay-container';
  box.innerHTML = "<div role='menu'>" +
    "<button role='menuitem' id='mi-profile'><mat-icon>person</mat-icon> " +
    "Go to user profile</button>" +
    "<a role='menuitem' href='#/secret-link'>Recycle</a>" +
    "<button role='menuitem' id='mi-orders'>Orders &amp; Payment</button>" +
    "<button role='menuitem' id='mi-privacy'>Privacy &amp; Security</button>" +
    "<button role='menuitem' id='mi-history'>History</button>" +
    "<button role='menuitem' id='mi-logout'><mat-icon>exit_to_app</mat-icon> Logout</button>" +
    "</div>";
  document.body.appendChild(box);
  document.getElementById('mi-profile').onclick = () => location.assign('/profile');
  document.getElementById('mi-orders').onclick = () => mark('item-O');
  document.getElementById('mi-privacy').onclick = () => mark('item-P');
  document.getElementById('mi-logout').onclick = () => mark('item-L');
  document.getElementById('mi-history').onclick = () => {
    mark('item-H'); post('/api/history', {}); };
  document.addEventListener('keydown', e => { if (e.key === 'Escape') box.remove(); });
}
function openDialog(n) {
  mark('card-' + n);
  const dlg = document.createElement('div');
  dlg.setAttribute('role', 'dialog');
  dlg.innerHTML = "<form id='rf' action='/api/reviews' method='post'>" +
    "<textarea name='review' required></textarea><button>Submit</button></form>" +
    "<div class='actions'><button id='dlg-close'>Close</button></div>";
  document.body.appendChild(dlg);
  document.getElementById('rf').onsubmit = e => { e.preventDefault();
    post('/api/review', {review: e.target.review.value}); };
  document.getElementById('dlg-close').onclick = () => mark('dlg-close');   // G2c: never
  document.addEventListener('keydown', e => {
    // W1: a debounced write 300 ms after the dialog closes
    if (e.key === 'Escape' && dlg.isConnected) { dlg.remove();
      setTimeout(() => post('/api/after-close', {}), 300); } });
}
function render() {
  const name = location.hash.replace(/^#!?\/?/, '');
  document.getElementById('app').innerHTML = views[name] || '<p>?</p>';
  if (name === 'menu') {
    document.getElementById('acct').onclick = openMenu;
    ws = new WebSocket('ws://' + location.host + '/ws');
    ws.onopen = () => ws.send('hello');
  }
  if (name === 'covered') {
    document.getElementById('ct').onclick = () => mark('card-covered');
    // a real pointer (a coordinate click) fires pointerdown; the card's own el.click()
  // and a click dispatched on the veil itself do not (D72: the veil, label-less, is a
  // reveal target of its own now)
  document.getElementById('veil').onpointerdown = () => mark('veil-hit');
  }
  if (name === 'cards') {
    for (const c of document.querySelectorAll('.product-card'))
      c.onclick = () => openDialog(c.dataset.n);
    document.getElementById('add').onclick = e => { e.stopPropagation(); mark('add'); };
    for (const c of document.querySelectorAll('.product-card'))
      c.style.cursor = 'pointer';
  }
}
window.addEventListener('hashchange', render);
render();
"""


class RevealSpa(_Lab):
    """A menu behind a mat-menu-style trigger (its profile item navigates by script),
    product cards whose dialogs hold a review form, and every write a reveal could make:
    a POST, side-effect GETs, a WebSocket message, a debounced POST after close."""
    index = _HASH_INDEX.replace("/main.js", "/reveal.js").replace("#/about", "#/menu")
    script = ("/reveal.js", _REVEAL_JS)
    pages = {"/profile": ("<!doctype html><html><head><title>profile</title></head><body>"
                          "<form action='/profile' method='post'><input name='username'>"
                          "<button>Set username</button></form></body></html>")}


_G1_JS = r"""
const routes = [{path:'g1'}, {path:'g1bad'}, {path:'g1captcha'}, {path:'g1card'},
                {path:'g1ack'}];
const post = (url, body) => fetch(url, {method: 'POST', headers: {'Content-Type':
  'application/json'}, body: JSON.stringify(body || {})}).catch(() => {});
const views = {
  '': '<p>home</p>',
  // an Angular-like form: the button stays disabled until every validator passes
  'g1': "<div class='g1'><input id='qty' type='number' min='10' max='20' required>" +
    "<input id='zip' type='text' pattern='[0-9]{5}' required>" +
    "<select id='nationality' name='nationality' required><option value=''>--</option>" +
    "<option value='BE'>Belgium</option><option value='FR'>France</option></select>" +
    "<input id='rating' type='range' min='0' max='5' value='0' class='ng-invalid'>" +
    "<label><input id='terms' type='checkbox' required> I accept the terms</label>" +
    "<mat-select id='size' role='combobox' aria-label='Size' class='ng-invalid' " +
    "tabindex='0'>Choose</mat-select><button id='send' disabled>Send</button></div>",
  // a pattern no ladder value can satisfy
  'g1bad': "<div><input id='tag' pattern='[A-Z]{3}-[a-z]{2}' required>" +
    "<button id='send' disabled>Send</button></div>",
  'g1captcha': "<div><textarea id='comment'></textarea><code id='captcha'>2*3+1</code>" +
    "<input id='captchaControl' required><button id='send'>Send</button></div>",
  // a saved card picker: never chosen in (G1c)
  'g1card': "<div><input id='note'><mat-select id='mat-select-3' formcontrolname='card' " +
    "role='combobox' class='ng-invalid' tabindex='0'>Card</mat-select>" +
    "<button id='send' disabled>Save</button></div>",
  // a required checkbox whose label deletes the account: never checked (G1d)
  'g1ack': "<div><input id='reason'><label><input id='ack' type='checkbox' required>" +
    " I understand my account will be deleted</label>" +
    "<button id='send' disabled>Continue</button></div>",
};
function overlay(options, onPick) {
  const box = document.createElement('div');
  box.setAttribute('role', 'listbox');
  box.innerHTML = options.map(o => `<div role='option'>${o}</div>`).join('');
  document.body.appendChild(box);
  for (const o of box.querySelectorAll('[role=option]'))
    o.onclick = () => { onPick(o.textContent); box.remove(); };
}
function g1() {
  const $ = id => document.getElementById(id);
  let size = '';
  const check = () => {
    const rating = Number($('rating').value);
    $('rating').classList.toggle('ng-invalid', rating < 1);
    $('size').classList.toggle('ng-invalid', !size);
    const ok = $('qty').validity.valid && $('zip').validity.valid &&
      $('nationality').validity.valid && rating >= 1 && $('terms').checked && !!size;
    $('send').disabled = !ok;
  };
  for (const id of ['qty', 'zip', 'rating', 'terms', 'nationality'])
    for (const ev of ['input', 'change']) $(id).addEventListener(ev, check);
  // selectionChange autosaves (B5): never sent before the submission
  $('nationality').addEventListener('change', () => post('/api/autosave', {n: 1}));
  $('size').onclick = () => overlay(['Small', 'Large'], v => {
    size = v; check(); post('/api/autosave', {size: v}); });
  $('send').onclick = () => post('/api/g1-submit', {qty: $('qty').value,
    zip: $('zip').value, nationality: $('nationality').value, rating: $('rating').value,
    terms: $('terms').checked, size});
  check();
}
function render() {
  const name = location.hash.replace(/^#!?\/?/, '');
  document.getElementById('app').innerHTML = views[name] || '<p>?</p>';
  const send = document.getElementById('send');
  if (name === 'g1') return g1();
  if (!send) return;
  send.onclick = () => post('/api/sent/' + name, {});
  if (name === 'g1bad') document.getElementById('tag').oninput = e =>
    { send.disabled = !e.target.validity.valid; };
  if (name === 'g1card') document.getElementById('mat-select-3').onclick = () =>
    overlay(['Visa •••• 4242', 'Mastercard •••• 5555'], v => {
      document.getElementById('mat-select-3').classList.remove('ng-invalid');
      send.disabled = false; });
  if (name === 'g1ack') document.getElementById('ack').onchange = e =>
    { send.disabled = !e.target.checked; };
}
window.addEventListener('hashchange', render);
render();
"""


class G1Spa(_Lab):
    """Forms whose button stays disabled until their validators pass (FR-CRAWL-15)."""
    index = _HASH_INDEX.replace("/main.js", "/g1.js").replace("#/about", "#/g1")
    script = ("/g1.js", _G1_JS)


_SESSION_REVEAL_JS = r"""
const routes = [{path:'session1'}, {path:'mid'}, {path:'session2'}, {path:'late'}];
const mark = code => fetch('/rest/marker/' + code).catch(() => {});
// an icon-only toggle that logs out client-side (no request at all)
const toggle = "<button id='t' aria-haspopup='true'><mat-icon>more_vert</mat-icon></button>";
const menu = "<button id='t' aria-haspopup='menu' aria-label='Open help'>Help</button>";
function render() {
  const name = location.hash.replace(/^#!?\/?/, '');
  const app = document.getElementById('app');
  app.innerHTML = name.startsWith('session') ? toggle : (name ? menu : '<p>home</p>');
  const t = document.getElementById('t');
  if (!t) return;
  t.onclick = () => { mark('opened-' + name);
    if (name.startsWith('session')) window.localStorage.removeItem('token'); };
}
window.addEventListener('hashchange', render);
render();
"""


class SessionRevealSpa(_Lab):
    """Reveals in an authenticated crawl whose session lives in localStorage: two
    routes' toggles clear the token client-side (W4)."""
    index = _HASH_INDEX.replace("/main.js", "/sess.js").replace("#/about", "#/session1")
    script = ("/sess.js", _SESSION_REVEAL_JS)


_DIALOG2_JS = r"""
const routes = [{path:'reviews'}, {path:'after1'}, {path:'after2'}];
const post = (url, body) => fetch(url, {method: 'POST', headers: {'Content-Type':
  'application/json'}, body: JSON.stringify(body || {})}).catch(() => {});
function openDialog() {
  const dlg = document.createElement('div');
  dlg.setAttribute('role', 'dialog');
  // form A: its button is detached by the test right after the window's lift (see
  // test_a_click_that_raises_never_leaves_the_window_open); form B: a select that
  // autosaves on change
  dlg.innerHTML = "<form id='fa'><textarea name='review'></textarea>" +
    "<button id='sa'>Send</button></form>" +
    "<form id='fb'><select name='topic' required><option value=''>--</option>" +
    "<option value='g'>General</option></select><button id='sb' disabled>Save</button></form>";
  document.body.appendChild(dlg);
  document.querySelector('#fa textarea').addEventListener('input',
    () => post('/api/autosave-a', {}));
  document.getElementById('fa').onsubmit = e => { e.preventDefault(); post('/api/first'); };
  const sel = document.querySelector('#fb select');
  sel.addEventListener('change', () => { post('/api/autosave-b', {});
    document.getElementById('sb').disabled = !sel.value; });
  document.getElementById('fb').onsubmit = e => { e.preventDefault(); post('/api/second'); };
}
function render() {
  const name = location.hash.replace(/^#!?\/?/, '');
  document.getElementById('app').innerHTML = name === 'reviews' ?
    "<div class='tile' role='button' tabindex='0' id='t'>Apple Juice</div>" :
    '<p>' + (name || 'home') + '</p>';
  const t = document.getElementById('t');
  if (t) t.onclick = openDialog;
}
window.addEventListener('hashchange', render);
render();
"""


class TwoFormDialogSpa(_Lab):
    """A revealed dialog with two forms: the first one's click raises after the lift;
    the second one's select POSTs on change (review B-M1)."""
    index = _HASH_INDEX.replace("/main.js", "/dlg2.js").replace("#/about", "#/reviews")
    script = ("/dlg2.js", _DIALOG2_JS)


_POPUP_JS = r"""
const routes = [{path:'pop'}, {path:'after1'}, {path:'after2'}, {path:'after3'}];
function render() {
  const name = location.hash.replace(/^#!?\/?/, '');
  document.getElementById('app').innerHTML = name === 'pop' ?
    "<button id='b' aria-haspopup='dialog' aria-label='Open preview'>Preview</button>" :
    '<p>' + (name || 'home') + '</p>';
  const b = document.getElementById('b');
  // a popup (no request: about:blank) whose own timer POSTs shortly after
  if (b) b.onclick = () => { const w = window.open('', '_blank');
    if (w) w.document.write("<script>setTimeout(() => fetch('/api/popup-post', " +
      "{method: 'POST', body: 'x'}).catch(() => {}), 300)<\/script>"); };
}
window.addEventListener('hashchange', render);
render();
"""


class PopupSpa(_Lab):
    """A reveal that opens a popup with a delayed POST (review A-S1)."""
    index = _HASH_INDEX.replace("/main.js", "/pop.js").replace("#/about", "#/pop")
    script = ("/pop.js", _POPUP_JS)


_POST_REVEAL_JS = r"""
const routes = [{path:'postreveal'}, {path:'after1'}];
function render() {
  const name = location.hash.replace(/^#!?\/?/, '');
  document.getElementById('app').innerHTML = name === 'postreveal' ?
    "<button id='b' aria-haspopup='dialog' aria-label='Show details'>Details</button>" :
    '<p>' + (name || 'home') + '</p>';
  const b = document.getElementById('b');
  // a reveal whose click auto-submits a POST form: a POST navigation (CC-CRAWL-0029)
  if (b) b.onclick = () => { const f = document.createElement('form');
    f.method = 'post'; f.action = '/api/revealpost';
    const i = document.createElement('input'); i.name = 'v'; i.value = '1';
    f.appendChild(i); document.body.appendChild(f); f.submit(); };
}
window.addEventListener('hashchange', render);
render();
"""


class PostRevealSpa(_Lab):
    """A reveal whose click submits a POST form (CC-CRAWL-0029)."""
    index = _HASH_INDEX.replace("/main.js", "/postrev.js").replace("#/about", "#/postreveal")
    script = ("/postrev.js", _POST_REVEAL_JS)
