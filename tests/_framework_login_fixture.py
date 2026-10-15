"""Login pages as web frameworks ship them by default, for BUG-0148 (PA-0154(b)).

Every shape here comes from a framework's own documented defaults (its login route,
form field names, CSRF field and button label), never from a lab: Django's
``LoginView`` and admin, the Rails 8 authentication generator, Devise, ASP.NET Core
Identity's default UI, Spring Security's generated login page and Laravel Breeze; and
four single-page-app shapes (a Vue Router hash-mode link, an Angular ``routerLink``
button that pushes a route with no login word, an account menu that renders its items
only when opened, a Bootstrap modal). Negatives and stated residuals sit beside them.

`FrameworkApp` is a recording loopback server (``ThreadingHTTPServer`` on 127.0.0.1,
port 0, in this process). Server-rendered shapes check their CSRF field against the
cookie the login page set; a correct login answers 302 with a session cookie. The SPA
shapes post JSON to ``/api/login``. Every request is recorded (method, path, body).
"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

USER = "operator@example.invalid"


@dataclass
class Shape:
    """One app: ``pages`` maps a path to its HTML (``{csrf}`` is the token, ``{other}``
    another server's origin) or to ``"REDIRECT:<location>"``; ``login`` is the action
    path that accepts ``user`` / ``password`` (and ``csrf`` when set). ``spa``: any
    other GET path serves ``pages["/"]`` (history-mode fallback)."""
    name: str
    base: str
    pages: dict
    login: str
    user: str
    password: str
    csrf: str | None = None
    spa: bool = False
    json_login: bool = False
    #: paths whose POST is a decoy login (an app page that must never get credentials)
    decoys: tuple = ()
    expect_action: str = ""
    tags: tuple = field(default_factory=tuple)


# --- server-rendered framework defaults ------------------------------------------------
DJANGO = Shape(
    "django-loginview", "/", {
        "/": "<!doctype html><html><body><header><a href='/'>Home</a> "
             "<a href='/accounts/login/'>Log in</a></header><p>Welcome</p></body></html>",
        # django.contrib.auth.views.LoginView with the documented registration/login.html
        "/accounts/login/":
            "<!doctype html><html><body><form method='post' action='/accounts/login/'>"
            "<input type='hidden' name='csrfmiddlewaretoken' value='{csrf}'>"
            "<label for='id_username'>Username:</label><input type='text' "
            "name='username' autofocus autocapitalize='none' autocomplete='username' "
            "maxlength='150' required id='id_username'>"
            "<label for='id_password'>Password:</label><input type='password' "
            "name='password' autocomplete='current-password' required id='id_password'>"
            "<input type='submit' value='login'><input type='hidden' name='next' "
            "value=''></form></body></html>"},
    "/accounts/login/", "username", "password", csrf="csrfmiddlewaretoken")

DJANGO_ADMIN = Shape(
    "django-admin", "/admin/", {
        "/admin/": "REDIRECT:/admin/login/?next=/admin/",
        "/admin/login/":
            "<!doctype html><html><body><div id='content'><form "
            "action='/admin/login/?next=/admin/' method='post' id='login-form'>"
            "<input type='hidden' name='csrfmiddlewaretoken' value='{csrf}'>"
            "<div class='form-row'><label class='required' for='id_username'>Username:"
            "</label> <input type='text' name='username' autofocus autocapitalize='none'"
            " autocomplete='username' maxlength='150' required id='id_username'></div>"
            "<div class='form-row'><label class='required' for='id_password'>Password:"
            "</label> <input type='password' name='password' "
            "autocomplete='current-password' required id='id_password'>"
            "<input type='hidden' name='next' value='/admin/'></div>"
            "<div class='submit-row'><input type='submit' value='Log in'></div>"
            "</form></div></body></html>"},
    "/admin/login/", "username", "password", csrf="csrfmiddlewaretoken")

RAILS = Shape(
    "rails-auth-generator", "/", {
        "/": "<!doctype html><html><body><nav><a href='/'>Home</a> "
             "<a href='/session/new'>Sign in</a></nav></body></html>",
        # `bin/rails generate authentication`: resource :session, sessions/new.html.erb
        "/session/new":
            "<!doctype html><html><body><form action='/session' accept-charset='UTF-8' "
            "method='post'><input type='hidden' name='authenticity_token' "
            "value='{csrf}' autocomplete='off'><input type='email' "
            "name='email_address' required autofocus autocomplete='username' "
            "placeholder='Enter your email address'><input type='password' "
            "name='password' required autocomplete='current-password' "
            "placeholder='Enter your password' maxlength='72'>"
            "<input type='submit' name='commit' value='Sign in'></form>"
            "<a href='/passwords/new'>Forgot password?</a></body></html>"},
    "/session", "email_address", "password", csrf="authenticity_token")

DEVISE = Shape(
    "devise", "/", {
        "/": "<!doctype html><html><body><nav><a href='/users/sign_in'>Log in</a> "
             "<a href='/users/sign_up'>Sign up</a></nav></body></html>",
        # devise/sessions/new.html.erb and devise/shared/_links.html.erb
        "/users/sign_in":
            "<!doctype html><html><body><h2>Log in</h2><form class='new_user' "
            "id='new_user' action='/users/sign_in' accept-charset='UTF-8' "
            "method='post'><input type='hidden' name='authenticity_token' "
            "value='{csrf}'><div class='field'><label for='user_email'>Email</label>"
            "<input autofocus autocomplete='email' type='email' value='' "
            "name='user[email]' id='user_email'></div><div class='field'>"
            "<label for='user_password'>Password</label><input "
            "autocomplete='current-password' type='password' name='user[password]' "
            "id='user_password'></div><div class='field'><input name='user[remember_me]'"
            " type='hidden' value='0'><input type='checkbox' value='1' "
            "name='user[remember_me]' id='user_remember_me'><label "
            "for='user_remember_me'>Remember me</label></div><div class='actions'>"
            "<input type='submit' name='commit' value='Log in'></div></form>"
            "<a href='/users/sign_up'>Sign up</a><br><a href='/users/password/new'>"
            "Forgot your password?</a></body></html>"},
    "/users/sign_in", "user[email]", "user[password]", csrf="authenticity_token")

ASPNET = Shape(
    "aspnet-identity", "/", {
        "/": "<!doctype html><html><body><ul class='navbar-nav'><li class='nav-item'>"
             "<a class='nav-link text-dark' href='/Identity/Account/Register'>Register</a>"
             "</li><li class='nav-item'><a class='nav-link text-dark' "
             "href='/Identity/Account/Login'>Login</a></li></ul></body></html>",
        # Microsoft.AspNetCore.Identity.UI: Areas/Identity/Pages/Account/Login.cshtml
        "/Identity/Account/Login":
            "<!doctype html><html><body><h1>Log in</h1><form id='account' "
            "method='post'><h2>Use a local account to log in.</h2><div "
            "class='form-floating mb-3'><input class='form-control' "
            "autocomplete='username' aria-required='true' placeholder='name@example.com'"
            " type='email' id='Input_Email' name='Input.Email' value=''><label "
            "for='Input_Email' class='form-label'>Email</label></div><div "
            "class='form-floating mb-3'><input class='form-control' "
            "autocomplete='current-password' aria-required='true' "
            "placeholder='password' type='password' id='Input_Password' "
            "name='Input.Password'><label for='Input_Password' class='form-label'>"
            "Password</label></div><div class='checkbox mb-3'><label "
            "class='form-label'><input class='form-check-input' type='checkbox' "
            "id='Input_RememberMe' name='Input.RememberMe' value='true'> Remember me?"
            "</label></div><div><button id='login-submit' type='submit' "
            "class='w-100 btn btn-lg btn-primary'>Log in</button></div><div><p>"
            "<a id='forgot-password' href='/Identity/Account/ForgotPassword'>Forgot "
            "your password?</a></p><p><a href='/Identity/Account/Register'>Register as "
            "a new user</a></p></div><input name='__RequestVerificationToken' "
            "type='hidden' value='{csrf}'><input name='Input.RememberMe' "
            "type='hidden' value='false'></form></body></html>"},
    "/Identity/Account/Login", "Input.Email", "Input.Password",
    csrf="__RequestVerificationToken")

SPRING = Shape(
    "spring-security", "/", {
        "/": "REDIRECT:/login",
        # DefaultLoginPageGeneratingFilter
        "/login":
            "<!DOCTYPE html><html lang='en'><head><title>Please sign in</title></head>"
            "<body><div class='content'><form class='login-form' method='post' "
            "action='/login'><h2>Please sign in</h2><p><label for='username' "
            "class='screenreader'>Username</label><input type='text' id='username' "
            "name='username' placeholder='Username' required autofocus></p><p><label "
            "for='password' class='screenreader'>Password</label><input type='password'"
            " id='password' name='password' placeholder='Password' required></p>"
            "<input name='_csrf' type='hidden' value='{csrf}' /><button type='submit' "
            "class='primary'>Sign in</button></form></div></body></html>"},
    "/login", "username", "password", csrf="_csrf")

LARAVEL = Shape(
    "laravel-breeze", "/", {
        "/": "<!doctype html><html><body><nav class='-mx-3 flex flex-1 justify-end'>"
             "<a href='/login' class='rounded-md px-3 py-2'>Log in</a> <a "
             "href='/register' class='rounded-md px-3 py-2'>Register</a></nav>"
             "</body></html>",
        # resources/views/auth/login.blade.php
        "/login":
            "<!doctype html><html><body><form method='POST' action='/login'>"
            "<input type='hidden' name='_token' value='{csrf}' autocomplete='off'>"
            "<div><label for='email'>Email</label><input id='email' type='email' "
            "name='email' value='' required autofocus autocomplete='username'></div>"
            "<div class='mt-4'><label for='password'>Password</label><input "
            "id='password' type='password' name='password' required "
            "autocomplete='current-password'></div><div class='block mt-4'><label "
            "for='remember_me' class='inline-flex items-center'><input id='remember_me'"
            " type='checkbox' name='remember'><span>Remember me</span></label></div>"
            "<div class='flex items-center justify-end mt-4'><a "
            "href='/forgot-password'>Forgot your password?</a><button type='submit' "
            "class='ms-3'>Log in</button></div></form></body></html>"},
    "/login", "email", "password", csrf="_token")

SERVER_RENDERED = [DJANGO, DJANGO_ADMIN, RAILS, DEVISE, ASPNET, SPRING, LARAVEL]

# --- single-page-app shapes ------------------------------------------------------------
_SPA_LOGIN = """
const loginView = () => "<form id='lf'><input type='email' name='email' " +
  "autocomplete='username'><input type='password' name='password'>" +
  "<button type='submit'>Continue</button></form>";
function wire() { const f = document.getElementById('lf'); if (!f) return;
  f.onsubmit = async e => { e.preventDefault();
    const r = await fetch('/api/login', {method: 'POST', headers:
      {'Content-Type': 'application/json'}, body: JSON.stringify({email:
      f.email.value, password: f.password.value})});
    if (r.status === 200) document.getElementById('app').innerHTML = '<p>home</p>'; }; }
"""


def _spa_page(body: str, script: str) -> str:
    return ("<!doctype html><html><body>" + body + "<div id='app'></div><script>"
            + _SPA_LOGIN + script + "</script></body></html>")


VUE_HASH = Shape(
    "vue-hash-link", "/", {
        "/": _spa_page(
            "<nav><a href='#/'>Home</a> <a href='#/sign-in'>Sign in</a></nav>",
            "const render = () => { const r = location.hash.replace(/^#\\/?/, '');"
            "document.getElementById('app').innerHTML = r === 'sign-in' ? loginView()"
            " : '<p>home</p>'; wire(); };"
            "window.addEventListener('hashchange', render); render();")},
    "/api/login", "email", "password", spa=True, json_login=True)

ROUTERLINK_BUTTON = Shape(
    "routerlink-button", "/", {
        "/": _spa_page(
            "<nav><button type='button' id='go'>Log in</button></nav>",
            "const render = () => { document.getElementById('app').innerHTML ="
            " location.pathname === '/members/access' ? loginView() : '<p>home</p>';"
            " wire(); };"
            "document.getElementById('go').onclick = () => {"
            " history.pushState({}, '', '/members/access'); render(); };"
            "window.addEventListener('popstate', render); render();")},
    "/api/login", "email", "password", spa=True, json_login=True)

ACCOUNT_MENU = Shape(
    "account-menu", "/", {
        "/": _spa_page(
            "<header><button type='button' id='acct' aria-haspopup='menu' "
            "aria-expanded='false' aria-label='Account'><svg width='16' height='16' "
            "aria-hidden='true'><circle cx='8' cy='8' r='6'/></svg></button>"
            "<div id='menu'></div></header>",
            "document.getElementById('acct').onclick = () => {"
            " const m = document.getElementById('menu');"
            " m.innerHTML = \"<div role='menu'><button role='menuitem' id='si'>Sign in"
            "</button><button role='menuitem'>Register</button></div>\";"
            " document.getElementById('acct').setAttribute('aria-expanded', 'true');"
            " document.getElementById('si').onclick = () => {"
            "  document.getElementById('app').innerHTML = loginView(); wire(); }; };")},
    "/api/login", "email", "password", spa=True, json_login=True)

BOOTSTRAP_MODAL = Shape(
    "bootstrap-modal", "/", {
        "/": "<!doctype html><html><body><nav><button type='button' "
             "class='btn btn-primary' data-bs-toggle='modal' "
             "data-bs-target='#loginModal'>Log in</button></nav>"
             "<div class='modal fade' id='loginModal' tabindex='-1' aria-hidden='true' "
             "style='display:none'><div class='modal-dialog'><div class='modal-content'>"
             "<form method='post' action='/login'><input type='hidden' name='_token' "
             "value='{csrf}'><input type='email' name='email' autocomplete='username'>"
             "<input type='password' name='password' autocomplete='current-password'>"
             "<button type='submit' class='btn btn-primary'>Sign in</button></form>"
             "</div></div></div><script>document.querySelector("
             "'[data-bs-toggle=modal]').onclick = () => { const m = "
             "document.getElementById('loginModal'); m.style.display = 'block'; "
             "m.removeAttribute('aria-hidden'); };</script></body></html>"},
    "/login", "email", "password", csrf="_token")

SPA_SHAPES = [VUE_HASH, ROUTERLINK_BUTTON, ACCOUNT_MENU, BOOTSTRAP_MODAL]

# --- negatives ---------------------------------------------------------------------------
SUBMITTER_ONLY = Shape(
    "sign-in-submitter-of-another-form", "/", {
        "/": "<!doctype html><html><body><form method='post' action='/newsletter'>"
             "<input type='email' name='email'><button>Sign in</button></form>"
             "</body></html>"},
    "/login", "email", "password")

OFF_ORIGIN = Shape(
    "sign-in-elsewhere", "/", {
        "/": "<!doctype html><html><body><a href='{other}/oauth/authorize'>Sign in "
             "with Google</a> <a href='{other}/login'>Sign in</a></body></html>"},
    "/login", "email", "password")

ONLOAD_WRITE = Shape(
    "post-on-load", "/", {
        "/": "<!doctype html><html><body><a href='/login'>Log in</a><script>"
             "fetch('/api/track', {method: 'POST', body: 'visit'});</script></body></html>",
        "/login": LARAVEL.pages["/login"]},
    "/login", "email", "password", csrf="_token")

MISLABELLED = Shape(
    "mislabelled-sign-in", "/", {
        "/": "<!doctype html><html><body><button type='button' onclick=\"fetch("
             "'/api/subscribe', {method: 'POST', body: 'x'})\">Sign in</button>"
             "</body></html>"},
    "/login", "email", "password")

#: An app page with a login form of its own (a lab exercise, a demo) is linked before the
#: real login: the path rank must try ``/login`` first, and never fill the decoy.
DECOY = Shape(
    "decoy-before-login", "/", {
        "/": "<!doctype html><html><body><a href='/xss_login'>Exercise: login form</a> "
             "<a href='/login'>Members</a></body></html>",
        "/xss_login": "<!doctype html><html><body><form method='post' "
                      "action='/xss_login'><input name='login'><input type='password' "
                      "name='password'><button>Go</button></form></body></html>",
        "/login": SPRING.pages["/login"]},
    "/login", "username", "password", csrf="_csrf", decoys=("/xss_login",))

# --- stated residuals (strict xfails) ---------------------------------------------------
SHADOW_DOM = Shape(
    "shadow-dom-form", "/", {
        "/": "<!doctype html><html><body><login-box></login-box><script>"
             "customElements.define('login-box', class extends HTMLElement {"
             " connectedCallback() { this.attachShadow({mode: 'open'}).innerHTML ="
             " \"<form method='post' action='/login'><input type='email' name='email'>"
             "<input type='password' name='password'><button>Log in</button></form>\";"
             " } });</script></body></html>"},
    "/login", "email", "password")

ROLELESS_DIV = Shape(
    "clickable-div", "/", {
        "/": BOOTSTRAP_MODAL.pages["/"].replace(
            "<button type='button' class='btn btn-primary' data-bs-toggle='modal' "
            "data-bs-target='#loginModal'>Log in</button>",
            "<div class='nav-link' data-bs-toggle='modal'>Log in</div>")},
    "/login", "email", "password", csrf="_token")

NON_ENGLISH = Shape(
    "non-english-label", "/", {
        "/": BOOTSTRAP_MODAL.pages["/"].replace(">Log in</button></nav>",
                                                ">Anmelden</button></nav>")},
    "/login", "email", "password", csrf="_token")

IDENTIFIER_FIRST = Shape(
    "identifier-first", "/", {
        "/": "<!doctype html><html><body><a href='/signin'>Sign in</a></body></html>",
        "/signin": "<!doctype html><html><body><form method='post' "
                   "action='/signin/identifier'><input type='email' name='identifier' "
                   "autocomplete='username'><button>Next</button></form></body></html>"},
    "/signin/password", "identifier", "password")


class FrameworkApp:
    """A recording loopback server for one `Shape`. ``requests`` holds ``(method,
    path, body)``; ``logins`` the credential POSTs it accepted, by path."""

    def __init__(self, shape: Shape, password: str, *, other: str = ""):
        self.shape, self.password, self.other = shape, password, other
        self.requests: list[tuple[str, str, bytes]] = []
        self.logins: list[str] = []
        self.decoy_posts: list[str] = []
        self._lock = threading.Lock()
        app = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with app._lock:
                    app.requests.append((self.command, self.path, body))
                app.route(self, body)

            do_GET = do_POST = do_PUT = do_HEAD = _handle  # noqa: N815

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    @property
    def base(self) -> str:
        return self.origin + self.shape.base

    def route(self, h, body: bytes) -> None:
        path = h.path.split("?", 1)[0]
        shape = self.shape
        cookie = _cookie(h.headers.get("Cookie") or "", "csrf")
        if h.command == "POST" and path == shape.login:
            return self._login(h, body, cookie)
        if h.command == "POST" and path in shape.decoys:
            self.decoy_posts.append(path)
            return _send(h, 200, "text/html", b"<p>decoy</p>")
        if h.command == "POST":
            return _send(h, 404, "text/plain", b"no")
        page = shape.pages.get(path)
        if page is None and shape.spa and not path.startswith("/api/"):
            page = shape.pages["/"]
        if page is None:
            return _send(h, 404, "text/plain", b"no")
        if page.startswith("REDIRECT:"):
            return _send(h, 302, "text/plain", b"", location=page[len("REDIRECT:"):])
        token = cookie or secrets.token_hex(16)
        html = page.replace("{csrf}", token).replace("{other}", self.other)
        _send(h, 200, "text/html", html.encode(),
              cookie=None if cookie else f"csrf={token}; Path=/")

    def _login(self, h, body: bytes, cookie: str) -> None:
        shape = self.shape
        if shape.json_login:
            try:
                doc = json.loads(body or b"{}")
            except ValueError:
                doc = {}
        else:
            doc = dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
        csrf_ok = shape.csrf is None or (cookie and doc.get(shape.csrf) == cookie)
        if csrf_ok and doc.get(shape.user) == USER and \
                doc.get(shape.password) == self.password:
            self.logins.append(h.path.split("?", 1)[0])
            sid = f"sid={secrets.token_hex(16)}; Path=/; HttpOnly"
            if shape.json_login:
                return _send(h, 200, "application/json", b'{"ok":true}', cookie=sid)
            return _send(h, 302, "text/plain", b"", location=shape.base, cookie=sid)
        return _send(h, 403 if not csrf_ok else 401, "text/plain", b"rejected")

    def seen(self, method: str) -> list[str]:
        with self._lock:
            return [p for m, p, _b in self.requests if m == method]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _cookie(header: str, name: str) -> str:
    for part in header.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == name:
            return value
    return ""


def _send(h, status: int, ctype: str, data: bytes, *, location: str | None = None,
          cookie: str | None = None) -> None:
    h.send_response(status)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(data)))
    if location:
        h.send_header("Location", location)
    if cookie:
        h.send_header("Set-Cookie", cookie)
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(data)
