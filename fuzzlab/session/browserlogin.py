"""Browser-driven login detection for single-page apps (FR-SESS-19, CC-SESS-0021; D13).

`SessionManager._login` detects a server-rendered login form or an HTTP Basic
challenge. A single-page app (Juice Shop: ``#/login``, a form posting JSON to
``/rest/user/login``, a JWT in the JSON answer, then kept in ``localStorage`` and a
``token`` cookie) has neither, so when the manager may use a browser, it falls back to
this module. Nothing here is per-host configuration: the login is found by detection.

How (Revision 2 of the reviewed design; every bound is explicit):

* **its own worker thread** (`run`): Playwright's sync API cannot nest inside another
  sync Playwright (a re-login during an authenticated crawl), so the login runs on a
  dedicated thread with no event loop, under the manager's per-(host, identity) lock,
  joined with a deadline;
* **its own browser and context**, launched by the one helper
  (`navguard.chromium_launch_kwargs`, `browser_launch_args` over the login scope), with
  service workers blocked; nothing is recorded: no passive capture, no spider-DB writer,
  no HAR, no trace. The context is closed (`navguard.release` first, PA-0128) right
  after its ``storage_state()`` is captured, before the manager does anything else;
* **the login scope** is the base URL's origin plus the operator's ``auth_origins``
  (`LoginGate.in_scope`, the route's and WebSockets' one predicate). From the first
  fill until the context closes (**the window**) every request, whatever its method or
  content, must also pass the manager's `_credential_destination_ok`; WebSockets in
  the window connect only if they pass it too. Spotting the password (raw, percent,
  form ``+``, JSON-escaped, base64; URL, headers, body) only *identifies* the login
  request; it never decides where a request may go. A password-carrying request to an
  account endpoint (register, sign-up, users / accounts without a login token,
  password, reset, change) is aborted before it is sent (`account_endpoint_reason`).
  Aborted-request log lines name the host only;
* **a login-shaped form only** (`login_form_refusal`): exactly one enabled password
  control and one user field (`store_adapter.login_shaped`), no account word on the
  route, button labels, action or control names (`ACCOUNT_WORDS`), not a
  credential-change form (`store_adapter.credential_change_reason`), and the crawler's
  SPA form gate (`spa.form_refusal`). Forms are read with `spa.FORMS_JS` on the base
  page, then on SPA routes (from the page's own scripts and links) whose last segment
  is a login word (`detect._LOGIN_SEGMENTS`);
* **one click** through `spa.click_vetted` (covered -> Escape -> dispatch; labels read
  again), never retried within an attempt;
* **Playwright's API log is off**: the driver is started without ``DEBUG`` /
  ``PWDEBUG`` (they are removed from the environment for the instant the driver
  starts, under a lock), and ``DEBUGP`` (printed per message) refuses the login.

The worker hands back a `LoginObservation`: the login request's URL and its response,
the cookies that response set, the context's ``storage_state()``, and the in-scope GET
requests the app made after the click (protected-probe candidates). The password, the
request body and the form are never in it.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from urllib.parse import quote, quote_plus, unquote, urlsplit

from fuzzlab.core.redaction import name_tokens
from fuzzlab.core.urls import canonical_origin, in_origin_scope, origin_scope, url_key
from fuzzlab.tools.netquiet import Inflight

#: The whole browser login (launch to close), joined with this deadline.
LOGIN_DEADLINE_S = 120.0
#: After the deadline the login is cancelled; its cleanup (context, browser, driver) is
#: waited for this much longer before `run` reports it as still pending.
CLEANUP_S = 30.0
#: How long the login request may take to appear after the click.
WAIT_LOGIN_MS = 10000
#: How long the app may keep requesting after the login answer (bounded settle).
SETTLE_MS = 5000
#: At most this many login routes are visited, and probe candidates kept.
MAX_ROUTES = 5
MAX_PROBES = 8
#: The login response body is read up to this many bytes.
MAX_BODY = 1 << 20

#: Words (whole `name_tokens` tokens) that mark a form or its button as one that
#: creates, recovers or changes an account rather than logging in (reviewers A4/B3).
ACCOUNT_WORDS = frozenset({
    "register", "registration", "signup", "create", "join", "enroll", "enrol", "new",
    "forgot", "recover", "recovery", "reset", "change", "repeat", "confirm",
    "confirmation", "retype", "otp", "totp"})
#: ... or two adjacent tokens that do.
ACCOUNT_PAIRS = frozenset({("sign", "up"), ("security", "question"),
                           ("security", "answer")})
#: Methods that write: in the window, none may target an account endpoint (A-S1).
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: Path tokens of an account endpoint nothing may be written to in the window.
ACCOUNT_PATH_TOKENS = frozenset({"register", "registration", "signup", "password",
                                 "passwd", "reset", "change"})
#: ... and collections of accounts, refused unless a login token is in the path too.
ACCOUNT_COLLECTIONS = frozenset({"user", "users", "account", "accounts"})
LOGIN_PATH_TOKENS = frozenset({"login", "signin", "logon", "session", "sessions", "auth",
                               "authenticate", "authentication", "token", "tokens"})
LOGIN_PATH_PAIRS = frozenset({("sign", "in"), ("log", "in"), ("log", "on")})


class BrowserLoginError(RuntimeError):
    """A browser login failure; the manager reports it as a `SessionAuthError`. Its text
    never holds the password (`_scrub`)."""


@dataclass
class LoginObservation:
    """What the browser login saw (in memory only; no password, no request body)."""
    login_url: str
    status: int
    headers: dict[str, str] = field(repr=False)
    body: str = field(repr=False)
    #: cookies the login response set (``Set-Cookie``), valued from the context after it
    cookies: dict[str, str] = field(repr=False)
    storage_state: dict = field(repr=False)
    #: in-scope GET XHR/fetch URLs the app made after the login answer (2xx)
    probes: list[str] = field(repr=False)
    page_url: str = ""
    floor_https: bool = False


# --- the password detector (identification only) -------------------------------------
def secret_forms(secret: str, username: str | None = None) -> list[bytes]:
    """The forms ``secret`` takes in a request: raw, percent-encoded, form ``+``,
    JSON-escaped (ASCII and not), base64 (standard and URL-safe, with and without
    padding), and base64 of ``username:secret`` (a Basic header)."""
    texts = {secret, quote(secret, safe=""), quote_plus(secret),
             json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1]}
    raws = [secret.encode()]
    if username is not None:
        raws.append(f"{username}:{secret}".encode())
    for raw in raws:
        for enc in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
            text = enc.decode()
            texts |= {text, text.rstrip("=")}
    return sorted({t.encode() for t in texts if t}, key=len, reverse=True)


def carries(forms: list[bytes], url: str, headers, body) -> bool:
    """Does a request (its URL, any header value, its body) carry one of ``forms``?"""
    parts = [(url or "").encode(), unquote(url or "").encode()]
    parts += [str(v).encode() for v in (headers or {}).values()]
    if body:
        parts.append(body if isinstance(body, bytes) else str(body).encode())
    hay = b"\n".join(parts)
    return any(f in hay for f in forms)


def _scrub(text: str, forms: list[bytes]) -> str:
    """``text`` with every form of the password replaced by ``***``."""
    for f in forms:
        text = text.replace(f.decode("utf-8", "replace"), "***")
    return text


# --- the form and request gates ----------------------------------------------------------
def _account_hit(text: str) -> str | None:
    tokens = [t.lower() for t in name_tokens(text or "")]
    for tok in tokens:
        if tok in ACCOUNT_WORDS:
            return tok
    for pair in zip(tokens, tokens[1:]):
        if pair in ACCOUNT_PAIRS:
            return " ".join(pair)
    return None


def account_word_reason(form: dict, route: str) -> str | None:
    """An account word (`ACCOUNT_WORDS`, `ACCOUNT_PAIRS`) on the route, the button's text
    or aria-label, the form's action, or a control's name, by whole token."""
    from fuzzlab.tools.spa import normalise_route
    texts = [("route", normalise_route(route)), ("button", form.get("button") or ""),
             ("button aria-label", form.get("button_aria") or ""),
             ("action", unquote(urlsplit(form.get("action") or "").path))]
    texts += [("control", name or "") for name, _kind in form.get("controls") or []]
    for where, text in texts:
        hit = _account_hit(text)
        if hit:
            return f"account form ({where} has {hit!r})"
    return None


def login_form_refusal(form: dict, route: str) -> str | None:
    """Why this rendered form is not the login form to use, or None (FR-SESS-19)."""
    from fuzzlab.tools.spa import form_refusal, normalise_route
    from fuzzlab.tools.store_adapter import credential_change_reason, login_shaped
    controls = [(n, k) for n, k in form.get("controls") or []]
    passwords = [n for n, k in controls if k == "password"]
    if len(passwords) != 1:
        return f"{len(passwords)} password controls (a login form has exactly one)"
    if not login_shaped({"controls": controls}):
        return "not login-shaped (one password, one user field, nothing else typed)"
    why = account_word_reason(form, route)
    if why:
        return why
    label, aria = form.get("button") or "", form.get("button_aria") or ""
    shape = {"controls": controls + [(label, "submit"), (aria, "submit")],
             "action_url": form.get("action") or "/" + normalise_route(route),
             "entries": [(label, label), (aria, aria)]}
    why = credential_change_reason(shape)
    if why:
        return why
    return form_refusal(form, route, named=None)


def account_endpoint_reason(url: str) -> str | None:
    """A password-carrying request to this URL would create, reset or change an account
    (reviewers A4/B3): a register / sign-up / password / reset / change path token, or a
    users / accounts collection with no login token in the path. Whole tokens."""
    tokens = [t.lower() for t in name_tokens(unquote(urlsplit(url or "").path))]
    pairs = set(zip(tokens, tokens[1:]))
    for tok in tokens:
        if tok in ACCOUNT_PATH_TOKENS:
            return f"path has {tok!r}"
    if ("sign", "up") in pairs:
        return "path has 'sign up'"
    collection = next((t for t in tokens if t in ACCOUNT_COLLECTIONS), None)
    if collection and not (set(tokens) & LOGIN_PATH_TOKENS or pairs & LOGIN_PATH_PAIRS):
        return f"path has {collection!r} and no login token"
    return None


def _host(url: str) -> str:
    return urlsplit(url or "").hostname or "?"


class LoginGate:
    """The login context's one predicate and its observer. ``in_scope`` is the route's
    and WebSockets' scope (the login scope; in the window also the manager's credential
    destination rule); ``request_refusal`` aborts a password-carrying request to an
    account endpoint before it is sent; ``observe`` identifies the login request (by
    the password) and the app's later GETs. Holds the password's forms in memory only,
    for the life of the worker."""

    def __init__(self, destination_ok, base_url: str, auth_origins=(), *, forms,
                 cancelled: threading.Event | None = None):
        self._destination_ok = destination_ok
        #: set by `run` at the deadline: from then on every request is refused (B-M1)
        self.cancelled = cancelled if cancelled is not None else threading.Event()
        self._base = base_url
        self._origins = origin_scope(base_url, *auth_origins)
        self._forms = forms
        self.window_open = False
        self.floor_https = urlsplit(base_url).scheme.lower() == "https"
        #: why requests were refused (host-only texts)
        self.refusals: list[str] = []
        self.window_refusals = 0
        self.account_refusal: str | None = None
        self.routes: list[str] = []
        self.scripts = 0
        self.login: dict | None = None
        self.probes: list[str] = []

    def in_scope(self, url: str) -> bool:
        if self.cancelled.is_set():
            self.refusals.append(f"{_host(url)}: the login was abandoned")
            return False
        if not in_origin_scope(url, self._origins):
            return False
        if self.window_open and not self._destination_ok(url, self._base,
                                                         floor_https=self.floor_https):
            self.refusals.append(f"{_host(url)}: not a credential destination")
            self.window_refusals += 1
            return False
        return True

    def in_login_scope(self, url: str) -> bool:
        """The login scope alone (no window rule, nothing recorded)."""
        return in_origin_scope(url, self._origins)

    def note_out_of_scope(self, url: str) -> None:
        self.refusals.append(f"{_host(url)}: outside the login scope"
                             + (" (in the login window)" if self.window_open else ""))
        if self.window_open:
            self.window_refusals += 1

    def request_refusal(self, method, url, headers, body) -> str | None:
        """Before a request (or a body-keeping redirect hop) is sent: everything once
        the login was abandoned; in the window, every write (POST, PUT, PATCH, DELETE)
        to an account endpoint, whatever its body (a hashed password included,
        reviewer A-S1)."""
        if self.cancelled.is_set():
            return "browser login abandoned"
        if not self.window_open or (method or "").upper() not in WRITE_METHODS:
            return None
        why = account_endpoint_reason(url)
        if why is None:
            return None
        self.account_refusal = (f"a {method.upper()} to an account endpoint on "
                                f"{_host(url)} was refused in the login window ({why})")
        return "write to an account endpoint"

    def observe(self, request, response) -> None:
        from fuzzlab.tools.spa import (MAX_SCRIPT_BYTES, MAX_SCRIPTS_PER_PAGE,
                                       is_transport_url, route_destructive_reason,
                                       scan_routes)
        rtype = request.resource_type
        if rtype == "script":
            if (response.status == 200 and self.scripts < MAX_SCRIPTS_PER_PAGE
                    and canonical_origin(request.url) == canonical_origin(self._base)):
                self.scripts += 1
                body = response.body()
                found = scan_routes(body.decode("utf-8", "replace")) \
                    if len(body) <= MAX_SCRIPT_BYTES else None
                self.routes += [r for r in found or [] if r not in self.routes]
            return
        if not self.window_open:
            return
        method = request.method.upper()
        if self.login is None:
            if method in ("POST", "PUT") and carries(self._forms, request.url,
                                                     request.headers,
                                                     request.post_data_buffer):
                self.login = _capture(request.url, response)
            return
        if (method == "GET" and rtype in ("xhr", "fetch")
                and 200 <= response.status < 300 and len(self.probes) < MAX_PROBES
                and request.url not in self.probes
                and not is_transport_url(request.url)
                and route_destructive_reason(request.url) is None
                # a URL carrying the password is never kept (stored as the probe)
                and not carries(self._forms, request.url, {}, None)):
            self.probes.append(request.url)


def strip_url(url: str) -> str:
    """``url`` without its query and fragment: how a login URL is kept (A-M2)."""
    from urllib.parse import urlunsplit
    parts = urlsplit(url or "")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def drop_secret_values(storage: dict | None, forms) -> dict:
    """``storage`` (a ``storage_state()``) without any cookie or localStorage entry
    whose name or value carries the password (A-M2), before anything keeps it."""
    storage = storage or {}

    def clean(name, value) -> bool:
        return not carries(forms, "", {"n": name or "", "v": value or ""}, None)
    return {"cookies": [c for c in storage.get("cookies", []) or []
                        if clean(c.get("name"), c.get("value"))],
            "origins": [{**o, "localStorage": [e for e in o.get("localStorage") or []
                                               if clean(e.get("name"), e.get("value"))]}
                        for o in storage.get("origins", []) or []]}


def _capture(url: str, response) -> dict:
    """The login response, in memory (until the manager has detected the credential)."""
    from fuzzlab.session.detect import parse_set_cookie
    set_names: list[str] = []
    for h in getattr(response, "headers_array", None) or []:
        if (h.get("name") or "").lower() == "set-cookie":
            set_names += list(parse_set_cookie(h.get("value") or ""))
    body = response.body()[:MAX_BODY]
    return {"url": strip_url(url), "status": response.status,
            "headers": dict(response.headers),
            "body": body.decode("utf-8", "replace"), "set_cookies": set_names}


# --- the driver ------------------------------------------------------------------------
#: Serialises **this module's** driver starts only (A-N1, B-S4). The environment is
#: process-wide, so this is best effort: another launcher starting at the same instant
#: (the M6 executor, the spider, the fetcher, a `procutil` spawn) may briefly see
#: ``DEBUG`` unset, which is harmless (less logging), and none of them types a secret;
#: a thread that sets ``DEBUG`` inside the window has it overwritten on restore.
_ENV_LOCK = threading.Lock()


@contextmanager
def _driver_env_without_api_logs():
    """Start the Playwright driver with no ``DEBUG`` / ``PWDEBUG``: its API log
    (``pw:api``) would print the typed password (reviewer B8). The variables are
    removed for the instant the driver process is spawned (it copies the environment
    then), under a lock, and put back."""
    with _ENV_LOCK:
        saved = {k: os.environ.pop(k) for k in ("DEBUG", "PWDEBUG") if k in os.environ}
        try:
            yield
        finally:
            os.environ.update(saved)


def _settle(page, inflight: "Inflight", budget_ms: int,
            cancelled: threading.Event | None = None, until=None) -> None:
    """Pump the page until it is quiet for 3 polls of 100 ms, at most ``budget_ms``.
    With ``until``, quiet alone is not enough: the condition must hold too. After a 2xx
    login answer that is "a probe candidate was seen", so a slow app's follow-up GETs,
    made after its JS handles the answer, are not missed by a quiet gap (review of
    26507a1, PA-0128(2): a condition, not a longer sleep)."""
    deadline = time.monotonic() + budget_ms / 1000
    quiet = 0
    while time.monotonic() < deadline and \
            (quiet < 3 or (until is not None and not until())) and \
            not (cancelled is not None and cancelled.is_set()):
        page.wait_for_timeout(100)
        quiet = quiet + 1 if inflight.n == 0 else 0


def _sel(fid: str) -> str:
    return f'[data-fuzzlab-id="{fid}"]'


#: Empties the password field if the page still has it; never waits (X3, Z5).
_CLEAR_IF_PRESENT = "(sel) => { const e = document.querySelector(sel); if (e) e.value = ''; }"


def _login_routes(page, gate: LoginGate, base_url: str) -> list[str]:
    """URLs of the app's login routes: SPA routes from its scripts and links, and
    same-origin links, whose last segment is a login word (whole segment)."""
    from playwright.sync_api import Error as PlaywrightError

    from fuzzlab.session.detect import _LOGIN_SEGMENTS
    from fuzzlab.tools import spa
    try:
        hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
    except PlaywrightError:                          # no links readable: scripts only
        hrefs = []
    frag = spa.spa_fragment(page.url) or ""
    link_frags = [spa.spa_fragment(h) for h in hrefs]
    hash_mode = bool(frag) or any(f is not None for f in link_frags)
    hashbang = frag.startswith("!/") or any(f and f.startswith("!/") for f in link_frags)
    names = list(gate.routes) + [f.split("?", 1)[0] for f in link_frags if f]
    out: list[str] = []

    def login_name(path: str) -> bool:
        segs = [s for s in spa.normalise_route(path).split("/") if s]
        return bool(segs) and segs[-1].lower() in _LOGIN_SEGMENTS

    for name in names:
        kind, _reason = spa.classify_route(name)
        if kind != spa.ROUTE_OK or not login_name(name):
            continue
        out.append(spa.route_url(page.url, name, hash_mode=hash_mode, hashbang=hashbang,
                                 base=base_url))
    for h in hrefs:
        if spa.spa_fragment(h) is None and login_name(urlsplit(h).path):
            out.append(h.split("#", 1)[0])
    seen, unique = set(), []
    for url in out:
        key = spa.visit_key(url)
        if key in seen or spa.visit_key(page.url) == key or not gate.in_scope(url) \
                or spa.route_destructive_reason(url):
            continue
        seen.add(key)
        unique.append(url)
    return unique[:MAX_ROUTES]


def _pick_form(page, base_url: str, refusals: list[str], timeout_ms: int):
    """The first acceptable login form on the current page, or None."""
    from fuzzlab.tools import spa
    route = spa.route_of(page.url, base_url)
    for form in page.evaluate(spa.FORMS_JS, 20):
        if not spa.has_password(form):
            continue
        why = login_form_refusal(form, route)
        if why is None:
            pw = next(cid for (n, k), cid in zip(form["controls"], form["ids"])
                      if k == "password")
            if not page.is_enabled(_sel(pw), timeout=timeout_ms):
                why = "its password control is disabled"
        if why is None:
            return form, route
        refusals.append(f"{'/' + route if route else 'the base page'}: {why}")
    return None


def _username_control(form: dict) -> str | None:
    """The user field: `detect._USERNAME_HINT` over its name (`FORMS_JS`: name, id,
    formcontrolname, aria-label or placeholder) or ``type=email``, else the only one
    (`login_shaped` guarantees exactly one)."""
    from fuzzlab.session.detect import _USERNAME_HINT
    users = [(n, k, cid) for (n, k), cid in zip(form["controls"], form["ids"])
             if k in ("text", "email", "tel")]
    for name, kind, cid in users:
        if kind == "email" or _USERNAME_HINT.search(name or ""):
            return cid
    return users[0][2] if len(users) == 1 else None


def _alive(cancelled: threading.Event) -> None:
    """A checkpoint before each step that could act (a navigation, a fill, the click):
    an abandoned login stops here (B-M1)."""
    if cancelled.is_set():
        raise BrowserLoginError("the browser login was abandoned at its deadline")


def _drive(destination_ok, base_url: str, auth_origins, cred, forms,
           timeout_ms: int, cancelled: threading.Event | None = None) -> LoginObservation:
    """The browser part of the login (runs on the worker thread). ``cancelled`` (set by
    `run` at the deadline) is checked before every navigation, fill and the click, and
    makes the gate refuse every request; the ``finally`` still closes everything."""
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    from fuzzlab.tools import spa
    from fuzzlab.tools.navguard import (browser_launch_args, chromium_launch_kwargs,
                                        guard_page, navigate, release)
    cancelled = cancelled if cancelled is not None else threading.Event()
    gate = LoginGate(destination_ok, base_url, auth_origins, forms=forms,
                     cancelled=cancelled)
    launch = chromium_launch_kwargs(browser_launch_args([base_url, *auth_origins]))
    manager = sync_playwright()
    with _driver_env_without_api_logs():
        try:
            pw = manager.__enter__()
        except Exception as exc:  # noqa: BLE001 - no driver: no browser login
            raise BrowserLoginError(f"the browser login needs Playwright, whose driver "
                                    f"did not start ({_first_line(exc)})") from None
    try:
        try:
            browser = pw.chromium.launch(**launch)
        except Exception as exc:  # noqa: BLE001 - no browser: a loud failure
            raise BrowserLoginError(f"the browser login needs Chromium, which could not "
                                    f"be launched ({_first_line(exc)})") from None
        context = None
        try:
            # its own context; nothing recorded: no HAR, no trace, no capture (B2/A2)
            context = browser.new_context(service_workers="block")
            guard_page(context, allow=frozenset({url_key(base_url)}),
                       in_scope=gate.in_scope, on_out_of_scope=gate.note_out_of_scope,
                       request_refusal=gate.request_refusal, observe=gate.observe)
            page = context.new_page()
            # requests in flight, minus long-lived ones (SP-40)
            inflight = Inflight(page)
            page.on("dialog", lambda d: d.dismiss())    # an app's alert is never ours
            _alive(cancelled)
            # BUG-0138 (CC-SESS-0024): the commit, then a bounded load: a page whose
            # script navigates to a refused URL while it is parsed is not waited out;
            # with no form on it the login fails loudly, and fast
            navigate(page, base_url, timeout_ms=timeout_ms)
            _settle(page, inflight, SETTLE_MS, cancelled)
            refusals: list[str] = []
            picked = _pick_form(page, base_url, refusals, timeout_ms)
            if picked is None:
                for url in _login_routes(page, gate, base_url):
                    _alive(cancelled)
                    navigate(page, url, timeout_ms=timeout_ms)
                    _settle(page, inflight, SETTLE_MS, cancelled)
                    picked = _pick_form(page, base_url, refusals, timeout_ms)
                    if picked is not None:
                        break
            if picked is None:
                raise BrowserLoginError(
                    "no login form was found in the browser"
                    + (f" (refused: {'; '.join(refusals)})" if refusals else
                       " (no rendered form with a password control on the base page "
                       "or a login route)"))
            form, route = picked
            user = _username_control(form)
            pw_id = next(cid for (n, k), cid in zip(form["controls"], form["ids"])
                         if k == "password")
            if user is None:
                raise BrowserLoginError("the login form's user field was not found")
            # the window opens before the first fill and lasts until the context closes
            gate.floor_https = gate.floor_https or \
                urlsplit(page.url).scheme.lower() == "https"
            gate.window_open = True
            _alive(cancelled)
            page.fill(_sel(user), cred.username, timeout=timeout_ms)
            _alive(cancelled)
            page.fill(_sel(pw_id), cred.password, timeout=timeout_ms)
            _alive(cancelled)
            how = spa.click_vetted(page, _sel(form["button_id"]),
                                   [form.get("button") or "", form.get("button_aria") or "",
                                    form.get("button_icons") or ""],
                                   timeout_ms=timeout_ms)
            if how is None:
                raise BrowserLoginError("the login button's labels changed after the "
                                        "gate vetted them: not clicked")
            # wait for the login request; give up early once something was refused in
            # the window and the page has gone quiet (3 polls)
            deadline = time.monotonic() + WAIT_LOGIN_MS / 1000
            quiet = 0
            while gate.login is None and gate.account_refusal is None \
                    and time.monotonic() < deadline and quiet < 3 \
                    and not cancelled.is_set():
                page.wait_for_timeout(100)
                quiet = quiet + 1 if gate.window_refusals and inflight.n == 0 else 0
            if gate.login is None and (gate.window_refusals
                                       or gate.account_refusal is not None):
                # BUG-0136 review (X3): a refused submission leaves the login page
                # alive (ERR_ABORTED keeps the document; a refused fetch never replaced
                # it), so the password is taken out of its field before teardown.
                # Cleared in place if the field is still there, never waited for: an
                # app that removed it costs nothing (BUG-0137 review Z5)
                with suppress(PlaywrightError):
                    page.evaluate(_CLEAR_IF_PRESENT, _sel(pw_id))
            if gate.login is not None:
                _settle(page, inflight, SETTLE_MS, cancelled,
                        until=(lambda: bool(gate.probes))
                        if 200 <= gate.login["status"] < 300 else None)
            _alive(cancelled)
            # nothing carrying the password is kept, before any filtering (A-M2)
            storage = drop_secret_values(context.storage_state(), forms)
            page_url = strip_url(page.url)
        finally:
            # nothing swallowed (PA-0106): a failing close still closes the browser,
            # and its error reaches `run`, which reports it (scrubbed)
            try:
                if context is not None:
                    release(context)                   # pages closed first (PA-0128)
                    context.close()
            finally:
                browser.close()
    finally:
        manager.__exit__(None, None, None)
    if gate.account_refusal is not None:
        raise BrowserLoginError(f"refused: {gate.account_refusal}")
    if gate.login is None:
        hosts = sorted(set(gate.refusals))
        raise BrowserLoginError(
            "the login click sent no in-scope POST/PUT carrying the password"
            + (f"; refused in the login scope: {', '.join(hosts)}" if hosts else ""))
    login = gate.login
    if carries(forms, login["url"], {}, None):
        raise BrowserLoginError("refusing the login: its request URL carries the "
                                "password in its path (it would be stored)")
    jar = {c["name"]: c["value"] for c in storage.get("cookies", [])}
    return LoginObservation(
        login_url=login["url"], status=login["status"], headers=login["headers"],
        body=login["body"],
        cookies={n: jar[n] for n in login["set_cookies"] if n in jar},
        storage_state=filter_storage_state(storage, gate.in_login_scope, [base_url]),
        probes=list(gate.probes), page_url=page_url, floor_https=gate.floor_https)


def _first_line(exc) -> str:
    text = str(exc).splitlines()[0][:160] if str(exc) else repr(exc)
    return text


#: Live login workers by (base URL, identity): no second login starts beside one that
#: is still running or cleaning up (B-M2).
_LIVE: dict[tuple[str, str], threading.Thread] = {}
_LIVE_LOCK = threading.Lock()


def run(destination_ok, base_url: str, cred, *, identity: str = "", auth_origins=(),
        timeout_ms: int = 10000, deadline_s: float = LOGIN_DEADLINE_S,
        cleanup_s: float = CLEANUP_S) -> LoginObservation:
    """Perform the browser login on a dedicated worker thread (no event loop: a sync
    Playwright never nests in another, reviewer B5) and wait for it, at most
    ``deadline_s``. At the deadline the login is **cancelled** (B-M1): the worker stops
    at its next checkpoint, its gate refuses every request, and its ``finally`` closes
    the context, browser and driver, which is waited for up to ``cleanup_s`` more. A
    login for the same (base URL, identity) whose worker is still alive refuses a new
    one (B-M2). Raises `BrowserLoginError`, whose text never holds the password."""
    if "DEBUGP" in os.environ:
        raise BrowserLoginError("refusing the browser login: DEBUGP is set, so "
                                "Playwright would print every message, the password "
                                "included")
    forms = secret_forms(cred.password, cred.username)
    out: dict = {}
    cancelled = threading.Event()
    key = (url_key(base_url), identity)

    def work() -> None:
        try:
            out["obs"] = _drive(destination_ok, base_url, list(auth_origins), cred, forms,
                                timeout_ms, cancelled)
        except BrowserLoginError as exc:
            out["err"] = _scrub(str(exc), forms)
        except BaseException as exc:  # noqa: BLE001 - reported, scrubbed, never raw
            out["err"] = _scrub(f"browser login failed ({type(exc).__name__}: "
                                f"{_first_line(exc)})", forms)
        finally:
            with _LIVE_LOCK:
                if _LIVE.get(key) is threading.current_thread():
                    del _LIVE[key]

    worker = threading.Thread(target=work, name="fuzzlab-browser-login", daemon=True)
    with _LIVE_LOCK:
        previous = _LIVE.get(key)
        if previous is not None and previous.is_alive():
            raise BrowserLoginError("a previous browser login for this base URL and "
                                    "identity is still finishing; not starting another")
        _LIVE[key] = worker
    worker.start()
    worker.join(deadline_s)
    if worker.is_alive():
        cancelled.set()
        worker.join(cleanup_s)
        if worker.is_alive():
            raise BrowserLoginError(f"the browser login did not finish within "
                                    f"{deadline_s:.0f} s; browser login abandoned; "
                                    f"cleanup pending")
        raise BrowserLoginError(f"the browser login did not finish within "
                                f"{deadline_s:.0f} s; abandoned and closed")
    if "err" in out:
        raise BrowserLoginError(out["err"])
    return out["obs"]


# --- storage_state adoption (FR-CRAWL-14) ------------------------------------------------
def canonical_host(url: str) -> str | None:
    """``url``'s host as `canonical_origin` spells it (loopback aliases one host)."""
    origin = canonical_origin(url)
    return origin.split("://", 1)[1].rsplit(":", 1)[0] if origin else None


def filter_storage_state(state: dict | None, in_scope, scope_urls) -> dict:
    """``state`` (a Playwright ``storage_state()``) kept to in-scope origins only
    (reviewer A7): a localStorage origin passes ``in_scope``; a cookie is kept when the
    browser sends it to the host of a ``scope_urls`` entry that is itself in scope, in
    any spelling its origin folds (a loopback host's three), by SP-74's predicate
    (`navguard.cookie_reaches`; BUG-0559 review round 2, BB-2: one comparison of a
    cookie's domain with a host in fuzzlab)."""
    from fuzzlab.tools.navguard import cookie_reaches, origin_host_spellings
    state = state or {}
    hosts = {h for u in scope_urls if u and in_scope(u) for h in origin_host_spellings(u)}

    def cookie_ok(c: dict) -> bool:
        return any(cookie_reaches(c, h) for h in hosts)
    origins = [o for o in state.get("origins", []) or []
               if in_scope((o.get("origin") or "").rstrip("/") + "/")]
    return {"cookies": [dict(c) for c in state.get("cookies", []) or [] if cookie_ok(c)],
            "origins": [{"origin": o["origin"],
                         "localStorage": [dict(e) for e in o.get("localStorage") or []]}
                        for o in origins]}
