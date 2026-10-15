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
  SPA form gate (`spa.form_refusal`); a standard login page's route or action word
  (`LOGIN_ROUTE_OVERRIDES`) does not refuse it when that route or action names a login
  (BUG-0148). Forms are read with `spa.FORMS_JS` on the base page (a form whose password
  control is not visible is refused), then (BUG-0148, `_Discovery`) on what the page's
  own login affordances lead to -- "Log in" / "Sign in" links visited, other such
  controls clicked in the reveal window, one level of an account menu opened -- then on
  path candidates by rank (`detect.login_path_match`), at most `MAX_ROUTES`;
* **before the window** every write (any method but GET and HEAD) is aborted, counted
  and named in the diagnosis (`LoginGate.request_refusal`, BUG-0148);
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
from fuzzlab.session.detect import LABEL_FILLER, LOGIN_ENDPOINT_TOKENS, LOGIN_PAIRS

#: The whole browser login (launch to close), joined with this deadline.
LOGIN_DEADLINE_S = 120.0
#: After the deadline the login is cancelled; its cleanup (context, browser, driver) is
#: waited for this much longer before `run` reports it as still pending.
CLEANUP_S = 30.0
#: How long the login request may take to appear after the click.
WAIT_LOGIN_MS = 10000
#: How long the app may keep requesting after the login answer (bounded settle).
SETTLE_MS = 5000
#: At most this many distinct login candidates are tried after the base page
#: (affordance links and clicks, then path candidates by rank; BUG-0148), and probe
#: candidates kept.
MAX_ROUTES = 5
MAX_PROBES = 8
#: At most this many disclosure controls (an account menu) are opened, one level deep.
MAX_DISCLOSURES = 2
#: At most this many elements are read as possible affordances on one page.
MAX_AFFORDANCES = 400
#: An affordance click's actionability probe is bounded by this (a hidden one raises).
CLICK_MS = 3000
#: At most this many aborted pre-window writes are named in a diagnosis.
MAX_NAMED_WRITES = 8
#: Methods that pass before the login window: they are not writes (review A, A6).
PREWINDOW_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: The search for the login form (after the base page) stops after this long, well
#: inside `LOGIN_DEADLINE_S`, so a slow app gets the diagnosis, not "abandoned" (A10).
DISCOVERY_BUDGET_S = 60.0
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
#: The login vocabulary is SP-16's (`session.detect`), never a copy (BUG-0148, PA-0154(c)).
LOGIN_PATH_TOKENS = LOGIN_ENDPOINT_TOKENS
LOGIN_PATH_PAIRS = LOGIN_PAIRS
#: Words a standard framework login page has on its route or form action that the form
#: gates otherwise refuse (BUG-0148): Rails ``session/new`` (``new``), Devise
#: ``users/sign_in`` (``users``), ASP.NET Identity ``Identity/Account/Login``
#: (``account``), Django ``admin/login`` (``admin``). Dropped from a route or an
#: action, for the gates only, when that location is a login page's own name
#: (`names_login_page`). Button labels and control names keep every rule.
LOGIN_ROUTE_OVERRIDES = frozenset({"new", "users", "account", "admin"})


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
    #: writes aborted before the login window, ``METHOD host/path`` (BUG-0148)
    aborted_writes: list[str] = field(default_factory=list)


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


def names_login_page(path: str) -> bool:
    """A location (a route, or a form action's path) is a login page's own name: its
    last segment is a whole login word or pair, or it ends in ``session(s)/new`` or a
    login directory's front controller (`detect.login_path_match` == `RANK_SEGMENT`;
    review A, A1). Never the wider endpoint vocabulary: ``/auth/users/`` (a registration
    API) and ``/auth/account`` are not login pages."""
    from fuzzlab.session.detect import MODE_CANDIDATE, RANK_SEGMENT, login_path_match
    return bool(path) and \
        login_path_match(unquote(path), mode=MODE_CANDIDATE) == RANK_SEGMENT


def _drop_overrides(path: str) -> str:
    """``path`` as its tokens, `LOGIN_ROUTE_OVERRIDES` removed (for the gates only)."""
    return "/".join(t for t in name_tokens(unquote(path or ""))
                    if t.lower() not in LOGIN_ROUTE_OVERRIDES)


def _gated_route_and_action(form: dict, route: str) -> tuple[dict, str]:
    """BUG-0148 (design section 2): the gates see the route without
    `LOGIN_ROUTE_OVERRIDES` when the route is a login page's name
    (`names_login_page`), and the form action without them when the action's path is;
    the action keeps its origin and query (its destructive and transaction rules still
    see them). Each location is judged on its own: a login route whose form posts to
    ``/users/new`` is still refused for the action's ``new``."""
    from urllib.parse import urlunsplit
    action = form.get("action") or ""
    apath = urlsplit(action).path
    gated = form
    if action and names_login_page(apath):
        gated = dict(form)
        gated["action"] = urlunsplit(urlsplit(action)._replace(
            path="/" + _drop_overrides(apath)))
    return gated, (_drop_overrides(route) if names_login_page(route) else route)


def _without_hidden(form: dict) -> dict:
    """``form`` without its hidden controls (review B, B2(b))."""
    return {**form, "controls": [(n, k) for n, k in form.get("controls") or []
                                 if k != "hidden"]}


def login_form_core_refusal(form: dict, route: str) -> str | None:
    """The login-form gates both login paths share (one implementation, PA-0003;
    review A, A2): the browser login (`login_form_refusal`) and the requests-side
    discovery (`SessionManager._discover_login_form`). Why ``form`` (`spa.FORMS_JS`'s
    shape, or `detect.gate_description`) is not a login form, or None:

    * exactly one password control, login-shaped (`store_adapter.login_shaped`);
    * no account word on the route, the button's labels, the action or any control
      name, hidden ones included (`account_word_reason`), and no destructive control
      name (`core.urls.text_destructive_reason`);
    * not a credential-change form (`store_adapter.credential_change_reason`), judged
      **without the hidden fields**: on a form that passed the gates above, a hidden
      field is a framework token (Rails ``authenticity_token``, Drupal
      ``form_build_id``, Keycloak ``credentialId``, a checkbox's unchecked value), never
      an object selector (review B, B2(b)). That refusal stays for the import side.

    A login page's own route or action word (`LOGIN_ROUTE_OVERRIDES`) does not refuse it
    (`names_login_page`, BUG-0148)."""
    from fuzzlab.core.urls import text_destructive_reason
    from fuzzlab.tools.spa import normalise_route, route_destructive_reason
    from fuzzlab.tools.store_adapter import credential_change_reason, login_shaped
    form, route = _gated_route_and_action(form, route)
    controls = [(n, k) for n, k in form.get("controls") or []]
    passwords = [n for n, k in controls if k == "password"]
    if len(passwords) != 1:
        return f"{len(passwords)} password controls (a login form has exactly one)"
    if not login_shaped({"controls": controls}):
        return "not login-shaped (one password, one user field, nothing else typed)"
    why = account_word_reason(form, route)
    if why:
        return why
    for name, _kind in controls:
        reason = text_destructive_reason(name)
        if reason:
            return f"destructive control {name!r} ({reason!r})"
    reason = route_destructive_reason(form.get("action") or "") or \
        route_destructive_reason("/" + normalise_route(route))
    if reason:
        return f"destructive action or route ({reason!r})"
    label, aria = form.get("button") or "", form.get("button_aria") or ""
    shape = {"controls": [(n, k) for n, k in controls if k != "hidden"]
             + [(label, "submit"), (aria, "submit")],
             "action_url": form.get("action") or "/" + normalise_route(route),
             "entries": [(label, label), (aria, aria)]}
    return credential_change_reason(shape)


def login_form_refusal(form: dict, route: str) -> str | None:
    """Why this rendered form is not the login form to use, or None (FR-SESS-19): the
    shared gates (`login_form_core_refusal`), then the crawler's SPA form gate
    (`spa.form_refusal`) on the form without its hidden fields (B2(b))."""
    from fuzzlab.tools.spa import form_refusal
    why = login_form_core_refusal(form, route)
    if why:
        return why
    gated, gated_route = _gated_route_and_action(_without_hidden(form), route)
    return form_refusal(gated, gated_route, named=None)


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
        #: BUG-0148 (design section 5): every write aborted before the window, as
        #: ``METHOD host/path`` (no query), each once, in order
        self.prewindow_writes: list[str] = []
        self._named_writes: dict[str, None] = {}
        self.prewindow_write_count = 0
        #: an affordance click is in progress (its reveal window, design section 3)
        self.clicking = False
        #: navigations a click triggered (captured, never followed; visited later)
        self.captured: list[str] = []
        #: hosts an affordance click tried to reach outside the login scope
        self.click_out_of_scope: list[str] = []

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
        if self.clicking and _host(url) not in self.click_out_of_scope:
            self.click_out_of_scope.append(_host(url))

    def note_prewindow_write(self, method: str, url: str) -> None:
        """An aborted write before the window: counted, and named by host and path
        (each name once, in order: a diagnosis, never a send decision)."""
        self.prewindow_write_count += 1
        parts = urlsplit(url or "")
        self._named_writes.setdefault(
            f"{(method or '?').upper()} {parts.hostname or '?'}{parts.path or '/'}")
        self.prewindow_writes[:] = list(self._named_writes)

    def window_refusal(self, method: str, url: str, navigation: bool) -> str | None:
        """The route's ``window`` hook (design section 3): while an affordance click is
        in progress (`clicking`), the crawler's reveal-window rule
        (`spa.window_request_refusal`) aborts every navigation -- a GET one's target is
        captured, to be visited through `navguard.navigate` and the gates -- every write
        and every word-refused GET. Outside a click it lets everything through (the
        pre-window rule of `request_refusal` still applies)."""
        from fuzzlab.tools.spa import window_request_refusal
        if not self.clicking:
            return None
        why = window_request_refusal(method, url, navigation)
        if why is None:
            return None
        method = (method or "").upper()
        if method not in ("GET", "HEAD"):
            self.note_prewindow_write(method, url)
        elif navigation and url not in self.captured:
            self.captured.append(url)
        return why

    def ws_hold(self) -> bool:
        """Page-to-server WebSocket messages are held for the whole pre-window phase
        (review A, A5) and during an affordance click (the reveal window's W3 rule); from
        the first fill they are forwarded, as before."""
        return self.clicking or not self.window_open

    def request_refusal(self, method, url, headers, body) -> str | None:
        """Before a request (or a body-keeping redirect hop) is sent: everything once
        the login was abandoned; **before the window** (from launch to the first fill
        of a vetted form; BUG-0148), every write -- any method but GET and HEAD, on page
        load, on a route visit or on an affordance click -- counted and named
        (`note_prewindow_write`). GET, HEAD and OPTIONS pass (review A, A6). A read sent
        as a POST (a GraphQL query, SignalR's ``negotiate``, a JSON-RPC read) is aborted
        too: a stated cross-technology cost (review B, B3); in the window, every write (POST, PUT, PATCH, DELETE)
        to an account endpoint, whatever its body (a hashed password included,
        reviewer A-S1)."""
        if self.cancelled.is_set():
            return "browser login abandoned"
        if not self.window_open:
            # TODO(SP-37, merge order with DISC-CAPTURE): route this pre-window rule
            # through `capture.capture_refusal` once both land (review B, B3).
            if (method or "").upper() in PREWINDOW_READ_METHODS:
                return None
            self.note_prewindow_write(method, url)
            return "a write before the login window"
        if (method or "").upper() not in WRITE_METHODS:
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


class _Inflight:
    """Requests in flight on a page, so a settle waits for the app's own XHRs."""

    def __init__(self, page):
        self.n = 0
        page.on("request", self._up)
        page.on("requestfinished", self._down)
        page.on("requestfailed", self._down)

    def _up(self, _request):
        self.n += 1

    def _down(self, _request):
        self.n = max(0, self.n - 1)


def _settle(page, inflight: _Inflight, budget_ms: int,
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


# --- finding the login form (BUG-0148: by affordance first, then by path rank) --------
#: What a diagnosis says about a page that asks for a user field alone.
IDENTIFIER_FIRST = ("a user-field form with no password control (identifier-first "
                    "login: not supported)")
NO_AFFORDANCE = "no login affordance found (English labels only)"
#: Labels of a disclosure control that is opened to look for a login affordance inside
#: it (design section 3). The signal is the control's own ``aria-haspopup`` /
#: ``aria-expanded=false``; its label must be the shared filler (`detect.LABEL_FILLER`)
#: plus these words only, or empty with an icon. No icon-ligature names (review B, B6).
DISCLOSURE_WORDS = LABEL_FILLER | frozenset({"user", "profile", "me", "menu"})

#: Marks the elements a login affordance can be (``data-fuzzlab-aff``), in document
#: order: ``a[href]``, ``button``, ``[role=button]``, ``[role=link]``,
#: ``[role=menuitem]``, ``input[type=button]`` -- never a form's submitter
#: (``input[type=submit|image]``, or a ``<button>`` of type submit that belongs to a
#: form): clicking one would submit its form. Links are read visible or not (measured,
#: BUG-0148 section 0). Labels are read afterwards with the one label reader,
#: `spa.LABELS_JS`.
AFFORDANCES_JS = r"""
(maxScan) => {
  const SEL = 'a[href], button, [role=button], [role=link], [role=menuitem], ' +
    'input[type=button]';
  const shown = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
    && getComputedStyle(el).visibility !== 'hidden';
  const submitter = el => {
    const tag = el.tagName.toLowerCase();
    if (tag === 'input')
      return ['submit', 'image'].includes((el.getAttribute('type') || '').toLowerCase());
    if (tag !== 'button') return false;
    const type = (el.getAttribute('type') || 'submit').toLowerCase();
    return type === 'submit' && !!(el.form || el.closest('form'));
  };
  window.__fuzzlabA = (window.__fuzzlabA || 0) + 1;
  const run = window.__fuzzlabA, items = [];
  for (const el of document.querySelectorAll(SEL)) {
    if (items.length >= maxScan) break;
    if (submitter(el)) continue;
    const id = `a${run}n${items.length}`;
    el.setAttribute('data-fuzzlab-aff', id);
    const popup = (el.getAttribute('aria-haspopup') || 'false').toLowerCase() !== 'false'
      || el.getAttribute('aria-expanded') === 'false';
    items.push({id, link: el.matches('a[href]') ? el.href : null, popup,
      icon: !!el.querySelector('svg, img, i, [class*="icon"]'), visible: shown(el),
      disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true'});
  }
  return {run, items};
}
"""


def _labels_js() -> str:
    """``els => [[id, [text, aria, icons]], ...]``: `spa.LABELS_JS`, the one label
    reader (PA-0003), applied to each marked element."""
    from fuzzlab.tools.spa import LABELS_JS
    return ("els => els.map(e => [e.getAttribute('data-fuzzlab-aff'), (" + LABELS_JS
            + ")(e)])")


def _without_account_words(text: str) -> str:
    """``text``'s tokens without the account words and pairs (`ACCOUNT_WORDS`,
    `ACCOUNT_PAIRS`): a combined "Login / Register" or "Log In / Sign Up" label is an
    affordance (review B, B2(a)); the form gates protect the fill."""
    tokens = [t.lower() for t in name_tokens(text or "")]
    drop = {i for i, t in enumerate(tokens) if t in ACCOUNT_WORDS}
    for i, pair in enumerate(zip(tokens, tokens[1:])):
        if pair in ACCOUNT_PAIRS:
            drop |= {i, i + 1}
    return " ".join(t for i, t in enumerate(tokens) if i not in drop)


def affordance_refusal(labels) -> str | None:
    """Why a control is not a login affordance to follow or click, or None: its label
    is not a login label (`detect.login_affordance`), or it fails the label gates every
    click passes (`spa.submitter_glyph`; `spa.label_refusal` on its text and aria-label,
    whose account-word part is waived, `_without_account_words`: destructive, settings
    and transaction words still refuse)."""
    from fuzzlab.session.detect import login_affordance
    from fuzzlab.tools.spa import label_refusal, submitter_glyph
    text, aria, icons = (list(labels or []) + ["", "", ""])[:3]
    if not login_affordance(text, aria):
        return "not a login label"
    glyph = submitter_glyph(icons, text, aria)
    if glyph:
        return f"destructive icon ({glyph!r})"
    for where, value in (("text", text), ("aria-label", aria)):
        why = label_refusal(_without_account_words(value))
        if why:
            return f"{where} {why}"
    return None


def disclosure_refusal(item: dict) -> str | None:
    """Why a control is not a disclosure to open (one level) for a login affordance, or
    None: it announces a popup (``aria-haspopup``, ``aria-expanded=false``), is not a
    link, is visible and enabled, and its label is account-like (`DISCLOSURE_WORDS`) or
    empty with an icon; no destructive glyph, no refused label."""
    from fuzzlab.tools.spa import DESTRUCTIVE_GLYPHS, label_refusal
    if not item.get("popup") or item.get("link") or not item.get("visible") \
            or item.get("disabled"):
        return "not a visible, enabled popup control"
    text, aria, icons = (list(item.get("labels") or []) + ["", "", ""])[:3]
    if any(g in DESTRUCTIVE_GLYPHS for g in (icons or "").lower().split()):
        return "destructive icon"
    tokens = name_tokens(f"{text} {aria}")
    if not tokens:
        return None if item.get("icon") else "no label and no icon"
    if not set(tokens) <= DISCLOSURE_WORDS:
        return "not an account menu"
    for value in (text, aria):
        if label_refusal(value):
            return "refused label"
    return None


def _read_affordances(page) -> list[dict]:
    """The page's affordance elements (`AFFORDANCES_JS`), each with its labels
    (`spa.LABELS_JS`) and its ordinal among the elements with the same labels."""
    marked = page.evaluate(AFFORDANCES_JS, MAX_AFFORDANCES)
    run = marked.get("run")
    labels = dict(page.eval_on_selector_all(f'[data-fuzzlab-aff^="a{run}n"]',
                                            _labels_js()))
    counts: dict[tuple, int] = {}
    items = []
    for item in marked.get("items") or []:
        item["labels"] = list(labels.get(item["id"]) or ["", "", ""])
        key = tuple(item["labels"])
        item["ordinal"] = counts.get(key, 0)
        counts[key] = item["ordinal"] + 1
        items.append(item)
    return items


@dataclass
class _Candidate:
    """A place to look for the login form: a ``link`` (an affordance's in-scope href,
    or a navigation a click triggered), a ``click`` (``steps``: the labels and ordinal
    of each control to click from the base page, a disclosure first when there is
    one) or a ``path`` (a script or link route by rank, `detect.login_path_match`)."""
    kind: str
    key: str
    url: str = ""
    steps: tuple = ()
    rank: int = 0
    #: the order (design section 6, review B): 0 an exact login label, 1 a rank-1 path,
    #: 2 a label that only contains a login word, 3 a rank-2 path (`_tier`)
    tier: int = 0

    def describe(self) -> str:
        if self.kind == "click":
            names = [s[0][0] or s[0][1] or "(icon)" for s in self.steps]
            return "click " + " > ".join(repr(n) for n in names)
        return ("link " if self.kind == "link" else f"path (rank {self.rank}) ") + \
            _short(self.url)


def _short(url: str) -> str:
    """A URL as a diagnosis names it: its path and SPA fragment, never its query."""
    parts = urlsplit(url or "")
    frag = parts.fragment.split("?", 1)[0]
    return (parts.path or "/") + (f"#{frag}" if frag else "")


class _Refused(Exception):
    """A candidate that was not tried to the end (hidden, gone, its labels changed)."""


class _Discovery:
    """Finds the login form after the base page showed none (BUG-0148, design sections
    3 and 6): the page's own login affordances first -- in-scope links visited with
    `navguard.navigate`, other controls clicked with `spa.click_vetted` in the reveal
    window (`LoginGate.window_refusal`, `LoginGate.ws_hold`), one level of an account
    menu opened -- then path candidates by rank (`detect.login_path_match`: rank 1, then
    rank 2). At most `MAX_ROUTES` distinct candidates; each one's failure (hidden,
    detached, refused) is recorded and the next is tried. Nothing here fills or submits:
    the first form `_pick_form` accepts ends the search."""

    def __init__(self, page, gate: LoginGate, base_url: str, inflight, timeout_ms: int,
                 cancelled: threading.Event, refusals: list[str], notes: set):
        self.page, self.gate, self.base = page, gate, base_url
        self.inflight, self.timeout_ms, self.cancelled = inflight, timeout_ms, cancelled
        self.refusals, self.notes = refusals, notes
        self.tried: list[str] = []
        self.keys: set[str] = set()
        self.affordances = 0
        self.dirty = False            # the page has left the base page's first state
        self.started = time.monotonic()
        self.budget_spent = False

    def over_budget(self) -> bool:
        """Has the search spent `DISCOVERY_BUDGET_S` (review A, A10)? Recorded once."""
        if time.monotonic() - self.started < DISCOVERY_BUDGET_S:
            return False
        if not self.budget_spent:
            self.budget_spent = True
            self.refusals.append(f"the search's time budget ({DISCOVERY_BUDGET_S:.0f} s) "
                                 f"was spent; the remaining candidates were not tried")
        return True

    @staticmethod
    def _navigates(link, here: str) -> bool:
        """A link that loads another document: http(s), and not this page again
        (``href="#"``, ``#modal`` and ``javascript:`` are clicked instead; review A, A3)."""
        from fuzzlab.tools import spa
        return bool(link) and urlsplit(link).scheme.lower() in ("http", "https") and \
            spa.visit_key(link) != here

    # -- reading -----------------------------------------------------------------------
    def _link(self, url: str, out: list, tier: int = 0) -> None:
        from fuzzlab.tools import spa
        url = url.split("#", 1)[0] if spa.spa_fragment(url) is None else url
        if not self.gate.in_login_scope(url):
            host = _host(url)
            if host not in self.gate.click_out_of_scope:
                self.gate.click_out_of_scope.append(host)
            return
        if spa.route_destructive_reason(url):
            self.refusals.append(f"link {_short(url)}: destructive")
            return
        out.append(_Candidate("link", spa.visit_key(url), url=url, tier=tier))

    def affordance_candidates(self) -> list[_Candidate]:
        """The base page's login links and clicks, then those inside one level of each
        account menu (opened in the reveal window), in document order."""
        from fuzzlab.tools import spa
        try:
            items = _read_affordances(self.page)
        except _playwright_errors() as exc:              # the page went away meanwhile
            self.refusals.append(f"the base page's controls: {_first_line(exc)}")
            return []
        out: list[_Candidate] = []
        here = spa.visit_key(self.page.url)
        for item in items:
            if affordance_refusal(item["labels"]) is not None:
                continue
            self.affordances += 1
            tier = _tier(item["labels"])
            link = item.get("link")
            if self._navigates(link, here):
                self._link(link, out, tier)
            else:
                step = (tuple(item["labels"]), item["ordinal"])
                out.append(_Candidate("click", json.dumps([step]), steps=(step,),
                                      tier=tier))
        opened = 0
        for item in items:
            if opened >= MAX_DISCLOSURES or self.over_budget():
                break
            if disclosure_refusal(item) is not None:
                continue
            opened += 1
            outer = (tuple(item["labels"]), item["ordinal"])
            try:
                self._restore()
                self._click([outer])
                inner = _read_affordances(self.page)
            except (_Refused, *_playwright_errors()) as exc:
                self.refusals.append(f"menu {outer[0][0] or outer[0][1] or '(icon)'!r}: "
                                     f"{_first_line(exc)}")
                continue
            before = {(tuple(i["labels"]), i["ordinal"]) for i in items}
            inner_here = spa.visit_key(self.page.url)
            for sub in inner:
                step = (tuple(sub["labels"]), sub["ordinal"])
                if step in before or affordance_refusal(sub["labels"]) is not None:
                    continue
                self.affordances += 1
                tier = _tier(sub["labels"])
                link = sub.get("link")
                if self._navigates(link, inner_here):
                    self._link(link, out, tier)
                else:
                    out.append(_Candidate("click", json.dumps([outer, step]),
                                          steps=(outer, step), tier=tier))
        return out

    def path_candidates(self) -> list[_Candidate]:
        """Script routes (`LoginGate.routes`) and link routes that are login candidates
        (`detect.login_path_match`, mode ``candidate``): rank 1 before rank 2, each in
        the order found; never the root, a parameterised, destructive or out-of-scope
        route."""
        from playwright.sync_api import Error as PlaywrightError

        from fuzzlab.session.detect import MODE_CANDIDATE, login_path_match
        from fuzzlab.tools import spa
        page = self.page
        try:
            hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        except PlaywrightError:                      # no links readable: scripts only
            hrefs = []
        frag = spa.spa_fragment(page.url) or ""
        link_frags = [spa.spa_fragment(h) for h in hrefs]
        hash_mode = bool(frag) or any(f is not None for f in link_frags)
        hashbang = frag.startswith("!/") or any(f and f.startswith("!/") for f in link_frags)
        found: list[tuple[int, str]] = []
        for name in list(self.gate.routes) + [f.split("?", 1)[0] for f in link_frags if f]:
            kind, _reason = spa.classify_route(name)
            rank = login_path_match(spa.normalise_route(name), mode=MODE_CANDIDATE) \
                if kind == spa.ROUTE_OK else None
            if rank:
                found.append((rank, spa.route_url(page.url, name, hash_mode=hash_mode,
                                                  hashbang=hashbang, base=self.base)))
        for h in hrefs:
            if spa.spa_fragment(h) is None:
                rank = login_path_match(h, mode=MODE_CANDIDATE)
                if rank:
                    found.append((rank, h.split("#", 1)[0]))
        out = []
        here = spa.visit_key(page.url)
        for rank, url in sorted(found, key=lambda pair: pair[0]):      # stable
            if spa.visit_key(url) == here or not self.gate.in_login_scope(url) \
                    or spa.route_destructive_reason(url):
                continue
            out.append(_Candidate("path", spa.visit_key(url), url=url, rank=rank,
                                  tier=1 if rank == 1 else 3))
        return out

    # -- acting --------------------------------------------------------------------------
    def _restore(self) -> None:
        """Back to the base page (design section 3, A5), unless it is still as loaded:
        each click starts from the page its controls were read on."""
        from fuzzlab.tools.navguard import navigate
        if self.dirty:
            _alive(self.cancelled)
            navigate(self.page, self.base, timeout_ms=self.timeout_ms)
            _settle(self.page, self.inflight, SETTLE_MS, self.cancelled)
            self.dirty = False

    def _click(self, steps) -> None:
        """Click each step's control, found again by its labels and ordinal, through
        `spa.click_vetted` in the reveal window (`LoginGate.clicking`), and settle."""
        from fuzzlab.tools import spa
        for labels, ordinal in steps:
            same = [i for i in _read_affordances(self.page)
                    if tuple(i["labels"]) == tuple(labels)]
            if len(same) <= ordinal:
                raise _Refused("the control was not found again")
            item = same[ordinal]
            if not item.get("visible"):
                raise _Refused("not visible")
            if item.get("disabled"):
                raise _Refused("disabled")
            _alive(self.cancelled)
            self.dirty = True
            self.gate.clicking = True
            try:
                how = spa.click_vetted(self.page, f'[data-fuzzlab-aff="{item["id"]}"]',
                                       list(labels),
                                       timeout_ms=min(self.timeout_ms, CLICK_MS))
                if how is None:
                    raise _Refused("its labels changed before the click")
                _settle(self.page, self.inflight, SETTLE_MS, self.cancelled)
            finally:
                self.gate.clicking = False

    def run(self, candidates: list[_Candidate]):
        """Try ``candidates`` in order (a click's captured navigations right after it),
        at most `MAX_ROUTES` distinct ones; the first acceptable form, or None."""
        from fuzzlab.tools.navguard import navigate
        queue = list(candidates)
        while queue:
            cand = queue.pop(0)
            if cand.key in self.keys:
                continue
            if self.over_budget():
                break
            if len(self.keys) >= MAX_ROUTES:
                self.refusals.append(f"{len(queue) + 1} more candidate(s) not tried "
                                     f"(at most {MAX_ROUTES})")
                break
            self.keys.add(cand.key)
            self.tried.append(cand.describe())
            self.gate.captured.clear()
            before = len(self.refusals)
            try:
                if cand.kind == "click":
                    self._restore()
                    self._click(cand.steps)
                else:
                    _alive(self.cancelled)
                    self.dirty = True
                    navigate(self.page, cand.url, timeout_ms=self.timeout_ms)
                    _settle(self.page, self.inflight, SETTLE_MS, self.cancelled)
                picked = _pick_form(self.page, self.base, self.refusals, self.timeout_ms,
                                    self.notes)
            except _Refused as exc:
                self.refusals.append(f"{cand.describe()}: {exc}")
                continue
            except _playwright_errors() as exc:
                self.refusals.append(f"{cand.describe()}: {_first_line(exc)}")
                continue
            if picked is not None:
                return picked
            if len(self.refusals) == before:
                self.refusals.append(f"{cand.describe()}: no form with a password "
                                     f"control")
            if cand.kind == "click":
                found: list[_Candidate] = []
                for url in list(self.gate.captured):
                    self._link(url, found)
                queue[:0] = [c for c in found if c.key not in self.keys]
        return None

    def diagnosis(self) -> str:
        """Why no login form was found: every candidate and why it failed, the writes
        aborted before the window, an affordance leading off the login scope, an
        identifier-first page, no affordance at all."""
        parts = []
        if self.tried:
            parts.append("tried: " + ", ".join(self.tried))
        if self.refusals:
            parts.append("refused: " + "; ".join(self.refusals))
        if not self.tried and not self.refusals:
            parts.append("no rendered form with a password control on the base page, "
                         "and no login candidate")
        writes = self.gate.prewindow_writes
        if writes:
            named = ", ".join(writes[:MAX_NAMED_WRITES])
            more = len(writes) - MAX_NAMED_WRITES
            parts.append(f"{self.gate.prewindow_write_count} write(s) aborted before "
                         f"the login window: {named}"
                         + (f" and {more} more" if more > 0 else "")
                         + " (a read the app sends as a POST, such as a GraphQL query, "
                           "is aborted too)")
        for host in self.gate.click_out_of_scope:
            parts.append(f"a login affordance leads to {host}, outside the login scope "
                         f"(needs --auth-origin <its origin> if it belongs to this app)")
        if IDENTIFIER_FIRST in self.notes:
            parts.append(IDENTIFIER_FIRST)
        if not self.affordances:
            parts.append(NO_AFFORDANCE)
        return "; ".join(parts)


def _tier(labels) -> int:
    """An affordance's place in the order: 0 for an exact login label, 2 for one that
    only contains a login word (`detect.affordance_rank`), so a rank-1 path (1) comes
    between them."""
    from fuzzlab.session.detect import AFFORDANCE_EXACT, affordance_rank
    text, aria = (list(labels or []) + ["", ""])[:2]
    return 0 if affordance_rank(text, aria) == AFFORDANCE_EXACT else 2


def _playwright_errors() -> tuple:
    from playwright.sync_api import Error as PlaywrightError
    return (PlaywrightError,)


def _identifier_only(form: dict) -> bool:
    """A form that asks for a user field and nothing else a user types, with no
    password control: the first step of an identifier-first login."""
    from fuzzlab.session.detect import USERNAME_HINT
    typed = [(n, k) for n, k in form.get("controls") or []
             if k in ("text", "email", "tel", "password", "textarea", "search", "number")]
    return len(typed) == 1 and typed[0][1] in ("text", "email") and \
        (typed[0][1] == "email" or bool(USERNAME_HINT.search(typed[0][0] or "")))


def _pick_form(page, base_url: str, refusals: list[str], timeout_ms: int,
               notes: set | None = None):
    """The first acceptable login form on the current page, or None. A form whose
    password control is not visible (a pre-rendered hidden modal) is refused, so the
    search goes on to the control that opens it (BUG-0148, design section 4; measured:
    ``is_enabled`` is true for a hidden control, and waits out its timeout for a mark
    `spa.FORMS_JS` re-assigned to an enclosing container)."""
    from playwright.sync_api import Error as PlaywrightError

    from fuzzlab.tools import spa
    route = spa.route_of(page.url, base_url)
    for form in page.evaluate(spa.FORMS_JS, 20):
        if not spa.has_password(form):
            if notes is not None and _identifier_only(form):
                notes.add(IDENTIFIER_FIRST)
            continue
        why = login_form_refusal(form, route)
        if why is None:
            pw = next(cid for (n, k), cid in zip(form["controls"], form["ids"])
                      if k == "password")
            try:
                if not page.is_visible(_sel(pw)):
                    why = "its password control is not visible"
                elif not page.is_enabled(_sel(pw), timeout=timeout_ms):
                    why = "its password control is disabled"
            except PlaywrightError as exc:
                why = f"its password control could not be read ({_first_line(exc)})"
        if why is None:
            return form, route
        refusals.append(f"{'/' + route if route else 'the base page'}: {why}")
    return None


def _username_control(form: dict) -> str | None:
    """The user field: `detect.USERNAME_HINT` over its name (`FORMS_JS`: name, id,
    formcontrolname, aria-label or placeholder) or ``type=email``, else the only one
    (`login_shaped` guarantees exactly one)."""
    from fuzzlab.session.detect import USERNAME_HINT
    users = [(n, k, cid) for (n, k), cid in zip(form["controls"], form["ids"])
             if k in ("text", "email", "tel")]
    for name, kind, cid in users:
        if kind == "email" or USERNAME_HINT.search(name or ""):
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
                       request_refusal=gate.request_refusal, observe=gate.observe,
                       window=gate.window_refusal, ws_hold=gate.ws_hold)
            page = context.new_page()
            inflight = _Inflight(page)
            page.on("dialog", lambda d: d.dismiss())    # an app's alert is never ours
            _alive(cancelled)
            # BUG-0138 (CC-SESS-0024): the commit, then a bounded load: a page whose
            # script navigates to a refused URL while it is parsed is not waited out;
            # with no form on it the login fails loudly, and fast
            navigate(page, base_url, timeout_ms=timeout_ms)
            _settle(page, inflight, SETTLE_MS, cancelled)
            refusals: list[str] = []
            notes: set = set()
            picked = _pick_form(page, base_url, refusals, timeout_ms, notes)
            if picked is None:
                # BUG-0148 (design section 6): the base page's own login affordances,
                # then path candidates by rank; at most MAX_ROUTES distinct ones
                finder = _Discovery(page, gate, base_url, inflight, timeout_ms,
                                    cancelled, refusals, notes)
                candidates = finder.affordance_candidates()
                try:
                    finder._restore()
                except PlaywrightError as exc:
                    # review A, A7: the path candidates and the diagnosis still follow
                    refusals.append(f"back to the base page: {_first_line(exc)}")
                candidates += finder.path_candidates()
                candidates.sort(key=lambda c: c.tier)         # stable: document order
                picked = finder.run(candidates)
                if picked is None:
                    raise BrowserLoginError("no login form was found in the browser ("
                                            + finder.diagnosis() + ")")
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
        probes=list(gate.probes), page_url=page_url, floor_https=gate.floor_https,
        aborted_writes=list(gate.prewindow_writes))


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
    (reviewer A7): a localStorage origin passes ``in_scope``; a cookie is kept when its
    domain matches the host of a ``scope_urls`` entry that is itself in scope."""
    state = state or {}
    hosts = [h for h in (canonical_host(u) for u in scope_urls if u and in_scope(u)) if h]

    def cookie_ok(c: dict) -> bool:
        domain = canonical_host("http://" + (c.get("domain") or "").lstrip(".") + "/")
        return domain is not None and any(h == domain or h.endswith("." + domain)
                                          for h in hosts)
    origins = [o for o in state.get("origins", []) or []
               if in_scope((o.get("origin") or "").rstrip("/") + "/")]
    return {"cookies": [dict(c) for c in state.get("cookies", []) or [] if cookie_ok(c)],
            "origins": [{"origin": o["origin"],
                         "localStorage": [dict(e) for e in o.get("localStorage") or []]}
                        for o in origins]}
