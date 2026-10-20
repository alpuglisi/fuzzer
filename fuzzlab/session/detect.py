"""Dynamic login/session detection (D13).

Detects the common login shapes automatically — a login form (→ session cookie),
a JSON login (→ bearer/JWT), or an HTTP Basic/Bearer challenge — plus success and
logout signals. Anything it cannot parse is reported as "not detected" so the
session manager can fail loudly (no silent unauthenticated run).

No cryptography dependency: a JWT's `exp` is read by decoding the payload segment
directly (base64url). We never verify or trust the token — only time its refresh.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlsplit

from bs4 import BeautifulSoup

from fuzzlab.core.forms import (FormEntries, form_entries, is_disabled, owned_controls,
                                submitter_overrides)

_USERNAME_HINT = re.compile(r"user|email|login|uname|account", re.I)
_TOKEN_KEYS = {"token", "access_token", "accesstoken", "jwt", "id_token", "bearer"}


# --- JWT ---------------------------------------------------------------------
def decode_jwt_exp(token: str) -> float | None:
    """Return a JWT's `exp` (unix ts) by decoding its payload, or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    seg = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(seg))
    except Exception:  # noqa: BLE001 - malformed token payload
        return None
    exp = payload.get("exp")
    return float(exp) if isinstance(exp, (int, float)) else None


# --- login form --------------------------------------------------------------
@dataclass
class LoginForm:
    action_url: str
    method: str
    #: The form's entry list as a browser would send it (BUG-0110): ordered pairs,
    #: duplicates kept, the submitter's name=value included.
    fields: FormEntries
    username_field: str | None
    password_field: str
    #: ``formaction``/``formmethod``/``formenctype`` on the submitter. Not applied:
    #: the session manager refuses a form that carries any (BUG-0110).
    submitter_overrides: tuple[str, ...] = ()
    #: Where the page's own script sends this form as JSON (`json_login_target`,
    #: FR-SESS-21): a form with no ``action`` whose page script POSTs one login URL with
    #: a JSON body. None: the form is submitted as a browser would natively.
    json_url: str | None = None

    def fill(self, username: str, password: str) -> FormEntries:
        """The entry list with the credentials put in place of the username and
        password entries (hidden fields such as a CSRF token are carried through)."""
        data = self.fields
        if self.username_field:
            data = data.replace(self.username_field, username)
        return data.replace(self.password_field, password)


def is_login_page(html: str) -> bool:
    """True if the HTML contains a password input (looks like a login page)."""
    soup = BeautifulSoup(html or "", "html.parser")
    return soup.find("input", attrs={"type": "password"}) is not None


def shows_login_form(html: str, page_url: str, login_url: str | None,
                     login_fields=None) -> bool:
    """True if the page shows *this session's* login form: a password form that posts
    to ``login_url`` (canonical origin and path), or whose entry names are exactly
    ``login_fields`` (the login form re-rendered in place, posting to itself). Any
    password field is not enough — an LDAP-settings, change-password or SQLi-login
    lab page has one (BUG-0113). With no known ``login_url``, any password input counts
    (the old, coarse rule)."""
    if not login_url:
        return is_login_page(html)
    from fuzzlab.core.urls import url_key
    wanted = frozenset(login_fields) if login_fields else None
    soup = BeautifulSoup(html or "", "html.parser")
    for form in soup.find_all("form"):
        if form.find("input", attrs={"type": "password"}) is None:
            continue
        action = form.get("action")
        target = urljoin(page_url, action) if action else page_url
        if url_key(target) == url_key(login_url):
            return True
        if wanted is not None and frozenset(form_entries(form).names()) == wanted:
            return True
    return False


def find_login_form(html: str, page_url: str) -> LoginForm | None:
    """Find the login form on a page: the form containing a password input."""
    soup = BeautifulSoup(html or "", "html.parser")
    for form in soup.find_all("form"):
        password_field = None
        username_field = None
        # What a browser would POST on an unmodified submit (BUG-0110): the submitter's
        # name=value, a select's default option, only checked boxes, no disabled controls.
        fields = form_entries(form)
        text_candidates: list[str] = []
        for el in owned_controls(form):
            name = el.get("name")
            if el.name != "input" or not name or is_disabled(el):
                continue
            itype = (el.get("type") or "text").lower()
            if itype == "password" and password_field is None:
                password_field = name
            elif itype in ("text", "email", "tel", "") and name:
                text_candidates.append(name)
        if not password_field:
            continue
        # username: prefer a name that hints at user/email, else first text input.
        for cand in text_candidates:
            if _USERNAME_HINT.search(cand):
                username_field = cand
                break
        if username_field is None and text_candidates:
            username_field = text_candidates[0]
        action = form.get("action")
        action_url = urljoin(page_url, action) if action else page_url
        method = (form.get("method") or "GET").upper()
        json_url = None if action is not None else json_login_target(soup, page_url)
        return LoginForm(action_url, method, fields, username_field, password_field,
                         submitter_overrides(form), json_url=json_url)
    return None


#: A script's request to a URL literal with a write method (FR-SESS-21): an
#: ``XMLHttpRequest`` ``open``, a ``fetch`` with a ``method``, or a client library's
#: ``post``. A URL built at run time (a template with ``${``) is not read.
_SCRIPT_POSTS = (
    re.compile(r"""\.open\(\s*(['"])POST\1\s*,\s*(['"`])(?P<url>[^'"`$\s]+)\2""", re.I),
    re.compile(r"""\bfetch\(\s*(['"`])(?P<url>[^'"`$\s]+)\1\s*,\s*\{[^{}]{0,400}?"""
               r"""\bmethod\s*:\s*(['"])POST\3""", re.I),
    re.compile(r"""\b(?:axios|\$|\$http|http|this\.http|api|client)\.post\(\s*(['"`])"""
               r"""(?P<url>[^'"`$\s]+)\1"""),
)
#: The script builds a JSON body.
_SCRIPT_JSON = re.compile(r"JSON\.stringify|application/json", re.I)


def json_login_target(soup, page_url: str) -> str | None:
    """Where a page's own inline script POSTs its login form as JSON (FR-SESS-21): the
    one URL literal, among the script's write requests, whose last path segment is a
    login word (`_LOGIN_SEGMENTS`), in a script that builds a JSON body (the evidence
    is read per ``<script>``: another script's JSON says nothing of this one). Resolved
    against the page (a protocol-relative ``//host/login`` included). None when there
    is no such request, or more than one (the login is then not guessed)."""
    found = set()
    for script in soup.find_all("script"):
        if script.get("src"):
            continue
        text = script.string or script.get_text() or ""
        if not _SCRIPT_JSON.search(text):
            continue
        for rx in _SCRIPT_POSTS:
            for m in rx.finditer(text):
                url = urljoin(page_url, m.group("url"))
                segment = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1].lower()
                if segment.rsplit(".", 1)[0] in _LOGIN_SEGMENTS:
                    found.add(url)
    return found.pop() if len(found) == 1 else None


# --- session credential from a login response --------------------------------
@dataclass
class DetectedCredential:
    kind: str                                    # 'cookie' | 'bearer' | 'basic'
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    token_exp: float | None = None


def _lower_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in (headers or {}).items()}


def parse_set_cookie(value: str) -> dict[str, str]:
    """Best-effort: first name=value of a single Set-Cookie header."""
    if not value:
        return {}
    first = value.split(";", 1)[0].strip()
    name, sep, val = first.partition("=")
    return {name: val} if sep else {}


def find_token_in_json(obj: object) -> str | None:
    """Recursively find a token-ish string value under a known key."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key.lower() in _TOKEN_KEYS and isinstance(val, str) and val:
                return val
        for val in obj.values():
            found = find_token_in_json(val)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_token_in_json(item)
            if found:
                return found
    return None


def detect_session_credential(status: int, headers: dict[str, str], body: str,
                              cookies: dict[str, str] | None = None
                              ) -> DetectedCredential | None:
    """Detect what a login response established, or None if undetectable."""
    low = _lower_headers(headers)
    # 1. Cookies (prefer a jar the caller parsed; fall back to the header).
    if cookies:
        return DetectedCredential(kind="cookie", cookies=dict(cookies))
    if "set-cookie" in low:
        parsed = parse_set_cookie(low["set-cookie"])
        if parsed:
            return DetectedCredential(kind="cookie", cookies=parsed)
    # 2. A token/JWT in a JSON body -> bearer.
    if body:
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            data = None
        if data is not None:
            token = find_token_in_json(data)
            if token:
                return DetectedCredential(
                    kind="bearer",
                    headers={"Authorization": f"Bearer {token}"},
                    token_exp=decode_jwt_exp(token),
                )
    # 3. An auth challenge -> Basic/Bearer (manager fills credentials).
    if status == 401 and "www-authenticate" in low:
        scheme = "basic" if "basic" in low["www-authenticate"].lower() else "bearer"
        return DetectedCredential(kind=scheme)
    return None


#: A path segment (lower-cased, extension stripped) that names a login page, whole.
_LOGIN_SEGMENTS = frozenset({"login", "signin", "sign_in", "sign-in", "log_in", "log-in",
                             "logon"})
#: ... or, only when the session's login URL is unknown, whose final `name_tokens` token
#: is one of these (``wp-login``, ``user_login``), never a token in the middle
#: (``ba_insecure_login_1``, ``login_form``). With a known login URL, an app page named
#: ``xss_login.php`` is not a login page (reviewer B, PA-0022's vocabulary check).
_LOGIN_TOKENS = frozenset({"login", "signin", "logon"})
#: Front controllers whose routing parameter names the page (``index.php?page=login``).
_ROUTER_SEGMENTS = frozenset({"index", "default", "main"})
_ROUTE_PARAMS = frozenset({"page", "action", "route", "r", "p", "view"})


def _login_segment(segment: str, final_token: bool) -> bool:
    from fuzzlab.core.redaction import name_tokens
    stem = segment.lower()
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    if stem in _LOGIN_SEGMENTS:
        return True
    tokens = name_tokens(stem) if final_token else []
    return bool(tokens) and tokens[-1] in _LOGIN_TOKENS


def looks_like_login_url(url: str, *, final_token: bool = True) -> bool:
    """Anchored: the URL's last non-empty path segment names a login page (whole, or,
    with ``final_token``, as its final token), or it ends in ``session(s)/new``, or a
    front controller's routing parameter does. Only ``http``/``https`` URLs. Never a
    substring: ``ba_insecure_login_1.php``, ``login_form.php`` and ``loginhistory`` are
    not login URLs (BUG-0122, PA-0122)."""
    parts = urlsplit(url or "")
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        return False
    segments = [s for s in parts.path.split("/") if s]
    if not segments:
        return False
    if len(segments) >= 2 and segments[-1].lower() == "new" and \
            segments[-2].lower() in ("session", "sessions"):
        return True
    if _login_segment(segments[-1], final_token):
        return True
    if segments[-1].lower().rsplit(".", 1)[0] in _ROUTER_SEGMENTS:
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            routed = [s for s in value.split("/") if s]
            if key.lower() in _ROUTE_PARAMS and routed and \
                    _login_segment(routed[-1], final_token):
                return True
    return False


_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _same_login_url(target: str, login_url: str) -> bool:
    """``target`` is the session's login URL: the same host and path (the scheme may
    differ, http <-> https in either direction, default ports only), carrying every
    query parameter of ``login_url`` with its value (query-routed logins; extra ones
    such as ``next`` are allowed). Never a substring test (BUG-0122)."""
    from fuzzlab.core.urls import canonical_origin
    a, b = canonical_origin(target), canonical_origin(login_url)
    if a is None or b is None:
        return False
    if a != b:
        (sa, ra), (sb, rb) = a.split("://", 1), b.split("://", 1)
        ha, pa = ra.rsplit(":", 1)
        hb, pb = rb.rsplit(":", 1)
        if ha != hb or pa != _DEFAULT_PORTS.get(sa) or pb != _DEFAULT_PORTS.get(sb):
            return False
    t, lo = urlsplit(target), urlsplit(login_url)
    if (t.path.rstrip("/") or "/") != (lo.path.rstrip("/") or "/"):
        return False
    have = set(parse_qsl(t.query, keep_blank_values=True))
    return all(pair in have for pair in parse_qsl(lo.query, keep_blank_values=True))


def redirect_is_logout(location: str, page_url: str | None,
                       login_url: str | None) -> bool:
    """A redirect to ``location`` (relative or absolute) sends us to a login page: the
    session's own ``login_url`` (`_same_login_url`), or an anchored login URL
    (`looks_like_login_url`), which also catches a login route other than the one
    recorded. With a known ``login_url`` only whole login segments count, never a final
    token: an app page such as ``xss_login.php`` is not a logout (reviewer B). Only this
    hop is judged (BUG-0122)."""
    target = urljoin(page_url or login_url or "", location)
    if login_url and _same_login_url(target, login_url):
        return True
    return looks_like_login_url(target, final_token=not login_url)


#: Path tokens of an endpoint whose request submits a credential to create, reset or
#: change an account (FR-SESS-22). Deliberately narrower than
#: `browserlogin.ACCOUNT_PATH_TOKENS`: that set (with its ``user``/``account``
#: collections and a bare ``change``) guards writes in the login window, and here it
#: would name ``/api/users/42`` or ``/api/orders/42/change-status`` a credential
#: submission (BUG-0529 review, measured), hiding a lost session.
CREDENTIAL_PATH_TOKENS = frozenset({"register", "registration", "signup", "password",
                                    "passwd", "reset"})
CREDENTIAL_PATH_PAIRS = frozenset({("sign", "up")})


@dataclass(frozen=True)
class LoginFacts:
    """SP-16's facts about one exchange, the inputs SP-56 needs (FR-SESS-22)."""
    credential_submission: bool
    redirect_to_login: bool
    #: The request's path names account creation or a password reset or change
    #: (`CREDENTIAL_PATH_TOKENS`) and is not a login URL: its redirect to the login page
    #: is its success ("now log in"), never a failed login (the runner's setup steps).
    account_submission: bool = False


def _credential_path(url: str) -> bool:
    from urllib.parse import unquote

    from fuzzlab.core.redaction import name_tokens
    tokens = [t.lower() for t in name_tokens(unquote(urlsplit(url or "").path))]
    return bool(set(tokens) & CREDENTIAL_PATH_TOKENS
                or set(zip(tokens, tokens[1:])) & CREDENTIAL_PATH_PAIRS)


def login_facts(url: str, headers=None, *, response_url: str | None = None,
                login_url: str | None = None, entry_names=()) -> LoginFacts:
    """Whether the request to ``url`` submits a credential, and whether its answer
    (``headers``) redirects to a login page -- the one place both are decided for the
    contract runner, the oracle, the blind-SQLi builder and the live filter (SP-16,
    PA-0003; consumed by `core.comparability.response_class`, SP-56).

    - **A credential submission** is a request to the session's own ``login_url`` (when
      known) or an SP-16 login URL (`looks_like_login_url`), to a path naming account
      creation or a password reset (`CREDENTIAL_PATH_TOKENS`), or one whose entries name
      a credential (`core.redaction.is_credential_name`; JSON leaves by their
      `jsonbody.display_name`, a string -- any other name is ignored). Its refusal (a
      401, a redirect back to the login page) is that endpoint's answer, never a lost
      session.
    - **A redirect to a login page**: ``Location`` read in any case, resolved against
      the response's own URL (``response_url``: a PRG follow-up's) or else ``url``, and
      judged by `redirect_is_logout` with the known ``login_url``.
    - **An account submission**: the path names account creation or a password reset
      or change and is not a login URL -- a redirect to the login page is its success.

    Total: odd input reads as "no"."""
    from fuzzlab.core.redaction import is_credential_name
    try:
        at_login = bool(login_url and _same_login_url(url, login_url)) \
            or looks_like_login_url(url)
    except (ValueError, TypeError):
        at_login = False
    try:
        path = _credential_path(url)
    except (ValueError, TypeError):
        path = False
    named = any(isinstance(n, str) and is_credential_name(n) for n in (entry_names or ()))
    location = ""
    try:
        location = next((str(v) for k, v in dict(headers or {}).items()
                         if str(k).lower() == "location"), "")
    except (TypeError, ValueError):
        location = ""
    try:
        redirect = bool(location) and redirect_is_logout(location, response_url or url,
                                                         login_url)
    except (ValueError, TypeError):
        redirect = False
    return LoginFacts(credential_submission=at_login or path or named,
                      redirect_to_login=redirect,
                      account_submission=path and not at_login)


def detect_logout(status: int, headers: dict[str, str], body: str,
                  login_url: str | None = None, page_url: str | None = None,
                  content_check: bool = True, login_fields=None) -> bool:
    """Detect that a response indicates an expired/absent session."""
    if status in (401, 403):
        return True
    low = _lower_headers(headers)
    location = low.get("location", "")
    if location and redirect_is_logout(location, page_url, login_url):
        return True
    # A protected page that came back as *the* login page means we were logged out.
    # With a known login form and page, only that form counts: an app page with a
    # password field of its own is not a logout (BUG-0113). ``content_check=False``
    # (a Basic session) logs out by 401/403 only.
    if status == 200 and content_check:
        if login_url and page_url:
            return shows_login_form(body, page_url, login_url, login_fields)
        return is_login_page(body)
    return False
