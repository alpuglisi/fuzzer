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
#: The public name of the user-field hint (PA-0154(c): no private import elsewhere).
USERNAME_HINT = _USERNAME_HINT
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
        return LoginForm(action_url, method, fields, username_field, password_field,
                         submitter_overrides(form))
    return None


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


# --- the login vocabulary and its one owner (SP-16; BUG-0122, BUG-0148) ---------------
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

#: The public login vocabulary (BUG-0148, PA-0154(c)): every other module takes it from
#: here, never from a ``_LOGIN_*`` name and never as a copy. One login word ...
LOGIN_WORDS = _LOGIN_TOKENS
#: ... or two adjacent tokens that are one.
LOGIN_PAIRS = frozenset({("sign", "in"), ("log", "in"), ("log", "on")})
#: The path tokens of a login **endpoint** (where a login request is sent): a login
#: word, or a session / token / auth resource (``/api/accounts/session``,
#: ``/oauth/token``). Used by the browser login's account-endpoint rule and its form
#: gate's override (`browserlogin.LOGIN_PATH_TOKENS` is this set).
LOGIN_ENDPOINT_TOKENS = LOGIN_WORDS | frozenset({
    "session", "sessions", "auth", "authenticate", "authentication", "token", "tokens"})
#: Words a login link or button may carry besides its login word or pair ("Sign in to
#: your account", "Log in here"): dropped before the label is compared (BUG-0148).
AFFORDANCE_FILLER = frozenset({"to", "your", "my", "account", "here", "now", "please"})
#: A label is a login affordance when its tokens, filler dropped, are exactly one of
#: these. "Sign up", "Log out", "Login with Google" and "Forgot password" are not.
_AFFORDANCE_LABELS = frozenset({(w,) for w in LOGIN_WORDS} | set(LOGIN_PAIRS))

#: `login_path_match` modes.
MODE_LOGOUT = "logout"
MODE_CANDIDATE = "candidate"
#: Candidate ranks: a whole login segment (or ``session(s)/new``), then a final token.
RANK_SEGMENT = 1
RANK_TOKEN = 2


def _stem(segment: str) -> str:
    """A path segment without its extension (``login.php`` -> ``login``)."""
    return segment.rsplit(".", 1)[0] if "." in segment else segment


def _login_segment(segment: str, final_token: bool) -> bool:
    from fuzzlab.core.redaction import name_tokens
    stem = _stem(segment.lower())
    if stem in _LOGIN_SEGMENTS:
        return True
    tokens = name_tokens(stem) if final_token else []
    return bool(tokens) and tokens[-1] in _LOGIN_TOKENS


def _segments_match(segments: list[str], query: str, final_token: bool) -> bool:
    """The anchored rule over a path's non-empty segments and its query."""
    if not segments:
        return False
    if len(segments) >= 2 and segments[-1].lower() == "new" and \
            segments[-2].lower() in ("session", "sessions"):
        return True
    if _login_segment(segments[-1], final_token):
        return True
    if _stem(segments[-1].lower()) in _ROUTER_SEGMENTS:
        for key, value in parse_qsl(query, keep_blank_values=True):
            routed = [s for s in value.split("/") if s]
            if key.lower() in _ROUTE_PARAMS and routed and \
                    _login_segment(routed[-1], final_token):
                return True
    return False


def _final_login_tokens(segment: str) -> bool:
    """The segment's own-case `name_tokens` (``UserLogin`` -> user, login) end in a login
    word or a login pair. Tokens only: never a prefix or suffix of a run-together word
    (``userlogin``, ``loginhistory``: PA-0122(1))."""
    from fuzzlab.core.redaction import name_tokens
    tokens = name_tokens(_stem(segment))
    return bool(tokens) and (tokens[-1] in LOGIN_WORDS
                             or tuple(tokens[-2:]) in LOGIN_PAIRS)


def _path_and_query(target: str, *, route: bool) -> tuple[str, str] | None:
    """A URL's path and query, or (with ``route``) a bare SPA route's (``#/auth/sign-in``,
    ``auth/sign-in?x=1``); None for a non-web URL."""
    parts = urlsplit(target or "")
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        return None
    if route and not parts.scheme and not parts.netloc and not parts.path and \
            parts.fragment:
        route, _sep, query = parts.fragment.lstrip("!").partition("?")
        return route, query
    return parts.path, parts.query


def login_path_match(target: str, *, mode: str, final_token: bool = True):
    """**The** login-URL rule (SP-16; BUG-0122, BUG-0148). Anchored, never a substring:

    * ``mode="logout"`` (`MODE_LOGOUT`): a bool, `looks_like_login_url`'s rule -- the
      last non-empty path segment names a login page (whole, or, with ``final_token``,
      as its final token), or the path ends in ``session(s)/new``, or a front
      controller's routing parameter does. Only ``http``/``https`` URLs.
      ``ba_insecure_login_1.php``, ``login_form.php`` and ``loginhistory`` are not login
      URLs (PA-0122). It decides session state (a redirect to it is a logout), so it is
      deliberately narrow.
    * ``mode="candidate"`` (`MODE_CANDIDATE`): where the browser login may *look* for a
      login form (a visit, then the form gates). `RANK_SEGMENT` (1) for a whole login
      segment or the REST "new session" pair (the logout rule without its final-token
      half); `RANK_TOKEN` (2) for a final `name_tokens` token or a final login pair
      (``wp-login``, ``UserLogin``, ``user-sign-in``); None otherwise. No prefix or
      suffix of a run-together word: ``userlogin`` is found by its page's "Log in"
      affordance (`login_affordance`), the signal every technology shares, not by its
      path. Every logout positive is a candidate at some rank (tested)."""
    where = _path_and_query(target, route=mode == MODE_CANDIDATE)
    if where is None:
        return False if mode == MODE_LOGOUT else None
    path, query = where
    segments = [s for s in path.split("/") if s]
    if mode == MODE_LOGOUT:
        return _segments_match(segments, query, final_token)
    if mode != MODE_CANDIDATE:
        raise ValueError(f"unknown login_path_match mode {mode!r}")
    if _segments_match(segments, query, False):
        return RANK_SEGMENT
    if _segments_match(segments, query, True) or \
            (segments and _final_login_tokens(segments[-1])):
        return RANK_TOKEN
    return None


def looks_like_login_url(url: str, *, final_token: bool = True) -> bool:
    """`login_path_match` in its ``logout`` mode (unchanged since BUG-0122): used by
    `redirect_is_logout` and the probe sender's redirect rule."""
    return login_path_match(url, mode=MODE_LOGOUT, final_token=final_token)


def login_affordance(text: str, aria: str = "") -> bool:
    """Is a link or button labelled as **the** way to log in (BUG-0148)? Its
    aria-label / title (the accessible name) or its text, as `name_tokens` with
    `AFFORDANCE_FILLER` dropped, is exactly ``login``, ``signin``, ``logon``,
    ``log in``, ``sign in`` or ``log on``. English labels only (a stated residual). The
    caller still applies the label gates to both (`browserlogin.affordance_refusal`)."""
    from fuzzlab.core.redaction import name_tokens

    def match(label: str) -> bool:
        tokens = tuple(t for t in name_tokens(label or "") if t not in AFFORDANCE_FILLER)
        return tokens in _AFFORDANCE_LABELS
    return match(aria) or match(text)


#: At most this many links are read from one page by `login_links`.
MAX_PAGE_LINKS = 2000


def login_links(html: str, page_url: str) -> list[str]:
    """The login candidates a server-rendered page links to, for the requests-side
    discovery (`SessionManager._discover_login_form`, BUG-0148): first the ``<a href>``
    whose text (or aria-label / title) is a login affordance (`login_affordance`), then
    those whose path is a `RANK_SEGMENT` login candidate, each in document order,
    absolute, without fragment, deduplicated. Nothing here decides whether one may be
    fetched (the caller's navigation rule does)."""
    soup = BeautifulSoup(html or "", "html.parser")
    afford, ranked = [], []
    for a in soup.find_all("a", href=True)[:MAX_PAGE_LINKS]:
        href = (a.get("href") or "").strip()
        if not href or href.startswith("#"):
            continue
        url = urljoin(page_url, href).split("#", 1)[0]
        if urlsplit(url).scheme.lower() not in ("http", "https"):
            continue
        text = " ".join(a.get_text(" ").split())
        aria = a.get("aria-label") or a.get("title") or ""
        if login_affordance(text, aria):
            afford.append(url)
        elif login_path_match(url, mode=MODE_CANDIDATE) == RANK_SEGMENT:
            ranked.append(url)
    out: list[str] = []
    for url in afford + ranked:
        if url not in out:
            out.append(url)
    return out


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
