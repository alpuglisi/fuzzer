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
from urllib.parse import urljoin

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


def detect_logout(status: int, headers: dict[str, str], body: str,
                  login_url: str | None = None) -> bool:
    """Detect that a response indicates an expired/absent session."""
    if status in (401, 403):
        return True
    low = _lower_headers(headers)
    location = low.get("location", "")
    if location and ("login" in location.lower()
                     or (login_url and login_url in location)):
        return True
    # A protected page that came back as a login page means we were logged out.
    if status == 200 and is_login_page(body):
        return True
    return False
