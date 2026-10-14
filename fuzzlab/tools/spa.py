"""Single-page apps for the crawler (forms phase 3; FR-CRAWL-12, FR-CRAWL-13).

Pure helpers, testable without a browser; `tools/spider.py` wires them:

* **routes** (FR-CRAWL-12) -- `scan_routes` reads route declarations out of a
  same-origin script body the browser already loaded (Angular ``{path:'x'``, Vue
  ``path: '/x'``, React ``{ path: "/x"`` and ``<Route path="/x"``). It is a linear scan
  (``str.find`` with bounded look-around, no regular expression over the body) of a
  body at most `MAX_SCRIPT_BYTES` long; `classify_route` skips parameterised and
  wildcard routes and names destructive ones; `route_url` builds the hash-mode
  (``origin/#/x``) or history-mode (``origin/x``) URL;
* **visit keys** -- `visit_key` keys a page on its canonical origin, path, query and,
  for a SPA route, its fragment (``#/x`` or ``#!/x``), so loopback aliases are one site
  and hash routes are distinct pages;
* **transport noise** -- `is_transport_url`: socket.io / engine.io polling URLs are a
  transport, not an endpoint;
* **SPA form submission** (FR-CRAWL-13) -- `form_refusal` is the one gate for
  ``--submit-spa-forms``, and `FORMS_JS` finds forms and form-like containers in the
  rendered page.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit, urlunsplit

from fuzzlab.core.redaction import is_sensitive_name, name_tokens
from fuzzlab.core.urls import canonical_origin, destructive_reason, transaction_reason

#: A same-origin script larger than this is not scanned for routes.
MAX_SCRIPT_BYTES = 4 * 1024 * 1024
#: At most this many scripts are scanned per page.
MAX_SCRIPTS_PER_PAGE = 32
#: At most this many routes are taken from one script.
MAX_ROUTES_PER_SCRIPT = 500
#: A route value longer than this is not a route.
MAX_ROUTE_LEN = 128
#: At most this many forms are submitted per crawl (reported).
MAX_SUBMISSIONS = 50
#: Whitespace tolerated around ``:`` / ``=`` in a declaration (bounded look-around).
_MAX_GAP = 8
#: How far back ``<Route`` may open the tag a ``path=`` attribute belongs to.
_MAX_TAG_BACK = 200
_QUOTES = "'\"`"
_ROUTE_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "0123456789-_./~:*")


# --- route extraction ---------------------------------------------------------------
def _skip_ws(text: str, i: int, limit: int) -> int:
    end = min(len(text), i + limit)
    while i < end and text[i] in " \t\r\n":
        i += 1
    return i


def _back_ws(text: str, i: int, limit: int) -> int:
    """The index of the last non-space character at or before ``i`` (bounded)."""
    stop = max(-1, i - limit)
    while i > stop and text[i] in " \t\r\n":
        i -= 1
    return i


def _quoted(text: str, i: int) -> str | None:
    """The string literal starting at ``i`` (its quote), if it closes within
    `MAX_ROUTE_LEN` characters; None otherwise."""
    if i >= len(text) or text[i] not in _QUOTES:
        return None
    end = text.find(text[i], i + 1, i + 2 + MAX_ROUTE_LEN)
    if end < 0:
        return None
    return text[i + 1:end]


def scan_routes(text: str, max_bytes: int = MAX_SCRIPT_BYTES) -> list[str] | None:
    """The route paths ``text`` declares, in order, deduplicated; None when ``text`` is
    longer than ``max_bytes`` (not scanned).

    A declaration is the key ``path`` (bare or quoted) opening an object or following a
    comma, then ``:`` and a string literal (``{path:'x'``, ``{ path: "/x", element``,
    ``,"path":"x"``), or a ``path=`` attribute of a ``<Route`` tag. Each occurrence of
    ``path`` costs bounded work (whitespace and literals have fixed caps), so the scan is
    linear in ``len(text)`` (PA-0095)."""
    if len(text) > max_bytes:
        return None
    found: dict[str, None] = {}
    i = text.find("path")
    while i >= 0 and len(found) < MAX_ROUTES_PER_SCRIPT:
        value = _declaration_at(text, i)
        if value is not None:
            found.setdefault(value, None)
        i = text.find("path", i + 4)
    return list(found)


def _declaration_at(text: str, i: int) -> str | None:
    after = i + 4
    before = i - 1
    if before >= 0 and text[before] in _QUOTES:              # "path": ...
        if after >= len(text) or text[after] != text[before]:
            return None
        after += 1
        before -= 1
    elif (before >= 0 and (text[before].isalnum() or text[before] in "_$")) or \
            (after < len(text) and (text[after].isalnum() or text[after] in "_$")):
        return None                                           # part of a longer name
    j = _skip_ws(text, after, _MAX_GAP)
    if j >= len(text):
        return None
    if text[j] == ":":                                        # an object key
        k = _back_ws(text, before, _MAX_GAP)
        if k < 0 or text[k] not in "{,":
            return None
        return _quoted(text, _skip_ws(text, j + 1, _MAX_GAP))
    if text[j] == "=":                                        # a JSX attribute
        tag = text.rfind("<Route", max(0, i - _MAX_TAG_BACK), i)
        if tag < 0 or text.find(">", tag, i) >= 0:
            return None
        return _quoted(text, _skip_ws(text, j + 1, _MAX_GAP))
    return None


ROUTE_OK, ROUTE_PARAM, ROUTE_DESTRUCTIVE, ROUTE_ROOT, ROUTE_INVALID, ROUTE_TRANSPORT = (
    "ok", "parameterised", "destructive", "root", "invalid", "transport")
#: Kinds that are not routes at all: never counted as found (lane S review).
NOT_ROUTES = frozenset({ROUTE_ROOT, ROUTE_INVALID, ROUTE_TRANSPORT})


def normalise_route(path: str) -> str:
    """A route path without its leading ``#``, ``!`` and ``/`` and trailing ``/``."""
    return (path or "").lstrip("#!").strip("/")


def classify_route(path: str) -> tuple[str, str | None]:
    """``(kind, reason)``: `ROUTE_OK`, or why the route is not visited --
    parameterised or wildcard (``:id``, ``*``, ``**``), destructive
    (`core.urls.destructive_reason` on the route path), the root, a socket.io /
    engine.io transport path (socket.io's own ``{path:'/socket.io'}`` option,
    `is_transport_url`), or not a route (a protocol-relative ``//host`` value
    included)."""
    if (path or "").lstrip("#!").startswith("//"):
        return ROUTE_INVALID, None
    route = normalise_route(path)
    if not route:
        return ROUTE_ROOT, None
    if len(route) > MAX_ROUTE_LEN or not set(route) <= _ROUTE_CHARS or "//" in route:
        return ROUTE_INVALID, None
    if is_transport_url("/" + route):
        return ROUTE_TRANSPORT, None
    if "*" in route or any(seg.startswith(":") for seg in route.split("/")):
        return ROUTE_PARAM, route
    reason = destructive_reason("/" + route)
    if reason:
        return ROUTE_DESTRUCTIVE, reason
    return ROUTE_OK, None


def route_url(page_url: str, path: str, *, hash_mode: bool, hashbang: bool = False,
              base: str | None = None) -> str:
    """The URL of route ``path``: hash mode ``<page>#/<path>`` (``#!/`` for a hashbang
    app) on the page's own URL without its fragment; history mode ``<base><path>``."""
    route = normalise_route(path)
    if hash_mode:
        return page_url.split("#", 1)[0] + ("#!/" if hashbang else "#/") + route
    return urljoin(base or page_url, route)


# --- SPA fragments and visit keys -----------------------------------------------------
def spa_fragment(url: str) -> str | None:
    """The fragment of ``url`` when it names a SPA route (starts with ``/`` or ``!/``)."""
    from fuzzlab.core.urls import is_spa_route_fragment    # the one definition (PA-0003)
    _head, sep, frag = (url or "").partition("#")
    return frag if sep and is_spa_route_fragment(frag) else None


def crawl_url(url: str, keep_spa: bool) -> str:
    """``url`` with its fragment dropped, unless it is a SPA route and ``keep_spa``."""
    head = (url or "").split("#", 1)[0]
    frag = spa_fragment(url) if keep_spa else None
    return head + "#" + frag if frag is not None else head


def visit_key(url: str) -> str:
    """How the crawler dedupes a page: canonical origin (loopback aliases one site),
    path, query and a SPA-route fragment. A URL without a usable origin keys as
    itself (fragment rules kept)."""
    parts = urlsplit(url or "")
    origin = canonical_origin(url) if parts.netloc else None
    frag = spa_fragment(url)
    tail = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if origin is None:
        tail = urlunsplit(parts._replace(fragment=""))
    return (origin or "") + tail + (f"#{frag}" if frag is not None else "")


def route_destructive_reason(url: str) -> str | None:
    """`core.urls.destructive_reason` on the URL, and on its SPA-route fragment (path
    and query), which that rule never sees: ``/#/logout`` is destructive."""
    reason = destructive_reason(url)
    frag = spa_fragment(url)
    if reason is None and frag is not None:
        reason = destructive_reason("/" + frag.lstrip("!/"))
    return reason


def route_of(url: str, base: str | None = None) -> str:
    """The route a page shows: its SPA fragment's path (``#/a/b?q=1`` -> ``a/b``), or
    its path relative to ``base`` (history mode)."""
    frag = spa_fragment(url)
    if frag is not None:
        return normalise_route(frag.split("?", 1)[0])
    path = urlsplit(url or "").path or "/"
    root = urlsplit(base or "").path or "/"
    if base and path.startswith(root):
        path = path[len(root):]
    return normalise_route(path)


# --- transport noise ------------------------------------------------------------------
_TRANSPORT_SEGMENTS = frozenset({"socket.io", "engine.io"})


def is_transport_url(url: str) -> bool:
    """A socket.io / engine.io transport URL: a whole path segment ``socket.io`` or
    ``engine.io``, or a query with both ``EIO`` and ``transport`` (whole names)."""
    parts = urlsplit(url or "")
    if any(seg.lower() in _TRANSPORT_SEGMENTS for seg in parts.path.split("/")):
        return True
    names = {p.partition("=")[0].lower() for p in parts.query.split("&") if p}
    return {"eio", "transport"} <= names


# --- SPA form submission ----------------------------------------------------------------
#: A field whose name or label has one of these tokens holds a one-time code.
_OTP_TOKENS = frozenset({"totp", "otp", "mfa", "2fa", "twofa", "tfa", "code", "token",
                         "authenticator", "verification", "passcode"})
#: Control kinds a submission fills, with what (`store_adapter`'s fillers).
_TEXT_KINDS = frozenset({"text", "search", "textarea"})
#: The password filler: never a real credential.
PASSWORD_FILLER = "fuzzlab-filler-not-a-password"


def fillable(kind: str) -> bool:
    """Whether a control of ``kind`` is one a submission types into."""
    from fuzzlab.tools.store_adapter import _FILLERS
    return kind in _TEXT_KINDS or kind == "password" or kind in _FILLERS


def filler(kind: str) -> str:
    """The value typed into a control of ``kind`` (`store_adapter`'s fillers; a
    password gets `PASSWORD_FILLER`)."""
    from fuzzlab.tools.store_adapter import _FILLERS, _TEXT_FILLER
    if kind == "password":
        return PASSWORD_FILLER
    return _FILLERS.get(kind, _TEXT_FILLER)


def form_signature(form: dict) -> str:
    """One submission per signature: the controls (name, kind) and the button label."""
    import json
    return json.dumps([sorted([n, k] for n, k in form["controls"]), form["button"]])


def _words(text: str) -> set[str]:
    return {t.lower() for t in name_tokens(text or "")}


def form_refusal(form: dict, route: str, *, named: frozenset[str] | None) -> str | None:
    """Why this SPA form must never be submitted, or None (FR-CRAWL-13).

    ``form``: ``{"controls": [(name, kind)], "button": label, "button_aria": label,
    "action": url | None, "autocomplete": [..]}`` as `FORMS_JS` describes it --
    ``button`` is the button's text with icon elements removed (``mat-icon``,
    ``.material-icons``, ``material-symbols``, ``aria-hidden``, Font Awesome, ``svg``;
    an icon-only button with no aria-label keeps its raw text), ``button_aria`` its
    ``aria-label`` or ``title``; the button is refused when either is. ``named``: the routes the
    operator named (None or empty: every route). Refused: a route not named; a
    destructive, settings-like or transaction route, button label, action or control
    name; a form with ``<input type=file>``; a credential-change form
    (`store_adapter.credential_change_reason`); a form whose only input is a one-time
    code (2FA/TOTP)."""
    from fuzzlab.tools.formnav import settings_word
    from fuzzlab.tools.store_adapter import credential_change_reason
    if named and normalise_route(route) not in named:
        return f"route {route!r} not named by the operator"
    label = form.get("button") or ""
    aria = form.get("button_aria") or ""
    # the button is refused when EITHER its visible text (icons removed) or its
    # aria-label / title is destructive, settings-like or a transaction (live-run fix)
    for where, text in (("route", "/" + normalise_route(route)), ("button", label),
                        ("button aria-label", aria)):
        reason = (destructive_reason("/?x=" + text.replace(" ", "+")) if where != "route"
                  else destructive_reason(text))
        if reason:
            return f"destructive {where} ({reason!r})"
        word = settings_word(text)
        if word:
            return f"settings-like {where} ({word!r})"
        word = transaction_reason(text)
        if word:
            return f"transaction {where} ({word!r})"
    action = form.get("action")
    if action:
        reason = route_destructive_reason(action) or transaction_reason(action)
        if reason:
            return f"destructive or transaction action ({reason!r})"
    kinds = [k for _n, k in form["controls"]]
    if kinds.count("file"):
        return "form with a file input"
    for name, _kind in form["controls"]:
        reason = destructive_reason("/?x=" + (name or "").replace(" ", "+"))
        if reason:
            return f"destructive control {name!r} ({reason!r})"
        word = settings_word(name)
        if word:
            return f"settings control {name!r} ({word!r})"
    # the route stands in for the action path; the button (both labels) is the submitter
    shape = {"controls": [(n, k) for n, k in form["controls"]]
             + [(label, "submit"), (aria, "submit")],
             "action_url": "/" + normalise_route(route),
             "entries": [(label, label), (aria, aria)]}
    reason = credential_change_reason(shape)
    if reason:
        return reason
    typed = [(n, k) for n, k in form["controls"] if fillable(k)]
    if len(typed) == 1:
        name, _kind = typed[0]
        auto = [a.lower() for a in form.get("autocomplete") or []]
        if auto.count("one-time-code") or _words(name) & _OTP_TOKENS:
            return f"one-time-code form ({name!r})"
    return None


def has_password(form: dict) -> bool:
    return any(k == "password" for _n, k in form["controls"])


def sensitive_control(name: str) -> bool:
    """A non-password control a submission leaves as it is (a token, a CSRF field)."""
    return is_sensitive_name(name)


#: Finds the rendered page's forms and form-like containers (inputs with exactly one
#: button), marks each control and button with ``data-fuzzlab-id`` and describes them.
FORMS_JS = r"""
(maxForms) => {
  const BTN = 'button, input[type=submit], input[type=button], input[type=image]';
  const kindOf = el => {
    const tag = el.tagName.toLowerCase();
    if (tag === 'textarea' || tag === 'select') return tag;
    return (el.getAttribute('type') || 'text').toLowerCase();
  };
  const typed = el => !['hidden', 'submit', 'button', 'reset', 'image'].includes(kindOf(el));
  const shown = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const buttonOk = b => shown(b) && (b.getAttribute('type') || 'submit').toLowerCase() !== 'reset';
  // live Juice Shop run: <button aria-label="Login"><mat-icon>exit_to_app</mat-icon> Log in
  // </button> read as "exit_to_app Log in" (destructive "exit"). The label judged is the
  // text with icon elements removed, plus aria-label / title; an icon-only button with
  // neither keeps its raw text (fail closed: <button><mat-icon>delete</mat-icon></button>).
  const ICONS = 'mat-icon, .material-icons, [class*="material-symbols"], ' +
    '[aria-hidden="true"], i.fa, [class*="fa-"], svg';
  const squash = t => (t || '').replace(/\s+/g, ' ').trim().slice(0, 100);
  const buttonLabels = b => {
    const aria = squash(b.getAttribute('aria-label') || b.getAttribute('title'));
    if (b.tagName.toLowerCase() === 'input') return [squash(b.value), aria];
    const clone = b.cloneNode(true);
    clone.querySelectorAll(ICONS).forEach(e => e.remove());
    const text = squash(clone.textContent);
    return [text || (aria ? '' : squash(b.textContent)), aria];
  };
  const containers = [];
  for (const f of document.querySelectorAll('form')) containers.push(f);
  for (const b of document.querySelectorAll(BTN)) {
    if (b.closest('form') || !buttonOk(b)) continue;
    let node = b.parentElement;
    for (let i = 0; node && i < 8; i++, node = node.parentElement) {
      const ctl = [...node.querySelectorAll('input, textarea, select')].filter(typed);
      if (ctl.length) {
        const btns = [...node.querySelectorAll(BTN)].filter(buttonOk);
        if (btns.length === 1 && !containers.includes(node)) containers.push(node);
        break;
      }
    }
  }
  window.__fuzzlabN = (window.__fuzzlabN || 0) + 1;
  const run = window.__fuzzlabN;
  const out = [];
  containers.slice(0, maxForms).forEach((c, fi) => {
    const btns = [...c.querySelectorAll(BTN)].filter(buttonOk);
    const submit = btns.find(b => (b.getAttribute('type') || 'submit').toLowerCase() === 'submit') || btns[0];
    const controls = [], ids = [], autocomplete = [];
    [...c.querySelectorAll('input, textarea, select')].forEach((el, ci) => {
      const name = el.getAttribute('name') || el.id || el.getAttribute('formcontrolname')
        || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '';
      const id = `r${run}f${fi}c${ci}`;
      el.setAttribute('data-fuzzlab-id', id);
      controls.push([name, kindOf(el)]);
      ids.push(id);
      autocomplete.push(el.getAttribute('autocomplete') || '');
    });
    let button = null, label = '', aria = '';
    if (submit) {
      button = `r${run}f${fi}b`;
      submit.setAttribute('data-fuzzlab-id', button);
      [label, aria] = buttonLabels(submit);
    }
    const action = c.tagName.toLowerCase() === 'form' && c.getAttribute('action')
      ? c.action : null;
    out.push({controls, ids, autocomplete, button: label, button_aria: aria,
              button_id: button, action});
  });
  return out;
}
"""
