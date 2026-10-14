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
  rendered page; `click_vetted` clicks a vetted button once (also the session
  manager's browser login, FR-SESS-19);
* **forms phase 4** (FR-CRAWL-15/16) -- `window_request_refusal` (what the reveal
  window lets through), the label gate (`label_refusal`, `reveal_refusal`,
  `submitter_glyph`), constraint-aware filling (`g1_candidates`, `g1_sensitive`,
  `select_refusal`, `checkbox_refusal`, `captcha_reason`) and the page-side scripts
  (`G1_READ_JS`, `PATTERN_TEST_JS`, `REVEAL_JS`, `MENU_ITEMS_JS`). `tools/spider.py`
  holds the window's state and runs them.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit, urlunsplit

from fuzzlab.core.redaction import is_sensitive_name, name_tokens
from fuzzlab.core.urls import (canonical_origin, destructive_reason, text_destructive_reason,
                               transaction_reason)

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
    and query), which that rule never sees: ``/#/logout`` is destructive. The fragment
    is also judged as a whole text (`text_destructive_reason`), so a second ``#`` in it
    hides nothing (BUG-0131 sweep)."""
    reason = destructive_reason(url)
    frag = spa_fragment(url)
    if reason is None and frag is not None:
        reason = destructive_reason("/" + frag.lstrip("!/")) or text_destructive_reason(frag)
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
    ``button`` is the button's text with icon-ligature elements removed (``mat-icon``,
    ``.material-icons``, ``material-symbols`` only, `_LABELS_FN`; an icon-only button
    with no aria-label keeps its raw text), ``button_aria`` its ``aria-label`` or
    ``title``; the button is refused when either is, or when ``button_icons`` names a
    `DESTRUCTIVE_GLYPHS` glyph (`submitter_glyph`: a `TEXT_FIRST_GLYPHS` glyph such as
    ``exit_to_app`` is judged by the button's text / aria-label when it has one,
    refused only on a glyph-only button). ``named``: the routes the
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
    glyph = submitter_glyph(form.get("button_icons") or "", label, aria)
    if glyph:
        return f"destructive button icon ({glyph!r})"
    # the button is refused when EITHER its visible text (icons removed) or its
    # aria-label / title is destructive, settings-like or a transaction (live-run fix)
    for where, text in (("route", "/" + normalise_route(route)), ("button", label),
                        ("button aria-label", aria)):
        # a label is a text, never embedded in a URL: a '#' would hide the rest (BUG-0131)
        reason = (text_destructive_reason(text) if where != "route"
                  else destructive_reason(text) or text_destructive_reason(text))
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
        reason = text_destructive_reason(name)                  # BUG-0131
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


#: A button's labels as the gate judges them: ``[text, aria, icons]`` (live-run fix,
#: reviewer B). ``text`` is the button's text with **icon-ligature** elements removed
#: (``mat-icon``, ``.material-icons``, ``material-symbols``: their text is a glyph name,
#: Juice Shop's ``exit_to_app``); nothing else is removed -- ``aria-hidden`` hides real
#: text from assistive technology and is not an icon. An icon-only button with no
#: aria-label keeps its raw text (fail closed). ``aria`` is ``aria-label`` or ``title``;
#: ``icons`` the ligature names, judged against `DESTRUCTIVE_GLYPHS`.
_LABELS_FN = r"""
  const ICONS = 'mat-icon, .material-icons, [class*="material-symbols"]';
  const squash = t => (t || '').replace(/\s+/g, ' ').trim().slice(0, 100);
  const buttonLabels = b => {
    const aria = squash(b.getAttribute('aria-label') || b.getAttribute('title'));
    if (b.tagName.toLowerCase() === 'input') return [squash(b.value), aria, ''];
    const clone = b.cloneNode(true);
    const icons = [...clone.querySelectorAll(ICONS)];
    const glyphs = squash(icons.map(e => e.textContent).join(' '));
    icons.forEach(e => e.remove());
    const text = squash(clone.textContent);
    return [text || (aria ? '' : squash(b.textContent)), aria, glyphs];
  };
"""

#: ``el => [text, aria, icons]`` for one element: re-read right before a click, which
#: must find the labels the gate vetted (an app may re-render and reuse the node).
LABELS_JS = "el => {" + _LABELS_FN + "  return buttonLabels(el);\n}"

def covered(exc) -> bool:
    """Did a click fail because another element covers the target (an overlay)?"""
    return "intercepts pointer events" in str(exc)


def click_vetted(page, selector: str, vetted, *, timeout_ms: int,
                 counts: dict | None = None, before_click=None) -> str | None:
    """Click the button a gate already vetted, exactly once (live-run fix; the one
    implementation, PA-0003: the crawler's SPA submission and the session manager's
    browser login, FR-SESS-19). A trial click (actionability only, nothing is clicked)
    comes first. Only if something **covers** the button (Playwright: "intercepts
    pointer events") -- a first-visit welcome dialog, a cookie bar -- is ``Escape``
    pressed once and the trial repeated; if it is still covered, its own ``click()`` is
    run on the element (``clicks_dispatched``). A hidden, detached or never-actionable
    button raises (not submittable): a user could not click it either. Right before the
    click the button's labels are read again and must equal ``vetted`` (`LABELS_JS`; an
    app may re-render after Escape and reuse the marked node); otherwise nothing is
    clicked (``forms_label_changed``). An overlay's own buttons are never clicked.
    Returns ``"clicked"``, ``"dispatched"`` or None (labels changed); ``counts`` (when
    given) is incremented for the two counted outcomes. ``before_click`` (when given) is
    called right before the one real click, after every check (the crawler lifts its
    reveal window there, for that click only: W1)."""
    from playwright.sync_api import Error as PlaywrightError
    counts = counts if counts is not None else {}
    probe = min(timeout_ms, 5000)
    dispatch = False
    try:
        page.click(selector, trial=True, timeout=probe)
    except PlaywrightError as exc:
        if not covered(exc):
            raise
        page.keyboard.press("Escape")
        try:
            page.click(selector, trial=True, timeout=probe)
        except PlaywrightError as again:
            if not covered(again):
                raise
            dispatch = True
    if list(page.eval_on_selector(selector, LABELS_JS)) != list(vetted):
        counts["forms_label_changed"] = counts.get("forms_label_changed", 0) + 1
        return None
    if before_click is not None:
        before_click()
    if dispatch:
        page.eval_on_selector(selector, "el => el.click()")
        counts["clicks_dispatched"] = counts.get("clicks_dispatched", 0) + 1
        return "dispatched"
    page.click(selector, timeout=timeout_ms)
    return "clicked"


#: Material glyph names whose button acts destructively whatever its text says
#: (``<button><mat-icon>delete</mat-icon> Item 3</button>``): refused (fail closed).
#: ``exit_to_app`` (FR-CRAWL-16, G2d) is a logout icon as often as a login one.
DESTRUCTIVE_GLYPHS = frozenset({
    "delete", "delete_forever", "delete_outline", "delete_sweep", "logout",
    "remove_circle", "remove_circle_outline", "remove_shopping_cart", "person_remove",
    "power_settings_new", "no_accounts", "exit_to_app"})
#: Destructive glyphs that a **form's submitter** is judged on by its text first
#: (G2d): Juice Shop's LOGIN button is ``<button aria-label="Login"><mat-icon>
#: exit_to_app</mat-icon> Log in</button>`` (lane S's live fix). Such a submitter with a
#: text or aria-label is judged on those (`form_refusal`'s label rules); a glyph-only
#: one is refused. A reveal candidate (`reveal_refusal`) is refused on any glyph.
TEXT_FIRST_GLYPHS = frozenset({"exit_to_app"})


def submitter_glyph(icons: str, text: str, aria: str) -> str | None:
    """The destructive glyph that refuses a form's submitter, or None: any
    `DESTRUCTIVE_GLYPHS` glyph, except a `TEXT_FIRST_GLYPHS` one on a button that has a
    text or an aria-label (judged on those instead)."""
    labelled = bool((text or "").strip() or (aria or "").strip())
    for glyph in (icons or "").lower().split():
        if glyph in DESTRUCTIVE_GLYPHS and not (glyph in TEXT_FIRST_GLYPHS and labelled):
            return glyph
    return None

#: Finds the rendered page's forms and form-like containers (inputs with exactly one
#: button), marks each control and button with ``data-fuzzlab-id`` and describes them.
FORMS_JS = r"""
(maxForms) => {""" + _LABELS_FN + r"""
  const BTN = 'button, input[type=submit], input[type=button], input[type=image]';
  const CUSTOM_SELECT = 'mat-select, [role=combobox]:not(input):not(select):not(textarea)';
  const kindOf = el => {
    const tag = el.tagName.toLowerCase();
    if (tag === 'textarea' || tag === 'select') return tag;
    return (el.getAttribute('type') || 'text').toLowerCase();
  };
  const typed = el => !['hidden', 'submit', 'button', 'reset', 'image'].includes(kindOf(el));
  const shown = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const buttonOk = b => shown(b) && (b.getAttribute('type') || 'submit').toLowerCase() !== 'reset';
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
    const controls = [], ids = [], autocomplete = [], tags = [];
    // custom selects (mat-select, a role=combobox that is not an input) are selects
    // too (FR-CRAWL-15): kind "select", their tag kept in `tags`
    [...c.querySelectorAll('input, textarea, select, ' + CUSTOM_SELECT)].forEach((el, ci) => {
      const name = el.getAttribute('name') || el.id || el.getAttribute('formcontrolname')
        || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '';
      const id = `r${run}f${fi}c${ci}`;
      el.setAttribute('data-fuzzlab-id', id);
      const custom = el.matches(CUSTOM_SELECT);
      controls.push([name, custom ? 'select' : kindOf(el)]);
      tags.push(custom ? 'custom-select' : el.tagName.toLowerCase());
      ids.push(id);
      autocomplete.push(el.getAttribute('autocomplete') || '');
    });
    // CAPTCHA hints (G1e): the attribute values and label texts of the container, judged
    // by whole token in Python (`captcha_reason`); a canvas is an image challenge
    const hints = [];
    for (const el of [c, ...c.querySelectorAll('*')].slice(0, 400)) {
      for (const a of ['id', 'class', 'name', 'aria-label', 'placeholder',
                       'formcontrolname', 'alt', 'title', 'src'])
        if (el.getAttribute(a)) hints.push(el.getAttribute(a).slice(0, 200));
      const tag = el.tagName.toLowerCase();
      if (tag === 'label' || tag === 'mat-label' || tag === 'code')
        hints.push(squash(el.textContent));
    }
    const challenge = !!c.querySelector('canvas');
    let button = null, label = '', aria = '', glyphs = '';
    if (submit) {
      button = `r${run}f${fi}b`;
      submit.setAttribute('data-fuzzlab-id', button);
      [label, aria, glyphs] = buttonLabels(submit);
    }
    const action = c.tagName.toLowerCase() === 'form' && c.getAttribute('action')
      ? c.action : null;
    out.push({controls, ids, autocomplete, tags, button: label, button_aria: aria,
              button_icons: glyphs, button_id: button, action,
              hints: hints.slice(0, 400), challenge});
  });
  return out;
}
"""


# =====================================================================================
# Forms phase 4: the reveal window, constraint-aware filling (G1, FR-CRAWL-15) and
# reveal navigation (G2, FR-CRAWL-16)
# =====================================================================================
# --- the label gate (G2d; also G1c/G1d) ------------------------------------------------
def _base_forms(text: str) -> str:
    """``text``'s tokens with common English inflections folded to candidate base forms
    (``deleted`` -> ``delete``, ``removing`` -> ``remove``, ``wipes`` -> ``wipe``), so a
    label's destructive verb is caught in any of those forms. Only ever adds refusals."""
    out = []
    for tok in name_tokens(text or ""):
        tok = tok.lower()
        if len(tok) > 4 and tok.endswith("ing"):
            out += [tok[:-3], tok[:-3] + "e"]
        elif len(tok) > 3 and tok.endswith("ed"):
            out += [tok[:-1], tok[:-2]]
        elif len(tok) > 3 and tok.endswith("s"):
            out += [tok[:-1]]
    return " ".join(out)


def label_refusal(text: str | None) -> str | None:
    """Why a label -- a reveal candidate's, a menu item's, an option's, a checkbox's --
    fails the gate, or None: a destructive word (`core.urls.text_destructive_reason`,
    also on the label's inflections folded, `_base_forms`),
    a settings word (`formnav.settings_word`), a transaction word
    (`core.urls.transaction_reason`, CC-CORE-0045) or an account word (the session
    manager's `ACCOUNT_WORDS` / `ACCOUNT_PAIRS`), each by whole token."""
    from fuzzlab.session.browserlogin import _account_hit       # the one account rule
    from fuzzlab.tools.formnav import settings_word
    text = text or ""
    reason = text_destructive_reason(text) or text_destructive_reason(_base_forms(text))
    if reason:
        return f"destructive ({reason!r})"
    word = settings_word(text)
    if word:
        return f"settings-like ({word!r})"
    word = transaction_reason(text)
    if word:
        return f"transaction ({word!r})"
    word = _account_hit(text)
    if word:
        return f"account word ({word!r})"
    return None


def reveal_refusal(labels) -> str | None:
    """Why a reveal candidate or a revealed menu item is never clicked, or None (G2d):
    any `DESTRUCTIVE_GLYPHS` glyph (``exit_to_app`` included: no text-first rule for a
    reveal), no label at all, or a text / aria-label that fails `label_refusal`.
    ``labels`` is ``[text, aria, icons]`` (`LABELS_JS`)."""
    text, aria, icons = (list(labels or []) + ["", "", ""])[:3]
    glyph = next((g for g in (icons or "").lower().split() if g in DESTRUCTIVE_GLYPHS),
                 None)
    if glyph:
        return f"destructive icon ({glyph!r})"
    if not ((text or "").strip() or (aria or "").strip()):
        return "no label to judge"
    for where, value in (("text", text), ("aria-label", aria)):
        why = label_refusal(value)
        if why:
            return f"{where} {why}"
    return None


# --- CAPTCHA (G1e) ---------------------------------------------------------------------
#: A form whose controls or labels carry one of these tokens has a CAPTCHA: refused.
CAPTCHA_TOKENS = frozenset({"captcha", "recaptcha", "hcaptcha", "turnstile"})


def captcha_reason(form: dict) -> str | None:
    """Why ``form`` is a CAPTCHA form (never submitted; no CAPTCHA is solved, G1e), or
    None: a control name or a container hint (`FORMS_JS` ``hints``: attribute values and
    label texts) with a `CAPTCHA_TOKENS` token (whole tokens), or a ``<canvas>``
    challenge in the container."""
    if form.get("challenge"):
        return "CAPTCHA form (a canvas challenge)"
    texts = [n for n, _k in form.get("controls") or []] + list(form.get("hints") or [])
    for text in texts:
        hit = {t.lower() for t in name_tokens(text or "")} & CAPTCHA_TOKENS
        if hit:
            return f"CAPTCHA form ({sorted(hit)[0]!r})"
    return None


# --- G1: the constraint-aware ladder (FR-CRAWL-15) ---------------------------------------
#: At most this many values are tried per invalid control (G1a).
G1_MAX_ATTEMPTS = 6
#: How long the page may take to test a ``pattern`` against the candidates (a worker,
#: terminated at the deadline: no verdict, no candidate), ms.
G1_PATTERN_TIMEOUT_MS = 500
#: Name-hint tokens of the typed ladder (a control with no explicit constraint that is
#: still invalid).
_HINT_TOKENS = {
    "phone": frozenset({"phone", "mobile", "tel", "telephone", "cell", "msisdn"}),
    "zip": frozenset({"zip", "zipcode", "postal", "postcode", "plz"}),
    "quantity": frozenset({"quantity", "qty", "amount", "count"}),
    "year": frozenset({"year"}),
}
#: A checkbox whose label has one of these words is never checked (G1d): it subscribes
#: or sets a default / remember-me.
SUBSCRIPTION_WORDS = frozenset({"newsletter", "subscribe", "subscription", "default",
                                "remember"})
#: A digit run this long in an option's value or text marks a numeric id (a card ending,
#: an account number), G1c.
OPTION_ID_DIGITS = 4


def _hint(names) -> str | None:
    toks = {t.lower() for n in names for t in name_tokens(n or "")}
    for hint, words in _HINT_TOKENS.items():
        if toks & words:
            return hint
    return None


def _number(text):
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    return value if value == value and abs(value) != float("inf") else None


def _on_grid(value: float, lo, step) -> bool:
    if step is None:
        return True
    k = (value - (lo if lo is not None else 0.0)) / step
    return abs(k - round(k)) < 1e-9


def _numeric_candidates(info: dict, hint: str | None) -> list[str]:
    """Ladder values in ``[min, max]`` on the ``step`` grid (default 1; ``any``: no
    grid), name-hinted values first."""
    from fuzzlab.tools.store_adapter import LADDER_MAX_DIGITS, ladder_digits
    lo, hi = _number(info.get("min")), _number(info.get("max"))
    raw_step = (info.get("step") or "").strip().lower()
    step = None if raw_step == "any" else (_number(raw_step) or 1.0)
    if step is not None and step <= 0:
        step = 1.0
    pool = {"phone": ladder_digits(10), "zip": ["12345", *ladder_digits(5)],
            "quantity": ["1", "2"], "year": ["2000"]}.get(hint, [])
    for n in range(1, LADDER_MAX_DIGITS + 1):
        pool += ladder_digits(n)
    out = []
    for text in dict.fromkeys(pool):
        value = float(text)
        if (lo is None or value >= lo) and (hi is None or value <= hi) \
                and _on_grid(value, lo, step):
            out.append(text)
        if len(out) >= G1_MAX_ATTEMPTS:
            break
    return out


def pattern_lengths(pattern: str) -> list[int]:
    """The lengths a ``pattern``'s quantifiers name (``{5}``, ``{2,4}``, ``{3,}``),
    in order, at most 15 each (a bounded scan, no regular expression)."""
    from fuzzlab.tools.store_adapter import LADDER_MAX_DIGITS
    out, i = [], pattern.find("{")
    while i >= 0 and len(out) < 8:
        end = pattern.find("}", i, i + 12)
        if end > i:
            for part in pattern[i + 1:end].split(","):
                if part.strip().isdigit() and 1 <= int(part) <= LADDER_MAX_DIGITS:
                    out.append(int(part))
        i = pattern.find("{", i + 1)
    return list(dict.fromkeys(out))


def _fit_length(text: str, lo, hi) -> str | None:
    """``text`` fitted into ``[minlength, maxlength]``: the text filler padded with
    ``x`` or cut to a prefix, a repeated digit lengthened or shortened; None when it
    cannot be (only ladder values come out, `store_adapter.is_ladder_value`)."""
    from fuzzlab.tools.store_adapter import (LADDER_MAX_DIGITS, LADDER_MAX_TEXT,
                                             LADDER_MIN_PREFIX, LADDER_PAD, LADDER_TEXT)
    lo = int(lo) if lo is not None and lo >= 0 else 0
    hi = int(hi) if hi is not None and hi >= 0 else None
    if lo <= len(text) and (hi is None or len(text) <= hi):
        return text
    if text == LADDER_TEXT:
        want = max(lo, len(text)) if hi is None else min(max(lo, len(text)), hi)
        if want >= len(text) and want <= LADDER_MAX_TEXT:
            return text + LADDER_PAD * (want - len(text))
        if LADDER_MIN_PREFIX <= want < len(text) and want >= lo:
            return text[:want]
        return None
    if text.isdigit() and len(set(text)) == 1:
        want = lo if len(text) < lo else hi
        if want and 1 <= want <= LADDER_MAX_DIGITS and want >= lo:
            return text[0] * want
    return None


def g1_candidates(info: dict) -> list[str]:
    """The values G1 tries, in order, for one invalid control (FR-CRAWL-15, G1a), all
    of them ladder values or fillers (`store_adapter.is_filler`): a number / range in
    ``[min, max]`` on its step grid; a text fitted into ``[minlength, maxlength]``; for
    a ``pattern``, generated candidates (digits of the pattern's quantifier lengths,
    letters, e-mail, URL, phone) that the page's own ``RegExp`` must accept (tested in
    the page, `PATTERN_TEST_JS`; the caller keeps the first `G1_MAX_ATTEMPTS`); with no
    explicit constraint, the typed ladder by name hint (phone/mobile -> 10 digits,
    zip/postal -> 5 digits, quantity/amount -> 1, year -> 2000) or filler variants.
    ``info`` is one `G1_READ_JS` entry."""
    from fuzzlab.tools.store_adapter import (_FILLERS, LADDER_PAD, LADDER_TEXT,
                                             LADDER_TEXT_VARIANTS, ladder_digits)
    kind = (info.get("kind") or "text").lower()
    hint = _hint(info.get("names") or [])
    if kind in ("number", "range"):
        return _numeric_candidates(info, hint)
    if kind in _FILLERS and kind not in ("tel",):
        return [_FILLERS[kind]]
    pattern = info.get("pattern") or ""
    if pattern:
        pool = []
        for n in pattern_lengths(pattern) + [5, 10, 3, 1]:
            pool += ladder_digits(n)[:1] + ladder_digits(n)[-1:]
        pool += [LADDER_TEXT, *LADDER_TEXT_VARIANTS, _FILLERS["email"], _FILLERS["url"],
                 _FILLERS["tel"]]
    elif kind == "tel" or hint == "phone":
        pool = [_FILLERS["tel"], *ladder_digits(10)[:2]]
    elif hint == "zip":
        pool = ["12345", "11111"]
    elif hint == "quantity":
        pool = ["1", "2"]
    elif hint == "year":
        pool = ["2000"]
    else:
        pool = [LADDER_TEXT, LADDER_TEXT + LADDER_PAD * 8, *LADDER_TEXT_VARIANTS,
                _FILLERS["email"], _FILLERS["url"], ladder_digits(10)[4]]
    lo, hi = _number(info.get("minlength")), _number(info.get("maxlength"))
    out = []
    for text in pool:
        fitted = _fit_length(text, lo, hi) if (lo is not None or hi is not None) else text
        if fitted is not None:
            out.append(fitted)
    out = list(dict.fromkeys(out))
    return out if pattern else out[:G1_MAX_ATTEMPTS]


#: One-time-code tokens G1 never fills (G1b): `_OTP_TOKENS` without ``code`` -- a bare
#: ``code`` is sensitive only as the whole name (`is_sensitive_name`), and ``zipCode`` or
#: ``postcode`` must stay fillable.
_G1_OTP_TOKENS = _OTP_TOKENS - {"code"}


def g1_sensitive(names) -> str | None:
    """The name that makes a control one G1 never fills (G1b), or None: a sensitive
    (`core.redaction.is_sensitive_name`: a security answer, a PIN, a card security
    code...), credential (`is_credential_name`) or one-time-code name
    (`_G1_OTP_TOKENS`)."""
    from fuzzlab.core.redaction import is_credential_name
    for name in names or []:
        if name and (is_sensitive_name(name) or is_credential_name(name)
                     or _words(name) & _G1_OTP_TOKENS):
            return name
    return None


def _digit_run(text: str) -> int:
    best = run = 0
    for ch in text or "":
        run = run + 1 if ch.isascii() and ch.isdigit() else 0
        best = max(best, run)
    return best


def select_refusal(names, options, chosen_label: str) -> str | None:
    """Why a select, mat-select or radio group is never chosen in (G1c; the form is then
    not submittable), or None: a name that is an object selector
    (`store_adapter._object_selector`, or ``id``); an option whose value or text looks
    like an identifier (`core.redaction.is_identifier_value` / `looks_like_identifier`),
    holds a run of `OPTION_ID_DIGITS` digits, or is a number that is not its own text (a
    record key); or a chosen option whose label fails `label_refusal`. Countries,
    ratings and plain enums pass. ``options``: ``[(value, text)]``."""
    from fuzzlab.core.redaction import is_identifier_value, looks_like_identifier
    from fuzzlab.tools.store_adapter import _object_selector
    for name in names or []:
        toks = [t.lower() for t in name_tokens(name or "")]
        if name and (_object_selector(name) or toks == ["id"]):
            return f"an object selector ({name!r})"
    for value, text in options or []:
        value, text = value or "", text or ""
        if is_identifier_value(value) or looks_like_identifier(text) \
                or max(_digit_run(value), _digit_run(text)) >= OPTION_ID_DIGITS:
            return f"an identifier-like option ({text[:40]!r})"
        if value.isascii() and value.isdigit() and value not in name_tokens(text):
            return f"a numeric record key as an option value ({text[:40]!r})"
    why = label_refusal(chosen_label)
    return f"option {chosen_label[:40]!r}: {why}" if why else None


def checkbox_refusal(label: str | None) -> str | None:
    """Why a required checkbox (or a radio option) is never checked (G1d; the form is
    then not submittable), or None: no label (text, aria-label or associated
    ``<label>``), a label that fails `label_refusal`, or a subscription / default /
    remember-me word (`SUBSCRIPTION_WORDS`, plural folded)."""
    label = label or ""
    if not label.strip():
        return "an unlabelled checkbox"
    why = label_refusal(label)
    if why:
        return why
    toks = {t.lower() for t in name_tokens(label)}
    hit = (toks | {t[:-1] for t in toks if len(t) > 3 and t.endswith("s")}) \
        & SUBSCRIPTION_WORDS
    if hit:
        return f"a subscription or remember-me box ({sorted(hit)[0]!r})"
    return None


# --- W2: what the reveal window lets through ----------------------------------------------
def window_request_refusal(method: str, url: str, navigation: bool) -> str | None:
    """Why a request is aborted while the reveal window is open (W2), or None: every
    navigation (its target is queued through the normal gates instead); every method but
    GET and HEAD, whatever its destination; and a GET or HEAD that is destructive (also
    by its SPA fragment), a transaction (`core.urls.transaction_reason`), an account
    endpoint (`browserlogin.account_endpoint_reason`) or carries an account word or a
    credential token in its path or query (whole tokens). Residual: an opaque GET with
    a side effect and none of these words."""
    from urllib.parse import unquote_plus

    from fuzzlab.core.redaction import CREDENTIAL_TOKENS
    from fuzzlab.session.browserlogin import _account_hit, account_endpoint_reason
    if navigation:
        return "a navigation (its target is queued instead)"
    method = (method or "").upper()
    if method not in ("GET", "HEAD"):
        return f"a {method or '(no method)'} request"
    reason = route_destructive_reason(url)
    if reason:
        return f"a destructive GET ({reason!r})"
    reason = transaction_reason(url)
    if reason:
        return f"a transaction GET ({reason!r})"
    reason = account_endpoint_reason(url)
    if reason:
        return f"an account endpoint ({reason})"
    parts = urlsplit(url or "")
    text = unquote_plus(parts.path) + " " + unquote_plus(parts.query)
    word = _account_hit(text)
    if word:
        return f"an account word in a GET ({word!r})"
    names = [unquote_plus(p.partition("=")[0]) for p in parts.query.split("&") if p]
    toks = {t.lower() for n in [unquote_plus(parts.path), *names] for t in name_tokens(n)}
    hit = toks & CREDENTIAL_TOKENS
    if hit:
        return f"a credential token in a GET ({sorted(hit)[0]!r})"
    return None


# --- G2: bounds (caps as constants, B8) ---------------------------------------------------
#: At most this many candidates are read from one page.
MAX_REVEAL_CANDIDATES = 40
#: At most this many reveals are clicked on one page, and in one crawl.
MAX_REVEALS_PER_PAGE = 6
MAX_REVEALS = 60
#: Cards / list items of one structural signature clicked per route (G2a).
MAX_CARDS_PER_SIGNATURE = 3
#: Revealed menu items clicked per reveal (G2b).
MAX_MENU_ITEMS = 4
#: A card whose text is longer than this cannot be judged whole: refused (G2a(b)).
MAX_CARD_TEXT = 1000


def reveal_key(route: str, cand: dict) -> str:
    """One click per (route, kind, label signature, card signature)."""
    import json
    return json.dumps([normalise_route(route), cand.get("kind"),
                       list(cand.get("labels") or []), cand.get("sig") or ""])


# --- the page side ------------------------------------------------------------------------
#: The controls G1 reads (``ids``: `FORMS_JS` ids). Per control: its kind and tag, the
#: constraint attributes, whether it is invalid by any signal (``validity``,
#: ``aria-invalid``, Angular's ``ng-invalid`` on it or on its mat-checkbox /
#: mat-radio-group / mat-slider / mat-select host, ``mat-form-field-invalid``), its
#: names (name, id, formcontrolname, aria-label, placeholder), its label text (own
#: ``<label>``, aria-labelledby, mat-checkbox / mat-radio-button / mat-form-field label),
#: a native select's options, a radio's group and whether it is checked.
G1_READ_JS = r"""
(ids) => {
  const squash = t => (t || '').replace(/\s+/g, ' ').trim().slice(0, 200);
  const HOST = 'mat-checkbox, .mat-mdc-checkbox, mat-radio-group, [role=radiogroup], ' +
               'mat-slider, .mat-mdc-slider, mat-select';
  const FIELD = 'mat-form-field, .mat-mdc-form-field, .mat-form-field';
  const flagged = el => !!el && (el.classList.contains('ng-invalid') ||
    (el.getAttribute('aria-invalid') || '') === 'true');
  const invalidOf = el => {
    if (el.validity && !el.validity.valid) return true;
    if (flagged(el)) return true;
    const host = el.parentElement && el.parentElement.closest(HOST);
    if (flagged(host)) return true;
    const field = el.closest(FIELD);
    return !!(field && (field.classList.contains('mat-form-field-invalid') ||
                        field.classList.contains('mat-mdc-form-field-invalid')));
  };
  const labelOf = el => {
    const parts = [];
    for (const l of (el.labels || [])) parts.push(l.textContent);
    const by = el.getAttribute('aria-labelledby');
    if (by) for (const i of by.split(/\s+/)) { const x = document.getElementById(i);
      if (x) parts.push(x.textContent); }
    const box = el.closest('mat-checkbox, .mat-mdc-checkbox, mat-radio-button, ' +
                           '.mat-mdc-radio-button, label');
    if (box) parts.push(box.textContent);
    const field = el.closest(FIELD);
    if (field) { const ml = field.querySelector('mat-label, label');
      if (ml) parts.push(ml.textContent); }
    if (el.getAttribute('aria-label')) parts.push(el.getAttribute('aria-label'));
    return squash([...new Set(parts.map(squash))].join(' '));
  };
  return ids.map(id => {
    const el = document.querySelector(`[data-fuzzlab-id="${id}"]`);
    if (!el) return {id, missing: true};
    const tag = el.tagName.toLowerCase();
    const custom = el.matches('mat-select, [role=combobox]:not(input):not(select):not(textarea)');
    const kind = custom ? 'select' : (tag === 'textarea' || tag === 'select') ? tag :
      (el.getAttribute('type') || 'text').toLowerCase();
    const fcn = el.getAttribute('formcontrolname') ||
      ((el.parentElement && el.parentElement.closest('[formcontrolname]')) || el)
        .getAttribute('formcontrolname') || '';
    const names = [el.getAttribute('name'), el.id, fcn, el.getAttribute('aria-label'),
                   el.getAttribute('placeholder')].filter(Boolean).map(squash);
    const a = n => el.getAttribute(n);
    return {id, tag: custom ? 'custom-select' : tag, kind,
      required: !!el.required || a('aria-required') === 'true',
      min: a('min'), max: a('max'), step: a('step'), minlength: a('minlength'),
      maxlength: a('maxlength'), pattern: a('pattern'),
      invalid: invalidOf(el), checked: !!el.checked, group: a('name') || '',
      value: (tag === 'select' || kind === 'radio' || kind === 'checkbox') ? el.value : null,
      names, label: labelOf(el),
      options: tag === 'select' ? [...el.options].map(o => [o.value, squash(o.textContent),
                                                        !!o.disabled]) : []};
  });
}
"""

#: ``el => invalid`` for one control, by the same signals as `G1_READ_JS`.
G1_INVALID_JS = r"""
el => {
  const HOST = 'mat-checkbox, .mat-mdc-checkbox, mat-radio-group, [role=radiogroup], ' +
               'mat-slider, .mat-mdc-slider, mat-select';
  const flagged = x => !!x && (x.classList.contains('ng-invalid') ||
    (x.getAttribute('aria-invalid') || '') === 'true');
  if (el.validity && !el.validity.valid) return true;
  if (flagged(el)) return true;
  return flagged(el.parentElement && el.parentElement.closest(HOST));
}
"""

#: ``(el, value)``: set an ``<input>``'s value through the native setter and fire
#: ``input`` and ``change`` (a range, which ``page.fill`` refuses), as a user's drag does.
G1_SET_JS = r"""
(el, value) => {
  const proto = el.tagName.toLowerCase() === 'textarea' ? HTMLTextAreaElement.prototype
                                                       : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
  el.dispatchEvent(new Event('input', {bubbles: true}));
  el.dispatchEvent(new Event('change', {bubbles: true}));
}
"""

#: The visible options of an open select panel (mat-option / role=option), marked
#: ``data-fuzzlab-opt``: ``[{id, value, text, disabled}]``.
G1_OPTIONS_JS = r"""
() => {
  const squash = t => (t || '').replace(/\s+/g, ' ').trim().slice(0, 200);
  const shown = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  window.__fuzzlabO = (window.__fuzzlabO || 0) + 1;
  return [...document.querySelectorAll('mat-option, [role=option]')].filter(shown)
    .slice(0, 200).map((o, i) => {
      const id = `o${window.__fuzzlabO}n${i}`;
      o.setAttribute('data-fuzzlab-opt', id);
      return {id, value: o.getAttribute('value') || '', text: squash(o.textContent),
              disabled: o.getAttribute('aria-disabled') === 'true' ||
                        o.classList.contains('mat-mdc-option-disabled')};
    });
}
"""

#: ``{pattern, candidates, timeout}`` -> ``[bool]`` (or null): the page's own
#: ``RegExp('^(?:' + pattern + ')$')`` (flag ``v``, else ``u``, else none, as HTML
#: compiles it) tested on each candidate **in a worker** terminated at ``timeout`` ms,
#: so a catastrophic pattern costs a bounded wait and gives no verdict (G1a).
PATTERN_TEST_JS = r"""
async ({pattern, candidates, timeout}) => {
  const src = "onmessage = e => { const p = e.data.p; let re = null;" +
    "for (const f of ['v', 'u', '']) { try { re = new RegExp('^(?:' + p + ')$', f); break; }" +
    " catch (x) {} } postMessage(re ? e.data.cs.map(c => re.test(c)) : null); };";
  let w;
  try { w = new Worker(URL.createObjectURL(new Blob([src], {type: 'text/javascript'}))); }
  catch (e) { return null; }
  return await new Promise(resolve => {
    const t = setTimeout(() => { w.terminate(); resolve(null); }, timeout);
    w.onmessage = e => { clearTimeout(t); w.terminate(); resolve(e.data); };
    w.onerror = () => { clearTimeout(t); w.terminate(); resolve(null); };
    w.postMessage({p: pattern, cs: candidates});
  });
}
"""

#: Reveal candidates (G2a), marked ``data-fuzzlab-reveal``: popup / toggle announcers
#: (``[aria-haspopup]``, mat-menu triggers, ``[aria-expanded=false]``, buttons with
#: ``aria-controls``, sidenav toggles by whole label token or a ``menu`` glyph) and
#: cards / list items that are themselves interactive (role=button, a tabindex, an
#: ``onclick``, or a pointer cursor) with no interactive descendant. Never a link, a
#: select-like control, a disabled element, or an element inside a form (unless a
#: ``type=button`` button). ``[{id, kind, labels: [text, aria, icons], sig, long}]``.
REVEAL_JS = r"""
(maxScan) => {""" + _LABELS_FN + r"""
  const shown = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
    && getComputedStyle(el).visibility !== 'hidden';
  const INTERACTIVE = 'a[href], button, input, select, textarea, [role=button], ' +
    '[role=link], [role=checkbox], [role=menuitem], [role=tab], [role=switch], ' +
    '[role=option], [tabindex]:not([tabindex="-1"]), [onclick], [contenteditable=""], ' +
    '[contenteditable=true]';
  const ANNOUNCE = '[aria-haspopup]:not([aria-haspopup=false]), .mat-mdc-menu-trigger, ' +
    '.mat-menu-trigger, [aria-expanded=false], button[aria-controls], ' +
    '[role=button][aria-controls]';
  const SELECTLIKE = 'select, mat-select, [role=combobox], [aria-haspopup=listbox], ' +
    'input, textarea, a[href], [role=option]';
  const CARDS = 'mat-card, .mat-mdc-card, .mat-card, [role=listitem], ' +
    '[role=button]:not(button), mat-grid-tile, mat-list-item, .mat-mdc-list-item';
  const TOGGLE_WORDS = ['sidenav', 'sidebar', 'drawer', 'hamburger'];
  const inForm = el => !!el.closest('form') && !(el.tagName.toLowerCase() === 'button'
    && (el.getAttribute('type') || '').toLowerCase() === 'button');
  const disabled = el => !!el.disabled || el.getAttribute('aria-disabled') === 'true';
  const selfInteractive = el => el.matches('button, [role=button], ' +
    '[tabindex]:not([tabindex="-1"]), [onclick]') || typeof el.onclick === 'function' ||
    getComputedStyle(el).cursor === 'pointer';
  const words = t => (t || '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const cardLabels = el => {
    const clone = el.cloneNode(true);
    const icons = [...clone.querySelectorAll(ICONS)];
    const glyphs = squash(icons.map(e => e.textContent).join(' '));
    icons.forEach(e => e.remove());
    const full = (clone.textContent || '').replace(/\s+/g, ' ').trim();
    const aria = squash(el.getAttribute('aria-label') || el.getAttribute('title'));
    return {labels: [full.slice(0, 1000), aria, glyphs], long: full.length > 1000};
  };
  const sigOf = el => [el.tagName.toLowerCase(), el.getAttribute('role') || '',
    ...[...el.classList].filter(c => !/^(ng-|cdk-)/.test(c)).sort()].join('.');
  window.__fuzzlabR = (window.__fuzzlabR || 0) + 1;
  const run = window.__fuzzlabR;
  const out = [], seen = new Set();
  const add = (el, kind, labels, sig, long) => {
    if (seen.has(el) || out.length >= maxScan) return;
    seen.add(el);
    const id = `v${run}c${out.length}`;
    el.setAttribute('data-fuzzlab-reveal', id);
    out.push({id, kind, labels, sig, long: !!long});
  };
  const usable = el => shown(el) && !disabled(el) && !el.matches(SELECTLIKE) &&
    !el.closest('a[href]') && !inForm(el);
  for (const el of document.querySelectorAll(ANNOUNCE)) {
    if (usable(el)) add(el, 'announcer', buttonLabels(el), '', false);
  }
  for (const el of document.querySelectorAll('button, [role=button]')) {
    if (seen.has(el) || !usable(el)) continue;
    const labels = buttonLabels(el);
    const toks = words(labels[0] + ' ' + labels[1]);
    if (toks.some(t => TOGGLE_WORDS.includes(t)) || words(labels[2]).includes('menu'))
      add(el, 'toggle', labels, '', false);
  }
  for (const el of document.querySelectorAll(CARDS)) {
    if (seen.has(el) || !usable(el) || !selfInteractive(el)) continue;
    if (el.querySelector(INTERACTIVE)) continue;       // B6: not one target
    const c = cardLabels(el);
    add(el, 'card', c.labels, sigOf(el), c.long);
  }
  return out;
}
"""

#: ``el => [text, aria, icons]`` of a card, as `REVEAL_JS` read it (re-read right before
#: the element's own click).
CARD_LABELS_JS = r"""
el => {
  const squash = t => (t || '').replace(/\s+/g, ' ').trim().slice(0, 100);
  const ICONS = 'mat-icon, .material-icons, [class*="material-symbols"]';
  const clone = el.cloneNode(true);
  const icons = [...clone.querySelectorAll(ICONS)];
  const glyphs = squash(icons.map(e => e.textContent).join(' '));
  icons.forEach(e => e.remove());
  const full = (clone.textContent || '').replace(/\s+/g, ' ').trim();
  return [full.slice(0, 1000), squash(el.getAttribute('aria-label') || el.getAttribute('title')),
          glyphs];
}
"""

#: The visible menu items after a reveal (role=menuitem, mat-menu items), marked
#: ``data-fuzzlab-item``: ``[{id, labels, href}]`` (``href``: a link item's URL).
MENU_ITEMS_JS = r"""
() => {""" + _LABELS_FN + r"""
  const shown = el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  window.__fuzzlabM = (window.__fuzzlabM || 0) + 1;
  return [...document.querySelectorAll('[role=menuitem], .mat-mdc-menu-item, .mat-menu-item')]
    .filter(shown).slice(0, 50).map((el, i) => {
      const id = `m${window.__fuzzlabM}i${i}`;
      el.setAttribute('data-fuzzlab-item', id);
      return {id, labels: buttonLabels(el),
              href: el.matches('a[href]') ? el.href : null,
              disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true'};
    });
}
"""
