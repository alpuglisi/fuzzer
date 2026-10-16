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
  `select_refusal`, `checkbox_refusal`; CAPTCHA forms are no longer refused, D71)
  and the page-side scripts
  (`G1_READ_JS`, `PATTERN_TEST_JS`, `REVEAL_JS`, `MENU_ITEMS_JS`). `tools/spider.py`
  holds the window's state and runs them.
* **route query parameters** (FR-CRAWL-17, forms phase 5) -- `scan_script` reads routes
  and query-parameter names in one call (`scan_query_params`: paired ``navigate([..],
  {queryParams:{..}})`` / Vue ``push({path, query})`` / React literal ``?a=``, and
  unpaired reads such as ``queryParams.id``); `query_url` / `query_url_refusal` build
  and gate a seed or probe URL; `mint_markers` and `observed_names` are the observation
  probe's fresh markers and their attribution (`OBSERVE_JS` reads the rendered DOM).
"""

from __future__ import annotations

import json
import secrets
import string
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

from fuzzlab.core.redaction import is_sensitive_name, name_tokens
from fuzzlab.core import sendpolicy
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


def scan_routes(text: str, max_bytes: int = MAX_SCRIPT_BYTES, *,
                counter: "StepCounter | None" = None) -> list[str] | None:
    """The route paths ``text`` declares, in order, deduplicated; None when ``text`` is
    longer than ``max_bytes`` (not scanned).

    A declaration is the key ``path`` (bare or quoted) opening an object or following a
    comma, then ``:`` and a string literal (``{path:'x'``, ``{ path: "/x", element``,
    ``,"path":"x"``), or a ``path=`` attribute of a ``<Route`` tag. ``str.find`` only
    moves forward, and each occurrence of ``path`` costs bounded work (whitespace and
    literals have fixed caps), so the scan is linear in ``len(text)`` (PA-0095).
    ``counter`` (a `StepCounter`) receives its operation counts: one step per occurrence
    plus each whitespace character examined, and the characters ``str.find`` covered
    (PA-0135)."""
    if len(text) > max_bytes:
        return None
    counter = counter if counter is not None else StepCounter()
    found: dict[str, None] = {}
    i = text.find("path")
    counter.scanned += i + 4 if i >= 0 else len(text)
    while i >= 0 and len(found) < MAX_ROUTES_PER_SCRIPT:
        counter.tick()
        value = _declaration_at(text, i, counter)
        if value is not None:
            found.setdefault(value, None)
        nxt = text.find("path", i + 4)
        counter.scanned += (nxt if nxt >= 0 else len(text)) - i
        i = nxt
    return list(found)


def _declaration_at(text: str, i: int, counter=None) -> str | None:
    counter = counter if counter is not None else StepCounter()
    tick = counter.tick
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
    tick(j - after + 1)
    if j >= len(text):
        return None
    if text[j] == ":":                                        # an object key
        k = _back_ws(text, before, _MAX_GAP)
        start = _skip_ws(text, j + 1, _MAX_GAP)
        tick(before - k + start - j)
        if k < 0 or text[k] not in "{,":
            return None
        return _quoted(text, start)
    if text[j] == "=":                                        # a JSX attribute
        lo = max(0, i - _MAX_TAG_BACK)
        tag = text.rfind("<Route", lo, i)
        counter.scanned += i - lo                             # the bounded look-back
        start = _skip_ws(text, j + 1, _MAX_GAP)
        tick(start - j + 1)
        if tag < 0 or text.find(">", tag, i) >= 0:
            return None
        return _quoted(text, start)
    return None


ROUTE_OK, ROUTE_PARAM, ROUTE_DESTRUCTIVE, ROUTE_ROOT, ROUTE_INVALID, ROUTE_TRANSPORT = (
    "ok", "parameterised", "destructive", "root", "invalid", "transport")
#: Kinds that are not routes at all: never counted as found (lane S review).
NOT_ROUTES = frozenset({ROUTE_ROOT, ROUTE_INVALID, ROUTE_TRANSPORT})


def normalise_route(path: str) -> str:
    """A route path without its leading ``#``, ``!`` and ``/`` and trailing ``/``."""
    return (path or "").lstrip("#!").strip("/")


def classify_route(path: str, *, strict: bool = False) -> tuple[str, str | None]:
    """``(kind, reason)``: `ROUTE_OK`, or why the route is not visited --
    parameterised or wildcard (``:id``, ``*``, ``**``), destructive
    (`core.urls.destructive_reason` on the route path), the root, a socket.io /
    engine.io transport path (socket.io's own ``{path:'/socket.io'}`` option,
    `is_transport_url`), or not a route (a protocol-relative ``//host`` value and a
    relative ``.`` / ``..`` segment included, FR-CRAWL-17 review A-S2). *(D72:)*
    destructive only with ``strict`` (the login flow); a crawl's routes never are."""
    if (path or "").lstrip("#!").startswith("//"):
        return ROUTE_INVALID, None
    route = normalise_route(path)
    if not route:
        return ROUTE_ROOT, None
    if len(route) > MAX_ROUTE_LEN or not set(route) <= _ROUTE_CHARS or "//" in route \
            or any(seg in (".", "..") for seg in route.split("/")):
        return ROUTE_INVALID, None                            # '.' / '..': relative
    if is_transport_url("/" + route):
        return ROUTE_TRANSPORT, None
    if "*" in route or any(seg.startswith(":") for seg in route.split("/")):
        return ROUTE_PARAM, route
    if not strict:
        # D72: a crawl visits a destructive-looking route (last, `_deferrable`); only
        # the login flow's choice of a route (``strict``) still refuses one
        return ROUTE_OK, None
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


#: engine.io control packets a page sends on its own: ping, pong, upgrade, noop, the
#: upgrade probe (CC-CRAWL-0039, review M4).
_ENGINEIO_CONTROL = frozenset({"2", "3", "5", "6", "2probe", "3probe"})


def engineio_control(message) -> bool:
    """Is a page-to-server WebSocket message an engine.io / socket.io **control** packet
    -- a ping, pong, upgrade, noop or probe, or a socket.io connect/disconnect (``40`` /
    ``41``, optionally ``/namespace,``) with no payload? An event (``42[...]``), an ack,
    a connect with an auth payload and anything unreadable are not."""
    import re
    if isinstance(message, (bytes, bytearray)):
        try:
            message = bytes(message).decode("utf-8")
        except UnicodeDecodeError:
            return False
    if not isinstance(message, str):
        return False
    text = message.strip()
    return text in _ENGINEIO_CONTROL or \
        re.fullmatch(r"4[01](/[A-Za-z0-9_-]{0,64},?)?", text) is not None


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


def form_refusal(form: dict, route: str, *, named: frozenset[str] | None,
                 strict: bool = False) -> str | None:
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
    code (2FA/TOTP); *(CC-CRAWL-0038)* a submitter found only by its click listener
    (``submitter == "listener"``) with no text and no aria-label.

    The destructive, transaction and credential-change parts follow `core.sendpolicy`
    (D71: each can be turned off for a lab run); ``strict`` keeps all three, for the
    login flow's choice of a login form (`browserlogin.login_form_refusal`)."""
    from fuzzlab.tools.formnav import settings_word
    from fuzzlab.tools.store_adapter import credential_change_reason
    keep = (lambda r: r) if strict else None
    destructive = keep or sendpolicy.destructive
    transaction = keep or sendpolicy.transaction
    credential = keep or sendpolicy.credential_change
    if named and normalise_route(route) not in named:
        return f"route {route!r} not named by the operator"
    label = form.get("button") or ""
    aria = form.get("button_aria") or ""
    if form.get("submitter") == "listener" and not (label.strip() or aria.strip()):
        # CC-CRAWL-0038: an element found only by its click listener needs a label
        return "a listener submitter with no label to judge"
    if form.get("submitter") == "listener" and form.get("submitter_long"):
        return "a listener submitter's text too long to judge whole"
    glyph = destructive(submitter_glyph(form.get("button_icons") or "", label, aria))
    if glyph:
        return f"destructive button icon ({glyph!r})"
    # the button is refused when EITHER its visible text (icons removed) or its
    # aria-label / title is destructive, settings-like or a transaction (live-run fix)
    for where, text in (("route", "/" + normalise_route(route)), ("button", label),
                        ("button aria-label", aria)):
        # a label is a text, never embedded in a URL: a '#' would hide the rest (BUG-0131)
        reason = destructive(text_destructive_reason(text) if where != "route"
                             else destructive_reason(text) or text_destructive_reason(text))
        if reason:
            return f"destructive {where} ({reason!r})"
        word = settings_word(text)
        if word:
            return f"settings-like {where} ({word!r})"
        word = transaction(transaction_reason(text))
        if word:
            return f"transaction {where} ({word!r})"
    action = form.get("action")
    if action:
        reason = destructive(route_destructive_reason(action)) \
            or transaction(transaction_reason(action))
        if reason:
            return f"destructive or transaction action ({reason!r})"
    kinds = [k for _n, k in form["controls"]]
    if kinds.count("file"):
        return "form with a file input"
    for name, _kind in form["controls"]:
        reason = destructive(text_destructive_reason(name))     # BUG-0131
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
    reason = credential(credential_change_reason(shape))
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
    // an element that is itself an icon: its text is a glyph name (review M2)
    if (b.matches(ICONS)) return ['', aria, squash(b.textContent)];
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

#: The listener registry (CC-CRAWL-0038, crawler survey option 6): an init script every
#: crawl context runs before the page's own scripts. It records which elements get a
#: ``click``, ``submit`` or key listener -- through ``addEventListener`` (a framework's
#: own bindings, Angular's ``(click)`` / ``(keyup.enter)`` included) or an ``on*``
#: property -- in a WeakMap, so it never changes the DOM, never holds an element alive
#: and never changes what the listener does. ``window.__fuzzlabListen`` (not enumerable)
#: answers ``has(el, type)`` and ``elements(type)`` (connected elements only, at most
#: `MAX_LISTENED` recorded). It only reads: no event is dispatched.
MAX_LISTENED = 5000
LISTEN_INIT_JS = r"""
(() => {
  if (window.__fuzzlabListen) return;
  const TYPES = new Set(['click', 'submit', 'keydown', 'keyup', 'keypress']);
  const seen = new WeakMap(), refs = [];
  const note = (el, type) => {
    try {
      if (!(el instanceof Element) || !TYPES.has(type)) return;
      let kinds = seen.get(el);
      if (!kinds) {
        if (refs.length >= __MAX__) {                  // drop dead and detached ones
          const live = refs.filter(r => { const e = r.deref(); return e && e.isConnected; });
          refs.length = 0;
          refs.push(...live);
          if (refs.length >= __MAX__) return;
        }
        kinds = new Set();
        seen.set(el, kinds);
        refs.push(new WeakRef(el));
      }
      kinds.add(type);
    } catch (e) { /* the registry never breaks the page */ }
  };
  const add = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function addEventListener(type) {
    note(this, String(type));
    return add.apply(this, arguments);
  };
  for (const type of TYPES) {
    const d = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'on' + type);
    if (!d || !d.set || !d.configurable) continue;
    Object.defineProperty(HTMLElement.prototype, 'on' + type, {
      configurable: true, enumerable: d.enumerable, get: d.get,
      set(value) { if (value) note(this, type); return d.set.call(this, value); }});
  }
  Object.defineProperty(window, '__fuzzlabListen', {value: Object.freeze({
    has: (el, type) => { const k = seen.get(el); return !!k && k.has(type); },
    elements: type => refs.map(r => r.deref())
      .filter(el => el && el.isConnected && seen.get(el).has(type)),
  })});
})();
""".replace("__MAX__", str(MAX_LISTENED))

#: ``el => name`` of a control, as `FORMS_JS` names it, re-read right before Enter is
#: pressed; None when its form now has a default button that Enter would click (review
#: M1: a button rendered after the gate ran).
CONTROL_NAME_JS = r"""
el => {
  if (el.form && [...el.form.elements].some(e => e.matches(
      'button:not([type]), button[type=submit], input[type=submit], input[type=image]')))
    return null;
  return el.getAttribute('name') || el.id || el.getAttribute('formcontrolname') ||
    el.getAttribute('aria-label') || el.getAttribute('placeholder') || '';
}
"""

#: Text controls a button-less container is submitted from by Enter (CC-CRAWL-0038).
ENTER_KINDS = ("text", "search", "email", "url", "tel", "number")

#: Finds the rendered page's forms and form-like containers (inputs with exactly one
#: button), marks each control and button with ``data-fuzzlab-id`` and describes them.
#: *(CC-CRAWL-0038:)* with the listener registry (`LISTEN_INIT_JS`) it also finds a
#: button-less container whose one submitter is an element with a click listener, and
#: a text control with a key listener and no button anywhere near it (``submit_by``
#: ``"enter"``, the control to press Enter in is ``enter_id``); a ``<form>`` with a text
#: control and no button is an Enter form too. A container with a password control is
#: never an Enter container found by its listener.
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
  // CC-CRAWL-0038: the listener registry (LISTEN_INIT_JS), when the context has it
  const L = window.__fuzzlabListen;
  // a form's default button: any submit or image button among its elements, hidden or
  // outside it (``form=``) included -- Enter would click it (review M1)
  const hasDefaultButton = f => [...f.elements].some(e => e.matches(
    'button:not([type]), button[type=submit], input[type=submit], input[type=image]'));
  const ENTER = __ENTER__;
  const CTL = 'input, textarea, select';
  const inContainer = el => containers.some(c => c === el || c.contains(el));
  const submitters = new Map(), enters = new Map();
  if (L) {
    const clickers = L.elements('click').filter(el => !el.matches(CTL) &&
      !el.querySelector(CTL) && !el.matches(BTN));
    for (const s of clickers) {
      if (!shown(s) || s.closest('a[href]') || s.closest('form') || inContainer(s)) continue;
      let node = s.parentElement;
      for (let i = 0; node && i < 8; i++, node = node.parentElement) {
        const ctl = [...node.querySelectorAll(CTL)].filter(typed);
        if (!ctl.length) continue;
        const btns = [...node.querySelectorAll(BTN)].filter(buttonOk);
        const rivals = clickers.filter(o => o !== s && node.contains(o) && shown(o));
        if (!btns.length && !rivals.length && !ctl.some(inContainer) &&
            !containers.includes(node)) {
          containers.push(node);
          submitters.set(node, s);
        }
        break;
      }
    }
    for (const el of document.querySelectorAll('input')) {
      if (!ENTER.includes(kindOf(el)) || !shown(el) || inContainer(el)) continue;
      if (!['keydown', 'keyup', 'keypress'].some(t => L.has(el, t))) continue;
      const node = el.parentElement || el;
      const ctl = [...node.querySelectorAll(CTL)].filter(typed);
      if (ctl.some(c => kindOf(c) === 'password' || inContainer(c))) continue;
      // no button, hidden or shown, and no click-listened element within three levels
      // (review M3): Enter must never stand in for a button the gate did not judge
      let near = false;
      for (let n = el.parentElement, i = 0; n && i < 3 && !near; i++, n = n.parentElement)
        near = !!n.querySelector(BTN) || clickers.some(o => n.contains(o));
      if (near || el.form) continue;
      containers.push(node);
      enters.set(node, el);
    }
  }
  window.__fuzzlabN = (window.__fuzzlabN || 0) + 1;
  const run = window.__fuzzlabN;
  const out = [];
  containers.slice(0, maxForms).forEach((c, fi) => {
    const btns = [...c.querySelectorAll(BTN)].filter(buttonOk);
    const submit = submitters.get(c) ||
      btns.find(b => (b.getAttribute('type') || 'submit').toLowerCase() === 'submit') || btns[0];
    let enterEl = enters.get(c) || null;
    if (!submit && !enterEl && c.tagName.toLowerCase() === 'form' &&
        !hasDefaultButton(c)) {
      // implicit submission with no default button: one text field only (review M1)
      const texts = [...c.elements].filter(e => e.tagName.toLowerCase() === 'input' &&
        ENTER.includes(kindOf(e)) && shown(e));
      enterEl = texts.length === 1 ? texts[0] : null;
    }
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
    // container hints (G1e): the attribute values and label texts of the container, and
    // a canvas challenge -- recorded only; no CAPTCHA form is refused since D71
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
              hints: hints.slice(0, 400), challenge,
              submit_by: submit ? 'click' : (enterEl ? 'enter' : null),
              submitter: submitters.has(c) ? 'listener' : (submit ? 'button' : null),
              submitter_long: submitters.has(c) &&
                (submit.textContent || '').replace(/\s+/g, ' ').trim().length > 100,
              enter_id: enterEl ? enterEl.getAttribute('data-fuzzlab-id') : null});
  });
  return out;
}
""".replace("__ENTER__", json.dumps(list(ENTER_KINDS)))


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
    reason = sendpolicy.destructive(text_destructive_reason(text)
                                    or text_destructive_reason(_base_forms(text)))
    if reason:
        return f"destructive ({reason!r})"
    word = settings_word(text)
    if word:
        return f"settings-like ({word!r})"
    word = sendpolicy.transaction(transaction_reason(text))
    if word:
        return f"transaction ({word!r})"
    word = sendpolicy.credential_change(_account_hit(text))     # D71: the credential rule
    if word:
        return f"account word ({word!r})"
    return None


def reveal_refusal(labels) -> str | None:
    """Why a reveal candidate or a revealed menu item is never clicked: never, since D72
    (G2d superseded). A reveal click is a visit: the reveal window (W1-W3) still holds
    every write it causes -- any method but GET/HEAD, a navigation (queued instead), a
    WebSocket message -- so no label, glyph or word is judged any more. Kept as the one
    place a reveal is gated, so a later rule has one home (PA-0003)."""
    return None


# --- CAPTCHA (G1e): dropped by the owner (D71) -------------------------------------------
# A CAPTCHA form is submitted like any other form: no CAPTCHA is solved, and the app's
# answer to a wrong one is recorded like any other response. `FORMS_JS` still reports
# a container's ``hints`` and a ``challenge`` canvas; nothing refuses on them.


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
    navigation (its target is queued through the normal gates instead), and every method
    but GET and HEAD, whatever its destination. *(D72:)* a GET or HEAD that is not a
    navigation goes through whatever its words: the destructive, transaction, account-
    action and credential-token GET rules of W2 are superseded."""
    if navigation:
        return "a navigation (its target is queued instead)"
    method = (method or "").upper()
    if method not in ("GET", "HEAD"):
        return f"a {method or '(no method)'} request"
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
  const L = window.__fuzzlabListen;                 // CC-CRAWL-0038, when present
  const selfInteractive = el => el.matches('button, [role=button], ' +
    '[tabindex]:not([tabindex="-1"]), [onclick]') || typeof el.onclick === 'function' ||
    getComputedStyle(el).cursor === 'pointer' || (!!L && L.has(el, 'click'));
  const words = t => (t || '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const cardLabels = el => {
    if (el.matches(ICONS))                              // itself an icon (review M2)
      return {labels: ['', squash(el.getAttribute('aria-label') || el.getAttribute('title')),
                       squash(el.textContent)], long: false};
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
  // CC-CRAWL-0038: an element the app gave a click listener (a framework binding, no
  // role or class to find it by) is a card too, under the same rules
  // (not a form-like container's submitter: within three levels of a typed control)
  const nearControl = el => { let n = el.parentElement;
    for (let i = 0; n && i < 3; i++, n = n.parentElement)
      if (n.querySelector('input, textarea, select')) return true;
    return false; };
  if (L) for (const el of L.elements('click')) {
    if (seen.has(el) || !usable(el) || el.matches('button, a, label, option, ' +
        'summary, ' + CARDS) || nearControl(el)) continue;
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
  if (el.matches(ICONS))                                // itself an icon (review M2)
    return ['', squash(el.getAttribute('aria-label') || el.getAttribute('title')),
            squash(el.textContent)];
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


# =====================================================================================
# Forms phase 5: route query parameters (FR-CRAWL-17)
# =====================================================================================
# --- Q1/Q2: the scan --------------------------------------------------------------------
#: How far one anchor's window reaches (characters); a window also ends at the next
#: anchor of the same kind and at the end of its call's argument list.
QUERY_WINDOW = 512
#: The walker's step budget per script (review A-S1, S4): every character or token the
#: Python-level walker examines is one step; the scan stops when it is spent
#: (`QueryScan.budget_hit`, counted). A noise anchor costs O(1) steps, a window at most
#: about `QUERY_WINDOW`, so the budget bounds the walk whatever the anchors are.
MAX_QUERY_STEPS = 2_000_000
#: At most this many distinct names are taken from one script.
MAX_QUERY_NAMES = 50
#: A name longer than this is not a query-parameter name.
MAX_QUERY_NAME_LEN = 64
#: Observable / ParamMap members, never a parameter name (``queryParams.subscribe``).
QUERY_MEMBERS = frozenset({"subscribe", "pipe", "get", "has", "keys", "getAll",
                           "forEach", "toString"})
#: How far back a Vue ``query:{`` may find the ``push(`` / ``replace(`` it belongs to.
_MAX_CALL_BACK = 200
_ID_START = frozenset(string.ascii_letters + "_")
_ID_CHARS = _ID_START | frozenset(string.digits)
_JS_ID_CHARS = _ID_CHARS | {"$"}
#: The anchors, the only places a name is read (never a bare ``get(`` or ``query``).
_Q_NAVIGATE = "navigate("
_Q_NAVIGATE_URL = "navigateByUrl("
_Q_PARAMS_OBJ = "queryParams:"
_Q_PARAMS_DOT = "queryParams."
_Q_PARAMS_IDX = "queryParams["
_Q_PARAM_MAP = "queryParamMap.get("
_Q_SEARCH_PARAMS = "searchParams.get("
_Q_URL_SEARCH = "URLSearchParams("
_Q_VUE_ROUTE = "route.query."
_Q_VUE_QUERY = "query:"
_Q_JSX_LINK = "<Link"
_Q_JS_LINK = "Link,{"
_QUERY_ANCHORS = (_Q_NAVIGATE, _Q_NAVIGATE_URL, _Q_PARAMS_OBJ, _Q_PARAMS_DOT,
                  _Q_PARAMS_IDX, _Q_PARAM_MAP, _Q_SEARCH_PARAMS, _Q_URL_SEARCH,
                  _Q_VUE_ROUTE, _Q_VUE_QUERY, _Q_JSX_LINK, _Q_JS_LINK)
#: `QueryScan.refused` reasons (counted, never logged with a name).
Q_DYNAMIC = "dynamic segment"
Q_NONLITERAL = "non-literal query"
Q_SENSITIVE = "sensitive name"
Q_NAME_CAP = "name cap"
Q_SHAPE = "not identifier-shaped"


class _BudgetSpent(Exception):
    """The walker's step budget is spent: the scan stops (`QueryScan.budget_hit`)."""


class StepCounter:
    """The operation counts of a scan (BUG-0135, PA-0135): ``steps`` is the
    Python-level work (each character, token or loop turn a walker examines), ``scanned``
    the characters the body-level ``str.find`` calls covered. A complexity test asserts
    on these, never on a wall-clock ratio. ``budget`` (None: unbounded) stops a walk
    that would spend more steps."""

    def __init__(self, budget: int | None = None):
        self.steps = 0
        self.scanned = 0
        self.budget = budget

    def tick(self, n: int = 1) -> None:
        self.steps += n
        if self.budget is not None and self.steps > self.budget:
            raise _BudgetSpent


@dataclass
class QueryScan:
    """What `scan_query_params` read from one script: ``pairs`` (route -> names, in
    order), ``unpaired`` names (read with no route), ``refused`` counts by reason,
    ``anchors`` examined, whether the step budget stopped the scan (``budget_hit``), and
    its operation counts (``steps``, ``scanned``; `StepCounter`)."""
    pairs: dict = field(default_factory=dict)
    unpaired: list = field(default_factory=list)
    refused: dict = field(default_factory=dict)
    anchors: int = 0
    budget_hit: bool = False
    steps: int = 0
    scanned: int = 0

    def _refuse(self, reason: str) -> None:
        self.refused[reason] = self.refused.get(reason, 0) + 1


def scan_script(text: str, max_bytes: int = MAX_SCRIPT_BYTES):
    """``(routes, QueryScan)`` for one same-origin script body -- the crawler's one call
    per script it already loaded (FR-CRAWL-12 and FR-CRAWL-17) -- or None when ``text``
    is longer than ``max_bytes`` (not scanned). Two linear scans of the same body, each
    with its own operation bound (PA-0095, PA-0135)."""
    if len(text) > max_bytes:
        return None
    return scan_routes(text, max_bytes), scan_query_params(text, max_bytes)


def _ws(st: StepCounter, text: str, i: int, hi: int) -> int:
    """`_skip_ws` up to ``hi``, each skipped character a step."""
    j = _skip_ws(text, i, max(0, hi - i))
    st.tick(j - i + 1)
    return j


def _string_end(st: StepCounter, text: str, i: int, hi: int) -> int | None:
    """The index of the quote closing the string literal opened at ``i`` (escapes
    honoured), searched only before ``hi``; None when it does not close."""
    quote = text[i]
    j = text.find(quote, i + 1, hi)
    st.tick()
    while j > 0:
        k = j - 1
        while k > i and text[k] == "\\":
            k -= 1
        st.tick(j - k)
        if (j - 1 - k) % 2 == 0:                  # an even run of backslashes: closed
            return j
        j = text.find(quote, j + 1, hi)
    return None


def _literal(st: StepCounter, text: str, i: int, hi: int):
    """``(value, end)`` for the string literal at ``i``: ``value`` None when it is a
    template literal with a substitution (not literal); ``end`` its closing quote, or
    None (not a string, or unterminated before ``hi``)."""
    if i >= hi or text[i] not in _QUOTES:
        return None, None
    end = _string_end(st, text, i, hi)
    if end is None:
        return None, None
    value = text[i + 1:end]
    if text[i] == "`" and "${" in value:
        return None, end
    return value, end


def _skip_value(st: StepCounter, text: str, i: int, hi: int) -> int | None:
    """From ``i``, skip one expression: the index of the first ``,`` or closing bracket
    at depth 0 (strings skipped), or None when ``hi`` comes first."""
    depth = 0
    while i < hi:
        st.tick()
        c = text[i]
        if c in _QUOTES:
            end = _string_end(st, text, i, hi)
            if end is None:
                return None
            i = end + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif c == "," and depth == 0:
            return i
        i += 1
    return None


def _close(st: StepCounter, text: str, i: int, hi: int) -> int | None:
    """The index of the bracket closing the one at ``i``, or None before ``hi``."""
    j = _skip_value(st, text, i + 1, hi)
    while j is not None and text[j] == ",":
        j = _skip_value(st, text, j + 1, hi)
    return j


def _ident(st: StepCounter, text: str, i: int, hi: int,
           chars=_JS_ID_CHARS) -> tuple[str, int]:
    j = i
    while j < hi and text[j] in chars:
        j += 1
    st.tick(j - i + 1)
    return text[i:j], j


def _object_keys(st: StepCounter, text: str, i: int, hi: int):
    """``(keys, end)`` for the object literal whose ``{`` is at ``i``: each depth-1 key
    as ``(name, value_index, quoted)`` (``value_index`` None for a shorthand ``{q}``),
    ``end`` its closing ``}``; None when it does not close before ``hi``. Methods,
    spreads and computed keys are skipped."""
    keys = []
    j = i + 1
    while j < hi:
        j = _ws(st, text, j, hi)
        if j >= hi:
            return None
        c = text[j]
        if c == "}":
            return keys, j
        name, quoted = None, False
        if c in _QUOTES:
            name, end = _literal(st, text, j, hi)
            if end is None:
                return None
            quoted, j = True, end + 1
        elif c in _ID_START or c == "$":
            name, j = _ident(st, text, j, hi)
        k = _ws(st, text, j, hi)
        if k >= hi:
            return None
        if name is not None and text[k] == ":":
            value = _ws(st, text, k + 1, hi)
            keys.append((name, value, quoted))
            j = _skip_value(st, text, value, hi)
        elif name is not None and text[k] in ",}":
            keys.append((name, None, quoted))
            j = k
        else:                                     # a method, a spread, a computed key
            j = _skip_value(st, text, k, hi)
        if j is None:
            return None
        if text[j] == "}":
            return keys, j
        if text[j] != ",":
            return None
        j += 1
    return None


def query_name_ok(name) -> bool:
    """A query-parameter name the scan takes: identifier characters only (ASCII
    letters, digits, ``_``; not starting with a digit), at most `MAX_QUERY_NAME_LEN`,
    never an Observable / ParamMap member (`QUERY_MEMBERS`)."""
    return (isinstance(name, str) and 0 < len(name) <= MAX_QUERY_NAME_LEN
            and name[0] in _ID_START and all(ch in _ID_CHARS for ch in name)
            and name not in QUERY_MEMBERS)


class _QueryState:
    def __init__(self, st: StepCounter):
        self.st = st
        self.scan = QueryScan()
        self.names: dict[str, None] = {}

    def take(self, name, route: str | None = None, *, literal: bool = False) -> None:
        """Keep ``name`` (paired with ``route``, or unpaired): identifier-shaped, not
        sensitive (counted by class only), within the per-script cap. A name written as
        a string literal (a quoted key, a ``get("x")`` argument) that is not
        identifier-shaped is counted (``not identifier-shaped``, review A-N2)."""
        if not query_name_ok(name):
            if literal and isinstance(name, str) and name and name not in QUERY_MEMBERS:
                self.scan._refuse(Q_SHAPE)
            return
        if is_sensitive_name(name):
            self.scan._refuse(Q_SENSITIVE)
            return
        if name not in self.names:
            if len(self.names) >= MAX_QUERY_NAMES:
                self.scan._refuse(Q_NAME_CAP)
                return
            self.names[name] = None
        if route is None:
            if name not in self.scan.unpaired:
                self.scan.unpaired.append(name)
        else:
            got = self.scan.pairs.setdefault(route, [])
            if name not in got:
                got.append(name)

    def take_query_text(self, query: str, route: str | None) -> None:
        for part in query.split("&"):
            self.st.tick()
            self.take(part.partition("=")[0], route, literal=True)


def _known_route(route: str | None) -> str | None:
    """``route``, or None when it is relative -- a ``.`` / ``..`` segment (review A2-S3,
    U7): its names are then unpaired, never counted as a pair `classify_route` would
    refuse later."""
    if route is None:
        return None
    segs = route.split("?", 1)[0].lstrip("#!").split("/")
    return None if any(seg in (".", "..") for seg in segs) else route


def _literal_url(state: _QueryState, value: str) -> None:
    """A literal ``"/x?a=1&b"`` (React ``navigate`` / ``<Link to>``, Angular
    ``navigateByUrl``): its names paired with its route, or unpaired when it names no
    route (``?a=1``)."""
    route, sep, query = value.partition("?")
    if sep:
        state.take_query_text(query.split("#", 1)[0], _known_route(route or None))


def _query_object(state: _QueryState, text: str, i: int, hi: int, route: str | None,
                  *, count_nonliteral: bool = True) -> int | None:
    """The ``queryParams`` / ``query`` value at ``i``: an object literal's keys are taken
    (paired with ``route`` or unpaired); anything else is a non-literal query (counted).
    Returns the end of the value, or None."""
    st = state.st
    if i < hi and text[i] == "{":
        got = _object_keys(st, text, i, hi)
        if got is None:
            return None
        for name, _value, quoted in got[0]:
            state.take(name, route, literal=quoted)
        return got[1]
    if count_nonliteral:
        state.scan._refuse(Q_NONLITERAL)
    return _skip_value(st, text, i, hi)


def _scan_navigate(state: _QueryState, text: str, i: int, hi: int) -> int | None:
    """Angular ``navigate([route, ...], {queryParams: {...}})`` or a React literal
    ``navigate("/x?a=")``. An all-literal array is the route (elements joined with
    ``/``); a multi-element array with any non-literal element is a dynamic segment
    (refused, its names dropped: no element is ever seeded alone, B7, A-S2); an empty
    array or a lone non-literal element names no known route, so its names are
    unpaired, as are a navigation ``relativeTo`` another route's (review A-S2: the
    route is relative). Returns the call's end."""
    st = state.st
    j = _ws(st, text, i, min(hi, i + _MAX_GAP))
    if j >= hi:
        return None
    if text[j] in _QUOTES:                                   # React: navigate("/x?a=")
        value, end = _literal(st, text, j, hi)
        if value is not None:
            _literal_url(state, value)
        return end
    if text[j] != "[":
        return None
    parts, literal, k, count = [], True, j + 1, 0
    while True:
        k = _ws(st, text, k, hi)
        if k >= hi:
            return None
        if text[k] == "]":
            break
        count += 1
        value, end = _literal(st, text, k, hi)
        if value is not None:
            parts.append(value)
            k = _ws(st, text, end + 1, hi)
        else:
            literal = False
            k = _skip_value(st, text, k, hi)
            if k is None:
                return None
        if k >= hi:
            return None
        if text[k] == ",":
            k += 1
        elif text[k] != "]":
            return None
    if literal and parts:
        route = "/".join(p.strip("/") for p in parts if p.strip("/")) or "/"
    else:
        route = None
    dynamic = count > 1 and not literal
    k = _ws(st, text, k + 1, hi)
    if k >= hi or text[k] != ",":
        return k if k < hi else None                          # no options: no query
    k = _ws(st, text, k + 1, hi)
    if k >= hi or text[k] != "{":
        return _skip_value(st, text, k, hi)                   # options not literal
    got = _object_keys(st, text, k, hi)
    if got is None:
        return None
    keys, end = got
    if any(name == "relativeTo" for name, _v, _q in keys):
        route = None                                          # relative: unpaired
    route = _known_route(route)
    for name, value, _quoted in keys:
        if name != "queryParams" or value is None:
            continue
        if dynamic:
            if value < hi and text[value] == "{":
                sub = _object_keys(st, text, value, hi)
                if sub is not None and any(query_name_ok(n) for n, _v, _q in sub[0]):
                    state.scan._refuse(Q_DYNAMIC)
            continue
        _query_object(state, text, value, hi, route)
    return end


def _scan_navigate_url(state, text, i, hi):
    """Angular ``navigateByUrl("/x?a=1")``: a literal URL, as a React literal (review
    A-N1). A non-literal argument gives nothing."""
    st = state.st
    j = _ws(st, text, i, min(hi, i + _MAX_GAP))
    value, end = _literal(st, text, j, hi)
    if value is not None:
        _literal_url(state, value)
    return end


def _after_identifier(text: str, p: int) -> bool:
    """The anchor at ``p`` continues a longer identifier (``myqueryParams:``)."""
    return p > 0 and text[p - 1] in _JS_ID_CHARS


def _scan_params_obj(state, text, p, i, hi):
    """A ``queryParams: {...}`` outside a ``navigate`` call: its names, unpaired (never
    part of a longer name, review A-N4)."""
    if _after_identifier(text, p):
        return None
    j = _ws(state.st, text, i, min(hi, i + _MAX_GAP))
    if j >= hi or text[j] != "{":
        return None
    return _query_object(state, text, j, hi, None, count_nonliteral=False)


def _member(state, text, i, hi):
    """``queryParams.<name>`` / ``route.query.<name>``: unpaired, unless it is a member
    call (``.subscribe(``, any name followed by ``(``)."""
    name, j = _ident(state.st, text, i, hi)
    k = _ws(state.st, text, j, hi)
    if name and not (k < hi and text[k] == "("):
        state.take(name)
    return j


def _quoted_arg(state, text, i, hi):
    """``queryParams["q"]`` / ``.get("q")``: the literal, unpaired."""
    j = _ws(state.st, text, i, min(hi, i + _MAX_GAP))
    value, end = _literal(state.st, text, j, hi)
    if value is not None:
        state.take(value, literal=True)
    return end


def _scan_url_search(state, text, i, hi):
    """``URLSearchParams(...).get("q")``."""
    close = _close(state.st, text, i - 1, hi)
    if close is None:
        return None
    j = _ws(state.st, text, close + 1, hi)
    if not text.startswith(".get(", j):
        return close
    return _quoted_arg(state, text, j + 5, hi)


def _scan_vue_route(state, text, i, hi):
    """``this.$route.query.q`` / ``route.query.q`` (not ``myroute.query``)."""
    before = text[i - 1] if i > 0 else ""
    if before and before in _ID_CHARS:
        return None
    return _member(state, text, i + len(_Q_VUE_ROUTE), hi)


def _scan_vue_push(state, text, i, hi, floor):
    """Vue ``router.push({path: '/x', query: {a: ..}})`` (or ``replace``): the
    ``query:{`` anchor at ``i`` counts only as a depth-1 key of a ``push(`` /
    ``replace(`` call's object found at most `_MAX_CALL_BACK` back (and not before
    ``floor``, the end of the previous window). Paired with a literal ``path``; a
    ``name:`` route or a non-literal path leaves its names unpaired."""
    st = state.st
    if _after_identifier(text, i):
        return None
    brace = _ws(st, text, i + len(_Q_VUE_QUERY), min(len(text), i + 64))
    if brace >= len(text) or text[brace] != "{":
        return None
    lo = max(floor, i - _MAX_CALL_BACK)
    call = max(text.rfind("push(", lo, i), text.rfind("replace(", lo, i))
    st.tick()
    st.scanned += 2 * (i - lo)                                # the bounded look-back
    if call < 0:
        return None
    obj = _ws(st, text, text.find("(", call) + 1, i)
    if obj >= i or text[obj] != "{":
        return None
    got = _object_keys(st, text, obj, min(len(text), obj + QUERY_WINDOW))
    if got is None:
        return None
    keys, end = got
    if not any(name == "query" and value == brace for name, value, _q in keys):
        return None
    route = None
    for name, value, _q in keys:
        if name == "path" and value is not None:
            route, _e = _literal(st, text, value, end)
    _query_object(state, text, brace, end, _known_route(route))
    return end


def _scan_jsx_link(state, text, i, hi):
    """``<Link to="/x?a=">`` (or ``to={"/x?a="}``) in a JSX string."""
    st = state.st
    if i + len(_Q_JSX_LINK) >= hi or text[i + len(_Q_JSX_LINK)] not in " \t\r\n":
        return None
    close = text.find(">", i, hi)
    st.tick()
    if close < 0:
        return None
    at = text.find("to=", i, close)
    while at >= 0 and text[at - 1] not in " \t\r\n":
        st.tick()
        at = text.find("to=", at + 3, close)
    if at < 0:
        return close
    j = at + 3
    if j < close and text[j] == "{":
        j += 1
    value, _end = _literal(st, text, j, close)
    if value is not None:
        _literal_url(state, value)
    return close


def _scan_js_link(state, text, i, hi):
    """Compiled JSX ``(Link,{to:"/x?a="})``."""
    st = state.st
    got = _object_keys(st, text, i + len(_Q_JS_LINK) - 1, hi)
    if got is None:
        return None
    for name, value, _q in got[0]:
        if name == "to" and value is not None:
            literal, _e = _literal(st, text, value, got[1])
            if literal is not None:
                _literal_url(state, literal)
    return got[1]


def scan_query_params(text: str, max_bytes: int = MAX_SCRIPT_BYTES, *,
                      budget: int = MAX_QUERY_STEPS) -> QueryScan | None:
    """The query-parameter names ``text`` reads (FR-CRAWL-17, Q1/Q2), or None when it
    is longer than ``max_bytes``.

    **Paired** (route, names): Angular ``navigate([`/r`], {queryParams: {id: t}})``,
    ``navigateByUrl("/r?a=")``, Vue ``push({path: '/r', query: {q: x}})`` and React
    literals (``navigate("/r?a=")``, ``<Link to="/r?a=">``). **Unpaired** names:
    ``queryParams.id``, ``queryParams["id"]``, ``queryParamMap.get("id")``,
    ``searchParams.get("id")``, ``URLSearchParams(..).get("id")``, ``$route.query.id`` /
    ``route.query.id``, a ``queryParams: {..}`` object outside a ``navigate`` call, and a
    navigation ``relativeTo`` another route. Names are identifier-shaped
    (`query_name_ok`); a sensitive name (`core.redaction.is_sensitive_name`) is dropped
    and counted by class only; at most `MAX_QUERY_NAMES` per script.

    The bound (review A-M2, BUG-0135): each anchor kind is searched with ``str.find``
    from a position that only moves forward (monotone: each kind's searches together
    cover the body at most once; ``scanned`` counts them, and each window's bounded
    search, at most `QUERY_WINDOW` per anchor), and every Python-level step of the
    walker -- each character, token and loop turn it examines, inside a window that ends
    at ``min(anchor + QUERY_WINDOW, the next anchor of the same kind, the end of its
    call)`` -- is counted against ``budget`` (``steps``; `MAX_QUERY_STEPS`), which stops
    the scan when spent (``budget_hit``). So the scan is O(len(text)) C-level finds plus
    at most ``budget`` steps (PA-0095, PA-0135)."""
    if len(text) > max_bytes:
        return None
    st = StepCounter(budget)
    state = _QueryState(st)
    nxt = {}
    for a in _QUERY_ANCHORS:
        nxt[a] = text.find(a)
        st.scanned += (nxt[a] if nxt[a] >= 0 else len(text))
    floor = 0
    try:
        while True:
            live = [(p, a) for a, p in nxt.items() if p >= 0]
            st.tick()
            if not live:
                break
            p, anchor = min(live)
            state.scan.anchors += 1
            start = p + len(anchor)
            same = text.find(anchor, start, p + QUERY_WINDOW)
            hi = same if same >= 0 else min(len(text), p + QUERY_WINDOW)
            st.scanned += hi - start                          # the bounded window find
            if anchor == _Q_NAVIGATE:
                end = _scan_navigate(state, text, start, hi)
            elif anchor == _Q_NAVIGATE_URL:
                end = _scan_navigate_url(state, text, start, hi)
            elif anchor == _Q_PARAMS_OBJ:
                end = _scan_params_obj(state, text, p, start, hi)
            elif anchor == _Q_PARAMS_DOT:
                end = None if _after_identifier(text, p) else \
                    _member(state, text, start, hi)
            elif anchor == _Q_PARAMS_IDX:
                end = None if _after_identifier(text, p) else \
                    _quoted_arg(state, text, start, hi)
            elif anchor in (_Q_PARAM_MAP, _Q_SEARCH_PARAMS):
                end = _quoted_arg(state, text, start, hi)
            elif anchor == _Q_URL_SEARCH:
                end = _scan_url_search(state, text, start, hi)
            elif anchor == _Q_VUE_ROUTE:
                end = _scan_vue_route(state, text, p, hi)
            elif anchor == _Q_VUE_QUERY:
                end = _scan_vue_push(state, text, p, hi, floor)
            elif anchor == _Q_JSX_LINK:
                end = _scan_jsx_link(state, text, p, hi)
            else:
                end = _scan_js_link(state, text, p, hi)
            pos = max(start, (end + 1) if end is not None else start)
            floor = max(floor, pos if end is not None else floor)
            for a, at in nxt.items():
                if 0 <= at < pos:
                    found = text.find(a, pos)
                    st.scanned += (found if found >= 0 else len(text)) - pos
                    nxt[a] = found
    except _BudgetSpent:
        state.scan.budget_hit = True
    state.scan.steps, state.scan.scanned = st.steps, st.scanned
    return state.scan


# --- Q3: seeds and probe URLs -------------------------------------------------------------
#: The crawl-queue sources of a seed visit (stored as the page's ``source``) and of a
#: probe load (never stored).
SEED_SOURCE = "spa-query"
PROBE_SOURCE = "spa-query-probe"
#: A seed whose window blocked a write (a non-GET): kept as a page, never imported as a
#: point -- an M6 fuzz load of it would send that write outside any window (review A-M1;
#: `tools.store_adapter.import_spider` reads it).
WRITE_SEED_SOURCE = "spa-query-writes"


#: The value a seed gives each name: the text filler (`store_adapter`'s, PA-0003).
def query_filler() -> str:
    return filler("text")


def redirect_name(name: str) -> bool:
    """Whether ``name`` is redirect-ish: one of its whole tokens
    (`core.redaction.name_tokens`), or the whole name, is in the shared open-redirect
    name set (`core.urls.REDIRECT_PARAMS`, the one definition, PA-0003). Such a name is
    given the same-origin path ``/`` in seeds and probes, never the filler. That is
    hygiene: the guard is the window, which aborts every navigation a load makes (B6,
    review A-S5)."""
    from fuzzlab.core.urls import REDIRECT_PARAMS
    low = (name or "").lower()
    return low in REDIRECT_PARAMS or bool(set(name_tokens(name or "")) & REDIRECT_PARAMS)


def query_value(name: str, value: str) -> str:
    """``value`` for ``name`` -- or ``/`` when the name is redirect-ish."""
    return "/" if redirect_name(name) else value


def query_url(route_url: str, pairs) -> str:
    """``route_url`` with ``pairs`` (``[(name, value)]``) as its route's query: in a hash
    route's fragment (``#/r?a=x``), else the URL's own query (history mode)."""
    query = "&".join(f"{n}={v}" for n, v in pairs)
    head, sep, frag = route_url.partition("#")
    if sep:
        joiner = "&" if "?" in frag else "?"
        return f"{head}#{frag}{joiner}{query}"
    joiner = "&" if "?" in head else "?"
    return f"{head}{joiner}{query}"


def seed_url(route_url: str, names) -> str:
    """A seed: ``route_url`` with each name set to the filler (``/`` for a redirect-ish
    name, `query_value`)."""
    return query_url(route_url, [(n, query_value(n, query_filler())) for n in names])


def query_url_refusal(url: str) -> str | None:
    """Why a seed or probe URL is never loaded (FR-CRAWL-17, Q3; A-M1), or None. *(D72:)*
    never for its words: a seed or probe load is a GET visit, and its window still holds
    every write the load causes (U1, B2). Kept as the one gate for a query load's URL."""
    return None


def filler_in_path(url: str) -> bool:
    """A seed's filler as a whole path segment of a request ``url`` (Q6: a value in a
    path gives no point; counted with the probe's markers in a path)."""
    from urllib.parse import unquote
    return query_filler() in unquote(urlsplit(url or "").path).split("/")


# --- Q5: the observation probe's markers ----------------------------------------------------
#: At most this many routes are probed per crawl, and this many names per probe load.
MAX_QUERY_PROBE_ROUTES = 40
MAX_UNPAIRED_NAMES = 12
#: Markers: letters only, fixed length, fresh per load (B2, A-M3): the prefix, the
#: name's index in two letters, then `MARKER_RAND_LEN` random letters. All lower case,
#: so every marker is word-shaped and never `looks_like_identifier` (pinned by a test).
MARKER_PREFIX = "fzq"
MARKER_ALPHABET = string.ascii_lowercase
MARKER_INDEX_LEN = 2
MARKER_RAND_LEN = 8
MARKER_LEN = len(MARKER_PREFIX) + MARKER_INDEX_LEN + MARKER_RAND_LEN


def mint_markers(count: int) -> list[str]:
    """``count`` fresh markers for one probe load (a new random part each call): only
    the current load's markers are ever attributed (PA-0090)."""
    if not 0 <= count <= MAX_UNPAIRED_NAMES:
        raise ValueError("marker count out of range")
    width = len(MARKER_ALPHABET)
    out = []
    for n in range(count):
        index = MARKER_ALPHABET[n // width] + MARKER_ALPHABET[n % width]
        rand = "".join(secrets.choice(MARKER_ALPHABET) for _ in range(MARKER_RAND_LEN))
        out.append(MARKER_PREFIX + index + rand)
    return out


def _bounded_hit(text: str, marker: str) -> bool:
    """``marker`` in ``text`` with a non-alphanumeric character (or the edge) on each
    side."""
    i = text.find(marker)
    while i >= 0:
        j = i + len(marker)
        if (i == 0 or not text[i - 1].isalnum()) and (j == len(text) or
                                                      not text[j].isalnum()):
            return True
        i = text.find(marker, i + 1)
    return False


def _name_assignment(text: str, names) -> bool:
    """``text`` carries ``<name>=`` syntax for one of the probed ``names`` (a whole
    name: no identifier character before it)."""
    for name in names:
        i = text.find(name + "=")
        while i >= 0:
            if i == 0 or text[i - 1] not in _JS_ID_CHARS:
                return True
            i = text.find(name + "=", i + 1)
    return False


#: Strings longer than this are not judged (not counted: fail closed).
MAX_OBSERVED_STRING = 8192


def observed_names(texts, requests, markers: dict, names, *, doc_path: str | None = None,
                   route: str | None = None) -> tuple[set, int]:
    """``(kept names, marker-in-path count)`` for one probe load (FR-CRAWL-17, Q5).

    ``markers`` maps **this load's** markers to their names; nothing else is ever
    attributed (a stale marker from an earlier load matches none of them). ``texts``
    are the rendered DOM's strings (`OBSERVE_JS`); ``requests`` the ``(url, body,
    blocked)`` of every request the load made (the request hook, aborted ones included).
    A **blocked** request (aborted by the window or the guard) is never evidence: a
    name whose only evidence is a blocked request is not kept (review A-M1). The
    caller marks requests blocked by URL, which is conservative: a completed GET to a
    URL that was also blocked (as a POST, say) is not evidence either (review B-N4).
    Blocked includes every request of the load that failed while the window was open
    (a request whose redirect hop the window refused fails, Y1); matching is by the
    exact URL string the page requested (review A3-N2).

    A marker counts where it appears with non-alphanumeric boundaries in a string that
    carries no other of this load's markers. ``<name>=`` syntax of a probed name also
    discounts it (a URL self-echo -- ``location.href`` in a link, a canonical URL, B5) in
    a DOM string and a body, but in a request **URL** only when that URL is a copy of the
    page's own: its path is the document's (``doc_path``) or it carries the fragment
    route (``route``, e.g. ``#/search``) -- an app's API forwarding ``?q=<marker>``
    keeps ``q`` (review A-S3). A marker in a request URL's path is counted
    (``marker_in_path``); it still keeps the name (no server-side point comes from it,
    Q6)."""
    from urllib.parse import unquote
    kept: set = set()
    in_path = 0
    judged = [(t, None) for t in texts or [] if isinstance(t, str)]
    for entry in requests or []:
        url, body = entry[0], entry[1]
        if len(entry) > 2 and entry[2]:
            continue                                    # blocked: never evidence
        judged.append((unquote(url or ""), "url"))
        if body:
            judged.append((unquote(body), None))
    for text, kind in judged:
        if len(text) > MAX_OBSERVED_STRING:
            continue
        hits = [m for m in markers if _bounded_hit(text, m)]
        if len(hits) != 1:
            continue
        if kind == "url":
            self_copy = (doc_path is not None and urlsplit(text).path == doc_path) or \
                bool(route and route in text)
            if self_copy and _name_assignment(text, names):
                continue
        elif _name_assignment(text, names):
            continue
        kept.add(markers[hits[0]])
        if kind == "url" and _bounded_hit(urlsplit(text).path, hits[0]):
            in_path += 1
    return kept, in_path


#: A marker as a whole token (fixed shape): what `scrub_markers` replaces.
_MARKER_RE = None
#: What a marker becomes in every stored row (review A-S4).
MARKER_PLACEHOLDER = "__FUZZLAB_PROBE__"


def scrub_markers(text):
    """``text`` with every whole-token marker (`MARKER_PREFIX`, then `MARKER_INDEX_LEN` +
    `MARKER_RAND_LEN` lower-case letters) replaced by `MARKER_PLACEHOLDER`: applied at the
    spider's storage boundary, so a marker an app persisted and replays later never
    reaches a row. Total: a non-string is returned as is."""
    global _MARKER_RE
    if not isinstance(text, str) or MARKER_PREFIX not in text:
        return text
    if _MARKER_RE is None:
        import re
        _MARKER_RE = re.compile(r"(?<![A-Za-z0-9])" + MARKER_PREFIX + "[a-z]{%d}(?![A-Za-z0-9])"
                                % (MARKER_INDEX_LEN + MARKER_RAND_LEN))
    return _MARKER_RE.sub(MARKER_PLACEHOLDER, text)


#: ``prefix => [string]``: every text node, attribute value and form-control value of
#: the rendered document that contains ``prefix`` (at most 500 strings; 20000 nodes).
OBSERVE_JS = r"""
(prefix) => {
  const out = [];
  const push = s => { if (typeof s === 'string' && s.indexOf(prefix) >= 0 && out.length < 500)
    out.push(s); };
  const root = document.documentElement;
  if (!root) return out;
  const walk = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
  let n = 0;
  for (let node = walk.currentNode; node && n < 20000; node = walk.nextNode(), n++) {
    if (node.nodeType === 3) { push(node.nodeValue); continue; }
    for (const a of node.attributes || []) push(a.value);
    const tag = node.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') push(node.value);
  }
  return out;
}
"""
