"""Selector-form navigation for the crawler (FR-CRAWL-8, forms phase 1).

Some apps reach their pages only through a menu-like form: one ``<select>`` and a
button (bWAPP's "choose your bug" pickers POST a select and answer with a redirect).
A link-only crawler never sees those pages. This module decides which such forms may
be submitted, and with which options, and turns their redirects into links to crawl.

Submitting a form can change state, so the gate comes **before** any submission
(reviewers A/B):

* off unless the operator asks (``--follow-selector-forms``);
* a GET selector form may be enumerated (GET is safe); a POST one only when the
  operator **names its select** (``--follow-selector-forms bug``);
* a form whose select, control or submitter **name** is a settings word, or whose
  action is out of scope or destructive, is never submitted; an **option** whose value
  or label is a settings word or destructive is skipped;
* every response must be a cookie-less 3xx to an in-scope, non-destructive URL, or
  enumeration of that form stops; a redirect back to the form's own page or action is
  skipped, and five of those in a row mark a settings form (stop);
* option 4(a) (owner, 2026-10-17): a cookie-less 200 answer with an HTML body is the
  chosen page itself (an app that renders it instead of redirecting). With an
  ``on_page`` reader it is read as a page -- its links queued, its forms recorded --
  and enumeration goes on. An answer that adds nothing the picker's own page or an
  earlier answer did not show is a self-redirect: five in a row stop the form (a
  settings form when nothing was found before them). Without a reader, or with no HTML
  body, a non-redirect still stops;
* submissions go through an isolated client (the caller's ``submit``), so a response
  cookie never reaches the crawler.

The HTTP itself is the caller's ``submit(method, action_url, entries) -> (status,
headers)`` or ``(status, headers, html)`` (``html`` the body of a 2xx HTML answer, else
None); this module is pure and testable.
"""

from __future__ import annotations

import logging
from typing import Callable
from urllib.parse import urljoin, urlsplit

from fuzzlab.core.forms import FormEntries
from fuzzlab.core.redaction import name_tokens
from fuzzlab.core import sendpolicy
from fuzzlab.core.urls import destructive_reason, text_destructive_reason, url_key

#: A select or control named with one of these words configures something. Shared by
#: navigation (`refusal`, `option_refusal`) and the importer's POST-selector rule
#: (forms phase 2, FR-CRAWL-10 / FR-FUZZ-43). ``t`` is deliberately absent: a lone
#: ``t`` token comes from contractions ("Don't").
SETTINGS_WORDS = frozenset({
    "level", "security", "role", "status", "permission", "permissions", "admin",
    "enable", "disable", "active", "lang", "language", "theme", "mode",
    # forms phase 2 (reviewer B-R4)
    "sort", "tz", "currency", "country", "region", "layout", "skin", "view", "display",
    "default", "notify", "privacy", "visibility",
})
#: Adjacent tokens that together are a settings word (``per_page`` tokenises to
#: ``per``, ``page``; ``page`` alone must not count: it is a common content parameter).
SETTINGS_PAIRS = frozenset({("per", "page")})
#: This many self-redirects in a row, before any real navigation: a settings form.
MAX_SELF_REDIRECTS = 5
#: At most this many options of one form are submitted.
MAX_OPTIONS = 500
#: A 2xx answer's body is read up to this many characters (option 4(a)).
MAX_PAGE_CHARS = 2_000_000


def html_answer(status: int, headers: dict | None) -> bool:
    """A 2xx answer whose body is an HTML page (option 4(a)): the caller's ``submit``
    reads the body only for these."""
    low = {k.lower(): v for k, v in (headers or {}).items()}
    media = (low.get("content-type") or "").split(";")[0].strip().lower()
    return 200 <= status < 300 and media in ("text/html", "application/xhtml+xml")


def settings_word(text: str) -> str | None:
    """The settings word (or pair, as ``per_page``) in a control name, option value
    or label, matched by whole token; None when there is none."""
    toks = [t.lower() for t in name_tokens(text or "")]
    for tok in toks:
        if tok in SETTINGS_WORDS:
            return tok
    for pair in zip(toks, toks[1:]):
        if pair in SETTINGS_PAIRS:
            return "_".join(pair)
    return None


def signature(record: dict) -> tuple:
    """One enumeration per (method, select name, option values), whatever the action:
    the same header picker appears on every page."""
    opts = record.get("options") or []
    name = opts[0][0] if opts else ""
    return (record["method"], name, tuple(sorted(v for _n, v, _l in opts)))


def signature_key(record: dict) -> str:
    """`signature` as text: how the spider files a picker's verdict and the importer
    finds it again (one derivation, PA-0003)."""
    import json
    return json.dumps(signature(record))


class _AllSelects:
    """D73's "every select" (a generic run): tested by identity, never a name an
    operator can type."""

    def __repr__(self) -> str:
        return "ALL_SELECTS"


#: ``named`` for a generic run (D73): a POST picker is submitted without being named,
#: when `unnamed_post_refusal` finds nothing against it.
ALL_SELECTS = _AllSelects()

#: A select whose name is shorter than this cannot be judged by its name (``t``, ``v``,
#: ``tz``): an unnamed POST picker so named is never submitted, and the importer never
#: fuzzes one (forms phase 2, reviewer B-R4; one definition since D73).
MIN_JUDGEABLE_SELECT_NAME = 3

#: A submit button that says one of these sets something (D73 review M4): an unnamed
#: POST picker submitted by it is a settings form (bWAPP's security picker says "Set").
SETTER_WORDS = frozenset({"set", "save", "apply", "update", "change", "switch",
                          "select", "choose", "assign", "move"})


def unnamed_post_refusal(record: dict) -> str | None:
    """Why a POST picker the operator did not name must never be submitted (D73), or
    None. The importer's own rule for a POST form first (`store_adapter.form_skip_reason`
    without a verdict: multipart, settings controls, a select too short to judge,
    credential and account changes, a destructive action or entry, hidden ones
    included), then the transaction rule on the action, the entries and the submit
    button, a submit button that sets something or is missing, and a button that sends
    the form elsewhere (``formaction``...). Option labels are not judged by the
    transaction rule: they name the page chosen, not what the submission does."""
    from fuzzlab.core.urls import transaction_reason
    from fuzzlab.tools.store_adapter import form_skip_reason
    reason = form_skip_reason({**record, "verdict": None})
    if reason:
        return reason
    sub = record.get("submitter")
    if not sub:
        return "no enabled submit button"
    if sub.get("overrides"):
        return f"submit button overrides {', '.join(sub['overrides'])}"
    texts = [record["action_url"], sub.get("name"), sub.get("value"), sub.get("label")]
    texts += [t for e in record.get("entries") or () for t in e]
    for text in texts:
        why = sendpolicy.transaction(transaction_reason(text))
        if why:
            return f"transaction ({why!r})"
    for text in (sub.get("label"), sub.get("value"), sub.get("name")):
        word = next((t for t in (x.lower() for x in name_tokens(text or ""))
                     if t in SETTER_WORDS), None)
        if word:
            return f"submit button sets something ({word!r})"
    return None


def refusal(record: dict, named, allow_get: bool,
            in_scope: Callable[[str], bool]) -> str | None:
    """Why this selector form must never be submitted, or None when it may be.
    ``named`` is the operator's select names, or `ALL_SELECTS` (D73)."""
    if not record.get("selector") or not record.get("options"):
        return "not a selector form"
    select = record["options"][0][0]
    if record["method"] == "POST" and named is ALL_SELECTS:
        why = unnamed_post_refusal(record)
        if why:
            return f"unnamed POST select {select!r}: {why}"
    elif record["method"] == "POST" and select not in named:
        return f"POST select {select!r} not named by the operator"
    if record["method"] == "GET" and not allow_get and named is not ALL_SELECTS \
            and select not in named:
        return "GET selector forms not enabled"
    for name, _kind in record.get("controls") or []:
        word = settings_word(name)
        if word:
            return f"control {name!r} is a settings control ({word!r})"
    action = record["action_url"]
    if not in_scope(action):
        return "action out of scope"
    reason = sendpolicy.destructive(destructive_reason(action))
    if reason:
        return f"action is destructive ({reason!r})"
    return None


def option_refusal(value: str, label: str) -> str | None:
    """Why one option must not be submitted (it is skipped, the form continues)."""
    for text in (value, label):
        word = settings_word(text)
        if word:
            return f"settings word {word!r}"
        reason = sendpolicy.destructive(text_destructive_reason(text))   # BUG-0131
        if reason:
            return f"destructive ({reason!r})"
    return None


#: What a submitted picker did (FR-CRAWL-10): recorded so the importer never fuzzes a
#: picker the crawler saw act as a settings form.
VERDICT_NAVIGATION = "navigation"
VERDICT_SETTINGS = "settings"


def enumerate_form(record: dict, submit, in_scope: Callable[[str], bool],
                   log: Callable[[str], None] = logging.info,
                   on_verdict: Callable[[str], None] | None = None,
                   on_page: Callable[[str, str], int] | None = None,
                   on_sent: Callable[[], None] | None = None) -> list[str]:
    """Submit each allowed option of a gated selector form; return the in-scope,
    non-destructive URLs it redirects to (to crawl as ordinary GET links).

    ``on_verdict`` (forms phase 2) is told ``"settings"`` when enumeration stops on a
    cookie, or on a run of redirects back to the form itself before anything was
    found; else ``"navigation"`` when a redirect was found or a page was read. An
    answer that only re-renders a page (200) is never a settings verdict (D73 review
    M1: bWAPP's ``sqli_13.php`` movie picker answers so, and is an injection point). It
    only reports; what is submitted is unchanged.

    ``on_page(action_url, html)`` (option 4(a)) reads a cookie-less 2xx HTML answer as
    the chosen page and returns how many links and forms it found that neither the
    picker's own page nor an earlier answer showed.

    The stall (D73 review M2): a redirect back to the form, a redirect to a page
    already found and an answer that adds nothing are one run; `MAX_SELF_REDIRECTS` in
    a row stop the form, whatever was found before (measured on bWAPP's 159 options:
    its longest such run is 3). ``on_sent`` is called once per submission."""
    base = FormEntries(tuple(e) for e in record["entries"])
    select = record["options"][0][0]
    own = {url_key(record["page_url"]), url_key(record["action_url"])}
    found: list[str] = []
    pages = 0
    stall = 0
    self_only = True        # every answer of the current stall redirected to the form
    settings = False
    for _name, value, label in (record["options"] or [])[:MAX_OPTIONS]:
        why = option_refusal(value, label)
        if why:
            log(f"selector {select!r}: skipped option {label!r} ({why})")
            continue
        answer = submit(record["method"], record["action_url"],
                        base.replace(select, value))
        if on_sent is not None:
            on_sent()
        status, headers = answer[0], answer[1]
        html = answer[2] if len(answer) > 2 else None
        low = {k.lower(): v for k, v in (headers or {}).items()}
        location = low.get("location")
        if "set-cookie" in low:
            log(f"selector {select!r}: response set a cookie; stopped (settings form)")
            settings = True
            break
        progress, to_self = False, False
        if on_page is not None and html and html_answer(status, headers) \
                and not location:
            # option 4(a): the chosen page itself, read from this answer -- never a
            # second request
            if on_page(record["action_url"], html[:MAX_PAGE_CHARS]):
                pages += 1
                progress = True
        else:
            if not (300 <= status < 400) or not location:
                log(f"selector {select!r}: non-redirect response {status}; stopped")
                break
            target = urljoin(record["action_url"], location).split("#")[0]
            if not in_scope(target) or sendpolicy.destructive(destructive_reason(target)):
                log(f"selector {select!r}: redirect to {urlsplit(target).path} refused; "
                    f"stopped")
                break
            to_self = url_key(target) in own
            if not to_self and target not in found:
                found.append(target)
                progress = True
        if progress:
            stall, self_only = 0, True
            continue
        stall += 1
        self_only = self_only and to_self
        if stall >= MAX_SELF_REDIRECTS:
            settings = self_only and not (found or pages)
            log(f"selector {select!r}: {stall} answers in a row add nothing new; stopped"
                + (" (settings form)" if settings else ""))
            break
    if on_verdict is not None and (settings or found or pages):
        on_verdict(VERDICT_SETTINGS if settings else VERDICT_NAVIGATION)
    return found
