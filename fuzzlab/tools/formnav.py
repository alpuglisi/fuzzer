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
* submissions go through an isolated client (the caller's ``submit``), so a response
  cookie never reaches the crawler.

The HTTP itself is the caller's ``submit(method, action_url, entries) -> (status,
headers)``; this module is pure and testable.
"""

from __future__ import annotations

import logging
from typing import Callable
from urllib.parse import urljoin, urlsplit

from fuzzlab.core.forms import FormEntries
from fuzzlab.core.redaction import name_tokens
from fuzzlab.core.urls import destructive_reason, url_key

#: A select or control named with one of these words configures something.
SETTINGS_WORDS = frozenset({
    "level", "security", "role", "status", "permission", "permissions", "admin",
    "enable", "disable", "active", "lang", "language", "theme", "mode",
})
#: This many self-redirects in a row, before any real navigation: a settings form.
MAX_SELF_REDIRECTS = 5
#: At most this many options of one form are submitted.
MAX_OPTIONS = 500


def _settings_word(text: str) -> str | None:
    for tok in name_tokens(text or ""):
        if tok.lower() in SETTINGS_WORDS:
            return tok.lower()
    return None


def signature(record: dict) -> tuple:
    """One enumeration per (method, select name, option values), whatever the action:
    the same header picker appears on every page."""
    opts = record.get("options") or []
    name = opts[0][0] if opts else ""
    return (record["method"], name, tuple(sorted(v for _n, v, _l in opts)))


def refusal(record: dict, named: frozenset[str], allow_get: bool,
            in_scope: Callable[[str], bool]) -> str | None:
    """Why this selector form must never be submitted, or None when it may be."""
    if not record.get("selector") or not record.get("options"):
        return "not a selector form"
    select = record["options"][0][0]
    if record["method"] == "POST" and select not in named:
        return f"POST select {select!r} not named by the operator"
    if record["method"] == "GET" and not allow_get and select not in named:
        return "GET selector forms not enabled"
    for name, _kind in record.get("controls") or []:
        word = _settings_word(name)
        if word:
            return f"control {name!r} is a settings control ({word!r})"
    action = record["action_url"]
    if not in_scope(action):
        return "action out of scope"
    reason = destructive_reason(action)
    if reason:
        return f"action is destructive ({reason!r})"
    return None


def option_refusal(value: str, label: str) -> str | None:
    """Why one option must not be submitted (it is skipped, the form continues)."""
    for text in (value, label):
        word = _settings_word(text)
        if word:
            return f"settings word {word!r}"
        reason = destructive_reason("/?" + "x=" + (text or "").replace(" ", "+"))
        if reason:
            return f"destructive ({reason!r})"
    return None


def enumerate_form(record: dict, submit, in_scope: Callable[[str], bool],
                   log: Callable[[str], None] = logging.info) -> list[str]:
    """Submit each allowed option of a gated selector form; return the in-scope,
    non-destructive URLs it redirects to (to crawl as ordinary GET links)."""
    base = FormEntries(tuple(e) for e in record["entries"])
    select = record["options"][0][0]
    own = {url_key(record["page_url"]), url_key(record["action_url"])}
    found: list[str] = []
    self_run = 0
    for _name, value, label in (record["options"] or [])[:MAX_OPTIONS]:
        why = option_refusal(value, label)
        if why:
            log(f"selector {select!r}: skipped option {label!r} ({why})")
            continue
        status, headers = submit(record["method"], record["action_url"],
                                 base.replace(select, value))
        low = {k.lower(): v for k, v in (headers or {}).items()}
        location = low.get("location")
        if "set-cookie" in low:
            log(f"selector {select!r}: response set a cookie; stopped (settings form)")
            break
        if not (300 <= status < 400) or not location:
            log(f"selector {select!r}: non-redirect response {status}; stopped")
            break
        target = urljoin(record["action_url"], location).split("#")[0]
        if not in_scope(target) or destructive_reason(target):
            log(f"selector {select!r}: redirect to {urlsplit(target).path} refused; stopped")
            break
        if url_key(target) in own:
            self_run += 1
            if self_run >= MAX_SELF_REDIRECTS and not found:
                log(f"selector {select!r}: redirects back to itself; stopped (settings form)")
                break
            continue
        self_run = 0
        if target not in found:
            found.append(target)
    return found
