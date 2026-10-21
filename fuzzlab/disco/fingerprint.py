"""State fingerprints for the explorer's state graph (pure; no browser).

A **state** is what the page offers, not where it is: the hash of its normalised route
plus the sorted signatures of its visible interactive elements. Text content is left
out on purpose, so a page whose data changes (a new row, a counter) stays one state,
while a page that grows a dialog, a tab panel or a form is a new one.

**A delegated candidate is never part of a state's identity** (`counts_for_state`,
FR-CRAWL-40; BUG-0551 review B2). It is any labelled text leaf -- a ``p``, ``span``,
``li``, ``td`` -- under a click listener on an ancestor, the document or the window,
which a dropdown's dismiss handler, a data-api or a framework's root registers on most
pages. Which leaves are candidates depends on their text (an empty one is none) and
their order (the first of each shape, a bound per read), so counting them made a click
that only swapped static text a new state. The explorer still reads and tries them;
the state key, a state's core and every restore check read the other elements only.

An **element signature** is its layout identity: tag, role, type, name, class tokens,
its short ancestor chain (``tag#id.class`` of up to three ancestors) and a normalised
id / href / form action -- each with digit runs folded to ``#`` (``mat-input-3`` and
``mat-input-7`` are one control; ``/users/17`` and ``/users/42`` are one link shape).
The ancestry is what tells a list that appeared inside a panel from the toolbar
entries beside it when neither carries an id or text the signature may use.

**Class tokens that carry UI state are dropped** (`stable_classes`): a BEM modifier
(``x--visible``) and any class one of whose ``-``/``_`` parts is a state word
(`STATE_WORDS`: ``visible``, ``showing``, ``active``, ``open``, ``pristine``,
``touched``...). Frameworks toggle them as the UI changes, so the same element would
get another signature in another state (measured on Juice Shop: ``ng-untouched`` on an
input, ``search-container--visible`` on its ancestor).
"""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from fuzzlab.core.urls import canonical_origin, spa_route

_DIGITS = re.compile(r"[0-9]+")
_HEXISH = re.compile(r"\b[0-9a-fA-F]{16,}\b")
#: The element attributes a signature keeps (text never).
SIGNATURE_KEYS = ("tag", "role", "type", "name", "id", "cls", "ancestry", "href", "action",
                  "listeners")


#: Words that mark a class as UI state rather than identity (any framework).
STATE_WORDS = frozenset({
    "active", "inactive", "open", "opened", "opening", "closed", "closing", "show", "shown",
    "showing", "hide", "hidden", "visible", "invisible", "selected", "unselected",
    "expanded", "collapsed", "collapsing", "focus", "focused", "hover", "hovered",
    "disabled", "enabled", "checked", "unchecked", "pressed", "current", "highlighted",
    "pristine", "dirty", "touched", "untouched", "valid", "invalid", "pending",
    "submitted", "loading", "loaded", "animating", "animated", "entering", "leaving"})
#: Deliberately not state words: ``in``, ``out``, ``error``, ``success``, ``empty``...
#: (``sign-in-button`` and ``error-message`` are identities).


def stable_classes(cls: str) -> str:
    """``a.b.c`` class tokens without the ones that carry UI state (module doc)."""
    keep = []
    for token in (cls or "").split("."):
        if not token or "--" in token or \
                any(part in STATE_WORDS for part in re.split(r"[-_]", token.lower())):
            continue
        keep.append(token)
    return ".".join(keep)


def _stable_ancestry(ancestry: str) -> str:
    """Each ``tag#id.class`` link of an ancestry with its state classes dropped."""
    out = []
    for link in (ancestry or "").split("<"):
        head, _sep, classes = link.partition(".")
        kept = stable_classes(classes)
        out.append(f"{head}.{kept}" if kept else head)
    return "<".join(out)


def _fold(value: str) -> str:
    return _DIGITS.sub("#", _HEXISH.sub("{h}", value))


def normalise_route(url: str) -> str:
    """Origin + path (digit runs folded) + a SPA route fragment (``#/x``), never the
    query's values: ``/p?id=7`` and ``/p?id=9`` are one route; the query's names stay."""
    parts = urlsplit(url or "")
    names = sorted({kv.split("=", 1)[0] for kv in parts.query.split("&") if kv})
    route = f"{canonical_origin(url) or ''}{_fold(parts.path or '/')}"
    if names:
        route += "?" + "&".join(names)
    spa = spa_route(url)                     # (route path, route query)
    if spa:
        route += "#" + _fold(spa[0] or "/")
        spa_names = sorted({kv.split("=", 1)[0] for kv in spa[1].split("&") if kv})
        if spa_names:
            route += "?" + "&".join(spa_names)
    return route


def element_signature(el: dict) -> str:
    """A stable signature of one interactive element description (see module doc)."""
    parts = []
    for key in SIGNATURE_KEYS:
        val = el.get(key)
        if val in (None, "", []):
            continue
        if key == "cls":
            val = stable_classes(str(val))
            if not val:
                continue
        elif key == "ancestry":
            val = _stable_ancestry(str(val))
        if key == "href" or key == "action":
            val = normalise_route(str(val))
        elif key == "listeners":
            val = ",".join(sorted(str(v) for v in val))
        else:
            val = _fold(str(val).strip().lower())
        parts.append(f"{key}={val}")
    return "|".join(parts)


def counts_for_state(el: dict) -> bool:
    """Whether an element description is part of a state's identity: every one but a
    delegated candidate (``how == "delegated"``; module doc)."""
    return el.get("how") != "delegated"


def state_signatures(elements: list[dict]) -> frozenset[str]:
    """The signatures a state's identity reads (`counts_for_state`): its key's set and
    a state's core (`explore.State`)."""
    return frozenset(element_signature(e) for e in elements if counts_for_state(e))


def state_fingerprint(url: str, elements: list[dict]) -> str:
    """The state key: hash of the route and the *set* of element signatures
    (`state_signatures`)."""
    sigs = sorted(state_signatures(elements))
    doc = json.dumps([normalise_route(url), sigs], separators=(",", ":"))
    return hashlib.sha256(doc.encode("utf-8")).hexdigest()[:24]
