"""State keys for the explorer's state graph (pure; no browser).

A page has **two keys** (FR-CRAWL-31, BUG-0539):

* the **execution key** (`execution_key`, SP-62) is a state's identity: two pages are
  one state only when their execution keys are equal. It holds the exact route
  (`execution_route`: the path as served, every query value, a SPA route's own query;
  a sensitive name's value replaced), the *multiset* of its visible interactive
  elements' signatures (one button and two identical buttons are two states), the
  workflow markers a control holds (`workflow_markers`: a select's value, a checked
  box, ``aria-selected`` / ``aria-current`` / ``aria-checked``, a short hidden input's
  value) and the session generation it was read in. ``/wizard?step=1`` and
  ``/wizard?step=2`` with the same Next button are two states.
* the **structural key** (`state_fingerprint`) is a similarity index, read only to
  schedule and to fold (the frontier's order and per-route bound, a harvest alias): the
  folded route (digit runs folded, query names only) and the *set* of signatures. It
  never decides whether a state was visited (an AST guard holds that).

Text content is left out of both on purpose, so a page whose data changes (a new row,
a counter) stays one state, while a page that grows a dialog, a tab panel or a form is
a new one.

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


def state_fingerprint(url: str, elements: list[dict]) -> str:
    """The **structural** key: hash of the folded route and the *set* of element
    signatures. A similarity index for scheduling and folding only, never a state's
    identity (`execution_key` is; module doc)."""
    sigs = sorted({element_signature(e) for e in elements})
    doc = json.dumps([normalise_route(url), sigs], separators=(",", ":"))
    return hashlib.sha256(doc.encode("utf-8")).hexdigest()[:24]


# --- the execution key (FR-CRAWL-31, SP-62) ---------------------------------------------

#: A hidden input's value longer than this is no workflow marker (a serialised view
#: state, a blob); one that looks like a token is not either (`looks_like_identifier`).
MAX_MARKER_VALUE = 64


def _query_pairs(query: str) -> list[str]:
    """``query``'s ``name=value`` parts, a sensitive name's value replaced
    (`redact_query`), sorted -- each occurrence kept (a multiset, not a set)."""
    from fuzzlab.core.redaction import redact_query
    return sorted(p for p in redact_query(query or "").split("&") if p)


def execution_route(url: str) -> str:
    """The exact route of a page (the execution key's, FR-CRAWL-31): origin, the path as
    served (numeric segments kept: ``/users/17`` and ``/users/42`` are two routes), every
    query pair with its value, and a SPA route fragment with its own query pairs. A
    sensitive name's value is replaced (a token selects no workflow and changes per
    session)."""
    parts = urlsplit(url or "")
    route = f"{canonical_origin(url) or ''}{parts.path or '/'}"
    pairs = _query_pairs(parts.query)
    if pairs:
        route += "?" + "&".join(pairs)
    spa = spa_route(url)                     # (route path, route query)
    if spa:
        route += "#" + (spa[0] or "/")
        spa_pairs = _query_pairs(spa[1])
        if spa_pairs:
            route += "?" + "&".join(spa_pairs)
    return route


def element_multiset(elements: list[dict]) -> tuple[tuple[str, int], ...]:
    """Each element signature with how many times the page holds it, sorted: one button
    and two identical buttons differ."""
    counts: dict[str, int] = {}
    for el in elements:
        sig = el.get("signature") or element_signature(el)
        counts[sig] = counts.get(sig, 0) + 1
    return tuple(sorted(counts.items()))


def workflow_markers(elements: list[dict], page_marks=()) -> tuple[str, ...]:
    """The control values that select a workflow, sorted (FR-CRAWL-31):

    * an element's ``sel`` (read by the explorer: a select's value, a checkbox's or
      radio's checked state, ``aria-selected`` / ``aria-current`` / ``aria-checked``),
      keyed by its signature and occurrence; a sensitive name's value is left out;
    * ``page_marks``: ``["hidden", name, value]`` for a hidden input -- kept only when
      its name is not sensitive and its value is short and not token-like (a CSRF token
      changes per load) -- and ``["current", where, index, value]`` for a
      non-interactive ``aria-current`` marker (a stepper's position).

    Typed text is never a marker: it is data."""
    from fuzzlab.core.redaction import is_sensitive_name, looks_like_identifier
    out = []
    seen: dict[str, int] = {}
    for el in elements:
        sel = str(el.get("sel") or "")
        sig = el.get("signature") or element_signature(el)
        occ = el.get("occurrence")
        if occ is None:
            occ = seen.get(sig, 0)
        seen[sig] = max(seen.get(sig, 0), occ + 1)
        if not sel or is_sensitive_name(str(el.get("name") or "")):
            continue
        out.append(f"el:{sig}#{occ}:{sel}")
    for mark in page_marks or ():
        if not isinstance(mark, (list, tuple)) or not mark:
            continue
        kind = mark[0]
        if kind == "hidden" and len(mark) == 3:
            name, value = str(mark[1] or ""), str(mark[2] or "")
            if not name or is_sensitive_name(name) or len(value) > MAX_MARKER_VALUE \
                    or looks_like_identifier(value):
                continue
            out.append(f"hidden:{name}={value}")
        elif kind == "current" and len(mark) == 4:     # state classes dropped (BUG-0501)
            where = _fold(_stable_ancestry(str(mark[1])))
            out.append(f"current:{where}@{mark[2]}={mark[3]}")
    return tuple(sorted(out))


def execution_key(url: str, elements: list[dict], markers=(), generation: int = 0) -> str:
    """A state's identity (SP-62, FR-CRAWL-31): hash of the exact route
    (`execution_route`), the element multiset (`element_multiset`), the workflow
    markers (`workflow_markers` output) and the session generation the page was read
    in. Every visited-state check of the explorer compares these."""
    doc = json.dumps(["x1", execution_route(url), element_multiset(elements),
                      sorted(markers), int(generation)], separators=(",", ":"))
    return hashlib.sha256(doc.encode("utf-8")).hexdigest()[:24]
