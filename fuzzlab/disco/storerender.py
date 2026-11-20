"""Store -> render pairs from a capture's own evidence (FR-CRAWL-672, CC-CRAWL-0671).

A stored-XSS point is two requests: the write that stores a value, and the page that
later shows it. Ground truth names both; a discovery run has to see them. This module
reads them from a disco capture (`disco.capture.read_capture` records, in time order):

* **the write** -- an answered (status < 400) POST/PUT/PATCH exchange with a JSON or
  form-encoded body; each of its string leaves of at least `MIN_VALUE_CHARS`
  characters holding a letter is a value it may have stored;
* **the render** -- a LATER answered exchange, not itself a write that sends the same
  value (that would be an echo of another write, not a page showing a stored one),
  whose response body holds the value. Its page is the exchange's own URL for an HTML
  document, else the page whose script fetched it (its ``Referer``, same origin as
  the exchange): the page a browser has to load to run what was stored;
* **no prior** -- the value appears in no response before the first write that sends
  it: a value the app already showed is no evidence that the write stored it.

The evidence is the application's own traffic; no name, path or value of any target is
known here. A value two leaves (or two writes) share pairs every one of them: the pair
costs a confirmation, never a finding, because `oracle.StoredXssStrategy` confirms by
executing its own payload in the render page (PA-0546(2): err towards keeping).

Pure and bounded: at most `MAX_VALUES` candidate values, `MAX_PAIRS` pairs,
`MAX_RENDERS_PER_LEAF` render pages per leaf, and a response read to `MAX_BODY_CHARS`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit, urlunsplit

#: A stored value is at least this long and holds a letter (shorter text is common).
MIN_VALUE_CHARS = 6
#: At most this many candidate values are tracked (the first writes', in time order).
MAX_VALUES = 200
#: At most this many pairs are returned.
MAX_PAIRS = 200
#: At most this many render pages per written leaf.
MAX_RENDERS_PER_LEAF = 3
#: A response body is searched up to this many characters.
MAX_BODY_CHARS = 262_144
#: Methods whose request may store a value: POST and the write opt-in methods (SP-41's
#: owner, `tools.store_adapter.WRITE_METHODS`, read here, never restated).
def _storing_methods() -> frozenset[str]:
    from fuzzlab.tools.store_adapter import WRITE_METHODS
    return WRITE_METHODS | {"POST"}
_HTML = ("text/html", "application/xhtml+xml")


@dataclass(frozen=True)
class StoreRender:
    #: Index of the write in the records given.
    write_index: int
    method: str
    url: str
    #: The written leaf's parameter name (`core.jsonbody.display_name`, or the form
    #: field's name).
    param: str
    #: The page that shows the stored value (no fragment).
    render_url: str


def _media(ctype) -> str:
    return (ctype or "").split(";", 1)[0].strip().lower()


def _usable(value) -> bool:
    return (isinstance(value, str) and len(value) >= MIN_VALUE_CHARS
            and any(c.isalpha() for c in value))


def write_leaves(rec) -> list[tuple[str, str]]:
    """``(param, value)`` of every usable string leaf of a write's body, or ``[]``."""
    from fuzzlab.core import jsonbody
    if (getattr(rec, "kind", None) != "http" or (rec.method or "").upper() not in _storing_methods()
            or rec.status is None or rec.status >= 400 or not rec.req_body
            or rec.req_truncated):
        return []
    media = _media(rec.req_ctype)
    out: list[tuple[str, str]] = []
    try:
        if media == "application/json" or media.endswith("+json"):
            found = jsonbody.leaves(jsonbody.loads(rec.req_body)) or []
            out = [(jsonbody.display_name(p), v) for p, v in found]
        elif media == "application/x-www-form-urlencoded":
            out = parse_qsl(rec.req_body, keep_blank_values=True)
    except (ValueError, TypeError, RecursionError):
        return []
    return [(n, v) for n, v in out if _usable(v)]


def render_page(rec) -> str | None:
    """The page a browser loads to show ``rec``'s response: the exchange itself for an
    HTML GET document, else its same-origin ``Referer``; None when there is none."""
    if (rec.method or "").upper() == "GET" and _media(rec.res_ctype) in _HTML:
        page = rec.url
    else:
        headers = rec.req_headers or {}
        page = headers.get("referer") or headers.get("Referer")
        if not page:
            return None
        try:
            if urlsplit(page)[:2] != urlsplit(rec.url)[:2]:
                return None
        except ValueError:
            return None
    try:
        parts = urlsplit(page)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def store_render_pairs(records) -> list[StoreRender]:
    """The store -> render pairs ``records`` show (module docstring), in write order."""
    records = list(records)
    first_write: dict[str, int] = {}             # value -> index of its first write
    leaves_of: dict[int, list[tuple[str, str]]] = {}
    for i, rec in enumerate(records):
        leaves = write_leaves(rec)
        if leaves:
            leaves_of[i] = leaves
            for _n, v in leaves:
                if v not in first_write and len(first_write) < MAX_VALUES:
                    first_write[v] = i
    if not first_write:
        return []
    shown_before: set[str] = set()               # values a response held before
    renders: dict[str, list[tuple[int, str]]] = {v: [] for v in first_write}
    for i, rec in enumerate(records):
        body = rec.res_body if getattr(rec, "kind", None) == "http" else None
        if not isinstance(body, str) or not body or rec.status is None or rec.status >= 400:
            continue
        body = body[:MAX_BODY_CHARS]
        sent = {v for _n, v in leaves_of.get(i, ())}
        page = None
        for value, first in first_write.items():
            if value not in body:
                continue
            if i <= first:
                if i < first:
                    shown_before.add(value)      # the app showed it before any write
                continue                         # the write's own response is no render
            if value in sent:
                continue                         # another write echoing its own value
            page = page if page is not None else (render_page(rec) or "")
            if page and all(p != page for _j, p in renders[value]):
                renders[value].append((i, page))
    out: list[StoreRender] = []
    seen: set[tuple] = set()
    for i in sorted(leaves_of):
        rec = records[i]
        for name, value in leaves_of[i]:
            if value in shown_before or value not in renders:
                continue
            for j, page in renders[value][:MAX_RENDERS_PER_LEAF]:
                if j <= i:
                    continue                     # shown before THIS write
                key = (rec.method.upper(), rec.url, name, page)
                if key in seen:
                    continue
                seen.add(key)
                out.append(StoreRender(i, rec.method.upper(), rec.url, name, page))
                if len(out) >= MAX_PAIRS:
                    return out
    return out


def pairs_as_json(pairs) -> str:
    """The pairs as a JSON list (diagnostics)."""
    return json.dumps([p.__dict__ for p in pairs], sort_keys=True)
