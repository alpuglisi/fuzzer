"""State fingerprints for the explorer's state graph (pure; no browser).

A **state** is what the page offers, not where it is: the hash of its normalised route
plus the sorted signatures of its visible interactive elements. Text content is left
out on purpose, so a page whose data changes (a new row, a counter) stays one state,
while a page that grows a dialog, a tab panel or a form is a new one.

An **element signature** is its layout identity: tag, role, type, name, class tokens,
its short ancestor chain (``tag#id.class`` of up to three ancestors) and a normalised
id / href / form action -- each with digit runs folded to ``#`` (``mat-input-3`` and
``mat-input-7`` are one control; ``/users/17`` and ``/users/42`` are one link shape).
The ancestry is what tells a list that appeared inside a panel from the toolbar
entries beside it when neither carries an id or text the signature may use.
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
        if key == "href" or key == "action":
            val = normalise_route(str(val))
        elif key == "listeners":
            val = ",".join(sorted(str(v) for v in val))
        else:
            val = _fold(str(val).strip().lower())
        parts.append(f"{key}={val}")
    return "|".join(parts)


def state_fingerprint(url: str, elements: list[dict]) -> str:
    """The state key: hash of the route and the *set* of element signatures."""
    sigs = sorted({element_signature(e) for e in elements})
    doc = json.dumps([normalise_route(url), sigs], separators=(",", ":"))
    return hashlib.sha256(doc.encode("utf-8")).hexdigest()[:24]
