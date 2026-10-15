"""One parser for a candidate's stored ``evidence`` JSON (BUG-0107, PA-0108, FR-ML-24).

`candidate.evidence` is written by the pipeline as an object with string ``url``,
``param`` and ``category`` (and usually ``method``). A row that does not parse, parses to
something other than an object, or carries the wrong field types is **unreadable**:
`parse_evidence` returns ``None`` and the ML path quarantines it (skips and counts it),
never replacing it with defaults — ``{}`` once became a fabricated negative training row
on endpoint ``/``. Display readers use `display_evidence`, which never raises.
"""

from __future__ import annotations

import json

_STR_FIELDS = ("url", "param", "category")


def parse_evidence(raw) -> dict | None:
    """The evidence object, or ``None`` when it is unreadable (see the module
    docstring). A missing ``method`` is allowed (the documented GET default applies
    where it is read); a present one must be a string."""
    if not isinstance(raw, (str, bytes)) or not raw:
        return None
    try:
        ev = json.loads(raw)
    except (ValueError, TypeError, RecursionError):
        return None
    if not isinstance(ev, dict):
        return None
    if any(not isinstance(ev.get(k), str) for k in _STR_FIELDS):
        return None
    if ev.get("method") is not None and not isinstance(ev["method"], str):
        return None
    return ev


def method_key(method) -> str:
    """The HTTP method as every label / seen-key join compares it: upper-case, and
    ``GET`` when missing (the evidence default). The one definition (PA-0003) for both
    sides of a join (BUG-0075, PA-0076); moved here from ``ml.dataset`` so the web UI
    can share it without the ML package (CC-CORE-0500)."""
    return method.upper() if isinstance(method, str) and method else "GET"


def display_evidence(raw) -> dict:
    """For display only (feeds no labels): the parsed object, or ``{}``."""
    try:
        ev = json.loads(raw) if raw else {}
    except (ValueError, TypeError, RecursionError):
        return {}
    return ev if isinstance(ev, dict) else {}
