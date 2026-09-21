"""Intercepting proxy (component #11, Phase 6).

A from-scratch Burp-style proxy (D4) that is an **optional observer** on the shared
store (D5) — never in the timing path. Its defining feature is the **dual path**: a
parsed path (``h11``) for normal traffic and a **byte-exact raw path**
(``RawMessage``) for malformed-traffic study and hand-editing.

Offline-testable seams (message model, parsers, scope, match-and-replace, history,
interception, repeater, session capture) live here; the live CONNECT/TLS socket
serving is the on-host last mile (see ``docs/PHASE_6_PLAN.md``).
"""

from __future__ import annotations

from fuzzlab.proxy.history import FlowRecord, HistoryWriter
from fuzzlab.proxy.intercept import Interceptor, PendingFlow
from fuzzlab.proxy.matchreplace import MatchReplaceEngine, MatchReplaceRule
from fuzzlab.proxy.message import RawMessage
from fuzzlab.proxy.repeater import Repeater, RepeaterTab
from fuzzlab.proxy.scope import Scope, ScopeRule
from fuzzlab.proxy.session_capture import SessionCapture

__all__ = [
    "RawMessage",
    "Scope",
    "ScopeRule",
    "MatchReplaceEngine",
    "MatchReplaceRule",
    "HistoryWriter",
    "FlowRecord",
    "Interceptor",
    "PendingFlow",
    "Repeater",
    "RepeaterTab",
    "SessionCapture",
]
