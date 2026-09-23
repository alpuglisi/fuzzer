"""Shared types for the oracle: what it probes with and what it returns."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Probe:
    """One response the oracle observed while confirming."""
    status: int
    text: str
    elapsed: float = 0.0                       # seconds
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Candidate:
    """A candidate injection point the oracle is asked to confirm."""
    url: str
    param: str
    method: str = "GET"
    location: str = "query"                    # query | body | fragment | ...
    vuln_class: str | None = None              # hint; None -> strategies self-select
    sink_context: str | None = None            # from the auditor's typing, if known
    category: str | None = None                # reference category; scopes strategies
    # Stored-XSS: where the payload is planted before it renders on `url` (M6).
    store_url: str | None = None
    store_param: str | None = None
    store_method: str = "POST"
    store_location: str = "body"
    # A whole-body point's real content type (e.g. "application/json"), from
    # `fuzzlab.audit.engine.InjectionPoint.body_content_type` -- `None` unless
    # the ground truth positively declared the format (CC-FUZZ-0028/FR-FUZZ-15).
    content_type: str | None = None


@dataclass
class Verdict:
    confirmed: bool
    vuln_class: str
    mechanism: str
    evidence: dict[str, Any] = field(default_factory=dict)


class Sender:
    """Duck-typed HTTP sender the oracle uses. Injected so tests need no network.

    Implementations return a :class:`Probe`. ``timing=True`` marks a
    timing-sensitive send (the real seam serializes those per host). ``method`` and
    ``location`` (``query``/``body``/``header``) place the payload; they default to
    GET/query so a sender that only handles that case can omit them (the oracle
    passes them only for non-default candidates, e.g. POST body). ``content_type``
    is only meaningful for a whole-body point (``param="body"``, no single named
    field, e.g. a JSON API): when set, the sender sends ``value`` as the raw body
    with that content type instead of form-encoding ``{param: value}``; ``None``
    keeps the existing form-encoded behavior (CC-FUZZ-0028/FR-FUZZ-15).
    """

    def send(self, url: str, param: str, value: str, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None) -> Probe:  # pragma: no cover - interface
        raise NotImplementedError
