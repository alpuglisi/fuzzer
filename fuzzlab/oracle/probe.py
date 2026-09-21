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
    location: str = "query"                    # query | body | ...
    vuln_class: str | None = None              # hint; None -> strategies self-select
    sink_context: str | None = None            # from the auditor's typing, if known


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
    ``location`` (``query``/``body``) place the payload; they default to GET/query so
    a sender that only handles that case can omit them (the oracle passes them only
    for non-default candidates, e.g. POST body).
    """

    def send(self, url: str, param: str, value: str, timing: bool = False,
             method: str = "GET", location: str = "query") -> Probe:  # pragma: no cover - interface
        raise NotImplementedError
