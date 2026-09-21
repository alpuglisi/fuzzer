"""Live WAF adapter: back the mutation `Filter` seam with real HTTP round-trips.

`FilterLearner` and `MutationSearch` take a `Filter` — any object with
``caught(payload) -> bool`` and ``evaluate(payload) -> FilterResult`` (offline tests use
`FilterModel.from_lab()`). :class:`HttpFilter` implements that seam against the **live**
lab WAF: it sends the payload as a parameter value through a probe sender and treats the
WAF's block status (HTTP 403 by default) as "caught", parsing the matched rule ids from
the block page for evidence. Lab-only; the caller supplies an authorized sender.
"""

from __future__ import annotations

import re

from fuzzlab.mutation.filtermodel import FilterResult

# Lab WAF rule ids look like "sqli-union-select", "xss-script-tag", "path-traversal".
_RULE_ID = re.compile(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)+\b")


def parse_rule_ids(block_body: str) -> list[str]:
    """Best-effort matched-rule ids from the WAF's 403 page (evidence only)."""
    if not block_body:
        return []
    # De-duplicate, preserve order; drop obvious non-ids.
    seen: list[str] = []
    for m in _RULE_ID.findall(block_body):
        if m not in seen and m not in ("request-blocked",):
            seen.append(m)
    return seen


class HttpFilter:
    """A `Filter` backed by live HTTP: block status -> caught (the live WAF)."""

    def __init__(self, sender, url: str, param: str, *, method: str = "GET",
                 location: str = "query", block_status: int = 403):
        self._sender = sender
        self._url = url
        self._param = param
        self._method = method
        self._location = location
        self._block = block_status

    def _probe(self, payload: str):
        return self._sender.send(self._url, self._param, payload,
                                 method=self._method, location=self._location)

    def caught(self, payload: str) -> bool:
        return self._probe(payload).status == self._block

    def evaluate(self, payload: str) -> FilterResult:
        probe = self._probe(payload)
        if probe.status == self._block:
            return FilterResult(action="block",
                                hits=parse_rule_ids(getattr(probe, "text", "") or ""),
                                clean=payload)
        return FilterResult(action="allow", hits=[], clean=payload)
