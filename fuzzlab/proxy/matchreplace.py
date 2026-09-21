"""Match-and-replace rules (FR-PROXY-5).

Ordered, byte-level rewrites applied to a message as it passes through the proxy.
Because rules operate on ``RawMessage`` sections at the byte level, they compose with
the raw path: a rule can introduce exactly the bytes it specifies (including malformed
ones) without the parsed path normalizing them away.

A rule targets one section — the request/status line, a named header's value, or the
body — and matches either a literal byte string or a regex. Header and request-line
edits go through ``RawMessage``'s byte-surgery helpers so untouched lines stay verbatim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from fuzzlab.proxy.message import RawMessage, _as_bytes

_TARGETS = ("request_line", "status_line", "header", "body")


@dataclass
class MatchReplaceRule:
    target: str                     # one of _TARGETS
    match: str | bytes              # literal, or a regex if is_regex
    replace: str | bytes = b""
    header_name: str | None = None  # required when target == "header"
    is_regex: bool = False
    enabled: bool = True

    def __post_init__(self):
        if self.target not in _TARGETS:
            raise ValueError(f"unknown match-replace target: {self.target}")
        if self.target == "header" and not self.header_name:
            raise ValueError("header target requires header_name")

    def _sub(self, data: bytes) -> bytes:
        rep = _as_bytes(self.replace)
        if self.is_regex:
            return re.sub(_as_bytes(self.match), rep, data)
        return data.replace(_as_bytes(self.match), rep)

    def apply(self, msg: RawMessage) -> RawMessage:
        if not self.enabled:
            return msg
        if self.target in ("request_line", "status_line"):
            new_line = self._sub(msg.start_line)
            return msg if new_line == msg.start_line else msg.with_request_line(new_line)
        if self.target == "body":
            new_body = self._sub(msg.body)
            return msg if new_body == msg.body else msg.with_body(new_body)
        # target == "header": rewrite each matching header's value in place.
        key = _as_bytes(self.header_name).lower()
        current = msg.get_all(self.header_name)
        if not current:
            return msg
        changed = False
        kept: list[bytes] = []
        for line in msg.header_lines():
            i = line.find(b":")
            if i != -1 and line[:i].lower() == key:
                name = line[:i]
                value = line[i + 1:].lstrip(b" \t")
                new_value = self._sub(value)
                if new_value != value:
                    changed = True
                kept.append(name + b": " + new_value)
            else:
                kept.append(line)
        if not changed:
            return msg
        return msg._rebuild(msg.start_line, kept, msg.body)


class MatchReplaceEngine:
    """Applies a list of rules in order; disabled rules are skipped."""

    def __init__(self, rules: list[MatchReplaceRule] | None = None):
        self.rules: list[MatchReplaceRule] = list(rules or [])

    def add(self, rule: MatchReplaceRule) -> "MatchReplaceEngine":
        self.rules.append(rule)
        return self

    def apply(self, msg: RawMessage) -> RawMessage:
        for rule in self.rules:
            msg = rule.apply(msg)
        return msg
