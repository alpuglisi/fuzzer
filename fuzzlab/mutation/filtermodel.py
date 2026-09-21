"""Offline model of the lab WAF (Phase 8 T8.3, FR-MUT-3 seam).

Mirrors the PHP lab WAF (`puppy-fort-factory/includes/waf.php`) from the **shared**
`waf-rules.json`, so filter-transformation learning is testable offline without the live
container. One ruleset, two consumers: the PHP filter enforces it on the wire; this
models it here. Live, the same learner (T8.3 `learn.py`) observes real canary round-trips
through the proxy/HTTP seam instead of this model.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_LAB_RULES = (Path(__file__).resolve().parents[2] /
              "puppy-fort-factory" / "config" / "waf-rules.json")


def php_pattern_to_regex(pattern: str) -> re.Pattern:
    """Convert a PHP ``/regex/flags`` pattern to a compiled Python regex."""
    body = pattern[1:pattern.rindex("/")]
    flags = pattern[pattern.rindex("/") + 1:]
    return re.compile(body, re.IGNORECASE if "i" in flags else 0)


@dataclass
class FilterResult:
    action: str              # "allow" | "block" | "sanitized"
    hits: list[str]          # rule ids that matched
    clean: str               # what the app would see (sanitized), == payload if allowed

    @property
    def caught(self) -> bool:
        """True if any rule matched (the payload would be blocked or altered)."""
        return bool(self.hits)


class FilterModel:
    """A regex signature filter mirroring the lab WAF, in a chosen mode."""

    def __init__(self, rules: list[dict], mode: str = "block"):
        self.mode = mode
        self._rules = [(r.get("id", "?"), r.get("category", "?"),
                        php_pattern_to_regex(r["pattern"]))
                       for r in rules if r.get("pattern")]

    @classmethod
    def from_rules_file(cls, path, mode: str = "block") -> "FilterModel":
        data = json.loads(Path(path).read_text())
        return cls(data.get("rules", []), mode=mode)

    @classmethod
    def from_lab(cls, mode: str = "block") -> "FilterModel":
        """Build from the committed lab ruleset (the target the engine evades)."""
        return cls.from_rules_file(_LAB_RULES, mode=mode)

    def evaluate(self, payload: str) -> FilterResult:
        hits, clean = [], payload
        for rid, _cat, rx in self._rules:
            if rx.search(payload):
                hits.append(rid)
                clean = rx.sub("", clean)
        if not hits:
            action = "allow"
        elif self.mode == "sanitize":
            action = "sanitized"
        elif self.mode == "log":
            action = "allow"                 # log mode records but lets it through
        else:
            action = "block"
        return FilterResult(action=action, hits=hits, clean=clean)

    def caught(self, payload: str) -> bool:
        """True if the filter catches ``payload`` (any rule matches)."""
        return self.evaluate(payload).caught

    def rule_ids(self) -> list[str]:
        return [rid for rid, _c, _r in self._rules]
