"""Rules as data: an editable, versioned rule set the auditor loads (T2.3).

A rule declares which injection *category* applies to an injection point, via a
declarative ``when`` predicate (no code). New rules are data edits, not code
changes. The predicate is a small, safe condition language:

- ``always``: true
- ``location_in``: [query, body, ...]
- ``method_in``: [GET, POST]
- ``sink_context_in``: [html, html-attribute, url-attribute, js]
- ``name_regex``: a regex matched (case-insensitively) against the parameter name

Present conditions are ANDed; a rule with no conditions (and no ``always``) never
fires. Categories align with the `references/` catalogs and the oracle's classes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

_RULES_PKG = "fuzzlab.audit.rules_data"


@dataclass
class Rule:
    id: str
    category: str
    transaction_type: str
    when: dict[str, Any] = field(default_factory=dict)
    reference: str = ""


def load_rules(path: str | Path | None = None) -> list[Rule]:
    """Load the rule set from a JSON file (default: the bundled rule set)."""
    if path is None:
        text = resources.files(_RULES_PKG).joinpath("default_rules.json").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    data = json.loads(text)
    return [Rule(id=r["id"], category=r["category"],
                 transaction_type=r["transaction_type"], when=r.get("when", {}),
                 reference=r.get("reference", "")) for r in data["rules"]]


def known_categories(rules: list[Rule] | None = None) -> list[str]:
    """The set of injection categories the rule set can test (for selection)."""
    rules = load_rules() if rules is None else rules
    return sorted({r.category for r in rules})


def matches(rule: Rule, point) -> bool:
    """Evaluate a rule's ``when`` predicate against an injection point."""
    when = rule.when
    if when.get("always"):
        return True
    checks: list[bool] = []
    if "location_in" in when:
        checks.append(point.location in when["location_in"])
    if "method_in" in when:
        checks.append(point.method in when["method_in"])
    if "sink_context_in" in when:
        checks.append((point.sink_context or "") in when["sink_context_in"])
    if "name_regex" in when:
        checks.append(bool(re.search(when["name_regex"], point.param or "", re.I)))
    return bool(checks) and all(checks)
