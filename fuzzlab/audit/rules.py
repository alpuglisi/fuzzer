"""Rules as data: an editable, versioned rule set the auditor loads (T2.3).

A rule declares which injection *category* applies to an injection point, via a
declarative ``when`` predicate (no code). New rules are data edits, not code
changes. The predicate is a small, safe condition language:

- ``always``: true
- ``location_in``: [query, body, ...]
- ``method_in``: [GET, POST]
- ``sink_context_in``: [html, html-attribute, url-attribute, js]
- ``name_regex``: a regex matched (case-insensitively) against the parameter name
- ``value_shape_in``: [ip, hostname, filename, path, url] — the point's example value
  has one of these shapes (`fuzzlab.audit.value_shape`; forms phase 2, FR-AUD-20)
- ``origin_in``: [crawl, ground-truth] — where the point came from (FR-AUD-20)

Present conditions are ANDed; a rule with no conditions (and no ``always``) never
fires. Categories align with the `references/` catalogs and the oracle's classes.

Rules are checked when loaded (`validate_rule`, PA-0086(1)): an unknown ``when`` key, a
value outside a closed set, or a regex that does not compile raises `RuleError`, so a
misspelt condition can never silently disable a rule.
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


#: Every ``when`` key the predicate language understands.
WHEN_KEYS = frozenset({"always", "location_in", "method_in", "sink_context_in",
                       "name_regex", "value_shape_in", "origin_in"})
#: Where an injection point can come from (``origin_in``).
ORIGINS = ("crawl", "ground-truth")
_LIST_KEYS = ("location_in", "method_in", "sink_context_in", "value_shape_in", "origin_in")


class RuleError(ValueError):
    """A rule whose ``when`` predicate the engine cannot evaluate as written."""


def validate_rule(rule) -> None:
    """Raise `RuleError` unless ``rule`` is a `Rule` whose ``when`` uses only known
    keys, list values of strings, closed-set members for ``value_shape_in`` /
    ``origin_in``, and a ``name_regex`` that compiles."""
    from fuzzlab.audit.value_shape import SHAPES
    if not isinstance(rule, Rule):
        raise RuleError(f"not a Rule: {type(rule).__name__}")
    when = rule.when
    if not isinstance(when, dict):
        raise RuleError(f"{rule.id}: 'when' must be an object")
    unknown = sorted(set(when) - WHEN_KEYS)
    if unknown:
        raise RuleError(f"{rule.id}: unknown 'when' key(s) {unknown}")
    for key in _LIST_KEYS:
        if key in when and not (isinstance(when[key], list)
                                and all(isinstance(v, str) for v in when[key])):
            raise RuleError(f"{rule.id}: {key} must be a list of strings")
    for key, allowed in (("value_shape_in", SHAPES), ("origin_in", ORIGINS)):
        bad = sorted(set(when.get(key, [])) - set(allowed))
        if bad:
            raise RuleError(f"{rule.id}: {key} has unknown value(s) {bad}")
    if "name_regex" in when:
        try:
            re.compile(when["name_regex"])
        except (re.error, TypeError) as exc:
            raise RuleError(f"{rule.id}: name_regex does not compile: {exc}") from exc


def load_rules(path: str | Path | None = None) -> list[Rule]:
    """Load the rule set from a JSON file (default: the bundled rule set); every rule
    is checked (`validate_rule`)."""
    if path is None:
        text = resources.files(_RULES_PKG).joinpath("default_rules.json").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    data = json.loads(text)
    rules = [Rule(id=r["id"], category=r["category"],
                  transaction_type=r["transaction_type"], when=r.get("when", {}),
                  reference=r.get("reference", "")) for r in data["rules"]]
    for rule in rules:
        validate_rule(rule)
    return rules


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
    if "value_shape_in" in when:
        shapes = getattr(point, "value_shapes", None) or ()
        checks.append(bool(set(shapes) & set(when["value_shape_in"])))
    if "origin_in" in when:
        checks.append(getattr(point, "origin", None) in when["origin_in"])
    return bool(checks) and all(checks)
