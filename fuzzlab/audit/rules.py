"""Rules as data: an editable, versioned rule set the auditor loads (T2.3).

A rule declares which injection *category* applies to an injection point, via a
declarative ``when`` predicate (no code). New rules are data edits, not code
changes. The predicate is a small, safe condition language:

- ``always``: true
- ``location_in``: [query, body, ...]
- ``location_not_in``: [fragment, ...] — the point's location is none of these (forms
  phase 3: a server-side rule never fires on a ``fragment`` point, whose payload never
  reaches the server; FR-AUD-22)
- ``method_in``: [GET, POST]
- ``sink_context_in``: [html, html-attribute, url-attribute, js]
- ``name_regex``: a regex that must match (case-insensitively) the **whole** parameter
  name (a ``json`` point's last object key, `rule_name`; forms phase 3, FR-AUD-22;
  anchored by construction since FR-AUD-702, BUG-0710)
- ``name_token_regex``: a regex that must match (case-insensitively) one **whole token**
  of that name (`core.redaction.name_tokens`: split at ``_ - . [ ]``, camelCase and
  letter/digit boundaries; FR-AUD-702, BUG-0710). A word never matches inside another
  word (``ip`` in ``description``, ``load`` in ``payload``); a compound a rule means is
  written out in the regex (``\\w*url`` for ``returnurl``, ``dest\\w*`` for
  ``destination``)
- ``content_type_in``: [none, json, xml, multipart, form] -- the family of the point's
  own body content type (`core.redaction.media_family` of ``body_content_type``;
  ``none`` when the point has none: a field of a form, a query, a JSON leaf;
  FR-AUD-701). A whole-body point carries the captured request's own type
- ``path_token_regex``: a regex that must match one whole token of the point's URL path
  (FR-AUD-704)
- ``body_leaf_token_regex``: a regex that must match one whole token of the last key of
  one of a whole-body point's own captured leaves (``base_entries``; FR-AUD-705)
- ``server_language_in``: [javascript, ...] -- the language the run's fingerprint read
  from the target's own answer (`core.fingerprint.server_language`; FR-AUD-706). Never
  true when the run has no such evidence
- ``value_shape_in``: [ip, hostname, filename, path, url] — the point's example value
  has one of these shapes (`fuzzlab.audit.value_shape`; forms phase 2, FR-AUD-20)
- ``origin_in``: [crawl, ground-truth] — where the point came from (FR-AUD-20)
A GraphQL variable's ``name_regex`` is matched against its leaf name and against the
name of every field argument it feeds (``$h`` in ``importPaste(host: $h)`` is judged as
``host`` too; FR-AUD-600).

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
WHEN_KEYS = frozenset({"always", "location_in", "location_not_in", "method_in",
                       "sink_context_in", "name_regex", "name_token_regex",
                       "value_shape_in", "origin_in", "content_type_in",
                       "path_token_regex", "body_leaf_token_regex",
                       "server_language_in"})
#: Where an injection point can come from (``origin_in``).
ORIGINS = ("crawl", "ground-truth")
#: Every location a point can have (``location_in`` / ``location_not_in``): the ground
#: truth's (`labels.schema.json`, `manifest.schema.json`) and the crawler's ``json``
#: (forms phase 3 merge, reviewer A: a typo must never silently widen a rule).
LOCATIONS = ("query", "body", "header", "cookie", "json", "fragment", "path")
#: A point's body content-type family (``content_type_in``; `core.redaction.
#: media_family`, ``none`` when the point has no body type of its own; FR-AUD-701).
CONTENT_TYPES = ("none", "json", "xml", "multipart", "form")
#: The ``when`` keys whose value is a regex (checked to compile at load).
_REGEX_KEYS = ("name_regex", "name_token_regex", "path_token_regex",
               "body_leaf_token_regex")
_LIST_KEYS = ("location_in", "location_not_in", "method_in", "sink_context_in",
              "value_shape_in", "origin_in", "content_type_in", "server_language_in")


class RuleError(ValueError):
    """A rule whose ``when`` predicate the engine cannot evaluate as written."""


def validate_rule(rule) -> None:
    """Raise `RuleError` unless ``rule`` is a `Rule` whose ``when`` uses only known
    keys, list values of strings, closed-set members for ``value_shape_in`` /
    ``origin_in`` / ``location_in`` / ``location_not_in``, and a ``name_regex`` that
    compiles."""
    from fuzzlab.audit.value_shape import SHAPES
    from fuzzlab.core.fingerprint import LANGUAGES
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
    for key, allowed in (("value_shape_in", SHAPES), ("origin_in", ORIGINS),
                         ("location_in", LOCATIONS), ("location_not_in", LOCATIONS),
                         ("content_type_in", CONTENT_TYPES),
                         ("server_language_in", LANGUAGES)):
        bad = sorted(set(when.get(key, [])) - set(allowed))
        if bad:
            raise RuleError(f"{rule.id}: {key} has unknown value(s) {bad}")
    for key in _REGEX_KEYS:
        if key in when:
            try:
                re.compile(when[key])
            except (re.error, TypeError) as exc:
                raise RuleError(f"{rule.id}: {key} does not compile: {exc}") from exc


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


def rule_name(point) -> str:
    """The name ``name_regex`` matches: a ``json`` point's last object key
    (`core.jsonbody.name_segment`; ``user.email`` -> ``email``), so a leaf is judged by
    its own name however deep it sits (forms phase 3, FR-AUD-22); else the parameter
    name."""
    from fuzzlab.core import jsonbody
    name = point.param or ""
    if getattr(point, "location", None) == jsonbody.LOCATION:
        path = jsonbody.parse_name(name)
        return jsonbody.name_segment(path) if path is not None else name
    return name


def content_type_family(point) -> str:
    """The point's body content-type family for ``content_type_in`` (FR-AUD-701):
    `core.redaction.media_family` of its ``body_content_type``, ``none`` when it has
    none, ``other`` (in no rule's set) for a type outside the families."""
    from fuzzlab.core.redaction import media_family
    declared = getattr(point, "body_content_type", None)
    if not declared:
        return "none"
    return media_family(declared) or "other"


def _token_match(pattern: str, names) -> bool:
    """True when ``pattern`` matches one whole token of one of ``names``, case
    insensitively (`core.redaction.name_tokens`; FR-AUD-702, BUG-0710)."""
    from fuzzlab.core.redaction import name_tokens
    return any(re.fullmatch(pattern, token, re.I)
               for name in names for token in name_tokens(name))


def _path_of(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return urlsplit(url or "").path
    except ValueError:
        return ""


def _leaf_names(point) -> list[str]:
    """The last key of each of a whole-body point's own captured leaves (FR-AUD-705):
    its ``base_entries`` read as `core.jsonbody` entries; none for any other point."""
    from fuzzlab.core import jsonbody
    if not getattr(point, "body_content_type", None) or not point.base_entries:
        return []
    names = []
    for path, _value in point.base_entries:
        parsed = path if isinstance(path, (list, tuple)) else jsonbody.parse_name(path)
        if parsed:
            names.append(jsonbody.name_segment(parsed))
    return [n for n in names if isinstance(n, str)]


def matches(rule: Rule, point, target: dict | None = None) -> bool:
    """Evaluate a rule's ``when`` predicate against an injection point. ``target`` holds
    what the run read from the target itself (``{"server_language": ...}``, FR-AUD-706);
    a ``server_language_in`` rule never fires without it."""
    from fuzzlab.audit import graphql_context
    when = rule.when
    if graphql_context.not_a_data_point(point) is not None:
        return False                        # FR-AUD-601
    if when.get("always"):
        return True
    checks: list[bool] = []
    if "location_in" in when:
        checks.append(point.location in when["location_in"])
    if "location_not_in" in when:
        checks.append(point.location not in when["location_not_in"])
    if "method_in" in when:
        checks.append(point.method in when["method_in"])
    if "sink_context_in" in when:
        checks.append((point.sink_context or "") in when["sink_context_in"])
    if "name_regex" in when or "name_token_regex" in when:
        names = (rule_name(point), *graphql_context.argument_names(point))
        if "name_regex" in when:
            checks.append(any(re.fullmatch(when["name_regex"], n, re.I) for n in names))
        if "name_token_regex" in when:
            checks.append(_token_match(when["name_token_regex"], names))
    if "value_shape_in" in when:
        shapes = getattr(point, "value_shapes", None) or ()
        checks.append(bool(set(shapes) & set(when["value_shape_in"])))
    if "origin_in" in when:
        checks.append(getattr(point, "origin", None) in when["origin_in"])
    if "content_type_in" in when:
        checks.append(content_type_family(point) in when["content_type_in"])
    if "path_token_regex" in when:
        checks.append(_token_match(when["path_token_regex"], [_path_of(point.url)]))
    if "body_leaf_token_regex" in when:
        checks.append(_token_match(when["body_leaf_token_regex"], _leaf_names(point)))
    if "server_language_in" in when:
        language = (target or {}).get("server_language")
        checks.append(language is not None and language in when["server_language_in"])
    return bool(checks) and all(checks)
