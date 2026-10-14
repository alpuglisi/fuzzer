"""Evaluate rules over injection points, logging every evaluation (T2.3).

For each (injection point, rule) pair the engine records an `evaluation` row with
its outcome (fired / not-fired) — so negatives are in the store, not just hits —
and emits a `candidate` row for each fired evaluation. An optional `categories`
filter scopes which rules run (used by category selection, D14 / T2.9).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from fuzzlab.audit.rules import Rule, RuleError, load_rules, matches, validate_rule

_log = logging.getLogger(__name__)


@dataclass
class InjectionPoint:
    url: str
    param: str
    method: str = "GET"
    location: str = "query"
    sink_context: str | None = None
    # Stored-XSS: where the payload is planted before it renders on `url` (M6).
    store_url: str | None = None
    store_param: str | None = None
    # A whole-body point's real content type (e.g. "application/json") -- set
    # only when the ground truth says so (CC-FUZZ-0032/FR-FUZZ-19); a sender
    # must never assume JSON for every `param="body"` point (some are XML/
    # binary-serialized, e.g. TrackerNest's XXE/insecure-deserialization
    # cases), so this is `None` unless the caller positively knows the format.
    body_content_type: str | None = None
    # A crawled form's default entry list (forms phase 1, FR-FUZZ-42), or a crawled
    # link's query (forms phase 2, FR-FUZZ-43): every probe of `param` sends the other
    # fields with it. None for a lone parameter.
    base_entries: tuple[tuple[str, str], ...] | None = None
    # Forms phase 2 (FR-AUD-20). Where the point came from ("crawl" / "ground-truth");
    # read only by the `origin_in` predicate, never written to evidence.
    origin: str | None = None
    # The shapes of the point's example value (`audit.value_shape.SHAPES`), for the
    # `value_shape_in` predicate. Empty for ground-truth and header points.
    value_shapes: frozenset[str] = frozenset()
    # The value a command-injection probe starts from in place of an ip/host-shaped
    # default (`value_shape.SAFE_HOST`), so the app's own host is never sent.
    base_value: str | None = None
    # A crawled URL-shaped example's `value_shape.redirect_seed` (BUG-0124): written to
    # an open-redirect candidate's evidence only (the stated FR-AUD-20 exception).
    redirect_seed: str | None = None


def evaluate(points: list[InjectionPoint], store, run_id: int,
             rules: list[Rule] | None = None,
             categories: list[str] | None = None, plugins=None) -> dict[str, int]:
    """Evaluate every rule against every point; record all evaluations + candidates.

    ``categories`` (None = all) scopes the active rules — the hook for D14/T2.9
    category selection. An optional ``plugins`` (PluginManager) contributes extra rules
    (``register_rules``) and is notified of each emitted candidate (``on_candidate``).
    """
    rules = load_rules() if rules is None else rules
    counts = {"evaluation": 0, "candidate": 0, "negative": 0}
    if plugins is not None:
        # register_rules; a plugin rule is checked like the bundled file's (PA-0086(1)):
        # an invalid one is left out and counted, never evaluated, never fatal
        valid = []
        for rule in plugins.rules():
            try:
                validate_rule(rule)
            except RuleError as exc:
                counts["invalid_plugin_rules"] = counts.get("invalid_plugin_rules", 0) + 1
                _log.warning("plugin rule left out: %s", exc)
                continue
            valid.append(rule)
        rules = list(rules) + valid
    active = [r for r in rules if categories is None or r.category in categories]

    for point in points:
        for rule in active:
            fired = matches(rule, point)
            store.conn.execute(
                "INSERT INTO evaluation (run_id, url, method, param, location, "
                "rule_id, category, transaction_type, fired, sink_context, evidence) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, point.url, point.method, point.param, point.location,
                 rule.id, rule.category, rule.transaction_type, 1 if fired else 0,
                 point.sink_context, json.dumps({"when": rule.when})),
            )
            counts["evaluation"] += 1
            if fired:
                evidence = {"rule_id": rule.id, "category": rule.category,
                            "url": point.url, "param": point.param,
                            "method": point.method, "location": point.location}
                if point.store_url:                      # stored-XSS store endpoint (M6)
                    evidence["store_url"] = point.store_url
                    evidence["store_param"] = point.store_param or point.param
                if point.body_content_type:
                    evidence["body_content_type"] = point.body_content_type
                if point.base_entries is not None:
                    evidence["entries"] = [list(e) for e in point.base_entries]
                if point.base_value is not None:
                    evidence["base_value"] = point.base_value
                if point.redirect_seed is not None and rule.category == "open-redirect":
                    evidence["redirect_seed"] = point.redirect_seed     # FR-AUD-21
                store.conn.execute(
                    "INSERT INTO candidate (run_id, rule, evidence, sink_context) "
                    "VALUES (?,?,?,?)",
                    (run_id, rule.transaction_type, json.dumps(evidence),
                     point.sink_context),
                )
                counts["candidate"] += 1
                if plugins is not None:
                    plugins.on_candidate(dict(evidence))     # observation (return ignored)
            else:
                counts["negative"] += 1

    store.conn.commit()
    return counts
