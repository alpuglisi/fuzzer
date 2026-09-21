"""Evaluate rules over injection points, logging every evaluation (T2.3).

For each (injection point, rule) pair the engine records an `evaluation` row with
its outcome (fired / not-fired) — so negatives are in the store, not just hits —
and emits a `candidate` row for each fired evaluation. An optional `categories`
filter scopes which rules run (used by category selection, D14 / T2.9).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from fuzzlab.audit.rules import Rule, load_rules, matches


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


def evaluate(points: list[InjectionPoint], store, run_id: int,
             rules: list[Rule] | None = None,
             categories: list[str] | None = None, plugins=None) -> dict[str, int]:
    """Evaluate every rule against every point; record all evaluations + candidates.

    ``categories`` (None = all) scopes the active rules — the hook for D14/T2.9
    category selection. An optional ``plugins`` (PluginManager) contributes extra rules
    (``register_rules``) and is notified of each emitted candidate (``on_candidate``).
    """
    rules = load_rules() if rules is None else rules
    if plugins is not None:
        rules = list(rules) + list(plugins.rules())        # register_rules
    active = [r for r in rules if categories is None or r.category in categories]
    counts = {"evaluation": 0, "candidate": 0, "negative": 0}

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
