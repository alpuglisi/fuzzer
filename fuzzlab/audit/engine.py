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
    # The store request's method and location, and a JSON store body's other leaves
    # (``store_location="json"``; FR-FUZZ-56): from the ground truth's point at the
    # store URL. A form POST when that point is not enumerated.
    store_method: str = "POST"
    store_location: str = "body"
    store_entries: tuple | None = None
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
    # The one mechanism that decides this point (FR-AUD-30, BUG-0523): ``(category,
    # arm)``, written by the point builder (a stored case's observe point, a
    # ground-truth DOM point); its arm reaches that category's evidence only.
    decided_by: tuple[str, str] | None = None
    # FR-FUZZ-67 (BUG-0544): the replay recipe of entries whose stored value is a
    # placeholder (blanked by redaction): ``(source page URL or None, (names, ...))``.
    # Before each send the oracle's binder fetches the page in the probe's session and
    # binds those entries' current values, in memory only; never a value here (D12).
    bindings: tuple[str | None, tuple[str, ...]] | None = None
    # Why this point's request can never be rebuilt (a sibling naming a host outside the
    # lab, FR-AUD-20): the test is inconclusive with this reason; nothing is sent.
    replay_refusal: str | None = None


def evaluate(points: list[InjectionPoint], store, run_id: int,
             rules: list[Rule] | None = None,
             categories: list[str] | None = None, plugins=None,
             identity: str | None = None) -> dict[str, int]:
    """Evaluate every rule against every point; record all evaluations + candidates.

    ``categories`` (None = all) scopes the active rules — the hook for D14/T2.9
    category selection. An optional ``plugins`` (PluginManager) contributes extra rules
    (``register_rules``) and is notified of each emitted candidate (``on_candidate``).

    Every candidate's evidence carries its request context's id and the run's
    ``identity`` scope (`core.reqctx.stamp`, SP-57, FR-FUZZ-66): the one identity the
    pipeline confirms on, the oracle attributes a finding to and ML labels by.
    """
    from fuzzlab.core import reqctx
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
                # the request's own fields, written by the identity's owner (SP-57)
                evidence = {"rule_id": rule.id, "category": rule.category,
                            **reqctx.point_evidence(point)}
                if point.base_value is not None:
                    evidence["base_value"] = point.base_value
                if point.redirect_seed is not None and rule.category == "open-redirect":
                    evidence["redirect_seed"] = point.redirect_seed     # FR-AUD-21
                if point.decided_by is not None and rule.category == point.decided_by[0]:
                    evidence["decided_by"] = point.decided_by[1]        # FR-AUD-30
                reqctx.stamp(evidence, identity)                         # FR-FUZZ-66
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
