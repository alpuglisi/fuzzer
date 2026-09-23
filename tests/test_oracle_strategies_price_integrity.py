"""PriceIntegrityBypassStrategy (CC-FUZZ-0037/FR-FUZZ-23): the project's
first real audit-rule/oracle-strategy pair for `price_integrity_bypass`
(CWE-807) -- already built on two stacks' lab pages (`php_laravel`'s
Booking.com checkout, `CC-LAB-0212`; `spring_boot`'s Netflix plan-change,
`CC-LAB-0188`), but with no detection anywhere in the project until this
strategy. Mirrors `test_oracle_strategies_mass_assignment.py`'s own
vulnerable/secure-twin fake-sender pattern, generalized from a boolean
privileged field to a numeric charge field.
"""

from __future__ import annotations

import json

from fuzzlab.audit.rules import load_rules, matches
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import PriceIntegrityBypassStrategy


def _cand():
    return Candidate(url="http://h/api/subscription/change-plan", param="body",
                     method="POST", location="body", vuln_class="price_integrity_bypass",
                     category="price-integrity-bypass", content_type="application/json")


_PLAN_PRICES = {"basic": 6.99, "standard": 15.49, "premium": 22.99}


class _ClientTrustedAmountVulnerableSender:
    """Simulates the vulnerable twin: whatever monthly_charge the request
    body sends is trusted and echoed straight back."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        body = json.loads(value)
        record = {"plan_tier": body.get("plan_tier", ""), "monthly_charge": body.get("monthly_charge")}
        return Probe(200, json.dumps(record))


class _ServerRecomputedAmountSecureSender:
    """Simulates the secure twin: monthly_charge is discarded entirely and
    looked up server-side by plan_tier -- the same real price every time,
    regardless of what the client sends."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        body = json.loads(value)
        tier = body.get("plan_tier", "")
        record = {"plan_tier": tier, "monthly_charge": _PLAN_PRICES.get(tier)}
        return Probe(200, json.dumps(record))


class _AlwaysSameLowAmountSender:
    """A false-positive-avoidance case: the server always reports the same
    fixed low amount no matter what is sent -- probe A's own baseline
    check must pass (it happens to equal 0.01), but probe B's own high
    probe must not track, so this must fail closed overall."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        return Probe(200, json.dumps({"plan_tier": "standard", "monthly_charge": 0.01}))


class _NonJsonSender:
    """A false-negative-avoidance case: the point has no declared JSON
    content type at all -- this strategy has nothing to parse and must
    fail closed rather than misfire."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):  # pragma: no cover - never reached (gated before send)
        raise AssertionError("should never be called -- content_type gate must short-circuit")


class _MissingFieldSender:
    """A false-negative-avoidance case: the response never echoes the
    monthly_charge field at all."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        return Probe(200, json.dumps({"status": "ok"}))


class _RejectsProbeBSender:
    """A false-negative-avoidance case: probe A succeeds, but probe B
    (the differentiator) is rejected outright."""

    def __init__(self):
        self._calls = 0

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        self._calls += 1
        if self._calls == 1:
            return Probe(200, json.dumps({"plan_tier": "standard", "monthly_charge": 0.01}))
        return Probe(400, "bad request")


def test_confirms_the_vulnerable_client_trusted_amount_twin():
    strategy = PriceIntegrityBypassStrategy()
    verdict = strategy.confirm(_cand(), _ClientTrustedAmountVulnerableSender())
    assert verdict is not None and verdict.confirmed
    assert verdict.vuln_class == "price_integrity_bypass"
    assert verdict.mechanism == "client-price-trust-differential"
    assert verdict.evidence["field"] == "monthly_charge"
    assert verdict.evidence["low"] == 0.01
    assert verdict.evidence["high"] == 999999.99


def test_fails_closed_on_the_secure_server_recomputed_amount_twin():
    strategy = PriceIntegrityBypassStrategy()
    assert strategy.confirm(_cand(), _ServerRecomputedAmountSecureSender()) is None


def test_fails_closed_on_a_target_that_always_returns_the_same_fixed_amount():
    strategy = PriceIntegrityBypassStrategy()
    assert strategy.confirm(_cand(), _AlwaysSameLowAmountSender()) is None


def test_fails_closed_when_content_type_is_not_json():
    strategy = PriceIntegrityBypassStrategy()
    cand = Candidate(url="http://h/x", param="amount", method="POST", location="body",
                     vuln_class="price_integrity_bypass", category="price-integrity-bypass",
                     content_type=None)
    assert strategy.confirm(cand, _NonJsonSender()) is None


def test_fails_closed_when_the_charge_field_is_missing():
    strategy = PriceIntegrityBypassStrategy()
    assert strategy.confirm(_cand(), _MissingFieldSender()) is None


def test_fails_closed_when_probe_b_is_rejected():
    strategy = PriceIntegrityBypassStrategy()
    assert strategy.confirm(_cand(), _RejectsProbeBSender()) is None


def test_registered_in_default_strategies():
    from fuzzlab.oracle.strategies import default_strategies
    kinds = [type(s) for s in default_strategies()]
    assert PriceIntegrityBypassStrategy in kinds


def test_r_price_integrity_rule_matches_a_body_payment_charge_point():
    class _Point:
        location = "body"
        method = "POST"
        param = "body"
        sink_context = "payment_charge"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-PRICE-INTEGRITY")
    assert matches(rule, _Point())


def test_r_price_integrity_rule_does_not_match_a_query_point():
    class _Point:
        location = "query"
        method = "GET"
        param = "body"
        sink_context = "payment_charge"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-PRICE-INTEGRITY")
    assert not matches(rule, _Point())


def test_r_price_integrity_rule_does_not_match_an_unrelated_sink_context():
    class _Point:
        location = "body"
        method = "POST"
        param = "body"
        sink_context = "sql"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-PRICE-INTEGRITY")
    assert not matches(rule, _Point())
