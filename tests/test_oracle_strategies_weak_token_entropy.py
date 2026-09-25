"""PredictableTokenSourceStrategy (CC-FUZZ-0038/FR-FUZZ-24): the project's
first real audit-rule/oracle-strategy pair for `weak_token_entropy`
(CWE-330), the deliberately-separated detection follow-on to Twitch's 5th
real page (`CC-LAB-0181`). Mirrors `test_oracle_strategies_access_control.py`'s
own vulnerable/secure-twin fake-sender pattern.
"""

from __future__ import annotations

import json
import time

from fuzzlab.audit.rules import load_rules, matches
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import PredictableTokenSourceStrategy


def _cand():
    return Candidate(url="http://h/sessions/refresh", param="body", method="POST",
                     location="body", vuln_class="weak_token_entropy",
                     category="weak-token-entropy", content_type="application/json")


class _TimestampVulnerableSender:
    """Simulates the vulnerable twin: the session token is the current
    nanosecond timestamp -- this project's own real, empirically-verified
    `predictable_token_source.go.j2` shape."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        return Probe(200, json.dumps({"session_token": str(time.time_ns())}))


class _CsprngSecureSender:
    """Simulates the secure twin: 64 hex characters from crypto/rand,
    never parses as a decimal integer."""

    def __init__(self):
        self._n = 0

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        import secrets
        self._n += 1
        return Probe(200, json.dumps({"session_token": secrets.token_hex(32)}))


class _StaleTokenSender:
    """A false-positive-avoidance case: a fixed token that never changes
    (e.g. a caching bug) -- both parse as the same integer, delta is 0,
    which the strategy's own `0 <= delta` bound would otherwise accept.
    Included to document that a delta of exactly 0 is not itself treated
    as suspicious (a real, if narrow, accepted risk: this strategy cannot
    distinguish 'issued twice within the same nanosecond' from 'always
    issues the literal same value'), not silently assumed away."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        return Probe(200, json.dumps({"session_token": "1234567890123456789"}))


class _MissingFieldSender:
    """A false-negative-avoidance case: no `session_token` field at all."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        return Probe(200, json.dumps({"status": "ok"}))


def test_confirms_the_vulnerable_timestamp_twin():
    strategy = PredictableTokenSourceStrategy()
    verdict = strategy.confirm(_cand(), _TimestampVulnerableSender())
    assert verdict is not None and verdict.confirmed
    assert verdict.vuln_class == "weak_token_entropy"
    assert verdict.mechanism == "timestamp-derived-token"
    assert "delta_ns" in verdict.evidence
    assert verdict.evidence["delta_ns"] >= 0


def test_fails_closed_on_the_secure_csprng_twin():
    strategy = PredictableTokenSourceStrategy()
    assert strategy.confirm(_cand(), _CsprngSecureSender()) is None


def test_fails_closed_when_the_session_token_field_is_missing():
    strategy = PredictableTokenSourceStrategy()
    assert strategy.confirm(_cand(), _MissingFieldSender()) is None


def test_evidence_never_records_the_full_raw_token():
    strategy = PredictableTokenSourceStrategy()
    verdict = strategy.confirm(_cand(), _TimestampVulnerableSender())
    assert verdict is not None
    assert "token_a_prefix" in verdict.evidence and "token_b_prefix" in verdict.evidence
    assert len(verdict.evidence["token_a_prefix"]) <= 8
    assert "token_a" not in verdict.evidence and "token_b" not in verdict.evidence


def test_confirms_a_zero_delta_stale_token_a_known_accepted_edge_case():
    # Documented, accepted limitation (see the strategy's own docstring):
    # a delta of exactly 0 is not itself treated as suspicious, so a
    # target that always issues the literal same token value also
    # confirms here -- pinned so this narrow false-positive class stays
    # a documented, deliberate choice, not a silent surprise.
    strategy = PredictableTokenSourceStrategy()
    verdict = strategy.confirm(_cand(), _StaleTokenSender())
    assert verdict is not None and verdict.evidence["delta_ns"] == 0


def test_registered_in_default_strategies():
    from fuzzlab.oracle.strategies import default_strategies
    kinds = [type(s) for s in default_strategies()]
    assert PredictableTokenSourceStrategy in kinds


def test_r_weak_token_entropy_rule_matches_a_post_session_token_point():
    class _Point:
        location = "body"
        method = "POST"
        param = "body"
        sink_context = "session_token"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-WEAK-TOKEN-ENTROPY")
    assert matches(rule, _Point())


def test_r_weak_token_entropy_rule_does_not_match_a_get_point():
    class _Point:
        location = "body"
        method = "GET"
        param = "body"
        sink_context = "session_token"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-WEAK-TOKEN-ENTROPY")
    assert not matches(rule, _Point())
