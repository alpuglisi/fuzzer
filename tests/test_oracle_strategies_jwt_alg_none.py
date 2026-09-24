"""JwtAlgNoneConfusionStrategy (CC-FUZZ-0037/FR-FUZZ-23): the project's
first real audit-rule/oracle-strategy pair for `jwt_algorithm_confusion`
(CWE-347), the deliberately-separated detection follow-on to Twitch's 4th
real page (`CC-LAB-0180`). Mirrors `test_oracle_strategies_access_control.py`'s
own vulnerable/secure-twin fake-sender pattern.
"""

from __future__ import annotations

import base64
import json

from fuzzlab.audit.rules import load_rules, matches
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import JwtAlgNoneConfusionStrategy


def _cand():
    return Candidate(url="http://h/generated/labgen-go-0007", param="Authorization",
                     method="GET", location="header", vuln_class="jwt_algorithm_confusion",
                     category="jwt-algorithm-confusion")


def _decode_jwt(value: str) -> tuple[dict, dict]:
    token = value.removeprefix("Bearer ")
    header_b64, payload_b64, _sig = token.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)
    header = json.loads(base64.urlsafe_b64decode(pad(header_b64)))
    payload = json.loads(base64.urlsafe_b64decode(pad(payload_b64)))
    return header, payload


class _AlgNoneVulnerableSender:
    """Simulates the vulnerable twin (`jwt_alg_none_default`): an alg:none
    token's own forged claims are echoed back; a garbage HS256 signature
    is still correctly rejected -- this project's own real, empirically-
    verified behavior (`CC-LAB-0180`)."""

    def send(self, url, param, value, timing=False, method="GET", location="header",
              content_type=None):
        header, payload = _decode_jwt(value)
        if header.get("alg", "").lower() == "none":
            return Probe(200, json.dumps({"channel_id": payload.get("channel_id"),
                                          "role": payload.get("role"), "settings": "private"}))
        return Probe(401, '{"error":"invalid token"}')


class _SecureSender:
    """Simulates the secure twin (`jwt_none_alg_opt_in`): rejects every
    token outright (no real HS256 secret known to this fake sender)."""

    def send(self, url, param, value, timing=False, method="GET", location="header",
              content_type=None):
        return Probe(401, '{"error":"invalid token"}')


class _AcceptsAnythingSender:
    """A false-positive-avoidance case: an endpoint that accepts and
    echoes back anything at all, regardless of signature/algorithm."""

    def send(self, url, param, value, timing=False, method="GET", location="header",
              content_type=None):
        _header, payload = _decode_jwt(value)
        return Probe(200, json.dumps({"channel_id": payload.get("channel_id"),
                                      "role": payload.get("role")}))


class _CrashesOnGarbageSender:
    """A false-positive-avoidance case: probe B's garbage signature
    causes an unrelated 500 (a parsing crash), not a real 401/403
    auth rejection -- must not be mistaken for evidence."""

    def send(self, url, param, value, timing=False, method="GET", location="header",
              content_type=None):
        header, payload = _decode_jwt(value)
        if header.get("alg", "").lower() == "none":
            return Probe(200, json.dumps({"channel_id": payload.get("channel_id"),
                                          "role": payload.get("role")}))
        return Probe(500, "internal server error")


def test_confirms_the_vulnerable_alg_none_twin():
    strategy = JwtAlgNoneConfusionStrategy()
    verdict = strategy.confirm(_cand(), _AlgNoneVulnerableSender())
    assert verdict is not None and verdict.confirmed
    assert verdict.vuln_class == "jwt_algorithm_confusion"
    assert verdict.mechanism == "alg-none-bypass"
    assert "marker" in verdict.evidence


def test_fails_closed_on_the_secure_twin():
    strategy = JwtAlgNoneConfusionStrategy()
    assert strategy.confirm(_cand(), _SecureSender()) is None


def test_fails_closed_when_the_endpoint_accepts_anything():
    strategy = JwtAlgNoneConfusionStrategy()
    assert strategy.confirm(_cand(), _AcceptsAnythingSender()) is None


def test_fails_closed_on_a_500_crash_not_a_real_auth_rejection():
    strategy = JwtAlgNoneConfusionStrategy()
    assert strategy.confirm(_cand(), _CrashesOnGarbageSender()) is None


def test_registered_in_default_strategies():
    from fuzzlab.oracle.strategies import default_strategies
    kinds = [type(s) for s in default_strategies()]
    assert JwtAlgNoneConfusionStrategy in kinds


def test_r_jwt_alg_none_rule_matches_an_authorization_header_point():
    class _Point:
        location = "header"
        method = "GET"
        param = "Authorization"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-JWT-ALG-NONE")
    assert matches(rule, _Point())


def test_r_jwt_alg_none_rule_does_not_match_an_unrelated_header():
    class _Point:
        location = "header"
        method = "POST"
        param = "X-Signature-256"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-JWT-ALG-NONE")
    assert not matches(rule, _Point())
