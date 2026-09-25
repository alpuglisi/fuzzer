"""MassAssignmentPrivilegedFieldStrategy (CC-FUZZ-0039/FR-FUZZ-25): the
project's first real audit-rule/oracle-strategy pair for `mass_assignment`
(CWE-915) -- already built on three other stacks' lab pages
(`php_current`/`ruby_rails`/`php_laravel`), but with no detection anywhere
in the project until this strategy, closing Twitch's 6th real page
(`CC-LAB-0182`)'s own deliberately-separated detection follow-on. Mirrors
`test_oracle_strategies_weak_token_entropy.py`'s own vulnerable/
secure-twin fake-sender pattern.
"""

from __future__ import annotations

import json

from fuzzlab.audit.rules import load_rules, matches
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import MassAssignmentPrivilegedFieldStrategy


def _cand():
    return Candidate(url="http://h/channels/profile", param="body",
                     method="POST", location="body", vuln_class="mass_assignment",
                     category="mass-assignment", content_type="application/json")


class _UnfilteredAssignVulnerableSender:
    """Simulates the vulnerable twin: `json.Unmarshal` onto the live
    record -- whatever the request body sets (including `is_partner`)
    takes effect and is echoed straight back."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        body = json.loads(value)
        record = {"display_name": body.get("display_name", ""),
                  "bio": body.get("bio", ""),
                  "is_partner": body.get("is_partner", False)}
        return Probe(200, json.dumps(record))


class _TypedAllowlistSecureSender:
    """Simulates the secure twin: only `display_name`/`bio` ever reach
    the record -- `is_partner` in the request body is silently dropped,
    the record always echoes back its seeded `false`."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        body = json.loads(value)
        record = {"display_name": body.get("display_name", ""),
                  "bio": body.get("bio", ""),
                  "is_partner": False}
        return Probe(200, json.dumps(record))


class _AlwaysTruePermissiveSender:
    """A false-positive-avoidance case: the privileged field always reads
    back `true`, regardless of what probe A sends (e.g. a broadly broken
    endpoint, not specifically mass-assignable). Probe A's own baseline
    check (`before is not False -> None`) must reject this before probe B
    is ever sent."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        body = json.loads(value)
        return Probe(200, json.dumps({"display_name": body.get("display_name", ""),
                                      "bio": body.get("bio", ""),
                                      "is_partner": True}))


class _NonJsonSender:
    """A false-negative-avoidance case: the point has no declared JSON
    content type at all (e.g. a form-encoded nested-param shape like
    `ruby_rails`'s own `FCART-0004`) -- this strategy has nothing to
    parse and must fail closed rather than misfire."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):  # pragma: no cover - never reached (gated before send)
        raise AssertionError("should never be called -- content_type gate must short-circuit")


class _MissingFieldSender:
    """A false-negative-avoidance case: the response never echoes the
    privileged field at all."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        return Probe(200, json.dumps({"status": "ok"}))


def test_confirms_the_vulnerable_unfiltered_assign_twin():
    strategy = MassAssignmentPrivilegedFieldStrategy()
    verdict = strategy.confirm(_cand(), _UnfilteredAssignVulnerableSender())
    assert verdict is not None and verdict.confirmed
    assert verdict.vuln_class == "mass_assignment"
    assert verdict.mechanism == "privileged-field-injection"
    assert verdict.evidence["field"] == "is_partner"


def test_fails_closed_on_the_secure_typed_allowlist_twin():
    strategy = MassAssignmentPrivilegedFieldStrategy()
    assert strategy.confirm(_cand(), _TypedAllowlistSecureSender()) is None


def test_fails_closed_on_an_always_true_permissive_target():
    strategy = MassAssignmentPrivilegedFieldStrategy()
    assert strategy.confirm(_cand(), _AlwaysTruePermissiveSender()) is None


def test_fails_closed_when_content_type_is_not_json():
    strategy = MassAssignmentPrivilegedFieldStrategy()
    cand = Candidate(url="http://h/x", param="role", method="POST", location="body",
                     vuln_class="mass_assignment", category="mass-assignment",
                     content_type=None)
    assert strategy.confirm(cand, _NonJsonSender()) is None


def test_fails_closed_when_the_privileged_field_is_missing():
    strategy = MassAssignmentPrivilegedFieldStrategy()
    assert strategy.confirm(_cand(), _MissingFieldSender()) is None


def test_registered_in_default_strategies():
    from fuzzlab.oracle.strategies import default_strategies
    kinds = [type(s) for s in default_strategies()]
    assert MassAssignmentPrivilegedFieldStrategy in kinds


def test_r_mass_assignment_rule_matches_a_body_mass_assignment_point():
    class _Point:
        location = "body"
        method = "POST"
        param = "body"
        sink_context = "mass_assignment"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-MASS-ASSIGNMENT")
    assert matches(rule, _Point())


def test_r_mass_assignment_rule_does_not_match_a_query_point():
    class _Point:
        location = "query"
        method = "GET"
        param = "body"
        sink_context = "mass_assignment"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-MASS-ASSIGNMENT")
    assert not matches(rule, _Point())
