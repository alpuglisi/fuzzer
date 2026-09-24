"""InsecureDeserializationTypeConfusionStrategy (CC-FUZZ-0034/FR-FUZZ-21):
the project's first real audit-rule/oracle-strategy pair for the
`insecure_deserialization` vulnerability class, closing one of the two
remaining structural zeros `test_multitarget_category4.py` tracked. Mirrors
`test_oracle_strategies_access_control.py`'s own vulnerable/secure-twin
fake-sender pattern.
"""

from __future__ import annotations

import re

from fuzzlab.audit.rules import load_rules, matches
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import InsecureDeserializationTypeConfusionStrategy


def _cand():
    return Candidate(url="http://h/api/playback/resume", param="body", method="POST",
                     location="body", vuln_class="insecure_deserialization",
                     category="insecure-deserialization", content_type="application/json")


class _UnrestrictedPolymorphicTypingSender:
    """Simulates the vulnerable twin (`activateDefaultTyping` with an
    always-ALLOWED validator): a real class name in the WRAPPER_ARRAY
    format is instantiated (200); a bogus one is rejected, but only after
    genuinely attempting class resolution -- the error echoes the literal
    class name back, exactly this project's own real, empirically-verified
    Jackson error shape."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        import json
        class_name = json.loads(value)[0]
        if class_name == "java.util.HashMap":
            return Probe(200, '{"status":"ok"}')
        return Probe(400, f"Could not resolve type id '{class_name}' as a subtype "
                          f"of `java.lang.Object`: no such class found")


class _FixedPojoSender:
    """Simulates the secure twin (no polymorphic typing at all): the
    array-wrapped format is categorically rejected before any type
    resolution is attempted -- the error never mentions the class name."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        return Probe(400, "Cannot deserialize value of type `...PlaybackResumeRequest` "
                          "from Array value (token `START_ARRAY`)")


class _AcceptsAnythingSender:
    """A false-positive-avoidance case: an endpoint that returns 200 for
    literally any body without validating it at all (weak input handling,
    not a deserialization vulnerability)."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        return Probe(200, '{"status":"ok"}')


def test_confirms_the_vulnerable_unrestricted_polymorphic_typing_twin():
    strategy = InsecureDeserializationTypeConfusionStrategy()
    verdict = strategy.confirm(_cand(), _UnrestrictedPolymorphicTypingSender())
    assert verdict is not None and verdict.confirmed
    assert verdict.vuln_class == "insecure_deserialization"
    assert verdict.mechanism == "polymorphic-type-confusion"
    assert verdict.evidence["benign_class"] == "java.util.HashMap"
    assert "bogus_class" in verdict.evidence


def test_fails_closed_on_the_secure_fixed_pojo_twin():
    strategy = InsecureDeserializationTypeConfusionStrategy()
    assert strategy.confirm(_cand(), _FixedPojoSender()) is None


def test_fails_closed_when_the_endpoint_accepts_any_body():
    # The bogus-class probe also returns 200 here -- no differential signal.
    strategy = InsecureDeserializationTypeConfusionStrategy()
    assert strategy.confirm(_cand(), _AcceptsAnythingSender()) is None


def test_noops_without_a_declared_json_content_type():
    strategy = InsecureDeserializationTypeConfusionStrategy()

    class _ExplodingSender:
        def send(self, *a, **k):
            raise AssertionError("must not send any probe without content_type declared")

    cand = Candidate(url="http://h/x", param="body", method="POST", location="body",
                     vuln_class="insecure_deserialization", category="insecure-deserialization",
                     content_type=None)
    assert strategy.confirm(cand, _ExplodingSender()) is None


def test_bogus_class_name_is_freshly_minted_each_call():
    strategy = InsecureDeserializationTypeConfusionStrategy()
    seen = []

    class _RecordingSender(_UnrestrictedPolymorphicTypingSender):
        def send(self, url, param, value, timing=False, method="POST", location="body",
                  content_type=None):
            seen.append(value)
            return super().send(url, param, value, timing=timing, method=method,
                                location=location, content_type=content_type)

    strategy.confirm(_cand(), _RecordingSender())
    strategy.confirm(_cand(), _RecordingSender())
    bogus_payloads = [v for v in seen if "HashMap" not in v]
    assert len(bogus_payloads) == 2 and bogus_payloads[0] != bogus_payloads[1]


def test_registered_in_default_strategies():
    from fuzzlab.oracle.strategies import default_strategies
    kinds = [type(s) for s in default_strategies()]
    assert InsecureDeserializationTypeConfusionStrategy in kinds


def test_r_insecure_deserialization_rule_matches_a_body_deserialization_point():
    class _Point:
        location = "body"
        method = "POST"
        param = "body"
        sink_context = "deserialization"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-INSECURE-DESERIALIZATION")
    assert matches(rule, _Point())


def test_r_insecure_deserialization_rule_does_not_match_an_unrelated_sink_context():
    class _Point:
        location = "body"
        method = "POST"
        param = "body"
        sink_context = "xml"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-INSECURE-DESERIALIZATION")
    assert not matches(rule, _Point())
