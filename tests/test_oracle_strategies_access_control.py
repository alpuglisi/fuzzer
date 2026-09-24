"""AccessControlIdorStrategy (CC-FUZZ-0033/FR-FUZZ-20): the project's first
real audit-rule/oracle-strategy pair for the `access_control` (IDOR/BOLA)
vulnerability class, closing the CC-LAB-0178 open question. Mirrors the
established vulnerable/secure-twin fake-sender pattern from
`test_oracle_oob.py`'s own SSRF strategy tests, plus explicit false-positive
coverage the adequacy review (pre-change review gate) required.
"""

from __future__ import annotations

from fuzzlab.audit.rules import load_rules, matches
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import AccessControlIdorStrategy, default_strategies


def _cand():
    return Candidate(url="http://h/generated/labgen-go-0005", param="channel_id",
                     method="GET", location="query", vuln_class="access_control",
                     category="access-control")


class _NoOwnershipCheckSender:
    """Simulates the vulnerable twin (`no_ownership_check`): any channel_id
    is accepted and echoed back in a 200 analytics body -- this project's
    own `object_lookup_authorization_check.go.j2` sink shape."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
              content_type=None):
        body = ('{"channel_id":"' + value +
                '","subscriber_count":42,"revenue_estimate_usd":1234.56}')
        return Probe(200, body)


class _IdentityMatchSender:
    """Simulates the secure twin (`identity_match_before_fetch`): the
    requested channel_id never matches the caller's own (absent) identity,
    so every probe is rejected."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
              content_type=None):
        return Probe(403, "")


class _PublicSearchSender:
    """A false-positive probe: a legitimate public search/lookup endpoint
    that echoes back whatever id it's given (no secrets gated by ownership)
    -- distinct 200 bodies, no denial marker, ids echoed. The strategy has
    no way to know this data isn't sensitive; it is expected to (and does,
    by design -- see the strategy's own docstring) flag this as a candidate
    the way any black-box differential would. Included here to document the
    known false-positive class, not to assert a negative the strategy can't
    actually detect."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
              content_type=None):
        return Probe(200, '{"public_item_id":"' + value + '","title":"widget"}')


class _CannedPageSender:
    """A false-positive-avoidance case: an endpoint that returns the exact
    same static page regardless of the id (no differential signal at all)."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
              content_type=None):
        return Probe(200, "<html>static landing page</html>")


class _DenialPageSender:
    """A secure endpoint that denies with a 200 status but an "access
    denied"-shaped body rather than a non-2xx status."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
              content_type=None):
        return Probe(200, "Sorry, access denied for id " + value)


def test_confirms_the_vulnerable_no_ownership_check_twin():
    strategy = AccessControlIdorStrategy()
    verdict = strategy.confirm(_cand(), _NoOwnershipCheckSender())
    assert verdict is not None and verdict.confirmed
    assert verdict.vuln_class == "access_control"
    assert verdict.mechanism == "identity-differential"
    assert "probe_a" in verdict.evidence and "probe_b" in verdict.evidence


def test_fails_closed_on_the_secure_identity_match_twin():
    strategy = AccessControlIdorStrategy()
    assert strategy.confirm(_cand(), _IdentityMatchSender()) is None


def test_fails_closed_when_the_body_never_differs():
    strategy = AccessControlIdorStrategy()
    assert strategy.confirm(_cand(), _CannedPageSender()) is None


def test_fails_closed_on_a_200_with_a_denial_phrase():
    strategy = AccessControlIdorStrategy()
    assert strategy.confirm(_cand(), _DenialPageSender()) is None


def test_documented_false_positive_class_a_public_echo_endpoint_does_confirm():
    # Not a defect: the strategy's own docstring states this limitation
    # explicitly (a black-box differential cannot know the data isn't
    # sensitive). Pinned here so the limitation stays documented, not silent.
    strategy = AccessControlIdorStrategy()
    verdict = strategy.confirm(_cand(), _PublicSearchSender())
    assert verdict is not None and verdict.confirmed


def test_denial_marker_is_word_boundary_anchored():
    # PA-0022: a substring like "preauthorized" must not false-trigger the
    # "unauthorized" denial marker.
    assert not AccessControlIdorStrategy._DENIAL_MARKERS.search(
        "this widget is preauthorized for id 50172")


def test_registered_in_default_strategies():
    kinds = [type(s) for s in default_strategies()]
    assert AccessControlIdorStrategy in kinds


def test_r_access_control_rule_matches_a_channel_id_query_get_point():
    class _Point:
        location = "query"
        method = "GET"
        param = "channel_id"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-ACCESS-CONTROL")
    assert matches(rule, _Point())


def test_r_access_control_rule_does_not_match_a_body_or_post_point():
    class _BodyPoint:
        location = "body"
        method = "GET"
        param = "channel_id"

    class _PostPoint:
        location = "query"
        method = "POST"
        param = "channel_id"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-ACCESS-CONTROL")
    assert not matches(rule, _BodyPoint())
    assert not matches(rule, _PostPoint())
