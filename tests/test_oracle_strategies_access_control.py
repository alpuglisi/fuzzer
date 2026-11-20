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


def _cand(captured="41"):
    """FR-FUZZ-712: the point carries the id the target itself gave (a crawled link's
    value, `base_entries`), as a crawl run's candidate does."""
    entries = None if captured is None else (("channel_id", captured),)
    return Candidate(url="http://h/channels/analytics", param="channel_id",
                     method="GET", location="query", vuln_class="access_control",
                     category="access-control", base_entries=entries)


class _NoOwnershipCheckSender:
    """Simulates the vulnerable twin (`no_ownership_check`): any channel_id
    is accepted and echoed back in a 200 analytics body -- this project's
    own `object_lookup_authorization_check.go.j2` sink shape."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
              content_type=None, **kw):
        body = ('{"channel_id":"' + value +
                '","subscriber_count":42,"revenue_estimate_usd":1234.56}')
        return Probe(200, body)


class _IdentityMatchSender:
    """Simulates the secure twin (`identity_match_before_fetch`): the
    requested channel_id never matches the caller's own (absent) identity,
    so every probe is rejected."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
              content_type=None, **kw):
        return Probe(403, "")


#: The unauthenticated replay of a protected endpoint: refused (FR-FUZZ-714).
_ANON = _IdentityMatchSender()


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
              content_type=None, **kw):
        return Probe(200, '{"public_item_id":"' + value + '","title":"widget"}')


class _CannedPageSender:
    """A false-positive-avoidance case: an endpoint that returns the exact
    same static page regardless of the id (no differential signal at all)."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
              content_type=None, **kw):
        return Probe(200, "<html>static landing page</html>")


class _DenialPageSender:
    """A secure endpoint that denies with a 200 status but an "access
    denied"-shaped body rather than a non-2xx status."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
              content_type=None, **kw):
        return Probe(200, "Sorry, access denied for id " + value)


class _RealPhotoViewPageSender:
    """R3 (CC-LAB-0239, docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md): the actual
    rendered markup `fuzzlab.labgen.emitters.php_laravel`'s
    `resources/views/site/photo-view.blade.php` produces for
    `LABGEN-CF-0001` (vulnerable, `db_row_by_id_lookup` + `no_ownership_check`)
    -- copied from that real template, not a generic `<html>` stub, so this
    is a genuine check that the strategy's denial-marker/echo/diff logic
    still holds against the real HTML shape a photo id now renders as (it
    was JSON before this step). Confirms R3's own "no change needed"
    conclusion isn't just true against a stub."""

    def send(self, url, param, value, timing=False, method="GET", location="query",
              content_type=None, **kw):
        return Probe(
            200,
            f"<h2>Photo #{value}</h2>\n"
            f"<p><strong>Owner:</strong> 1</p>\n"
            f"<p>Photo caption {value}</p>\n"
            f"<p><em>/uploads/{value}.jpg</em></p>\n"
            "<p>Private</p>",
        )


def test_confirms_the_vulnerable_no_ownership_check_twin():
    strategy = AccessControlIdorStrategy(_ANON)
    verdict = strategy.confirm(_cand(), _NoOwnershipCheckSender())
    assert verdict is not None and verdict.confirmed
    assert verdict.vuln_class == "access_control"
    assert verdict.mechanism == "identity-differential"
    assert "probe_a" in verdict.evidence and "probe_b" in verdict.evidence


def test_fails_closed_on_the_secure_identity_match_twin():
    strategy = AccessControlIdorStrategy(_ANON)
    assert strategy.confirm(_cand(), _IdentityMatchSender()) is None


def test_fails_closed_when_the_body_never_differs():
    strategy = AccessControlIdorStrategy(_ANON)
    assert strategy.confirm(_cand(), _CannedPageSender()) is None


def test_confirms_against_the_real_rendered_photo_view_html_shape():
    """R3: proves the strategy's own 'no change needed' conclusion against
    the actual new HTML markup, not just a generic stub."""
    strategy = AccessControlIdorStrategy(_ANON)
    verdict = strategy.confirm(_cand(), _RealPhotoViewPageSender())
    assert verdict is not None and verdict.confirmed


def test_fails_closed_on_a_200_with_a_denial_phrase():
    strategy = AccessControlIdorStrategy(_ANON)
    assert strategy.confirm(_cand(), _DenialPageSender()) is None


def test_a_public_echo_endpoint_gives_no_verdict():
    """FR-FUZZ-714 (BUG-0735): the former documented false-positive class. A public
    object keyed by id answers the unauthenticated replay too, so it is no verdict."""
    strategy = AccessControlIdorStrategy(_PublicSearchSender())
    assert strategy.confirm(_cand(), _PublicSearchSender()) is None


def test_a_public_catalogue_neighbour_gives_no_verdict():
    """A catalogue keyed by a numeric id (``?id=41`` / ``?id=42``: both 200, distinct,
    stable) -- served alike with no session: never an access-control finding."""
    def answer(v):
        return Probe(200, f"<h1>Product {v}</h1><p>price {int(v) * 3}</p>")
    strategy = AccessControlIdorStrategy(_Recording(answer))
    assert strategy.confirm(_cand("41"), _Recording(answer)) is None


def test_no_verdict_without_an_unauthenticated_sender():
    """No anonymous control (a run with no logged-in session): UnplaceableLocation."""
    import pytest

    from fuzzlab.oracle.probe import UnplaceableLocation
    with pytest.raises(UnplaceableLocation, match="unauthenticated"):
        AccessControlIdorStrategy().confirm(_cand(), _NoOwnershipCheckSender())


def test_the_anonymous_replay_carries_the_neighbour_and_no_session():
    anon = _Recording(lambda v: Probe(401, ""))
    verdict = AccessControlIdorStrategy(anon).confirm(_cand("41"), _Recording())
    assert verdict is not None and verdict.evidence["anonymous_status"] == 401
    assert anon.sent == ["42"]


def test_default_strategies_give_the_strategy_the_runs_anonymous_sender():
    from fuzzlab.oracle.strategies import PeerAccounts
    anon = _IdentityMatchSender()
    peer = PeerAccounts(sender=None, owner="", peer_name="", anonymous=anon)
    idor = next(s for s in default_strategies(peer=peer)
                if isinstance(s, AccessControlIdorStrategy))
    assert idor._anonymous is anon
    idor = next(s for s in default_strategies() if isinstance(s, AccessControlIdorStrategy))
    assert idor._anonymous is None


def test_denial_marker_is_word_boundary_anchored():
    # PA-0022: a substring like "preauthorized" must not false-trigger the
    # "unauthorized" denial marker.
    assert not AccessControlIdorStrategy._DENIAL_MARKERS.search(
        "this widget is preauthorized for id 50172")


def test_registered_in_default_strategies():
    kinds = [type(s) for s in default_strategies()]
    assert AccessControlIdorStrategy in kinds


def test_r_access_control_rule_matches_a_channel_id_query_get_point():
    # By the generic identifier shape (`_id$`, BUG-0660), not by the name itself.
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


# --- FR-FUZZ-712 (BUG-0734, CC-FUZZ-0712): the target's own id and its neighbour ----

class _Recording:
    """Records every value sent; answers like the vulnerable twin (any id echoed)."""

    def __init__(self, answer=None):
        self.sent = []
        self.answer = answer or (lambda v: Probe(200, '{"id":"' + v + '","n":1}'))

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, **kw):
        self.sent.append(value)
        return self.answer(value)


def test_sends_only_the_targets_id_and_its_neighbour():
    """No synthetic id: the captured value twice (keyed-ness), then its +1 neighbour."""
    sender = _Recording()
    verdict = AccessControlIdorStrategy(_ANON).confirm(_cand("41"), sender)
    assert verdict is not None and verdict.confirmed
    assert sender.sent == ["41", "41", "42"]
    assert (verdict.evidence["value_a"], verdict.evidence["value_b"]) == ("41", "42")


def test_no_verdict_when_the_target_gave_no_id():
    """A ground-truth-point candidate carries no captured value: a stated miss
    (UnplaceableLocation, no verdict), never a guessed id -- and nothing is sent."""
    import pytest

    from fuzzlab.oracle.probe import UnplaceableLocation
    sender = _Recording()
    with pytest.raises(UnplaceableLocation, match="no id value"):
        AccessControlIdorStrategy(_ANON).confirm(_cand(None), sender)
    with pytest.raises(UnplaceableLocation, match="numeric neighbour"):
        AccessControlIdorStrategy(_ANON).confirm(
            _cand("3f2a9c4e-7b1d-4c2a-9e8f-1a2b3c4d5e6f"), sender)
    assert sender.sent == []


def test_tries_the_lower_neighbour_when_the_upper_is_past_the_last_object():
    def answer(v):
        return Probe(404, "") if v == "42" else Probe(200, '{"id":"' + v + '"}')
    sender = _Recording(answer)
    verdict = AccessControlIdorStrategy(_ANON).confirm(_cand("41"), sender)
    assert verdict is not None and verdict.evidence["value_b"] == "40"


def test_a_page_that_changes_on_every_load_never_confirms():
    """PA-0117(2): the captured id's own answer must replicate; a body with a fresh
    nonce per load is no id-keyed differential."""
    import itertools
    counter = itertools.count()
    sender = _Recording(lambda v: Probe(200, f"<p>id {v}</p><i>{next(counter)}</i>"))
    assert AccessControlIdorStrategy(_ANON).confirm(_cand("41"), sender) is None


def test_an_empty_or_missing_neighbour_never_confirms():
    for body in ("null", "{}", "[]", "Item 42 does not exist", "No such record"):
        sender = _Recording(lambda v, body=body: Probe(200, '{"id":"41"}') if v == "41"
                            else Probe(200, body))
        assert AccessControlIdorStrategy(_ANON).confirm(_cand("41"), sender) is None, body


def test_a_zero_padded_id_keeps_its_width():
    assert AccessControlIdorStrategy.neighbours("0099") == ["0100", "0098"]
    assert AccessControlIdorStrategy.neighbours("0") == ["1"]


def test_no_fixed_synthetic_id_remains():
    """BUG-0734: the former `_ID_A`/`_ID_B` constants are gone."""
    assert not hasattr(AccessControlIdorStrategy, "_ID_A")
    assert not hasattr(AccessControlIdorStrategy, "_ID_B")
