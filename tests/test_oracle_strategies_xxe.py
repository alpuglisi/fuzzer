"""XxeInBandMarkerStrategy / XxeOobStrategy (CC-FUZZ-0031/FR-FUZZ-18): the
project's first real audit-rule/oracle-strategy pair for `xxe` (CWE-611).
Mirrors `test_oracle_oob.py`'s own SSRF strategy tests (the same in-band/OOB
pairing, reused for XML entity resolution instead of a raw URL param).
"""

from __future__ import annotations

from fuzzlab.audit.rules import load_rules, matches
from fuzzlab.oracle.oob import OobListener
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import XxeInBandMarkerStrategy, XxeOobStrategy


def _cand():
    return Candidate(url="http://h/issues/import", param="body", method="POST",
                     location="body", vuln_class="xxe", category="xxe")


class _XxeVulnerableSender:
    """Simulates the vulnerable twin (plain `DocumentBuilderFactory`, no
    hardening): resolves the external entity for real and echoes its
    fetched content back in the response -- this project's own real,
    empirically-verified `xml_external_entities_enabled.java.j2` shape."""

    def __init__(self):
        self.sent = []

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        import urllib.request
        self.sent.append(value)
        start = value.index('SYSTEM "') + len('SYSTEM "')
        entity_url = value[start:value.index('"', start)]
        try:
            with urllib.request.urlopen(entity_url, timeout=2) as resp:
                text = resp.read().decode("ascii", "replace")
        except OSError:
            return Probe(502, "")
        return Probe(200, f"Imported issue title: {text}")


class _XxeBlindFetchingSender:
    """Simulates a vulnerable twin that resolves the entity (a real fetch
    happens) but never reflects its content back -- only an OOB hit, not
    the in-band marker, can confirm this one."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        import urllib.request
        start = value.index('SYSTEM "') + len('SYSTEM "')
        entity_url = value[start:value.index('"', start)]
        try:
            urllib.request.urlopen(entity_url, timeout=2)
        except OSError:
            pass
        return Probe(200, "ok")


class _XxeSecureSender:
    """Simulates the secure twin (`disallow-doctype-decl`): rejects the
    DOCTYPE outright, before any entity is ever touched."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        return Probe(400, 'Import error: DOCTYPE is disallowed when the feature '
                          '"http://apache.org/xml/features/disallow-doctype-decl" set to true.')


def test_in_band_strategy_confirms_when_the_entity_content_is_echoed_back():
    listener = OobListener()
    listener.start()
    try:
        strategy = XxeInBandMarkerStrategy(listener)
        verdict = strategy.confirm(_cand(), _XxeVulnerableSender())
        assert verdict is not None and verdict.confirmed
        assert verdict.vuln_class == "xxe"
        assert verdict.mechanism == "in-band-external-entity-marker"
        assert "marker" in verdict.evidence and "wrapper" in verdict.evidence
    finally:
        listener.stop()


def test_in_band_strategy_sends_raw_xml_body_not_form_encoded():
    listener = OobListener()
    listener.start()
    try:
        strategy = XxeInBandMarkerStrategy(listener)
        sender = _XxeVulnerableSender()
        strategy.confirm(_cand(), sender)
        assert sender.sent and sender.sent[0].startswith("<?xml")
    finally:
        listener.stop()


def test_in_band_strategy_does_not_confirm_a_blind_fetch():
    listener = OobListener()
    listener.start()
    try:
        strategy = XxeInBandMarkerStrategy(listener)
        assert strategy.confirm(_cand(), _XxeBlindFetchingSender()) is None
    finally:
        listener.stop()


def test_in_band_strategy_does_not_confirm_the_secure_twin():
    listener = OobListener()
    listener.start()
    try:
        strategy = XxeInBandMarkerStrategy(listener)
        assert strategy.confirm(_cand(), _XxeSecureSender()) is None
    finally:
        listener.stop()


def test_in_band_strategy_noops_without_a_listener():
    strategy = XxeInBandMarkerStrategy(listener=None)

    class _ExplodingSender:
        def send(self, *a, **k):
            raise AssertionError("must not send any probe without a listener")

    assert strategy.confirm(_cand(), _ExplodingSender()) is None


def test_oob_strategy_confirms_a_blind_fetch_via_the_callback():
    listener = OobListener()
    listener.start()
    try:
        strategy = XxeOobStrategy(listener, timeout=2.0)
        verdict = strategy.confirm(_cand(), _XxeBlindFetchingSender())
        assert verdict is not None and verdict.confirmed
        assert verdict.vuln_class == "xxe"
        assert verdict.mechanism == "oob-external-entity-fetch"
        assert "canary" in verdict.evidence
    finally:
        listener.stop()


def test_oob_strategy_fail_closed_when_the_secure_twin_never_fetches():
    listener = OobListener()
    listener.start()
    try:
        strategy = XxeOobStrategy(listener, timeout=0.1)
        assert strategy.confirm(_cand(), _XxeSecureSender()) is None
    finally:
        listener.stop()


def test_oob_strategy_noops_without_a_listener():
    strategy = XxeOobStrategy(listener=None)

    class _ExplodingSender:
        def send(self, *a, **k):
            raise AssertionError("must not send any probe without a listener")

    assert strategy.confirm(_cand(), _ExplodingSender()) is None


def test_xxe_strategies_registered_in_default_strategies_cheapest_first():
    from fuzzlab.oracle.strategies import default_strategies
    strategies = default_strategies()
    kinds = [type(s) for s in strategies]
    assert XxeInBandMarkerStrategy in kinds and XxeOobStrategy in kinds
    assert kinds.index(XxeInBandMarkerStrategy) < kinds.index(XxeOobStrategy)


def test_entity_value_is_always_the_injected_listeners_own_callback_url():
    # Safety-scope pin (per the strategy's own docstring): never a file://
    # or other non-canary URI, only OobListener's own minted callback.
    listener = OobListener()
    listener.start()
    try:
        strategy = XxeInBandMarkerStrategy(listener)
        sender = _XxeVulnerableSender()
        strategy.confirm(_cand(), sender)
        for payload in sender.sent:
            start = payload.index('SYSTEM "') + len('SYSTEM "')
            entity_url = payload[start:payload.index('"', start)]
            assert entity_url.startswith("http://127.0.0.1:")
    finally:
        listener.stop()


def test_r_xxe_rule_matches_a_body_xml_point():
    class _Point:
        location = "body"
        method = "POST"
        param = "body"
        sink_context = "xml"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-XXE")
    assert matches(rule, _Point())


def test_r_xxe_rule_does_not_match_an_unrelated_sink_context():
    class _Point:
        location = "body"
        method = "POST"
        param = "body"
        sink_context = "deserialization"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-XXE")
    assert not matches(rule, _Point())
