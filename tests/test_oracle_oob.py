"""Tests for the M8 out-of-band callback mechanism: the loopback listener
(`fuzzlab.oracle.oob.OobListener`) and the strategy that uses it
(`CommandInjectionOobStrategy`). Exercises the real listener (a real socket,
real HTTP requests) rather than a fake of it, per PA-0005 (a real code path
needs at least one test on the real implementation)."""

from __future__ import annotations

import urllib.request

import pytest

from fuzzlab.oracle import Candidate
from fuzzlab.oracle.oob import OobListener
from fuzzlab.oracle.probe import Probe
from fuzzlab.oracle.strategies import (
    CommandInjectionOobStrategy,
    SsrfInBandMarkerStrategy,
    SsrfOobStrategy,
)


def _cand():
    return Candidate(url="http://h/ping", param="host", vuln_class="command-injection",
                     category="command-injection")


# --- OobListener: the real loopback service ----------------------------------

def test_listener_refuses_non_loopback_host():
    with pytest.raises(ValueError):
        OobListener(host="0.0.0.0")


def test_listener_records_a_real_http_hit():
    listener = OobListener()
    listener.start()
    try:
        token = listener.register()
        url = listener.callback_url(token)
        assert url.startswith("http://127.0.0.1:")
        # Simulate the target performing the out-of-band request.
        with urllib.request.urlopen(url, timeout=2) as resp:
            assert resp.status == 200
        hit = listener.wait_for(token, timeout=2.0)
        assert hit is not None
        assert hit.token == token
        assert f"/cb/{token}" in hit.path
        assert hit.remote_addr in ("127.0.0.1", "::1")
    finally:
        listener.stop()


def test_listener_wait_for_times_out_without_a_hit():
    listener = OobListener()
    listener.start()
    try:
        token = listener.register()
        listener.callback_url(token)  # minted, but nothing ever requests it
        assert listener.wait_for(token, timeout=0.2, poll=0.02) is None
    finally:
        listener.stop()


def test_listener_does_not_cross_wire_tokens():
    listener = OobListener()
    listener.start()
    try:
        token_a = listener.register()
        token_b = listener.register()
        with urllib.request.urlopen(listener.callback_url(token_a), timeout=2):
            pass
        assert listener.wait_for(token_a, timeout=2.0) is not None
        assert listener.wait_for(token_b, timeout=0.2, poll=0.02) is None
    finally:
        listener.stop()


def test_callback_url_requires_start():
    listener = OobListener()
    with pytest.raises(RuntimeError):
        listener.callback_url("deadbeef")


# --- CommandInjectionOobStrategy (M8) -----------------------------------------

class _VulnerableSender:
    """Simulates a target whose shell actually fetches the embedded canary URL."""

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        for token_url in _extract_urls(value):
            try:
                urllib.request.urlopen(token_url, timeout=2)
            except OSError:
                pass
        return Probe(200, "ok")


class _SecureSender:
    """Simulates a target that never executes the injected shell fragment."""

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        return Probe(200, "ok")


def _extract_urls(value: str) -> list[str]:
    import re
    return re.findall(r"https?://[^\s`)]+", value)


def test_oob_strategy_confirms_when_target_fetches_the_canary():
    listener = OobListener()
    listener.start()
    try:
        strategy = CommandInjectionOobStrategy(listener, timeout=2.0)
        verdict = strategy.confirm(_cand(), _VulnerableSender())
        assert verdict is not None and verdict.confirmed
        assert verdict.vuln_class == "command-injection"
        assert verdict.mechanism == "oob-callback"
        assert "canary" in verdict.evidence
    finally:
        listener.stop()


def test_oob_strategy_fail_closed_when_nothing_calls_back():
    listener = OobListener()
    listener.start()
    try:
        strategy = CommandInjectionOobStrategy(listener, timeout=0.1)
        verdict = strategy.confirm(_cand(), _SecureSender())
        assert verdict is None
    finally:
        listener.stop()


def test_oob_strategy_noops_without_a_listener():
    """Mirrors the M6 BrowserExecutor seam: no injected listener -> no probes sent,
    no network touched, fail-closed immediately."""
    strategy = CommandInjectionOobStrategy(listener=None)

    class _ExplodingSender:
        def send(self, *a, **k):
            raise AssertionError("must not send any probe without a listener")

    assert strategy.confirm(_cand(), _ExplodingSender()) is None


def test_oob_strategy_registered_in_default_strategies():
    from fuzzlab.oracle.strategies import default_strategies
    strategies = default_strategies()
    assert any(isinstance(s, CommandInjectionOobStrategy) for s in strategies)


def test_oracle_confirm_uses_oob_mechanism_end_to_end():
    """Full Oracle.confirm() pipeline wiring (not just the strategy in isolation)."""
    from fuzzlab.oracle.oracle import Oracle
    listener = OobListener()
    listener.start()
    try:
        oracle = Oracle(oob=listener)
        verdict = oracle.confirm(_cand(), _VulnerableSender())
        assert verdict is not None and verdict.mechanism == "oob-callback"
    finally:
        listener.stop()


# --- SsrfInBandMarkerStrategy / SsrfOobStrategy (CC-FUZZ-0027) ---------------

def _ssrf_cand():
    return Candidate(url="http://h/thumb", param="url", vuln_class="ssrf",
                     category="ssrf")


class _SsrfEchoingSender:
    """Simulates an SSRF sink that fetches the given URL and echoes the
    response body back (this project's own `unchecked_url_fetch` shape:
    `io.Copy(w, resp.Body)`)."""

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        try:
            with urllib.request.urlopen(value, timeout=2) as resp:
                return Probe(200, resp.read().decode("ascii", "replace"))
        except OSError:
            return Probe(502, "")


class _SsrfBlindFetchingSender:
    """Simulates an SSRF sink that fetches the URL but never echoes the
    body back (e.g. only status/side effects observable) -- only an OOB
    hit, not the in-band marker, can confirm this one."""

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        try:
            urllib.request.urlopen(value, timeout=2)
        except OSError:
            pass
        return Probe(200, "ok")


class _SsrfSecureSender:
    """Simulates a secure twin that never fetches the given URL at all
    (blocked by a scheme/IP allowlist before any request is made)."""

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        return Probe(403, "forbidden")


def test_ssrf_in_band_strategy_confirms_when_the_body_is_echoed_back():
    listener = OobListener()
    listener.start()
    try:
        strategy = SsrfInBandMarkerStrategy(listener)
        verdict = strategy.confirm(_ssrf_cand(), _SsrfEchoingSender())
        assert verdict is not None and verdict.confirmed
        assert verdict.vuln_class == "ssrf"
        assert verdict.mechanism == "in-band-fetch-marker"
        assert "marker" in verdict.evidence
    finally:
        listener.stop()


def test_ssrf_in_band_strategy_does_not_confirm_a_blind_fetch():
    listener = OobListener()
    listener.start()
    try:
        strategy = SsrfInBandMarkerStrategy(listener)
        assert strategy.confirm(_ssrf_cand(), _SsrfBlindFetchingSender()) is None
    finally:
        listener.stop()


def test_ssrf_in_band_strategy_does_not_confirm_the_secure_twin():
    listener = OobListener()
    listener.start()
    try:
        strategy = SsrfInBandMarkerStrategy(listener)
        assert strategy.confirm(_ssrf_cand(), _SsrfSecureSender()) is None
    finally:
        listener.stop()


def test_ssrf_in_band_strategy_noops_without_a_listener():
    strategy = SsrfInBandMarkerStrategy(listener=None)

    class _ExplodingSender:
        def send(self, *a, **k):
            raise AssertionError("must not send any probe without a listener")

    assert strategy.confirm(_ssrf_cand(), _ExplodingSender()) is None


def test_ssrf_oob_strategy_confirms_a_blind_fetch_via_the_callback():
    listener = OobListener()
    listener.start()
    try:
        strategy = SsrfOobStrategy(listener, timeout=2.0)
        verdict = strategy.confirm(_ssrf_cand(), _SsrfBlindFetchingSender())
        assert verdict is not None and verdict.confirmed
        assert verdict.vuln_class == "ssrf"
        assert verdict.mechanism == "oob-fetch-callback"
        assert "canary" in verdict.evidence
    finally:
        listener.stop()


def test_ssrf_oob_strategy_fail_closed_when_the_secure_twin_never_fetches():
    listener = OobListener()
    listener.start()
    try:
        strategy = SsrfOobStrategy(listener, timeout=0.1)
        assert strategy.confirm(_ssrf_cand(), _SsrfSecureSender()) is None
    finally:
        listener.stop()


def test_ssrf_oob_strategy_noops_without_a_listener():
    strategy = SsrfOobStrategy(listener=None)

    class _ExplodingSender:
        def send(self, *a, **k):
            raise AssertionError("must not send any probe without a listener")

    assert strategy.confirm(_ssrf_cand(), _ExplodingSender()) is None


def test_ssrf_strategies_registered_in_default_strategies_cheapest_first():
    from fuzzlab.oracle.strategies import default_strategies
    strategies = default_strategies()
    kinds = [type(s) for s in strategies]
    assert SsrfInBandMarkerStrategy in kinds and SsrfOobStrategy in kinds
    # Cheapest-first, matching every other category's own stacking order.
    assert kinds.index(SsrfInBandMarkerStrategy) < kinds.index(SsrfOobStrategy)
