"""PA-0630 (BUG-0630): in a timing differential every mutation is the baseline's own
value plus the part under test, so whatever the baseline value makes the application do
(VulnerableApp runs `ping -c 2 <value>`: ~1 s) is in both sides and the added latency is
the payload's alone. Enforced by discovery over every default strategy that runs the
shared timing engine (`ConfirmationStrategy._confirm_timing`), proven on a synthetic
offender (PA-0034(2))."""

from __future__ import annotations

import inspect

import pytest

from fuzzlab.oracle import strategies as S
from fuzzlab.oracle.probe import Candidate, Probe


class _Recorder:
    """A constant-latency application: nothing confirms, every value sent is kept."""

    def __init__(self):
        self.sent: list[str] = []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None):
        self.sent.append(value)
        return Probe(200, "ok", elapsed=0.05, headers={})


def _timing_strategies(strategies):
    return [s for s in strategies
            if "_confirm_timing" in inspect.getsource(type(s).confirm)]


def _offences(strategy, candidate) -> list[str]:
    rec = _Recorder()
    strategy.confirm(candidate, rec)
    n = getattr(strategy, "baseline_samples", 3)
    baseline, mutations = rec.sent[:n], rec.sent[n:]
    assert len(set(baseline)) == 1, baseline
    return [m for m in mutations if not m.startswith(baseline[0])]


def _candidates(strategy):
    yield Candidate(url="http://h/x", param="p", category=strategy.category)
    yield Candidate(url="http://h/x", param="p", category=strategy.category,
                    base_value="127.0.0.1")


def test_the_discovery_finds_the_timing_strategies():
    names = {type(s).__name__ for s in _timing_strategies(S.default_strategies())}
    assert {"SqliTimingStrategy", "CommandInjectionStrategy"} <= names


@pytest.mark.parametrize("strategy", _timing_strategies(S.default_strategies()),
                         ids=lambda s: type(s).__name__)
def test_every_timing_mutation_carries_the_baselines_value(strategy):
    for candidate in _candidates(strategy):
        assert _offences(strategy, candidate) == [], (type(strategy).__name__, candidate)


def test_the_guard_flags_a_payload_that_drops_the_baseline_value():
    """The pre-fix command-injection shape: bare templates against a `1` baseline."""
    class Offender(S.ConfirmationStrategy):
        vuln_class, mechanism, category = "command-injection", "t", "command-injection"

        def confirm(self, candidate, sender):
            return self._confirm_timing(candidate, sender, ["$(sleep {d})", "; sleep {d}"])
    assert _timing_strategies([Offender()])
    assert _offences(Offender(), Candidate(url="http://h/x", param="p")) == \
        ["$(sleep 2)", "; sleep 2"]
