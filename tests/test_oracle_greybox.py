"""Tests for the M10 grey-box confirmation mechanism wired into the oracle:
`fuzzlab.oracle.strategies.GreyboxConfirmationStrategy`. Everything here runs
offline with `InMemoryCoverageSource`/`InMemoryDbFaultSource` (real test doubles
of the decision-logic seam, not mocks of this strategy's own code, per PA-0005) and
a fake correlating sender -- the live pcov/DB-fault side channel and a correlating
probe sender that actually attaches the `X-Fzl-Cov` header are on-host last-mile
work (docs/ON_HOST_TASKS.md)."""

from __future__ import annotations

from fuzzlab.greybox.coverage import InMemoryCoverageSource
from fuzzlab.greybox.dbfault import DbFault, InMemoryDbFaultSource
from fuzzlab.oracle import Candidate
from fuzzlab.oracle.probe import Probe
from fuzzlab.oracle.strategies import GreyboxConfirmationStrategy


def _sqli_cand():
    return Candidate(url="http://h/login.php", param="user", vuln_class="sqli",
                     category="sql-injection")


def _xss_cand():
    return Candidate(url="http://h/search.php", param="q", vuln_class="xss-reflected",
                     category="xss")


class _CorrelatingSender:
    """Fake sender exposing both the plain `Sender` interface (so the black-box
    strategies that run before M10 can send their probes and fail to confirm on a
    benign target) and the `send_correlated` contract M10 needs, returning a fixed
    correlation id per call so tests can key their fakes' coverage/db-fault maps."""

    def __init__(self, request_id: str = "req-1"):
        self._request_id = request_id
        self.correlated_calls = []

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        return Probe(200, "ok")           # benign: no SQL error / no XSS marker

    def send_correlated(self, url, param, value, method="GET", location="query"):
        self.correlated_calls.append((url, param, value, method, location))
        return Probe(200, "ok"), self._request_id


class _PlainSender:
    """A sender with no `send_correlated` -- what every non-greybox-aware sender
    (e.g. `RequestsProbeSender`) looks like today."""

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        return Probe(200, "ok")


# --- applies() scoping --------------------------------------------------------

def test_applies_scoped_to_sql_injection_and_xss_only():
    strategy = GreyboxConfirmationStrategy()
    assert strategy.applies(_sqli_cand())
    assert strategy.applies(_xss_cand())
    assert not strategy.applies(Candidate(url="http://h/x", param="p",
                                          category="command-injection"))
    assert not strategy.applies(Candidate(url="http://h/x", param="p", category=None))


# --- fail-closed no-ops --------------------------------------------------------

def test_noops_without_any_source():
    strategy = GreyboxConfirmationStrategy(coverage=None, dbfault=None)
    sender = _CorrelatingSender()
    assert strategy.confirm(_sqli_cand(), sender) is None
    assert sender.correlated_calls == []          # never even tries to correlate


def test_noops_without_a_correlating_sender():
    """Mirrors the M6/M8 seam: sources injected but the sender can't correlate a
    probe to a request id -> no-op, fail-closed, never a guess."""
    coverage = InMemoryCoverageSource({"req-1": {"/var/www/html/login.php": [1]}})
    dbfault = InMemoryDbFaultSource({"req-1": DbFault(True)})
    strategy = GreyboxConfirmationStrategy(coverage, dbfault)
    assert strategy.confirm(_sqli_cand(), _PlainSender()) is None


# --- sqli: needs sink covered AND a db fault -----------------------------------

def test_confirms_sqli_when_sink_covered_and_db_fault():
    coverage = InMemoryCoverageSource({"req-1": {"/var/www/html/login.php": [10, 11]}})
    dbfault = InMemoryDbFaultSource({"req-1": DbFault(True, "syntax error")})
    strategy = GreyboxConfirmationStrategy(coverage, dbfault)
    sender = _CorrelatingSender()

    verdict = strategy.confirm(_sqli_cand(), sender)

    assert verdict is not None and verdict.confirmed
    assert verdict.vuln_class == "sqli"
    assert verdict.mechanism == "grey-box-coverage"
    assert verdict.evidence["mechanism"] == "M10"
    assert verdict.evidence["sink_covered"] is True
    assert verdict.evidence["db_fault"] is True
    assert sender.correlated_calls           # it did send a correlated probe


def test_fails_closed_sqli_sink_covered_without_db_fault():
    coverage = InMemoryCoverageSource({"req-1": {"/var/www/html/login.php": [10]}})
    dbfault = InMemoryDbFaultSource()         # no fault recorded (defaults to False)
    strategy = GreyboxConfirmationStrategy(coverage, dbfault)
    assert strategy.confirm(_sqli_cand(), _CorrelatingSender()) is None


def test_fails_closed_sqli_db_fault_without_sink_covered():
    coverage = InMemoryCoverageSource({"req-1": {"/var/www/html/other.php": [1]}})
    dbfault = InMemoryDbFaultSource({"req-1": DbFault(True)})
    strategy = GreyboxConfirmationStrategy(coverage, dbfault)
    assert strategy.confirm(_sqli_cand(), _CorrelatingSender()) is None


def test_sqli_confirmation_needs_both_sources_not_just_one():
    coverage = InMemoryCoverageSource({"req-1": {"/var/www/html/login.php": [10]}})
    strategy = GreyboxConfirmationStrategy(coverage=coverage, dbfault=None)
    assert strategy.confirm(_sqli_cand(), _CorrelatingSender()) is None


# --- xss: sink covered alone is enough -----------------------------------------

def test_confirms_xss_when_sink_covered_no_dbfault_source_needed():
    coverage = InMemoryCoverageSource({"req-1": {"/var/www/html/search.php": [4]}})
    strategy = GreyboxConfirmationStrategy(coverage=coverage, dbfault=None)

    verdict = strategy.confirm(_xss_cand(), _CorrelatingSender())

    assert verdict is not None and verdict.confirmed
    assert verdict.vuln_class == "xss-reflected"
    assert verdict.mechanism == "grey-box-coverage"


def test_fails_closed_xss_when_sink_not_covered():
    coverage = InMemoryCoverageSource({"req-1": {"/var/www/html/other.php": [4]}})
    strategy = GreyboxConfirmationStrategy(coverage=coverage, dbfault=None)
    assert strategy.confirm(_xss_cand(), _CorrelatingSender()) is None


# --- registration --------------------------------------------------------------

def test_registered_in_default_strategies():
    from fuzzlab.oracle.strategies import default_strategies
    strategies = default_strategies()
    assert any(isinstance(s, GreyboxConfirmationStrategy) for s in strategies)


# --- full Oracle.confirm() pipeline --------------------------------------------

def test_oracle_confirm_uses_greybox_mechanism_end_to_end():
    """Full `Oracle.confirm()` wiring (not just the strategy in isolation): the
    black-box sqli strategies run first on a benign target and abstain, then M10
    confirms from the injected coverage/db-fault sources."""
    from fuzzlab.oracle.oracle import Oracle

    coverage = InMemoryCoverageSource({"req-1": {"/var/www/html/login.php": [10]}})
    dbfault = InMemoryDbFaultSource({"req-1": DbFault(True)})
    oracle = Oracle(coverage=coverage, dbfault=dbfault)

    verdict = oracle.confirm(_sqli_cand(), _CorrelatingSender())

    assert verdict is not None
    assert verdict.mechanism == "grey-box-coverage"
    assert verdict.vuln_class == "sqli"


def test_oracle_confirm_greybox_noop_leaves_candidate_unconfirmed():
    """No coverage/db-fault sources injected -> the run behaves exactly as before
    M10 was wired in (fail-closed, no new confirmations)."""
    from fuzzlab.oracle.oracle import Oracle

    oracle = Oracle()
    verdict = oracle.confirm(_sqli_cand(), _CorrelatingSender())
    assert verdict is None
