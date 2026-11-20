"""PA-0650(1) / FR-FUZZ-653: the M6 sentinel wait ends only on the hit, its deadline or a
Playwright error -- never on a prediction that nothing more can run (BUG-0650).

Deterministic: a fake page whose ``wait_for_timeout`` advances a fake clock, so the
whole window is checked in polls, not seconds (SP-21). The real-browser cases are
`tests/test_m6_slow_sinks.py`."""

from __future__ import annotations

import pytest

from fuzzlab.tools import browserexec
from fuzzlab.tools.browserexec import PlaywrightBrowserExecutor


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class _QuietPage:
    """A page on which nothing ever happens after ``load``."""

    def __init__(self, clock):
        self.clock = clock
        self.polls = 0

    def wait_for_timeout(self, ms):
        self.polls += 1
        self.clock.now += ms / 1000


def window_kept(executor_cls, monkeypatch) -> bool:
    """Whether ``executor_cls``'s wait, with ``load`` fired and no hit, lasts its whole
    `SETTLE_MS` from ``load``."""
    clock = _Clock()
    monkeypatch.setattr(browserexec.time, "monotonic", clock)
    executor = executor_cls()
    page = _QuietPage(clock)
    load_at = [clock()]
    fired = executor._wait_for_token(page, set(), "tok", RuntimeError, load_at,
                                     cap=clock() + 60)
    return fired is False and clock() - load_at[0] >= executor.SETTLE_MS / 1000


def test_the_wait_lasts_its_whole_window_without_a_hit(monkeypatch):
    assert window_kept(PlaywrightBrowserExecutor, monkeypatch)


def test_a_hit_still_ends_the_wait_at_once(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(browserexec.time, "monotonic", clock)
    page = _QuietPage(clock)
    assert PlaywrightBrowserExecutor()._wait_for_token(
        page, {"tok"}, "tok", RuntimeError, [clock()], cap=clock() + 60) is True
    assert page.polls == 0


def test_the_guard_catches_an_early_end(monkeypatch):
    """A synthetic offender: a wait that stops after 500 ms of a quiet page (BUG-0650's
    shape) fails the guard."""

    class EarlyEnd(PlaywrightBrowserExecutor):
        def _wait_for_token(self, page, hits, token, error, load_at=None, cap=None):
            start = browserexec.time.monotonic()
            while token not in hits and browserexec.time.monotonic() - start < 0.5:
                page.wait_for_timeout(self._POLL_MS)
            return token in hits

    assert not window_kept(EarlyEnd, monkeypatch)


def test_the_wait_takes_no_early_end_hook():
    """The wait's signature has no hook through which a quiet predicate could end it."""
    import inspect
    params = list(inspect.signature(PlaywrightBrowserExecutor._wait_for_token).parameters)
    assert params == ["self", "page", "hits", "token", "error", "load_at", "cap"]


@pytest.mark.parametrize("name", ["pagequiet", "PageQuiet", "EARLY_END", "settled("])
def test_no_quiet_predicate_is_back_in_the_executor(name):
    import inspect
    assert name not in inspect.getsource(browserexec)
