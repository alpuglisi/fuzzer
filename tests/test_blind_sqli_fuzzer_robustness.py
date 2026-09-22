"""Robustness coverage for `blind_sqli_fuzzer.py`'s top-level orchestration
(`run_fuzzing_cycle`/`establish_baseline`), which had zero prior test coverage.

The primary fix under test: a `KeyboardInterrupt` mid-`run_fuzzing_cycle` previously
propagated straight out of the function, discarding every already-completed timing
observation (`rows` was a local variable only ever returned at the very end) — real
data loss on a run a user deliberately interrupted, not just an ugly traceback. Fixed
by catching the interrupt inside the loop and returning the partial `rows` collected
so far, so `main()`'s existing `save_dataset(rows, args.output)` call naturally
persists what was gathered instead of losing it.
"""
import argparse

import pytest

from fuzzlab.tools.blind_sqli_fuzzer import (PAYLOADS, establish_baseline,
                                             run_fuzzing_cycle)

_BASELINE = {"avg_time": 0.1, "std_dev_time": 0.02, "avg_size": 100, "samples": 5}


def _args(**overrides):
    defaults = dict(repeats=2, timeout=5, pause=0, sigma=3, min_delay=2)
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class _FakeSender:
    """Returns a fixed, non-malicious-looking response for every call, until
    `raise_after` calls have happened, at which point it raises `to_raise`."""

    def __init__(self, raise_after=None, to_raise=KeyboardInterrupt):
        self.calls = 0
        self.raise_after = raise_after
        self.to_raise = to_raise

    def get(self, url, param, value, timeout):
        self.calls += 1
        if self.raise_after is not None and self.calls > self.raise_after:
            raise self.to_raise()
        return 0.1, 200, 100        # latency, status, size — never "detected"


def test_run_fuzzing_cycle_completes_normally_and_returns_every_row():
    sender = _FakeSender()
    rows = run_fuzzing_cycle(sender, "http://x/p.php", "id", _BASELINE, PAYLOADS, _args())
    assert len(rows) == len(PAYLOADS)
    assert all(r["eval_outcome"] in
              {"true_positive", "false_positive", "false_negative", "true_negative"}
              for r in rows)


def test_keyboard_interrupt_mid_cycle_returns_partial_rows_not_empty():
    # Each payload makes `repeats` (2) calls; interrupt on the 5th call, partway
    # through the 3rd payload — the first two payloads' rows must survive.
    sender = _FakeSender(raise_after=4, to_raise=KeyboardInterrupt)
    rows = run_fuzzing_cycle(sender, "http://x/p.php", "id", _BASELINE, PAYLOADS, _args())
    assert 0 < len(rows) < len(PAYLOADS)


def test_keyboard_interrupt_on_the_very_first_call_returns_no_rows_not_a_crash():
    sender = _FakeSender(raise_after=0, to_raise=KeyboardInterrupt)
    rows = run_fuzzing_cycle(sender, "http://x/p.php", "id", _BASELINE, PAYLOADS, _args())
    assert rows == []


def test_request_exceptions_still_skip_a_payload_without_aborting_the_run():
    import requests

    class FlakyOnceSender(_FakeSender):
        def get(self, url, param, value, timeout):
            self.calls += 1
            if self.calls == 1:
                raise requests.RequestException("boom")
            return 0.1, 200, 100

    sender = FlakyOnceSender()
    rows = run_fuzzing_cycle(sender, "http://x/p.php", "id", _BASELINE, PAYLOADS, _args())
    # the first payload's repeats never complete (no latencies collected -> skipped);
    # every other payload still runs to completion.
    assert len(rows) == len(PAYLOADS) - 1


def test_establish_baseline_raises_a_clear_error_when_target_unreachable():
    import requests

    class AlwaysFailsSender:
        def get(self, url, param, value, timeout):
            raise requests.RequestException("connection refused")

    with pytest.raises(ConnectionError):
        establish_baseline(AlwaysFailsSender(), "http://x/p.php", "id", 3, 5)
