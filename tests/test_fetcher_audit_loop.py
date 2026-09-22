"""Robustness coverage for `fetcher.py`'s top-level audit loop (`run_audit_loop`),
extracted from the previously-untested `__main__` block.

The fix under test: a `KeyboardInterrupt` mid-audit previously propagated straight
out of the `for target, source in targets:` loop in `__main__` — `audit_page`'s own
`except Exception` does not catch `KeyboardInterrupt` (it doesn't inherit from
`Exception`) — skipping `results_db.close()`, `print_summary()`, and the
store-consolidation step, and leaking the results-DB connection. `run_audit_loop`
now catches the interrupt itself and returns normally, so the caller's cleanup
always runs, mirroring `LocalSpider.crawl()`'s equivalent guard in `spider.py`.
"""
from fuzzlab.tools.fetcher import run_audit_loop, setup_results_db


class _FakeFetcher:
    """`.fetch(url)` returns a fixed page, or raises after `raise_after` calls."""

    def __init__(self, raise_after=None, to_raise=KeyboardInterrupt):
        self.calls = 0
        self.raise_after = raise_after
        self.to_raise = to_raise

    def fetch(self, url):
        self.calls += 1
        if self.raise_after is not None and self.calls > self.raise_after:
            raise self.to_raise()
        return 200, "text/html", "<html><body>hi</body></html>", []


def _targets(n):
    return [(f"http://x/page{i}.php", "link") for i in range(n)]


def test_run_audit_loop_visits_every_target_on_a_clean_run(tmp_path):
    db = setup_results_db(str(tmp_path / "r.db"), append=False)
    audited = run_audit_loop(_targets(5), _FakeFetcher(), [], db, set())
    assert audited == 5
    db.close()


def test_keyboard_interrupt_mid_loop_returns_instead_of_raising(tmp_path):
    db = setup_results_db(str(tmp_path / "r.db"), append=False)
    fetcher = _FakeFetcher(raise_after=2, to_raise=KeyboardInterrupt)
    audited = run_audit_loop(_targets(5), fetcher, [], db, set())
    assert audited == 2                    # stopped after the 2nd target succeeded
    # the caller's cleanup (close/summary) is reachable — the connection is still usable
    db.execute("SELECT 1")
    db.close()


def test_keyboard_interrupt_on_the_first_target_returns_zero_not_a_crash(tmp_path):
    db = setup_results_db(str(tmp_path / "r.db"), append=False)
    fetcher = _FakeFetcher(raise_after=0, to_raise=KeyboardInterrupt)
    audited = run_audit_loop(_targets(3), fetcher, [], db, set())
    assert audited == 0
    db.close()


def test_a_single_target_fetch_error_is_handled_by_audit_page_not_the_loop(tmp_path):
    # audit_page's own `except Exception` already handles a per-page fetch failure;
    # the loop must keep going to the remaining targets, same as before this change.
    db = setup_results_db(str(tmp_path / "r.db"), append=False)
    fetcher = _FakeFetcher(raise_after=1, to_raise=ConnectionError)
    audited = run_audit_loop(_targets(3), fetcher, [], db, set())
    assert audited == 3                    # every target still counted as "audited"
    db.close()
