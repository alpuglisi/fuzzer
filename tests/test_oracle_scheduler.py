"""Phase 4 T4.3: the bandit orders the oracle's mechanisms to spend fewer probes."""

import random
import re

from fuzzlab.core.store import Store
from fuzzlab.oracle import Candidate, Oracle
from fuzzlab.oracle.probe import Probe
from fuzzlab.oracle.strategies import default_strategies
from fuzzlab.scheduler import ThompsonBandit, arm_priors

_CTX = "sql-injection:query"
_ARMS = ("sqli:error-signature", "sqli:boolean-differential", "sqli:differential-timing")


def _cand():
    return Candidate(url="http://h/p.php", param="id",
                     category="sql-injection", location="query")


class TimingOnlySender:
    """Confirms SQLi only via timing (rising delay); no error/boolean signal."""
    def __init__(self):
        self.n = 0

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        self.n += 1
        m = re.search(r"SLEEP\((\d+)\)", value, re.I)
        d = int(m.group(1)) if m else 0
        return Probe(200, "ok", elapsed=d + 0.02, headers={})


def _trained_timing_bandit(seed):
    bandit = ThompsonBandit(rng=random.Random(seed), priors=arm_priors(default_strategies()))
    for _ in range(40):
        bandit.update(_CTX, "sqli:differential-timing", 1.0)
        bandit.update(_CTX, "sqli:error-signature", 0.0)
        bandit.update(_CTX, "sqli:boolean-differential", 0.0)
    return bandit


def test_bandit_reaches_timing_with_fewer_probes():
    # Fresh bandit: priors favor error/boolean, so timing is tried last (wasted probes).
    fresh = Oracle(scheduler=ThompsonBandit(rng=random.Random(0),
                                            priors=arm_priors(default_strategies())))
    s_fresh = TimingOnlySender()
    v1 = fresh.confirm(_cand(), s_fresh)

    # Trained bandit: it learned timing confirms here -> tries it first.
    trained = Oracle(scheduler=_trained_timing_bandit(0))
    s_trained = TimingOnlySender()
    v2 = trained.confirm(_cand(), s_trained)

    assert v1 is not None and v2 is not None
    assert v1.mechanism == "differential-timing" and v2.mechanism == "differential-timing"
    assert s_trained.n < s_fresh.n          # front-loading timing skipped error+boolean probes


def test_oracle_updates_the_scheduler():
    bandit = _trained_timing_bandit(1)
    before = bandit.mean(_CTX, "sqli:differential-timing")
    Oracle(scheduler=bandit).confirm(_cand(), TimingOnlySender())
    # The confirming arm's posterior rises; a tried-but-failed arm's does not.
    assert bandit.mean(_CTX, "sqli:differential-timing") > before


def test_no_scheduler_keeps_fixed_order(tmp_path):
    # Without a scheduler the oracle still confirms (cheapest-first, unchanged).
    v = Oracle().confirm(_cand(), TimingOnlySender())
    assert v is not None and v.mechanism == "differential-timing"


# --- B0: bandit posterior/regret emitter ------------------------------------
def test_oracle_emits_bandit_posterior_and_regret_when_store_attached(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "h")
        bandit = _trained_timing_bandit(2)
        Oracle(store=store, run_id=run_id, scheduler=bandit).confirm(
            _cand(), TimingOnlySender())
        rows = store.conn.execute(
            "SELECT source, key, step, value FROM metric_series WHERE run_id=? "
            "ORDER BY step", (run_id,)).fetchall()
        assert rows
        assert {r["source"] for r in rows} == {"bandit"}
        keys = {r["key"] for r in rows}
        assert "regret/cumulative" in keys
        assert any(k.startswith("posterior/") and k.endswith("/mean") for k in keys)
        assert all(r["value"] == r["value"] for r in rows)  # no NaN


def test_oracle_with_scheduler_but_no_store_emits_nothing(tmp_path):
    with Store(tmp_path / "s.db") as store:
        # scheduler attached, but no store/run_id on the Oracle itself
        bandit = _trained_timing_bandit(3)
        Oracle(scheduler=bandit).confirm(_cand(), TimingOnlySender())
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM metric_series").fetchone()["c"] == 0
