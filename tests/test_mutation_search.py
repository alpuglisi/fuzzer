"""Phase 8 T8.4: bandit-scheduled, coverage-guided mutation search."""

from fuzzlab.core.store import MetricLogger, Store
from fuzzlab.mutation.filtermodel import FilterModel
from fuzzlab.mutation.search import MutationSearch, _reward

SQLI = "1 union select password from users"


def _cov(payload):
    """Fake grey-box coverage: some surface forms 'reach more code'."""
    lines = {1, 2}
    if "/**/" in payload:
        lines |= {10, 11, 12}
    if "%09" in payload or "%0a" in payload:
        lines |= {20, 21}
    return {"app.php": lines}


def test_reward_zero_when_meaning_changes():
    assert _reward(evaded=True, preserving=False, novel=5) == 0.0   # useless
    assert _reward(evaded=True, preserving=True, novel=0) == 0.6
    assert _reward(evaded=False, preserving=True, novel=3) == 0.4


def test_pure_evasion_finds_preserving_bypass():
    fm = FilterModel.from_lab()
    res = MutationSearch(fm, seed=1, budget=30).search(SQLI, "sql-injection")
    assert res.evaded is True and res.semantics_ok is True
    assert fm.caught(res.variant) is False            # actually evades the filter
    assert res.operators and res.steps <= 30


def test_coverage_guided_accumulates_novelty_and_evades():
    fm = FilterModel.from_lab()
    s = MutationSearch(fm, seed=1, budget=40, coverage_fn=_cov)
    res = s.search(SQLI, "sql-injection")
    assert res.evaded and res.semantics_ok
    assert s.frontier.size > 2                         # reached lines beyond the base {1,2}


def test_search_is_deterministic_under_seed():
    fm = FilterModel.from_lab()
    a = MutationSearch(fm, seed=7, budget=25).search(SQLI)
    b = MutationSearch(fm, seed=7, budget=25).search(SQLI)
    assert (a.variant, a.operators) == (b.variant, b.operators)


def test_budget_is_bounded():
    fm = FilterModel.from_lab()
    res = MutationSearch(fm, seed=3, budget=3, coverage_fn=_cov).search(SQLI)
    assert res.steps <= 3


def test_bandit_is_actually_updated():
    fm = FilterModel.from_lab()
    s = MutationSearch(fm, seed=1, budget=30, coverage_fn=_cov)
    s.search(SQLI, "sql-injection")
    from fuzzlab.mutation.operators import default_operators
    arms = [op.id for op in default_operators("sql-injection")]
    means = [s.scheduler.mean("sql-injection", a) for a in arms]
    assert any(abs(m - 0.5) > 1e-9 for m in means)    # posteriors moved off the prior


def test_returns_best_even_when_base_uncaught():
    fm = FilterModel.from_lab()
    res = MutationSearch(fm, seed=1, budget=10).search("golden retriever fort")
    assert res.evaded is True and res.semantics_ok is True   # already passes


# --- B0 emitter: MutationSearch reward/novelty -> metric_series (CC-MUT-0011) ----

def test_search_emits_no_metrics_without_a_logger():
    """Additive: omitting metric_logger changes nothing about search behavior."""
    fm = FilterModel.from_lab()
    res = MutationSearch(fm, seed=1, budget=10).search(SQLI, "sql-injection")
    assert res.evaded is True and res.semantics_ok is True


def test_search_logs_reward_and_novelty_per_step(tmp_path):
    fm = FilterModel.from_lab()
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("mutate-test", "cfg")
        with MetricLogger(store, run_id, source="mutation", flush_every=200) as ml:
            res = MutationSearch(fm, seed=1, budget=30, coverage_fn=_cov,
                                 metric_logger=ml).search(SQLI, "sql-injection")
        rows = store.conn.execute(
            "SELECT source, key, step, value FROM metric_series "
            "WHERE run_id=? ORDER BY key, step", (run_id,)).fetchall()

    keys = {r["key"] for r in rows}
    assert keys == {"reward", "novelty"}
    assert all(r["source"] == "mutation" for r in rows)
    reward_steps = [r["step"] for r in rows if r["key"] == "reward"]
    novelty_steps = [r["step"] for r in rows if r["key"] == "novelty"]
    # one (reward, novelty) row pair per step that actually tried a variant (a step
    # whose chosen arm produced no variants logs nothing, by design)
    assert reward_steps                                    # some steps did log
    assert all(1 <= s <= 30 for s in reward_steps)
    assert reward_steps == sorted(reward_steps)            # monotonic step numbering
    assert novelty_steps == reward_steps
    # the search did find a preserving bypass, so some reward row should be > 0
    assert any(r["value"] > 0 for r in rows if r["key"] == "reward")


def test_search_metric_emission_does_not_change_result(tmp_path):
    """Emitting metrics is a pure side-channel: identical seed => identical result
    whether or not a metric_logger is attached."""
    fm_a = FilterModel.from_lab()
    fm_b = FilterModel.from_lab()
    without = MutationSearch(fm_a, seed=7, budget=25).search(SQLI)
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("mutate-test", "cfg")
        with MetricLogger(store, run_id, source="mutation") as ml:
            withlog = MutationSearch(fm_b, seed=7, budget=25,
                                     metric_logger=ml).search(SQLI)
    assert (without.variant, without.operators) == (withlog.variant, withlog.operators)


def test_metric_logger_shared_across_bases_in_run_mutation(tmp_path):
    """run_mutation() (fuzzlab.mutation.run) wires a MetricLogger through to every
    base's MutationSearch, all under one run_id/source."""
    from fuzzlab.mutation import run as mrun

    class _FakeSender:
        """Every request is 'caught' unless the payload contains 'safe'."""
        def send(self, url, param, payload, method="GET", location="query"):
            from fuzzlab.oracle.probe import Probe
            blocked = "safe" not in payload
            return Probe(status=403 if blocked else 200, text="")

    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("mutate-test", "cfg")
        mrun.run_mutation(
            url="http://127.0.0.1/x", param="q", store=store, run_id=run_id,
            sender=_FakeSender(), bases=["1 union select 1"],
            vuln_class="sql-injection", seed=1, budget=5)
        rows = store.conn.execute(
            "SELECT DISTINCT source FROM metric_series WHERE run_id=?",
            (run_id,)).fetchall()
    assert [r["source"] for r in rows] == ["mutation"]
