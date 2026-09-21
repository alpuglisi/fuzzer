"""Phase 8 T8.4: bandit-scheduled, coverage-guided mutation search."""

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
