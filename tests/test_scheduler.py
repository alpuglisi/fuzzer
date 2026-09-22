"""Tests for the Phase 4 payload scheduler (Thompson bandit + uniform control)."""

import random

from fuzzlab.core.store import MetricLogger, Store
from fuzzlab.scheduler import Beta, ThompsonBandit, UniformScheduler


def test_beta_update_and_mean():
    b = Beta()
    assert b.mean == 0.5
    b.update(1.0)                          # a hit
    b.update(0.0)                          # a miss
    assert b.alpha == 2.0 and b.beta == 2.0 and b.mean == 0.5
    b.update(0.25)                         # fractional reward splits the trial
    assert b.alpha == 2.25 and b.beta == 2.75
    b.update(5.0)                          # clamped to 1.0
    assert b.alpha == 3.25


def test_bandit_learns_and_best_arm_tracks_reward():
    bandit = ThompsonBandit(rng=random.Random(1))
    for _ in range(20):
        bandit.update("ctx", "good", 1.0)
        bandit.update("ctx", "bad", 0.0)
    assert bandit.mean("ctx", "good") > bandit.mean("ctx", "bad")
    assert bandit.best_arm("ctx", ["good", "bad"]) == "good"


def test_priors_seed_unseen_arms():
    bandit = ThompsonBandit(priors={"known": (9.0, 1.0)})
    assert bandit.mean("ctx", "known") == 0.9      # catalog prior applied
    assert bandit.mean("ctx", "fresh") == 0.5      # default uniform prior


def test_select_is_deterministic_with_a_seed_and_returns_an_arm():
    arms = ["a", "b", "c"]
    picks1 = [ThompsonBandit(rng=random.Random(7)).select("ctx", arms) for _ in range(1)]
    picks2 = [ThompsonBandit(rng=random.Random(7)).select("ctx", arms) for _ in range(1)]
    assert picks1 == picks2 and picks1[0] in arms


def test_bandit_beats_uniform_on_hits(tmp_path):
    # Environment: arm 'c' pays off far more often than 'a'/'b'.
    probs = {"a": 0.1, "b": 0.1, "c": 0.9}
    arms = list(probs)
    env = random.Random(2024)

    def reward(arm):
        return 1.0 if env.random() < probs[arm] else 0.0

    bandit = ThompsonBandit(rng=random.Random(1))
    uniform = UniformScheduler(rng=random.Random(1))
    bandit_hits = uniform_hits = 0
    for _ in range(400):
        a = bandit.select("ctx", arms)
        r = reward(a)
        bandit.update("ctx", a, r)
        bandit_hits += r
        u = uniform.select("ctx", arms)
        uniform_hits += reward(u)

    assert bandit.best_arm("ctx", arms) == "c"     # it found the good arm
    assert bandit_hits > uniform_hits              # and beat the control on hits


def test_posteriors_persist_across_stores(tmp_path):
    path = tmp_path / "b.db"
    with Store(path) as store:
        b = ThompsonBandit()
        for _ in range(5):
            b.update("sqli:query", "time-based", 1.0)
        b.update("sqli:query", "union", 0.0)
        b.save(store)
    # A fresh bandit loads the learned posteriors from the store.
    with Store(path) as store:
        b2 = ThompsonBandit().load(store)
        assert b2.mean("sqli:query", "time-based") > b2.mean("sqli:query", "union")
        # A second save upserts (no duplicate rows) on the UNIQUE(context, arm).
        b2.save(store)
        n = store.conn.execute(
            "SELECT COUNT(*) c FROM bandit_posteriors "
            "WHERE context='sqli:query'").fetchone()["c"]
        assert n == 2


def test_bandit_order_puts_learned_arm_first():
    bandit = ThompsonBandit(rng=random.Random(0))
    for _ in range(40):
        bandit.update("ctx", "win", 1.0)
        bandit.update("ctx", "lose", 0.0)
    order = bandit.order("ctx", ["lose", "win"])
    assert order[0] == "win" and set(order) == {"lose", "win"}


def test_uniform_order_is_a_permutation():
    order = UniformScheduler(rng=random.Random(0)).order("ctx", ["a", "b", "c"])
    assert sorted(order) == ["a", "b", "c"]


def test_cost_normalized_prefers_the_cheaper_arm(tmp_path):
    b = ThompsonBandit(rng=random.Random(0), cost_normalized=True)
    for _ in range(30):
        b.update("ctx", "cheap", 1.0, cost=2)      # equal reward...
        b.update("ctx", "dear", 1.0, cost=20)      # ...10x the cost
    assert b.order("ctx", ["dear", "cheap"])[0] == "cheap"
    assert b.cost_mean("ctx", "dear") > b.cost_mean("ctx", "cheap")


def test_cost_persists_across_stores(tmp_path):
    path = tmp_path / "c.db"
    with Store(path) as store:
        b = ThompsonBandit()
        b.update("ctx", "a", 1.0, cost=7)
        b.save(store)
    with Store(path) as store:
        b2 = ThompsonBandit().load(store)
        assert b2.cost_mean("ctx", "a") == 7.0


def test_backoff_inherits_parent_strength():
    backoff = ThompsonBandit(backoff=True)
    for _ in range(10):
        backoff.update("sql-injection", "x", 1.0)          # parent learns x is good
    child = backoff.mean("sql-injection:html", "x")        # fresh child inherits it

    flat = ThompsonBandit(backoff=False)
    for _ in range(10):
        flat.update("sql-injection", "x", 1.0)
    assert flat.mean("sql-injection:html", "x") == 0.5     # no inheritance
    assert child > 0.5 and child > flat.mean("sql-injection:html", "x")


def test_uniform_selects_from_arms_and_ignores_feedback():
    u = UniformScheduler(rng=random.Random(3))
    picks = {u.select("ctx", ["a", "b"]) for _ in range(20)}
    assert picks <= {"a", "b"} and picks                      # only valid arms
    u.update("ctx", "a", 1.0)                                 # no-op, no crash


# --- per-pull metric emission (CC-SCHED-0005, R-05) ------------------------

def test_update_with_no_metrics_attached_is_unchanged():
    # Default behavior (no attach_metrics call): update() works exactly as before.
    b = ThompsonBandit(rng=random.Random(0))
    b.update("ctx", "a", 1.0)
    b.flush_metrics()                       # no-op, does not raise with nothing attached
    assert b.mean("ctx", "a") == 2.0 / 3.0


def test_attach_metrics_emits_regret_and_posterior_rows(tmp_path):
    with Store(tmp_path / "m.db") as store:
        run_id = store.start_run("test", "cfg")
        bandit = ThompsonBandit(rng=random.Random(0))
        bandit.attach_metrics(MetricLogger(store, run_id, "bandit", flush_every=200))

        bandit.update("ctx", "good", 1.0)
        bandit.update("ctx", "bad", 0.0)
        bandit.update("ctx", "good", 1.0)
        bandit.flush_metrics()

        rows = store.conn.execute(
            "SELECT source, key, step, value FROM metric_series "
            "WHERE run_id=? ORDER BY key, step", (run_id,)).fetchall()

    keys = {r["key"] for r in rows}
    assert all(r["source"] == "bandit" for r in rows)
    assert "regret/cumulative" in keys
    # One arm_<N> series per distinct arm played, first-seen order (good=0, bad=1).
    assert "posterior/arm_0/mean" in keys
    assert "posterior/arm_1/mean" in keys

    regret_rows = [r for r in rows if r["key"] == "regret/cumulative"]
    assert [r["step"] for r in regret_rows] == [1, 2, 3]
    # Cumulative regret is non-decreasing (each pull adds a non-negative term).
    values = [r["value"] for r in regret_rows]
    assert values == sorted(values)

    good_rows = [r for r in rows if r["key"] == "posterior/arm_0/mean"]
    # Two pulls of "good" recorded (steps 1 and 3); posterior mean rises with reward.
    assert [r["step"] for r in good_rows] == [1, 3]
    assert good_rows[1]["value"] > good_rows[0]["value"]


def test_attach_metrics_does_not_change_selection_or_posteriors():
    # Emission is observational-only: same seed => same posteriors/selections with
    # or without a logger attached.
    plain = ThompsonBandit(rng=random.Random(7))
    for _ in range(10):
        plain.update("ctx", "a", 1.0)
        plain.update("ctx", "b", 0.0)

    with_metrics = ThompsonBandit(rng=random.Random(7))
    with_metrics.attach_metrics(_fake_logger())
    for _ in range(10):
        with_metrics.update("ctx", "a", 1.0)
        with_metrics.update("ctx", "b", 0.0)

    assert plain.mean("ctx", "a") == with_metrics.mean("ctx", "a")
    assert plain.mean("ctx", "b") == with_metrics.mean("ctx", "b")
    assert plain.select("ctx", ["a", "b"]) == with_metrics.select("ctx", ["a", "b"])


def _fake_logger():
    """A minimal stand-in with the ``log``/``flush`` surface MetricLogger exposes,
    so this test doesn't need a real Store just to prove emission is side-effect-free
    on the bandit's own state."""
    class _Fake:
        def __init__(self):
            self.rows = []

        def log(self, key, step, value, ts=None):
            self.rows.append((key, step, value))
            return True

        def flush(self):
            pass

    return _Fake()
