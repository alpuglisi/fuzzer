"""Bandit backoff pools pulls into parent contexts (BUG-0088, FR-SCHED-10).

`_seed` backs a cold (context, arm) off to its parent context's posterior, but `update`
only ever wrote the leaf, so no parent existed and `backoff=True` changed nothing.
"""

from __future__ import annotations

import random

from fuzzlab.core.store import Store
from fuzzlab.oracle.oracle import Oracle
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import SqliErrorStrategy
from fuzzlab.scheduler.bandit import ThompsonBandit
from fuzzlab.scheduler.context import is_pooled_context


class _SqlError:
    def send(self, *a, **k):
        return Probe(200, "You have an error in your SQL syntax")


def _trained(backoff: bool) -> ThompsonBandit:
    b = ThompsonBandit(rng=random.Random(0), backoff=backoff, cost_normalized=True)
    o = Oracle(strategies=[SqliErrorStrategy()], scheduler=b)
    for i in range(20):
        o.confirm(Candidate(f"http://127.0.0.1/p{i}", "id", location="query",
                            category="sql-injection"), _SqlError())
    return b


ARM = SqliErrorStrategy().arm


def test_a_cold_sibling_context_backs_off_to_the_pooled_parent():
    b = _trained(backoff=True)
    assert b.mean("sql-injection:query", ARM) > 0.9
    sibling = b.mean("sql-injection:body", ARM)          # cold: seeded from the parent
    assert 0.5 < sibling <= (1 + 2.0) / (2 + 2.0)        # bounded by backoff_strength=2
    assert b.mean("sql-injection", ARM) > 0.9 and b.mean("", ARM) > 0.9


def test_without_backoff_no_parent_is_created_and_nothing_changes():
    b = _trained(backoff=False)
    assert {c for c, _a in b._post} == {"sql-injection:query"}
    assert b.mean("sql-injection:body", ARM) == 0.5


def test_parents_count_pulls_but_no_cost_and_survive_save_load(tmp_path):
    b = _trained(backoff=True)
    with Store(tmp_path / "s.db") as store:
        b.save(store)
        rows = {r["context"]: r for r in store.conn.execute(
            "SELECT context, cost_sum, cost_n FROM bandit_posteriors WHERE arm=?", (ARM,))}
        assert rows["sql-injection:query"]["cost_n"] == 20
        assert rows["sql-injection"]["cost_n"] == rows[""]["cost_n"] == 20
        assert rows["sql-injection"]["cost_sum"] == rows[""]["cost_sum"] == 0
        again = ThompsonBandit(backoff=True).load(store)
        assert again.mean("sql-injection", ARM) == b.mean("sql-injection", ARM)


def test_pooled_contexts_are_the_parents():
    assert is_pooled_context("") and is_pooled_context("sql-injection")
    assert not is_pooled_context("sql-injection:query")


def test_the_panels_label_pooled_rows(tmp_path):
    from fuzzlab.web import diagnostics as diag
    from fuzzlab.web import mlview
    b = _trained(backoff=True)
    with Store(tmp_path / "s.db") as store:
        b.save(store)
        arms = {a["context"]: a for a in mlview.bandit_panel(store)["arms"]
                if a["arm"] == ARM}
        diag_rows = {a["context"]: a for a in diag.bandit_arms(store) if a["arm"] == ARM}
    assert arms["sql-injection"]["pooled"] and arms[""]["pooled"]
    assert arms["sql-injection"]["mean_cost"] is None            # never shown as 0
    assert not arms["sql-injection:query"]["pooled"]
    assert arms["sql-injection:query"]["pulls"] == arms[""]["pulls"] == 20
    assert diag_rows[""]["pooled"] and not diag_rows["sql-injection:query"]["pooled"]
