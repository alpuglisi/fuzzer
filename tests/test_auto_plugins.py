"""`fuzzlab auto` attaches the ML stages through plugins (CC-FUZZ-0050, FR-FUZZ-34).

The golden files in `tests/data/auto_summary/` were captured from `fuzzlab auto` *before*
the ML stages moved behind the plugin hooks: the summary a user sees must not change.
Regenerate them only for a deliberate summary change, and say so in its change record.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fuzzlab.core.store import Store
from tests.test_auto_budget import _earlier_runs, _main

GOLDEN = Path(__file__).parent / "data" / "auto_summary"

CASES = {
    "run": ["--score", "--rank", "--anomaly", "--confirm-budget", "2"],
    "earlier": ["--score", "--rank", "--anomaly", "--confirm-budget", "2",
                "--train-on", "earlier"],
    "score_only": ["--score"],
    "budget_fallback_nolabels": ["--confirm-budget", "2"],
}


def _run(tmp_path, monkeypatch, capsys, *extra, earlier=True):
    if earlier:
        with Store(tmp_path / "s.db") as store:
            _earlier_runs(store)
    rc = _main(tmp_path, monkeypatch, *extra)
    return rc, capsys.readouterr().out.replace(str(tmp_path), "<TMP>")


@pytest.mark.parametrize("name", sorted(CASES))
def test_summary_is_byte_identical_to_the_pre_plugin_capture(tmp_path, monkeypatch,
                                                             capsys, name):
    rc, out = _run(tmp_path, monkeypatch, capsys, *CASES[name],
                   earlier=name != "budget_fallback_nolabels")
    assert f"rc={rc}\n" + out == (GOLDEN / f"{name}.txt").read_text()


# --- the run record, failures and exit codes (CC-FUZZ-0050) ----------------------

import fuzzlab.ml.active as ml_active                      # noqa: E402
import fuzzlab.ml.train as ml_train                        # noqa: E402
from fuzzlab.harness import auto_cli                       # noqa: E402
from fuzzlab.harness.multitarget import TargetSpec, run_targets   # noqa: E402
from fuzzlab.labels import contract                        # noqa: E402
from fuzzlab.plugins import PluginManager                  # noqa: E402
from tests.test_auto import GT_DIR, AutoSender             # noqa: E402
from tests import test_auto_budget as _budget              # noqa: E402
from tests.test_auto_budget import _last_run, _metric      # noqa: E402

confirm_calls = _budget.confirm_calls                      # the shared pytest fixture


def _rows(store, run_id):
    return {r["name"]: dict(r) for r in store.conn.execute(
        "SELECT name, version, config, status, error FROM run_plugin WHERE run_id=?",
        (run_id,))}


def _runs(tmp_path) -> int:
    if not (tmp_path / "s.db").exists():
        return 0
    with Store(tmp_path / "s.db") as store:
        return store.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0]


def test_ml_flags_record_their_stages_on_the_run(tmp_path, monkeypatch, capsys):
    rc, _ = _run(tmp_path, monkeypatch, capsys, *CASES["earlier"])
    assert rc == 0
    store, run_id = _last_run(tmp_path)
    with store:
        rows = _rows(store, run_id)
    assert set(rows) == {"ml-budget", "ml-classifier", "ml-ranker", "ml-anomaly"}
    assert {r["status"] for r in rows.values()} == {"ok"}
    assert rows["ml-classifier"]["config"] == '{"hybrid":false,"model_kind":"auto","train_on":"earlier"}'
    assert rows["ml-budget"]["config"] == '{"method":"score","seed":0}'


def test_no_ml_flags_and_no_plugins_attaches_nothing(tmp_path, monkeypatch, capsys):
    seen = {}
    real = auto_cli.run_auto

    def spy(**kw):
        seen["plugins"] = kw.get("plugins")
        return real(**kw)

    monkeypatch.setattr(auto_cli, "run_auto", spy)
    rc, _ = _run(tmp_path, monkeypatch, capsys)
    assert rc == 0 and seen["plugins"] is None
    store, run_id = _last_run(tmp_path)
    with store:
        assert _rows(store, run_id) == {}


def test_a_failing_stage_is_rolled_back_reported_and_exits_1(tmp_path, monkeypatch, capsys):
    def broken(*a, **k):
        raise RuntimeError("cannot serialise the model")

    monkeypatch.setattr(ml_train, "dumps_model", broken)    # after the score UPDATE
    rc, out = _run(tmp_path, monkeypatch, capsys, "--score", "--rank", "--anomaly")
    assert rc == 1
    assert "  ml-classifier: FAILED — RuntimeError('cannot serialise the model')" in out
    assert "  ranker (" in out and "  anomaly: flagged" in out
    store, run_id = _last_run(tmp_path)
    with store:
        q = store.conn.execute
        assert q("SELECT COUNT(*) FROM candidate WHERE run_id=? AND score IS NOT NULL",
                 (run_id,)).fetchone()[0] == 0            # rolled back
        assert q("SELECT COUNT(*) FROM candidate WHERE run_id=? AND rank_score IS NULL",
                 (run_id,)).fetchone()[0] == 0            # later stages still ran
        assert q("SELECT COUNT(*) FROM model WHERE name IN ('logistic', 'gbt')"
                 ).fetchone()[0] == 0
        rows = _rows(store, run_id)
        assert rows["ml-classifier"]["status"] == "failed"
        assert "cannot serialise" in rows["ml-classifier"]["error"]
        assert rows["ml-ranker"]["status"] == rows["ml-anomaly"]["status"] == "ok"


def test_a_failing_prioritizer_keeps_the_cap_and_exits_1(tmp_path, monkeypatch, capsys,
                                                         confirm_calls):
    def broken(*a, **k):
        raise RuntimeError("prioritizer broke")

    monkeypatch.setattr(ml_active, "prioritize", broken)
    rc, out = _run(tmp_path, monkeypatch, capsys, "--confirm-budget", "2")
    assert rc == 1
    assert ("  oracle budget: ml-budget FAILED — RuntimeError('prioritizer broke'); "
            "confirmed the first 2 of") in out
    assert "trained on" not in out and "NOT applied" not in out
    assert len(set(confirm_calls)) == 2                      # the cap held
    store, run_id = _last_run(tmp_path)
    with store:
        assert _metric(store, run_id, "pipeline_confirm_budget_error") == 1
        assert _metric(store, run_id, "pipeline_oracle_checked_keys") == 2
        assert _rows(store, run_id)["ml-budget"]["status"] == "failed"


class _EP:
    def __init__(self, name, obj):
        self.name, self._obj = name, obj

    def load(self):
        return self._obj


class _ThirdPartyPrio:
    name, priority = "tp-order", 5

    def register_prioritizer(self):
        return lambda store, run_id, ids: None


def _entry_points(monkeypatch, *plugins):
    import fuzzlab.plugins.discovery as discovery
    monkeypatch.setattr(discovery, "_entry_points",
                        lambda group: [_EP(p.name, p) for p in plugins])


def test_two_prioritizers_are_a_usage_error_before_any_run(tmp_path, monkeypatch, capsys):
    _entry_points(monkeypatch, _ThirdPartyPrio())
    with pytest.raises(SystemExit) as exc:
        _main(tmp_path, monkeypatch, "--confirm-budget", "2", "--plugins")
    assert exc.value.code == 2
    assert "only one plugin may order the budget: tp-order, ml-budget" in capsys.readouterr().err
    assert _runs(tmp_path) == 0


def test_a_third_party_prioritizer_orders_the_budget_without_ml(tmp_path, monkeypatch,
                                                                capsys):
    import fuzzlab.plugins.optional as optional
    monkeypatch.setattr(optional, "_package_absent", lambda: True)
    _entry_points(monkeypatch, _ThirdPartyPrio())
    rc, out = _run(tmp_path, monkeypatch, capsys, "--confirm-budget", "2", "--plugins",
                   earlier=False)
    assert rc == 0 and "oracle budget NOT applied" in out   # it returned None: confirm all


@pytest.mark.parametrize("extra, msg", [
    (["--score"], "ML components are not installed: --score/--rank/--anomaly need "
                  "fuzzlab.ml"),
    (["--confirm-budget", "2"], "ML components are not installed: --confirm-budget needs "
                                "fuzzlab.ml or a --plugins plugin that contributes a "
                                "prioritizer"),
])
def test_ml_flags_without_ml_are_a_usage_error_before_any_run(tmp_path, monkeypatch, capsys,
                                                              extra, msg):
    import fuzzlab.plugins.optional as optional
    monkeypatch.setattr(optional, "_package_absent", lambda: True)
    with pytest.raises(SystemExit) as exc:
        _main(tmp_path, monkeypatch, *extra)
    assert exc.value.code == 2 and msg in capsys.readouterr().err
    assert _runs(tmp_path) == 0


def test_a_failing_third_party_post_run_plugin_is_reported(tmp_path, monkeypatch, capsys):
    class Broken:
        name = "tp-stage"

        def after_run(self, store, run_id):
            raise RuntimeError("third party")

    _entry_points(monkeypatch, Broken())
    rc, out = _run(tmp_path, monkeypatch, capsys, "--plugins", earlier=False)
    assert rc == 1 and "  plugin tp-stage: FAILED — RuntimeError('third party')" in out


def test_run_targets_dispatches_post_run_plugins_per_target_run(tmp_path):
    calls = []

    class Flaky:
        name = "flaky"

        def after_run(self, store, run_id):
            calls.append(run_id)
            if len(calls) == 1:
                raise RuntimeError("first target only")
            return {"run": run_id}

    gt = contract.load(GT_DIR)
    specs = [TargetSpec(n, "http://127.0.0.1:8080", ground_truth=gt,
                        points_source="ground-truth") for n in ("a", "b")]
    with Store(tmp_path / "u.db") as store:
        outcomes = run_targets(specs, store, sender_for=lambda spec: AutoSender(),
                               plugins=PluginManager(plugins=[Flaky()]))
        assert calls == [o.run_id for o in outcomes]
        assert [o.plugin_outcomes[0].ok for o in outcomes] == [False, True]
        rows = {r["run_id"]: r["status"] for r in store.conn.execute(
            "SELECT run_id, status FROM run_plugin WHERE name='flaky'")}
        assert rows == {outcomes[0].run_id: "failed", outcomes[1].run_id: "ok"}
