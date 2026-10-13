"""`fuzzlab auto --confirm-budget N` and `--anomaly` (CC-FUZZ-0048, FR-FUZZ-32).

The oracle confirms only N distinct candidates, ordered by a model trained on earlier
runs against the same target; the rest are recorded as `skipped_budget` (never as
rejections or training negatives). With no usable earlier labels the budget is not
applied and every candidate is confirmed, as before.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.runmode import RunPlan
from fuzzlab.core.store import Store
from fuzzlab.harness import auto_cli
from fuzzlab.harness.pipeline import run_pipeline
from fuzzlab.ml.active import Prioritized
from fuzzlab.oracle import Oracle
from tests.test_auto import GT_DIR, AutoSender
from tests.test_ml_train import _seed_rich

BASE = "http://127.0.0.1:8080"


@pytest.fixture
def confirm_calls(monkeypatch):
    """Record every candidate the oracle is asked to confirm (key + whether it confirmed)."""
    calls = []
    real = Oracle.confirm

    def recording(self, candidate, sender):
        verdict = real(self, candidate, sender)
        calls.append(_Call((candidate.url, candidate.param, candidate.method,
                            candidate.location, candidate.category), verdict is not None))
        return verdict
    monkeypatch.setattr(Oracle, "confirm", recording)
    return calls


class _Call(tuple):
    def __new__(cls, key, confirmed):
        obj = super().__new__(cls, key)
        obj.confirmed = confirmed
        return obj


def _rejected_keys(calls) -> int:
    """Checked keys minus confirmed keys — the per-key rejection count (CC-FUZZ-0048)."""
    keys = {tuple(c) for c in calls}
    confirmed = {tuple(c) for c in calls if c.confirmed}
    return len(keys) - len(confirmed)


def _statuses(store, run_id) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in store.conn.execute(
            "SELECT oracle_status s FROM candidate WHERE run_id=?", (run_id,)).fetchall():
        out[r["s"]] = out.get(r["s"], 0) + 1
    return out


def _metric(store, run_id, key):
    row = store.conn.execute(
        "SELECT value FROM run_metrics WHERE run_id=? AND key=?", (run_id, key)).fetchone()
    return None if row is None else row["value"]


# --- pipeline level ------------------------------------------------------------

from fuzzlab.audit import InjectionPoint  # noqa: E402

_POINTS = [InjectionPoint(url=f"{BASE}/product.php", param="id"),
           InjectionPoint(url=f"{BASE}/search.php", param="q"),
           InjectionPoint(url=f"{BASE}/blog_post.php", param="id")]
_PLAN = RunPlan(mode="manual", categories=["sql-injection", "xss"], scored=False,
                source="manual")


def _pipeline(store, **kw):
    run_id = store.start_run("auto", "127.0.0.1:8080")
    result = run_pipeline(list(_POINTS), store, run_id, AutoSender(), _PLAN, **kw)
    return run_id, result


def test_unbudgeted_run_confirms_every_row_and_marks_it_checked(tmp_path, confirm_calls):
    with Store(tmp_path / "a.db") as store:
        run_id, result = _pipeline(store)
        n = result.candidates
        assert len(confirm_calls) == n and _statuses(store, run_id) == {"checked": n}
        m = result.metrics
        assert m["oracle_checked"] == n and m["oracle_skipped"] == 0
        assert m["oracle_checked_keys"] == len({tuple(c) for c in confirm_calls})
        assert m["oracle_rejected"] == _rejected_keys(confirm_calls)
        assert any(c.confirmed for c in confirm_calls)       # the fake does confirm some
        assert "confirm_budget" not in m


def test_budget_confirms_exactly_the_first_n_keys_in_prioritizer_order(tmp_path, confirm_calls):
    seen = {}

    def prioritizer(store, run_id, ids):
        seen["ids"] = list(ids)
        return Prioritized(order=list(reversed(ids)), method="stub", training_rows=7)
    with Store(tmp_path / "a.db") as store:
        run_id, result = _pipeline(store, confirm_budget=2, prioritizer=prioritizer)
        keys = len(seen["ids"])
        assert keys > 2
        assert len(confirm_calls) == 2 and len(set(confirm_calls)) == 2
        rows = store.conn.execute(
            "SELECT id, oracle_status FROM candidate WHERE run_id=? ORDER BY id",
            (run_id,)).fetchall()
        checked = {r["id"] for r in rows if r["oracle_status"] == "checked"}
        assert set(seen["ids"][-2:]) <= checked              # the prioritizer's first two
        m = result.metrics
        assert m["oracle_checked_keys"] == 2 and m["confirmable_keys"] == keys
        assert m["oracle_skipped"] == len(rows) - m["oracle_checked"]
        assert m["confirm_budget"] == 2 and m["confirm_budget_fallback"] == 0
        assert m["budget_method"] == "stub" and m["budget_training_rows"] == 7
        assert m["oracle_rejected"] == _rejected_keys(confirm_calls)
        assert _metric(store, run_id, "pipeline_oracle_skipped") == m["oracle_skipped"]


def test_budget_falls_back_to_confirming_all_when_the_prioritizer_has_no_model(
        tmp_path, confirm_calls):
    with Store(tmp_path / "a.db") as store:
        run_id, result = _pipeline(store, confirm_budget=1,
                                   prioritizer=lambda store, run_id, ids: None)
        assert len(confirm_calls) == result.candidates
        assert _statuses(store, run_id) == {"checked": result.candidates}
        assert result.metrics["confirm_budget_fallback"] == 1


def test_duplicate_rows_share_one_key_one_confirmation_and_one_status(tmp_path, confirm_calls):
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        ev = ('{"url": "%s/product.php", "param": "id", "category": "sql-injection", '
              '"method": "GET", "location": "query"}' % BASE)
        for rule in ("R1", "R2"):                     # two rules fired on one point
            store.conn.execute("INSERT INTO candidate (run_id, rule, evidence) VALUES (?,?,?)",
                               (run_id, rule, ev))
        store.conn.commit()
        result = run_pipeline([], store, run_id, AutoSender(), _PLAN, confirm_budget=1,
                              prioritizer=lambda s, r, ids: Prioritized(order=list(ids),
                                                                        method="stub"))
        assert len(confirm_calls) == 1                         # one key, one confirmation
        assert _statuses(store, run_id) == {"checked": 2}
        m = result.metrics
        assert m["confirmable_keys"] == 1 and m["oracle_checked_keys"] == 1
        # per key: confirmed once -> no phantom rejection for the duplicate row
        assert m["oracle_rejected"] == _rejected_keys(confirm_calls)
        assert result.findings == (1 if confirm_calls[0].confirmed else 0)


def test_no_confirmer_rows_are_recorded_and_are_not_rejections(tmp_path, confirm_calls):
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "h")
        store.conn.execute(
            "INSERT INTO candidate (run_id, rule, evidence) VALUES (?,?,?)",
            (run_id, "X", '{"url": "/x", "param": "p", "category": "no-such-category"}'))
        store.conn.commit()
        result = run_pipeline([], store, run_id, AutoSender(), _PLAN)
        assert confirm_calls == []
        assert _statuses(store, run_id) == {"no_confirmer": 1}
        assert result.metrics["oracle_rejected"] == 0
        assert result.metrics["oracle_no_confirmer"] == 1


def test_confirm_budget_must_be_positive(tmp_path):
    with Store(tmp_path / "a.db") as store:
        with pytest.raises(ValueError):
            _pipeline(store, confirm_budget=0, prioritizer=lambda *a: None)


# --- CLI end to end ---------------------------------------------------------------

def _earlier_runs(store, n=2, base_url=BASE):
    for _ in range(n):
        r = _seed_rich(store)
        store.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)", (r, base_url))
    store.conn.commit()


def _main(tmp_path, monkeypatch, *extra):
    monkeypatch.setattr(auto_cli, "make_probe_sender", lambda base, identity=None: AutoSender())
    return auto_cli.main(["--base-url", BASE, "--store", str(tmp_path / "s.db"),
                          "--spider-db", str(tmp_path / "none.db"),
                          "--ground-truth", GT_DIR, "--points", "ground-truth",
                          "--authorized", *extra])


def _last_run(tmp_path):
    store = Store(tmp_path / "s.db")
    return store, store.conn.execute("SELECT MAX(id) i FROM run").fetchone()["i"]


@pytest.mark.parametrize("method", ["score", "random", "committee", "uncertainty"])
def test_cli_budgeted_run_trained_on_earlier_runs(tmp_path, monkeypatch, capsys,
                                                  confirm_calls, method):
    with Store(tmp_path / "s.db") as store:
        _earlier_runs(store)
    assert _main(tmp_path, monkeypatch, "--confirm-budget", "2",
                 "--budget-method", method, "--anomaly") == 0
    out = capsys.readouterr().out
    store, run_id = _last_run(tmp_path)
    with store:
        st = _statuses(store, run_id)
        assert len(set(confirm_calls)) == len(confirm_calls) == 2
        assert st.get("skipped_budget", 0) > 0
        assert _metric(store, run_id, "pipeline_oracle_checked_keys") == 2
        assert _metric(store, run_id, "pipeline_confirm_budget_fallback") == 0
        flagged = store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND anomaly_flag=1",
            (run_id,)).fetchone()["c"]
        assert flagged == _metric(store, run_id, "anomaly_flagged") > 0
        # never more than the contamination budget, whole tie groups only (BUG-0070)
        assert flagged <= _metric(store, run_id, "anomaly_flag_budget")
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE run_id=? AND anomaly_score IS NULL",
            (run_id,)).fetchone()["c"] == 0
    assert "oracle budget: checked 2 of" in out
    assert ("random order" in out) == (method == "random")
    if method != "random":
        assert "trained on 40 earlier labelled candidate(s)" in out
    assert "skipped candidates count as misses in the score" in out
    assert "anomaly: flagged" in out


@pytest.mark.parametrize("setup", ["no-earlier-runs", "other-target-only"])
def test_cli_budget_falls_back_loudly_without_usable_earlier_labels(
        tmp_path, monkeypatch, capsys, confirm_calls, setup):
    if setup == "other-target-only":
        with Store(tmp_path / "s.db") as store:
            _earlier_runs(store, base_url="http://elsewhere:9000")
    assert _main(tmp_path, monkeypatch, "--confirm-budget", "2",
                 "--budget-method", "score") == 0          # random never falls back
    out = capsys.readouterr().out
    store, run_id = _last_run(tmp_path)
    with store:
        assert set(_statuses(store, run_id)) == {"checked"}
        assert _metric(store, run_id, "pipeline_confirm_budget_fallback") == 1
    assert len(confirm_calls) > 2
    assert "oracle budget NOT applied" in out


@pytest.mark.parametrize("args, msg", [
    (["--confirm-budget", "0"], "--confirm-budget must be at least 1"),
    (["--anomaly-contamination", "0.9"], "--anomaly-contamination must be in (0, 0.5]"),
    (["--anomaly-contamination", "0"], "--anomaly-contamination must be in (0, 0.5]"),
])
def test_cli_rejects_bad_values(tmp_path, monkeypatch, capsys, args, msg):
    with pytest.raises(SystemExit):
        _main(tmp_path, monkeypatch, *args)
    assert msg in capsys.readouterr().err


def test_launcher_renders_the_new_flags_as_typed_inputs():
    from fuzzlab.web.commandspec import spec
    fields = {o.dest: o for o in spec("auto").options}
    assert fields["confirm_budget"].type == "int"
    assert fields["budget_seed"].type == "int"
    assert fields["anomaly_contamination"].type == "float"
    assert fields["budget_method"].type == "choice"
    assert set(fields["budget_method"].choices) == {"score", "uncertainty",
                                                    "committee", "random"}
    assert fields["anomaly"].type == "bool"


def test_unbudgeted_run_confirms_rows_in_their_original_order(tmp_path, confirm_calls):
    """Order matters to a bandit scheduler, so the no-budget path must not regroup
    duplicate rows by key: interleaved duplicates are confirmed in row order."""
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        ev = ('{"url": "%s/%s", "param": "%s", "category": "sql-injection", '
              '"method": "GET", "location": "query"}')
        rows = [("product.php", "id"), ("search.php", "q"), ("product.php", "id")]
        for page, param in rows:                       # A, B, A (A is duplicated)
            store.conn.execute("INSERT INTO candidate (run_id, rule, evidence) VALUES (?,?,?)",
                               (run_id, "R", ev % (BASE, page, param)))
        store.conn.commit()
        run_pipeline([], store, run_id, AutoSender(), _PLAN)
        assert [(c[0].rsplit("/", 1)[1], c[1]) for c in confirm_calls] == rows
