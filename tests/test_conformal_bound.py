"""The conformal gate keeps its stated per-side bound; anomaly flags keep their fraction
(BUG-0070, CC-ML-0019, PA-0069).

PA-0069(1): a stated guarantee is asserted *as stated* — at most α of the calibration
negatives flagged and of the positives dropped, ties included — at the smallest sizes
the toolkit accepts, with a non-vacuity check that the gate is not merely conservative.
"""

from __future__ import annotations

import json
import math
import random
from fractions import Fraction

import pytest

from fuzzlab.core.anomaly_flags import FLAG_RULE_TIES_NOT_SPLIT, flag_note
from fuzzlab.core.store import Store
from fuzzlab.ml import anomaly
from fuzzlab.ml.conformal import (GATE_RULE, NEVER_DROP, NEVER_FLAG, ConformalGate,
                                  lower_index, min_class_size, upper_index)
from fuzzlab.ml.train import (OLD_GATE_NOTE, gate_input, gate_notes, latest_classifier,
                              train_and_score)
from tests.test_ml_train import _seed_rich

SIZES = (1, 2, 3, 5, 8, 9, 10, 20, 50, 200)
ALPHAS = (0.05, 0.1, 0.2, 0.5)


def _counts(gate, scores, labels):
    flagged = sum(1 for s, y in zip(scores, labels) if not y and gate.decide(s) == "flag")
    dropped = sum(1 for s, y in zip(scores, labels) if y and gate.decide(s) == "drop")
    return flagged, dropped


# --- the bound on the calibration set ---------------------------------------------------

@pytest.mark.parametrize("alpha", ALPHAS)
@pytest.mark.parametrize("n", SIZES)
def test_per_side_error_on_the_calibration_set_is_at_most_alpha_with_ties(n, alpha):
    rng = random.Random(n * 1000 + int(alpha * 100))
    for _ in range(30):
        neg = [round(rng.random(), 1) for _ in range(n)]           # heavy ties
        pos = [round(rng.random(), 1) for _ in range(rng.randint(1, n + 3))]
        scores, labels = neg + pos, [0] * len(neg) + [1] * len(pos)
        gate = ConformalGate.calibrate(scores, labels, alpha=alpha)
        flagged, dropped = _counts(gate, scores, labels)
        assert flagged <= alpha * len(neg)
        assert dropped <= alpha * len(pos)


@pytest.mark.parametrize("alpha", ALPHAS)
@pytest.mark.parametrize("n", SIZES)
def test_non_vacuous_with_distinct_scores(n, alpha):
    """Distinct scores, classes placed so the thresholds do not cross (negatives HIGH,
    positives LOW — no swap): exactly n - k_hi negatives are flagged and k_lo - 1
    positives dropped, the most the bound allows. (Well-separated classes the usual way
    round make t_lo > t_hi and the swap shrinks both sets — `test_overlap_swap…`.)"""
    rng = random.Random(n)
    neg = [0.9 + x / 10**7 for x in rng.sample(range(10**6), n)]     # in [0.9, 1)
    pos = [x / 10**7 for x in rng.sample(range(10**6), n)]           # in [0, 0.1)
    gate = ConformalGate.calibrate(neg + pos, [0] * n + [1] * n, alpha=alpha)
    flagged, dropped = _counts(gate, neg + pos, [0] * n + [1] * n)
    k_hi, k_lo = upper_index(n, alpha), lower_index(n, alpha)
    assert flagged == (0 if k_hi is None else n - k_hi)
    assert dropped == (0 if k_lo is None else k_lo - 1)
    assert (gate.t_hi == NEVER_FLAG) == (k_hi is None)
    assert (gate.t_lo == NEVER_DROP) == (k_lo is None)


def test_overlap_swap_keeps_the_bound():
    """Well-separated classes (negatives LOW, positives HIGH) put the drop threshold
    above the flag threshold; the swap restores t_lo <= t_hi, which only shrinks both
    the flag and the drop sets — the bound still holds, and the crossed middle abstains."""
    rng = random.Random(3)
    swapped = 0
    for _ in range(300):
        n = rng.randint(9, 40)
        neg = [rng.uniform(0.0, 0.6) for _ in range(n)]
        pos = [rng.uniform(0.4, 1.0) for _ in range(n)]
        gate = ConformalGate.calibrate(neg + pos, [0] * n + [1] * n, alpha=0.2)
        raw_hi = math.nextafter(sorted(neg)[upper_index(n, 0.2) - 1], math.inf)
        raw_lo = math.nextafter(sorted(pos)[lower_index(n, 0.2) - 1], -math.inf)
        if raw_lo > raw_hi:
            swapped += 1
            assert (gate.t_lo, gate.t_hi) == (raw_hi, raw_lo)
        assert gate.t_lo <= gate.t_hi
        flagged, dropped = _counts(gate, neg + pos, [0] * n + [1] * n)
        assert flagged <= 0.2 * n and dropped <= 0.2 * n
    assert swapped > 100                              # the swap branch is exercised


def test_never_flag_and_never_drop_sentinels_are_beyond_every_probability():
    gate = ConformalGate.calibrate([0.2] * 5 + [0.8] * 5, [0] * 5 + [1] * 5, alpha=0.1)
    assert (gate.t_lo, gate.t_hi) == (NEVER_DROP, NEVER_FLAG)
    assert {gate.decide(s) for s in (0.0, -0.0, 0.5, 1.0)} == {"abstain"}
    assert json.loads(json.dumps(gate.t_hi)) == NEVER_FLAG       # survives the store
    assert json.loads(json.dumps(gate.t_lo)) == NEVER_DROP


def test_min_class_size_is_where_both_sides_start_to_act():
    assert min_class_size(0.1) == 9 and min_class_size(0.05) == 19
    for alpha in ALPHAS + (0.15, 0.3, 1 / 3):
        need = min_class_size(alpha)
        assert upper_index(need, alpha) is not None and lower_index(need, alpha) is not None
        assert upper_index(need - 1, alpha) is None and lower_index(need - 1, alpha) is None


def test_indices_are_exact_for_the_alpha_actually_used():
    """PA-0069(2): the order-statistic rank is computed in exact arithmetic on alpha's
    binary value — compared with a brute-force count of the defining inequality."""
    alphas = [k / 100 for k in range(1, 100)] + [1 / k for k in range(2, 60)]
    for alpha in alphas:
        a = Fraction(alpha)
        for n in range(0, 60):
            # smallest j in 1..n with j >= (n+1)(1-a); None if none
            hi = next((j for j in range(1, n + 1) if j >= (n + 1) * (1 - a)), None)
            # largest j in 1..n with j <= (n+1)a; None if none
            lo = max((j for j in range(1, n + 1) if j <= (n + 1) * a), default=None)
            assert upper_index(n, alpha) == hi, (alpha, n)
            assert lower_index(n, alpha) == lo, (alpha, n)


@pytest.mark.parametrize("alpha", [0, 1, 1.5, -0.1, float("nan"), True, "0.1"])
def test_alpha_outside_the_open_unit_interval_is_refused(alpha, tmp_path):
    with pytest.raises(ValueError, match="alpha"):
        ConformalGate.calibrate([0.1, 0.9], [0, 1], alpha=alpha)
    with Store(tmp_path / "a.db") as store:
        run = _seed_rich(store)
        with pytest.raises(ValueError, match="alpha"):
            train_and_score(store, run, alpha=alpha)
        assert store.conn.execute("SELECT COUNT(*) c FROM model").fetchone()["c"] == 0
        assert store.conn.execute(
            "SELECT COUNT(*) c FROM candidate WHERE score IS NOT NULL").fetchone()["c"] == 0
    with Store(tmp_path / "thin.db") as store:           # thin data: no gate is built,
        from tests.test_ml_train import _cand            # yet a bad alpha is refused
        thin = store.start_run("auto", "127.0.0.1:8080")
        _cand(store, thin, "/a.php", "id", "xss")
        store.conn.commit()
        with pytest.raises(ValueError, match="alpha"):
            train_and_score(store, thin, alpha=alpha)
        assert store.conn.execute("SELECT COUNT(*) c FROM model").fetchone()["c"] == 0


# --- the bound on new exchangeable data --------------------------------------------------

def test_held_out_error_is_alpha_both_sides_and_not_merely_conservative():
    """n = 20 per class, alpha = 0.1, 4000 trials. The new rule's exact held-out rate is
    1 - k/(n+1) = 2/21 ≈ 0.095 per side; the old rule (index round(0.9·19) = 17, >=) was
    4/21 ≈ 0.19."""
    rng = random.Random(7)
    n, alpha, trials = 20, 0.1, 4000
    flags = drops = 0
    for _ in range(trials):
        neg = [rng.random() for _ in range(n)]
        pos = [rng.random() for _ in range(n)]
        gate = ConformalGate.calibrate(neg + pos, [0] * n + [1] * n, alpha=alpha)
        flags += gate.decide(rng.random()) == "flag"
        drops += gate.decide(rng.random()) == "drop"
    se = math.sqrt(alpha * (1 - alpha) / trials)
    for rate in (flags / trials, drops / trials):
        assert alpha - 1 / (n + 1) - 3 * se <= rate <= alpha + 3 * se


# --- stored models: old rows keep their meaning; new rows say their rule -----------------

def test_new_rows_record_the_rule_and_class_sizes_and_explain_never_drop(tmp_path):
    with Store(tmp_path / "n.db") as store:
        run = _seed_rich(store)                       # 6 positives, 14 negatives
        train_and_score(store, run)
        clf = latest_classifier(store, run)
        c = clf.calibration
        assert c["gate_rule"] == GATE_RULE and (c["n_pos"], c["n_neg"]) == (6, 14)
        assert c["t_lo"] == NEVER_DROP                # 6 < 9 positives at alpha 0.1
        assert gate_notes(c) == ["never drops: needs ≥ 9 positives at α=0.1 (has 6)"]


def test_an_old_row_decides_exactly_as_before_and_is_labelled():
    old = {"alpha": 0.1, "t_lo": 0.3, "t_hi": 0.7, "score_source": "oof-labelled"}
    gate = ConformalGate(t_lo=old["t_lo"], t_hi=old["t_hi"])
    assert [gate.decide(s) for s in (0.3, 0.31, 0.69, 0.7)] == \
        ["drop", "abstain", "abstain", "flag"]               # >= / <= unchanged
    assert gate_notes(old) == [OLD_GATE_NOTE]
    assert gate_notes({"alpha": 0.1}) == []                   # no gate, nothing to say


def test_the_gate_is_calibrated_on_the_stored_rounded_scores(tmp_path):
    """PA-0069(3): judged on exactly what the readers see (stored `score_oof`), the
    labelled rows of the calibration run keep the bound."""
    with Store(tmp_path / "r.db") as store:
        run = _seed_rich(store)
        for i in range(10, 22):                       # widen the negatives so it flags
            from tests.test_ml_train import _cand
            _cand(store, run, f"/q{i}.php", "page", "xss")
        store.conn.commit()
        train_and_score(store, run)
        clf = latest_classifier(store, run)
        flagged = dropped = neg = pos = 0
        from fuzzlab.ml.dataset import build_dataset
        ds = build_dataset(store, run)
        label = dict(zip(ds.ids, ds.y))
        for r in store.conn.execute(
                "SELECT id, score, score_oof, oracle_status FROM candidate WHERE run_id=?",
                (run,)).fetchall():
            judged = gate_input(clf.calibration, r["oracle_status"], r["score"],
                                r["score_oof"])
            y = label[r["id"]]
            neg += not y
            pos += y
            flagged += (not y) and clf.gate.decide(judged) == "flag"
            dropped += y and clf.gate.decide(judged) == "drop"
        assert flagged <= 0.1 * neg and dropped <= 0.1 * pos


def test_a_score_that_rounds_across_the_threshold_stays_on_its_side():
    # unrounded 0.50000049 rounds (as stored) to 0.5; calibrated on stored values, the
    # flag order statistic is 0.5 itself and a stored 0.5 is not flagged
    neg = [0.1 * i for i in range(9)] + [0.50000049]
    stored = [round(s, 6) for s in neg]
    gate = ConformalGate.calibrate(stored + [0.9] * 10, [0] * 10 + [1] * 10, alpha=0.1)
    assert sum(gate.decide(s) == "flag" for s in stored) <= 1


# --- anomaly flags (BUG-0070's sweep): at most k, whole tie groups only ------------------

def test_flag_budget():
    assert anomaly.flag_budget(0, 0.1) == 0
    assert anomaly.flag_budget(3, 0.1) == 1 and anomaly.flag_budget(46, 0.1) == 5


def test_identical_scores_flag_nothing():
    flags = anomaly.flag_top([1.0] * 20, 0.1)
    assert sum(flags) == 0
    assert anomaly.flag_reason([1.0] * 20, flags, 0.1) == \
        "top tie group of 20 exceeds k=2: nothing stands out"


def test_two_tie_groups():
    scores = [5.0] * 6 + [1.0] * 14
    assert sum(anomaly.flag_top(scores, 0.1)) == 0             # k=2 < 6
    assert anomaly.flag_top(scores, 0.3) == [True] * 6 + [False] * 14   # k=6
    flags = anomaly.flag_top([9.0] + [5.0] * 3 + [1.0] * 16, 0.15)       # k=3
    assert sum(flags) == 1
    assert anomaly.flag_reason([9.0] + [5.0] * 3 + [1.0] * 16, flags, 0.15) == \
        "flagged 1 of at most k=3: the next tie group of 3 would exceed it"


def test_distinct_scores_flag_exactly_k_and_ties_never_exceed_it():
    rng = random.Random(11)
    for _ in range(500):
        n = rng.randint(1, 60)
        c = rng.choice((0.05, 0.1, 0.2, 0.5))
        distinct = rng.sample(range(10**6), n)
        assert sum(anomaly.flag_top(distinct, c)) == anomaly.flag_budget(n, c)
        tied = [rng.randint(0, 4) for _ in range(n)]
        flags = anomaly.flag_top(tied, c)
        assert sum(flags) <= anomaly.flag_budget(n, c)
        # whole tie groups only: a flagged value has every copy flagged
        flagged_values = {s for s, f in zip(tied, flags) if f}
        assert all(f for s, f in zip(tied, flags) if s in flagged_values)
        # and every flagged score is above every unflagged one
        if flagged_values and not all(flags):
            assert min(flagged_values) > max(s for s, f in zip(tied, flags) if not f)


def test_detect_anomalies_records_budget_rule_and_reason(tmp_path):
    with Store(tmp_path / "an.db") as store:
        run = _seed_rich(store)
        result = anomaly.detect_anomalies(store, run, contamination=0.1)
        m = {r["key"]: r["value"] for r in store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run,))}
        assert m["anomaly_flag_rule"] == anomaly.FLAG_RULE == FLAG_RULE_TIES_NOT_SPLIT
        assert m["anomaly_flag_budget"] == result["flag_budget"] == 2
        assert m["anomaly_flagged"] == result["flagged"] <= 2
        assert (result["flag_reason"] is None) == (result["flagged"] == 2)
        note = flag_note(store, run, m)
        assert (note is None) == (result["flagged"] == 2)


def test_old_runs_flags_are_labelled(tmp_path):
    with Store(tmp_path / "old.db") as store:
        run = _seed_rich(store)
        store.conn.execute("UPDATE candidate SET anomaly_flag=1, anomaly_score=3.0 "
                           "WHERE run_id=?", (run,))
        assert flag_note(store, run, {"anomaly_flagged": 20.0}) == \
            "flags from the pre-BUG-0070 rule (tie groups may exceed the fraction)"
        store.conn.execute("UPDATE candidate SET anomaly_flag=0 WHERE run_id=?", (run,))
        assert flag_note(store, run, {}) is None                # nothing stored, nothing said


def test_trainer_calibrates_on_stored_values_not_raw_oof(monkeypatch):
    """PA-0069(3), mutation-proven: two negatives whose raw out-of-fold score 0.4999996
    is stored as 0.5. Calibrated on raw values, the stored 0.5s would sit above
    nextafter(0.4999996) and both be flagged (2 > α·n = 1)."""
    from fuzzlab.ml import train
    from fuzzlab.ml.dataset import Dataset
    neg = [0.05 * i for i in range(1, 9)] + [0.4999996, 0.4999996]
    pos = [0.01] * 10                 # below the negatives: thresholds do not cross
    ds = Dataset(X=[[0.0]] * 20, y=[0] * 10 + [1] * 10,
                 groups=[f"/g{i}" for i in range(20)], ids=list(range(20)))
    monkeypatch.setattr(train, "_oof_scores", lambda d, factory, k: neg + pos)
    gate = train._select_and_evaluate(ds, "logistic", 5, 0.1)[4]
    stored = [round(s, 6) for s in neg]
    assert sum(gate.decide(s) == "flag" for s in stored) <= 0.1 * len(neg)


def test_pooled_view_says_old_rule_when_any_runs_gate_lacks_it(tmp_path):
    from fuzzlab.web import mlview
    with Store(tmp_path / "p.db") as store:
        old, new = _seed_rich(store), _seed_rich(store)
        train_and_score(store, old)
        train_and_score(store, new)          # newest row (the pooled view's) is new-rule
        row = store.conn.execute("SELECT id, calibration FROM model WHERE "
                                 "json_extract(calibration, '$.run_id')=?", (old,)).fetchone()
        calib = json.loads(row["calibration"])
        del calib["gate_rule"]
        store.conn.execute("UPDATE model SET calibration=? WHERE id=?",
                           (json.dumps(calib), row["id"]))
        store.conn.commit()
        assert OLD_GATE_NOTE not in mlview.conformal_panel(store, new)["notes"]
        assert mlview.conformal_panel(store, old)["notes"] == [OLD_GATE_NOTE]
        pooled = mlview.conformal_panel(store)
        assert "gate_rule" in latest_classifier(store).calibration
        assert OLD_GATE_NOTE in pooled["notes"]
        assert pooled["notes"].count(OLD_GATE_NOTE) == 1
