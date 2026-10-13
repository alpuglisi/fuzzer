"""Saved trained models (CC-ML-0015 / CC-CORE-0027, FR-ML-13), the per-run report's
model pins (BUG-0066 / CC-UI-0039) and the ML tab's coefficient panel (CC-UI-0038)."""

from __future__ import annotations

import ast
import copy
import json
import pickle
import random
from pathlib import Path

import pytest

from fuzzlab.core import migrations
from fuzzlab.core.store import Store
from fuzzlab.ml import persist
from fuzzlab.ml.active import prioritize
from fuzzlab.ml.anomaly import ECOD
from fuzzlab.ml.baselines import PrevalenceBaseline
from fuzzlab.ml.dataset import FEATURE_NAMES, FEATURE_VERSION, build_dataset
from fuzzlab.ml.gbt import GradientBoostedTrees
from fuzzlab.ml.logistic import LogisticRegression
from fuzzlab.ml.persist import ModelIncompatibleError, ModelParamsError, dumps_model, loads_model
from fuzzlab.ml.rank_train import _candidate_texts, latest_ranker, load_ranker, train_and_rank
from fuzzlab.ml.ranker import Ranker
from fuzzlab.ml.train import latest_classifier, load_classifier, train_and_score
from fuzzlab.report.report import build_report
from fuzzlab.web import mlview
from tests.test_ml_train import _seed_rich

REPO = Path(__file__).resolve().parent.parent


def _data(n=60, d=len(FEATURE_NAMES), seed=3):
    rng = random.Random(seed)
    X = [[rng.gauss(0, 1) for _ in range(d)] for _ in range(n)]
    y = [1 if x[0] + 0.5 * x[2] > 0.3 else 0 for x in X]
    return X, y


def _roundtrip(kind, model, names, ecod=None):
    text, sha = dumps_model(kind, model, feature_names=names,
                            feature_version=FEATURE_VERSION, ecod=ecod)
    return text, sha, loads_model(text, sha)


# --- migration 14 -----------------------------------------------------------------

def test_migration_14_adds_the_model_params_columns(tmp_path):
    with Store(tmp_path / "m.db") as store:
        assert store.schema_version() == max(v for v, _ in migrations.MIGRATIONS) >= 14
        cols = {r[1] for r in store.conn.execute("PRAGMA table_info(model)")}
        assert {"params", "params_sha256"} <= cols


# --- exact round trips --------------------------------------------------------------

@pytest.mark.parametrize("cls,kind", [(LogisticRegression, "logistic"),
                                      (GradientBoostedTrees, "gbt"),
                                      (PrevalenceBaseline, "prevalence")])
def test_classifier_round_trip_predicts_exactly_the_same(cls, kind):
    X, y = _data()
    model = cls().fit(X, y)
    _, _, loaded = _roundtrip(kind, model, FEATURE_NAMES)
    loaded.check_compatible()
    assert loaded.predict_proba(X) == model.predict_proba(X)      # exact, not approx


def test_hybrid_round_trip_reapplies_the_stored_ecod():
    from fuzzlab.ml.anomaly import augment
    X, y = _data()
    ecod = ECOD().fit(X)
    model = LogisticRegression().fit(augment(X, ecod), y)
    _, _, loaded = _roundtrip("logistic", model, FEATURE_NAMES + ["anomaly_ecod"], ecod)
    loaded.check_compatible()
    # callers pass plain rows; the loader appends the stored detector's score itself
    assert loaded.predict_proba(X) == model.predict_proba(augment(X, ecod))


def test_ranker_and_constant_round_trip():
    X, y = _data()
    texts = [f"p{i % 7} /x{i % 5}.php sql-injection get" for i in range(len(X))]
    ranker = Ranker().fit(X, texts, y)
    _, _, loaded = _roundtrip("ranker", ranker, ranker.feature_names)
    loaded.check_compatible()
    assert loaded.score(X, texts) == ranker.score(X, texts)
    _, _, const = _roundtrip("constant", 0.0, FEATURE_NAMES)
    assert const.score(X[:3], texts[:3]) == [0.0, 0.0, 0.0]


def test_same_model_gives_the_same_canonical_text_and_sha():
    X, y = _data()
    model = GradientBoostedTrees().fit(X, y)
    a = dumps_model("gbt", model, feature_names=FEATURE_NAMES, feature_version=FEATURE_VERSION)
    b = dumps_model("gbt", model, feature_names=FEATURE_NAMES, feature_version=FEATURE_VERSION)
    assert a == b


# --- trainers save; saved rows reproduce the stored scores ---------------------------

@pytest.mark.parametrize("kind,hybrid", [("logistic", False), ("gbt", False),
                                         ("logistic", True)])
def test_trained_classifier_row_reproduces_the_stored_scores(tmp_path, kind, hybrid):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        result = train_and_score(store, run_id, model_kind=kind, hybrid=hybrid)
        clf = latest_classifier(store, run_id)
        assert clf.params_sha256 == result["params_sha256"]
        loaded = load_classifier(store, clf)
        loaded.check_compatible()
        ds = build_dataset(store, run_id, include_unlabelled=True)
        stored = [r["score"] for r in store.conn.execute(
            "SELECT score FROM candidate WHERE run_id=? ORDER BY id", (run_id,))]
        assert [round(p, 6) for p in loaded.predict_proba(ds.X)] == stored


def test_trained_ranker_row_reproduces_the_stored_rank_scores(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        train_and_rank(store, run_id)
        loaded = load_ranker(store, latest_ranker(store, run_id)[0])
        loaded.check_compatible()
        ds = build_dataset(store, run_id, include_unlabelled=True)
        texts = _candidate_texts(store, run_id, ds.ids)
        stored = [r["rank_score"] for r in store.conn.execute(
            "SELECT rank_score FROM candidate WHERE run_id=? ORDER BY id", (run_id,))]
        assert [round(s, 6) for s in loaded.score(ds.X, texts)] == stored


def test_fallback_models_are_saved_too(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "h")
        train_and_score(store, run_id)
        train_and_rank(store, run_id)
        assert load_classifier(store, latest_classifier(store, run_id)).kind == "prevalence"
        assert load_ranker(store, latest_ranker(store, run_id)[0]).kind == "constant"


def test_a_legacy_row_without_params_loads_as_none(tmp_path):
    with Store(tmp_path / "a.db") as store:
        store.conn.execute("INSERT INTO model (name, version, calibration) VALUES "
                           "('logistic', 1, '{}')")
        store.conn.commit()
        assert load_classifier(store, latest_classifier(store, None)) is None


# --- fail closed --------------------------------------------------------------------

def _good():
    X, y = _data()
    text, sha = dumps_model("logistic", LogisticRegression().fit(X, y),
                            feature_names=FEATURE_NAMES, feature_version=FEATURE_VERSION)
    return json.loads(text)


def _resealed(env) -> tuple[str, str]:
    text = json.dumps(env, sort_keys=True, separators=(",", ":"))
    return text, persist._sha(text)


def test_tampered_text_fails_the_sha_check():
    env = _good()
    text, sha = _resealed(env)
    env["params"]["b"] += 1.0
    with pytest.raises(ModelParamsError, match="sha256"):
        loads_model(_resealed(env)[0], sha)


@pytest.mark.parametrize("payload", [
    pickle.dumps({"kind": "logistic"}),                    # bytes: a pickle payload
    "\x80\x04\x95 not json",                                # non-JSON text
    '{"format": 1, "kind": "logistic", "x": NaN}',         # NaN token
    '{"format": Infinity}',                                # Infinity token
    "[" * 50000 + "]" * 50000,                              # runaway nesting
])
def test_non_json_pickle_nonfinite_and_deep_input_are_rejected(payload):
    sha = persist._sha(payload) if isinstance(payload, str) else "x"
    with pytest.raises(ModelParamsError):
        loads_model(payload, sha)


def _mutated(mutate):
    env = copy.deepcopy(_good())
    mutate(env)
    return _resealed(env)


@pytest.mark.parametrize("mutate", [
    lambda e: e.update(format=2),                                        # unknown format
    lambda e: e.update(kind="pickle"),                                   # unknown kind
    lambda e: e["params"].update(w=e["params"]["w"][:-1]),               # length mismatch
    lambda e: e["params"].update(std=[0.0] * len(e["params"]["std"])),   # zero std
    lambda e: e["params"].update(b="1.0"),                               # wrong type
    lambda e: e.update(feature_version="1"),                             # wrong type
    lambda e: e.update(extra=1),                                         # unknown key
    lambda e: e.update(ecod={"n": 1, "d": 11, "sorted": [], "skew": []}),  # ecod w/o feature
    lambda e: e.update(feature_names=e["feature_names"][:-1] + ["anomaly_ecod"]),  # feature w/o ecod
])
def test_malformed_envelopes_are_rejected(mutate):
    text, sha = _mutated(mutate)
    with pytest.raises(ModelParamsError):
        loads_model(text, sha)


def _gbt_env():
    X, y = _data()
    text, _ = dumps_model("gbt", GradientBoostedTrees(n_estimators=3).fit(X, y),
                          feature_names=FEATURE_NAMES, feature_version=FEATURE_VERSION)
    return json.loads(text)


def _deepest_split(node):
    while "l" in node and "l" in node["l"]:
        node = node["l"]
    return node


@pytest.mark.parametrize("mutate", [
    lambda t: _deepest_split(t).update(f=999),                           # feature out of range
    lambda t: _deepest_split(t).pop("r"),                                # one child
])
def test_malformed_trees_are_rejected(mutate):
    env = _gbt_env()
    mutate(env["params"]["trees"][0])
    with pytest.raises(ModelParamsError):
        loads_model(*_resealed(env))


def _leaf_at_depth(node, depth, want):
    """Path to some leaf at exactly ``want`` depth (the parent dict and side), or None."""
    if "v" in node:
        return None
    for side in ("l", "r"):
        child = node[side]
        if "v" in child and depth + 1 == want:
            return node, side
        found = None if "v" in child else _leaf_at_depth(child, depth + 1, want)
        if found:
            return found
    return None


def test_a_tree_deeper_than_max_depth_is_rejected():
    env = _gbt_env()
    max_depth = env["params"]["max_depth"]
    for tree in env["params"]["trees"]:
        spot = _leaf_at_depth(tree, 0, max_depth)
        if spot:
            parent, side = spot
            parent[side] = {"f": 0, "t": 0.0, "l": {"v": 0.0}, "r": {"v": 0.0}}  # valid split
            break
    else:
        pytest.skip("no leaf at max_depth in this fixture")
    with pytest.raises(ModelParamsError, match="deeper than max_depth"):
        loads_model(*_resealed(env))


def test_unsorted_ecod_is_rejected():
    from fuzzlab.ml.anomaly import augment
    X, y = _data()
    ecod = ECOD().fit(X)
    text, _ = dumps_model("logistic", LogisticRegression().fit(augment(X, ecod), y),
                          feature_names=FEATURE_NAMES + ["anomaly_ecod"],
                          feature_version=FEATURE_VERSION, ecod=ecod)
    env = json.loads(text)
    env["ecod"]["sorted"][0].reverse()
    with pytest.raises(ModelParamsError, match="not sorted"):
        loads_model(*_resealed(env))


def test_non_finite_model_cannot_be_saved():
    X, y = _data()
    model = LogisticRegression().fit(X, y)
    model._w[0] = float("nan")
    # rejected by the canonical serialiser itself (allow_nan=False), before validation
    with pytest.raises(ModelParamsError, match="non-finite value"):
        dumps_model("logistic", model, feature_names=FEATURE_NAMES,
                    feature_version=FEATURE_VERSION)


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_a_non_finite_token_is_rejected_at_parse_time(token):
    """Defence in depth: validation would also catch a non-finite weight, but the parser
    refuses the token outright (parse_constant), so it never reaches a model."""
    env = _good()
    text = json.dumps(env, sort_keys=True, separators=(",", ":"))
    text = text.replace('"b":', f'"b":{token},"_b":', 1)
    with pytest.raises(ModelParamsError, match=f"non-finite number {token}"):
        loads_model(text, persist._sha(text))


def test_persist_never_imports_pickle_or_marshal():
    tree = ast.parse((REPO / "fuzzlab/ml/persist.py").read_text(encoding="utf-8"))
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not imported & {"pickle", "marshal", "dill", "shelve", "cloudpickle"}


# --- compatibility --------------------------------------------------------------------

def test_check_compatible_rejects_a_changed_feature_layout():
    X, y = _data()
    model = LogisticRegression().fit(X, y)
    names = list(FEATURE_NAMES)
    swapped = names[:]
    swapped[0], swapped[1] = swapped[1], swapped[0]
    for kwargs in ({"feature_names": swapped, "feature_version": FEATURE_VERSION},
                   {"feature_names": names, "feature_version": FEATURE_VERSION + 1}):
        loaded = loads_model(*dumps_model("logistic", model, **kwargs))
        with pytest.raises(ModelIncompatibleError):
            loaded.check_compatible()
    # a hybrid model missing its anomaly feature name can't even be saved
    with pytest.raises(ModelParamsError):
        dumps_model("logistic", model, feature_names=names,
                    feature_version=FEATURE_VERSION, ecod=ECOD().fit(X))


def test_a_row_of_the_wrong_width_is_refused():
    X, y = _data()
    _, _, loaded = _roundtrip("logistic", LogisticRegression().fit(X, y), FEATURE_NAMES)
    with pytest.raises(ModelIncompatibleError):
        loaded.predict_proba([X[0][:-1]])


# --- the budget prioritizer's identity ------------------------------------------------

def test_prioritizer_records_a_deterministic_model_sha(tmp_path):
    from tests.test_ml_budget_and_scope import _current_run, _prior_runs
    with Store(tmp_path / "a.db") as store:
        _prior_runs(store)
        run_id, ids = _current_run(store)
        for method in ("score", "committee"):
            a = prioritize(store, run_id, ids, method=method, seed=4)
            b = prioritize(store, run_id, ids, method=method, seed=4)
            assert a.model_sha256 and a.model_sha256 == b.model_sha256 and a.seed == 4
        assert prioritize(store, run_id, ids, method="committee", seed=5).model_sha256 != \
            prioritize(store, run_id, ids, method="committee", seed=4).model_sha256
        assert prioritize(store, run_id, ids, method="random").model_sha256 is None


# --- BUG-0066: the per-run report pins THIS run's models ------------------------------

def test_report_pins_the_runs_own_models_not_the_newest(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run1 = _seed_rich(store)
        train_and_score(store, run1)
        train_and_rank(store, run1)
        sha1 = latest_classifier(store, run1).params_sha256
        run2 = _seed_rich(store)
        train_and_score(store, run2)                 # newer versions, another run
        train_and_rank(store, run2)
        rep1 = build_report(store, run1)
        assert rep1["reproducibility"]["model_versions"] == {"logistic": 1, "ranker": 1}
        assert rep1["reproducibility"]["model_params_sha256"]["logistic"] == sha1
        rep2 = build_report(store, run2)
        assert rep2["reproducibility"]["model_versions"] == {"logistic": 2, "ranker": 2}


def test_report_sha_is_null_for_a_legacy_model(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "h")
        # no saved params (pre-migration 14); scoped to its run, as trainers write it — a
        # scope-less row now covers only a run holding stored scores (BUG-0074)
        store.conn.execute("INSERT INTO model (name, version, feature_version, calibration) "
                           "VALUES ('logistic', 1, 1, ?)", (json.dumps({"run_id": run_id}),))
        store.conn.commit()
        rep = build_report(store, run_id)
        assert rep["reproducibility"]["model_params_sha256"] == {"logistic": None}


# --- the ML tab's coefficient panel ---------------------------------------------------

def test_weights_panel_shows_the_saved_coefficients(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        train_and_score(store, run_id, model_kind="logistic", hybrid=True)
        panel = mlview.weights_panel(store, run_id)
        assert panel["available"] is True
        saved = load_classifier(store, latest_classifier(store, run_id)).model.to_params()
        names = FEATURE_NAMES + ["anomaly score (ECOD)"]
        assert {w["feature"]: w["weight"] for w in panel["weights"]} == dict(zip(names, saved["w"]))
        assert [abs(w["weight"]) for w in panel["weights"]] == \
            sorted((abs(w) for w in saved["w"]), reverse=True)
        assert "not feature importance" in panel["note"]


@pytest.mark.parametrize("setup,reason", [
    ("none", "no trained classifier"),
    ("gbt", "tree model"),
    ("fallback", "fallback model"),
    ("legacy", "trained before models were saved"),
])
def test_weights_panel_explains_when_there_are_no_coefficients(tmp_path, setup, reason):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        if setup == "gbt":
            train_and_score(store, run_id, model_kind="gbt")
        elif setup == "fallback":
            train_and_score(store, run_id, min_rows=10**6)
        elif setup == "legacy":
            store.conn.execute("INSERT INTO model (name, version, calibration) VALUES "
                               "('logistic', 1, ?)", (json.dumps({"run_id": run_id}),))
            store.conn.commit()
        panel = mlview.weights_panel(store, run_id)
        assert panel["available"] is False and reason in panel["reason"]


# --- BUG-0095 / PA-0096: numeric extremes and sizes stay inside the typed boundary -----

_HUGE = 10 ** 1000                                   # an int no float can hold


def _calibrated_env():
    from fuzzlab.ml.calibration import PlattScaler
    X, y = _data()
    text, _ = dumps_model("logistic", LogisticRegression().fit(X, y),
                          feature_names=FEATURE_NAMES, feature_version=FEATURE_VERSION,
                          calibrator=PlattScaler(a=1.5, b=-0.2))
    return json.loads(text)


def _hybrid_env():
    X, y = _data()
    ecod = ECOD().fit(X)
    text, _ = dumps_model("logistic", LogisticRegression().fit(
        [r + [ecod.score(r)] for r in X], y), feature_names=FEATURE_NAMES
        + ["anomaly_ecod"], feature_version=FEATURE_VERSION, ecod=ecod)
    return json.loads(text)


def _prevalence_env():
    text, _ = dumps_model("prevalence", PrevalenceBaseline().fit([[0.0]], [1]),
                          feature_names=FEATURE_NAMES, feature_version=FEATURE_VERSION)
    return json.loads(text)


@pytest.mark.parametrize("make,mutate", [
    (_prevalence_env, lambda e: e["params"].update(rate=_HUGE)),          # the finding
    (_good, lambda e: e["params"]["w"].__setitem__(0, _HUGE)),            # logistic weight
    (_good, lambda e: e["params"].update(b=-_HUGE)),                      # logistic bias
    (_calibrated_env, lambda e: e["calibrator"].update(a=_HUGE)),         # platt a
    (_hybrid_env, lambda e: e["ecod"]["skew"].__setitem__(0, _HUGE)),     # ecod value
    (_gbt_env, lambda e: e["params"].update(f0=_HUGE)),                   # gbt prior
    (_gbt_env, lambda e: _deepest_split(e["params"]["trees"][0]).update(t=_HUGE)),
])
def test_an_int_too_large_for_a_float_is_a_typed_refusal(make, mutate):
    env = copy.deepcopy(make())
    mutate(env)
    text, sha = _resealed(env)
    with pytest.raises(ModelParamsError):
        loads_model(text, sha)


@pytest.mark.parametrize("literal", ["1e400", "-1e400", "1" + "0" * 5000])
def test_extreme_literals_are_a_typed_refusal(literal):
    """`1e400` parses to inf; a 5001-digit int trips Python's int-string limit
    (ValueError) — both surface as ModelParamsError, never a raw exception."""
    text, _ = _resealed(_prevalence_env())
    text = text.replace('"rate":1.0', f'"rate":{literal}')
    assert literal in text
    with pytest.raises(ModelParamsError):
        loads_model(text, persist._sha(text))


@pytest.mark.parametrize("value", [_HUGE, float("nan"), float("inf"), -0.0, True, "1",
                                   None, [1.0], 2 ** 1024],
                         ids=["huge", "nan", "inf", "-0.0", "bool", "str", "none", "list",
                              "2**1024"])
def test_is_num_is_total(value):
    """PA-0096: a validation predicate never raises, whatever it is given."""
    assert persist._is_num(value) is (value == 0 and not isinstance(value, bool))


def test_oversized_text_is_refused_before_parsing(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("json.loads must not run on oversized text")
    text = '{"x":"' + "a" * persist.MAX_PARAMS_BYTES + '"}'
    monkeypatch.setattr(persist.json, "loads", boom)
    with pytest.raises(ModelParamsError, match="MAX_PARAMS_BYTES"):
        loads_model(text, persist._sha(text))


def test_a_model_over_the_element_budget_is_refused(monkeypatch):
    text, sha = _resealed(_good())                   # 11-feature logistic: > 50 values
    monkeypatch.setattr(persist, "MAX_MODEL_ELEMENTS", 50)
    with pytest.raises(ModelParamsError, match="MAX_MODEL_ELEMENTS"):
        loads_model(text, sha)
    X, y = _data()
    with pytest.raises(ModelParamsError, match="MAX_MODEL_ELEMENTS"):  # and on save
        dumps_model("logistic", LogisticRegression().fit(X, y),
                    feature_names=FEATURE_NAMES, feature_version=FEATURE_VERSION)


@pytest.mark.parametrize("mutate", [
    lambda e: e["params"].update(n_estimators=persist.MAX_TREES + 1,
                                 trees=e["params"]["trees"] * 400),
    lambda e: e["params"].update(max_depth=persist.MAX_DEPTH + 1),
])
def test_gbt_tree_count_and_depth_limits(mutate):
    env = copy.deepcopy(_gbt_env())
    mutate(env)
    text, sha = _resealed(env)
    with pytest.raises(ModelParamsError, match="trees of depth"):
        loads_model(text, sha)


def test_a_real_trained_model_fits_the_limits(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        train_and_score(store, run_id, hybrid=True)
        clf = latest_classifier(store, run_id)
        assert load_classifier(store, clf) is not None


def test_saved_mode_refuses_a_huge_int_cleanly(tmp_path):
    """The finding's path end to end: a resealed stored row → a refusal, not a crash."""
    from tests.test_ml_saved_and_decisions import _target, _two_trained_runs
    with Store(tmp_path / "a.db") as store:
        _two_trained_runs(store)
        for row in store.conn.execute("SELECT id, params FROM model WHERE params IS NOT "
                                      "NULL").fetchall():
            env = json.loads(row["params"])
            if env["kind"] == "logistic":
                env["params"]["b"] = _HUGE
            elif env["kind"] == "gbt":
                env["params"]["f0"] = _HUGE
            text, sha = _resealed(env)
            store.conn.execute("UPDATE model SET params=?, params_sha256=? WHERE id=?",
                               (text, sha, row["id"]))
        store.conn.commit()
        run_id = _seed_rich(store)
        _target(store, run_id)
        result = train_and_score(store, run_id, train_on="saved")
        assert result["refused"] is True and "cannot be applied" in result["reason"]


@pytest.mark.parametrize("exc", [OverflowError("int too large"), MemoryError()])
def test_the_loader_boundary_types_every_extreme_failure(monkeypatch, exc):
    """PA-0021 / PA-0096: whatever raises inside the loader, the caller sees one typed
    error — an OverflowError / MemoryError from a rebuild included."""
    text, sha = _resealed(_good())

    def boom(env, sha256):
        raise exc
    monkeypatch.setattr(persist, "_build", boom)
    with pytest.raises(ModelParamsError, match="out of range"):
        loads_model(text, sha)


# --- BUG-0103 / PA-0104: a loaded model's arithmetic must stay finite ---------------

def _logistic_env(w, std, d=len(FEATURE_NAMES)):
    env = copy.deepcopy(_good())
    env["params"].update(w=[w] * d, mean=[0.0] * d, std=[std] * d)
    return env


@pytest.mark.parametrize("std", [5e-324, 1e-300, 1e-13, -1.0])
def test_a_std_below_the_floor_is_refused(std):
    text, sha = _resealed(_logistic_env(0.0, std))
    with pytest.raises(ModelParamsError, match="standard deviation"):
        loads_model(text, sha)


def test_a_finite_model_whose_arithmetic_overflows_is_refused_at_scoring():
    """Valid parameters, but an input of 1e300 / std 1e-12 is not a finite z."""
    text, sha = _resealed(_logistic_env(1.0, 1e-12))
    m = loads_model(text, sha)
    with pytest.raises(ModelParamsError, match="not finite"):
        m.predict_proba([[1e300] * len(FEATURE_NAMES)])


def test_scores_are_checked_before_any_is_returned(monkeypatch):
    text, sha = _resealed(_good())
    m = loads_model(text, sha)
    monkeypatch.setattr(m.model, "predict_proba", lambda X: [0.5, float("nan")])
    with pytest.raises(ModelParamsError, match="non-finite"):
        m.predict_proba([[0.0] * len(FEATURE_NAMES)] * 2)


def test_the_trainer_floors_a_near_constant_features_std():
    from fuzzlab.ml.logistic import STD_FLOOR
    X = [[1.0 + (1e-15 if i % 2 else 0.0)] + [float(i % 3)] * (len(FEATURE_NAMES) - 1)
         for i in range(20)]
    model = LogisticRegression().fit(X, [i % 2 for i in range(20)])
    assert all(s >= STD_FLOOR for s in model._std)
    text, sha = dumps_model("logistic", model, feature_names=FEATURE_NAMES,
                            feature_version=FEATURE_VERSION)
    assert loads_model(text, sha) is not None
