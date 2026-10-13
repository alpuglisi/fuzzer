"""BUG-0061 / PA-0063: readers of the shared `model` table must pick the deployed model of
the right *family* for the right *run* — never "the newest row of any kind".

The classifier and the ranker both write `model` rows; every run trains its own. These
tests pin the shared run-scoped reader (`fuzzlab.ml.model_registry.select_latest`), the
two web readers that used to inline "newest row", and a source-scan guard so the inline
pattern cannot come back (CC-ML-0011, CC-UI-0034).
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from fuzzlab.core.store import Store
from fuzzlab.ml import model_registry
from fuzzlab.ml.rank_train import RANKER_MODEL_NAMES, latest_ranker, train_and_rank
from fuzzlab.ml.train import (_MODELS, CLASSIFIER_MODEL_NAMES, PREVALENCE_FALLBACK_NAME,
                              latest_classifier, train_and_score)
from fuzzlab.web import mlview
from fuzzlab.web.results import _scored_candidates
from tests.test_ml_train import _seed_rich

REPO = Path(__file__).resolve().parent.parent


def _model(store, name, calibration, version=1):
    store.conn.execute(
        "INSERT INTO model (name, version, feature_version, calibration) VALUES (?,?,?,?)",
        (name, version, 1, calibration if isinstance(calibration, str)
         else json.dumps(calibration)))
    store.conn.commit()


# --- family / name constants (PA-0001/PA-0027: derived, not restated) -------

def test_classifier_names_derive_from_the_model_registry():
    assert CLASSIFIER_MODEL_NAMES == tuple(_MODELS) + (PREVALENCE_FALLBACK_NAME,)


def test_classifier_and_ranker_names_are_disjoint():
    assert not set(CLASSIFIER_MODEL_NAMES) & set(RANKER_MODEL_NAMES)


# --- select_latest scope rules ----------------------------------------------

def test_select_latest_scope_rules(tmp_path):
    with Store(tmp_path / "s.db") as store:
        assert model_registry.select_latest(store, ["logistic"], 1,
                                             score_column="score") is None   # empty
        _model(store, "logistic", {"run_id": 1, "tag": "r1"}, 1)
        _model(store, "logistic", {"run_id": 2, "tag": "r2"}, 2)
        _model(store, "ranker", {"run_id": 1, "tag": "rank"}, 1)
        pick = lambda run: model_registry.select_latest(store, ["logistic"], run,
                                                        score_column="score")
        assert pick(1)[1]["tag"] == "r1"            # its own run, not the newer run 2
        assert pick(2)[1]["tag"] == "r2"
        assert pick(None)[1]["tag"] == "r2"         # any run -> newest of the family
        assert pick(3) is None                      # nothing covers run 3
        # a store-wide train covers exactly the runs it scored (BUG-0074): runs 1 and 3,
        # never a later run 4 it never saw — the pinned "covers everything" was the bug
        _model(store, "logistic", {"run_id": None, "scored_run_ids": [1, 3],
                                   "tag": "all"}, 3)
        assert pick(1)[1]["tag"] == "all"           # newest covering row wins
        assert pick(3)[1]["tag"] == "all"
        assert pick(2)[1]["tag"] == "r2"            # not scored by it: its own row
        assert pick(4) is None
        assert model_registry.select_latest(store, ["ranker"], 2,
                                            score_column="rank_score") is None  # family-only


def _scored_run(store, *, score=None, rank_score=None) -> int:
    run_id = store.start_run("auto", "h")
    store.conn.execute("INSERT INTO candidate (run_id, evidence, score, rank_score) "
                       "VALUES (?, '{}', ?, ?)", (run_id, score, rank_score))
    store.conn.commit()
    return run_id


def test_select_latest_legacy_and_malformed_calibration(tmp_path):
    """A legacy row (no `run_id` key) or a store-wide row without `scored_run_ids` covers
    a run only when the run holds a stored score in the family's column (BUG-0074): the
    old behaviour credited it to every run, even one never scored."""
    with Store(tmp_path / "s.db") as store:
        scored = _scored_run(store, score=0.4)                     # classifier-scored
        ranked = _scored_run(store, rank_score=0.7)                # ranker-only
        bare = _scored_run(store)                                  # never scored
        _model(store, "logistic", {"t_lo": 0.2, "t_hi": 0.8})      # legacy: no run_id key
        pick = lambda run, names=("logistic",): model_registry.select_latest(
            store, list(names), run, score_column="score")
        assert pick(scored)[1]["t_hi"] == 0.8        # a scored run keeps old behavior
        assert pick(ranked) is None and pick(bare) is None
        _model(store, "ranker", {"run_id": None})                  # store-wide, no list
        rank_pick = lambda run: model_registry.select_latest(
            store, ["ranker"], run, score_column="rank_score")
        assert rank_pick(ranked) is not None and rank_pick(scored) is None
        assert rank_pick(bare) is None
        _model(store, "gbt", "not json", scored)
        row, calib = pick(scored, ("logistic", "gbt"))
        assert row["name"] == "gbt" and calib == {}
        assert pick(scored, ()) is None
        with pytest.raises(ValueError):
            model_registry.select_latest(store, ["logistic"], scored, score_column="evidence")
        with pytest.raises(TypeError):                             # required keyword
            model_registry.select_latest(store, ["logistic"], scored)


# --- the classifier reader --------------------------------------------------

def test_latest_classifier_ignores_a_later_ranker_row(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        trained = train_and_score(store, run_id, model_kind="auto")
        train_and_rank(store, run_id)                  # writes a newer `model` row
        clf = latest_classifier(store, run_id)
        assert clf.name == trained["model"] and clf.name in CLASSIFIER_MODEL_NAMES
        assert clf.gate is not None
        assert clf.calibration["run_id"] == run_id
        assert clf.calibration["oof_pr_auc"] == trained["pr_auc"]
        assert clf.calibration["oof_pr_auc_prevalence"] == trained["baseline_prevalence"]
        ranker = latest_ranker(store, run_id)
        assert ranker[0]["name"] == "ranker" and ranker[1]["run_id"] == run_id


def test_latest_classifier_none_when_only_a_ranker_trained(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        train_and_rank(store, run_id)
        assert latest_classifier(store, run_id) is None


def test_fallback_classifier_has_no_gate_and_no_oof(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        assert train_and_score(store, run_id)["fallback"] is True     # empty -> thin
        clf = latest_classifier(store, run_id)
        assert clf.name == PREVALENCE_FALLBACK_NAME and clf.gate is None
        assert not any(k.startswith("oof_") for k in clf.calibration)


# --- the web readers (the bug's observable symptom) -------------------------

def test_run_page_keeps_the_conformal_decision_after_ranking(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        train_and_score(store, run_id, model_kind="auto")
        before_model, before = _scored_candidates(store, run_id)
        train_and_rank(store, run_id)                  # `fuzzlab auto --score --rank`
        model, scored = _scored_candidates(store, run_id)
        assert model["name"] == before_model["name"] != "ranker"
        assert [s["decision"] for s in scored] == [s["decision"] for s in before]
        assert {s["decision"] for s in scored} <= {"flag", "abstain", "drop"}
        panel = mlview.conformal_panel(store, run_id)
        assert panel["available"] is True and panel["model"]["name"] == model["name"]


def test_each_run_page_uses_its_own_classifier(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run1 = _seed_rich(store)
        train_and_score(store, run1)
        run2 = _seed_rich(store)
        train_and_score(store, run2)                   # newer row, other run
        assert _scored_candidates(store, run1)[0]["calibration"]["run_id"] == run1
        assert _scored_candidates(store, run2)[0]["calibration"]["run_id"] == run2
        assert mlview.conformal_panel(store, run1)["model"]["version"] == 1
        assert mlview.conformal_panel(store, run2)["model"]["version"] == 2


def test_conformal_panel_reasons(tmp_path):
    with Store(tmp_path / "a.db") as store:
        run_id = _seed_rich(store)
        train_and_rank(store, run_id)
        assert mlview.conformal_panel(store, run_id)["reason"] == "no trained classifier yet"
        _model(store, PREVALENCE_FALLBACK_NAME, {"run_id": run_id})
        assert (mlview.conformal_panel(store, run_id)["reason"]
                == "latest classifier has no conformal calibration")


# --- guard: no inline "newest row" read of `model` anywhere (PA-0063) -------

_FROM_MODEL = re.compile(r"\bFROM\s+model\b", re.I)
# "newest row" shapes: ORDER BY … DESC, LIMIT 1, and MAX(version) (BUG-0066: the
# per-run report's `MAX(version) … GROUP BY name` was the same mistake in another shape)
_NEWEST = re.compile(r"\bDESC\b|\bLIMIT\s+1\b|\bMAX\s*\(\s*version\s*\)", re.I)
_BY_NAME = re.compile(r"\bWHERE\s+name\b", re.I)


def _is_unfiltered_newest_model_read(sql: str) -> bool:
    return bool(_FROM_MODEL.search(sql) and _NEWEST.search(sql)
                and not _BY_NAME.search(sql))


def _strings(tree: ast.AST):
    """Every string a module builds: constants (the parser already joins adjacent
    literals) and f-strings (formatted parts replaced by a placeholder)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            yield node, "".join(v.value if isinstance(v, ast.Constant) else "{}"
                                for v in node.values)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node, node.value


def _offenders(source: str, exempt: tuple[str, ...] = ()) -> list[str]:
    tree = ast.parse(source)
    skip: set[int] = set()
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef) and fn.name in exempt:
            skip |= {id(n) for n in ast.walk(fn)}
    return [s for node, s in _strings(tree)
            if id(node) not in skip and _is_unfiltered_newest_model_read(s)]


def test_guard_catches_the_buggy_shapes():           # PA-0034(2): prove it on bad input
    buggy = [
        'q = "SELECT name, version, calibration FROM model ORDER BY id DESC LIMIT 1"',
        'q = ("SELECT name, calibration FROM model "\n     "ORDER BY id DESC LIMIT 1")',
        'q = f"SELECT {cols} FROM model ORDER BY id DESC"',
        'q = "select * from model limit 1"',
        # the old per-run report query (BUG-0066)
        'q = ("SELECT name, MAX(version) AS version, feature_version FROM model "\n'
        '     "GROUP BY name ORDER BY name")',
    ]
    for src in buggy:
        assert _offenders(src), src


def test_guard_ignores_legitimate_model_queries():   # PA-0022: no false positives
    fine = [
        # diagnostics.model_registry_timeline (lists every row on purpose)
        'q = ("SELECT name, version, feature_version, calibration, created_at FROM model "\n'
        '     "ORDER BY created_at, id")',
        # train._next_version (the ranker shares it via train._insert_model)
        'q = "SELECT MAX(version) v FROM model WHERE name=?"',
        # a different table whose name merely starts with "model"
        'q = "SELECT * FROM model_variant ORDER BY id DESC LIMIT 1"',
        # the shared selector's own query shape
        'q = f"SELECT id FROM model WHERE name IN ({marks}) ORDER BY id DESC"',
    ]
    for src in fine:
        assert not _offenders(src), src


def test_no_module_reads_model_as_newest_row_of_any_family():
    offenders = {}
    for path in sorted((REPO / "fuzzlab").rglob("*.py")):
        exempt = ("select_latest",) if path.name == "model_registry.py" else ()
        found = _offenders(path.read_text(encoding="utf-8"), exempt)
        if found:
            offenders[str(path.relative_to(REPO))] = found
    assert offenders == {}, ("read `model` through fuzzlab.ml.model_registry."
                             "select_latest, never as the newest row (BUG-0061)")


def test_family_readers_delegate_to_the_shared_selector():
    for rel, fn_name in (("fuzzlab/ml/train.py", "latest_classifier"),
                         ("fuzzlab/ml/rank_train.py", "latest_ranker")):
        tree = ast.parse((REPO / rel).read_text(encoding="utf-8"))
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == fn_name)
        assert not any(_FROM_MODEL.search(s) for _, s in _strings(fn)), rel
        assert any(isinstance(n, ast.Name) and n.id == "select_latest"
                   for n in ast.walk(fn)), rel


def test_a_store_wide_train_covers_exactly_the_runs_it_scored(tmp_path):
    """BUG-0074: a store-wide classifier and ranker record `scored_run_ids`; a run with no
    candidates at training time, and a later run, are never credited to them (the
    report and run page used to cite the store-wide model for both)."""
    from fuzzlab.report.report import build_report
    with Store(tmp_path / "a.db") as store:
        r1 = _seed_rich(store)
        empty = store.start_run("auto", "h")                # <= the newest, no candidates
        train_and_score(store, None)
        train_and_rank(store, None)
        later = _seed_rich(store)                           # after the train
        clf, ranker = latest_classifier(store, r1), latest_ranker(store, r1)
        assert clf.calibration["scored_run_ids"] == [r1]
        assert ranker[1]["scored_run_ids"] == [r1]
        for run in (empty, later):
            assert latest_classifier(store, run) is None and latest_ranker(store, run) is None
            assert build_report(store, run)["models"] == []
        assert {m["name"] for m in build_report(store, r1)["models"]} == {
            clf.name, ranker[0]["name"]}


def test_each_family_reader_backs_a_legacy_row_with_its_own_score_column(tmp_path):
    """`latest_classifier` reads `score`, `latest_ranker` `rank_score` (BUG-0074): a
    scope-less legacy row is credited only to a run holding that family's score."""
    with Store(tmp_path / "s.db") as store:
        scored = _scored_run(store, score=0.4)
        ranked = _scored_run(store, rank_score=0.7)
        _model(store, "logistic", {})
        _model(store, "ranker", {})
        assert latest_classifier(store, scored) is not None
        assert latest_classifier(store, ranked) is None
        assert latest_ranker(store, ranked) is not None
        assert latest_ranker(store, scored) is None
