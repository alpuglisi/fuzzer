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
        assert model_registry.select_latest(store, ["logistic"], 1) is None   # empty
        _model(store, "logistic", {"run_id": 1, "tag": "r1"}, 1)
        _model(store, "logistic", {"run_id": 2, "tag": "r2"}, 2)
        _model(store, "ranker", {"run_id": 1, "tag": "rank"}, 1)
        pick = lambda run: model_registry.select_latest(store, ["logistic"], run)
        assert pick(1)[1]["tag"] == "r1"            # its own run, not the newer run 2
        assert pick(2)[1]["tag"] == "r2"
        assert pick(None)[1]["tag"] == "r2"         # any run -> newest of the family
        assert pick(3) is None                      # nothing covers run 3
        _model(store, "logistic", {"run_id": None, "tag": "all"}, 3)  # store-wide train
        assert pick(1)[1]["tag"] == "all"           # newest covering row wins
        assert pick(3)[1]["tag"] == "all"
        assert model_registry.select_latest(store, ["ranker"], 2) is None   # family-only


def test_select_latest_legacy_and_malformed_calibration(tmp_path):
    with Store(tmp_path / "s.db") as store:
        _model(store, "logistic", {"t_lo": 0.2, "t_hi": 0.8})      # legacy: no run_id key
        row, calib = model_registry.select_latest(store, ["logistic"], 7)
        assert calib["t_hi"] == 0.8                  # legacy rows keep old behavior
        _model(store, "gbt", "not json", 1)
        row, calib = model_registry.select_latest(store, ["logistic", "gbt"], 7)
        assert row["name"] == "gbt" and calib == {}
        assert model_registry.select_latest(store, [], 7) is None


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
