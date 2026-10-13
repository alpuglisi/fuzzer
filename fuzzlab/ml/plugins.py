"""The ML stages as built-in plugins (CC-ML-0017, FR-ML-6).

ML attaches to the toolkit only through plugin hooks: the classifier, ranker and anomaly
tripwire are `after_run` plugins (they score a finished run; never labels), and the
budget prioritizer is a `register_prioritizer` plugin (it orders oracle work). The
harness never imports this package directly — `fuzzlab auto`'s flags reach it through
`fuzzlab.plugins.optional.import_ml` and `stage_plugins`, so a build without
`fuzzlab.ml` still scans, reports and serves the web app.

Each plugin is a plain object: ``name`` / ``version`` / ``priority`` and a ``config`` dict
of its options (recorded on the run, migration 15). ``version`` names the stage's option
semantics; the trained model's own identity is its ``params_sha256`` (FR-ML-13), which the
stage's result carries. The post-run hooks run under the advisory write guard
(`fuzzlab.plugins.guard`): these stages only INSERT into `model` / `run_metrics` /
`metric_series` and UPDATE the advisory `candidate` columns.
"""

from __future__ import annotations

import json
from functools import partial

#: Bumped when a stage's options change meaning (not when a model retrains).
ML_PLUGIN_VERSION = "2"     # 2: run-mode out-of-fold columns; no_confirmer unlabelled


class _Stage:
    version = ML_PLUGIN_VERSION
    name = ""
    priority = 100

    def __init__(self, **config):
        self.config = config


class ClassifierPlugin(_Stage):
    """`fuzzlab auto --score`: train the detection classifier, write advisory scores."""
    flag = "score"     # the `fuzzlab auto` option that attaches it
    name, priority = "ml-classifier", 10

    def __init__(self, train_on: str = "run", model_kind: str = "auto", hybrid: bool = False,
                 model_id: int | None = None):
        super().__init__(train_on=train_on, model_kind=model_kind, hybrid=hybrid)
        if model_id is not None:                  # only when pinned (keeps old configs)
            self.config["model_id"] = model_id

    def after_run(self, store, run_id):
        from fuzzlab.ml.train import train_and_score
        return train_and_score(store, run_id, model_kind=self.config["model_kind"],
                               train_on=self.config["train_on"],
                               hybrid=self.config["hybrid"],
                               model_id=self.config.get("model_id"))


class RankerPlugin(_Stage):
    """`fuzzlab auto --rank`: train the candidate ranker, write advisory rank scores."""
    flag = "rank"     # the `fuzzlab auto` option that attaches it
    name, priority = "ml-ranker", 20

    def __init__(self, train_on: str = "run", model_id: int | None = None):
        super().__init__(train_on=train_on)
        if model_id is not None:
            self.config["model_id"] = model_id

    def after_run(self, store, run_id):
        from fuzzlab.ml.rank_train import train_and_rank
        return train_and_rank(store, run_id, train_on=self.config["train_on"],
                              model_id=self.config.get("model_id"))


class AnomalyPlugin(_Stage):
    """`fuzzlab auto --anomaly`: persist the ECOD tripwire's score/flag per candidate."""
    flag = "anomaly"     # the `fuzzlab auto` option that attaches it
    name, priority = "ml-anomaly", 30

    def __init__(self, contamination: float = 0.1):
        super().__init__(contamination=contamination)

    def after_run(self, store, run_id):
        from fuzzlab.ml.anomaly import detect_anomalies
        result = detect_anomalies(store, run_id, contamination=self.config["contamination"])
        result["top"] = top_flagged(store, result)
        return result


class BudgetPlugin(_Stage):
    """`fuzzlab auto --confirm-budget N`: order the oracle budget (active learning)."""
    flag = "confirm_budget"     # the `fuzzlab auto` option that attaches it
    name, priority = "ml-budget", 10

    def __init__(self, method: str = "score", seed: int = 0):
        super().__init__(method=method, seed=seed)

    def register_prioritizer(self):
        from fuzzlab.ml.active import prioritize
        return partial(prioritize, method=self.config["method"], seed=self.config["seed"])


#: Stage plugin name per `fuzzlab auto` option (each plugin also carries its ``flag``).
STAGE_NAMES = {cls.flag: cls.name for cls in (ClassifierPlugin, RankerPlugin,
                                                AnomalyPlugin, BudgetPlugin)}


def stage_plugins(*, score: bool = False, rank: bool = False, anomaly: bool = False,
                  contamination: float = 0.1, train_on: str = "run", hybrid: bool = False,
                  model_id: int | None = None, ranker_model_id: int | None = None,
                  confirm_budget: int | None = None, budget_method: str = "score",
                  budget_seed: int = 0) -> list:
    """The plugins a set of `fuzzlab auto` options asks for — the one options→plugins
    mapping (PA-0003)."""
    out: list = []
    if confirm_budget is not None:
        out.append(BudgetPlugin(method=budget_method, seed=budget_seed))
    if score:
        out.append(ClassifierPlugin(train_on=train_on, hybrid=hybrid, model_id=model_id))
    if rank:
        out.append(RankerPlugin(train_on=train_on, model_id=ranker_model_id))
    if anomaly:
        out.append(AnomalyPlugin(contamination=contamination))
    return out


def top_flagged(store, anomaly: dict, limit: int = 5) -> list[dict]:
    """The most anomalous flagged candidates (path, param, category, score)."""
    from fuzzlab.core.urls import to_path
    flagged = sorted(((s, cid) for cid, s, f in zip(anomaly["ids"], anomaly["scores"],
                                                     anomaly["flags"]) if f), reverse=True)
    out = []
    for score, cid in flagged[:limit]:
        row = store.conn.execute("SELECT evidence FROM candidate WHERE id=?", (cid,)).fetchone()
        try:
            ev = json.loads(row["evidence"] or "{}") if row else {}
        except (ValueError, TypeError):
            ev = {}
        out.append({"path": to_path(ev.get("url", "")), "param": ev.get("param", ""),
                    "category": ev.get("category", ""), "score": round(score, 3)})
    return out
