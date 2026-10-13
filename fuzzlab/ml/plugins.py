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
`metric_series` / `holdout_metric` and UPDATE the advisory `candidate` columns.

New options (``calibrate``, ``holdout``, CC-ML-0020) appear in a stage's config only when
set, so a run without them records exactly the config it always did.
"""

from __future__ import annotations

from functools import partial

#: Bumped when a stage's options change meaning (not when a model retrains).
ML_PLUGIN_VERSION = "2"     # 2: run-mode out-of-fold columns; no_confirmer unlabelled


class _Stage:
    version = ML_PLUGIN_VERSION
    name = ""
    priority = 100

    def __init__(self, **config):
        self.config = config


def _with_held_endpoints(store, run_id, result: dict, config: dict) -> dict:
    """With the holdout on, add how many of the run's endpoints are held out — a
    label-free count, the only holdout fact the summary prints (CC-ML-0020)."""
    if config.get("holdout") and "holdout" in result:
        from fuzzlab.ml.holdout import held_endpoints
        result["holdout"]["endpoints"] = held_endpoints(store, run_id)
    return result


class ClassifierPlugin(_Stage):
    """`fuzzlab auto --score`: train the detection classifier, write advisory scores."""
    flag = "score"     # the `fuzzlab auto` option that attaches it
    name, priority = "ml-classifier", 10

    def __init__(self, train_on: str = "run", model_kind: str = "auto", hybrid: bool = False,
                 model_id: int | None = None, calibrate: str = "none",
                 holdout: bool = False):
        super().__init__(train_on=train_on, model_kind=model_kind, hybrid=hybrid)
        if model_id is not None:                  # only when pinned (keeps old configs)
            self.config["model_id"] = model_id
        if calibrate != "none":
            self.config["calibrate"] = calibrate
        if holdout:
            self.config["holdout"] = True

    def after_run(self, store, run_id):
        from fuzzlab.ml.train import train_and_score
        result = train_and_score(store, run_id, model_kind=self.config["model_kind"],
                               train_on=self.config["train_on"],
                               hybrid=self.config["hybrid"],
                               model_id=self.config.get("model_id"),
                               calibrate=self.config.get("calibrate", "none"),
                               holdout=self.config.get("holdout", False))
        return _with_held_endpoints(store, run_id, result, self.config)


class RankerPlugin(_Stage):
    """`fuzzlab auto --rank`: train the candidate ranker, write advisory rank scores."""
    flag = "rank"     # the `fuzzlab auto` option that attaches it
    name, priority = "ml-ranker", 20

    def __init__(self, train_on: str = "run", model_id: int | None = None,
                 holdout: bool = False, objective: str = "pointwise"):
        super().__init__(train_on=train_on)
        if model_id is not None:
            self.config["model_id"] = model_id
        if holdout:
            self.config["holdout"] = True
        if objective != "pointwise":              # only when not the default (CC-ML-0021)
            self.config["objective"] = objective

    def after_run(self, store, run_id):
        from fuzzlab.ml.rank_train import train_and_rank
        result = train_and_rank(store, run_id, train_on=self.config["train_on"],
                                model_id=self.config.get("model_id"),
                                holdout=self.config.get("holdout", False),
                                objective=self.config.get("objective", "pointwise"))
        return _with_held_endpoints(store, run_id, result, self.config)


class AnomalyPlugin(_Stage):
    """`fuzzlab auto --anomaly`: persist the ECOD tripwire's score/flag per candidate."""
    flag = "anomaly"     # the `fuzzlab auto` option that attaches it
    name, priority = "ml-anomaly", 30

    def __init__(self, contamination: float = 0.1, method: str = "ecod"):
        super().__init__(contamination=contamination)
        if method != "ecod":                      # only when not the default (CC-ML-0021)
            self.config["method"] = method

    def after_run(self, store, run_id):
        from fuzzlab.ml.anomaly import detect_anomalies
        from fuzzlab.core.anomaly_flags import top_flagged
        result = detect_anomalies(store, run_id, contamination=self.config["contamination"],
                                  method=self.config.get("method", "ecod"))
        result["top"] = top_flagged(store, run_id)
        return result


class BudgetPlugin(_Stage):
    """`fuzzlab auto --confirm-budget N`: order the oracle budget (active learning)."""
    flag = "confirm_budget"     # the `fuzzlab auto` option that attaches it
    name, priority = "ml-budget", 10

    def __init__(self, method: str = "score", seed: int = 0, holdout: bool = False):
        super().__init__(method=method, seed=seed)
        if holdout:
            self.config["holdout"] = True

    def register_prioritizer(self):
        from fuzzlab.ml.active import prioritize
        return partial(prioritize, method=self.config["method"], seed=self.config["seed"],
                       holdout=self.config.get("holdout", False))


#: Stage plugin name per `fuzzlab auto` option (each plugin also carries its ``flag``).
STAGE_NAMES = {cls.flag: cls.name for cls in (ClassifierPlugin, RankerPlugin,
                                                AnomalyPlugin, BudgetPlugin)}


def stage_plugins(*, score: bool = False, rank: bool = False, anomaly: bool = False,
                  contamination: float = 0.1, train_on: str = "run", hybrid: bool = False,
                  model_id: int | None = None, ranker_model_id: int | None = None,
                  confirm_budget: int | None = None, budget_method: str = "score",
                  budget_seed: int = 0, calibrate: str = "none",
                  holdout: bool = False, anomaly_method: str = "ecod",
                  rank_objective: str = "pointwise") -> list:
    """The plugins a set of `fuzzlab auto` options asks for — the one options→plugins
    mapping (PA-0003)."""
    out: list = []
    if confirm_budget is not None:
        out.append(BudgetPlugin(method=budget_method, seed=budget_seed, holdout=holdout))
    if score:
        out.append(ClassifierPlugin(train_on=train_on, hybrid=hybrid, model_id=model_id,
                                    calibrate=calibrate, holdout=holdout))
    if rank:
        out.append(RankerPlugin(train_on=train_on, model_id=ranker_model_id,
                                holdout=holdout, objective=rank_objective))
    if anomaly:
        out.append(AnomalyPlugin(contamination=contamination, method=anomaly_method))
    return out
