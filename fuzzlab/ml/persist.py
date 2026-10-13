"""Saving and reloading trained models (CC-ML-0015, FR-ML-13).

A trained model is stored in its `model` row as **canonical JSON** plus the sha256 of
exactly that text (migration 14). This module is the one home of that convention
(PA-0003): every writer goes through `dumps_model`, every reader through `loads_model`.

Envelope (format 1)::

    {"format": 1, "kind": <logistic|gbt|prevalence|ranker|constant>,
     "feature_names": [...], "feature_version": <int>, "params": {...}, "ecod": {...}|null}

Format 2 (CC-ML-0020, FR-ML-20) is format 1 plus ``"calibrator": {"kind": "platt", "a",
"b"}`` — written **only** when a classifier carries a probability calibrator, so a model
without one keeps its format-1 text and sha byte-identical. Each format has its own
exact key set; a calibrator is allowed only on the ``logistic`` / ``gbt`` kinds and must
be a strictly increasing Platt map (finite ``a > 0``, finite ``b``).

* Canonical text — ``sort_keys``, compact separators, ``allow_nan=False`` — so the same
  model always yields the same sha, and finite floats round-trip exactly.
* The loader **fails closed** with `ModelParamsError` on anything it cannot prove well
  formed: a sha mismatch, non-text or non-JSON input (a pickle payload included),
  NaN/Infinity, runaway nesting, an unknown format or kind, wrong types, inconsistent
  lengths, malformed trees, unsorted ECOD columns (PA-0021: one typed error at the
  boundary, never a raw library exception).
* No ``pickle``/``marshal``/``eval``: a store file can travel between machines, and
  unpickling it would be arbitrary code execution (CWE-502).
* The sha detects corruption and pins a model's identity for reproducibility. It is
  **not** authentication — anyone who can write the store can recompute it.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Sequence

FORMAT = 1                       # the envelope written when there is no calibrator
FORMAT_CALIBRATED = 2            # format 1 + a "calibrator" key (CC-ML-0020)
_ENVELOPE_KEYS = {"format", "kind", "feature_names", "feature_version", "params", "ecod"}
CALIBRATED_KINDS = ("logistic", "gbt")
CLASSIFIER_KINDS = ("logistic", "gbt", "prevalence")
RANKER_KINDS = ("ranker", "constant")
KINDS = CLASSIFIER_KINDS + RANKER_KINDS
ANOMALY_FEATURE = "anomaly_ecod"


class ModelParamsError(ValueError):
    """Stored model params are missing, corrupted, or not a well-formed model."""


class ModelIncompatibleError(ValueError):
    """A well-formed stored model does not match the current feature layout."""


# --- canonical text + sha ---------------------------------------------------------

def _canonical(obj: Any) -> str:
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except ValueError as exc:                    # NaN / Infinity in a fitted model
        raise ModelParamsError(f"model has a non-finite value: {exc}") from None


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def committee_sha(member_shas: Sequence[str]) -> str:
    """Identity of a bootstrap committee: its members' ranker shas, in member order."""
    return _sha("committee/1:" + ",".join(member_shas))


# --- validation -------------------------------------------------------------------

def _fail(msg: str):
    raise ModelParamsError(msg)


def _is_num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _keys(d, expected: set[str], what: str) -> None:
    if not isinstance(d, dict) or set(d) != expected:
        _fail(f"{what}: expected keys {sorted(expected)}, got "
              f"{sorted(d) if isinstance(d, dict) else type(d).__name__}")


def _nums(x, what: str, n: int | None = None) -> None:
    if not isinstance(x, list) or not all(_is_num(v) for v in x):
        _fail(f"{what}: expected a list of finite numbers")
    if n is not None and len(x) != n:
        _fail(f"{what}: expected {n} values, got {len(x)}")


def _check_logistic(p, width: int, what: str = "logistic") -> None:
    _keys(p, {"epochs", "lr", "l2", "class_balanced", "w", "b", "mean", "std"}, what)
    if not (_is_int(p["epochs"]) and _is_num(p["lr"]) and _is_num(p["l2"])
            and isinstance(p["class_balanced"], bool) and _is_num(p["b"])):
        _fail(f"{what}: bad hyperparameter or bias types")
    for k in ("w", "mean", "std"):                 # all equal to the feature width
        _nums(p[k], f"{what}.{k}", width)
    if any(s == 0 for s in p["std"]):
        _fail(f"{what}.std: zero standard deviation")


def _check_tree(node, width: int, depth: int, max_depth: int) -> None:
    if depth > max_depth:
        _fail(f"gbt tree deeper than max_depth={max_depth}")
    if isinstance(node, dict) and set(node) == {"v"}:
        if not _is_num(node["v"]):
            _fail("gbt leaf value is not a finite number")
        return
    _keys(node, {"f", "t", "l", "r"}, "gbt split node")
    if not (_is_int(node["f"]) and 0 <= node["f"] < width):
        _fail(f"gbt split feature {node['f']!r} outside 0..{width - 1}")
    if not _is_num(node["t"]):
        _fail("gbt split threshold is not a finite number")
    _check_tree(node["l"], width, depth + 1, max_depth)
    _check_tree(node["r"], width, depth + 1, max_depth)


def _check_gbt(p, width: int) -> None:
    _keys(p, {"n_estimators", "lr", "max_depth", "min_leaf", "class_balanced", "f0",
              "trees"}, "gbt")
    if not (_is_int(p["n_estimators"]) and _is_num(p["lr"]) and _is_int(p["max_depth"])
            and _is_int(p["min_leaf"]) and isinstance(p["class_balanced"], bool)
            and _is_num(p["f0"])):
        _fail("gbt: bad hyperparameter types")
    if not isinstance(p["trees"], list) or len(p["trees"]) != p["n_estimators"]:
        _fail("gbt: tree count does not match n_estimators")
    for t in p["trees"]:
        _check_tree(t, width, 0, p["max_depth"])


def _check_vectorizer(v) -> None:
    _keys(v, {"n", "max_features", "vocab", "idf"}, "vectorizer")
    if not (_is_int(v["n"]) and v["n"] >= 1 and _is_int(v["max_features"])):
        _fail("vectorizer: bad n / max_features")
    vocab = v["vocab"]
    if not (isinstance(vocab, list) and all(isinstance(g, str) for g in vocab)
            and len(set(vocab)) == len(vocab) and len(vocab) <= v["max_features"]):
        _fail("vectorizer.vocab: expected distinct strings, at most max_features")
    _nums(v["idf"], "vectorizer.idf", len(vocab))


def _check_ecod(e, d: int) -> None:
    _keys(e, {"n", "d", "sorted", "skew"}, "ecod")
    if not (_is_int(e["n"]) and e["n"] >= 1 and e["d"] == d):
        _fail(f"ecod: expected n >= 1 and d == {d}")
    if not isinstance(e["sorted"], list) or len(e["sorted"]) != d:
        _fail(f"ecod.sorted: expected {d} columns")
    for j, col in enumerate(e["sorted"]):
        _nums(col, f"ecod.sorted[{j}]", e["n"])
        if any(a > b for a, b in zip(col, col[1:])):
            _fail(f"ecod.sorted[{j}] is not sorted")
    _nums(e["skew"], "ecod.skew", d)


def _check_calibrator(c) -> None:
    _keys(c, {"kind", "a", "b"}, "calibrator")
    if c["kind"] != "platt":
        _fail(f"unknown calibrator kind {c['kind']!r}")
    if not (_is_num(c["a"]) and _is_num(c["b"]) and c["a"] > 0):
        _fail("calibrator: expected finite a > 0 and finite b")


def _validate(env) -> None:
    if not isinstance(env, dict):
        _fail(f"envelope: expected an object, got {type(env).__name__}")
    fmt = env.get("format")
    if fmt == FORMAT and not isinstance(fmt, bool):
        _keys(env, _ENVELOPE_KEYS, "envelope")
    elif fmt == FORMAT_CALIBRATED and not isinstance(fmt, bool):
        _keys(env, _ENVELOPE_KEYS | {"calibrator"}, "envelope (format 2)")
    else:
        _fail(f"unknown params format {fmt!r}")
    kind = env["kind"]
    if kind not in KINDS:
        _fail(f"unknown model kind {kind!r}")
    if fmt == FORMAT_CALIBRATED:
        if kind not in CALIBRATED_KINDS:
            _fail(f"a calibrator is allowed only on {', '.join(CALIBRATED_KINDS)}, "
                  f"not {kind!r}")
        _check_calibrator(env["calibrator"])
    names = env["feature_names"]
    if not (isinstance(names, list) and all(isinstance(n, str) for n in names)):
        _fail("feature_names: expected a list of strings")
    if not _is_int(env["feature_version"]):
        _fail("feature_version: expected an integer")
    p, ecod = env["params"], env["ecod"]
    if kind in CLASSIFIER_KINDS and (bool(names) and names[-1] == ANOMALY_FEATURE) != \
            (ecod is not None):
        _fail("a classifier ends in anomaly_ecod exactly when its ECOD is stored")
    if ecod is not None:
        if kind not in CLASSIFIER_KINDS or not names or names[-1] != ANOMALY_FEATURE:
            _fail("ecod is stored only with a hybrid classifier ending in anomaly_ecod")
        _check_ecod(ecod, len(names) - 1)
    if kind == "logistic":
        _check_logistic(p, len(names))
    elif kind == "gbt":
        _check_gbt(p, len(names))
    elif kind == "prevalence":
        _keys(p, {"rate"}, "prevalence")
        if not (_is_num(p["rate"]) and 0 <= p["rate"] <= 1):
            _fail("prevalence.rate: expected a number in [0, 1]")
    elif kind == "constant":
        _keys(p, {"value"}, "constant")
        if not _is_num(p["value"]):
            _fail("constant.value: expected a finite number")
    else:                                            # ranker
        base = {"seed", "vectorizer", "model", "feature_names"}
        if isinstance(p, dict) and "objective" in p:          # CC-ML-0021: pairwise only
            _keys(p, base | {"objective"}, "ranker")
            if p["objective"] != "pairwise":
                _fail(f"ranker.objective: only 'pairwise' is stored, got {p['objective']!r}")
        else:
            _keys(p, base, "ranker")
        _check_vectorizer(p["vectorizer"])
        vocab = p["vectorizer"]["vocab"]
        if p["feature_names"] != names or names[len(names) - len(vocab):] != \
                [f"ng[{g}]" for g in vocab]:
            _fail("ranker.feature_names must equal the envelope's and end in its vocab")
        _keys(p["model"], {"kind", "params"}, "ranker.model")
        if p["model"]["kind"] != "logistic":
            _fail(f"unsupported ranker model kind {p['model']['kind']!r}")
        _check_logistic(p["model"]["params"], len(names), "ranker.model")


# --- dump / load ------------------------------------------------------------------

def dumps_model(kind: str, model, *, feature_names: Sequence[str], feature_version: int,
                ecod=None, calibrator=None) -> tuple[str, str]:
    """Serialise a fitted model to canonical JSON; return ``(text, sha256)``.

    ``kind="constant"`` takes the constant score itself as ``model``. With a
    ``calibrator`` (a `calibration.PlattScaler`) the envelope is format 2; without one
    it is exactly the format-1 text it always was."""
    params = {"value": model} if kind == "constant" else model.to_params()
    env = {"format": FORMAT, "kind": kind, "feature_names": list(feature_names),
           "feature_version": feature_version, "params": params,
           "ecod": ecod.to_params() if ecod is not None else None}
    if calibrator is not None:
        env.update(format=FORMAT_CALIBRATED, calibrator=calibrator.to_params())
    text = _canonical(env)
    _validate(json.loads(text))                      # never store what we couldn't load
    return text, _sha(text)


def _reject_constant(name: str):
    raise ModelParamsError(f"non-finite number {name} in stored params")


def loads_model(text, sha256: str | None) -> "LoadedModel":
    """Verify and rebuild a stored model. Raises `ModelParamsError` on any doubt."""
    if not isinstance(text, str):
        _fail(f"stored params are {type(text).__name__}, not JSON text")
    try:
        if not isinstance(sha256, str) or _sha(text) != sha256:
            _fail("stored params do not match their sha256 (corrupted or altered)")
        env = json.loads(text, parse_constant=_reject_constant)
        _validate(env)
        return _build(env, sha256)
    except ModelParamsError:
        raise
    except RecursionError:
        _fail("stored params are nested too deeply")
    except (ValueError, TypeError, KeyError) as exc:
        _fail(f"stored params are not a well-formed model: {exc}")


def _build(env: dict, sha256: str) -> "LoadedModel":
    from fuzzlab.ml.anomaly import ECOD
    from fuzzlab.ml.baselines import PrevalenceBaseline
    from fuzzlab.ml.gbt import GradientBoostedTrees
    from fuzzlab.ml.logistic import LogisticRegression
    from fuzzlab.ml.ranker import Ranker
    kind, p = env["kind"], env["params"]
    model: Any = {"logistic": LogisticRegression, "gbt": GradientBoostedTrees,
                  "prevalence": PrevalenceBaseline, "ranker": Ranker}[kind].from_params(p) \
        if kind != "constant" else p["value"]
    ecod = ECOD.from_params(env["ecod"]) if env["ecod"] is not None else None
    calibrator = None
    if env.get("calibrator") is not None:
        from fuzzlab.ml.calibration import PlattScaler
        calibrator = PlattScaler.from_params(env["calibrator"])
    return LoadedModel(kind=kind, model=model, feature_names=list(env["feature_names"]),
                       feature_version=env["feature_version"], ecod=ecod, sha256=sha256,
                       calibrator=calibrator)


@dataclass
class LoadedModel:
    """A stored model, rebuilt. Call `check_compatible` before using it on new data."""
    kind: str
    model: Any
    feature_names: list[str]
    feature_version: int
    ecod: Any = None
    sha256: str | None = None
    calibrator: Any = None              # a `calibration.PlattScaler` (format 2), or None

    def _structural_width(self) -> int:
        if self.kind == "ranker":
            return len(self.feature_names) - len(self.model.vectorizer.vocab)
        return len(self.feature_names) - (1 if self.ecod is not None else 0)

    def check_compatible(self) -> None:
        """Raise `ModelIncompatibleError` unless the stored feature layout is the
        current one. Every model reads features by position, so a reordered or renamed
        feature would otherwise misalign silently."""
        from fuzzlab.ml.dataset import FEATURE_NAMES, FEATURE_VERSION
        if self.feature_version != FEATURE_VERSION:
            raise ModelIncompatibleError(
                f"model trained on feature_version {self.feature_version}, "
                f"current is {FEATURE_VERSION}")
        expected = list(FEATURE_NAMES)
        if self.kind == "ranker":
            expected += self.model.vectorizer.feature_names()
        elif self.ecod is not None:
            expected.append(ANOMALY_FEATURE)
        if self.feature_names != expected:
            raise ModelIncompatibleError("stored feature names differ from the current "
                                         "layout (renamed, reordered, added or removed)")

    def _check_rows(self, X) -> None:
        width = self._structural_width()
        for row in X:
            if len(row) != width:
                raise ModelIncompatibleError(
                    f"feature row has {len(row)} values, the model expects {width}")

    def predict_proba(self, X: Sequence[Sequence[float]]) -> list[float]:
        """Classifier kinds: probabilities for plain `dataset` feature rows — the stored
        ECOD augment (if any), then the model, then the stored calibrator (if any), so a
        reloaded model reproduces the scores it wrote."""
        if self.kind not in CLASSIFIER_KINDS:
            raise TypeError(f"{self.kind!r} is not a classifier")
        self._check_rows(X)
        if self.ecod is not None:
            from fuzzlab.ml.anomaly import augment
            X = augment(X, self.ecod)
        probs = self.model.predict_proba(X)
        return self.calibrator.transform(probs) if self.calibrator is not None else probs

    def score(self, X: Sequence[Sequence[float]], texts: Sequence[str]) -> list[float]:
        """Ranker kinds: rank scores for feature rows + candidate texts."""
        if self.kind not in RANKER_KINDS:
            raise TypeError(f"{self.kind!r} is not a ranker")
        self._check_rows(X)
        if self.kind == "constant":
            return [float(self.model)] * len(X)
        return self.model.score(X, texts)
