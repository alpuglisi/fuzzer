"""Probability calibration of the detection classifier (CC-ML-0019, FR-ML-19).

**Platt scaling only**: ``p = sigmoid(a·logit(s) + b)``, fitted by Newton's method on the
selected model's out-of-fold scores with Platt's target smoothing. Isotonic regression
is deliberately not offered: its plateaus create ties that break the conformal gate's
per-side error bound at a threshold and change PR-AUC, and it overfits at lab data
sizes. The slope is constrained to ``a > 0`` — a strictly monotone map never reorders or
ties scores — and a fit that is degenerate (``a <= 1e-9``) or does not converge is not
applied at all (``fit_platt`` returns ``None``).

Which calibrated values go where (PA-0068):

- ``candidate.score_oof`` holds **cross-fitted** calibrated out-of-fold scores — each
  fold's scores pass through a Platt fitted on the *other* folds' scores — and the
  conformal gate is calibrated on those;
- the Platt fitted on all out-of-fold scores is applied only to the deploy ``score``.
  Its calibration on new data is *expected*, not measured here; the measured one is the
  sealed holdout's ECE/Brier (FR-ML-18).

All-or-nothing: if the full fit or any fold fit is degenerate, no calibration is applied
anywhere (`cross_fit` returns ``None``).
"""

from __future__ import annotations

import math
from typing import Sequence

_EPS = 1e-6                  # scores are clipped to [eps, 1-eps] before the logit
_MIN_SLOPE = 1e-9


def _logit(s: float) -> float:
    s = min(1.0 - _EPS, max(_EPS, s))
    return math.log(s / (1.0 - s))


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class PlattScaler:
    """``sigmoid(a·logit(s) + b)`` with ``a > 0``."""

    def __init__(self, a: float = 1.0, b: float = 0.0):
        self.a, self.b = float(a), float(b)

    def transform(self, scores: Sequence[float]) -> list[float]:
        return [_sigmoid(self.a * _logit(s) + self.b) for s in scores]

    def to_params(self) -> dict:
        return {"kind": "platt", "a": self.a, "b": self.b}

    @classmethod
    def from_params(cls, d: dict) -> "PlattScaler":
        return cls(a=d["a"], b=d["b"])


def fit_platt(scores: Sequence[float], labels: Sequence[int], *, max_iter: int = 100,
              tol: float = 1e-10) -> PlattScaler | None:
    """Fit Platt scaling (Newton on the 2-parameter logistic log-loss, Platt's smoothed
    targets). ``None`` when it is degenerate: one class only, no convergence, a
    non-finite result, or a slope ``a <= 1e-9`` (the map would not be strictly
    increasing)."""
    n_pos = sum(1 for y in labels if y)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    hi, lo = (n_pos + 1.0) / (n_pos + 2.0), 1.0 / (n_neg + 2.0)
    t = [hi if y else lo for y in labels]
    x = [_logit(s) for s in scores]
    a, b = 1.0, 0.0
    for _ in range(max_iter):
        g_a = g_b = h_aa = h_ab = h_bb = 0.0
        for xi, ti in zip(x, t):
            p = _sigmoid(a * xi + b)
            d = p - ti
            w = p * (1.0 - p)
            g_a += d * xi
            g_b += d
            h_aa += w * xi * xi
            h_ab += w * xi
            h_bb += w
        h_aa += 1e-12
        h_bb += 1e-12
        det = h_aa * h_bb - h_ab * h_ab
        if det <= 0 or not math.isfinite(det):
            return None
        step_a = (h_bb * g_a - h_ab * g_b) / det
        step_b = (h_aa * g_b - h_ab * g_a) / det
        a, b = a - step_a, b - step_b
        if not (math.isfinite(a) and math.isfinite(b)):
            return None
        if abs(step_a) < tol and abs(step_b) < tol:
            break
    else:
        return None
    if a <= _MIN_SLOPE:
        return None
    return PlattScaler(a, b)


def cross_fit(scores: Sequence[float], labels: Sequence[int],
              folds) -> list[float] | None:
    """Cross-fitted calibrated scores: each fold's ``scores`` pass through a Platt
    fitted on the other folds' scores. ``folds`` is the ``(train, test)`` index pairs
    the out-of-fold scores came from. ``None`` if any fold fit is degenerate."""
    out = [0.0] * len(scores)
    for train, test in folds:
        platt = fit_platt([scores[i] for i in train], [labels[i] for i in train])
        if platt is None:
            return None
        for i, v in zip(test, platt.transform([scores[i] for i in test])):
            out[i] = v
    return out
