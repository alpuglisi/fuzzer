"""Split-conformal triage: turn advisory scores into flag / abstain / drop (Phase 5).

Calibrate two thresholds on a held-out calibration set at a target error rate ``alpha``:
- ``t_hi`` — the (1-alpha) quantile of *negative* scores, so scores at/above it are
  **flagged** with a bounded false-positive rate;
- ``t_lo`` — the alpha quantile of *positive* scores, so scores at/below it are
  **dropped** with a bounded false-negative rate.

Scores between the thresholds are **abstained** (handed to a human / the oracle). This
keeps the confident automated decisions calibrated and routes the uncertain middle to
review — the model never confirms (that stays the oracle's job).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


def _quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    q = 0.0 if q < 0 else 1.0 if q > 1 else q
    idx = int(round(q * (len(sorted_vals) - 1)))
    return sorted_vals[idx]


@dataclass
class ConformalGate:
    t_lo: float
    t_hi: float

    def decide(self, score: float) -> str:
        if score >= self.t_hi:
            return "flag"
        if score <= self.t_lo:
            return "drop"
        return "abstain"

    @classmethod
    def calibrate(cls, scores: Sequence[float], labels: Sequence[int],
                  alpha: float = 0.1) -> "ConformalGate":
        pos = sorted(s for s, y in zip(scores, labels) if y)
        neg = sorted(s for s, y in zip(scores, labels) if not y)
        # flag above the (1-alpha) quantile of negatives; drop below the alpha quantile
        # of positives. Fall back to [0,1] extremes when a class is absent.
        t_hi = _quantile(neg, 1.0 - alpha) if neg else 1.0
        t_lo = _quantile(pos, alpha) if pos else 0.0
        if t_lo > t_hi:                              # overlap -> abstain-only middle
            t_lo, t_hi = min(t_lo, t_hi), max(t_lo, t_hi)
        return cls(t_lo=t_lo, t_hi=t_hi)
