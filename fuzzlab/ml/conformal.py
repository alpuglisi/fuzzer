"""Split-conformal triage: turn advisory scores into flag / abstain / drop (Phase 5).

Calibrate two thresholds on a held-out calibration set at a target error rate ``alpha``,
with the **finite-sample split-conformal** order statistics (CC-ML-0019, BUG-0070):

- **flag** a score strictly above ``q_hi``, the ``ceil((n+1)(1-alpha))``-th smallest of
  the n *negative* calibration scores — at most ``alpha·n`` of them are flagged (ties
  included), and a new exchangeable negative is flagged with probability ≤ ``alpha``;
- **drop** a score strictly below ``q_lo``, the ``floor((m+1)alpha)``-th smallest of the
  m *positive* calibration scores — at most ``alpha·m`` dropped, ≤ ``alpha`` on new data.

When that order statistic does not exist (fewer than `min_class_size` rows of a class)
the gate **never flags** / **never drops**: no threshold could keep the bound.

`decide` compares ``>= t_hi`` / ``<= t_lo``, unchanged since the first gate, so every
stored model's thresholds keep their meaning. The strict inequalities are stored as
thresholds: ``t_hi = nextafter(q_hi, +inf)``, ``t_lo = nextafter(q_lo, -inf)`` (for
floats ``s >= nextafter(q, inf)`` ⟺ ``s > q``); "never" is ``nextafter(1.0, inf)`` /
``nextafter(0.0, -inf)``, which no probability reaches. Gates calibrated before
CC-ML-0019 used ``round(q·(n-1))`` with ``>=`` and could exceed ``alpha`` by about 1/n;
their rows lack ``gate_rule`` (`GATE_RULE`) and are labelled by the readers.

Scores between the thresholds are **abstained** (handed to a human / the oracle). The
model never confirms (that stays the oracle's job).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction
from typing import Sequence

#: Recorded as ``calibration["gate_rule"]`` by every gate calibrated with this rule.
GATE_RULE = "split-conformal"
NEVER_FLAG = math.nextafter(1.0, math.inf)       # above every probability
NEVER_DROP = math.nextafter(0.0, -math.inf)      # below every probability


def check_alpha(alpha) -> Fraction:
    if not (isinstance(alpha, (int, float)) and not isinstance(alpha, bool)
            and 0 < alpha < 1):
        raise ValueError(f"alpha must be in (0, 1), got {alpha!r}")
    return Fraction(alpha)                       # the exact binary value of alpha


def upper_index(n: int, alpha: float) -> int | None:
    """1-based rank ``ceil((n+1)(1-alpha))`` of the flag order statistic among ``n``
    negatives, computed exactly; ``None`` when it exceeds ``n`` (never flag)."""
    a = check_alpha(alpha)
    k = math.ceil((n + 1) * (1 - a))
    return k if 1 <= k <= n else None


def lower_index(m: int, alpha: float) -> int | None:
    """1-based rank ``floor((m+1)alpha)`` of the drop order statistic among ``m``
    positives, computed exactly; ``None`` when it is 0 (never drop)."""
    a = check_alpha(alpha)
    k = math.floor((m + 1) * a)
    return k if 1 <= k <= m else None


def min_class_size(alpha: float) -> int:
    """The fewest rows of a class for which the gate can flag (negatives) or drop
    (positives) at all: ``ceil(1/alpha) - 1`` — both sides need ``(n+1)·alpha ≥ 1``."""
    a = check_alpha(alpha)
    return math.ceil(1 / a) - 1


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
        """Thresholds from the calibration scores (see the module docstring). Raises
        ``ValueError`` unless ``0 < alpha < 1``."""
        check_alpha(alpha)
        pos = sorted(s for s, y in zip(scores, labels) if y)
        neg = sorted(s for s, y in zip(scores, labels) if not y)
        k_hi = upper_index(len(neg), alpha)
        k_lo = lower_index(len(pos), alpha)
        t_hi = NEVER_FLAG if k_hi is None else math.nextafter(neg[k_hi - 1], math.inf)
        t_lo = NEVER_DROP if k_lo is None else math.nextafter(pos[k_lo - 1], -math.inf)
        if t_lo > t_hi:                  # overlap: swapping only shrinks both sets
            t_lo, t_hi = t_hi, t_lo
        return cls(t_lo=t_lo, t_hi=t_hi)
