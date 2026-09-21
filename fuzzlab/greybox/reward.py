"""Shaped, multi-tier reward that folds grey-box signals into `attempt.reward`.

Phase 2's reward was a single black-box screening bit (timing/error detected or not).
Phase 3 composes **tiers** so the reward is denser and causal — and so the Phase 4
bandit can weigh them — while preserving the exit property: **a request reaching new
application code produces a distinguishable (strictly higher) reward** than one that
does not, all else equal.

Tiers (kept as separate, well-separated weights so ordering is guaranteed, not a
flattened number):
- **screening** — the black-box hit signal carried over from Phase 2, in [0, 1].
- **coverage novelty** — increases with the number of *new* application lines the
  request reached (saturating, so the first new lines matter most).
- **db_fault** — a database fault, strong corroboration (esp. for SQLi).

The weights are tunable constants; tests assert the ordering/monotonicity
properties, not magic magnitudes (PA-0001).
"""

from __future__ import annotations

from dataclasses import dataclass

# Tier weights. Separated so each tier is individually decisive at the margin.
W_SCREEN: float = 0.40
W_COVERAGE: float = 0.40
W_FAULT: float = 0.20


@dataclass(frozen=True)
class GreyboxSignal:
    """The grey-box signals attributed to one request/attempt."""
    screening: float = 0.0      # black-box hit signal in [0, 1] (Phase 2 carry-over)
    novel_lines: int = 0        # new application lines reached (from the frontier)
    db_fault: bool = False      # a database fault was provoked
    sink_covered: bool = False  # the vulnerable sink's line(s) were executed (M10)


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def novelty_term(novel_lines: int) -> float:
    """Saturating novelty in [0, 1): 0 for no new lines, →1 as new lines grow.

    Strictly increasing in ``novel_lines`` for ``novel_lines >= 0``, so any request
    that reaches new code scores strictly above one that reaches none.
    """
    n = max(0, int(novel_lines))
    return 1.0 - 1.0 / (1.0 + n)


def shaped_reward(signal: GreyboxSignal) -> float:
    """Combine the tiers into a reward in [0, 1]."""
    reward = (
        W_SCREEN * _clamp01(signal.screening)
        + W_COVERAGE * novelty_term(signal.novel_lines)
        + W_FAULT * (1.0 if signal.db_fault else 0.0)
    )
    return round(reward, 6)
