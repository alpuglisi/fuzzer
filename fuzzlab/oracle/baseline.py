"""Robust baselines: median / MAD instead of mean / stddev (Phase 2 T2.2).

A single slow response or one outlier page should not move the jitter band. The
median absolute deviation (MAD), scaled to a robust sigma, resists that far better
than mean/σ — important for a trustworthy differential-timing oracle.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass

_MAD_TO_SIGMA = 1.4826   # makes MAD a consistent estimator of stddev for normal data


def median_abs_deviation(values: list[float], med: float | None = None) -> float:
    med = statistics.median(values) if med is None else med
    return statistics.median([abs(v - med) for v in values])


@dataclass
class Baseline:
    median: float
    mad: float
    n: int

    def robust_sigma(self) -> float:
        return _MAD_TO_SIGMA * self.mad

    def threshold(self, k: float = 3.0, floor: float = 0.0) -> float:
        """A value must exceed this to count as a real deviation.

        ``k`` sigmas above the median, but at least ``median + floor`` (an absolute
        minimum separation, e.g. a minimum added delay for timing).
        """
        return max(self.median + k * self.robust_sigma(), self.median + floor)

    def exceeds(self, value: float, k: float = 3.0, floor: float = 0.0) -> bool:
        return value >= self.threshold(k, floor)


def build_baseline(values: list[float]) -> Baseline:
    if not values:
        raise ValueError("cannot build a baseline from no samples")
    med = statistics.median(values)
    return Baseline(median=med, mad=median_abs_deviation(values, med), n=len(values))
