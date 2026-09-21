"""Uniform scheduler: the Phase 4 control condition.

Selects an arm uniformly at random and ignores feedback. The bandit's value is only
meaningful relative to this baseline, so the Phase 4 exit measures the bandit against
`UniformScheduler` on hits-per-N-requests over held-out pages.
"""

from __future__ import annotations

import random
from typing import Iterable


class UniformScheduler:
    def __init__(self, rng: random.Random | None = None):
        self._rng = rng or random.Random()

    def select(self, context: str, arms: Iterable[str]) -> str:
        arms = list(arms)
        if not arms:
            raise ValueError("select() needs at least one arm")
        return self._rng.choice(arms)

    def order(self, context: str, arms: Iterable[str]) -> list[str]:
        """A random ordering (control): learns nothing, just shuffles."""
        arms = list(arms)
        self._rng.shuffle(arms)
        return arms

    def update(self, context: str, arm: str, reward: float) -> None:
        """Control: learns nothing from feedback (by design)."""
        return None
