"""Beta-Bernoulli Thompson-sampling bandit over payload families (Phase 4).

One Beta posterior per (context, arm). `select` samples each candidate arm's posterior
and plays the highest draw (Thompson sampling — explores in proportion to uncertainty);
`update` folds a reward in [0, 1] into that arm's posterior. Catalog priors seed arms
that are known to pay off for a context. Posteriors persist in the `bandit_posteriors`
table so learning carries across runs.

Deterministic: the RNG is injected, so tests seed it and assert exact behavior.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterable, Mapping


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else float(x)


@dataclass
class Beta:
    """A Beta(alpha, beta) posterior for one arm's success probability."""
    alpha: float = 1.0
    beta: float = 1.0

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    def update(self, reward: float) -> None:
        r = _clamp01(reward)                 # fractional reward splits the trial
        self.alpha += r
        self.beta += 1.0 - r


class ThompsonBandit:
    def __init__(self, rng: random.Random | None = None,
                 priors: Mapping[str, tuple[float, float]] | None = None):
        self._rng = rng or random.Random()
        self._priors = dict(priors or {})    # arm -> (alpha, beta) catalog prior
        self._post: dict[tuple[str, str], Beta] = {}

    def _posterior(self, context: str, arm: str) -> Beta:
        key = (context, arm)
        if key not in self._post:
            a, b = self._priors.get(arm, (1.0, 1.0))
            self._post[key] = Beta(a, b)
        return self._post[key]

    def select(self, context: str, arms: Iterable[str]) -> str:
        """Thompson sampling: draw each arm's posterior, play the highest."""
        best, best_sample = None, -1.0
        for arm in arms:
            p = self._posterior(context, arm)
            sample = self._rng.betavariate(p.alpha, p.beta)
            if sample > best_sample:
                best_sample, best = sample, arm
        if best is None:
            raise ValueError("select() needs at least one arm")
        return best

    def update(self, context: str, arm: str, reward: float) -> None:
        self._posterior(context, arm).update(reward)

    def mean(self, context: str, arm: str) -> float:
        return self._posterior(context, arm).mean

    def best_arm(self, context: str, arms: Iterable[str]) -> str:
        """The exploitation choice: highest posterior mean (no exploration)."""
        return max(arms, key=lambda a: self._posterior(context, a).mean)

    # -- persistence (bandit_posteriors table) ---------------------------------
    def load(self, store) -> "ThompsonBandit":
        for r in store.conn.execute(
            "SELECT context, arm, alpha, beta FROM bandit_posteriors").fetchall():
            self._post[(r["context"], r["arm"])] = Beta(r["alpha"], r["beta"])
        return self

    def save(self, store) -> None:
        for (context, arm), p in self._post.items():
            store.conn.execute(
                "INSERT INTO bandit_posteriors (context, arm, alpha, beta, updated_at) "
                "VALUES (?,?,?,?, datetime('now')) "
                "ON CONFLICT(context, arm) DO UPDATE SET "
                "alpha=excluded.alpha, beta=excluded.beta, updated_at=excluded.updated_at",
                (context, arm, p.alpha, p.beta))
        store.conn.commit()
