"""Beta-Bernoulli Thompson-sampling bandit over payload families (Phase 4).

One Beta posterior per (context, arm). `select`/`order` sample each candidate arm's
posterior and prefer the highest draw (Thompson sampling — explores in proportion to
uncertainty); `update` folds a reward in [0, 1] into that arm's posterior. Extras:

- **Cost-normalized selection (T4.4):** each observation records a cost; when
  ``cost_normalized`` is on, ordering divides the sampled reward by the arm's mean cost
  (reward-per-cost), so a cheap informative arm beats an expensive one of equal reward.
- **Hierarchical backoff (T4.5):** when ``backoff`` is on, a fresh (context, arm) is
  seeded from the first coarser context that has data (borrowing strength), then
  specializes.

Posteriors (and costs) persist in `bandit_posteriors`. Deterministic: the RNG is
injected, so tests seed it and assert exact behavior.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterable, Mapping

from fuzzlab.scheduler.context import context_parents


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
                 priors: Mapping[str, tuple[float, float]] | None = None,
                 cost_normalized: bool = False, backoff: bool = False,
                 backoff_strength: float = 2.0, cost_floor: float = 1.0):
        self._rng = rng or random.Random()
        self._priors = dict(priors or {})    # arm -> (alpha, beta) catalog prior
        self._post: dict[tuple[str, str], Beta] = {}
        self._cost: dict[tuple[str, str], list[float]] = {}   # -> [sum, n]
        self._cost_normalized = cost_normalized
        self._backoff = backoff
        self._backoff_strength = backoff_strength
        self._cost_floor = cost_floor

    def _seed(self, context: str, arm: str) -> Beta:
        """Prior for a fresh (context, arm): parent posterior (backoff) else catalog."""
        if self._backoff:
            for parent in context_parents(context):
                p = self._post.get((parent, arm))
                if p is not None:
                    s, m = self._backoff_strength, p.mean
                    return Beta(1.0 + s * m, 1.0 + s * (1.0 - m))
        a, b = self._priors.get(arm, (1.0, 1.0))
        return Beta(a, b)

    def _posterior(self, context: str, arm: str) -> Beta:
        key = (context, arm)
        if key not in self._post:
            self._post[key] = self._seed(context, arm)
        return self._post[key]

    def cost_mean(self, context: str, arm: str) -> float:
        c = self._cost.get((context, arm))
        return c[0] / c[1] if c and c[1] else self._cost_floor

    def _score(self, context: str, arm: str) -> float:
        p = self._posterior(context, arm)
        sample = self._rng.betavariate(p.alpha, p.beta)
        if self._cost_normalized:
            return sample / max(self.cost_mean(context, arm), self._cost_floor)
        return sample

    def select(self, context: str, arms: Iterable[str]) -> str:
        """Thompson sampling: score each arm, play the highest."""
        best, best_score = None, -1.0
        for arm in arms:
            s = self._score(context, arm)
            if s > best_score:
                best_score, best = s, arm
        if best is None:
            raise ValueError("select() needs at least one arm")
        return best

    def order(self, context: str, arms: Iterable[str]) -> list[str]:
        """A full ordering: score each arm once (cost-normalized if enabled), best first."""
        scored = [(self._score(context, arm), arm) for arm in arms]
        scored.sort(key=lambda t: t[0], reverse=True)
        return [arm for _s, arm in scored]

    def update(self, context: str, arm: str, reward: float, cost: float = 1.0) -> None:
        self._posterior(context, arm).update(reward)
        c = self._cost.setdefault((context, arm), [0.0, 0.0])
        c[0] += max(0.0, float(cost))
        c[1] += 1.0

    def mean(self, context: str, arm: str) -> float:
        return self._posterior(context, arm).mean

    def best_arm(self, context: str, arms: Iterable[str]) -> str:
        """The exploitation choice: highest posterior mean (no exploration)."""
        return max(arms, key=lambda a: self._posterior(context, a).mean)

    # -- persistence (bandit_posteriors table) ---------------------------------
    def load(self, store) -> "ThompsonBandit":
        for r in store.conn.execute(
            "SELECT context, arm, alpha, beta, cost_sum, cost_n "
            "FROM bandit_posteriors").fetchall():
            self._post[(r["context"], r["arm"])] = Beta(r["alpha"], r["beta"])
            if r["cost_n"]:
                self._cost[(r["context"], r["arm"])] = [r["cost_sum"], float(r["cost_n"])]
        return self

    def save(self, store) -> None:
        for (context, arm), p in self._post.items():
            c = self._cost.get((context, arm), [0.0, 0.0])
            store.conn.execute(
                "INSERT INTO bandit_posteriors "
                "(context, arm, alpha, beta, cost_sum, cost_n, updated_at) "
                "VALUES (?,?,?,?,?,?, datetime('now')) "
                "ON CONFLICT(context, arm) DO UPDATE SET "
                "alpha=excluded.alpha, beta=excluded.beta, cost_sum=excluded.cost_sum, "
                "cost_n=excluded.cost_n, updated_at=excluded.updated_at",
                (context, arm, p.alpha, p.beta, c[0], int(c[1])))
        store.conn.commit()
