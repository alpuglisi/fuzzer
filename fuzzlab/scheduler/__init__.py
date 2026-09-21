"""Payload scheduler (Phase 4 groundwork): pick the payload family to try next.

A scheduler chooses an **arm** (a payload family) for a given **context** (a discrete
bucket, e.g. the vuln class + sink), observes a reward in [0, 1] (the shaped reward
from `fuzzlab.greybox.reward`), and learns which families pay off where — so a run
finds the known vulns in fewer requests than uniform selection.

This package ships the learning core and its control, all deterministic and
offline-testable:
- `ThompsonBandit` — Beta-Bernoulli Thompson sampling per (context, arm), with
  catalog-derived priors and posteriors persisted in the `bandit_posteriors` table;
- `UniformScheduler` — the control condition (ignores feedback) to measure the bandit
  against (the Phase 4 exit: beat uniform on hits-per-N requests).

Wiring the scheduler into the live fuzz loop and the held-out comparison plot are the
later, on-lab parts of Phase 4.
"""

from fuzzlab.scheduler.bandit import Beta, ThompsonBandit
from fuzzlab.scheduler.uniform import UniformScheduler

__all__ = ["Beta", "ThompsonBandit", "UniformScheduler"]
