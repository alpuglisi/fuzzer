"""Context buckets and priors for the scheduler (Phase 4 T4.2).

The bandit keeps a posterior per (context, arm). A **context** is a discrete bucket
coarse enough to share evidence across similar injection points, fine enough to matter:
the vuln category plus the sink/location facet. **Arms** are the oracle's confirmation
mechanisms (what the scheduler orders in the confirm loop, T4.3); a mechanism arm is
``"<vuln_class>:<mechanism>"`` so mechanisms shared across classes stay distinct.

Two prior sources, both giving the bandit a warm start ("families that historically pay
off start ahead"):
- `arm_priors` — cost/reliability warm starts for the oracle *mechanisms* (a cheap,
  high-precision mechanism starts ahead of an expensive one);
- `catalog_priors` / `catalog_families` — read the `references/` payload catalogs, for
  the payload-family bandit that will select *within* a mechanism later.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Iterable

# Cost/reliability warm starts, keyed by mechanism. A cheap, high-precision mechanism
# (error signature, reflected context) starts optimistic so the bandit front-loads it;
# an expensive one (timing = many slow probes; browser execution) starts neutral.
_MECHANISM_PRIOR = {
    "error-signature": (3.0, 1.0),
    "boolean-differential": (2.0, 1.0),
    "reflected-context": (2.0, 1.0),
    "redirect-target-control": (2.0, 1.0),
    "file-content-marker": (2.0, 1.0),
    "evaluation-marker": (2.0, 1.0),
    "differential-timing": (1.0, 1.0),      # expensive -> neutral
    "browser-execution": (1.0, 1.0),        # expensive (browser) -> neutral
}


def context_for(category: str | None, location: str | None = None,
                sink_context: str | None = None) -> str:
    """The context bucket key: ``<category>:<sink_context|location|any>``."""
    facet = sink_context or location or "any"
    return f"{category or 'unknown'}:{facet}"


def context_parents(context: str) -> list[str]:
    """Coarser contexts to back off to, specific→root (excluding ``context`` itself).

    ``"sql-injection:html"`` → ``["sql-injection", ""]``; ``"sql-injection"`` → ``[""]``.
    A cold (context, arm) borrows strength from the first parent that has data (T4.5).
    """
    out: list[str] = []
    if ":" in context:
        out.append(context.split(":", 1)[0])     # drop the facet
    if context != "":
        out.append("")                            # the global root
    return [c for c in dict.fromkeys(out) if c != context]


def arm_priors(strategies: Iterable) -> dict[str, tuple[float, float]]:
    """Per-arm priors for the oracle-mechanism bandit, from the mechanism cost model.

    ``strategies`` are `ConfirmationStrategy` instances; each contributes its ``arm``
    (``vuln_class:mechanism``) with the prior for its mechanism.
    """
    out: dict[str, tuple[float, float]] = {}
    for s in strategies:
        prior = _MECHANISM_PRIOR.get(getattr(s, "mechanism", ""), (1.0, 1.0))
        out[getattr(s, "arm", getattr(s, "mechanism", ""))] = prior
    return out


def catalog_families(reference: str, root: str | Path = "references") -> list[str]:
    """Payload-family names for a reference category (its ``payloads/*.txt`` files)."""
    payloads = Path(root) / reference / "payloads"
    if not payloads.is_dir():
        return []
    return sorted(p.stem for p in payloads.glob("*.txt"))


def catalog_priors(reference: str, root: str | Path = "references",
                   cap: float = 3.0) -> dict[str, tuple[float, float]]:
    """Weak catalog-derived priors per payload family: bigger families start slightly
    more optimistic (log-scaled, capped), so a family with more curated payloads is
    tried a little sooner — then learning takes over."""
    payloads = Path(root) / reference / "payloads"
    out: dict[str, tuple[float, float]] = {}
    for p in sorted(payloads.glob("*.txt")) if payloads.is_dir() else []:
        try:
            n = sum(1 for line in p.read_text("utf-8", "replace").splitlines() if line.strip())
        except OSError:
            n = 0
        alpha = 1.0 + min(cap, math.log10(n + 1))     # 1.0 .. 1.0+cap
        out[p.stem] = (round(alpha, 3), 1.0)
    return out
