"""Tier 2 -- the full container-based oracle (T-LAB0.7).

**[design -- not exercised by this task's own test suite].** Per
``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.7, Tier 2 is "the only tier that
actually confirms a label" -- it requires the real, live containerized lab,
which is explicitly out of scope for this whole session (offline-buildable
work only). This module exists to fix Tier 2's *interface* now (what a case
and an oracle client look like) so an on-host follow-up task has a contract
to implement against -- it does **not** provide any working confirmation
logic itself.

This task's own tests only prove :func:`run_tier2_case` refuses to run
without a real oracle (:class:`~fuzzlab.labgen.conformance.tier1.OnHostRequiredError`),
and that its result-plumbing is wired correctly given a **test double**
standing in for one -- never that any real container-based confirmation
happened. A green test in this module is not, and must never be presented
as, a live confirmation; only a real on-host oracle (e.g. one of the
sqlmap/commix/SSTImap/ZAP tool-oracle wrappers other lanes own) can produce
one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from fuzzlab.labgen.conformance.tier1 import OnHostRequiredError, Tier1Case

__all__ = ["OnHostRequiredError", "Tier2Oracle", "Tier2Outcome", "run_tier2_case"]


@dataclass(frozen=True)
class Tier2Outcome:
    case: Tier1Case
    confirmed_vulnerable: bool
    matches_expectation: bool
    oracle_detail: str


class Tier2Oracle(Protocol):
    """What Tier 2 needs from a real, container-based oracle -- out of
    scope to implement or invoke for real in this task."""

    def confirm(self, case: Tier1Case) -> tuple[bool, str]:
        """Return ``(confirmed_vulnerable, detail)`` for ``case`` against
        the real, running, containerized target."""
        ...


def run_tier2_case(case: Tier1Case, oracle: Tier2Oracle | None) -> Tier2Outcome:
    """Run one Tier-2 case against ``oracle``.

    Raises :class:`OnHostRequiredError` when ``oracle`` is ``None`` -- Tier
    2 has no meaningful offline stand-in at all (per T-LAB0.7, it is *the*
    tier that confirms a label). A caller must supply a real, on-host
    oracle; this task's own tests supply only a test double, to check the
    wiring, never to claim confirmation.
    """
    if oracle is None:
        raise OnHostRequiredError(
            f"{case.cell_id}: Tier 2 requires a real, container-based oracle -- none was supplied. "
            "This is a [design] interface; wiring a real oracle is on-host work, out of scope for "
            "this session."
        )
    confirmed, detail = oracle.confirm(case)
    return Tier2Outcome(
        case=case,
        confirmed_vulnerable=confirmed,
        matches_expectation=confirmed == case.expected_vulnerable,
        oracle_detail=detail,
    )
