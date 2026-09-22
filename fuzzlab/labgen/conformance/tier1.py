"""Tier 1 -- in-process functional + security assertion (T-LAB0.7).

**No longer design-only for every stack.** Per ``docs/LAB_PHASE_0_PLAN.md``
T-LAB0.7, a real Tier-1 check runs the app in-process against a real
database -- **never** an in-memory SQLite substitute used as a claimed
dialect-accurate oracle, since identifier/alias-position SQL injection can
behave differently across SQL dialects (this module's decision logic itself
stays dialect-agnostic: it only checks whether a marker string appears in a
real response body). ``fuzzlab.labgen.conformance.live_boot.LiveBootHarness``
(``CC-LAB-0054``/``FR-LAB-52``) is a real, on-host-independent
:class:`Tier1Client` implementation for the ``php_laravel`` stack -- it
assembles a real Laravel build, boots it with a real ``php artisan serve``,
and serves real HTTP responses, so :func:`run_tier1_case` can now be, and is
(``CC-LAB-0060``/``FR-LAB-56``), exercised against a genuinely running
in-process app for the stacks that harness covers, entirely inside this
project's own offline test suite (no external/live lab target is touched --
see the module docstring on ``live_boot`` for the sandbox-local mechanism).
``tests/test_labgen_conformance_tier1.py`` carries both: the original
decision-logic tests against a hand-written fake client (never claim more
than "this module's wiring is coherent"), and skip-guarded
(``live_boot_available()``) tests that run real :class:`Tier1Case` objects
through :func:`run_tier1_case` against a real :class:`LiveBootHarness` for
the ``php_laravel`` real-page manifests that harness already proves boot
(the ``numeric`` and ``forms`` groups). Stacks with no such harness yet (e.g.
``php_current``) remain design-only for Tier 1 until one is built --
:class:`OnHostRequiredError` still refuses to run without a real client, and
a Tier-1 pass is still never recorded as Tier-2 oracle confirmation
(T-LAB0.7's own rule; Tier-2 wiring is separate, out-of-scope work -- see
``tier2.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from fuzzlab.labgen.schema import Cell


class OnHostRequiredError(RuntimeError):
    """Raised when a Tier-1/Tier-2 check is invoked without the on-host
    resources (a live app/DB, or a real oracle) it needs to mean anything."""


@dataclass(frozen=True)
class Tier1Case:
    """One Tier-1 HTTP-level case: send ``payload`` at ``param_name``
    (``location``: ``"query"`` or ``"body"``) and decide vulnerable/secure
    by whether ``evidence_marker`` appears in the response body.
    """

    cell_id: str
    method: str
    path: str
    param_name: str
    location: str  # "query" | "body"
    payload: str
    evidence_marker: str
    expected_vulnerable: bool


def build_tier1_case(
    cell: Cell,
    *,
    param_name: str,
    payload: str,
    evidence_marker: str,
    expected_vulnerable: bool,
) -> Tier1Case:
    """Build one :class:`Tier1Case` from a resolved :class:`Cell` plus the
    render-only metadata (param name, payload, evidence marker) a real
    integration would source from the emitter's own page profile / the
    real ground-truth contract. ``Cell`` itself deliberately carries none
    of this (it is not verdict-relevant), so it is supplied by the caller
    here -- exactly like ``fuzzlab.labgen.emitters.php_current``'s own
    ``_PAGE_PARAMS`` supplies render-only metadata ``Cell`` doesn't carry.
    """
    location = "query" if cell.route.method.upper() == "GET" else "body"
    return Tier1Case(
        cell_id=cell.cell_id,
        method=cell.route.method,
        path=cell.route.path,
        param_name=param_name,
        location=location,
        payload=payload,
        evidence_marker=evidence_marker,
        expected_vulnerable=expected_vulnerable,
    )


@dataclass(frozen=True)
class Tier1Outcome:
    case: Tier1Case
    vulnerable_detected: bool
    matches_expectation: bool
    response_excerpt: str


def evaluate_tier1_response(case: Tier1Case, response_body: str) -> Tier1Outcome:
    """Pure decision logic: does ``response_body`` show ``case.evidence_marker``?

    Fully offline-testable against a hand-written string -- this is the
    part of Tier 1 this task's own tests actually exercise for real; it
    never talks to a network or a real app.
    """
    vulnerable_detected = case.evidence_marker in response_body
    return Tier1Outcome(
        case=case,
        vulnerable_detected=vulnerable_detected,
        matches_expectation=vulnerable_detected == case.expected_vulnerable,
        response_excerpt=response_body[:200],
    )


class Tier1Client(Protocol):
    """What :func:`run_tier1_case` needs from an in-process app client.

    ``fuzzlab.labgen.conformance.live_boot.LiveBootHarness`` is a real,
    already-built implementation of this protocol for the ``php_laravel``
    stack (its ``.fetch()`` method); a stack without such a harness yet has
    no real implementation, and :func:`run_tier1_case` refuses to run
    without one (see :class:`OnHostRequiredError`)."""

    def fetch(self, case: Tier1Case) -> str:
        """Perform the request ``case`` describes and return the response
        body as text."""
        ...


def run_tier1_case(case: Tier1Case, client: Tier1Client | None) -> Tier1Outcome:
    """Run one Tier-1 case against ``client``.

    Raises :class:`OnHostRequiredError` when ``client`` is ``None`` --
    there is no meaningful offline stand-in for "the real app responded",
    per T-LAB0.7's own rule against an in-memory-SQLite substitute. A
    caller supplies a real (on-host) client, or, in this task's own tests
    only, a fake client that must never be mistaken for oracle
    confirmation (see the module docstring).
    """
    if client is None:
        raise OnHostRequiredError(
            f"{case.cell_id}: Tier 1 requires an in-process app + real DB container client -- "
            "none was supplied. This is a [design] interface; wiring a real client is on-host work."
        )
    body = client.fetch(case)
    return evaluate_tier1_response(case, body)
