"""Tier 2 -- the full container-based oracle (T-LAB0.7).

Per ``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.7, Tier 2 is "the only tier that
actually confirms a label" -- the canonical, production-grade form of that
requires the real, live containerized lab (or, per ``FR-LAB-41``'s own
``IdentifierSqliTier2Oracle``, a real HTTP oracle probing the real,
authorized-only target), which stays out of scope here (D11/CLAUDE.md
Safety: the real, loopback-only Ryder's Puppy Fort Factory target is never
touched without an explicit ``--authorized`` flag, and this lane does not
carry one).

**What this module now proves for real (``CC-LAB-0061``, extending the
``php_laravel`` live-boot precedent ``CC-LAB-0054`` established for Tier 1).**
:class:`LiveBootTier2Oracle` is a real, in-sandbox :class:`Tier2Oracle`
implementation: it drives a :class:`~fuzzlab.labgen.conformance.live_boot.
LiveBootHarness`-booted, **synthetic** ``php_laravel`` app (a real
``composer install`` + real ``php artisan serve`` boot against a per-run
SQLite database -- never the real, loopback-only lab target, never
requiring ``--authorized``, exactly like ``live_boot.py``'s own scope
statement) and adds a genuine control/baseline differential on top of
Tier 1's bare "does the marker appear" check: it fetches the case's real
response for ``case.payload`` **and** a second real response for an inert
control value, and only reports ``confirmed_vulnerable`` when the evidence
marker appears in the payload response and is genuinely **absent** from the
control response. That second, negative observation is the part Tier 1
never makes (:mod:`fuzzlab.labgen.conformance.tier1`'s own docstring: a
Tier-1 pass is never oracle confirmation) -- it rules out the case where the
"marker" is just static page content the app would have shown regardless of
the injection, which a bare presence check cannot distinguish. This is
still, deliberately, **not** the production-grade, dialect-sensitive,
container-based confirmation T-LAB0.7 describes (that remains
``IdentifierSqliTier2Oracle``'s and any future real-target oracle's job, per
``FR-LAB-52``/``FR-LAB-54``/``FR-LAB-55``'s own repeated scope statements) --
see :class:`LiveBootTier2Oracle`'s own docstring for the precise claim.

This task's own offline tests prove :func:`run_tier2_case` refuses to run
without a real oracle (:class:`~fuzzlab.labgen.conformance.tier1.OnHostRequiredError`),
and that its result-plumbing is wired correctly given a **test double**
standing in for one. ``tests/test_labgen_conformance_tier2.py`` additionally
carries real, on-host, skip-guarded tests
(``@pytest.mark.slow``, gated on ``live_boot.live_boot_available()``) that
run :class:`LiveBootTier2Oracle` against a genuinely booted app -- a real
confirmation of the narrower, synthetic-in-sandbox claim above, never a
substitute for one of the real, authorized, on-target oracles this module's
:class:`Tier2Oracle` protocol also accepts (e.g. the
sqlmap/commix/SSTImap/ZAP tool-oracle wrappers, or
``fuzzlab.labgen.identifier_sqli_assertion.IdentifierSqliTier2Oracle``, other
lanes own).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from fuzzlab.labgen.conformance.tier1 import OnHostRequiredError, Tier1Case

__all__ = [
    "LiveBootTier2Oracle",
    "OnHostRequiredError",
    "Tier2Client",
    "Tier2Oracle",
    "Tier2Outcome",
    "run_tier2_case",
]


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


class Tier2Client(Protocol):
    """What :class:`LiveBootTier2Oracle` needs from a booted app client --
    structurally satisfied by
    :class:`fuzzlab.labgen.conformance.live_boot.LiveBootHarness` (its real
    ``.get()``/``.post()`` methods) without this module importing that one
    directly, so this module stays usable against any future in-process
    client shaped the same way. Deliberately the same request shape
    :meth:`~fuzzlab.labgen.conformance.live_boot.LiveBootHarness.fetch`
    already builds for Tier 1 (``case.location`` picks query vs. body) --
    never a second, independently-invented request convention."""

    def get(self, path: str, *, params: dict[str, str] | None = None) -> object:
        """Return an object with a real ``.status``/``.body`` -- matches
        :class:`~fuzzlab.labgen.conformance.live_boot.HttpResponse`."""
        ...

    def post(self, path: str, *, data: dict[str, str] | None = None) -> object:
        ...


class LiveBootTier2Oracle:
    """A real, synthetic-in-sandbox :class:`Tier2Oracle` -- see this
    module's own docstring ("What this module now proves for real") for the
    full scope statement. Never touches the real, loopback-only lab target
    and needs no ``--authorized`` flag: ``client`` is expected to be a
    :class:`~fuzzlab.labgen.conformance.live_boot.LiveBootHarness` booted
    against a checked-in ``php_laravel`` skeleton + a manifest's own
    rendered output, exactly like Tier 1's own live-boot proof
    (``CC-LAB-0054``).

    **The control/baseline differential this adds over Tier 1.** ``confirm``
    sends ``case``'s real payload request, and a second real request with
    ``control_value`` substituted for ``case.payload`` at the same
    ``param_name``/``location`` -- an inert value this oracle's caller
    picks to be one the target vulnerability class cannot turn into
    ``case.evidence_marker`` (e.g. a plain existing id for a numeric-SQLi
    marker keyed off a *different* row, or a value containing no markup at
    all for an XSS marker). ``confirmed_vulnerable`` is only ``True`` when
    the marker is present in the payload response **and** absent from the
    control response -- ruling out the case where the marker is just
    something the page would have shown anyway, which neither
    ``evaluate_tier1_response`` nor a single request can distinguish on its
    own. A caller passing a control value that itself could produce the
    marker gets a real, reported ``inconclusive`` detail rather than a
    silently wrong verdict -- this oracle fails closed, per PA-0025's
    "never collapse ambiguity into a pass" convention, matching
    ``IdentifierSqliTier2Oracle``'s own fail-closed rule."""

    def __init__(self, client: Tier2Client, *, control_value: str) -> None:
        self._client = client
        self._control_value = control_value

    def _fetch(self, case: Tier1Case, value: str) -> str:
        if case.location == "query":
            return self._client.get(case.path, params={case.param_name: value}).body  # type: ignore[attr-defined]
        return self._client.post(case.path, data={case.param_name: value}).body  # type: ignore[attr-defined]

    def confirm(self, case: Tier1Case) -> tuple[bool, str]:
        payload_body = self._fetch(case, case.payload)
        control_body = self._fetch(case, self._control_value)
        marker_in_payload = case.evidence_marker in payload_body
        marker_in_control = case.evidence_marker in control_body

        if marker_in_control:
            # The control (which never carries the payload) already shows
            # the marker -- this control value cannot distinguish "the app
            # is vulnerable" from "the app always shows this text". Report
            # honestly rather than guessing either way (PA-0025).
            return (
                False,
                "inconclusive: evidence marker present even in the control/baseline response "
                f"(control_value={self._control_value!r}) -- this control cannot confirm or "
                "rule out the injection for this case",
            )

        confirmed = marker_in_payload and not marker_in_control
        detail = (
            f"payload response {'contained' if marker_in_payload else 'did not contain'} "
            f"the evidence marker; control/baseline response did not -- "
            f"{'confirmed' if confirmed else 'not confirmed'} via a real live-boot "
            "control differential (synthetic in-sandbox, not the real lab target)"
        )
        return confirmed, detail


def run_tier2_case(case: Tier1Case, oracle: Tier2Oracle | None) -> Tier2Outcome:
    """Run one Tier-2 case against ``oracle``.

    Raises :class:`OnHostRequiredError` when ``oracle`` is ``None`` -- Tier
    2 has no meaningful offline stand-in at all (per T-LAB0.7, it is *the*
    tier that confirms a label). A caller must supply a real oracle -- a
    real, in-sandbox :class:`LiveBootTier2Oracle`, a real on-target oracle
    like ``IdentifierSqliTier2Oracle``, or (this task's own offline tests
    only) a test double, to check the wiring, never to claim confirmation.
    """
    if oracle is None:
        raise OnHostRequiredError(
            f"{case.cell_id}: Tier 2 requires a real, container-based oracle -- none was supplied. "
            "Wire in a real oracle, e.g. conformance.tier2.LiveBootTier2Oracle (synthetic "
            "in-sandbox) or a real on-target oracle."
        )
    confirmed, detail = oracle.confirm(case)
    return Tier2Outcome(
        case=case,
        confirmed_vulnerable=confirmed,
        matches_expectation=confirmed == case.expected_vulnerable,
        oracle_detail=detail,
    )
