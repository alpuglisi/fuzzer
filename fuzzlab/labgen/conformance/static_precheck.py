"""Static-precheck flag mechanism (T-LAB0.7).

Per ``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.7 and ``CR-LAB-0001`` Addendum C
point 4: each ``(vuln_class, sink_context.family)`` shape the safety matrix
covers also carries a ``static_precheck: informative | uninformative`` flag.
A taint analyzer (Psalm+``psalm/plugin-laravel`` for PHP, Semgrep for
Python/Node) is used only as a bespoke *shape*-conformance rule ("does the
module contain the intended sink/transform"), never as a vulnerability
detector -- it is structurally blind to the identifier/alias/connector-
position injection shapes this program actually cares about, so a clean
scan for those shapes is not evidence of anything and must be **skipped**,
never trusted as confirmation.

This module builds only the flag mechanism and the skip rule -- not a real
Psalm/Semgrep integration (out of scope for this task; the plan treats the
checker as a later, pluggable concern). ``STATIC_PRECHECK_BY_SHAPE`` is this
task's own registry, kept here rather than in ``lab/safety_matrix.yaml``:
that file and its schema are owned by a concurrently-developed sibling
lane, and ``CR-LAB-0001``'s ``static_precheck`` field is a documented
*forward* addition to that schema that has not landed there yet. Once it
does, this registry's lookup can be swapped for a real matrix-entry read
without changing :func:`run_static_precheck`'s contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class StaticPrecheckStatus(str, Enum):
    INFORMATIVE = "informative"
    UNINFORMATIVE = "uninformative"


#: (vuln_class, sink_context_family) -> whether a taint-style static
#: checker's result means anything for this shape.
#:
#: Per Addendum C point 4: identifier/alias/connector-position SQL
#: injection looks identical to safe code to a taint engine, so every SQL
#: shape this Phase-0 sample renders is UNINFORMATIVE. An HTML-escaping
#: omission (``html_body``) is the one shape here a taint/lint-style
#: checker could plausibly flag for real (missing ``htmlspecialchars()``
#: around an echoed value is a textbook static-analysis finding), so it is
#: marked INFORMATIVE -- this exercises :func:`run_static_precheck`'s
#: "run for real" branch in tests, not only its skip branch, even though no
#: real Psalm/Semgrep checker is wired in yet (see the module docstring).
STATIC_PRECHECK_BY_SHAPE: dict[tuple[str, str], StaticPrecheckStatus] = {
    ("sqli", "sql_numeric_literal"): StaticPrecheckStatus.UNINFORMATIVE,
    ("sqli", "sql_string_literal"): StaticPrecheckStatus.UNINFORMATIVE,
    ("xss", "html_body"): StaticPrecheckStatus.INFORMATIVE,
    # --- L-P1.2b harder shapes (docs/LAB_IMPLEMENTATION_PLAN.md §2.2) ------
    # Identifier/alias/connector-position SQLi: UNINFORMATIVE for the same
    # (now empirically confirmed) reason as every other SQL shape here -- and
    # more sharply. A real sqlmap 1.8.4 spot-check could not detect the
    # allowlist-respecting identifier-swap case at all (see
    # fuzzlab/labgen/identifier_sqli_oracle.py's docstring, finding #3); a
    # taint engine has strictly less to go on than that, since the code
    # contains a visible input filter and no unescaped-string-concatenation
    # tell it keys on.
    ("sqli", "sql_identifier"): StaticPrecheckStatus.UNINFORMATIVE,
    ("sqli", "sql_join_alias"): StaticPrecheckStatus.UNINFORMATIVE,
    # Escaping-context-mismatch XSS: UNINFORMATIVE, and this is the
    # interesting case -- ("xss", "html_body") above is INFORMATIVE precisely
    # because a *missing* htmlspecialchars() is a textbook static finding. In
    # these two shapes the escaping is *present* and correct-looking; what is
    # wrong is the context it was chosen for. A taint engine that treats
    # htmlspecialchars() as a sanitizer (they all do) reports clean, so its
    # clean scan is evidence of nothing here and must be skipped, never
    # recorded as confirmation.
    ("xss", "url_javascript_scheme"): StaticPrecheckStatus.UNINFORMATIVE,
    ("xss", "html_attribute_unquoted"): StaticPrecheckStatus.UNINFORMATIVE,
    # --- L-P3.3c-G6: search.php's quoted-attribute reflection -------------
    # INFORMATIVE, unlike its unquoted sibling above, and for the same reason
    # the safety matrix scores the two families' `html_entity_escape` rows
    # differently: at a *quoted* attribute the vulnerable cell simply has no
    # escaping at all, which is the textbook missing-`htmlspecialchars()`
    # finding a taint engine is expected to report -- exactly `(xss,
    # html_body)`'s situation. The unquoted family is uninformative because
    # there the escaping is *present* and only the context is wrong.
    ("xss", "html_attribute_quoted"): StaticPrecheckStatus.INFORMATIVE,
}


class NoStaticCheckerConfiguredError(RuntimeError):
    """Raised when an INFORMATIVE shape is precheck'd with no checker
    callable supplied -- an authoring gap (real Psalm/Semgrep wiring is
    still separate, later work), not something to silently pass."""


@dataclass(frozen=True)
class PrecheckResult:
    status: StaticPrecheckStatus
    ran: bool
    passed: bool | None  # None when not run (skipped)
    detail: str


def static_precheck_status(vuln_class: str, sink_family: str) -> StaticPrecheckStatus:
    """Look up this shape's ``static_precheck`` flag.

    Fails loud on an unregistered shape, matching this project's "an
    authoring gap fails loud, never defaults silently" convention (see
    ``fuzzlab.labgen.verdict.SafetyMatrix.lookup``).
    """
    try:
        return STATIC_PRECHECK_BY_SHAPE[(vuln_class, sink_family)]
    except KeyError as exc:
        raise KeyError(
            f"no static_precheck entry for (vuln_class={vuln_class!r}, sink_family={sink_family!r}) "
            "-- add one to STATIC_PRECHECK_BY_SHAPE rather than defaulting silently"
        ) from exc


def run_static_precheck(
    vuln_class: str,
    sink_family: str,
    checker: Callable[[], bool] | None = None,
) -> PrecheckResult:
    """Run (or skip) a static-shape-conformance check for one
    ``(vuln_class, sink_family)`` shape.

    An **uninformative** shape is always skipped -- ``checker``, even if
    supplied, is never called: a clean-but-meaningless scan must never be
    recorded as evidence (Addendum C point 4). An **informative** shape
    calls ``checker`` and *requires* one to be supplied -- there is no
    silent default here either.
    """
    status = static_precheck_status(vuln_class, sink_family)
    if status is StaticPrecheckStatus.UNINFORMATIVE:
        return PrecheckResult(
            status=status,
            ran=False,
            passed=None,
            detail=(
                f"skipped: ({vuln_class}, {sink_family}) is static_precheck=uninformative -- "
                "a taint-style checker is structurally blind to this shape (CR-LAB-0001 Addendum C point 4)"
            ),
        )
    if checker is None:
        raise NoStaticCheckerConfiguredError(
            f"({vuln_class}, {sink_family}) is static_precheck=informative but no checker was supplied "
            "-- wiring a real Psalm/Semgrep checker is separate, later work; this shape must not be "
            "silently treated as passing or skipped in the meantime"
        )
    passed = checker()
    return PrecheckResult(
        status=status,
        ran=True,
        passed=passed,
        detail=f"ran: ({vuln_class}, {sink_family}) is static_precheck=informative",
    )
