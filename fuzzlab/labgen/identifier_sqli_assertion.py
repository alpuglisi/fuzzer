"""Wire lane L-P1.2a's identifier-SQLi prober in as the **build-time security
assertion** for this lane's identifier/alias/connector-position cells
(L-P1.2b, ``docs/LAB_IMPLEMENTATION_PLAN.md`` §2.2).

``fuzzlab.labgen.identifier_sqli_oracle.run_identifier_sqli_oracle`` exists
because a real sqlmap 1.8.4 spot-check could not detect this shape (that
module's docstring, finding #3). This module is the missing half: it turns a
resolved :class:`~fuzzlab.labgen.schema.Cell` plus the render-only probe
metadata an emitter's page profile carries into an
:class:`~fuzzlab.labgen.identifier_sqli_oracle.IdentifierSqliOracleRequest`,
runs it, and checks the outcome against the cell's **derived** verdict
(``fuzzlab.labgen.verdict.verdict()`` against a pinned safety matrix) --
never against a hand-asserted expectation (NFR-LAB-label-accuracy).

**Fail-closed, per PA-0025 and this project's oracle contract.** A verdict
mismatch *and* an ``inconclusive`` outcome both raise
:class:`IdentifierSqliAssertionError`. There is deliberately no
"allow inconclusive" switch: a build gate whose failure mode is "shrug and
pass" is the exact shape PA-0025 was written against.

**What this can and cannot confirm today (read before wiring it into a
build).** The oracle's only differential is a ``CASE WHEN`` substitution, so:

* ``transform: []`` at an identifier/alias sink -- confirmable
  (``confirmed_vulnerable``): the CASE-WHEN expression reaches the query and
  TRUE/FALSE produce different responses.
* ``transform: [identifier_allowlist]`` -- confirmable
  (``confirmed_secure``): the CASE-WHEN value is not in the allowlist, so it
  collapses to the fallback identifier and both probes come back identical
  *and healthy* (the healthy-baseline requirement is what makes that a
  trustworthy secure, not an assumed one).
* ``transform: [identifier_charset_filter]`` -- **not confirmable**, and this
  is a genuine gap, named here rather than papered over. The filter rejects
  the CASE-WHEN payload's spaces/parens with an HTTP 400, so both probes come
  back unhealthy and the oracle correctly returns ``inconclusive`` (it must
  never read two identical error pages as "secure"). Confirming that cell
  needs an *identifier-swap* differential -- fire two probes holding two
  different **bare, legal** identifiers (``name`` vs ``secret``) and diff the
  responses -- which is precisely the strategy no sqlmap technique
  implements, and which L-P1.2a's request shape cannot express (it always
  wraps the value in ``CASE WHEN``). Adding an identifier-swap
  :class:`~fuzzlab.labgen.identifier_sqli_oracle.DifferentialMode` is a small,
  well-scoped change to that module; it is **not** done here because that
  module is another lane's deliverable and this lane has no mandate to
  change its interface. Tracked as an open question in this component's
  ``requirements.md`` (§8) and in ``CC-LAB-0040``.
* ``transform: [param_bind]`` -- confirmable as *vulnerable* (the identifier
  is still concatenated), and worth asserting precisely because the code
  looks parameterized.

**Escaping-context-mismatch XSS is deliberately not covered here.** No
existing oracle applies: ``oracle_wrapper`` is sqlmap/commix/SSTImap
(SQLi/command-injection/SSTI), ``nuclei_oracle`` is path-traversal templates
only. The one existing mechanism that could plausibly flag those cells is
``zap_oracle``'s whole-app scan (it already filters alerts by name, so a
reflected-XSS alert name is expressible) -- but it needs the live,
containerized lab, so it is on-host Tier-2 work, and whether ZAP's active
scanner recognizes a ``javascript:``-URL/unquoted-attribute context at all is
an open question to settle **against the real binary** (PA-0005's
"verify against the real tool" convention) before any new XSS oracle is
written. Building one speculatively now is exactly what the task brief said
not to do.
"""

from __future__ import annotations

import dataclasses
from typing import Mapping, Optional

from .identifier_sqli_oracle import (
    DifferentialMode,
    HttpRunner,
    IdentifierSqliOracleRequest,
    IdentifierSqliOracleVerdict,
    IdentifierSqliVerdict,
    SqlDialect,
    default_http_runner,
    run_identifier_sqli_oracle,
)
from .schema import Cell
from .verdict import SafetyMatrix, Verdict, verdict as derive_verdict

__all__ = [
    "IDENTIFIER_SINK_FAMILIES",
    "IdentifierSqliAssertionError",
    "IdentifierSqliAssertionResult",
    "is_identifier_sqli_cell",
    "build_identifier_sqli_request",
    "assert_identifier_sqli_cell",
    "IdentifierSqliTier2Oracle",
]

#: The ``sink_context.family`` values whose cells this assertion covers --
#: the two identifier/alias/connector-position families L-P1.2b added to
#: ``lab/safety_matrix.yaml``. Kept here (not imported from the emitter)
#: because the assertion is stack-agnostic: it talks HTTP to a running
#: target, not to ``php_current``'s module registry.
IDENTIFIER_SINK_FAMILIES: tuple[str, ...] = ("sql_identifier", "sql_join_alias")


class IdentifierSqliAssertionError(AssertionError):
    """Raised when a cell's build-time oracle outcome does not match its
    derived verdict, or when the oracle could not conclude at all. An
    ``AssertionError`` subclass because this *is* the build-time security
    assertion -- a failure here means the generated lab does not demonstrate
    what its label says it does."""


@dataclasses.dataclass(frozen=True)
class IdentifierSqliAssertionResult:
    """The structured outcome of asserting one cell."""

    cell_id: str
    derived: Verdict
    oracle: IdentifierSqliOracleVerdict
    matches: bool
    detail: str


def is_identifier_sqli_cell(cell: Cell) -> bool:
    """Whether ``cell`` is one of the identifier/alias/connector-position
    cells this assertion applies to. Callers filter a manifest with this
    rather than hardcoding family strings at each call site."""
    return cell.sink_context.family in IDENTIFIER_SINK_FAMILIES


def build_identifier_sqli_request(
    cell: Cell,
    *,
    target_base_url: str,
    param_name: str,
    column_a: str,
    column_b: str,
    dialect: SqlDialect = SqlDialect.MYSQL,
    mode: DifferentialMode = DifferentialMode.RESPONSE_DIFF,
    base_query_params: Optional[Mapping[str, str]] = None,
    headers: Optional[Mapping[str, str]] = None,
    cookie: Optional[str] = None,
    timeout_s: float = 15.0,
    max_attempts: int = 1,
) -> IdentifierSqliOracleRequest:
    """Build the oracle request for ``cell``.

    ``param_name``/``column_a``/``column_b`` are supplied by the caller, not
    read off the ``Cell``: they are render-only metadata the IR deliberately
    does not carry (the same split ``conformance.tier1.build_tier1_case`` and
    ``php_current``'s ``_PAGE_PARAMS`` already use -- for ``php_current`` they
    come straight out of that page profile's ``param_name``/``column_a``/
    ``column_b`` keys).

    The probed endpoint is the cell's ``sink_endpoint`` when it has one (a
    stored/second-order cell's tainted value executes there, not at its
    injection point) and its ``route`` otherwise -- mirroring
    ``php_current.render()``'s own ``render_route`` choice exactly.

    Raises :class:`IdentifierSqliAssertionError` for a cell whose shape this
    cannot honestly probe -- a non-identifier sink family, or a parameter
    that is not carried in the query string (L-P1.2a's request shape builds a
    query URL only; silently sending a cookie/JSON parameter as a query
    parameter would produce a meaningless "secure").
    """
    if not is_identifier_sqli_cell(cell):
        raise IdentifierSqliAssertionError(
            f"{cell.cell_id}: sink_context.family={cell.sink_context.family!r} is not an "
            f"identifier/alias position (expected one of {IDENTIFIER_SINK_FAMILIES}) -- "
            "this oracle probes identifier substitution and means nothing elsewhere"
        )
    if cell.param.location != "query":
        raise IdentifierSqliAssertionError(
            f"{cell.cell_id}: param.location={cell.param.location!r} -- "
            "identifier_sqli_oracle builds a query-string URL only, so probing this cell "
            "would send the payload somewhere the sink never reads it and report a "
            "meaningless 'secure' (fail-closed rather than guess)"
        )
    if cell.param.encoding != "raw":
        raise IdentifierSqliAssertionError(
            f"{cell.cell_id}: param.encoding={cell.param.encoding!r} -- "
            "identifier_sqli_oracle url-encodes its own probe values once and has no "
            "hook for a double-encoded/base64 wire form, so the substitution would not "
            "arrive intact at the identifier position"
        )
    route = cell.sink_endpoint if cell.sink_endpoint is not None else cell.route
    return IdentifierSqliOracleRequest(
        target_base_url=target_base_url,
        endpoint_path=route.path,
        param_name=param_name,
        column_a=column_a,
        column_b=column_b,
        dialect=dialect,
        mode=mode,
        base_query_params=dict(base_query_params or {}),
        headers=dict(headers) if headers is not None else None,
        cookie=cookie,
        timeout_s=timeout_s,
        max_attempts=max_attempts,
    )


def assert_identifier_sqli_cell(
    cell: Cell,
    matrix: SafetyMatrix,
    *,
    runner: HttpRunner = default_http_runner,
    **request_kwargs,
) -> IdentifierSqliAssertionResult:
    """Derive ``cell``'s verdict from ``matrix`` and confirm it with lane
    L-P1.2a's differential prober.

    ``**request_kwargs`` are :func:`build_identifier_sqli_request`'s keyword
    arguments (``target_base_url``, ``param_name``, ``column_a``,
    ``column_b``, and the optional session/dialect/mode ones).

    Returns the :class:`IdentifierSqliAssertionResult` on agreement; raises
    :class:`IdentifierSqliAssertionError` on disagreement **or** on an
    inconclusive outcome (fail-closed, PA-0025). The exception message always
    carries the oracle's own ``reason`` string, so a build failure says which
    probe leg produced it rather than only that something disagreed.
    """
    derived = derive_verdict(cell.transform, cell.sink_context, matrix)
    request = build_identifier_sqli_request(cell, **request_kwargs)
    oracle = run_identifier_sqli_oracle(request, runner=runner)

    if oracle.outcome is IdentifierSqliVerdict.INCONCLUSIVE:
        raise IdentifierSqliAssertionError(
            f"{cell.cell_id}: identifier-SQLi oracle was inconclusive, which is never "
            f"accepted as confirmation of a {derived.verdict} label (fail-closed, PA-0025). "
            f"Oracle reason: {oracle.reason}. If this cell's pipeline is "
            "identifier_charset_filter, this is the documented CASE-WHEN blind spot -- see "
            "fuzzlab/labgen/identifier_sqli_assertion.py's module docstring; it needs an "
            "identifier-swap differential mode, not a relaxed gate."
        )

    expected_vulnerable = derived.verdict == "VULNERABLE"
    matches = oracle.confirmed_vulnerable == expected_vulnerable
    detail = (
        f"{cell.cell_id}: derived={derived.verdict}"
        f"{'/' + derived.difficulty if derived.difficulty else ''} "
        f"(matrix v{derived.safety_matrix_version}, missing={list(derived.missing)}) vs "
        f"oracle={oracle.outcome.value} [{oracle.mode.value}/{oracle.dialect.value}]: {oracle.reason}"
    )
    if not matches:
        raise IdentifierSqliAssertionError(
            f"{cell.cell_id}: derived verdict {derived.verdict} disagrees with the "
            f"build-time oracle outcome {oracle.outcome.value} -- the generated cell does "
            f"not demonstrate what the safety matrix says it does. {detail}"
        )
    return IdentifierSqliAssertionResult(
        cell_id=cell.cell_id, derived=derived, oracle=oracle, matches=True, detail=detail
    )


class IdentifierSqliTier2Oracle:
    """Adapter exposing this assertion through
    :class:`fuzzlab.labgen.conformance.tier2.Tier2Oracle`'s ``confirm(case)``
    protocol, so an identifier-position cell can be driven by the existing
    tiered conformance harness instead of a second, parallel one.

    Structurally typed (no import of the Protocol) -- the same convention
    ``identifier_sqli_oracle`` uses for its own runner/verdict shapes, so
    this module takes no dependency on the conformance package.

    Tier 2's ``confirm`` contract returns ``(confirmed_vulnerable, detail)``,
    a **boolean**, which cannot express "inconclusive" -- so this adapter
    raises :class:`IdentifierSqliAssertionError` instead of collapsing an
    inconclusive probe into ``False`` (which Tier 2 would then compare
    against ``expected_vulnerable`` and possibly call a pass).
    """

    def __init__(
        self,
        *,
        target_base_url: str,
        column_a: str,
        column_b: str,
        dialect: SqlDialect = SqlDialect.MYSQL,
        mode: DifferentialMode = DifferentialMode.RESPONSE_DIFF,
        runner: HttpRunner = default_http_runner,
        timeout_s: float = 15.0,
    ) -> None:
        self._target_base_url = target_base_url
        self._column_a = column_a
        self._column_b = column_b
        self._dialect = dialect
        self._mode = mode
        self._runner = runner
        self._timeout_s = timeout_s

    def confirm(self, case) -> tuple[bool, str]:
        """Probe the endpoint ``case`` names (a
        ``conformance.tier1.Tier1Case``: ``path``/``param_name``/``cell_id``)
        and return ``(confirmed_vulnerable, detail)``."""
        if case.location != "query":
            raise IdentifierSqliAssertionError(
                f"{case.cell_id}: Tier-2 identifier-SQLi confirmation needs a query-string "
                f"parameter (got location={case.location!r}) -- see "
                "build_identifier_sqli_request's own refusal for the same reason"
            )
        request = IdentifierSqliOracleRequest(
            target_base_url=self._target_base_url,
            endpoint_path=case.path,
            param_name=case.param_name,
            column_a=self._column_a,
            column_b=self._column_b,
            dialect=self._dialect,
            mode=self._mode,
            timeout_s=self._timeout_s,
        )
        oracle = run_identifier_sqli_oracle(request, runner=self._runner)
        if oracle.outcome is IdentifierSqliVerdict.INCONCLUSIVE:
            raise IdentifierSqliAssertionError(
                f"{case.cell_id}: identifier-SQLi oracle inconclusive -- Tier 2's boolean "
                f"confirm() contract cannot represent that, and reporting it as 'not "
                f"vulnerable' would be a fail-open. Oracle reason: {oracle.reason}"
            )
        return oracle.confirmed_vulnerable, oracle.reason
