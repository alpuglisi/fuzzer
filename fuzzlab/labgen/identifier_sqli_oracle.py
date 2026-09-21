"""A custom differential-response prober for identifier/alias/connector-
position SQL injection (injection into a column/table identifier or JOIN
alias, not an ordinary literal value) -- generator-build-time validation
tooling, the same category as ``fuzzlab.labgen.oracle_wrapper`` (sqlmap/
commix/SSTImap) and ``fuzzlab.labgen.nuclei_oracle`` (Nuclei), built for the
same reason (``docs/LAB_IMPLEMENTATION_PLAN.md`` sec 2.2): confirm that a
manifest-generated code cell is really vulnerable, or really secure, using
an oracle independent of hand-written exploit logic or an LLM's opinion of
its own code.

**Why this exists as a sibling module, not an extension of ``oracle_wrapper``
or ``nuclei_oracle``.** ``docs/LAB_IMPLEMENTATION_PLAN.md`` sec 2.2 recorded
research (sqlmap GitHub issues #97, #2459, #490) finding that sqlmap's
`--technique=` option only exposes the six classic *value*-context
techniques (boolean-blind/error-based/UNION/stacked/time-based/inline) --
`-p` and the `*` custom-injection-point marker both still assume the marked
position holds a mutable value sqlmap can wrap with a prefix/suffix
boundary, not a bare identifier token it must instead *substitute*. A spot
check against the real, apt-installed sqlmap 1.8.4 confirmed this in the
one case that matters most (see below): sqlmap correctly finds an
ORDER-BY-column-name injection when nothing stops it appending SQL
syntax (spaces/parens/`--` comments) to the injected value, and even a
JOIN-alias injection when the value flows into two positions and a
trailing `--` comment truncates the rest of the line -- but it reported
"all tested parameters do not appear to be injectable" against a *third*,
more realistic case: a column-name parameter validated by the application
against a bare-identifier character allowlist (`^[A-Za-z0-9_]+$`, no
spaces/quotes/parens/comments reach the query at all) where the actual
vulnerability is that the *value* is not checked against the real column
allowlist -- an attacker can still swap `name` for `secret` and exfiltrate
a column the endpoint never intended to expose, entirely through legal
identifier characters. sqlmap's payload set is built exclusively around
injecting boolean/comparison syntax or breaking out via a comment; it has
no "swap the identifier for a different real one and diff the response"
strategy, so it cannot find this class even at `--level=5 --risk=3`. This
is exactly the identifier/alias/connector-position gap the research
described, and it is the harder, allowlist-respecting case the harder SQLi
shapes in `php_current` (a later, separate lane) will actually emit -- so
this module's fallback design is required regardless of how the two looser
spot-check cases came out.

**Spot-check findings (this task, 2026-09-21), reproduced against a real
PHP 8.4 + PDO/SQLite test harness and sqlmap 1.8.4 (`apt-get install -y
sqlmap`, no prior instance on this host):**

1. ``ORDER BY $sort`` with `$sort` unsanitized (no character filtering) --
   sqlmap (`--level=3 --risk=3 --technique=BEUSTQ`) DID find it, via its
   built-in "SQLite AND boolean-based blind - WHERE, HAVING, ORDER BY or
   GROUP BY clause (JSON)" heuristic, which appends a `CASE WHEN ... END`
   expression after the identifier -- this succeeds only because ORDER BY
   accepts an arbitrary trailing expression and nothing filters the
   injected characters.
2. A JOIN alias, ``FROM items i1 JOIN items $alias ON i1.id = $alias.id``,
   `$alias` unsanitized -- sqlmap DID find it too (time-based blind), but
   only because its payload's trailing `-- <rand>` comments out the rest of
   the line (including the *second* substitution of the same tainted value
   in the `ON` clause), degenerating the "alias" injection into an ordinary
   statement-truncation injection. This is not identifier-aware detection;
   it is comment-based escape working to succeed despite the identifier
   framing.
3. A column-name parameter restricted by the application to
   `^[A-Za-z0-9_]+$` (case 1's script but rejecting anything else with an
   HTTP 400) where the real defect is "any *identifier-shaped* string
   reaches the query, not a real column allowlist" (confirmed manually:
   `?col=secret` returns the `secret` column) -- sqlmap
   (`--level=5 --risk=3 --technique=BEUSTQ`) reported **"all tested
   parameters do not appear to be injectable"** (8879/8879 requests
   rejected with HTTP 400 by the allowlist; zero of sqlmap's payloads
   contain only identifier-safe characters). This is the decisive
   confirmation of the research finding for the case this project's harder
   SQLi shapes will actually emit, and it is why this module exists: no
   configuration of sqlmap detects a pure identifier-swap vulnerability,
   because none of its payload templates express "try a different real
   identifier and diff the response" -- they all require characters an
   allowlisted identifier position strips.

Conclusion: the fallback in this module is required regardless of the
first two (looser) results, exactly per the plan's "ship the fallback
either way" decision.

**Design, matching `nuclei_oracle.py`'s established pattern:**

* Own independent ``IdentifierSqliVerdict`` enum, defined here (not
  imported from ``oracle_wrapper``/``nuclei_oracle``) -- fail-closed,
  three-outcome (``confirmed_vulnerable | confirmed_secure |
  inconclusive``), matching their contract shape without importing it.
* Reuses only ``oracle_wrapper.assert_loopback`` (loopback safety) directly.
  This module never shells out to an external binary (it fires HTTP
  requests, not a subprocess), so it has no textual need for
  ``locate_tool``/``ToolNotFoundError`` (`fuzzlab.labgen` still re-exports
  those from ``oracle_wrapper`` for any caller that wants them); no
  sqlmap/commix/SSTImap-specific code is imported or duplicated.
* **PA-0025 applies to HTTP-direct oracles too, not only subprocess tools.**
  A "no differential" result is only trustworthy if both probes actually
  reached and were executed by the target -- so every probe first fires a
  *baseline* request (the identifier position holding a definitely-valid,
  inert value) and refuses to call anything ``confirmed_secure`` unless
  that baseline came back healthy (2xx, no timeout). Two malformed-request
  failures that happen to produce identical error pages are never read as
  "secure" -- they are ``inconclusive`` (fail-closed).
* **DBMS-dialect-specific phrasing lives behind a small per-dialect
  registry (`_DIALECT_PHRASING`)**, not inline conditionals, so adding
  PostgreSQL (`pg_sleep`) or SQLite (`CASE WHEN ... END`, no native sleep)
  is a new registry entry, never a rewrite of the request/classification
  control flow. MySQL (`SLEEP()`) is implemented per the task; the other
  two dialects are named in `SqlDialect` with a clear
  `DialectNotImplementedError` so a caller gets an actionable error rather
  than a silent wrong phrasing.
* **Two differential modes**, both driven by the same TRUE/FALSE
  boolean-differential substitution:
  - ``response_diff`` (default): substitute
    ``(CASE WHEN (<condition>) THEN <column_a> ELSE <column_b> END)`` for
    the TRUE probe and the condition's logical negation for the FALSE
    probe, and diff the two response bodies (row order/values) and status
    codes.
  - ``timing_blind``: same substitution, but with the DBMS's sleep
    function gated behind the CASE (``CASE WHEN (<condition>) THEN
    SLEEP(n) ELSE 0 END``); classifies by comparing elapsed time against
    ``timing_threshold_s`` instead of diffing bodies -- for endpoints whose
    response body/status never reveals row-level differences.
* **Dependency-injected HTTP runner** (`HttpRunner`, same shape convention
  as `oracle_wrapper.Runner`/`nuclei_oracle.NucleiRunner`): tests never
  make a real network call; `default_http_runner` (the only piece that
  touches `requests`) is used in production and is swappable.
* **Loopback-only, lab-only, non-negotiable**, exactly like the other two
  oracle modules: every entry point calls `oracle_wrapper.assert_loopback`
  before firing any request.
"""

from __future__ import annotations

import dataclasses
import time
from enum import Enum
from typing import Callable, Mapping, MutableMapping, Optional
from urllib.parse import urlencode, urljoin

from .oracle_wrapper import assert_loopback

__all__ = [
    "SqlDialect",
    "DifferentialMode",
    "IdentifierSqliVerdict",
    "DialectNotImplementedError",
    "HttpProbeResult",
    "HttpRunner",
    "default_http_runner",
    "IdentifierSqliOracleRequest",
    "IdentifierSqliOracleVerdict",
    "run_identifier_sqli_oracle",
]


class SqlDialect(str, Enum):
    """DBMS dialects this module knows the name of. Only MySQL has phrasing
    implemented (task scope); the other two are named here so the
    *interface* (request/verdict shapes, control flow) never needs to
    change to add them -- only a new `_DIALECT_PHRASING` entry does."""

    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"


class DifferentialMode(str, Enum):
    """Which observable channel the two (TRUE/FALSE) probes are diffed on."""

    RESPONSE_DIFF = "response_diff"
    TIMING_BLIND = "timing_blind"


class IdentifierSqliVerdict(str, Enum):
    """The only three outcomes this module ever returns -- same fail-closed
    contract as `oracle_wrapper.Verdict`/`nuclei_oracle.NucleiVerdict`,
    defined independently here since this module takes no import dependency
    on either of those classes."""

    CONFIRMED_VULNERABLE = "confirmed_vulnerable"
    CONFIRMED_SECURE = "confirmed_secure"
    INCONCLUSIVE = "inconclusive"


class DialectNotImplementedError(NotImplementedError):
    """Raised instead of silently guessing a DBMS's CASE-WHEN/sleep syntax
    for a dialect this module has not implemented phrasing for yet."""


# --- per-dialect phrasing registry ------------------------------------------

@dataclasses.dataclass(frozen=True)
class _DialectPhrasing:
    """One DBMS's phrasing for the boolean-differential CASE-WHEN
    substitution and the blind timing signal. Adding a dialect means adding
    one of these to `_DIALECT_PHRASING`, never touching the prober's control
    flow (`_build_condition_value`/`_classify_*`)."""

    name: str
    case_when: Callable[[str, str, str], str]
    sleep_call: Callable[[float], str]


def _mysql_case_when(condition_sql: str, then_expr: str, else_expr: str) -> str:
    return f"(CASE WHEN ({condition_sql}) THEN {then_expr} ELSE {else_expr} END)"


def _mysql_sleep_call(seconds: float) -> str:
    return f"SLEEP({seconds})"


_DIALECT_PHRASING: Mapping[SqlDialect, _DialectPhrasing] = {
    SqlDialect.MYSQL: _DialectPhrasing(
        name="mysql", case_when=_mysql_case_when, sleep_call=_mysql_sleep_call,
    ),
    # PostgreSQL: CASE WHEN syntax is identical to MySQL's; only the sleep
    # call differs (`pg_sleep(n)` returns void and must be cast/used inside
    # a scalar subquery, e.g. `(SELECT pg_sleep(n))::text`). Left
    # unimplemented (task scope) -- add a `_DialectPhrasing` entry here.
    # SQLite: has no native sleep function; a `timing_blind` probe would
    # need a CPU-heavy expression standing in for SLEEP() (e.g. a
    # recursive CTE or repeated `randomblob`/`hex` calls, as sqlmap's own
    # "SQLite > 2.0 AND time-based blind (heavy query)" technique does --
    # see this module's docstring spot-check finding #2). `response_diff`
    # mode needs no dialect-specific phrasing beyond CASE WHEN, which is
    # already implemented in `_mysql_case_when` and is portable to SQLite
    # as-is. Left unimplemented (task scope) -- add a `_DialectPhrasing`
    # entry with a heavy-query `sleep_call` here.
}


def _phrasing_for(dialect: SqlDialect) -> _DialectPhrasing:
    phrasing = _DIALECT_PHRASING.get(dialect)
    if phrasing is None:
        raise DialectNotImplementedError(
            f"identifier_sqli_oracle has no CASE-WHEN/timing phrasing registered "
            f"for dialect {dialect.value!r} yet -- add a `_DialectPhrasing` entry "
            "to `_DIALECT_PHRASING` (see the module docstring) rather than "
            "guessing its syntax inline"
        )
    return phrasing


# --- HTTP probe result + dependency-injected runner -------------------------

@dataclasses.dataclass(frozen=True)
class HttpProbeResult:
    """The raw outcome of one HTTP probe, kept for debugging regardless of
    how it was classified. Mirrors the shape of
    `oracle_wrapper.OracleRunResult`/`nuclei_oracle.NucleiRunResult`
    (argv/returncode/stdout/stderr/timed_out/duration_s) adapted to an HTTP
    call instead of a subprocess."""

    url: str
    status_code: Optional[int]
    body: str
    timed_out: bool
    elapsed_s: float


# A runner is dependency-injected so tests never need to touch the network
# or a real target (see the test suite for the FakeHttpRunner used
# everywhere).
HttpRunner = Callable[[str, Mapping[str, str], Optional[str], float], HttpProbeResult]


def default_http_runner(
    url: str, headers: Mapping[str, str], cookie: Optional[str], timeout_s: float
) -> HttpProbeResult:
    """The real runner: fires a GET via `requests` (an existing project
    dependency -- see `fuzzlab/tools/spider.py`/`fetcher.py`) under a hard
    timeout."""
    import requests

    all_headers: MutableMapping[str, str] = dict(headers)
    if cookie:
        all_headers.setdefault("Cookie", cookie)
    start = time.monotonic()
    try:
        resp = requests.get(url, headers=all_headers, timeout=timeout_s)
        return HttpProbeResult(
            url=url,
            status_code=resp.status_code,
            body=resp.text,
            timed_out=False,
            elapsed_s=time.monotonic() - start,
        )
    except requests.exceptions.Timeout:
        return HttpProbeResult(
            url=url, status_code=None, body="", timed_out=True,
            elapsed_s=time.monotonic() - start,
        )
    except requests.exceptions.RequestException as exc:
        # A connection error (refused/reset/DNS) is not a timeout, but it is
        # just as unusable a signal as one -- surfaced with status_code=None
        # so `_classify` treats it the same way (fail-closed, never guessed
        # as either verdict).
        return HttpProbeResult(
            url=url, status_code=None, body=str(exc), timed_out=False,
            elapsed_s=time.monotonic() - start,
        )


# --- request shape ------------------------------------------------------

SessionRefresh = Callable[[], Mapping[str, str]]
"""Called once per attempt to obtain fresh headers/cookies immediately
before firing a probe pair. Kept for interface symmetry with
`oracle_wrapper.SessionRefresh`/`nuclei_oracle.SessionRefresh` (independently
defined here, same reasoning as `nuclei_oracle`)."""


@dataclasses.dataclass
class IdentifierSqliOracleRequest:
    """Everything needed to run the differential identifier-context probe
    against one declared (endpoint, query parameter) pair.

    `column_a`/`column_b` must be two real, distinct identifiers (column
    names, in the default `response_diff` mode two columns whose values
    differ across rows) that the vulnerable query would accept in the
    tainted position -- e.g. two real columns for an `ORDER BY`/`SELECT`
    injection, or two real table names for a JOIN-alias injection. In
    `response_diff` mode the oracle relies on their values actually
    differing to produce an observable diff; in `timing_blind` mode their
    identity does not matter beyond being valid identifiers (the sleep call
    stands in for them), so `column_a` alone is used as the harmless
    baseline value.
    """

    target_base_url: str
    endpoint_path: str
    param_name: str
    column_a: str
    column_b: str
    dialect: SqlDialect = SqlDialect.MYSQL
    mode: DifferentialMode = DifferentialMode.RESPONSE_DIFF
    true_condition_sql: str = "1=1"
    false_condition_sql: str = "1=2"
    base_query_params: Mapping[str, str] = dataclasses.field(default_factory=dict)
    sleep_seconds: float = 3.0
    timing_threshold_s: float = 2.5
    headers: Optional[Mapping[str, str]] = None
    cookie: Optional[str] = None
    refresh_session: Optional[SessionRefresh] = None
    timeout_s: float = 15.0
    max_attempts: int = 1


@dataclasses.dataclass(frozen=True)
class IdentifierSqliOracleVerdict:
    """The small, structured result the entry point returns."""

    outcome: IdentifierSqliVerdict
    dialect: SqlDialect
    mode: DifferentialMode
    reason: str
    baseline: Optional[HttpProbeResult] = None
    true_probe: Optional[HttpProbeResult] = None
    false_probe: Optional[HttpProbeResult] = None

    @property
    def confirmed_vulnerable(self) -> bool:
        return self.outcome is IdentifierSqliVerdict.CONFIRMED_VULNERABLE

    @property
    def confirmed_secure(self) -> bool:
        return self.outcome is IdentifierSqliVerdict.CONFIRMED_SECURE


# --- session resolution (mirrors oracle_wrapper._resolve_session) ----------

def _resolve_session(request: IdentifierSqliOracleRequest) -> tuple:
    cookie = request.cookie
    headers = dict(request.headers or {})
    if request.refresh_session is not None:
        fresh = dict(request.refresh_session())
        for key, value in fresh.items():
            if key.lower() == "cookie":
                cookie = value
            else:
                headers[key] = value
    return cookie, headers


def _build_url(request: IdentifierSqliOracleRequest, param_value: str) -> str:
    query = dict(request.base_query_params)
    query[request.param_name] = param_value
    base = request.target_base_url.rstrip("/") + "/"
    url = urljoin(base, request.endpoint_path.lstrip("/"))
    return f"{url}?{urlencode(query)}"


def _fire(
    request: IdentifierSqliOracleRequest,
    runner: HttpRunner,
    param_value: str,
    cookie: Optional[str],
    headers: Mapping[str, str],
) -> HttpProbeResult:
    url = _build_url(request, param_value)
    return runner(url, headers, cookie, request.timeout_s)


def _is_healthy(probe: HttpProbeResult) -> bool:
    return (not probe.timed_out) and probe.status_code is not None and 200 <= probe.status_code < 300


# --- classification -------------------------------------------------------

def _classify_response_diff(
    dialect: SqlDialect,
    baseline: HttpProbeResult,
    true_probe: HttpProbeResult,
    false_probe: HttpProbeResult,
) -> IdentifierSqliOracleVerdict:
    common = dict(dialect=dialect, mode=DifferentialMode.RESPONSE_DIFF,
                  baseline=baseline, true_probe=true_probe, false_probe=false_probe)
    # PA-0025: never infer "secure" (or "vulnerable") without independently
    # confirming the target was actually reached and executed the request --
    # a healthy baseline is the minimum bar.
    if not _is_healthy(baseline):
        return IdentifierSqliOracleVerdict(
            outcome=IdentifierSqliVerdict.INCONCLUSIVE,
            reason="baseline probe (a definitely-valid identifier value) did not "
                   "come back healthy (timeout or non-2xx) -- cannot trust any "
                   "diff (or lack of one) from probes fired against the same "
                   "unreachable/broken target (fail-closed, PA-0025)",
            **common,
        )
    if true_probe.timed_out or false_probe.timed_out:
        return IdentifierSqliOracleVerdict(
            outcome=IdentifierSqliVerdict.INCONCLUSIVE,
            reason="TRUE and/or FALSE differential probe timed out -- treated as "
                   "inconclusive, never as secure (fail-closed)",
            **common,
        )
    both_errored = not _is_healthy(true_probe) and not _is_healthy(false_probe)
    if both_errored:
        return IdentifierSqliOracleVerdict(
            outcome=IdentifierSqliVerdict.INCONCLUSIVE,
            reason="both TRUE and FALSE probes came back unhealthy (non-2xx) -- "
                   "the CASE-WHEN substitution may not even be reaching the "
                   "identifier position (e.g. rejected by an allowlist before "
                   "the query), so an identical pair of errors must never be "
                   "read as 'secure' (fail-closed, PA-0025)",
            **common,
        )
    if _is_healthy(true_probe) != _is_healthy(false_probe):
        return IdentifierSqliOracleVerdict(
            outcome=IdentifierSqliVerdict.INCONCLUSIVE,
            reason="TRUE and FALSE probes disagree on basic health (one 2xx, "
                   "the other not) -- an asymmetric error is not the "
                   "row-order/value differential this oracle looks for, and is "
                   "not a reliable secure signal either",
            **common,
        )
    if true_probe.body != false_probe.body:
        return IdentifierSqliOracleVerdict(
            outcome=IdentifierSqliVerdict.CONFIRMED_VULNERABLE,
            reason="the TRUE-condition and FALSE-condition CASE-WHEN "
                   "substitutions in the declared identifier position produced "
                   "different response bodies -- the query's structure "
                   "(column/table/alias choice) is controlled by attacker input",
            **common,
        )
    return IdentifierSqliOracleVerdict(
        outcome=IdentifierSqliVerdict.CONFIRMED_SECURE,
        reason="baseline, TRUE, and FALSE probes all came back healthy and the "
               "TRUE/FALSE response bodies are identical -- the CASE-WHEN "
               "substitution reached the endpoint but did not change the "
               "query's structure (consistent with parameterization or a real "
               "column/table allowlist)",
        **common,
    )


def _classify_timing_blind(
    dialect: SqlDialect,
    baseline: HttpProbeResult,
    true_probe: HttpProbeResult,
    false_probe: HttpProbeResult,
    threshold_s: float,
) -> IdentifierSqliOracleVerdict:
    common = dict(dialect=dialect, mode=DifferentialMode.TIMING_BLIND,
                  baseline=baseline, true_probe=true_probe, false_probe=false_probe)
    if not _is_healthy(baseline):
        return IdentifierSqliOracleVerdict(
            outcome=IdentifierSqliVerdict.INCONCLUSIVE,
            reason="baseline probe did not come back healthy -- cannot trust a "
                   "timing signal from the same unreachable/broken target "
                   "(fail-closed, PA-0025)",
            **common,
        )
    if true_probe.timed_out or false_probe.timed_out:
        # A hard client-side timeout on the TRUE probe is itself weak
        # evidence of the sleep firing, but it also means we cannot read an
        # exact elapsed time or the response body -- fail closed rather than
        # guess.
        return IdentifierSqliOracleVerdict(
            outcome=IdentifierSqliVerdict.INCONCLUSIVE,
            reason="TRUE and/or FALSE timing probe hit the client timeout "
                   "before a response was read -- cannot reliably distinguish "
                   "a SLEEP() firing from a hung/unreachable target "
                   "(fail-closed); raise `timeout_s` above `sleep_seconds` to "
                   "get a conclusive timing read",
            **common,
        )
    if not _is_healthy(true_probe) or not _is_healthy(false_probe):
        return IdentifierSqliOracleVerdict(
            outcome=IdentifierSqliVerdict.INCONCLUSIVE,
            reason="TRUE and/or FALSE timing probe came back unhealthy "
                   "(non-2xx) -- an error response makes the elapsed time "
                   "unreliable as a signal (fail-closed)",
            **common,
        )
    true_slept = true_probe.elapsed_s >= threshold_s
    false_slept = false_probe.elapsed_s >= threshold_s
    if true_slept and not false_slept:
        return IdentifierSqliOracleVerdict(
            outcome=IdentifierSqliVerdict.CONFIRMED_VULNERABLE,
            reason=f"TRUE-condition probe took {true_probe.elapsed_s:.2f}s "
                   f"(>= threshold {threshold_s}s) while the FALSE-condition "
                   f"probe took {false_probe.elapsed_s:.2f}s (< threshold) -- "
                   "the DBMS sleep call gated behind the CASE-WHEN in the "
                   "identifier position fired exactly when the injected "
                   "condition was true, a blind timing side channel",
            **common,
        )
    if not true_slept and not false_slept:
        return IdentifierSqliOracleVerdict(
            outcome=IdentifierSqliVerdict.CONFIRMED_SECURE,
            reason="neither the TRUE- nor the FALSE-condition probe showed the "
                   "configured timing delay -- the injected CASE-WHEN/SLEEP "
                   "expression never executed as SQL in the identifier "
                   "position",
            **common,
        )
    return IdentifierSqliOracleVerdict(
        outcome=IdentifierSqliVerdict.INCONCLUSIVE,
        reason=f"timing result is inconsistent with the boolean differential "
               f"(true_elapsed={true_probe.elapsed_s:.2f}s, "
               f"false_elapsed={false_probe.elapsed_s:.2f}s, "
               f"threshold={threshold_s}s) -- both probes slept, or neither "
               "matched the expected TRUE-only pattern; treated as "
               "inconclusive rather than guessed either way (fail-closed)",
        **common,
    )


def _run_pair(
    request: IdentifierSqliOracleRequest, runner: HttpRunner
) -> tuple:
    """Fire the baseline + TRUE + FALSE probes once, honoring
    `max_attempts`/`refresh_session` the same bounded-retry way
    `oracle_wrapper`/`nuclei_oracle` do: retry the *whole triplet* with a
    freshly refreshed session if any leg times out, up to `max_attempts`,
    never blocking the caller indefinitely."""
    phrasing = _phrasing_for(request.dialect)
    if request.mode is DifferentialMode.RESPONSE_DIFF:
        true_value = phrasing.case_when(
            request.true_condition_sql, request.column_a, request.column_b
        )
        false_value = phrasing.case_when(
            request.false_condition_sql, request.column_a, request.column_b
        )
    else:
        true_value = phrasing.case_when(
            request.true_condition_sql, phrasing.sleep_call(request.sleep_seconds), "0"
        )
        false_value = phrasing.case_when(
            request.false_condition_sql, phrasing.sleep_call(request.sleep_seconds), "0"
        )

    max_attempts = max(1, request.max_attempts)
    baseline = true_probe = false_probe = None
    for _ in range(max_attempts):
        cookie, headers = _resolve_session(request)
        baseline = _fire(request, runner, request.column_a, cookie, headers)
        true_probe = _fire(request, runner, true_value, cookie, headers)
        false_probe = _fire(request, runner, false_value, cookie, headers)
        if not (baseline.timed_out or true_probe.timed_out or false_probe.timed_out):
            break
    return baseline, true_probe, false_probe


def run_identifier_sqli_oracle(
    request: IdentifierSqliOracleRequest, runner: HttpRunner = default_http_runner
) -> IdentifierSqliOracleVerdict:
    """Fire a baseline probe plus a TRUE-condition / FALSE-condition
    boolean-differential pair against `request`'s declared identifier
    position and return a structured verdict.

    Never raises for a network/timeout/unhealthy-response condition (all
    downgrade to `IdentifierSqliVerdict.INCONCLUSIVE`, fail-closed) except
    `OracleSafetyError` (non-loopback target, raised by the reused
    `oracle_wrapper.assert_loopback`) and `DialectNotImplementedError` (no
    phrasing registered for `request.dialect`) -- both are configuration
    errors the caller must fix, not verdicts.
    """
    assert_loopback(request.target_base_url)
    _phrasing_for(request.dialect)  # raises DialectNotImplementedError up front
    baseline, true_probe, false_probe = _run_pair(request, runner)
    if request.mode is DifferentialMode.RESPONSE_DIFF:
        return _classify_response_diff(request.dialect, baseline, true_probe, false_probe)
    return _classify_timing_blind(
        request.dialect, baseline, true_probe, false_probe, request.timing_threshold_s
    )
