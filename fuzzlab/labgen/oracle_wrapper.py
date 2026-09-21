"""Reusable, importable wrapper around independent tool-oracles (sqlmap, commix,
SSTImap).

This is **generator-build-time validation tooling**: given a plain description of
an endpoint and a declared injection parameter, it shells out to a mature,
independently-authored exploitation tool headlessly and returns a small,
structured verdict (confirmed vulnerable / confirmed secure / inconclusive) used
to confirm that a manifest-generated code cell is really vulnerable, or really
secure, before it is trusted as ground truth.

It is unrelated to and independent of ``fuzzlab.oracle`` (the *runtime*
detection oracle the live fuzzing harness uses to score its own findings
against a target it does not control the ground truth of) — this module never
imports from, and is never imported by, ``fuzzlab.oracle``.

It is also independent of any manifest/schema object shape: callers pass plain,
explicit parameters (URL, method, parameter name/location, vulnerability class,
expected "secure" status code(s), timeout, an optional session/token-refresh
callback) rather than a "manifest cell" type, since that schema is designed and
owned elsewhere (see ``docs/change-requests/CR-LAB-0001-manifest-generator-realism-and-variation.md``
Addendum E and ``docs/LAB_SEED_AUTHORING_PLAYBOOK.md``).

Design notes, tracing directly to the three spikes that motivated this module
(``docs/spikes/SPIKE-001-sqlmap-vs-vapi.md``, ``docs/spikes/SPIKE-002-commix-vs-dvwa.md``,
``docs/spikes/SPIKE-003-sstimap-vs-ssti-flask-hacking-playground.md``):

* **sqlmap treats a 401/403 as an auth failure and refuses to test past it.**
  ``SqlInjectionOracleRequest.secure_status_codes`` is translated automatically
  into sqlmap's ``--ignore-code``; callers never need to know sqlmap's flag
  syntax (Spike 001). SSTImap has no equivalent status-code special-casing
  (verified by reading its source, Spike 003), so its request type has no
  such field.
* **commix must be scoped to the declared parameter only**, never a blind sweep
  of every form field — both request dataclasses always pass ``-p
  <param_name>`` (commix's own parameter-selection flag, the same convention
  sqlmap uses) rather than letting the tool discover parameters on its own
  (Spike 002). SSTImap has no ``-p`` flag; the equivalent scoping mechanism is
  its own **marker**, substituted into the declared parameter's exact value
  in the URL/body/header, combined with restricting ``-P`` to that one
  location category — this wrapper builds that marked request instead of
  ever letting SSTImap sweep every query/body/header/cookie field on its own
  (Spike 003).
* **A hung tool must never block the caller indefinitely.** Every invocation
  runs under a hard subprocess timeout (never sqlmap's/commix's own, less
  reliable, internal timeout flags) via an injected runner, and a timeout is
  always reported as ``inconclusive`` — never guessed as "secure" just because
  nothing conclusive came back (fail-closed). A bounded number of attempts
  (``max_attempts``) may be configured to retry once or twice with a freshly
  refreshed session before giving up; the total wall time is always bounded by
  ``timeout_s * max_attempts``, so a hung tool can never block the caller
  indefinitely even with retries enabled (Spike 002's rotating-CSRF-token
  finding). See the change-control entry for why a bounded timeout/retry was
  chosen over building generic per-request session-refresh machinery around
  each tool's own request loop.
* **Loopback-only, lab-only, non-negotiable.** Every entry point validates the
  target host before invoking either tool and raises ``OracleSafetyError``
  instead of ever silently proceeding against a non-loopback host.
"""

from __future__ import annotations

import dataclasses
import re
import shutil
import subprocess
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

__all__ = [
    "VulnClass",
    "ParamLocation",
    "Verdict",
    "OracleSafetyError",
    "ToolNotFoundError",
    "OracleRunResult",
    "OracleVerdict",
    "Runner",
    "default_runner",
    "assert_loopback",
    "locate_tool",
    "SqlInjectionOracleRequest",
    "CommandInjectionOracleRequest",
    "ServerSideTemplateInjectionOracleRequest",
    "run_sql_injection_oracle",
    "run_command_injection_oracle",
    "run_server_side_template_injection_oracle",
    "run_oracle",
]

# --- loopback allowlist (CR-LAB-0001 Addendum E / CLAUDE.md safety section) -

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class VulnClass(str, Enum):
    """The independent-tool-oracle-validated classes (Addendum E §1)."""

    SQL_INJECTION = "sql-injection"
    COMMAND_INJECTION = "command-injection"
    SERVER_SIDE_TEMPLATE_INJECTION = "server-side-template-injection"


class ParamLocation(str, Enum):
    """Where the declared injection parameter lives."""

    QUERY = "query"
    BODY = "body"
    HEADER = "header"


class Verdict(str, Enum):
    """The only three outcomes this module ever returns. There is no fourth
    "assume secure" outcome: ambiguity is never a guess (fail-closed, matching
    ``fuzzlab.oracle``'s existing philosophy of never inferring a positive from
    absence of a negative signal — see PA-0007)."""

    CONFIRMED_VULNERABLE = "confirmed_vulnerable"
    CONFIRMED_SECURE = "confirmed_secure"
    INCONCLUSIVE = "inconclusive"


class OracleSafetyError(RuntimeError):
    """Raised instead of ever running an oracle tool against a non-loopback host."""


class ToolNotFoundError(RuntimeError):
    """Raised instead of letting a raw ``FileNotFoundError`` propagate when the
    requested tool executable cannot be located (see BUG-0007 / PA-0021: a
    validation boundary that raises a typed error for some failure modes must
    raise it for every foreseeable one, including a missing executable)."""


@dataclasses.dataclass(frozen=True)
class OracleRunResult:
    """The raw outcome of one subprocess invocation, kept for debugging
    regardless of how it was classified."""

    argv: Sequence[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float


# A runner is dependency-injected so tests never need to touch the real
# `subprocess` module or a real binary (see the test suite for the default
# fake used everywhere except the one skip-guarded integration test).
Runner = Callable[[Sequence[str], float], OracleRunResult]


def default_runner(argv: Sequence[str], timeout_s: float) -> OracleRunResult:
    """The real runner: shells out via `subprocess.run` under a hard timeout."""
    start = time.monotonic()
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        return OracleRunResult(
            argv=list(argv),
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
            duration_s=time.monotonic() - start,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return OracleRunResult(
            argv=list(argv),
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            duration_s=time.monotonic() - start,
        )


@dataclasses.dataclass(frozen=True)
class OracleVerdict:
    """The small, structured result every entry point returns."""

    outcome: Verdict
    vuln_class: VulnClass
    reason: str
    run: Optional[OracleRunResult] = None

    @property
    def confirmed_vulnerable(self) -> bool:
        return self.outcome is Verdict.CONFIRMED_VULNERABLE

    @property
    def confirmed_secure(self) -> bool:
        return self.outcome is Verdict.CONFIRMED_SECURE


def assert_loopback(target_url: str) -> None:
    """Refuse anything that isn't loopback. Raises `OracleSafetyError`, never
    silently proceeds (CLAUDE.md safety section; CR-LAB-0001 Addendum E)."""
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise OracleSafetyError(
            f"target_url {target_url!r} must be a full http(s) URL with an "
            "explicit host so the loopback check can run -- refusing to guess"
        )
    host = parsed.hostname.lower()
    if host not in _LOOPBACK_HOSTS:
        raise OracleSafetyError(
            f"refusing to run oracle tooling against non-loopback host {host!r} "
            f"(target_url={target_url!r}): this is lab-only, authorized-only "
            "tooling (CLAUDE.md 'Safety' section) -- only localhost/127.0.0.1/::1 "
            "are permitted"
        )


def locate_tool(name: str, explicit_path: Optional[str] = None) -> str:
    """Find `name`'s executable, never raising a raw `FileNotFoundError`.

    Resolution order: an explicit path/command (if given) -> PATH lookup of
    `name`. Raises `ToolNotFoundError` with an actionable message otherwise.
    """
    candidate = explicit_path or name
    resolved = shutil.which(candidate)
    if resolved:
        return resolved
    if explicit_path and Path(explicit_path).is_file():
        return str(Path(explicit_path).resolve())
    raise ToolNotFoundError(
        f"{name!r} executable not found "
        + (f"at explicit path {explicit_path!r} or " if explicit_path else "")
        + "on PATH. Install it (see docs/LAB_SEED_AUTHORING_PLAYBOOK.md's "
        f"'Recommended next action') or pass an explicit path via the "
        f"`tool_path` parameter."
    )


# --- request shapes ----------------------------------------------------------

SessionRefresh = Callable[[], Mapping[str, str]]
"""Called once per attempt (see `max_attempts`) to obtain a fresh set of
headers/cookies immediately before invoking the tool. A key named
``"Cookie"``/``"cookie"`` (case-insensitive) is sent via the tool's dedicated
`--cookie` flag; every other key is sent as an ordinary header. This is the
'session/token-refresh awareness' half of the Spike 002 lesson; the bounded
timeout x max_attempts is the safety-valve half that guarantees the caller is
never blocked indefinitely regardless of whether a refresh callback is given."""


@dataclasses.dataclass
class SqlInjectionOracleRequest:
    """Everything needed to run sqlmap headlessly against one endpoint."""

    target_url: str
    param_name: str
    param_location: ParamLocation = ParamLocation.QUERY
    method: str = "GET"
    secure_status_codes: Sequence[int] = ()
    data: Optional[str] = None
    cookie: Optional[str] = None
    headers: Optional[Mapping[str, str]] = None
    refresh_session: Optional[SessionRefresh] = None
    timeout_s: float = 300.0
    max_attempts: int = 1
    tool_path: Optional[str] = None
    extra_args: Sequence[str] = ()
    vulnerable_marker: "re.Pattern[str]" = dataclasses.field(
        default_factory=lambda: re.compile(r"identified the following injection point", re.I)
    )
    secure_marker: "re.Pattern[str]" = dataclasses.field(
        default_factory=lambda: re.compile(r"does not seem to be injectable", re.I)
    )


@dataclasses.dataclass
class CommandInjectionOracleRequest:
    """Everything needed to run commix headlessly against one endpoint."""

    target_url: str
    param_name: str
    param_location: ParamLocation = ParamLocation.QUERY
    method: str = "GET"
    data: Optional[str] = None
    cookie: Optional[str] = None
    headers: Optional[Mapping[str, str]] = None
    refresh_session: Optional[SessionRefresh] = None
    timeout_s: float = 300.0
    max_attempts: int = 1
    tool_path: Optional[str] = None
    extra_args: Sequence[str] = ()
    vulnerable_marker: "re.Pattern[str]" = dataclasses.field(
        default_factory=lambda: re.compile(r"seems to be injectable", re.I)
    )
    secure_marker: "re.Pattern[str]" = dataclasses.field(
        default_factory=lambda: re.compile(r"does not seem to be injectable", re.I)
    )


@dataclasses.dataclass
class ServerSideTemplateInjectionOracleRequest:
    """Everything needed to run SSTImap headlessly against one endpoint.

    No ``secure_status_codes``/``--ignore-code``-equivalent field: SSTImap has
    no sqlmap-style "treat 401/403 as an unrecoverable auth failure" behavior
    (verified by reading its source, `docs/spikes/SPIKE-003-sstimap-vs-ssti-flask-hacking-playground.md`).

    Unlike sqlmap/commix, SSTImap has no ``-p``-style "test only this
    parameter" flag; scoping instead works by placing SSTImap's own
    ``marker`` string at the declared parameter's exact value (in the URL,
    body, or header, depending on `param_location`) and restricting SSTImap's
    ``-P`` injection-point flag to that one location category -- built
    automatically by `run_server_side_template_injection_oracle`, never left
    to SSTImap's own default, un-marked, all-locations sweep (Spike 003).
    """

    target_url: str
    param_name: str
    param_location: ParamLocation = ParamLocation.QUERY
    method: str = "GET"
    data: Optional[str] = None
    cookie: Optional[str] = None
    headers: Optional[Mapping[str, str]] = None
    refresh_session: Optional[SessionRefresh] = None
    timeout_s: float = 300.0
    max_attempts: int = 1
    tool_path: Optional[str] = None
    marker: str = "*"
    extra_args: Sequence[str] = ()
    vulnerable_marker: "re.Pattern[str]" = dataclasses.field(
        default_factory=lambda: re.compile(r"identified the following injection point", re.I)
    )
    secure_marker: "re.Pattern[str]" = dataclasses.field(
        default_factory=lambda: re.compile(r"appear(?:s)? to be not injectable", re.I)
    )


def _resolve_session(request) -> tuple[Optional[str], dict]:
    """Apply `refresh_session` (if any) for the current attempt, splitting a
    returned "Cookie" key out into the dedicated cookie slot."""
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


def _headers_flag_value(headers: Mapping[str, str]) -> str:
    return "\n".join(f"{key}: {value}" for key, value in headers.items())


def _build_sqlmap_argv(tool_path: str, request: SqlInjectionOracleRequest,
                        cookie: Optional[str], headers: Mapping[str, str]) -> list:
    argv = [sys.executable, tool_path, "--batch", "-u", request.target_url]
    if request.param_name:
        argv += ["-p", request.param_name]
    if request.method.upper() != "GET":
        argv += ["--method", request.method.upper()]
    if request.data is not None:
        argv += ["--data", request.data]
    if cookie:
        argv += ["--cookie", cookie]
    if headers:
        argv += ["--headers", _headers_flag_value(headers)]
    if request.secure_status_codes:
        # Spike 001's core lesson: sqlmap treats a 401/403 "secure" response
        # as an auth failure and refuses to test past it unless told to
        # ignore that status code explicitly.
        argv += ["--ignore-code", ",".join(str(code) for code in request.secure_status_codes)]
    argv += list(request.extra_args)
    return argv


def _build_commix_argv(tool_path: str, request: CommandInjectionOracleRequest,
                        cookie: Optional[str], headers: Mapping[str, str]) -> list:
    argv = [sys.executable, tool_path, "--batch", "--url", request.target_url]
    if request.param_name:
        # Spike 002's core lesson: scope to the declared parameter only,
        # never let commix sweep every form field.
        argv += ["-p", request.param_name]
    if request.data is not None:
        argv += ["--data", request.data]
    if cookie:
        argv += ["--cookie", cookie]
    if headers:
        argv += ["--headers", _headers_flag_value(headers)]
    argv += list(request.extra_args)
    return argv


def _mark_query_param(url: str, param_name: str, marker: str) -> str:
    """Return `url` with `param_name`'s query value replaced by `marker` (or
    `param_name=marker` appended if it wasn't already present)."""
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    marked = False
    new_pairs = []
    for key, value in pairs:
        if key == param_name:
            new_pairs.append((key, marker))
            marked = True
        else:
            new_pairs.append((key, value))
    if not marked:
        new_pairs.append((param_name, marker))
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def _mark_body_param(data: Optional[str], param_name: str, marker: str) -> str:
    """Return a `key=value&...` body string with `param_name`'s value
    replaced by `marker` (or `param_name=marker` appended if absent)."""
    pairs = parse_qsl(data or "", keep_blank_values=True)
    marked = False
    new_pairs = []
    for key, value in pairs:
        if key == param_name:
            new_pairs.append((key, marker))
            marked = True
        else:
            new_pairs.append((key, value))
    if not marked:
        new_pairs.append((param_name, marker))
    return urlencode(new_pairs)


_SSTIMAP_LOCATION_FLAG = {
    ParamLocation.QUERY: "Q",
    ParamLocation.BODY: "B",
    ParamLocation.HEADER: "H",
}


def _build_sstimap_argv(tool_path: str, request: ServerSideTemplateInjectionOracleRequest,
                         cookie: Optional[str], headers: Mapping[str, str]) -> list:
    # SSTImap has no `-p`-style parameter selector (Spike 003): scoping is
    # done by placing its marker at the declared parameter's exact value and
    # restricting `-P` to that one location category, never its default
    # un-marked, all-locations (`QBHC`) sweep.
    target_url = request.target_url
    data = request.data
    headers = dict(headers)
    if request.param_location == ParamLocation.QUERY:
        target_url = _mark_query_param(target_url, request.param_name, request.marker)
    elif request.param_location == ParamLocation.BODY:
        data = _mark_body_param(data, request.param_name, request.marker)
    elif request.param_location == ParamLocation.HEADER:
        headers[request.param_name] = request.marker

    argv = [
        sys.executable, tool_path,
        "-u", target_url,
        "-P", _SSTIMAP_LOCATION_FLAG[request.param_location],
    ]
    if request.marker != "*":
        argv += ["-M", request.marker]
    if request.method.upper() != "GET":
        argv += ["-m", request.method.upper()]
    if data is not None:
        argv += ["-d", data]
    if cookie:
        # SSTImap's -C is one 'Field=Value' pair per flag, stackable.
        for part in cookie.split(";"):
            part = part.strip()
            if part:
                argv += ["-C", part]
    for key, value in headers.items():
        argv += ["-H", f"{key}: {value}"]
    argv += list(request.extra_args)
    return argv


def _classify(run: OracleRunResult, vuln_class: VulnClass,
              vulnerable_marker: "re.Pattern[str]", secure_marker: "re.Pattern[str]") -> OracleVerdict:
    if run.timed_out:
        return OracleVerdict(
            outcome=Verdict.INCONCLUSIVE,
            vuln_class=vuln_class,
            reason="tool did not complete within the configured timeout/attempt budget "
                   "-- treated as inconclusive, never as secure (fail-closed)",
            run=run,
        )
    # Exit status alone is not a reliable secure/vulnerable signal: both
    # sqlmap and commix are observed (empirically, via the real-binary
    # integration test) to exit non-zero on a clean "not injectable" finding,
    # not only on a crash. So the tool's own textual verdict markers are
    # authoritative; a non-zero exit only matters when neither marker fired,
    # where it upgrades an otherwise-silent ambiguity into a more specific
    # inconclusive reason.
    combined = f"{run.stdout}\n{run.stderr}"
    is_vulnerable = bool(vulnerable_marker.search(combined))
    is_secure = bool(secure_marker.search(combined))
    if is_vulnerable and not is_secure:
        return OracleVerdict(Verdict.CONFIRMED_VULNERABLE, vuln_class,
                              "tool output matched the vulnerable marker", run)
    if is_secure and not is_vulnerable:
        return OracleVerdict(Verdict.CONFIRMED_SECURE, vuln_class,
                              "tool output matched the secure marker", run)
    if run.returncode not in (0,):
        return OracleVerdict(
            outcome=Verdict.INCONCLUSIVE,
            vuln_class=vuln_class,
            reason=f"tool exited with status {run.returncode!r} and produced neither "
                   "verdict marker -- treated as inconclusive, never as secure (fail-closed)",
            run=run,
        )
    return OracleVerdict(
        Verdict.INCONCLUSIVE, vuln_class,
        "tool output matched neither exactly one of the vulnerable/secure markers "
        "(none, or both -- either way, ambiguous)",
        run,
    )


def _run_bounded(build_argv, tool_name: str, request, runner: Runner) -> OracleRunResult:
    tool_path = locate_tool(tool_name, request.tool_path)
    max_attempts = max(1, request.max_attempts)
    last_run: Optional[OracleRunResult] = None
    for _ in range(max_attempts):
        cookie, headers = _resolve_session(request)
        argv = build_argv(tool_path, request, cookie, headers)
        last_run = runner(argv, request.timeout_s)
        if not last_run.timed_out:
            break
    assert last_run is not None  # max_attempts >= 1 guarantees at least one run
    return last_run


def run_sql_injection_oracle(
    request: SqlInjectionOracleRequest, runner: Runner = default_runner
) -> OracleVerdict:
    """Run sqlmap headlessly against `request.target_url` and return a
    structured verdict. Never raises for a tool crash/timeout/missing-binary
    condition except `OracleSafetyError` (non-loopback target) and
    `ToolNotFoundError` (sqlmap not found) -- both are configuration errors
    the caller must fix, not verdicts, so they are not silently downgraded to
    `inconclusive`.
    """
    assert_loopback(request.target_url)
    run = _run_bounded(_build_sqlmap_argv, "sqlmap", request, runner)
    return _classify(run, VulnClass.SQL_INJECTION, request.vulnerable_marker, request.secure_marker)


def run_command_injection_oracle(
    request: CommandInjectionOracleRequest, runner: Runner = default_runner
) -> OracleVerdict:
    """Run commix headlessly against `request.target_url` and return a
    structured verdict. Same fail-closed contract as `run_sql_injection_oracle`.
    """
    assert_loopback(request.target_url)
    run = _run_bounded(_build_commix_argv, "commix", request, runner)
    return _classify(run, VulnClass.COMMAND_INJECTION, request.vulnerable_marker, request.secure_marker)


def run_server_side_template_injection_oracle(
    request: ServerSideTemplateInjectionOracleRequest, runner: Runner = default_runner
) -> OracleVerdict:
    """Run SSTImap headlessly against `request.target_url` and return a
    structured verdict. Same fail-closed contract as `run_sql_injection_oracle`.
    """
    assert_loopback(request.target_url)
    run = _run_bounded(_build_sstimap_argv, "sstimap", request, runner)
    return _classify(run, VulnClass.SERVER_SIDE_TEMPLATE_INJECTION,
                      request.vulnerable_marker, request.secure_marker)


def run_oracle(
    request, runner: Runner = default_runner
) -> OracleVerdict:
    """Dispatch to the right tool based on the request's own type. A thin
    convenience for callers that already have a `SqlInjectionOracleRequest`,
    `CommandInjectionOracleRequest`, or `ServerSideTemplateInjectionOracleRequest`
    in hand and don't want an if/else of their own; does not accept or assume
    any manifest/schema type."""
    if isinstance(request, SqlInjectionOracleRequest):
        return run_sql_injection_oracle(request, runner)
    if isinstance(request, CommandInjectionOracleRequest):
        return run_command_injection_oracle(request, runner)
    if isinstance(request, ServerSideTemplateInjectionOracleRequest):
        return run_server_side_template_injection_oracle(request, runner)
    raise TypeError(
        f"run_oracle() only accepts SqlInjectionOracleRequest, "
        f"CommandInjectionOracleRequest, or ServerSideTemplateInjectionOracleRequest, "
        f"got {type(request).__name__}"
    )
