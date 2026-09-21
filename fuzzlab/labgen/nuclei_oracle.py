"""Reusable, importable wrapper around Nuclei as an independent tool-oracle.

This is **generator-build-time validation tooling**, the same kind of thing as
``fuzzlab.labgen.oracle_wrapper`` (sqlmap/commix) and built for the same reason
(``docs/LAB_SEED_AUTHORING_PLAYBOOK.md`` Addendum E): confirm that a
manifest-generated code cell is really vulnerable, or really secure, using a
mature, independently-authored tool rather than hand-written exploit logic or
an LLM's opinion of its own code.

**Why this is a separate module, not an extension of ``oracle_wrapper``.**
sqlmap and commix each take a `-p <param>` flag and auto-detect a vulnerability
class against it; the "oracle" is the tool's own detection engine. Nuclei has
no such auto-detection: it runs hand-authored YAML **templates** against a
target and reports which ones matched. So the oracle here is two things
together: (1) a small set of hand-authored templates, one per confirmed class
(``lab/nuclei-templates/``), and (2) this thin wrapper that runs ``nuclei``
headlessly with one of them and returns the same fail-closed
``confirmed_vulnerable | confirmed_secure | inconclusive`` verdict shape
``oracle_wrapper`` uses, as its own independent type — this module never
imports the sqlmap/commix request/verdict dataclasses from ``oracle_wrapper``
and is never imported by it. It does reuse three *generic safety/lookup*
helpers from that module directly (``assert_loopback``, ``locate_tool``,
``ToolNotFoundError``) since those encode no sqlmap/commix-specific behavior.

Scope for this task (see ``docs/LAB_SEED_AUTHORING_PLAYBOOK.md`` and
``docs/spikes/SPIKE-004-nuclei-vs-dvwa.md``): **path traversal / local file
inclusion only**, validated for real against a real vulnerable/secure pair.
XXE, open redirect, and known-CVE templates are explicitly out of scope here
(a much larger, separate undertaking per the task brief) — the wrapper's
shape (a ``template_path`` parameter) does not preclude adding them later as
new template files plus a new thin request type, the same way this module
sits alongside, not inside, ``oracle_wrapper``.

Design notes, tracing directly to Spike 004 (``docs/spikes/SPIKE-004-nuclei-vs-dvwa.md``):

* **Nuclei has no equivalent of sqlmap's/commix's own textual "vulnerable" /
  "not injectable" markers.** A template either matches (vulnerable) or it
  doesn't (Nuclei prints nothing for a clean scan). So the positive signal is
  "did our template's JSONL output contain a match" and the negative signal is
  "the scan completed with zero matches" -- but see the next point for why
  that second half is not as simple as "no matches -> secure".
* **The load-bearing gotcha this spike found: Nuclei silently treats an
  unreachable target as a clean scan.** With ``-silent`` (or even without it,
  unless stderr is inspected), a target that refuses every connection still
  makes Nuclei exit ``0`` with zero JSONL results -- Nuclei's own health-check
  logs "``Skipped <host> from target list as found unresponsive
  permanently``" to stderr and *continues on to report "no results found"*
  rather than failing the run. A wrapper that classified "exit 0, no matches"
  as ``confirmed_secure`` would silently misreport an unreachable target as a
  secure twin. This module therefore **never passes ``-silent``**, always
  parses stderr for the host-unreachable signal, and downgrades to
  ``inconclusive`` whenever that signal is present, regardless of exit code
  (see ``_HOST_UNREACHABLE_RE`` and ``ERROR_LOG.md`` for the incident this
  produced when first discovered against a stopped local test server).
* **The tool invocation is scoped to exactly the declared (endpoint, param)
  pair**, the same "never a blind sweep" lesson Spike 002 produced for commix
  -- but here it is expressed as **template variables** (``-var
  endpoint_path=... -var param_name=...``) substituted into the bundled
  template's request path, rather than a tool-native parameter-selection
  flag (Nuclei has none; a template's request shape is fixed at authoring
  time, so the *variables* are the scoping mechanism).
* **A hung tool must never block the caller indefinitely.** Same bounded
  subprocess-timeout x max-attempts contract as ``oracle_wrapper``, via an
  independently defined (but structurally identical) injected ``Runner``.
* **Loopback-only, lab-only, non-negotiable.** Every entry point calls
  ``oracle_wrapper.assert_loopback`` before invoking ``nuclei``.
"""

from __future__ import annotations

import dataclasses
import json
import re
import subprocess
import time
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from .oracle_wrapper import assert_loopback, locate_tool
# Note: `locate_tool` raises `oracle_wrapper.ToolNotFoundError` on a missing
# binary; callers that want to catch it import it from `oracle_wrapper` (or
# `fuzzlab.labgen`) directly -- this module has no reason to re-import a name
# it never references by identity.

__all__ = [
    "TraversalVulnClass",
    "NucleiVerdict",
    "NucleiRunResult",
    "NucleiOracleVerdict",
    "NucleiRunner",
    "default_nuclei_runner",
    "DEFAULT_PATH_TRAVERSAL_TEMPLATE",
    "PathTraversalOracleRequest",
    "run_path_traversal_oracle",
]

# --- default bundled template -----------------------------------------------

# Repo-root-relative, matching the existing convention for LAB-component assets
# (see fuzzlab/labgen/verdict.py's DEFAULT_SAFETY_MATRIX_PATH) -- callers that
# invoke tooling from somewhere other than the repo root pass an explicit
# `template_path` instead.
DEFAULT_PATH_TRAVERSAL_TEMPLATE = Path("lab/nuclei-templates/path-traversal-etc-passwd.yaml")


class TraversalVulnClass(str, Enum):
    """The one class this module's bundled template validates for real
    (Spike 004). Kept as an enum (rather than a bare string) for symmetry with
    ``oracle_wrapper.VulnClass`` and room to grow without a breaking change."""

    PATH_TRAVERSAL = "path-traversal"


class NucleiVerdict(str, Enum):
    """The only three outcomes this module ever returns -- same fail-closed
    contract as ``oracle_wrapper.Verdict``, defined independently here since
    this module takes no import dependency on that class."""

    CONFIRMED_VULNERABLE = "confirmed_vulnerable"
    CONFIRMED_SECURE = "confirmed_secure"
    INCONCLUSIVE = "inconclusive"


@dataclasses.dataclass(frozen=True)
class NucleiRunResult:
    """The raw outcome of one `nuclei` subprocess invocation, kept for
    debugging regardless of how it was classified."""

    argv: Sequence[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float


# A runner is dependency-injected so tests never need to touch the real
# `subprocess` module or a real `nuclei` binary (see the test suite for the
# default fake used everywhere except the one skip-guarded integration test).
NucleiRunner = Callable[[Sequence[str], float], NucleiRunResult]


def default_nuclei_runner(argv: Sequence[str], timeout_s: float) -> NucleiRunResult:
    """The real runner: shells out via `subprocess.run` under a hard timeout."""
    start = time.monotonic()
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        return NucleiRunResult(
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
        return NucleiRunResult(
            argv=list(argv),
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            duration_s=time.monotonic() - start,
        )


@dataclasses.dataclass(frozen=True)
class NucleiOracleVerdict:
    """The small, structured result every entry point returns."""

    outcome: NucleiVerdict
    vuln_class: TraversalVulnClass
    reason: str
    run: Optional[NucleiRunResult] = None

    @property
    def confirmed_vulnerable(self) -> bool:
        return self.outcome is NucleiVerdict.CONFIRMED_VULNERABLE

    @property
    def confirmed_secure(self) -> bool:
        return self.outcome is NucleiVerdict.CONFIRMED_SECURE


# --- request shape ------------------------------------------------------

SessionRefresh = Callable[[], Mapping[str, str]]
"""Called once per attempt (see `max_attempts`) to obtain fresh headers/cookies
immediately before invoking `nuclei`. Kept for interface symmetry with
`oracle_wrapper`'s own `SessionRefresh` (independently defined here, same
reasoning: a target's ambient defenses -- e.g. a rotating anti-CSRF cookie --
are not the class under test, per Spike 002's finding, carried forward here
even though the class validated so far (path traversal) does not itself need
it)."""


@dataclasses.dataclass
class PathTraversalOracleRequest:
    """Everything needed to run the bundled path-traversal template headlessly
    against one declared (endpoint, parameter) pair."""

    target_base_url: str
    endpoint_path: str
    param_name: str
    headers: Optional[Mapping[str, str]] = None
    cookie: Optional[str] = None
    refresh_session: Optional[SessionRefresh] = None
    timeout_s: float = 120.0
    max_attempts: int = 1
    tool_path: Optional[str] = None
    template_path: Path = DEFAULT_PATH_TRAVERSAL_TEMPLATE
    extra_args: Sequence[str] = ()


# --- host-unreachable detection (Spike 004's load-bearing finding) ----------

# Nuclei's own health-check logs one of these to stderr and then reports "no
# results" with exit code 0 when a target refuses every connection -- see the
# module docstring and docs/spikes/SPIKE-004-nuclei-vs-dvwa.md. Matched
# case-insensitively against the whole stderr stream.
_HOST_UNREACHABLE_RE = re.compile(
    r"unresponsive permanently|could not connect|connection refused|"
    r"no such host|context deadline exceeded|no address associated",
    re.I,
)


def _resolve_session(request: PathTraversalOracleRequest) -> tuple[Optional[str], dict]:
    """Apply `refresh_session` (if any) for the current attempt, splitting a
    returned "Cookie" key out into the dedicated cookie slot -- mirrors
    `oracle_wrapper._resolve_session`, defined independently here."""
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


def _headers_flag_values(headers: Mapping[str, str]) -> list:
    argv: list = []
    for key, value in headers.items():
        argv += ["-H", f"{key}: {value}"]
    return argv


def _build_nuclei_argv(
    tool_path: str,
    request: PathTraversalOracleRequest,
    cookie: Optional[str],
    headers: Mapping[str, str],
) -> list:
    argv = [
        tool_path,
        "-u", request.target_base_url,
        "-t", str(request.template_path),
        "-var", f"endpoint_path={request.endpoint_path}",
        "-var", f"param_name={request.param_name}",
        "-jsonl",
        # Deliberately NOT -silent: the host-unreachable signal this module
        # depends on (Spike 004) is only printed at the default verbosity.
    ]
    all_headers = dict(headers)
    if cookie:
        all_headers.setdefault("Cookie", cookie)
    argv += _headers_flag_values(all_headers)
    argv += list(request.extra_args)
    return argv


def _parse_jsonl_matches(stdout: str) -> list:
    """Parse `nuclei -jsonl` stdout into a list of result objects, ignoring
    any non-JSON noise line rather than failing the whole classification on
    one malformed line."""
    matches = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            matches.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return matches


def _classify(run: NucleiRunResult, vuln_class: TraversalVulnClass) -> NucleiOracleVerdict:
    if run.timed_out:
        return NucleiOracleVerdict(
            outcome=NucleiVerdict.INCONCLUSIVE,
            vuln_class=vuln_class,
            reason="nuclei did not complete within the configured timeout/attempt "
                   "budget -- treated as inconclusive, never as secure (fail-closed)",
            run=run,
        )
    if _HOST_UNREACHABLE_RE.search(run.stderr):
        # Spike 004's load-bearing finding: nuclei's own health-check silently
        # skips an unreachable target and still reports "no results" with
        # exit code 0. Without this check, an unreachable target would be
        # misclassified as confirmed_secure.
        return NucleiOracleVerdict(
            outcome=NucleiVerdict.INCONCLUSIVE,
            vuln_class=vuln_class,
            reason="nuclei reported the target as unreachable (see stderr) -- "
                   "treated as inconclusive, never as secure, since nuclei itself "
                   "exits 0 with zero matches for a target it never actually "
                   "reached (Spike 004 finding)",
            run=run,
        )
    matches = _parse_jsonl_matches(run.stdout)
    if matches:
        return NucleiOracleVerdict(
            outcome=NucleiVerdict.CONFIRMED_VULNERABLE,
            vuln_class=vuln_class,
            reason=f"nuclei template matched ({len(matches)} result(s)) -- "
                   f"matched-at: {matches[0].get('matched-at', '?')!r}",
            run=run,
        )
    if run.returncode == 0:
        return NucleiOracleVerdict(
            outcome=NucleiVerdict.CONFIRMED_SECURE,
            vuln_class=vuln_class,
            reason="nuclei completed the scan (exit 0), reached the target "
                   "(no unreachable-host signal in stderr), and produced zero "
                   "matches for the template",
            run=run,
        )
    return NucleiOracleVerdict(
        outcome=NucleiVerdict.INCONCLUSIVE,
        vuln_class=vuln_class,
        reason=f"nuclei exited with status {run.returncode!r} and produced no "
               "template match -- treated as inconclusive, never as secure "
               "(fail-closed)",
        run=run,
    )


def _run_bounded(request: PathTraversalOracleRequest, tool_path: str, runner: NucleiRunner) -> NucleiRunResult:
    max_attempts = max(1, request.max_attempts)
    last_run: Optional[NucleiRunResult] = None
    for _ in range(max_attempts):
        cookie, headers = _resolve_session(request)
        argv = _build_nuclei_argv(tool_path, request, cookie, headers)
        last_run = runner(argv, request.timeout_s)
        if not last_run.timed_out:
            break
    assert last_run is not None  # max_attempts >= 1 guarantees at least one run
    return last_run


def run_path_traversal_oracle(
    request: PathTraversalOracleRequest, runner: NucleiRunner = default_nuclei_runner
) -> NucleiOracleVerdict:
    """Run the bundled path-traversal Nuclei template headlessly against
    `request.target_base_url` + `request.endpoint_path` (with
    `request.param_name` as the templated injection parameter) and return a
    structured verdict.

    Never raises for a tool crash/timeout/unreachable-target condition except
    `OracleSafetyError` (non-loopback target, raised by the reused
    `oracle_wrapper.assert_loopback`) and `ToolNotFoundError` (nuclei not
    found) -- both are configuration errors the caller must fix, not verdicts,
    so they are not silently downgraded to `inconclusive`.
    """
    assert_loopback(request.target_base_url)
    tool_path = locate_tool("nuclei", request.tool_path)
    run = _run_bounded(request, tool_path, runner)
    return _classify(run, TraversalVulnClass.PATH_TRAVERSAL)
