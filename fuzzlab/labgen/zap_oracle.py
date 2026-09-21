"""Reusable, importable wrapper around OWASP ZAP as a whole-app safety-net oracle.

Like ``fuzzlab.labgen.oracle_wrapper`` (sqlmap/commix/SSTImap), this is
**generator-build-time validation tooling** used to confirm a manifest-generated
code cell is really vulnerable, or really secure, before it is trusted as
ground truth — never `fuzzlab.oracle` (the unrelated runtime detection oracle).
It is kept in its own module, deliberately not merged into
``oracle_wrapper.py``, because ZAP is structurally different from the other
three tools (see ``docs/spikes/SPIKE-005-zap-vs-ssti-flask-hacking-playground.md``):

* sqlmap/commix/SSTImap each target **one declared parameter** for **one
  declared class** and return a single per-parameter verdict.
* ZAP is a **whole-app active scanner** (per `CR-LAB-0001`'s tool-mapping
  table: "Whole-app safety net → OWASP ZAP daemon mode / Automation
  Framework — Supplementary"). It crawls a target, then attacks every
  URL/parameter it found with dozens of active-scan rules across many
  vulnerability classes at once, producing a *list* of alerts rather than a
  single pass/fail for one parameter.

This module's request/verdict shape reflects that difference deliberately
(see `ZapWholeAppScanRequest`/`ZapScanVerdict` below) while keeping the same
spirit as `oracle_wrapper`'s contract: loopback-only enforcement before
anything runs, a typed error instead of a raw exception for a missing
binary, and a fail-closed `confirmed_vulnerable | confirmed_secure |
inconclusive` verdict where a crash, timeout, or unreadable report is always
`inconclusive`, never guessed as secure.

Mechanically, ZAP's own "Automation Framework" (a YAML plan consumed via
`zap.sh -cmd -autorun <plan>`) turns out to let this wrapper keep the same
*single bounded subprocess call* shape the other three tools use: the plan
crawls the target, runs the active scanner, and writes a structured JSON
report to a file, then the whole process exits — there is no long-lived
daemon or polling loop needed for this wrapper's purposes (see the spike for
why a `-daemon` + REST-API-polling design was considered and rejected as
unnecessary complexity for this use case).

Scoping lesson carried over from Spikes 001/002/003 (never a blind sweep):
by default this wrapper's verdict is scoped to **one declared alert-name
pattern** (`ZapWholeAppScanRequest.alert_name_pattern`), e.g. "the class
under test is reflected XSS, so only count alerts whose name matches
'Cross Site Scripting'" — not "any alert ZAP happens to raise anywhere on
the app," which would conflate the class actually under test with routine
noise (a missing CSP header, a version-disclosure header, etc.) present on
almost any target. Leaving `alert_name_pattern` unset opts into genuine
whole-app "safety net" mode (any alert at/above `risk_threshold` counts) —
useful as a supplementary check, but coarser and noisier by design; callers
confirming one specific cell's class should almost always set it.
"""

from __future__ import annotations

import dataclasses
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Mapping, Optional, Sequence

import yaml

from fuzzlab.labgen.oracle_wrapper import (
    OracleRunResult,
    OracleSafetyError,
    Runner,
    ToolNotFoundError,
    Verdict,
    assert_loopback,
    default_runner,
    locate_tool,
)

__all__ = [
    "ZapWholeAppScanRequest",
    "ZapScanVerdict",
    "run_zap_whole_app_scan",
]

_RISK_LEVELS = ("informational", "low", "medium", "high")


def _risk_code(name: str) -> int:
    try:
        return _RISK_LEVELS.index(name.strip().lower())
    except ValueError:
        raise ValueError(
            f"risk level must be one of {_RISK_LEVELS!r}, got {name!r}"
        )


@dataclasses.dataclass
class ZapWholeAppScanRequest:
    """Everything needed to run a ZAP Automation Framework scan against one app.

    Unlike the per-parameter request types in `oracle_wrapper`, there is no
    `param_name`/`param_location`: ZAP crawls and attacks the whole app
    reachable from `target_url`. `alert_name_pattern` is this request type's
    analogue of "scope to the one thing under test" (see module docstring).
    """

    target_url: str
    alert_name_pattern: Optional["re.Pattern[str]"] = None
    risk_threshold: str = "Medium"
    include_paths: Sequence[str] = ()
    spider_max_duration_min: int = 1
    passive_scan_max_duration_min: int = 2
    active_scan_max_duration_min: int = 5
    timeout_s: float = 300.0
    max_attempts: int = 1
    tool_path: Optional[str] = None
    zap_home_dir: Optional[str] = None
    report_dir: Optional[str] = None
    extra_env_parameters: Optional[Mapping[str, object]] = None


@dataclasses.dataclass(frozen=True)
class ZapAlert:
    """One alert as ZAP's own JSON report describes it, kept for debugging."""

    name: str
    risk: str
    confidence: str
    url: str
    param: str


@dataclasses.dataclass(frozen=True)
class ZapScanVerdict:
    """The result of one whole-app scan. Same fail-closed spirit as
    `oracle_wrapper.OracleVerdict` (`Verdict.CONFIRMED_VULNERABLE |
    CONFIRMED_SECURE | INCONCLUSIVE`), but carries the *list* of matching
    alerts (there can be more than one) instead of a single tool-output
    string, and `checked_for` describes the scope (an alert-name pattern, or
    "any alert" in whole-app safety-net mode) since there is no single
    declared parameter to name.
    """

    outcome: Verdict
    checked_for: str
    reason: str
    matching_alerts: Sequence[ZapAlert] = ()
    all_alerts: Sequence[ZapAlert] = ()
    run: Optional[OracleRunResult] = None

    @property
    def confirmed_vulnerable(self) -> bool:
        return self.outcome is Verdict.CONFIRMED_VULNERABLE

    @property
    def confirmed_secure(self) -> bool:
        return self.outcome is Verdict.CONFIRMED_SECURE


def _build_plan(request: ZapWholeAppScanRequest, report_dir: str, report_file: str) -> dict:
    include_paths = [f"{request.target_url.split('?', 1)[0].rstrip('/')}/.*"]
    include_paths.extend(request.include_paths)
    env_parameters = {
        "failOnError": False,
        "failOnWarning": False,
        "continueOnFailure": True,
        "progressToStdout": True,
    }
    if request.extra_env_parameters:
        env_parameters.update(request.extra_env_parameters)
    return {
        "env": {
            "contexts": [
                {
                    "name": "ctx",
                    "urls": [request.target_url.split("?", 1)[0]],
                    "includePaths": include_paths,
                }
            ],
            "parameters": env_parameters,
        },
        "jobs": [
            {
                "type": "spider",
                "parameters": {
                    "url": request.target_url,
                    "maxDuration": request.spider_max_duration_min,
                },
            },
            {
                "type": "passiveScan-wait",
                "parameters": {"maxDuration": request.passive_scan_max_duration_min},
            },
            {
                "type": "activeScan",
                "parameters": {"maxScanDurationInMins": request.active_scan_max_duration_min},
            },
            {
                "type": "report",
                "parameters": {
                    "template": "traditional-json-plus",
                    "reportDir": report_dir,
                    "reportFile": report_file,
                },
            },
        ],
    }


def _build_zap_argv(tool_path: str, plan_path: str, zap_home_dir: str) -> list:
    return [tool_path, "-cmd", "-dir", zap_home_dir, "-autorun", plan_path]


def _load_alerts(report_path: Path) -> list:
    data = json.loads(report_path.read_text())
    alerts: list = []
    for site in data.get("site", []):
        for raw in site.get("alerts", []):
            risk = str(raw.get("riskdesc", "")).split(" (")[0].strip() or "Informational"
            for instance in raw.get("instances", [{}]) or [{}]:
                alerts.append(
                    ZapAlert(
                        name=raw.get("name", ""),
                        risk=risk,
                        confidence=str(raw.get("riskdesc", "")).split("(")[-1].rstrip(")").strip(),
                        url=instance.get("uri", ""),
                        param=instance.get("param", ""),
                    )
                )
    return alerts


def run_zap_whole_app_scan(
    request: ZapWholeAppScanRequest, runner: Runner = default_runner
) -> ZapScanVerdict:
    """Run a ZAP Automation Framework whole-app scan against `request.target_url`
    and return a structured verdict. Never raises for a tool crash, timeout,
    unreadable/malformed report, or missing binary except `OracleSafetyError`
    (non-loopback target) and `ToolNotFoundError` (`zap.sh` not found) — both
    are configuration errors the caller must fix, not verdicts.
    """
    assert_loopback(request.target_url)
    tool_path = locate_tool("zap.sh", request.tool_path)
    checked_for = (
        request.alert_name_pattern.pattern
        if request.alert_name_pattern is not None
        else f"any alert at/above risk '{request.risk_threshold}' (whole-app safety-net mode)"
    )
    threshold_code = _risk_code(request.risk_threshold)

    owns_zap_home = request.zap_home_dir is None
    owns_report_dir = request.report_dir is None
    zap_home_dir = request.zap_home_dir or tempfile.mkdtemp(prefix="fzl-zap-home-")
    report_dir = request.report_dir or tempfile.mkdtemp(prefix="fzl-zap-report-")
    report_file = "report"
    report_path = Path(report_dir) / f"{report_file}.json"

    try:
        plan = _build_plan(request, report_dir, report_file)
        plan_fd, plan_path = tempfile.mkstemp(prefix="fzl-zap-plan-", suffix=".yaml")
        try:
            with open(plan_fd, "w") as fh:
                yaml.safe_dump(plan, fh, sort_keys=False)

            argv = _build_zap_argv(tool_path, plan_path, zap_home_dir)
            max_attempts = max(1, request.max_attempts)
            last_run: Optional[OracleRunResult] = None
            for _ in range(max_attempts):
                if report_path.exists():
                    report_path.unlink()  # never classify a stale report from a prior attempt
                last_run = runner(argv, request.timeout_s)
                if not last_run.timed_out:
                    break
            assert last_run is not None

            if last_run.timed_out:
                return ZapScanVerdict(
                    outcome=Verdict.INCONCLUSIVE,
                    checked_for=checked_for,
                    reason="ZAP did not complete within the configured timeout/attempt "
                           "budget -- treated as inconclusive, never as secure (fail-closed)",
                    run=last_run,
                )
            if not report_path.exists():
                return ZapScanVerdict(
                    outcome=Verdict.INCONCLUSIVE,
                    checked_for=checked_for,
                    reason=f"ZAP exited {last_run.returncode!r} without producing a report "
                           "file -- treated as inconclusive, never as secure (fail-closed)",
                    run=last_run,
                )
            try:
                alerts = _load_alerts(report_path)
            except (json.JSONDecodeError, OSError) as exc:
                return ZapScanVerdict(
                    outcome=Verdict.INCONCLUSIVE,
                    checked_for=checked_for,
                    reason=f"ZAP's report could not be read/parsed ({exc!r}) -- treated as "
                           "inconclusive, never as secure (fail-closed)",
                    run=last_run,
                )

            def _matches(alert: ZapAlert) -> bool:
                if _risk_code(alert.risk) < threshold_code:
                    return False
                if request.alert_name_pattern is None:
                    return True
                return bool(request.alert_name_pattern.search(alert.name))

            matching = [a for a in alerts if _matches(a)]
            if matching:
                return ZapScanVerdict(
                    outcome=Verdict.CONFIRMED_VULNERABLE,
                    checked_for=checked_for,
                    reason=f"{len(matching)} alert(s) matched at/above risk "
                           f"'{request.risk_threshold}'",
                    matching_alerts=matching,
                    all_alerts=alerts,
                    run=last_run,
                )
            return ZapScanVerdict(
                outcome=Verdict.CONFIRMED_SECURE,
                checked_for=checked_for,
                reason="scan completed and no alert matched the declared scope "
                       f"at/above risk '{request.risk_threshold}'",
                all_alerts=alerts,
                run=last_run,
            )
        finally:
            Path(plan_path).unlink(missing_ok=True)
    finally:
        if owns_report_dir:
            shutil.rmtree(report_dir, ignore_errors=True)
        if owns_zap_home:
            shutil.rmtree(zap_home_dir, ignore_errors=True)
