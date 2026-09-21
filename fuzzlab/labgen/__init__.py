"""Lab-generator support code (LAB component, generator-build-time tooling).

Independently-developed pieces of work land here concurrently: the manifest
schema / verdict engine / build gates (Phase 0 foundation, D20 — ``schema``,
``verdict``, ``subseed``, ``gates``, ``denylist``, ``resolver``), the
sqlmap/commix/SSTImap per-parameter oracle wrapper (``oracle_wrapper``), and
the ZAP whole-app safety-net oracle (``zap_oracle``, a separate module since
ZAP has no single declared parameter to scope by unlike the other three
tools) — all generator-build-time security-assertion tooling, unrelated to
and never imported by ``fuzzlab.oracle``. None depend on each other. This
re-exports all of them.
"""

from . import denylist, gates, resolver, schema, subseed, verdict
from .oracle_wrapper import (
    CommandInjectionOracleRequest,
    OracleRunResult,
    OracleSafetyError,
    OracleVerdict,
    ParamLocation,
    ServerSideTemplateInjectionOracleRequest,
    SqlInjectionOracleRequest,
    ToolNotFoundError,
    Verdict as OracleVerdictOutcome,
    VulnClass,
    assert_loopback,
    default_runner,
    locate_tool,
    run_command_injection_oracle,
    run_oracle,
    run_server_side_template_injection_oracle,
    run_sql_injection_oracle,
)
from .zap_oracle import (
    ZapScanVerdict,
    ZapWholeAppScanRequest,
    run_zap_whole_app_scan,
)

__all__ = [
    "denylist",
    "gates",
    "resolver",
    "schema",
    "subseed",
    "verdict",
    "CommandInjectionOracleRequest",
    "OracleRunResult",
    "OracleSafetyError",
    "OracleVerdict",
    "ParamLocation",
    "ServerSideTemplateInjectionOracleRequest",
    "SqlInjectionOracleRequest",
    "ToolNotFoundError",
    "OracleVerdictOutcome",
    "VulnClass",
    "assert_loopback",
    "default_runner",
    "locate_tool",
    "run_command_injection_oracle",
    "run_oracle",
    "run_server_side_template_injection_oracle",
    "run_sql_injection_oracle",
    "ZapScanVerdict",
    "ZapWholeAppScanRequest",
    "run_zap_whole_app_scan",
]
