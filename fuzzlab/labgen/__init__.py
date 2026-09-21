"""Lab-generator support code (LAB component, generator-build-time tooling).

Two independently-developed pieces of work landed here concurrently: the
manifest schema / verdict engine / build gates (Phase 0 foundation, D20 —
``schema``, ``verdict``, ``subseed``, ``gates``, ``denylist``) and the
sqlmap/commix oracle wrapper (``oracle_wrapper``, generator-build-time
security-assertion tooling, unrelated to and never imported by
``fuzzlab.oracle``). Neither depends on the other. This re-exports both.
"""

from . import denylist, gates, schema, subseed, verdict
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

__all__ = [
    "denylist",
    "gates",
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
]
