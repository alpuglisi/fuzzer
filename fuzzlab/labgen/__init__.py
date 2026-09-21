"""Lab-generator support code (LAB component, generator-build-time tooling).

Several independently-developed pieces of work landed here: the manifest
schema / verdict engine / build gates / covering-array resolver (Phase 0
foundation, D20 — ``schema``, ``verdict``, ``subseed``, ``gates``,
``denylist``, ``resolver``), the module-composition emitter interface and
first (``php_current``) emitter (T-LAB0.4 — ``emitter``, ``modules``,
``emitters``), and the sqlmap/commix/SSTImap oracle wrapper
(``oracle_wrapper``, generator-build-time security-assertion tooling,
unrelated to and never imported by ``fuzzlab.oracle``). None of these
depends on any other. This re-exports all of them.
"""

from . import denylist, emitter, emitters, gates, modules, resolver, schema, subseed, verdict
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
    "emitter",
    "emitters",
    "gates",
    "modules",
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
]
