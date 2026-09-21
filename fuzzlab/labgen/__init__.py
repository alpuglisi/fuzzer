"""Lab-generator support code (LAB component, generator-build-time tooling).

Several independently-developed pieces of work landed here: the manifest
schema / verdict engine / build gates / covering-array resolver (Phase 0
foundation, D20 — ``schema``, ``verdict``, ``subseed``, ``gates``,
``denylist``, ``resolver``), the module-composition emitter interface and
first (``php_current``) emitter (T-LAB0.4 — ``emitter``, ``modules``,
``emitters``), the sqlmap/commix/SSTImap per-parameter oracle wrapper
(``oracle_wrapper``), the ZAP whole-app safety-net oracle (``zap_oracle``,
a separate module since ZAP has no single declared parameter to scope by
unlike the other three tools), the minimal-pair invariant checker
(``minimal_pair``, pulled forward from Phase 1 — a standalone offline check
that a cell's vulnerable/secure twins differ only within their declared
transform/sink region), and the fingerprint-independence build gate
(``fingerprint_gate``, `CR-LAB-0001` §3 — a chi-square test of independence
between stack and vuln_class/verdict, guarding against a stack becoming a
de facto proxy for a class once the generator goes multi-stack), and the
tiered emitter conformance suite (``conformance``, T-LAB0.7 — Tiers 0/3
fully exercised offline, Tiers 1/2 built as honestly-labeled ``[design]``
interfaces requiring on-host resources), and a second, independent tool
oracle for Nuclei (``nuclei_oracle``, path traversal/LFI only — a separate
module from ``oracle_wrapper`` since Nuclei has no auto-detection against a
declared parameter the way sqlmap/commix/SSTImap do; it matches
hand-authored templates instead) — all generator-build-time
security-assertion tooling, unrelated to and never imported by
``fuzzlab.oracle``. None of these depends on any other. This re-exports all
of them. ``fingerprint_gate`` imports ``scipy`` lazily inside its chi-square
functions (the optional ``labgen-stats`` extra), so importing this package
does not require it.
"""

from . import (
    conformance,
    denylist,
    emitter,
    emitters,
    fingerprint_gate,
    gates,
    minimal_pair,
    modules,
    resolver,
    schema,
    subseed,
    verdict,
)
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
from .nuclei_oracle import (
    NucleiOracleVerdict,
    NucleiRunResult,
    NucleiVerdict,
    PathTraversalOracleRequest,
    TraversalVulnClass,
    default_nuclei_runner,
    run_path_traversal_oracle,
)

__all__ = [
    "conformance",
    "denylist",
    "emitter",
    "emitters",
    "fingerprint_gate",
    "gates",
    "minimal_pair",
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
    "ZapScanVerdict",
    "ZapWholeAppScanRequest",
    "run_zap_whole_app_scan",
    "NucleiOracleVerdict",
    "NucleiRunResult",
    "NucleiVerdict",
    "PathTraversalOracleRequest",
    "TraversalVulnClass",
    "default_nuclei_runner",
    "run_path_traversal_oracle",
]
