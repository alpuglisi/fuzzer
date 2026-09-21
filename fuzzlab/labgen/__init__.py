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
interfaces requiring on-host resources), a second, independent tool oracle
for Nuclei (``nuclei_oracle``, path traversal/LFI only — a separate module
from ``oracle_wrapper`` since Nuclei has no auto-detection against a
declared parameter the way sqlmap/commix/SSTImap do; it matches
hand-authored templates instead), the identity/ownership graph loader
(``identity``, Phase 2, CR-LAB-0001 §8, L-P2.1 — named test identities,
resource ownership, and binary authz expectations, loaded from
``lab/identities/identities.yaml``; deliberately decoupled from the
manifest/``Cell`` IR the same way ``lab/patterns/provenance.yaml`` is
decoupled from it, and never imported by ``verdict``), a third, independent
oracle for identifier/alias/connector-position SQL injection
(``identifier_sqli_oracle``, L-P1.2a — a custom differential-response
prober, since a real sqlmap spot-check confirmed it does not reliably
detect this class; see that module's docstring for the spot-check findings),
and a small LAB-owned session helper (``identity_session``, L-P2.2 — one
cookie jar per known, generator-controlled test identity, for build-time
oracle confirmation of stored/second-order cells; deliberately not the
toolkit's own separate Session-manager component) — all generator-build-time
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
    identity,
    minimal_pair,
    modules,
    resolver,
    schema,
    subseed,
    verdict,
)
from .identity_session import (
    DuplicateIdentityError,
    IdentityLike,
    IdentitySessionStore,
    Session as IdentitySession,
    UnknownIdentityError,
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
from .identifier_sqli_oracle import (
    DialectNotImplementedError,
    DifferentialMode,
    HttpProbeResult,
    IdentifierSqliOracleRequest,
    IdentifierSqliOracleVerdict,
    IdentifierSqliVerdict,
    SqlDialect,
    default_http_runner,
    run_identifier_sqli_oracle,
)

__all__ = [
    "conformance",
    "denylist",
    "emitter",
    "emitters",
    "fingerprint_gate",
    "gates",
    "identity",
    "minimal_pair",
    "modules",
    "resolver",
    "schema",
    "subseed",
    "verdict",
    "DuplicateIdentityError",
    "IdentityLike",
    "IdentitySessionStore",
    "IdentitySession",
    "UnknownIdentityError",
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
    "DialectNotImplementedError",
    "DifferentialMode",
    "HttpProbeResult",
    "IdentifierSqliOracleRequest",
    "IdentifierSqliOracleVerdict",
    "IdentifierSqliVerdict",
    "SqlDialect",
    "default_http_runner",
    "run_identifier_sqli_oracle",
]
