"""The tiered emitter conformance suite (T-LAB0.7).

Per ``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.7 (the report's own §5.1/§5.6:
"write the suite before the second emitter"): a stack-agnostic, HTTP-level
suite any future emitter must pass, for every ``(class, sink_context)`` it
declares support for. Structured in four tiers, fastest first
(``CR-LAB-0001`` Addendum C):

- **Tier 0** (:mod:`fuzzlab.labgen.conformance.tier0`) -- lint + minimal-pair
  diff. Seconds, no container. **Fully exercised offline by this task**
  (a real ``php -l`` syntax check; a minimal-pair structural check that
  upgrades automatically once the sibling-owned
  ``fuzzlab.labgen.minimal_pair`` lands).
- **Tier 1** (:mod:`fuzzlab.labgen.conformance.tier1`) -- in-process
  functional + security assertion. **[design]** -- needs a real in-process
  app plus a real, long-lived database container (never in-memory SQLite,
  which produces dialect-dependent false passes for SQLi cells); this
  session is offline-only, so only the interface and decision logic are
  built and tested against synthetic responses via a fake client, never a
  live app.
- **Tier 2** (:mod:`fuzzlab.labgen.conformance.tier2`) -- the full
  container-based oracle, the only tier that actually confirms a label.
  **[design]** -- same on-host requirement as Tier 1, with no meaningful
  offline stand-in at all.
- **Tier 3** (:mod:`fuzzlab.labgen.conformance.tier3`) -- whole-lab
  regeneration. **Fully exercised offline by this task** (two full renders
  of a real emitter's output, byte-diffed).

A Tier-0 or Tier-1 pass is never recorded as oracle confirmation -- only a
real Tier-2 run is (T-LAB0.7's own rule). This package's own offline test
suite proves Tier 0/3 for real and Tier 1/2's *interfaces* only (including
their explicit refusal to run without a real client/oracle); running Tier
1/2 against the real lab is separate, on-host work, out of scope for this
session. See each tier module's own docstring for the exact "what is real
vs. what is design-only" boundary.

Each ``(vuln_class, sink_context.family)`` shape also carries a
``static_precheck: informative | uninformative`` flag
(:mod:`fuzzlab.labgen.conformance.static_precheck`) so a static/taint-style
checker's clean scan is never mistaken for confirmation on a shape it is
structurally blind to.
"""

from __future__ import annotations

from fuzzlab.labgen.conformance.static_precheck import (
    NoStaticCheckerConfiguredError,
    PrecheckResult,
    StaticPrecheckStatus,
    run_static_precheck,
    static_precheck_status,
)
from fuzzlab.labgen.conformance.tier0 import (
    LintResult,
    MinimalPairResult,
    get_minimal_pair_checker,
    lint_emitted_files,
    lint_php,
    php_available,
)
from fuzzlab.labgen.conformance.tier1 import (
    OnHostRequiredError,
    Tier1Case,
    Tier1Client,
    Tier1Outcome,
    build_tier1_case,
    evaluate_tier1_response,
    run_tier1_case,
)
from fuzzlab.labgen.conformance.tier2 import Tier2Oracle, Tier2Outcome, run_tier2_case
from fuzzlab.labgen.conformance.tier3 import RegenerateDiffError, regenerate_and_diff_emitter, render_whole_sample

__all__ = [
    "NoStaticCheckerConfiguredError",
    "PrecheckResult",
    "StaticPrecheckStatus",
    "run_static_precheck",
    "static_precheck_status",
    "LintResult",
    "MinimalPairResult",
    "get_minimal_pair_checker",
    "lint_emitted_files",
    "lint_php",
    "php_available",
    "OnHostRequiredError",
    "Tier1Case",
    "Tier1Client",
    "Tier1Outcome",
    "build_tier1_case",
    "evaluate_tier1_response",
    "run_tier1_case",
    "Tier2Oracle",
    "Tier2Outcome",
    "run_tier2_case",
    "RegenerateDiffError",
    "regenerate_and_diff_emitter",
    "render_whole_sample",
]
