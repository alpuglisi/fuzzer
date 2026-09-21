"""Deterministic, class-pluggable confirmation oracle (Phase 2).

The oracle is the sole writer of `finding` labels. It is built from a small set of
confirmation *mechanisms* (see `docs/architecture/oracle-confirmation.md`); a
`ConfirmationStrategy` per vulnerability class selects the mechanism(s) that prove
it. Ambiguity is "not confirmed", never a guess (fail-closed). ML never writes
labels.

Implemented mechanisms: differential timing (M1) for SQLi *and* command injection,
error signature (M2) and boolean/response differential (M3) for SQLi,
evaluation-marker (M4) for SSTI, reflected-canary-in-executable-context (M5) for
reflected XSS, file-content-marker (M7) for path traversal/LFI,
redirect-target-control (M9) for open redirect, and browser execution (M6) for
stored + DOM XSS (via an injected `BrowserExecutor`; the live Playwright executor is
`fuzzlab/tools/browserexec.py`). Out-of-band (M8) and grey-box (M10) come later.

Each class is one `ConfirmationStrategy`; `applies()` scopes it to its vuln_class, so
adding a vector is adding a strategy (+ a `category_to_oracle_class` mapping). Which
categories actually run is scoped by the run plan (D14), so vectors beyond the
target's ground truth cost nothing unless selected.
"""

from fuzzlab.oracle.probe import Probe, Candidate, Verdict
from fuzzlab.oracle.oracle import Oracle
from fuzzlab.oracle.strategies import category_to_oracle_class, default_strategies

__all__ = ["Probe", "Candidate", "Verdict", "Oracle", "default_strategies",
           "category_to_oracle_class"]
