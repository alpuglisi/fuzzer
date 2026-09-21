"""Deterministic, class-pluggable confirmation oracle (Phase 2).

The oracle is the sole writer of `finding` labels. It is built from a small set of
confirmation *mechanisms* (see `docs/architecture/oracle-confirmation.md`); a
`ConfirmationStrategy` per vulnerability class selects the mechanism(s) that prove
it. Ambiguity is "not confirmed", never a guess (fail-closed). ML never writes
labels.

Phase 2 ships the mechanisms the current lab needs: differential timing (M1),
error signature (M2), boolean/response differential (M3) for SQLi, and
reflected-canary-in-executable-context (M5) for reflected XSS. Browser execution
(M6, stored/DOM XSS), out-of-band (M8), and grey-box (M10) come later.
"""

from fuzzlab.oracle.probe import Probe, Candidate, Verdict
from fuzzlab.oracle.oracle import Oracle
from fuzzlab.oracle.strategies import default_strategies

__all__ = ["Probe", "Candidate", "Verdict", "Oracle", "default_strategies"]
