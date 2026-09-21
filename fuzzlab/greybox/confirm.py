"""M10 grey-box confirmation — the pure decision the oracle consults.

The oracle stays the sole finding-writer and fail-closed. M10 gives it one more
mechanism: where a black-box mechanism alone **abstains** (ambiguous), grey-box
evidence can confirm — the vulnerable **sink line executed** plus, for injection
that reaches the database, a **DB fault**. This module is only the decision + the
evidence it records; wiring it into `Oracle.confirm` (with the sources injected and
the sink's file/line known) is the live step (T3.6). Kept pure so the rule is
unit-tested here.

Mapping (by the oracle's `vuln_class`):
- ``sqli*``  → confirmed by M10 iff the sink was covered **and** a DB fault occurred.
- ``xss*``   → confirmed by M10 iff the sink (reflection point) was covered.
- others     → M10 does not confirm yet (returns False; the oracle abstains).
"""

from __future__ import annotations

from fuzzlab.greybox.reward import GreyboxSignal


def greybox_confirms(vuln_class: str, signal: GreyboxSignal) -> bool:
    """Whether M10 confirms this class from the grey-box signal alone."""
    vc = (vuln_class or "").lower()
    if vc.startswith("sqli"):
        return signal.sink_covered and signal.db_fault
    if vc.startswith("xss"):
        return signal.sink_covered
    return False


def m10_evidence(vuln_class: str, signal: GreyboxSignal) -> dict[str, object]:
    """Evidence dict recorded on a finding confirmed via M10."""
    return {
        "mechanism": "M10",
        "vuln_class": vuln_class,
        "sink_covered": signal.sink_covered,
        "db_fault": signal.db_fault,
        "novel_lines": signal.novel_lines,
    }
