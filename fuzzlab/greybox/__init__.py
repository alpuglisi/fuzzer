"""Grey-box instrumentation — consumer side (Phase 3).

The *capture* of grey-box signals (pcov line coverage, DB faults, lab reset) runs
on the instrumented lab host; this package is the **consumer** side that turns those
signals into a reward and a confirmation input. Every reader is defined behind an
injected-source protocol (like the oracle's `Sender`), so the reward math, the
coverage frontier, the reset hook, and the M10 decision are all unit-testable
offline with in-memory fakes. The live readers that back these protocols are the
on-host last mile (`docs/ON_HOST_TASKS.md`).

Grey-box is corroborating, not a shortcut: it feeds `attempt.reward`/`attempt.coverage`
/`attempt.db_fault` and gives the oracle its M10 input, but the oracle stays the sole
finding-writer and fail-closed.
"""

from fuzzlab.greybox.coverage import (
    CoverageFrontier,
    CoverageSource,
    InMemoryCoverageSource,
    app_lines,
    encode_coverage,
)
from fuzzlab.greybox.dbfault import DbFaultSource, InMemoryDbFaultSource
from fuzzlab.greybox.reset import FakeLabControl, LabControl
from fuzzlab.greybox.reward import GreyboxSignal, shaped_reward
from fuzzlab.greybox.confirm import greybox_confirms, m10_evidence
from fuzzlab.greybox.recorder import record_attempt_signals

__all__ = [
    "CoverageSource", "InMemoryCoverageSource", "CoverageFrontier", "app_lines",
    "encode_coverage",
    "DbFaultSource", "InMemoryDbFaultSource",
    "LabControl", "FakeLabControl",
    "GreyboxSignal", "shaped_reward",
    "greybox_confirms", "m10_evidence",
    "record_attempt_signals",
]
