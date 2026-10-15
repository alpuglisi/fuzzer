"""Label-free facts about a `model` row, read the same way by every reader (PA-0003).

In `core/` (not `fuzzlab.ml`) because `fuzzlab report` must work in a no-ML build
(FR-ML-6) and reads these facts too. Pure; no store access.
"""

from __future__ import annotations


def trained_on(calibration: dict) -> str | None:
    """What a model row was trained on: ``earlier`` runs, a ``saved`` model applied as
    is, or this ``run``'s own labels -- the default for a run-mode or legacy row, which
    never records the key. A recorded value that is none of these is malformed and reads
    as ``None`` (unknown), never as a default (PA-0108(2))."""
    if "trained_on" not in calibration:
        return "run"
    value = calibration["trained_on"]
    return value if value in ("run", "earlier", "saved") else None
