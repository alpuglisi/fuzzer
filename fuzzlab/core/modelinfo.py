"""Label-free facts about a `model` row, read the same way by every reader (PA-0003).

In `core/` (not `fuzzlab.ml`) because `fuzzlab report` must work in a no-ML build
(FR-ML-6) and reads these facts too. Pure; no store access.
"""

from __future__ import annotations


def trained_on(calibration: dict) -> str:
    """What a model row was trained on: ``earlier`` runs, a ``saved`` model applied as
    is, or this ``run``'s own labels -- the default for a run-mode or legacy row, which
    never records the key."""
    value = calibration.get("trained_on")
    return value if value in ("earlier", "saved") else "run"
