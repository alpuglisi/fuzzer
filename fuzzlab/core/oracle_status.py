"""The vocabulary of `candidate.oracle_status` (migration 13) — one definition (PA-0003).

Written by the pipeline for every candidate it handles; read by the ML dataset to decide
which rows carry an oracle label. NULL (rows written before migration 13, or by a
non-pipeline writer) keeps the old meaning: treated as oracle-labelled.
"""

from __future__ import annotations

CHECKED = "checked"                  # the oracle looked: "no finding" is a real negative
SKIPPED_BUDGET = "skipped_budget"    # the confirmation budget ran out before it
NO_CONFIRMER = "no_confirmer"        # its category has no oracle confirmer yet
#: Written for every confirmable row before the oracle loop starts, then overwritten as
#: the oracle reaches it (CC-CORE-0033, BUG-0071): a run that crashes mid-loop leaves its
#: unreached rows `pending` — unlabelled — never NULL (which reads as labelled).
PENDING = "pending"

#: Statuses whose "no finding" is not a negative — nobody checked. Never trained on as
#: labels; still scored, ranked and anomaly-scored (CC-ML-0014, CC-ML-0018).
UNLABELLED = frozenset({SKIPPED_BUDGET, NO_CONFIRMER, PENDING})
