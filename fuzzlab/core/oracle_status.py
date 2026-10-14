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
#: unreached rows `pending` — unlabelled — never NULL (which reads as labelled). Also left
#: on rows a safety breaker stopped before the oracle reached them (forms phase 2: the
#: header-point breaker, CC-CORE-0042); the reason is in the run's ``metrics`` /
#: ``skipped_points``, not in this column.
PENDING = "pending"
#: The candidate could not be decided: a cost cap stopped it, or no mechanism could
#: place the point. (1) A confirmer started a check but could not decide within its
#: cost cap (an SQLi family the hard cap kept from starting after an earlier one passed
#: its screen; CC-CORE-0043, FR-FUZZ-45) -- exhaustion follows a passed screen, so these
#: rows are the likeliest positives on noisy pages. (2) Every applicable mechanism
#: refused the point's location (`UnplaceableLocation`; mechanism ``unplaceable``,
#: CC-CORE-0046, FR-FUZZ-47) -- nothing was checked. Either way, never a negative
#: label; which one is in the run's ``inconclusive`` detail (its ``mechanism``).
INCONCLUSIVE = "inconclusive"

#: Statuses whose "no finding" is not a negative — nobody checked, or a check could
#: not decide. Never trained on as labels; still scored, ranked and anomaly-scored
#: (CC-ML-0014, CC-ML-0018, CC-ML-0028).
UNLABELLED = frozenset({SKIPPED_BUDGET, NO_CONFIRMER, PENDING, INCONCLUSIVE})
