"""The deterministic blind holdout (FR-ML-7, partially; FR-ML-19; CC-ML-0020).

A fixed, versioned fraction of each target's **endpoints** is held out: no model trained
with ``holdout=True`` ever trains on, selects with or calibrates on a held-out endpoint,
and the deploy model's scores on the held-out labelled rows give metrics that are sealed
away from the summary surfaces (`fuzzlab.core.sealed`).

Membership is ``sha256(f"{salt}|{canonical origin}|{endpoint}") / 2**256 < fraction``:
a pure function of the target and the endpoint, so a held-out endpoint is held out in
every run, for every category and parameter, and the group folds and the holdout never
split an endpoint (`dataset.endpoint_key`). A row whose run has no target row has no
origin and is never held out.

*Deviation from D10, stated:* D10 splits by lab cell/transform; the key here is the
endpoint, an interim choice behind ``HOLDOUT_VERSION`` so a cell/transform key can
replace it. External validation (WAVSEP / Juice Shop) is not built. The guarantee is per
model. Label-free components (the hybrid's ECOD) may see held-out rows' *features* —
transductive, never their labels.
"""

from __future__ import annotations

import hashlib

from fuzzlab.core.urls import canonical_origin

HOLDOUT_VERSION = 1
HOLDOUT_FRACTION = 0.2
HOLDOUT_SALT = "fuzzlab-holdout-v1"


def record() -> dict:
    """The membership a model trained with the holdout records (``calibration["holdout"]``,
    plus the held-out labelled row count added by the trainer)."""
    return {"version": HOLDOUT_VERSION, "fraction": HOLDOUT_FRACTION}


def matches_current(rec) -> bool:
    """Whether a recorded membership is today's (a saved model's holdout metrics are
    reported only then)."""
    return (isinstance(rec, dict) and rec.get("version") == HOLDOUT_VERSION
            and rec.get("fraction") == HOLDOUT_FRACTION)


def in_holdout(origin: str | None, endpoint: str) -> bool:
    """Whether ``endpoint`` of the target at canonical ``origin`` is held out."""
    if origin is None:
        return False
    digest = hashlib.sha256(f"{HOLDOUT_SALT}|{origin}|{endpoint}".encode()).hexdigest()
    return int(digest, 16) / 2 ** 256 < HOLDOUT_FRACTION


def _origins(store, ids) -> dict[int, str | None]:
    """Candidate id -> canonical origin of its run's recorded target (None without)."""
    from fuzzlab.ml.dataset import target_of
    run_of: dict[int, int] = {}
    for cid in ids:
        row = store.conn.execute("SELECT run_id FROM candidate WHERE id=?", (cid,)).fetchone()
        if row is not None:
            run_of[cid] = int(row["run_id"])
    origin_of_run: dict[int, str | None] = {}
    for rid in set(run_of.values()):
        target = target_of(store, rid)
        origin_of_run[rid] = canonical_origin(target) if target else None
    return {cid: origin_of_run.get(run_of.get(cid)) for cid in ids}


def mask(store, ds) -> list[bool]:
    """Per row of ``ds``: held out?"""
    origins = _origins(store, ds.ids)
    return [in_holdout(origins[cid], g) for cid, g in zip(ds.ids, ds.groups)]


def subset(ds, keep):
    """A copy of ``ds`` with only the rows whose index is in ``keep`` (in order)."""
    from fuzzlab.ml.dataset import Dataset
    keep = list(keep)
    labelled = [ds.labelled[i] for i in keep] if len(ds.labelled) == len(ds.y) else []
    return Dataset(X=[ds.X[i] for i in keep], y=[ds.y[i] for i in keep],
                   groups=[ds.groups[i] for i in keep], ids=[ds.ids[i] for i in keep],
                   labelled=labelled, feature_names=list(ds.feature_names),
                   feature_version=ds.feature_version)


def split(store, ds):
    """``(kept, held)``: ``ds`` without and with its held-out rows."""
    held = mask(store, ds)
    return (subset(ds, [i for i, h in enumerate(held) if not h]),
            subset(ds, [i for i, h in enumerate(held) if h]))


def held_endpoints(store, run_id: int) -> int:
    """How many of the run's endpoints are held out (label-free; printed by the CLI)."""
    from fuzzlab.ml.dataset import build_dataset
    every = build_dataset(store, run_id, include_unlabelled=True)
    origins = _origins(store, every.ids)
    return len({g for cid, g in zip(every.ids, every.groups) if in_holdout(origins[cid], g)})
