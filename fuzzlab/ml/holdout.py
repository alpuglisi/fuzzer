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

**The seal is per target (BUG-0091, FR-ML-19, PA-0092).** Once any model of a target
recorded a holdout, that target is *sealed*: `sealing_for_run` says so, and from then on
every producer of a label-derived ML number for the target — every trainer (an *implied*
holdout, even without ``--holdout``), every forward evaluation and every ML-tab panel —
leaves out the rows held out under every membership version the target recorded. One
mechanism decides it: `sealed_split` (and its reader form `held_ids`). A recorded
membership that the registry `MEMBERSHIPS` cannot evaluate exactly (an unregistered
version, or a fraction that differs) makes the target ``"unknown"``: run-scoped trainers
refuse (`SealingUnknown`), store-wide trains leave that target's labelled rows out, and
readers treat all its rows as sealed — fail closed.
"""

from __future__ import annotations

import hashlib
import json

from fuzzlab.core.urls import canonical_origin

HOLDOUT_VERSION = 1
HOLDOUT_FRACTION = 0.2
HOLDOUT_SALT = "fuzzlab-holdout-v1"
#: Every membership version that can be evaluated exactly: version -> (salt, fraction).
#: A version bump adds an entry here and never removes one, so an older model's held
#: rows stay computable (BUG-0091).
MEMBERSHIPS = {1: ("fuzzlab-holdout-v1", 0.2)}

#: `sealing_for_run`'s fail-closed answer.
UNKNOWN = "unknown"
SEALED = "sealed"


class SealingUnknown(RuntimeError):
    """A target recorded a holdout membership this code cannot evaluate exactly."""


def record() -> dict:
    """The membership a model trained with the holdout records (``calibration["holdout"]``,
    plus the held-out labelled row count added by the trainer)."""
    return {"version": HOLDOUT_VERSION, "fraction": HOLDOUT_FRACTION}


def matches_current(rec) -> bool:
    """Whether a recorded membership is today's (a saved model's holdout metrics are
    reported only then)."""
    return (isinstance(rec, dict) and rec.get("version") == HOLDOUT_VERSION
            and rec.get("fraction") == HOLDOUT_FRACTION)


def in_holdout(origin: str | None, endpoint: str, version: int | None = None) -> bool:
    """Whether ``endpoint`` of the target at canonical ``origin`` is held out under the
    registered membership ``version`` (today's when ``None``)."""
    if origin is None:
        return False
    salt, fraction = MEMBERSHIPS[HOLDOUT_VERSION if version is None else version]
    digest = hashlib.sha256(f"{salt}|{origin}|{endpoint}".encode()).hexdigest()
    return int(digest, 16) / 2 ** 256 < fraction


def _registered(rec) -> bool:
    """A recorded membership the registry evaluates exactly."""
    if not isinstance(rec, dict):
        return False
    v = rec.get("version")
    return (isinstance(v, int) and not isinstance(v, bool) and v in MEMBERSHIPS
            and rec.get("fraction") == MEMBERSHIPS[v][1])


def _sealing_of(recs) -> tuple | str | None:
    if not recs:
        return None
    if not all(_registered(r) for r in recs):
        return UNKNOWN
    return (SEALED, frozenset(r["version"] for r in recs))


def _run_origins(store) -> dict[int, str | None]:
    """Run id -> canonical origin of its recorded target (the first target row, as
    `dataset.target_of`)."""
    out: dict[int, str | None] = {}
    for r in store.conn.execute("SELECT run_id, base_url FROM target WHERE run_id IS NOT "
                                "NULL ORDER BY id").fetchall():
        out.setdefault(int(r["run_id"]), canonical_origin(r["base_url"]))
    return out


def _recorded(store, run_origin: dict) -> dict[str, list]:
    """Canonical origin -> the holdout records of every model row scoped to one of its
    runs (a store-wide row has no run, so no origin)."""
    out: dict[str, list] = {}
    for row in store.conn.execute("SELECT calibration FROM model").fetchall():
        try:
            cal = json.loads(row["calibration"] or "{}")
        except (ValueError, TypeError):
            continue
        rec = cal.get("holdout") if isinstance(cal, dict) else None
        rid = cal.get("run_id") if isinstance(cal, dict) else None
        if not rec or not isinstance(rid, int) or isinstance(rid, bool):
            continue
        origin = run_origin.get(rid)
        if origin is not None:
            out.setdefault(origin, []).append(rec)
    return out


def sealings(store, also: dict | None = None) -> dict[str, tuple | str]:
    """Every sealed target: canonical origin -> ``(SEALED, versions)`` or `UNKNOWN`.
    ``also`` adds records not yet stored (``{origin: record}``: a model being trained
    now)."""
    recs = _recorded(store, _run_origins(store))
    for origin, rec in (also or {}).items():
        if origin is not None:
            recs.setdefault(origin, []).append(rec)
    return {o: _sealing_of(r) for o, r in recs.items()}


def run_origin(store, run_id) -> str | None:
    """Canonical origin of a run's recorded target, or ``None``."""
    return None if run_id is None else _run_origins(store).get(int(run_id))


def sealing_for_run(store, run_id, also: dict | None = None):
    """The sealing of the run's target: ``None`` (never sealed, and ``also`` — a
    record for a model being trained now — adds nothing), ``(SEALED, versions)``, or
    `UNKNOWN` (fail closed). A run without a target row is never sealed."""
    origin = run_origin(store, run_id)
    if origin is None:
        return None
    return sealings(store, {origin: also} if also else None).get(origin)


def holdout_plan(store, run_id: int, explicit: bool) -> dict | None:
    """The holdout a **run-scoped** trainer applies: ``None`` (none asked, target not
    sealed), else ``{"implied": not explicit, "versions": ...}`` — today's version plus
    every version the target recorded. Raises `SealingUnknown` (the caller refuses)."""
    sealing = sealing_for_run(store, run_id, also=record() if explicit else None)
    if sealing == UNKNOWN:
        raise SealingUnknown(
            "holdout membership unknown for this target: a model recorded a membership "
            "version/fraction not in fuzzlab.ml.holdout.MEMBERSHIPS — refusing to train")
    if sealing is None and not explicit:
        return None
    versions = (sealing[1] if sealing else frozenset()) | {HOLDOUT_VERSION}
    if HOLDOUT_VERSION not in MEMBERSHIPS:
        raise SealingUnknown(f"holdout version {HOLDOUT_VERSION} is not registered in "
                             f"MEMBERSHIPS")
    return {"implied": not explicit, "versions": versions}


def model_record(p: dict, rows: int) -> dict:
    """The ``calibration["holdout"]`` a model trained under plan ``p`` records."""
    out = {**record(), "rows": rows}
    if p.get("implied"):
        out["implied"] = True
    if set(p["versions"]) != {HOLDOUT_VERSION}:
        out["versions"] = sorted(p["versions"])
    return out


def _origins(store, ids) -> dict[int, str | None]:
    """Candidate id -> canonical origin of its run's recorded target (None without);
    batched (chunked under SQLite's bound-parameter limit)."""
    ids = list(ids)
    run_of: dict[int, int] = {}
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for row in store.conn.execute(
                f"SELECT id, run_id FROM candidate WHERE id IN ({','.join('?' * len(chunk))})",
                chunk).fetchall():
            run_of[int(row["id"])] = int(row["run_id"])
    origin_of_run = _run_origins(store)
    return {cid: origin_of_run.get(run_of.get(cid)) for cid in ids}


def mask(store, ds) -> list[bool]:
    """Per row of ``ds``: held out under **today's** membership (a fixture helper; the
    trainers and readers use `sealed_split` / `held_ids`)."""
    origins = _origins(store, ds.ids)
    return [in_holdout(origins[cid], g) for cid, g in zip(ds.ids, ds.groups)]


def _partition(store, ds, *, run_id=None, p: dict | None = None):
    """``(held flags, unknown origins)`` per row of ``ds``. A row is held when its
    target is sealed and its endpoint is held out under any version that target
    recorded — plus, for ``run_id``'s target, the versions of plan ``p``. A row of an
    `UNKNOWN` target is held (fail closed) and its origin reported."""
    origins = _origins(store, ds.ids)
    seal = sealings(store)
    mine = run_origin(store, run_id) if p is not None else None
    held, unknown = [], set()
    for cid, endpoint in zip(ds.ids, ds.groups):
        origin = origins[cid]
        s = seal.get(origin)
        if s == UNKNOWN:
            unknown.add(origin)
            held.append(True)
            continue
        versions = set(s[1]) if s else set()
        if origin is not None and origin == mine:
            versions |= set(p["versions"])
        held.append(any(in_holdout(origin, endpoint, v) for v in versions))
    return held, sorted(unknown)


def sealed_split(store, ds, *, run_id=None, plan: dict | None = None,
                 skip_unknown: bool = False):
    """``(public, held)``: ``ds`` without and with its sealed rows — the one mechanism
    every trainer, forward evaluation and reader uses (PA-0003, PA-0092). Raises
    `SealingUnknown` when a row's target is `UNKNOWN`, unless ``skip_unknown`` (a
    store-wide train: those rows go to ``held``; see `unknown_origins`)."""
    flags, unknown = _partition(store, ds, run_id=run_id, p=plan)
    if unknown and not skip_unknown:
        raise SealingUnknown(f"holdout membership unknown for target(s) {unknown}")
    return (subset(ds, [i for i, h in enumerate(flags) if not h]),
            subset(ds, [i for i, h in enumerate(flags) if h]))


def unknown_origins(store, ds) -> list[str]:
    """The `UNKNOWN` targets among ``ds``'s rows (left out of a store-wide train)."""
    return _partition(store, ds)[1]


def held_ids(store, ds) -> set[int]:
    """The ids of ``ds``'s sealed rows — `sealed_split` for readers: an `UNKNOWN`
    target's rows are all sealed (never shown), never an error."""
    flags, _ = _partition(store, ds)
    return {cid for cid, h in zip(ds.ids, flags) if h}


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
    """``(kept, held)`` under **today's** membership only (a fixture helper; see
    `sealed_split`)."""
    held = mask(store, ds)
    return (subset(ds, [i for i, h in enumerate(held) if not h]),
            subset(ds, [i for i, h in enumerate(held) if h]))


def held_endpoints(store, run_id: int) -> int:
    """How many of the run's endpoints are sealed (label-free; printed by the CLI)."""
    from fuzzlab.ml.dataset import build_dataset
    every = build_dataset(store, run_id, include_unlabelled=True)
    p = {"versions": {HOLDOUT_VERSION}}
    flags, _ = _partition(store, every, run_id=run_id, p=p)
    return len({g for g, h in zip(every.groups, flags) if h})
