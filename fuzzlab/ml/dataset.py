"""Assemble a trainable dataset from the store (Phase 5 T5.2).

One example per **candidate** (an injection point nominated for a category). The label
is whether the oracle **confirmed** it — positives from `finding`, negatives from
candidates with no matching finding (the rejected/never-confirmed ones). Grouped by
endpoint (path) so `group_kfold` never leaks a page across folds. Features are a fixed,
versioned vector derived from what discovery/audit reliably record — no labels leak in.

Advisory only: this feeds scoring/ranking, never `finding` labels.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fuzzlab.core.evidence import parse_evidence
from fuzzlab.core.features import (CANDIDATE_FEATURE_NAMES, CANDIDATE_FEATURE_VERSION,
                                   extract_candidate_v1)
from fuzzlab.core.oracle_status import UNLABELLED
from fuzzlab.core.runmode import to_category
from fuzzlab.core.urls import canonical_origin, to_path

# The candidate feature vector is computed by `core/`'s versioned extractor (FR-ML-5,
# CC-CORE-0031); these aliases keep every persisted model's `feature_names` /
# `feature_version` and `check_compatible` unchanged.
FEATURE_NAMES = CANDIDATE_FEATURE_NAMES
FEATURE_VERSION = CANDIDATE_FEATURE_VERSION
_features = extract_candidate_v1


@dataclass
class Dataset:
    X: list[list[float]] = field(default_factory=list)
    y: list[int] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    ids: list[int] = field(default_factory=list)       # candidate ids, to write scores back
    # False for a budget-skipped row (only present with include_unlabelled=True):
    # its y is a placeholder 0, never a negative label
    labelled: list[bool] = field(default_factory=list)
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    feature_version: int = FEATURE_VERSION
    #: candidates in scope whose evidence is unreadable: skipped, never fabricated
    #: (BUG-0107); `scope_total` counts every candidate the query selected
    quarantined: list[int] = field(default_factory=list)
    scope_total: int = 0
    #: runs with a quarantined row and a finding no readable candidate matches: a
    #: label may have been lost with the quarantined row
    label_loss_runs: list[int] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.y)

    @property
    def positives(self) -> int:
        if len(self.labelled) != len(self.y):          # hand-built: all labelled
            return sum(self.y)
        return sum(y for y, lab in zip(self.y, self.labelled) if lab)


def method_key(method) -> str:
    """The HTTP method as every label / seen-key join compares it: upper-case, and
    ``GET`` when missing (the evidence default). The one definition (PA-0003) for both
    sides of a join (BUG-0075, PA-0076)."""
    return method.upper() if isinstance(method, str) and method else "GET"


def endpoint_key(ev: dict) -> str:
    """The endpoint a candidate belongs to — its URL path. The one definition for the
    group-k-fold groups and for blind-holdout membership (PA-0003, CC-ML-0020): folds
    and the holdout never split an endpoint."""
    return to_path(ev.get("url", ""))


def target_runs(store, target: str) -> list[int]:
    """Runs whose recorded target is ``target``, compared as canonical origins — so
    ``localhost:8080`` and ``127.0.0.1:8080`` are one target (CC-ML-0018, D-b)."""
    want = canonical_origin(target)
    if want is None:                     # no usable host: matches nothing
        return []
    return sorted({int(r["run_id"]) for r in store.conn.execute(
        "SELECT run_id, base_url FROM target WHERE run_id IS NOT NULL").fetchall()
        if canonical_origin(r["base_url"]) == want})


def _run_filter(store, run_id, before_run_id, target) -> tuple[str, tuple]:
    """SQL condition on a table's `run_id` column for the requested scope."""
    conds, args = [], []
    if run_id is not None:
        conds.append("run_id=?")
        args.append(run_id)
    if before_run_id is not None:
        conds.append("run_id<?")
        args.append(before_run_id)
    if target is not None:
        # only pipeline runs record a target row; a run without one never matches
        runs = target_runs(store, target)
        conds.append(f"run_id IN ({','.join('?' * len(runs))})" if runs else "0")
        args.extend(runs)
    return (" AND ".join(conds) or "1=1"), tuple(args)


def build_dataset(store, run_id: int | None = None, *, include_unlabelled: bool = False,
                  before_run_id: int | None = None, target: str | None = None) -> Dataset:
    """One example per candidate in scope.

    Scope: one run (``run_id``), or every run (``None``), optionally narrowed to runs
    before ``before_run_id`` and/or against ``target`` (the pipeline's
    ``target.base_url``). Labels and the ``rules_fired`` count come from each
    candidate's **own run** only — never from another run's findings or evaluations
    (BUG-0065: the store-wide view used to pool them, leaking labels across runs and
    targets and inflating counts).

    Candidates nobody checked (``oracle_status`` in `UNLABELLED`: skipped for budget,
    or in a category with no oracle confirmer — CC-ML-0018) have no label, so they are
    left out unless ``include_unlabelled`` (label-free uses: scoring every row, anomaly
    detection); they are then marked ``labelled=False``. ``target`` is compared as a
    canonical origin (`target_runs`).
    """
    where, args = _run_filter(store, run_id, before_run_id, target)

    # Keyed on every identity field both tables record, the method included (BUG-0075:
    # a finding confirmed only on POST used to label the GET candidate positive). A
    # finding with no recorded method (legacy / hand-written) matches any method, as
    # before — such rows never flip.
    positives: set[tuple[int, str, str, str, str]] = set()
    any_method: set[tuple[int, str, str, str]] = set()
    for f in store.conn.execute(
            f"SELECT run_id, url, param, vuln_class, method FROM finding WHERE {where}",
            args).fetchall():
        key = (int(f["run_id"]), f["url"], f["param"], to_category(f["vuln_class"]))
        if f["method"] is None:
            any_method.add(key)
        else:
            positives.add((*key, method_key(f["method"])))

    fired: dict[tuple[int, str, str], int] = {}
    for e in store.conn.execute(
            f"SELECT run_id, url, param, fired FROM evaluation WHERE {where}",
            args).fetchall():
        if e["fired"]:
            key = (int(e["run_id"]), to_path(e["url"]), e["param"])
            fired[key] = fired.get(key, 0) + 1

    ds = Dataset()
    matched: set = set()                        # finding keys a readable row matched
    quarantined_runs: set[int] = set()
    for c in store.conn.execute(
            f"SELECT id, run_id, evidence, sink_context, oracle_status FROM candidate "
            f"WHERE {where} ORDER BY id", args).fetchall():
        ds.scope_total += 1
        rid = int(c["run_id"])
        ev = parse_evidence(c["evidence"])
        if ev is None:                          # unreadable: quarantine, never invent
            ds.quarantined.append(int(c["id"]))
            quarantined_runs.add(rid)
            continue
        path = endpoint_key(ev)
        param = ev.get("param", "")
        cat = ev.get("category", "")
        key = (rid, path, param, cat)
        mkey = (*key, method_key(ev.get("method")))
        if mkey in positives:
            matched.add(mkey)
        if key in any_method:
            matched.add(key)
        unlabelled = c["oracle_status"] in UNLABELLED
        if unlabelled and not include_unlabelled:
            continue
        label = 1 if (mkey in positives or key in any_method) else 0
        ds.X.append(_features(ev, c["sink_context"], fired.get((rid, path, param), 0)))
        ds.y.append(0 if unlabelled else label)
        ds.groups.append(path)
        ds.ids.append(int(c["id"]))
        ds.labelled.append(not unlabelled)
    lost = {k[0] for k in (positives | any_method) - matched}
    ds.label_loss_runs = sorted(quarantined_runs & lost)
    return ds


#: The most of a training scope that may be quarantined before a trainer refuses.
MAX_QUARANTINED_FRACTION = 0.05


class DatasetEvidenceError(ValueError):
    """Too much of the training scope has unreadable evidence, or a label may have been
    lost with a quarantined row (BUG-0107): the train refuses rather than shift."""


def quarantine_refusal(ds: Dataset) -> str | None:
    """Why a trainer must refuse ``ds`` (FR-ML-24), or ``None``: a run with a quarantined
    row has a finding no readable candidate matches, or more than
    `MAX_QUARANTINED_FRACTION` of the scope's candidates are quarantined."""
    if ds.label_loss_runs:
        return (f"run(s) {ds.label_loss_runs} have candidates with unreadable evidence and "
                f"a finding no readable candidate matches (a label may be lost); repair "
                f"the evidence")
    if ds.scope_total and len(ds.quarantined) > MAX_QUARANTINED_FRACTION * ds.scope_total:
        return (f"{len(ds.quarantined)} of {ds.scope_total} candidates have unreadable "
                f"evidence (more than {MAX_QUARANTINED_FRACTION:.0%}); repair the evidence")
    return None


def target_of(store, run_id: int) -> str | None:
    """The pipeline's recorded target (`target.base_url`) for a run, or ``None`` when the
    run has no target row (the pipeline writes one only when it had points). The one
    definition of "same target" for cross-run training (PA-0003)."""
    row = store.conn.execute(
        "SELECT base_url FROM target WHERE run_id=? ORDER BY id LIMIT 1", (run_id,)).fetchone()
    return row["base_url"] if row else None


def candidate_keys(store, ids) -> list[tuple[str, str, str, str]]:
    """`(path, param, category, method)` of each candidate id, in order — the key a
    repeated injection point shares across runs (used for `seen_fraction`; the method
    joined it with BUG-0075)."""
    out = []
    for cid in ids:
        row = store.conn.execute("SELECT evidence FROM candidate WHERE id=?", (cid,)).fetchone()
        ev = parse_evidence(row["evidence"]) if row else None
        if ev is None:                          # unreadable: a key nothing else shares
            out.append(("\0quarantined", str(cid), "", ""))
            continue
        out.append((to_path(ev.get("url", "")), ev.get("param", ""), ev.get("category", ""),
                    method_key(ev.get("method"))))
    return out


def run_ids_of(store, ids) -> list[int]:
    """The distinct runs the given candidate ids belong to, sorted (chunked under
    SQLite's bound-parameter limit — a store-wide train passes every candidate)."""
    ids = list(ids)
    runs = set()
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        for row in store.conn.execute(
                f"SELECT DISTINCT run_id FROM candidate WHERE id IN "
                f"({','.join('?' * len(chunk))})", chunk).fetchall():
            if row["run_id"] is not None:
                runs.add(int(row["run_id"]))
    return sorted(runs)


def seen_fraction(store, train_ids, now_ids) -> float:
    """Share of ``now_ids`` whose (path, param, category, method) key occurs among
    ``train_ids``:
    how much of this run a model trained on earlier runs has effectively seen."""
    if not now_ids:
        return 0.0
    seen = set(candidate_keys(store, train_ids))
    return round(sum(1 for k in candidate_keys(store, now_ids) if k in seen) / len(now_ids), 6)
