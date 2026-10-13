"""Assemble a trainable dataset from the store (Phase 5 T5.2).

One example per **candidate** (an injection point nominated for a category). The label
is whether the oracle **confirmed** it — positives from `finding`, negatives from
candidates with no matching finding (the rejected/never-confirmed ones). Grouped by
endpoint (path) so `group_kfold` never leaks a page across folds. Features are a fixed,
versioned vector derived from what discovery/audit reliably record — no labels leak in.

Advisory only: this feeds scoring/ranking, never `finding` labels.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from fuzzlab.core.runmode import to_category
from fuzzlab.core.urls import to_path

FEATURE_NAMES = [
    "loc_body", "method_post", "has_sink", "cat_sqli", "cat_xss",
    "param_len", "name_id", "name_redirect", "name_file", "name_cmd", "rules_fired",
]
FEATURE_VERSION = 1

_RE_ID = re.compile(r"(^id$|_id$|^id_|id$)", re.I)
_RE_REDIR = re.compile(r"url|next|redirect|return|dest|goto|continue|target", re.I)
_RE_FILE = re.compile(r"file|path|page|include|template|doc|folder|dir|load", re.I)
_RE_CMD = re.compile(r"cmd|exec|command|ping|host|dns|domain|ip", re.I)


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

    def __len__(self) -> int:
        return len(self.y)

    @property
    def positives(self) -> int:
        if len(self.labelled) != len(self.y):          # hand-built: all labelled
            return sum(self.y)
        return sum(y for y, lab in zip(self.y, self.labelled) if lab)


def _features(ev: dict, sink_context, rules_fired: int) -> list[float]:
    name = ev.get("param", "") or ""
    loc = ev.get("location", "query")
    method = (ev.get("method", "GET") or "GET").upper()
    cat = ev.get("category", "")
    return [
        1.0 if loc == "body" else 0.0,
        1.0 if method == "POST" else 0.0,
        1.0 if sink_context else 0.0,
        1.0 if cat == "sql-injection" else 0.0,
        1.0 if cat == "xss" else 0.0,
        float(len(name)),
        1.0 if _RE_ID.search(name) else 0.0,
        1.0 if _RE_REDIR.search(name) else 0.0,
        1.0 if _RE_FILE.search(name) else 0.0,
        1.0 if _RE_CMD.search(name) else 0.0,
        float(rules_fired),
    ]


#: `candidate.oracle_status` of a row the oracle never looked at because the
#: confirmation budget ran out (migration 13). "No finding" is not a negative there.
SKIPPED_BUDGET = "skipped_budget"


def _run_filter(run_id, before_run_id, target) -> tuple[str, tuple]:
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
        conds.append("run_id IN (SELECT run_id FROM target WHERE base_url=?)")
        args.append(target)
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

    Candidates the oracle skipped for budget (``oracle_status='skipped_budget'``) have
    no label, so they are left out unless ``include_unlabelled`` (label-free uses:
    scoring every row, anomaly detection); they are then marked ``labelled=False``.
    """
    where, args = _run_filter(run_id, before_run_id, target)

    positives: set[tuple[int, str, str, str]] = set()
    for f in store.conn.execute(
            f"SELECT run_id, url, param, vuln_class FROM finding WHERE {where}",
            args).fetchall():
        positives.add((int(f["run_id"]), f["url"], f["param"], to_category(f["vuln_class"])))

    fired: dict[tuple[int, str, str], int] = {}
    for e in store.conn.execute(
            f"SELECT run_id, url, param, fired FROM evaluation WHERE {where}",
            args).fetchall():
        if e["fired"]:
            key = (int(e["run_id"]), to_path(e["url"]), e["param"])
            fired[key] = fired.get(key, 0) + 1

    ds = Dataset()
    for c in store.conn.execute(
            f"SELECT id, run_id, evidence, sink_context, oracle_status FROM candidate "
            f"WHERE {where} ORDER BY id", args).fetchall():
        unlabelled = c["oracle_status"] == SKIPPED_BUDGET
        if unlabelled and not include_unlabelled:
            continue
        try:
            ev = json.loads(c["evidence"] or "{}")
        except (ValueError, TypeError):
            ev = {}
        rid = int(c["run_id"])
        path = to_path(ev.get("url", ""))
        param = ev.get("param", "")
        cat = ev.get("category", "")
        label = 1 if (rid, path, param, cat) in positives else 0
        ds.X.append(_features(ev, c["sink_context"], fired.get((rid, path, param), 0)))
        ds.y.append(0 if unlabelled else label)
        ds.groups.append(path)
        ds.ids.append(int(c["id"]))
        ds.labelled.append(not unlabelled)
    return ds


def target_of(store, run_id: int) -> str | None:
    """The pipeline's recorded target (`target.base_url`) for a run, or ``None`` when the
    run has no target row (the pipeline writes one only when it had points). The one
    definition of "same target" for cross-run training (PA-0003)."""
    row = store.conn.execute(
        "SELECT base_url FROM target WHERE run_id=? ORDER BY id LIMIT 1", (run_id,)).fetchone()
    return row["base_url"] if row else None


def candidate_keys(store, ids) -> list[tuple[str, str, str]]:
    """`(path, param, category)` of each candidate id, in order — the key a repeated
    endpoint shares across runs (used for `seen_fraction`)."""
    out = []
    for cid in ids:
        row = store.conn.execute("SELECT evidence FROM candidate WHERE id=?", (cid,)).fetchone()
        try:
            ev = json.loads(row["evidence"] or "{}") if row else {}
        except (ValueError, TypeError):
            ev = {}
        out.append((to_path(ev.get("url", "")), ev.get("param", ""), ev.get("category", "")))
    return out


def run_ids_of(store, ids) -> list[int]:
    """The distinct runs the given candidate ids belong to, sorted."""
    runs = set()
    for cid in ids:
        row = store.conn.execute("SELECT run_id FROM candidate WHERE id=?", (cid,)).fetchone()
        if row is not None:
            runs.add(int(row["run_id"]))
    return sorted(runs)


def seen_fraction(store, train_ids, now_ids) -> float:
    """Share of ``now_ids`` whose (path, param, category) key occurs among ``train_ids``:
    how much of this run a model trained on earlier runs has effectively seen."""
    if not now_ids:
        return 0.0
    seen = set(candidate_keys(store, train_ids))
    return round(sum(1 for k in candidate_keys(store, now_ids) if k in seen) / len(now_ids), 6)
