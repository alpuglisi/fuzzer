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
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    feature_version: int = FEATURE_VERSION

    def __len__(self) -> int:
        return len(self.y)

    @property
    def positives(self) -> int:
        return sum(self.y)


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


def build_dataset(store, run_id: int | None = None) -> Dataset:
    where = "WHERE run_id=?" if run_id is not None else ""
    args: tuple = (run_id,) if run_id is not None else ()

    positives: set[tuple[str, str, str]] = set()
    for f in store.conn.execute(
            f"SELECT url, param, vuln_class FROM finding {where}", args).fetchall():
        positives.add((f["url"], f["param"], to_category(f["vuln_class"])))

    fired: dict[tuple[str, str], int] = {}
    for e in store.conn.execute(
            f"SELECT url, param, fired FROM evaluation {where}", args).fetchall():
        if e["fired"]:
            key = (to_path(e["url"]), e["param"])
            fired[key] = fired.get(key, 0) + 1

    ds = Dataset()
    for c in store.conn.execute(
            f"SELECT id, evidence, sink_context FROM candidate {where}", args).fetchall():
        try:
            ev = json.loads(c["evidence"] or "{}")
        except (ValueError, TypeError):
            ev = {}
        path = to_path(ev.get("url", ""))
        param = ev.get("param", "")
        cat = ev.get("category", "")
        label = 1 if (path, param, cat) in positives else 0
        ds.X.append(_features(ev, c["sink_context"], fired.get((path, param), 0)))
        ds.y.append(label)
        ds.groups.append(path)
        ds.ids.append(int(c["id"]))
    return ds
