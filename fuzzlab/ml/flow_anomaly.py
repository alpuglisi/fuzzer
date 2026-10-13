"""Anomaly tripwire over recorded HTTP flows (FR-ML-3 "over flows", FR-ML-23, CC-ML-0021).

Each in-scope flow of a run becomes a fixed, versioned feature vector built **only from
the flow row and body lengths** — never body content (`LENGTH(data)` is computed in
SQL, so no body bytes are loaded) — and is scored with ECOD or Isolation Forest **per
host**, so the difference between two hosts is never itself flagged. Advisory only: it
writes `flow.anomaly_score` / `anomaly_flag` (migration 18), never labels.

Contamination is a *forced* per-host fraction: up to that share of every scored host's
flows is flagged (whole tie groups only, `anomaly.flag_top`), even on a clean host —
"most unusual", not "malicious". A host with ≤ 2 flows is not scored. Flows outside the
proxy's scope (`in_scope = 0`) are ignored; NULL comes from the HTTP client, which only
sends in scope, so it counts as in scope.
"""

from __future__ import annotations

import math
from urllib.parse import urlsplit

FLOW_FEATURE_NAMES = [
    "status_class", "status_missing", "log_elapsed_ms", "elapsed_missing",
    "log_resp_len", "resp_body_missing", "log_req_len", "req_body_missing",
    "path_depth", "query_params", "method_post", "proto_ws", "proto_h2", "proto_http1",
]
FLOW_FEATURE_VERSION = 1
MIN_HOST_FLOWS = 3


def _len(store, sha) -> int | None:
    if sha is None:
        return None
    row = store.conn.execute("SELECT LENGTH(data) n FROM body WHERE sha256=?",
                             (sha,)).fetchone()
    return None if row is None else int(row["n"])


def flow_vector(row, req_len, resp_len) -> list[float]:
    """The v1 vector of one flow row (+ its decoded body lengths, None = missing)."""
    status, elapsed = row["status"], row["elapsed_ms"]
    parts = urlsplit(row["url"] or "")
    path = [p for p in (parts.path or "").split("/") if p]
    query = [q for q in (parts.query or "").split("&") if q]
    proto = (row["protocol"] or "http/1.1").lower()
    return [
        float(status // 100) if status is not None else 0.0,
        1.0 if status is None else 0.0,
        math.log1p(max(0.0, elapsed)) if elapsed is not None else 0.0,
        1.0 if elapsed is None else 0.0,
        math.log1p(resp_len) if resp_len is not None else 0.0,
        1.0 if resp_len is None else 0.0,
        math.log1p(req_len) if req_len is not None else 0.0,
        1.0 if req_len is None else 0.0,
        float(len(path)),
        float(len(query)),
        1.0 if (row["method"] or "").upper() == "POST" else 0.0,
        1.0 if proto == "ws" else 0.0,
        1.0 if proto == "h2" else 0.0,
        1.0 if proto not in ("ws", "h2") else 0.0,
    ]


def _host(row) -> str:
    return row["host"] or urlsplit(row["url"] or "").netloc or "(unknown)"


def flow_features(store, run_id: int) -> tuple[list[int], list[str], list[list[float]], int]:
    """``(flow ids, hosts, vectors, out-of-scope count)`` for a run's in-scope flows."""
    ids, hosts, X = [], [], []
    rows = store.conn.execute(
        "SELECT id, method, url, host, status, elapsed_ms, protocol, in_scope, "
        "req_body_sha, resp_body_sha FROM flow WHERE run_id=? ORDER BY id",
        (run_id,)).fetchall()
    out_of_scope = 0
    for r in rows:
        if r["in_scope"] == 0:
            out_of_scope += 1
            continue
        ids.append(int(r["id"]))
        hosts.append(_host(r))
        X.append(flow_vector(r, _len(store, r["req_body_sha"]),
                             _len(store, r["resp_body_sha"])))
    return ids, hosts, X, out_of_scope


def detect_flow_anomalies(store, run_id: int, *, method: str = "ecod",
                          contamination: float = 0.1, seed: int = 0,
                          top: int = 10) -> dict:
    """Score and flag a run's in-scope flows per host, and persist the result.

    Every flow of the run is written in the same pass: scored flows get their score and
    flag, the others (out of scope, or on a host with too few flows) are cleared to NULL
    — so a re-run never keeps a stale flag (PA-0068(3))."""
    from fuzzlab.ml.anomaly import ANOMALY_METHODS, fit_detector, flag_top
    if method not in ANOMALY_METHODS:
        raise ValueError(f"anomaly method must be one of {ANOMALY_METHODS}, got {method!r}")
    if not 0 < contamination <= 0.5:
        raise ValueError(f"contamination must be in (0, 0.5], got {contamination!r}")
    ids, hosts, X, out_of_scope = flow_features(store, run_id)
    by_host: dict[str, list[int]] = {}
    for i, h in enumerate(hosts):
        by_host.setdefault(h, []).append(i)
    score: dict[int, float] = {}
    flag: dict[int, bool] = {}
    per_host, skipped = {}, []
    for h, idx in sorted(by_host.items()):
        if len(idx) < MIN_HOST_FLOWS:
            skipped.append(h)
            continue
        rows = [X[i] for i in idx]
        sc = fit_detector(method, rows, seed=seed).scores(rows)
        fl = flag_top(sc, contamination)
        for i, s, f in zip(idx, sc, fl):
            score[ids[i]], flag[ids[i]] = s, f
        per_host[h] = {"flows": len(idx), "flagged": sum(fl)}
    store.conn.execute("UPDATE flow SET anomaly_score=NULL, anomaly_flag=NULL "
                       "WHERE run_id=?", (run_id,))
    for fid, s in score.items():
        store.conn.execute("UPDATE flow SET anomaly_score=?, anomaly_flag=? WHERE id=?",
                           (s, 1 if flag[fid] else 0, fid))
    # the flow feature version the stored flags read (BUG-0069); a rerun replaces it
    store.conn.execute("DELETE FROM run_metrics WHERE run_id=? AND key=?",
                       (run_id, "flow_anomaly_feature_version"))
    if score:
        store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                           (run_id, "flow_anomaly_feature_version",
                            float(FLOW_FEATURE_VERSION)))
    store.conn.commit()
    flagged_ids = sorted((f for f in score if flag[f]), key=lambda f: (-score[f], f))
    top_rows = []
    for fid in flagged_ids[:top]:
        r = store.conn.execute("SELECT method, url, host, status FROM flow WHERE id=?",
                               (fid,)).fetchone()
        top_rows.append({"id": fid, "method": r["method"], "url": r["url"],
                         "host": _host(r), "status": r["status"],
                         "score": round(score[fid], 4)})
    return {"run_id": run_id, "method": method, "contamination": contamination,
            "feature_version": FLOW_FEATURE_VERSION, "flows": len(ids),
            "out_of_scope": out_of_scope, "scored": len(score),
            "flagged": len(flagged_ids), "hosts": per_host, "skipped_hosts": skipped,
            "top": top_rows}
