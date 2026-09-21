"""Consolidate the tools' native outputs into the unified store (T0.8).

Phase 0 keeps each tool independently runnable with its own native output
(spider_results.db, audit_results.db, a fuzzer CSV) and adds a thin adapter that
imports those into the one shared store — the integration bus (D5) the harness and
later phases read. When a tool is given ``--store``, it calls the matching import
here after its run.

URLs are normalized to path form (``/product.php``) so pages, endpoints,
parameters, and findings line up with the ground-truth contract, which is written
in paths.

The fuzzer's confirmed *timing* detections are written as ``finding`` rows here so
the harness can score a live run in Phase 0. The deterministic oracle that will
own finding labels arrives in Phase 2; until then these are timing-only
confirmations, flagged as such in the finding confidence.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from fuzzlab.core.store import Store
from fuzzlab.core.urls import to_path


def _upsert_endpoint(store: Store, run_id: int, url_path: str, method: str,
                     source: str | None) -> int:
    row = store.conn.execute(
        "SELECT id FROM endpoint WHERE run_id=? AND url=? AND method=?",
        (run_id, url_path, method),
    ).fetchone()
    if row:
        return int(row["id"])
    cur = store.conn.execute(
        "INSERT INTO endpoint (run_id, url, method, source) VALUES (?,?,?,?)",
        (run_id, url_path, method, source),
    )
    return int(cur.lastrowid)


def _get_parameter(store: Store, run_id: int, endpoint_id: int, name: str) -> int | None:
    row = store.conn.execute(
        "SELECT id FROM parameter WHERE run_id=? AND endpoint_id=? AND name=?",
        (run_id, endpoint_id, name),
    ).fetchone()
    return int(row["id"]) if row else None


def import_spider(spider_db: str | Path, store: Store, run_id: int) -> dict[str, int]:
    """Import discovered pages -> page/endpoint/parameter rows."""
    src = sqlite3.connect(str(spider_db))
    src.row_factory = sqlite3.Row
    counts = {"page": 0, "endpoint": 0, "parameter": 0}
    seen_pages: set[tuple[str, str]] = set()
    try:
        rows = src.execute(
            "SELECT url, status_code, source FROM discovered_pages"
        ).fetchall()
    except sqlite3.Error:
        rows = []
    for row in rows:
        raw = row["url"]
        path = to_path(raw)
        source = row["source"] if "source" in row.keys() else "link"
        if (path, "GET") not in seen_pages:
            store.conn.execute(
                "INSERT OR IGNORE INTO page (run_id, url, method, status, source) "
                "VALUES (?,?,?,?,?)",
                (run_id, path, "GET", row["status_code"], source),
            )
            seen_pages.add((path, "GET"))
            counts["page"] += 1
        query = parse_qsl(urlparse(raw).query)
        if query:
            endpoint_id = _upsert_endpoint(store, run_id, path, "GET", source)
            counts["endpoint"] += 1
            for name, value in query:
                if _get_parameter(store, run_id, endpoint_id, name) is None:
                    store.conn.execute(
                        "INSERT INTO parameter (run_id, endpoint_id, name, location, example) "
                        "VALUES (?,?,?,?,?)",
                        (run_id, endpoint_id, name, "query", value),
                    )
                    counts["parameter"] += 1
    store.conn.commit()
    src.close()
    return counts


def import_audit(audit_db: str | Path, store: Store, run_id: int) -> dict[str, int]:
    """Import auditor findings -> candidate rows (with rule evidence)."""
    src = sqlite3.connect(str(audit_db))
    src.row_factory = sqlite3.Row
    counts = {"candidate": 0}
    try:
        rows = src.execute(
            "SELECT page_url, category, transaction_type, target_identifier, "
            "html_context, occurrences, reference FROM findings"
        ).fetchall()
    except sqlite3.Error:
        rows = []
    for row in rows:
        path = to_path(row["page_url"])
        endpoint_id = _upsert_endpoint(store, run_id, path, "GET", "audit")
        param_id = _get_parameter(store, run_id, endpoint_id, row["target_identifier"])
        evidence = {
            "category": row["category"],
            "transaction_type": row["transaction_type"],
            "target_identifier": row["target_identifier"],
            "occurrences": row["occurrences"] if "occurrences" in row.keys() else 1,
            "reference": row["reference"] if "reference" in row.keys() else None,
        }
        store.conn.execute(
            "INSERT INTO candidate (run_id, parameter_id, rule, evidence, sink_context) "
            "VALUES (?,?,?,?,?)",
            (run_id, param_id, row["transaction_type"], json.dumps(evidence),
             row["html_context"]),
        )
        counts["candidate"] += 1
    store.conn.commit()
    src.close()
    return counts


def import_fuzz_csv(csv_path: str | Path, store: Store, run_id: int) -> dict[str, int]:
    """Import fuzzer observations -> `attempt` rows only.

    Findings are no longer written here: the deterministic oracle
    (`fuzzlab/oracle/`) is the sole writer of `finding` labels, replacing the
    earlier provisional timing-only findings. The attempt's `reward` still records
    the fuzzer's timing detection (screening signal) for later ML.
    """
    counts = {"attempt": 0}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            detected = str(row.get("time_delay_detected", "0")).strip() in ("1", "true", "True")
            features = {
                "server_response_status": _to_int(row.get("server_response_status")),
                "server_response_length": _to_int(row.get("server_response_length")),
                "observed_latency_seconds": _to_float(row.get("observed_latency_seconds")),
                "latency_delta_seconds": _to_float(row.get("latency_delta_seconds")),
                "size_delta_bytes": _to_int(row.get("size_delta_bytes")),
                "repeats": _to_int(row.get("repeats")),
            }
            store.conn.execute(
                "INSERT INTO attempt (run_id, payload_family, features_json, reward) "
                "VALUES (?,?,?,?)",
                (run_id, row.get("payload_family"), json.dumps(features),
                 1.0 if detected else 0.0),
            )
            counts["attempt"] += 1
    store.conn.commit()
    return counts


def _to_int(value) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _to_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
