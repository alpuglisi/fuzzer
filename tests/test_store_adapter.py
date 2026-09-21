"""T0.8: tool outputs consolidate into the unified store.

Builds synthetic native outputs in the exact schemas the tools write, imports
them via the adapter, and asserts a full run populates page/endpoint/parameter/
candidate/attempt. Findings are written by the oracle, not the adapter
(see test_oracle_harness.py). No live lab needed.
"""

import csv
import sqlite3

from fuzzlab.core.store import Store
from fuzzlab.tools import store_adapter


def _make_spider_db(path):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE discovered_pages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT UNIQUE, status_code INTEGER,
        depth INTEGER, title TEXT, content TEXT, rendered INTEGER DEFAULT 0,
        source TEXT DEFAULT 'link')""")
    rows = [
        ("http://localhost:8080/index.php", 200, "link"),
        ("http://localhost:8080/product.php?id=1", 200, "link"),
        ("http://localhost:8080/search.php?q=puppy", 200, "link"),
        ("http://localhost:8080/blog_post.php?id=1", 200, "link"),
        ("http://localhost:8080/products.php?category=forts", 200, "link"),
    ]
    conn.executemany(
        "INSERT INTO discovered_pages (url, status_code, depth, source) VALUES (?,?,0,?)",
        rows)
    conn.commit(); conn.close()


def _make_audit_db(path):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, page_url TEXT NOT NULL,
        category TEXT NOT NULL, transaction_type TEXT NOT NULL,
        target_identifier TEXT NOT NULL, html_context TEXT,
        occurrences INTEGER NOT NULL DEFAULT 1, reference TEXT)""")
    conn.executemany(
        "INSERT INTO findings (page_url, category, transaction_type, target_identifier, "
        "html_context, occurrences, reference) VALUES (?,?,?,?,?,?,?)",
        [
            ("http://localhost:8080/product.php?id=1", "Error Induction",
             "SQL Syntax Errors", "id", "sql", 1, "sql-injection"),
            ("http://localhost:8080/search.php?q=puppy", "Reflection",
             "Reflected Input", "q", "html", 3, "xss"),
        ])
    conn.commit(); conn.close()


def _make_fuzz_csv(path):
    fields = ["timestamp", "target_url", "target_param", "fuzzed_input_payload",
              "payload_family", "server_response_status", "server_response_length",
              "observed_latency_seconds", "latency_delta_seconds", "size_delta_bytes",
              "repeats", "is_malicious_payload", "time_delay_detected", "eval_outcome"]
    rows = [
        {"target_url": "http://localhost:8080/product.php", "target_param": "id",
         "payload_family": "time_sleep", "server_response_status": 200,
         "server_response_length": 500, "observed_latency_seconds": 5.1,
         "latency_delta_seconds": 5.0, "size_delta_bytes": 0, "repeats": 2,
         "is_malicious_payload": 1, "time_delay_detected": 1, "eval_outcome": "TP"},
        {"target_url": "http://localhost:8080/blog_post.php", "target_param": "id",
         "payload_family": "time_sleep", "server_response_status": 200,
         "server_response_length": 400, "observed_latency_seconds": 5.0,
         "latency_delta_seconds": 4.9, "size_delta_bytes": 0, "repeats": 2,
         "is_malicious_payload": 1, "time_delay_detected": 1, "eval_outcome": "TP"},
        {"target_url": "http://localhost:8080/product.php", "target_param": "id",
         "payload_family": "benign", "server_response_status": 200,
         "server_response_length": 500, "observed_latency_seconds": 0.1,
         "latency_delta_seconds": 0.0, "size_delta_bytes": 0, "repeats": 2,
         "is_malicious_payload": 0, "time_delay_detected": 0, "eval_outcome": "TN"},
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def test_full_consolidation_populates_all_tables(tmp_path):
    spider_db = tmp_path / "spider_results.db"
    audit_db = tmp_path / "audit_results.db"
    fuzz_csv = tmp_path / "fuzz.csv"
    _make_spider_db(spider_db)
    _make_audit_db(audit_db)
    _make_fuzz_csv(fuzz_csv)

    with Store(tmp_path / "unified.db") as store:
        run_id = store.start_run("integration", "hash")
        sp = store_adapter.import_spider(spider_db, store, run_id)
        au = store_adapter.import_audit(audit_db, store, run_id)
        fz = store_adapter.import_fuzz_csv(fuzz_csv, store, run_id)

        assert sp["page"] == 5
        assert sp["parameter"] == 4          # id, q, id, category
        assert au["candidate"] == 2
        assert fz["attempt"] == 3
        assert "finding" not in fz            # findings come from the oracle now

        def count(table):
            return store.conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]

        # The adapter populates discovery/candidate/attempt tables; findings are
        # written by the oracle (see test_oracle_harness.py), not here.
        for table in ("page", "endpoint", "parameter", "candidate", "attempt"):
            assert count(table) > 0, f"{table} should be populated"
        assert count("finding") == 0


def test_attempts_recorded_with_detection_reward(tmp_path):
    fuzz_csv = tmp_path / "fuzz.csv"
    _make_fuzz_csv(fuzz_csv)
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("fuzzer", "h")
        store_adapter.import_fuzz_csv(fuzz_csv, store, run_id)
        # 3 attempts; the 2 timing hits carry reward 1.0, the benign one 0.0.
        rewards = [r["reward"] for r in store.conn.execute(
            "SELECT reward FROM attempt ORDER BY id").fetchall()]
        assert sorted(rewards) == [0.0, 1.0, 1.0]
        # The adapter writes no findings (oracle is the sole finding-writer).
        assert store.conn.execute("SELECT COUNT(*) c FROM finding").fetchone()["c"] == 0
