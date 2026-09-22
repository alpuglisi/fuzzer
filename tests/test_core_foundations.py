"""Phase 0 foundation tests: store/migrations, config, budget, HTTP seam."""

import math
import threading

import pytest

from fuzzlab.core import migrations
from fuzzlab.core.budget import BudgetExceeded, RequestBudget
from fuzzlab.core.config import load_config
from fuzzlab.core.http import HttpClient, OutOfScope, Request
from fuzzlab.core.store import MetricLogger, Store, connect, log_scalar, open_store


# --- store + migrations -------------------------------------------------
def test_migrations_are_idempotent(tmp_path):
    db = tmp_path / "s.db"
    conn = connect(db)
    head = max(v for v, _ in migrations.MIGRATIONS)
    v1 = migrations.migrate(conn)
    v2 = migrations.migrate(conn)  # re-running applies nothing
    assert v1 == v2 == head
    tables = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    for expected in ("run", "page", "candidate", "attempt", "finding",
                     "flow", "bandit_posteriors", "request_budget", "run_metrics",
                     "metric_series"):
        assert expected in tables


def test_store_run_and_body_roundtrip(tmp_path):
    with Store(tmp_path / "s.db") as store:
        assert store.schema_version() == max(v for v, _ in migrations.MIGRATIONS)
        run_id = store.start_run("test", "hash123")
        assert run_id == 1
        digest = store.put_body(b"hello")
        assert store.put_body(b"hello") == digest  # content-addressed dedup
        assert store.get_body(digest) == b"hello"
        store.set_meta("k", {"a": 1})
        assert store.get_meta("k") == {"a": 1}


def test_pragmas_set(tmp_path):
    conn = connect(tmp_path / "s.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_open_store_is_wal_smoke(tmp_path):
    """R-08 smoke test: the central open_store() connection is WAL, with the
    busy_timeout/synchronous pragmas the concurrency design relies on."""
    conn = open_store(tmp_path / "s.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    # busy_timeout reflects back the configured ms value.
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 10000
    conn.close()


# --- metric_series / log_scalar / MetricLogger (B0, CC-CORE-0018) -------
def test_metric_series_schema_and_indexes(tmp_path):
    with Store(tmp_path / "s.db") as store:
        cols = {r["name"] for r in store.conn.execute("PRAGMA table_info(metric_series)")}
        assert cols == {"id", "run_id", "source", "key", "step", "ts", "value"}
        indexes = {r["name"] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='metric_series'")}
        assert "idx_metric_series_run" in indexes
        assert "idx_metric_series_overlay" in indexes


def test_log_scalar_roundtrip(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "hash123")
        ok = log_scalar(store, run_id, "gbt", "train/loss", step=1, value=0.5)
        assert ok is True
        row = store.conn.execute(
            "SELECT run_id, source, key, step, value FROM metric_series"
        ).fetchone()
        assert (row["run_id"], row["source"], row["key"], row["step"], row["value"]) == (
            run_id, "gbt", "train/loss", 1, 0.5,
        )


def test_log_scalar_accepts_raw_connection(tmp_path):
    """Per-component emitters may hold their own open_store() connection
    rather than a full Store wrapper."""
    conn = open_store(tmp_path / "s.db")
    migrations.migrate(conn)
    conn.execute("INSERT INTO run (tool, config_hash) VALUES ('t', 'h')")
    conn.commit()
    run_id = conn.execute("SELECT id FROM run").fetchone()[0]
    assert log_scalar(conn, run_id, "bandit", "regret/cumulative", step=0, value=1.0)
    conn.close()


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_log_scalar_rejects_non_finite(tmp_path, bad):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "hash123")
        with pytest.warns(UserWarning):
            ok = log_scalar(store, run_id, "gbt", "train/loss", step=1, value=bad)
        assert ok is False
        count = store.conn.execute("SELECT COUNT(*) FROM metric_series").fetchone()[0]
        assert count == 0


def test_metric_logger_flushes_every_n(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "hash123")
        with MetricLogger(store, run_id, "coverage", flush_every=3) as ml:
            ml.log("lines", step=0, value=1.0)
            ml.log("lines", step=1, value=2.0)
            # not flushed yet (< flush_every)
            count_mid = store.conn.execute("SELECT COUNT(*) FROM metric_series").fetchone()[0]
            assert count_mid == 0
            ml.log("lines", step=2, value=3.0)  # hits flush_every=3 -> auto-flush
            count_after = store.conn.execute("SELECT COUNT(*) FROM metric_series").fetchone()[0]
            assert count_after == 3
            ml.log("lines", step=3, value=4.0)  # buffered, not yet flushed
        # context manager exit flushes the remainder
        final_count = store.conn.execute("SELECT COUNT(*) FROM metric_series").fetchone()[0]
        assert final_count == 4


def test_metric_logger_drops_non_finite_and_flushes_on_exception(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "hash123")
        with pytest.raises(RuntimeError):
            with MetricLogger(store, run_id, "coverage", flush_every=200) as ml:
                ml.log("lines", step=0, value=1.0)
                with pytest.warns(UserWarning):
                    assert ml.log("lines", step=1, value=float("nan")) is False
                raise RuntimeError("boom")
        # flush-on-exit-or-exception still wrote the one good row, dropped the bad one.
        rows = store.conn.execute("SELECT key, step, value FROM metric_series").fetchall()
        assert len(rows) == 1
        assert rows[0]["step"] == 0
        assert math.isfinite(rows[0]["value"])


# --- config -------------------------------------------------------------
def test_config_precedence_and_hash(tmp_path):
    cfg_file = tmp_path / "c.json"
    cfg_file.write_text('{"budget_total": 100}')
    env = {"FUZZLAB_BUDGET_TOTAL": "200", "FUZZLAB_AUTHORIZED": "true"}
    cfg = load_config(cfg_file, overrides={"target_base_url": "http://localhost:8080"},
                      environ=env)
    assert cfg["budget_total"] == 200          # env beats file
    assert cfg["authorized"] is True           # bool coercion from env
    assert cfg["target_base_url"] == "http://localhost:8080"  # override beats env
    assert len(cfg.hash()) == 64               # stable sha256

    cfg2 = load_config(cfg_file, overrides={"target_base_url": "http://localhost:8080"},
                       environ=env)
    assert cfg.hash() == cfg2.hash()           # deterministic


def test_config_redaction():
    cfg = load_config(overrides={"db_password": "s3cret"}, environ={})
    assert cfg.redacted()["db_password"] == "***"


def test_config_rejects_bad_timing_concurrency():
    with pytest.raises(ValueError):
        load_config(overrides={"timing_concurrency": 4}, environ={})


# --- budget + timing mutex ---------------------------------------------
def test_budget_total_and_component_caps():
    budget = RequestBudget(total=3, per_component={"crawler": 2})
    budget.checkout("crawler", 2)
    with pytest.raises(BudgetExceeded):
        budget.checkout("crawler", 1)          # component cap
    budget.checkout("auditor", 1)
    with pytest.raises(BudgetExceeded):
        budget.checkout("auditor", 1)          # total exhausted
    assert budget.remaining() == 0


def test_timing_lock_serializes_per_host():
    budget = RequestBudget(total=100)
    order = []
    holding = threading.Event()
    release = threading.Event()

    def first():
        with budget.timing_lock("localhost"):
            order.append("first-in")
            holding.set()
            release.wait(timeout=2)
            order.append("first-out")

    def second():
        holding.wait(timeout=2)
        with budget.timing_lock("localhost"):   # must block until first releases
            order.append("second-in")

    t1 = threading.Thread(target=first)
    t2 = threading.Thread(target=second)
    t1.start(); t2.start()
    holding.wait(timeout=2)
    release.set()
    t1.join(timeout=2); t2.join(timeout=2)
    assert order == ["first-in", "first-out", "second-in"]


# --- HTTP seam ----------------------------------------------------------
def test_http_scope_enforced():
    client = HttpClient(RequestBudget(10), scope_hosts=["localhost"])
    with pytest.raises(OutOfScope):
        client.send(Request("GET", "http://example.com/"))


def test_http_records_flow_and_uses_budget(tmp_path):
    def fake_transport(method, url, headers, body, timeout):
        return 200, {"Content-Type": "text/html"}, b"<html>ok</html>"

    budget = RequestBudget(10)
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "h")
        client = HttpClient(budget, ["localhost"], store=store, run_id=run_id,
                            transport=fake_transport)
        resp = client.send(Request("GET", "http://localhost/index.php"))
        assert resp.status == 200
        assert budget.used("http") == 1
        rows = store.conn.execute("SELECT url, status FROM flow").fetchall()
        assert rows[0]["url"] == "http://localhost/index.php"
        assert rows[0]["status"] == 200
