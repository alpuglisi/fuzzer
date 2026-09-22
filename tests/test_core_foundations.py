"""Phase 0 foundation tests: store/migrations, config, budget, HTTP seam."""

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
                     "flow", "bandit_posteriors", "request_budget", "run_metrics"):
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


# --- open_store()/WAL (B0 / R-08 CORE prerequisite) ----------------------
def test_open_store_wal_smoke(tmp_path):
    """The central connection helper always leaves the store in WAL mode."""
    conn = open_store(tmp_path / "s.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 10000
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_open_store_reasserting_wal_on_existing_store_is_a_noop(tmp_path):
    """Flipping WAL on again for a pre-existing (already-WAL) store is harmless."""
    path = tmp_path / "s.db"
    open_store(path).close()
    conn = open_store(path)   # second connection, same file: re-asserts WAL
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_migrations_additive_on_fresh_and_prepopulated_store(tmp_path):
    """The metric_series migration applies cleanly to a fresh store AND to one
    that already has data under the pre-migration schema (additive/reversible-safe)."""
    db = tmp_path / "s.db"
    conn = open_store(db)
    head = max(v for v, _ in migrations.MIGRATIONS)
    v = migrations.migrate(conn)
    assert v == head
    tables = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "metric_series" in tables
    idx = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    assert "idx_metric_series_series" in idx
    assert "idx_metric_series_overlay" in idx
    # Existing consumers (run_metrics rows) are untouched by the new table.
    cur = conn.execute("INSERT INTO run (tool, config_hash) VALUES ('t','h')")
    run_id = cur.lastrowid
    conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                (run_id, "k", 1.0))
    conn.commit()
    conn.close()

    # Re-open (simulating a later process on the same, now-populated file):
    # migrate() must be a clean no-op and existing rows survive.
    conn2 = open_store(db)
    v2 = migrations.migrate(conn2)
    assert v2 == head
    row = conn2.execute("SELECT value FROM run_metrics WHERE run_id=?", (run_id,)).fetchone()
    assert row["value"] == 1.0


# --- metric_series emitter API (B0) --------------------------------------
def test_log_scalar_writes_a_point(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "h")
        ok = log_scalar(store, run_id, "gbt", "train/loss", 1, 0.5, ts=100.0)
        assert ok is True
        rows = store.conn.execute(
            "SELECT run_id, source, key, step, ts, value FROM metric_series").fetchall()
        assert len(rows) == 1
        r = rows[0]
        assert (r["run_id"], r["source"], r["key"], r["step"], r["ts"], r["value"]) == \
            (run_id, "gbt", "train/loss", 1, 100.0, 0.5)


def test_log_scalar_rejects_non_finite(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "h")
        with pytest.warns(UserWarning):
            ok_nan = log_scalar(store, run_id, "gbt", "train/loss", 1, float("nan"))
        with pytest.warns(UserWarning):
            ok_inf = log_scalar(store, run_id, "gbt", "train/loss", 2, float("inf"))
        assert ok_nan is False
        assert ok_inf is False
        rows = store.conn.execute("SELECT * FROM metric_series").fetchall()
        assert rows == []


def test_metric_logger_buffers_and_flushes_on_exit(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "h")
        with MetricLogger(store, run_id, "bandit", flush_every=200) as logger:
            for step in range(5):
                logger.log("regret/cumulative", step, float(step))
            # Below flush_every, nothing committed yet on this same connection —
            # but assert via the buffer, not a concurrent connection (WAL
            # visibility across separate connections isn't the point here).
            assert len(logger._buf) == 5
        rows = store.conn.execute(
            "SELECT step, value FROM metric_series ORDER BY step").fetchall()
        assert [r["step"] for r in rows] == [0, 1, 2, 3, 4]
        assert logger._buf == []


def test_metric_logger_flushes_at_flush_every(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "h")
        logger = MetricLogger(store, run_id, "coverage", flush_every=3)
        for step in range(3):
            logger.log("coverage/lines", step, float(step))
        assert logger._buf == []  # auto-flushed at flush_every
        rows = store.conn.execute("SELECT COUNT(*) c FROM metric_series").fetchone()
        assert rows["c"] == 3
        logger.flush()  # no-op, nothing buffered


def test_metric_logger_flushes_on_exception(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "h")
        with pytest.raises(RuntimeError):
            with MetricLogger(store, run_id, "mutation", flush_every=200) as logger:
                logger.log("reward", 0, 1.0)
                raise RuntimeError("boom")
        rows = store.conn.execute("SELECT COUNT(*) c FROM metric_series").fetchone()
        assert rows["c"] == 1


def test_metric_logger_drops_non_finite_without_buffering(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "h")
        with MetricLogger(store, run_id, "ml", flush_every=200) as logger:
            with pytest.warns(UserWarning):
                logger.log("train/loss", 0, float("nan"))
            assert logger._buf == []
        rows = store.conn.execute("SELECT COUNT(*) c FROM metric_series").fetchone()
        assert rows["c"] == 0


def test_metric_logger_uses_begin_immediate(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("test", "h")
        logger = MetricLogger(store, run_id, "gbt", flush_every=200)
        logger.log("train/loss", 0, 1.0)
        calls = []
        store.conn.set_trace_callback(calls.append)
        try:
            logger.flush()
        finally:
            store.conn.set_trace_callback(None)
        assert any("BEGIN IMMEDIATE" in c for c in calls)


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
