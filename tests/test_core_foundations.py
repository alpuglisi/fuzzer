"""Phase 0 foundation tests: store/migrations, config, budget, HTTP seam."""

import threading

import pytest

from fuzzlab.core import migrations
from fuzzlab.core.budget import BudgetExceeded, RequestBudget
from fuzzlab.core.config import load_config
from fuzzlab.core.http import HttpClient, OutOfScope, Request
from fuzzlab.core.store import Store, connect


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
