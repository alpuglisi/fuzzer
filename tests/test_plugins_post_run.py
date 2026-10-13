"""Post-run and budget-order hooks, the advisory write guard, and the run record
(CC-PLUG-0005, CC-CORE-0028; FR-PLUG-6/7/8/9).

Every guard test asserts **the write did not happen** (row counts / content), not just
that the plugin was disabled — the guarded plugins below swallow the denial themselves
and carry on, so only the guard can be what stopped them.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import textwrap

import pytest

from fuzzlab.core import migrations
from fuzzlab.core.store import Store
from fuzzlab.plugins import PluginManager
from fuzzlab.plugins.guard import ADVISORY, ADVISORY_WRITES, READ_ONLY, authorizer, guarded
from fuzzlab.plugins.manager import FailedBudgetOrder, PluginConflict
from fuzzlab.plugins.optional import import_ml


def _seed(store):
    run_id = store.start_run("auto", "h")
    for i in range(3):
        store.conn.execute(
            "INSERT INTO candidate (run_id, rule, evidence, oracle_status) VALUES (?,?,?,?)",
            (run_id, "r", f'{{"url": "/p{i}", "param": "id", "category": "xss"}}', "checked"))
    store.conn.execute(
        "INSERT INTO finding (run_id, vuln_class, label, confidence, url, method, param) "
        "VALUES (?, 'xss', 1, 'marker', '/p0', 'GET', 'id')", (run_id,))
    for key, val in (("tp", 4.0), ("precision", 0.75)):
        store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                           (run_id, key, val))
    store.conn.commit()
    return run_id


def _state(store):
    """Everything label-defining the guard must keep intact."""
    q = store.conn.execute
    return {
        "findings": [tuple(r) for r in q("SELECT id, url, vuln_class FROM finding ORDER BY id")],
        "candidates": [tuple(r) for r in q(
            "SELECT id, run_id, evidence, oracle_status FROM candidate ORDER BY id")],
        "schema": sorted(tuple(r) for r in q("SELECT type, name, sql FROM sqlite_master")),
        "metrics": sorted(tuple(r) for r in q("SELECT run_id, key, value FROM run_metrics")),
    }


class _Stage:
    def __init__(self, name, fn, priority=50):
        self.name, self.priority, self.fn = name, priority, fn

    def after_run(self, store, run_id):
        return self.fn(store, run_id)


def _swallowing(*sql):
    """An after_run body that tries each statement and swallows any denial."""
    def body(store, run_id):
        for stmt in sql:
            try:
                store.conn.executescript(stmt) if ";" in stmt.strip()[:-1] \
                    else store.conn.execute(stmt)
            except sqlite3.DatabaseError:
                pass
        store.conn.commit()
        return {"tried": len(sql)}
    return body


# --- hooks: dispatch, containment, unit of work ---------------------------------

def test_after_run_dispatches_in_priority_order_and_contains_a_failure(tmp_path):
    calls = []

    def ok(name):
        return lambda store, run_id: calls.append(name) or {"by": name}

    def boom(store, run_id):
        calls.append("boom")
        raise RuntimeError("stage broke")

    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        m = PluginManager(plugins=[_Stage("late", ok("late"), 30), _Stage("boom", boom, 20),
                                   _Stage("early", ok("early"), 10)])
        outcomes = m.after_run(store, run_id)
        assert calls == ["early", "boom", "late"]
        assert [(o.info.name, o.ok) for o in outcomes] == [("early", True), ("boom", False),
                                                          ("late", True)]
        assert outcomes[0].result == {"by": "early"} and "stage broke" in outcomes[1].error
        assert m.disabled() == {"boom"}


def test_a_failed_stage_leaves_no_uncommitted_writes_behind(tmp_path):
    def half_done(store, run_id):
        store.conn.execute("UPDATE candidate SET score=0.97 WHERE run_id=?", (run_id,))
        raise RuntimeError("failed before its commit")

    def commits(store, run_id):
        store.conn.execute("UPDATE candidate SET anomaly_score=0.5 WHERE run_id=?", (run_id,))
        store.conn.commit()

    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        PluginManager(plugins=[_Stage("a", half_done, 10), _Stage("b", commits, 20)]) \
            .after_run(store, run_id)
        rows = store.conn.execute("SELECT score, anomaly_score FROM candidate").fetchall()
        assert {r["score"] for r in rows} == {None}          # rolled back
        assert {r["anomaly_score"] for r in rows} == {0.5}    # the next stage's own work


def test_zero_plugins_is_a_noop(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        before = _state(store)
        m = PluginManager()
        assert m.after_run(store, run_id) == [] and m.prioritizers() == []
        assert m.guarded_prioritizer() is None
        assert _state(store) == before


# --- the advisory write guard (FR-PLUG-6) --------------------------------------

VECTORS = {
    "insert-finding": ["INSERT INTO finding (run_id, vuln_class, label, confidence, url, "
                       "method, param) VALUES (1, 'sqli', 1, 'x', '/FAKE', 'GET', 'id')"],
    "update-finding": ["UPDATE finding SET url='/TAMPERED'"],
    "delete-finding": ["DELETE FROM finding"],
    "replace-finding": ["REPLACE INTO finding (id, run_id, vuln_class, label, confidence, url, "
                        "method, param) VALUES (1, 1, 'sqli', 1, 'x', '/R', 'GET', 'id')"],
    "insert-select": ["INSERT INTO finding (run_id, vuln_class, label, confidence, url, method, "
                      "param) SELECT run_id, 'sqli', 1, 'x', '/SEL', 'GET', 'id' FROM candidate"],
    "executescript": ["UPDATE finding SET url='/SCRIPT'; DELETE FROM finding;"],
    "rename-round-trip": ["ALTER TABLE finding RENAME TO f_tmp",
                          "INSERT INTO f_tmp (run_id, vuln_class, label, confidence, url, "
                          "method, param) VALUES (1, 'sqli', 1, 'x', '/RT', 'GET', 'id')",
                          "ALTER TABLE f_tmp RENAME TO finding"],
    "drop-column": ["ALTER TABLE finding DROP COLUMN param"],
    "drop-table": ["DROP TABLE finding"],
    "persistent-trigger": ["CREATE TRIGGER sneak AFTER UPDATE ON candidate BEGIN "
                           "INSERT INTO finding (run_id, vuln_class, label, confidence, url, "
                           "method, param) VALUES (1, 'sqli', 1, 'x', '/TRIG', 'GET', 'id'); END"],
    "temp-trigger": ["CREATE TEMP TRIGGER tsneak AFTER UPDATE ON candidate BEGIN "
                     "DELETE FROM finding; END"],
    "view-instead-of": ["CREATE VIEW fv AS SELECT * FROM finding",
                        "CREATE TRIGGER fvi INSTEAD OF INSERT ON fv BEGIN INSERT INTO finding "
                        "(run_id, vuln_class, label, confidence, url, method, param) VALUES "
                        "(1, 'sqli', 1, 'x', '/VIEW', 'GET', 'id'); END"],
    "temp-shadow": ["CREATE TEMP TABLE finding (x)", "INSERT INTO temp.finding VALUES (1)"],
    "writable-schema": ["PRAGMA writable_schema=ON"],
    "oracle-status": ["UPDATE candidate SET oracle_status='skipped_budget'"],
    "oracle-status-with-score": ["UPDATE candidate SET score=0.9, oracle_status='skipped_budget'"],
    "candidate-evidence": ["UPDATE candidate SET evidence='{}'"],
    "candidate-run": ["UPDATE candidate SET run_id=99"],
    "delete-candidate": ["DELETE FROM candidate"],
    "insert-candidate": ["INSERT INTO candidate (run_id, rule, evidence) VALUES (1, 'r', '{}')"],
    "update-metric": ["UPDATE run_metrics SET value=99 WHERE key IN ('tp', 'precision')"],
    "delete-metric": ["DELETE FROM run_metrics"],
    "delete-model": ["DELETE FROM model"],
}


@pytest.mark.parametrize("vector", sorted(VECTORS))
def test_guard_blocks_each_label_write_vector(tmp_path, vector):
    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        store.conn.execute("INSERT INTO model (name, version, calibration) VALUES ('x',1,'{}')")
        store.conn.commit()
        before = _state(store)
        models = store.conn.execute("SELECT COUNT(*) FROM model").fetchone()[0]
        m = PluginManager(plugins=[_Stage("sneaky", _swallowing(*VECTORS[vector]))])
        m.after_run(store, run_id)
        store.conn.execute("UPDATE candidate SET rank_score=0.1")   # would fire a trigger
        store.conn.commit()
        after = _state(store)
        assert after == before, vector
        assert store.conn.execute("SELECT COUNT(*) FROM model").fetchone()[0] == models
        assert store.conn.execute(
            "SELECT COUNT(*) FROM sqlite_temp_master").fetchone()[0] == 0


def test_guard_rechecks_a_statement_prepared_before_dispatch(tmp_path):
    sql = "UPDATE finding SET url='/CACHED'"
    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        store.conn.execute(sql)                  # prepared + cached while unguarded
        store.conn.rollback()
        before = _state(store)
        PluginManager(plugins=[_Stage("cached", _swallowing(sql))]).after_run(store, run_id)
        assert _state(store) == before


def test_guard_allows_exactly_the_advisory_writes_and_is_removed_afterwards(tmp_path):
    def advisory(store, run_id):
        store.conn.execute("UPDATE candidate SET score=0.4, rank_score=0.3, "
                           "rank_uncertainty=0.2, anomaly_score=1.5, anomaly_flag=1")
        store.conn.execute("INSERT INTO model (name, version, calibration) VALUES ('m',1,'{}')")
        store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                           (run_id, "ml_new", 1.0))
        store.conn.execute("INSERT INTO metric_series (run_id, source, key, step, value) "
                           "VALUES (?,?,?,?,?)", (run_id, "ml", "train/loss", 0, 0.5))
        store.conn.commit()
        return "ok"

    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        [outcome] = PluginManager(plugins=[_Stage("advisory", advisory)]).after_run(store, run_id)
        assert outcome.ok and outcome.result == "ok"
        assert store.conn.execute("SELECT COUNT(*) FROM candidate WHERE score=0.4 AND "
                                  "anomaly_flag=1").fetchone()[0] == 3
        # removed afterwards: the oracle path writes `finding` as usual
        store.conn.execute("INSERT INTO finding (run_id, vuln_class, label, confidence, url, "
                           "method, param) VALUES (?, 'sqli', 1, 'x', '/ok', 'GET', 'id')",
                           (run_id,))
        store.conn.commit()


def test_advisory_writes_are_one_declared_set():
    assert ADVISORY_WRITES["insert"] == {"model", "run_metrics", "metric_series"}
    assert ADVISORY_WRITES["update_candidate"] == {
        "score", "rank_score", "rank_uncertainty", "anomaly_score", "anomaly_flag",
        "score_oof", "rank_score_oof"}                  # CC-PLUG-0006


@pytest.mark.parametrize("mode", [ADVISORY, READ_ONLY])
def test_the_authorizer_itself_denies_schema_and_attach_actions(mode):
    """The first layer, on its own: DDL is also refused by the schema-table writes it
    implies, so the behavioural vectors above cannot tell which layer stopped it."""
    check = authorizer(mode)
    for action in (sqlite3.SQLITE_ALTER_TABLE, sqlite3.SQLITE_CREATE_TABLE,
                   sqlite3.SQLITE_CREATE_TEMP_TABLE, sqlite3.SQLITE_CREATE_TRIGGER,
                   sqlite3.SQLITE_CREATE_TEMP_TRIGGER, sqlite3.SQLITE_CREATE_VIEW,
                   sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_DROP_TABLE,
                   sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_ATTACH,
                   sqlite3.SQLITE_DETACH):
        assert check(action, "finding", None, "main", None) == sqlite3.SQLITE_DENY, action
    assert check(sqlite3.SQLITE_PRAGMA, "writable_schema", "ON", None, None) == \
        sqlite3.SQLITE_DENY
    assert check(sqlite3.SQLITE_PRAGMA, "table_info", None, None, None) == sqlite3.SQLITE_OK
    assert check(sqlite3.SQLITE_INSERT, "run_metrics", None, "temp", None) == \
        sqlite3.SQLITE_DENY                             # only the main database


def test_ddl_is_denied_even_if_not_exists_so_schema_version_cannot_run(tmp_path):
    with Store(tmp_path / "s.db") as store:
        with guarded(store.conn, ADVISORY), pytest.raises(sqlite3.DatabaseError):
            store.schema_version()


def test_read_only_guard_denies_every_write(tmp_path):
    with Store(tmp_path / "s.db") as store:
        _seed(store)
        with guarded(store.conn, READ_ONLY):
            store.conn.execute("SELECT COUNT(*) FROM finding").fetchone()
            for sql in ("UPDATE candidate SET score=0.1",
                        "INSERT INTO run_metrics (run_id, key, value) VALUES (1, 'k', 1)"):
                with pytest.raises(sqlite3.DatabaseError):
                    store.conn.execute(sql)
        store.conn.rollback()


# --- metric shadowing and transaction-mode tampering (FR-PLUG-7) ------------------

def test_a_shadowing_metric_is_deleted_and_the_plugin_fails(tmp_path):
    def shadow(store, run_id):
        store.conn.execute("UPDATE candidate SET score=0.6")          # allowed, committed
        store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                           (run_id, "precision", 1.0))
        store.conn.commit()                                          # commits itself

    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        [outcome] = PluginManager(plugins=[_Stage("shadow", shadow)]).after_run(store, run_id)
        assert not outcome.ok and "precision" in outcome.error
        assert [r[0] for r in store.conn.execute(
            "SELECT value FROM run_metrics WHERE run_id=? AND key='precision'",
            (run_id,))] == [0.75]
        # its other committed advisory writes stay (documented); its status is failed
        assert {r[0] for r in store.conn.execute("SELECT score FROM candidate")} == {0.6}


@pytest.mark.parametrize("bad", ["other-run", "same-plugin-twice", "earlier-plugin"])
def test_other_shadowing_metric_shapes_fail_the_plugin(tmp_path, bad):
    def first(store, run_id):
        store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                           (run_id, "ml_x", 1.0))
        store.conn.commit()

    def second(store, run_id):
        rows = {"other-run": [(run_id + 1, "ml_y")],
                "same-plugin-twice": [(run_id, "ml_z"), (run_id, "ml_z")],
                "earlier-plugin": [(run_id, "ml_x")]}[bad]
        for r, k in rows:
            store.conn.execute("INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                               (r, k, 2.0))
        store.conn.commit()

    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        outcomes = PluginManager(plugins=[_Stage("first", first, 10),
                                          _Stage("second", second, 20)]).after_run(store, run_id)
        assert [o.ok for o in outcomes] == [True, False]
        assert store.conn.execute(
            "SELECT COUNT(*) FROM run_metrics WHERE value=2.0").fetchone()[0] == 0


def test_switching_the_transaction_mode_fails_the_plugin_and_is_restored(tmp_path):
    def autocommits(store, run_id):
        store.conn.execute("UPDATE candidate SET score=0.1")        # before the switch
        store.conn.isolation_level = None                          # commits it
        store.conn.execute("UPDATE candidate SET anomaly_score=0.2")
        raise RuntimeError("then fails")

    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        mode = store.conn.isolation_level
        [outcome] = PluginManager(plugins=[_Stage("auto", autocommits)]).after_run(store, run_id)
        assert not outcome.ok
        assert store.conn.isolation_level == mode
        # documented: none of its writes, before or after the switch, can be undone
        assert {tuple(r) for r in store.conn.execute(
            "SELECT score, anomaly_score FROM candidate")} == {(0.1, 0.2)}


# --- the budget prioritizer (FR-PLUG-8) ------------------------------------------

class _Order:
    def __init__(self, order, method="m"):
        self.order, self.method = order, method
        self.training_rows = self.training_positives = 0


class _Prio:
    def __init__(self, name, fn, priority=10):
        self.name, self.priority, self.fn = name, priority, fn

    def register_prioritizer(self):
        return self.fn


def test_the_prioritizer_runs_read_only_and_valid_orders_pass_through(tmp_path):
    def writes(store, run_id, ids):
        try:
            store.conn.execute("UPDATE finding SET url='/PRIO'")
        except sqlite3.DatabaseError:
            pass
        return _Order(list(reversed(ids)))

    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        before = _state(store)
        run = PluginManager(plugins=[_Prio("p", writes)]).guarded_prioritizer()
        assert run.plugin_name == "p"
        assert run(store, run_id, [1, 2, 3]).order == [3, 2, 1]
        assert _state(store) == before


@pytest.mark.parametrize("bad", ["raises", "no-order", "foreign-ids", "no-method",
                                 "bool-rows"])
def test_a_failed_prioritizer_gives_a_row_order_that_keeps_the_cap(tmp_path, bad):
    def fn(store, run_id, ids):
        if bad == "raises":
            raise RuntimeError("prioritizer broke")
        order = _Order(ids)
        if bad == "no-order":
            order.order = None
        elif bad == "foreign-ids":
            order.order = [99]
        elif bad == "no-method":
            order.method = None
        else:
            order.training_rows = True
        return order

    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        m = PluginManager(plugins=[_Prio("p", fn)])
        got = m.guarded_prioritizer()(store, run_id, [3, 1, 2])
        assert isinstance(got, FailedBudgetOrder) and got.order == [3, 1, 2]
        assert got.method == "row-order (prioritizer failed)" and got.error
        assert got.training_rows == got.training_positives == 0 and got.model_sha256 is None
        assert m.disabled() == {"p"}


def test_none_from_a_valid_prioritizer_still_means_confirm_everything(tmp_path):
    with Store(tmp_path / "s.db") as store:
        run_id = _seed(store)
        assert PluginManager(plugins=[_Prio("p", lambda *a: None)]) \
            .guarded_prioritizer()(store, run_id, [1]) is None


def test_two_prioritizers_conflict_and_registration_is_collected_once():
    calls = []

    class Counting(_Prio):
        def register_prioritizer(self):
            calls.append(self.name)
            return self.fn

    m = PluginManager(plugins=[Counting("a", lambda *x: None), Counting("b", lambda *x: None)])
    with pytest.raises(PluginConflict, match="a, b"):
        m.guarded_prioritizer()
    with pytest.raises(PluginConflict):
        m.guarded_prioritizer()
    assert calls == ["a", "b"]                      # collected once, cached


# --- registry: names, run scope, record ------------------------------------------

def test_a_duplicate_name_is_refused():
    m = PluginManager(plugins=[_Stage("dup", lambda s, r: 1, 10),
                               _Stage("dup", lambda s, r: 2, 5)])
    assert [i.name for i in m.registry.registered()] == ["dup"]
    assert [i.priority for i in m.rejected()] == [5]


def test_containment_resets_per_run_and_a_pre_run_failure_is_recorded(tmp_path):
    class Breaks:
        name, priority = "breaks", 10

        def register_prioritizer(self):
            raise RuntimeError("bad registration")

    flaky = {"n": 0}

    def once(store, run_id):
        flaky["n"] += 1
        if flaky["n"] == 1:
            raise RuntimeError("first run only")

    with Store(tmp_path / "s.db") as store:
        m = PluginManager(plugins=[Breaks(), _Stage("flaky", once, 20)])
        assert m.prioritizers() == []                       # the CLI pre-check
        run1 = store.start_run("auto", "h")
        m.record(store, run1)
        m.after_run(store, run1)
        m.finalize(store, run1)
        run2 = store.start_run("auto", "h")
        m.record(store, run2)                               # new run scope
        assert m.after_run(store, run2)[0].ok               # retried, works now
        m.finalize(store, run2)
        rows = {(r["run_id"], r["name"]): (r["status"], r["error"]) for r in
                store.conn.execute("SELECT run_id, name, status, error FROM run_plugin")}
        assert rows[(run1, "breaks")][0] == "failed" and "bad registration" in rows[(run1, "breaks")][1]
        assert rows[(run1, "flaky")][0] == "failed" and "first run only" in rows[(run1, "flaky")][1]
        assert rows[(run2, "flaky")] == ("ok", None) and rows[(run2, "breaks")] == ("ok", None)


def test_config_is_recorded_as_canonical_json(tmp_path):
    class Configured:
        name, version, priority = "cfg", "2", 10
        config = {"b": 2, "a": "x"}

    class BadConfig:
        name = "bad"
        config = {"x": object()}

    with Store(tmp_path / "s.db") as store:
        run_id = store.start_run("auto", "h")
        PluginManager(plugins=[Configured(), BadConfig()]).record(store, run_id)
        rows = dict(store.conn.execute("SELECT name, config FROM run_plugin").fetchall())
        assert rows == {"cfg": '{"a":"x","b":2}', "bad": ""}


# --- migration 15 and the optional-ML door (CC-CORE-0028, FR-PLUG-9) -------------

def test_migration_15_adds_run_plugin_config_status_error(tmp_path):
    with Store(tmp_path / "s.db") as store:
        assert store.schema_version() == max(v for v, _ in migrations.MIGRATIONS) >= 15
        cols = {r[1] for r in store.conn.execute("PRAGMA table_info(run_plugin)")}
        assert {"config", "status", "error"} <= cols


def test_import_ml_returns_the_module_when_present_and_refuses_other_packages():
    assert import_ml("fuzzlab.ml.train").__name__ == "fuzzlab.ml.train"
    with pytest.raises(ValueError):
        import_ml("fuzzlab.core.store")
    with pytest.raises(ModuleNotFoundError):        # present package, missing submodule
        import_ml("fuzzlab.ml.no_such_module")


_CHILD = textwrap.dedent("""
    import importlib.abc, sys, types
    class Block(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name == "fuzzlab.ml" or name.startswith("fuzzlab.ml."):
                raise ModuleNotFoundError(f"No module named {name!r}", name="fuzzlab.ml")
    MODE = sys.argv[1]
    if MODE == "absent":
        sys.meta_path.insert(0, Block())
    elif MODE == "namespace":                    # a leftover dir: no __init__, no __file__
        leftover = types.ModuleType("fuzzlab.ml")
        leftover.__path__ = []
        sys.modules["fuzzlab.ml"] = leftover
    elif MODE == "broken":                       # package present, a submodule unloadable
        sys.modules["fuzzlab.ml.plugins"] = None
    elif MODE == "dependency-missing":           # the package exists but ITS import fails
        class MissingDep(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path=None, target=None):
                if name == "fuzzlab.ml":
                    raise ModuleNotFoundError("No module named 'numpy'", name="numpy")
        sys.meta_path.insert(0, MissingDep())
    from fuzzlab.plugins.optional import import_ml, ml_available
    try:
        print(import_ml("fuzzlab.ml.plugins") is None, ml_available())
    except ImportError as exc:
        print("raised", type(exc).__name__)
""")


@pytest.mark.parametrize("mode, expected", [("absent", "True False"),
                                            ("namespace", "True False"),
                                            ("broken", "raised ModuleNotFoundError"),
                                            ("dependency-missing",
                                             "raised ModuleNotFoundError"),
                                            ("present", "False True")])
def test_import_ml_absent_versus_broken(mode, expected):
    out = subprocess.run([sys.executable, "-c", _CHILD, mode], capture_output=True,
                         text=True, env=_child_env())
    assert out.stdout.strip() == expected, out.stderr


def _child_env():
    import os
    from pathlib import Path
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent) + os.pathsep \
        + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env
