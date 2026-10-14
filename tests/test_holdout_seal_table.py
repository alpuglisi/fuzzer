"""The holdout seal is durable, append-only state, and malformed seals fail closed
(BUG-0104, FR-ML-19 / FR-CORE-26, PA-0105, CC-PLUG-0009).

A calibration ``holdout`` of ``{}`` / ``None`` / ``False`` (or unparseable calibration)
was read as "no seal", so ordinary training could use the held-out labels. Migration 19
keeps every seal in `holdout_seal`, backfilled in the migration's own transaction.
"""

from __future__ import annotations

import json
import sqlite3
import threading

import pytest

from fuzzlab.core import migrations
from fuzzlab.core.store import Store
from fuzzlab.ml import holdout as ho
from fuzzlab.ml.train import train_and_score
from tests.test_ml_holdout_calibration import TARGET, _seed


def _model(store, calibration_text):
    store.conn.execute("INSERT INTO model (name, version, feature_version, calibration) "
                       "VALUES ('logistic', (SELECT COALESCE(MAX(version), 0) + 100 FROM "
                       "model), 1, ?)", (calibration_text,))
    store.conn.commit()


@pytest.mark.parametrize("rec", [{}, None, False, 0, "", [], {"version": 1}])
def test_a_present_but_malformed_record_is_unknown(tmp_path, rec):
    """The audit's repro, every falsy shape: never read as "no seal"."""
    with Store(tmp_path / "s.db") as store:
        r = _seed(store)
        _model(store, json.dumps({"run_id": r, "holdout": rec}))
        assert ho.sealing_for_run(store, r) == ho.UNKNOWN


def test_a_seal_survives_its_calibration_being_wiped(tmp_path):
    with Store(tmp_path / "s.db") as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", holdout=True)
        assert store.conn.execute("SELECT COUNT(*) FROM holdout_seal").fetchone()[0] == 1
        store.conn.execute("UPDATE model SET calibration='{}'")
        store.conn.commit()
        assert ho.sealing_for_run(store, r) == (ho.SEALED, frozenset({1}))


def _downgrade_to_18(store):
    """Turn a fresh store back into a version-18 one (as an older build left it)."""
    store.conn.execute("DROP TABLE holdout_seal")
    store.conn.execute("DROP TABLE holdout_seal_meta")
    # and undo every later migration (20: the form table)
    store.conn.execute("DROP INDEX IF EXISTS ix_form_endpoint")
    store.conn.execute("ALTER TABLE parameter DROP COLUMN form_id")
    store.conn.execute("DROP TABLE form")
    store.conn.execute("DELETE FROM schema_version WHERE version>=19")
    store.conn.commit()


def test_upgrading_a_v18_store_backfills_every_legacy_seal(tmp_path):
    path = tmp_path / "s.db"
    with Store(path) as store:
        a = _seed(store)
        b = _seed(store, target="http://127.0.0.1:9090")
        c = _seed(store, target="http://127.0.0.1:7070")
        _downgrade_to_18(store)
        _model(store, json.dumps({"run_id": a, "holdout": {"version": 1,
                                                           "fraction": 0.2, "rows": 3}}))
        _model(store, json.dumps({"run_id": b, "holdout": {}}))        # malformed
        _model(store, json.dumps({"run_id": c}))                       # never sealed
        top = store.conn.execute("SELECT MAX(id) FROM model").fetchone()[0]
    with Store(path) as store:                                         # migrates to 19
        assert store.schema_version() == 20      # 19, then 20 (the form table)
        rows = store.conn.execute("SELECT origin, version, fraction FROM holdout_seal "
                                  "ORDER BY id").fetchall()
        assert [tuple(r) for r in rows] == [(TARGET, 1, 0.2),
                                            ("http://127.0.0.1:9090", None, None)]
        assert store.conn.execute("SELECT watermark FROM holdout_seal_meta"
                                  ).fetchone()[0] == top
        assert ho.sealing_for_run(store, a) == (ho.SEALED, frozenset({1}))
        assert ho.sealing_for_run(store, b) == ho.UNKNOWN
        assert ho.sealing_for_run(store, c) is None


def test_an_unparseable_legacy_row_fails_closed_for_every_target(tmp_path):
    path = tmp_path / "s.db"
    with Store(path) as store:
        a = _seed(store)
        _downgrade_to_18(store)
        _model(store, "{not json")
    with Store(path) as store:
        assert ho.sealing_for_run(store, a) == ho.UNKNOWN
        with pytest.raises(ho.SealingUnknown):
            train_and_score(store, a, model_kind="logistic")


def test_readers_never_write_on_an_upgraded_store(tmp_path):
    """The backfill runs in the migration, so the ML tab stays read-only."""
    from fuzzlab.web import mlview
    path = tmp_path / "s.db"
    with Store(path) as store:
        r = _seed(store)
        train_and_score(store, r, model_kind="logistic", holdout=True)
        _downgrade_to_18(store)
    with Store(path) as store:
        before = store.conn.total_changes
        for panel in (mlview.classifier_panel, mlview.ranker_panel,
                      mlview.disagreement_panel):
            panel(store, r)
        ho.sealing_for_run(store, r)
        assert store.conn.total_changes == before


def test_guarded_ml_stages_can_seal_and_read(tmp_path):
    """CC-PLUG-0009: a guarded holdout stage writes its seal row; a READ_ONLY
    prioritizer reads seals without writing."""
    from fuzzlab.ml.active import prioritize
    from fuzzlab.ml.dataset import build_dataset
    from fuzzlab.plugins.guard import ADVISORY, READ_ONLY, guarded
    with Store(tmp_path / "s.db") as store:
        _seed(store, seed=3)
        _seed(store, seed=4)
        now = _seed(store, seed=5)
        with guarded(store.conn, ADVISORY):
            train_and_score(store, now, model_kind="logistic", holdout=True)
        assert store.conn.execute("SELECT COUNT(*) FROM holdout_seal").fetchone()[0] == 1
        ids = build_dataset(store, now, include_unlabelled=True).ids
        with guarded(store.conn, READ_ONLY):
            assert prioritize(store, now, ids) is not None


def test_concurrent_upgraders_backfill_once(tmp_path):
    path = tmp_path / "s.db"
    with Store(path) as store:
        a = _seed(store)
        _downgrade_to_18(store)
        _model(store, json.dumps({"run_id": a, "holdout": {"version": 1,
                                                           "fraction": 0.2}}))
    errors = []

    def open_it():
        try:
            conn = sqlite3.connect(path, timeout=30)
            conn.row_factory = sqlite3.Row
            migrations.migrate(conn)
            conn.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
    ts = [threading.Thread(target=open_it) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert errors == []
    with Store(path) as store:
        assert store.conn.execute("SELECT COUNT(*) FROM holdout_seal").fetchone()[0] == 1
