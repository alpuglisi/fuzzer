"""`fuzzlab auto` validates every usage-level input before any side effect, and a run
that fails after it starts says so on its run row (BUG-0078, PA-0079).

The D15 fail-safe used to exit 2 only after the store was opened and a run row written
(and the spider db imported), leaving an empty run that `fuzzlab report` then defaulted
to. Plugin errors were already settled first (CC-FUZZ-0050); this covers the rest.
"""

from __future__ import annotations

import importlib.util
import os

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness import auto_cli
from tests.test_auto import GT_DIR, AutoSender

BASE = "http://127.0.0.1:8080"


class _NoNet:
    def send(self, *a, **k):
        raise AssertionError("no traffic allowed")


def _main(tmp_path, monkeypatch, *extra, sender=None):
    monkeypatch.setattr(auto_cli, "make_probe_sender",
                        lambda base, identity=None: sender or _NoNet())
    return auto_cli.main(["--base-url", BASE, "--store", str(tmp_path / "s.db"),
                          "--spider-db", str(tmp_path / "none.db"), "--authorized",
                          *extra])


def _runs(tmp_path):
    if not os.path.exists(tmp_path / "s.db"):
        return []
    with Store(tmp_path / "s.db") as store:
        return [dict(r) for r in store.conn.execute("SELECT id, notes FROM run")]


def _no_playwright(monkeypatch):
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec",
                        lambda name, *a: None if name == "playwright" else real(name, *a))


@pytest.mark.parametrize("extra,setup,msg", [
    ((), None, "categor"),                                            # D15: nothing to run
    (("--points", "ground-truth", "--categories", "sql-injection"), None, "ground-truth"),
    (("--ground-truth", GT_DIR, "--browser"), _no_playwright, "Playwright"),
    (("--ground-truth", GT_DIR, "--greybox-coverage-file", "/nonexistent/fzl-cov"), None,
     "does not exist"),
    (("--ground-truth", GT_DIR, "--greybox-dbfault-file", "/nonexistent/fzl-db"), None,
     "does not exist"),
])
def test_usage_failures_exit_2_with_no_run_row(tmp_path, monkeypatch, capsys, extra, setup,
                                               msg):
    if setup is not None:
        setup(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        _main(tmp_path, monkeypatch, *extra)
    assert exc.value.code == 2
    assert msg in capsys.readouterr().err
    assert _runs(tmp_path) == []                 # the store was never even opened


def test_a_failure_after_the_run_starts_marks_it_aborted(tmp_path, monkeypatch):
    """The OOB listener's bind can only fail at run time: the run row records why, and
    the error still propagates (a real failure keeps its traceback)."""
    from fuzzlab.oracle import oob

    def refuse(self):
        raise OSError("address already in use")
    monkeypatch.setattr(oob.OobListener, "start", refuse)
    with pytest.raises(OSError):
        _main(tmp_path, monkeypatch, "--ground-truth", GT_DIR, "--oob")
    [run] = _runs(tmp_path)
    assert run["notes"] == "aborted: OSError: address already in use"


def test_a_late_usage_error_still_exits_2_and_marks_the_run(tmp_path, monkeypatch):
    from fuzzlab.core.runmode import RunModeError

    def conflict(**kw):
        raise RunModeError("two plugins would order the budget")
    monkeypatch.setattr(auto_cli, "run_auto", conflict)
    with pytest.raises(SystemExit) as exc:
        _main(tmp_path, monkeypatch, "--ground-truth", GT_DIR)
    assert exc.value.code == 2
    assert _runs(tmp_path)[0]["notes"] == "aborted: exit 2"


def test_a_good_run_is_not_marked(tmp_path, monkeypatch):
    assert _main(tmp_path, monkeypatch, "--ground-truth", GT_DIR, "--points",
                 "ground-truth", sender=AutoSender()) == 0
    assert [r["notes"] for r in _runs(tmp_path)] == [None]


# --- the PA-0002 sweep of BUG-0078's class: every other run-starting entry point ---

def test_store_mark_aborted_records_why(tmp_path):
    with Store(tmp_path / "s.db") as store:
        rid = store.start_run("auto", "h")
        store.mark_aborted(rid, SystemExit(2))
        other = store.start_run("auto", "h")
        store.mark_aborted(other, ValueError("x" * 600))
        notes = [r["notes"] for r in store.conn.execute("SELECT notes FROM run ORDER BY id")]
    assert notes[0] == "aborted: exit 2"
    assert notes[1].startswith("aborted: ValueError: xxx") and len(notes[1]) <= 509


def test_multitarget_validates_every_plan_before_any_run(tmp_path):
    from fuzzlab.core.runmode import RunModeError
    from fuzzlab.harness.multitarget import TargetSpec, run_targets
    from fuzzlab.labels import contract
    gt = contract.load(GT_DIR)
    specs = [TargetSpec("ok", BASE, ground_truth=gt, points_source="ground-truth"),
             TargetSpec("bad", BASE, points_source="ground-truth")]   # no contract
    with Store(tmp_path / "s.db") as store:
        with pytest.raises(RunModeError):
            run_targets(specs, store, sender_for=lambda s: AutoSender())
        assert store.conn.execute("SELECT COUNT(*) c FROM run").fetchone()["c"] == 0


def test_multitarget_marks_a_failing_run_aborted(tmp_path):
    from fuzzlab.harness.multitarget import TargetSpec, run_targets
    from fuzzlab.labels import contract
    gt = contract.load(GT_DIR)

    class Dead:
        def send(self, *a, **k):
            raise ConnectionError("target down")
    with Store(tmp_path / "s.db") as store:
        with pytest.raises(ConnectionError):
            run_targets([TargetSpec("a", BASE, ground_truth=gt,
                                    points_source="ground-truth")],
                        store, sender_for=lambda s: Dead())
        [row] = store.conn.execute("SELECT notes FROM run").fetchall()
    assert row["notes"] == "aborted: ConnectionError: target down"


def test_greybox_with_no_crawl_points_marks_its_run_aborted(tmp_path, capsys):
    from fuzzlab.greybox import greybox_cli
    with pytest.raises(SystemExit) as exc:
        greybox_cli.main(["--base-url", BASE, "--store", str(tmp_path / "s.db"),
                          "--spider-db", str(tmp_path / "none.db"), "--points", "crawl",
                          "--authorized"])
    assert exc.value.code == 2 and "no injection points" in capsys.readouterr().err
    assert _runs(tmp_path) == [{"id": 1, "notes": "aborted: exit 2"}]
