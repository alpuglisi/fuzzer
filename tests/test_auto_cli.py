"""Robustness coverage for `fuzzlab auto`'s CLI wrapper (`harness/auto_cli.py`),
which had zero direct test coverage before this change (`tests/test_auto.py`
exercises `harness.auto.run_auto` directly, never the CLI entry point).

Covers the exception/KeyboardInterrupt handling added around `run_auto` (previously
only `RunModeError` was caught; anything else — a network error, an ML training
failure — produced a raw traceback) and that a bandit scheduler's learned
posteriors are saved even when the run is interrupted or errors out partway
through, not only on a clean finish.
"""
from fuzzlab.core.store import Store
from fuzzlab.harness import auto_cli


def _argv(tmp_path, **extra):
    argv = ["--base-url", "http://x", "--spider-db", str(tmp_path / "missing.db"),
            "--store", str(tmp_path / "u.db"), "--categories", "sql-injection",
            "--authorized"]
    for k, v in extra.items():
        argv += [f"--{k}", str(v)] if v is not True else [f"--{k}"]
    return argv


def test_keyboard_interrupt_during_run_auto_is_reported_cleanly(tmp_path, monkeypatch, capsys):
    def _interrupt(**kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr(auto_cli, "run_auto", _interrupt)

    rc = auto_cli.main(_argv(tmp_path))
    assert rc == 0
    assert "Interrupted by user" in capsys.readouterr().out


def test_a_non_runmode_error_during_run_auto_exits_cleanly_not_a_traceback(
        tmp_path, monkeypatch, capsys):
    def _boom(**kwargs):
        raise ConnectionError("connection refused")
    monkeypatch.setattr(auto_cli, "run_auto", _boom)

    rc = None
    try:
        auto_cli.main(_argv(tmp_path))
    except SystemExit as exc:
        rc = exc.code
    assert rc == 2
    err = capsys.readouterr().err
    assert "auto failed" in err and "connection refused" in err


def test_bandit_posteriors_are_saved_even_when_the_run_is_interrupted(tmp_path, monkeypatch):
    saved = []

    def _interrupt(**kwargs):
        scheduler = kwargs["scheduler"]
        assert scheduler is not None
        scheduler._post[("ctx", "arm")] = _FakePosterior()
        raise KeyboardInterrupt()

    monkeypatch.setattr(auto_cli, "run_auto", _interrupt)
    store_path = str(tmp_path / "u.db")
    rc = auto_cli.main(_argv(tmp_path, bandit=True, store=store_path))
    assert rc == 0
    with Store(store_path) as s:
        row = s.conn.execute(
            "SELECT alpha, beta FROM bandit_posteriors WHERE context='ctx' AND arm='arm'"
        ).fetchone()
    assert row is not None                          # posterior persisted despite the interrupt


class _FakePosterior:
    alpha = 2.0
    beta = 1.0
