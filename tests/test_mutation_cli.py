"""Robustness coverage for `fuzzlab mutate-run` (`mutation/cli.py`), which had zero
prior test coverage despite sending live traffic at a WAF-protected target
(`mrun.run_mutation`) with no exception or `KeyboardInterrupt` handling at all
before this change — any error or Ctrl-C produced a raw traceback.
"""
from fuzzlab.mutation import cli as mutation_cli


def _argv(**extra):
    argv = ["--url", "http://x/search.php", "--param", "q", "--store", "unused.db",
            "--authorized"]
    for k, v in extra.items():
        argv += [f"--{k.replace('_', '-')}", str(v)]
    return argv


def test_keyboard_interrupt_during_run_mutation_is_reported_cleanly(
        tmp_path, monkeypatch, capsys):
    def _interrupt(**kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr(mutation_cli.mrun, "run_mutation", _interrupt)
    monkeypatch.setattr(mutation_cli, "make_probe_sender", lambda url, identity: object())

    rc = mutation_cli.main(["--url", "http://x/search.php", "--param", "q",
                            "--store", str(tmp_path / "u.db"), "--authorized"])
    assert rc == 0
    assert "Interrupted by user" in capsys.readouterr().out


def test_a_network_error_during_run_mutation_exits_cleanly_not_a_traceback(
        tmp_path, monkeypatch, capsys):
    def _boom(**kwargs):
        raise ConnectionError("connection refused")
    monkeypatch.setattr(mutation_cli.mrun, "run_mutation", _boom)
    monkeypatch.setattr(mutation_cli, "make_probe_sender", lambda url, identity: object())

    rc = None
    try:
        mutation_cli.main(["--url", "http://x/search.php", "--param", "q",
                           "--store", str(tmp_path / "u.db"), "--authorized"])
    except SystemExit as exc:
        rc = exc.code
    assert rc == 2                                  # argparse's p.error() exit code
    err = capsys.readouterr().err
    assert "mutate-run failed" in err and "connection refused" in err


def test_missing_authorized_flag_refuses_before_sending_anything(tmp_path, capsys):
    try:
        mutation_cli.main(["--url", "http://x/search.php", "--param", "q",
                           "--store", str(tmp_path / "u.db")])
        assert False, "expected SystemExit"
    except SystemExit as exc:
        assert exc.code == 2
    assert "authorized" in capsys.readouterr().err
