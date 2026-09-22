"""Robustness coverage for the top-level `fuzzlab <command>` dispatcher
(`fuzzlab/cli.py::main`), which had zero direct test coverage before this change
(`tests/test_web_runner.py` only checks the `argv` the web launcher constructs to
invoke it as a subprocess, never `main()`'s own dispatch/error-handling behavior).
"""
import fuzzlab.cli as cli


def test_help_and_no_args_print_usage(capsys):
    assert cli.main([]) == 0
    assert "usage: fuzzlab" in capsys.readouterr().out
    assert cli.main(["--help"]) == 0
    assert "usage: fuzzlab" in capsys.readouterr().out


def test_version():
    assert cli.main(["version"]) == 0


def test_unknown_command_is_a_clean_error_not_a_crash(capsys):
    rc = cli.main(["not-a-real-command"])
    assert rc == 2
    assert "unknown command: not-a-real-command" in capsys.readouterr().err


def test_dispatches_session_to_session_cli(monkeypatch):
    called = {}
    def fake_main(rest):
        called["rest"] = rest
        return 0
    monkeypatch.setattr("fuzzlab.session.cli.main", fake_main)
    assert cli.main(["session", "print", "--host", "h"]) == 0
    assert called["rest"] == ["print", "--host", "h"]


def test_a_subcommand_keyboard_interrupt_is_caught_by_the_top_level_backstop(
        monkeypatch, capsys):
    def _interrupt(rest):
        raise KeyboardInterrupt()
    monkeypatch.setattr("fuzzlab.session.cli.main", _interrupt)
    rc = cli.main(["session", "print", "--host", "h"])
    assert rc == 0
    assert "Interrupted by user" in capsys.readouterr().err


def test_a_subcommand_unhandled_exception_is_caught_by_the_top_level_backstop(
        monkeypatch, capsys):
    def _boom(rest):
        raise RuntimeError("something unexpected")
    monkeypatch.setattr("fuzzlab.mutation.cli.main", _boom)
    rc = cli.main(["mutate-run", "--url", "http://x", "--param", "q",
                   "--store", "u.db", "--authorized"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "fuzzlab mutate-run failed" in err and "something unexpected" in err


def test_argparse_systemexit_from_a_subcommand_still_propagates(monkeypatch):
    # A clean `p.error()`/`sys.exit()` from a subcommand (already the established
    # convention throughout these tools) must not be swallowed by the backstop —
    # SystemExit is a BaseException, not caught by `except Exception`.
    def _clean_exit(rest):
        raise SystemExit(2)
    monkeypatch.setattr("fuzzlab.session.cli.main", _clean_exit)
    try:
        cli.main(["session", "print", "--host", "h"])
        assert False, "expected SystemExit to propagate"
    except SystemExit as exc:
        assert exc.code == 2
