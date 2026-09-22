"""Robustness coverage for `fuzzlab session` (`session/cli.py`), which had zero
prior test coverage despite handling credentials (secrets-adjacent).

Covers the clean-error-handling added on top of the previously-unguarded
`input()`/`getpass.getpass()` prompts, the credential-store write, and the
`print` subcommand's login call — none of the three raised anything but a raw
traceback before this change.
"""
import pytest

from fuzzlab.core.credentials import CredentialStore
from fuzzlab.session import cli as session_cli
from fuzzlab.session.manager import SessionAuthError
from tests.test_credentials import FakeBackend


def _fake_store(monkeypatch):
    store = CredentialStore(backend=FakeBackend())
    monkeypatch.setattr(session_cli.CredentialStore, "open", staticmethod(lambda cfg: store))
    return store


def test_set_credential_happy_path(monkeypatch, capsys):
    store = _fake_store(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda prompt="": "alice")
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "s3cret")
    rc = session_cli.main(["set-credential", "--host", "h", "--identity", "alice"])
    assert rc == 0
    assert "stored credentials for alice@h" in capsys.readouterr().out
    cred = store.get("h", "alice")
    assert cred.username == "alice" and cred.password == "s3cret"


def test_set_credential_username_flag_skips_the_prompt(monkeypatch):
    _fake_store(monkeypatch)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "s3cret")
    calls = []
    monkeypatch.setattr("builtins.input", lambda prompt="": calls.append(1) or "unused")
    rc = session_cli.main(["set-credential", "--host", "h", "--identity", "a", "--username", "bob"])
    assert rc == 0
    assert calls == []                              # input() never called


def test_set_credential_non_interactive_terminal_gives_a_clean_message_not_a_traceback(
        monkeypatch, capsys):
    _fake_store(monkeypatch)
    def _no_tty(prompt=""):
        raise EOFError()
    monkeypatch.setattr("builtins.input", _no_tty)
    rc = session_cli.main(["set-credential", "--host", "h", "--identity", "a"])
    assert rc == 1
    assert "interactive terminal" in capsys.readouterr().out


def test_set_credential_backend_failure_gives_a_clean_message(monkeypatch, capsys):
    store = _fake_store(monkeypatch)
    def _boom(*a, **k):
        raise RuntimeError("keyring backend unavailable")
    monkeypatch.setattr(store, "set", _boom)
    monkeypatch.setattr("builtins.input", lambda prompt="": "alice")
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "s3cret")
    rc = session_cli.main(["set-credential", "--host", "h", "--identity", "a"])
    assert rc == 1
    assert "Could not save credentials" in capsys.readouterr().out


def test_print_reports_login_failure_cleanly(monkeypatch, capsys):
    _fake_store(monkeypatch)
    def _fail(self, host, identity, base_url):
        raise SessionAuthError("bad credentials")
    monkeypatch.setattr(session_cli.SessionManager, "session_header", _fail)
    rc = session_cli.main(["print", "--host", "h", "--identity", "a", "--base-url", "http://h/"])
    assert rc == 1
    assert "login failed: bad credentials" in capsys.readouterr().out


def test_print_reports_an_unreachable_target_cleanly_not_a_traceback(monkeypatch, capsys):
    _fake_store(monkeypatch)
    def _fail(self, host, identity, base_url):
        raise ConnectionError("connection refused")
    monkeypatch.setattr(session_cli.SessionManager, "session_header", _fail)
    rc = session_cli.main(["print", "--host", "h", "--identity", "a", "--base-url", "http://h/"])
    assert rc == 1
    assert "Could not reach http://h/" in capsys.readouterr().out


def test_store_open_failure_gives_a_clean_message(monkeypatch, capsys):
    def _boom(cfg):
        raise RuntimeError("no keyring backend on this host")
    monkeypatch.setattr(session_cli.CredentialStore, "open", staticmethod(_boom))
    rc = session_cli.main(["set-credential", "--host", "h", "--identity", "a", "--username", "u"])
    assert rc == 1
    assert "Could not open the credential store" in capsys.readouterr().out
