"""BUG-0690 sweep (PA-0690): the greybox CLI's session is carried whole or refused.

`greybox_cli._cookie_for` kept only a ``Cookie:`` session header and returned ``None``
for any other, so a bearer-token identity ran greybox fully anonymous and a browser
login's Authorization beside its cookie was dropped (PA-0545(1): "sends anonymously"
is never a disposition). The greybox sender carries a Cookie only, so any other
session header is now refused before a probe is sent.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.urls import canonical_origin
from fuzzlab.session.state import SessionState

BASE = "http://127.0.0.1:8092/"


def _cookie_for(monkeypatch, state: SessionState):
    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.greybox import greybox_cli
    from fuzzlab.session import manager as manager_mod
    from tests.test_credentials import FakeBackend
    monkeypatch.setattr(CredentialStore, "open",
                        classmethod(lambda cls, cfg: CredentialStore(backend=FakeBackend())))
    monkeypatch.setattr(manager_mod.SessionManager, "ensure",
                        lambda self, host, identity, base_url, *, operator=False: state)
    return greybox_cli._cookie_for("127.0.0.1", "user", BASE)


def _state(**kw) -> SessionState:
    return SessionState("127.0.0.1", "user", valid=True,
                        origins=frozenset({canonical_origin(BASE)}), **kw)


def test_a_cookie_session_is_carried(monkeypatch):
    cookie, _secure, _is_auth, origins = _cookie_for(
        monkeypatch, _state(kind="cookie", cookies={"sid": "s"}))
    assert cookie == "sid=s" and origins == frozenset({canonical_origin(BASE)})


def test_a_bearer_session_is_refused_never_run_anonymously(monkeypatch):
    """Pre-fix: ``(None, ...)`` -- the sender then probed with no session at all."""
    from fuzzlab.session.manager import SessionAuthError
    with pytest.raises(SessionAuthError) as err:
        _cookie_for(monkeypatch, _state(kind="bearer",
                                        headers={"Authorization": "Bearer t0ken"}))
    assert "Authorization" in str(err.value) and "t0ken" not in str(err.value)


def test_a_cookie_and_authorization_session_is_refused_never_half_carried(monkeypatch):
    """Pre-fix: the Cookie only -- the Authorization half silently dropped."""
    from fuzzlab.session.manager import SessionAuthError
    with pytest.raises(SessionAuthError):
        _cookie_for(monkeypatch, _state(kind="bearer", cookies={"sid": "s"},
                                        headers={"Authorization": "Bearer t0ken"}))


def test_the_cli_reports_the_refusal_as_a_usage_error_before_any_probe(monkeypatch,
                                                                        capsys, tmp_path):
    from fuzzlab.greybox import greybox_cli
    from fuzzlab.session.manager import SessionAuthError

    def refuse(*_a, **_k):
        raise SessionAuthError("carries Authorization")
    monkeypatch.setattr(greybox_cli, "_cookie_for", refuse)
    with pytest.raises(SystemExit):
        greybox_cli.main(["--base-url", BASE, "--store", str(tmp_path / "x.db"),
                          "--identity", "user", "--points", "crawl", "--authorized"])
    assert "authentication failed for user@127.0.0.1: carries Authorization" in \
        capsys.readouterr().err
    assert not (tmp_path / "x.db").exists()                  # before any side effect
