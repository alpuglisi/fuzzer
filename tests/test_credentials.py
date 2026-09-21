"""Tests for the per-host credential store (T1.1, D12)."""

import pytest

from fuzzlab.core.credentials import Credential, CredentialError, CredentialStore


class FakeBackend:
    """In-memory keyring backend so the store's logic is testable without a real one."""

    def __init__(self):
        self.data: dict[tuple[str, str], str] = {}

    def get_password(self, service, account):
        return self.data.get((service, account))

    def set_password(self, service, account, password):
        self.data[(service, account)] = password

    def delete_password(self, service, account):
        self.data.pop((service, account), None)


def test_set_get_delete_per_host():
    store = CredentialStore(backend=FakeBackend())
    store.set("localhost", "admin", "admin", "admin123")
    store.set("juice.local", "admin", "jadmin", "jpw")
    # Credentials are associated with the host they belong to.
    assert store.get("localhost", "admin") == Credential("admin", "admin123")
    assert store.get("juice.local", "admin") == Credential("jadmin", "jpw")
    assert store.get("localhost", "user") is None
    store.delete("localhost", "admin")
    assert store.get("localhost", "admin") is None


def test_require_raises_when_missing():
    store = CredentialStore(backend=FakeBackend())
    with pytest.raises(CredentialError):
        store.require("localhost", "admin")


def test_password_is_not_reprd():
    assert "s3cret" not in repr(Credential("u", "s3cret"))
    assert "***" in repr(Credential("u", "s3cret"))


def test_env_fallback_only_when_allowed_and_in_scope():
    env = {"FUZZLAB_CRED_LOCALHOST_ADMIN": "admin:frompw"}
    # Not allowed -> ignored.
    off = CredentialStore(backend=FakeBackend(), allow_env=False,
                          scope_hosts=["localhost"], environ=env)
    assert off.get("localhost", "admin") is None
    # Allowed but host out of scope -> ignored.
    oos = CredentialStore(backend=FakeBackend(), allow_env=True,
                          scope_hosts=["other"], environ=env)
    assert oos.get("localhost", "admin") is None
    # Allowed and in scope -> honored.
    on = CredentialStore(backend=FakeBackend(), allow_env=True,
                         scope_hosts=["localhost"], environ=env)
    assert on.get("localhost", "admin") == Credential("admin", "frompw")


def test_env_fallback_requires_username_password_format():
    env = {"FUZZLAB_CRED_LOCALHOST_ADMIN": "nocolon"}
    store = CredentialStore(backend=FakeBackend(), allow_env=True,
                            scope_hosts=["localhost"], environ=env)
    with pytest.raises(CredentialError):
        store.get("localhost", "admin")


def test_backend_takes_precedence_when_env_absent():
    store = CredentialStore(backend=FakeBackend(), allow_env=True,
                            scope_hosts=["localhost"], environ={})
    store.set("localhost", "admin", "admin", "kbpw")
    assert store.get("localhost", "admin") == Credential("admin", "kbpw")
