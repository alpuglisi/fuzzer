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


def test_host_is_keyed_by_hostname_regardless_of_port_or_scheme():
    """Save with a port (or a full URL) and look up by bare hostname — they agree
    (the session layer looks up by urlparse(url).hostname, without a port)."""
    store = CredentialStore(backend=FakeBackend())
    store.set("127.0.0.1:8080", "admin", "admin", "admin123")   # saved with a port
    assert store.get("127.0.0.1", "admin") == Credential("admin", "admin123")
    assert store.require("127.0.0.1", "admin").username == "admin"
    # a full URL and a different port also normalize to the same host key
    assert store.get("http://127.0.0.1:9999/x", "admin") == Credential("admin", "admin123")
    # and the reverse: saved without a port, fetched with one
    store.set("example.com", "user", "u", "p")
    assert store.get("example.com:443", "user") == Credential("u", "p")


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


def _crypto_or_skip():
    """Skip (not fail) when `cryptography` can't be imported/used — e.g. a broken
    build in CI/sandbox — since this test exercises the real backend. The rust
    bindings load lazily on first use and can raise a pyo3 ``PanicException`` (a
    ``BaseException``, not ``Exception``), so force a real op and catch broadly."""
    try:
        from cryptography.fernet import Fernet
        Fernet(Fernet.generate_key()).encrypt(b"probe")
    except BaseException as exc:  # noqa: BLE001 - broken native build panics, not raises
        pytest.skip(f"cryptography unavailable/broken: {exc}")


def _enc_backend(path):
    from fuzzlab.core.credentials import _encrypted_file_backend
    return _encrypted_file_backend(str(path), {"FUZZLAB_KEYRING_PASSPHRASE": "lab-pass"})


def test_encrypted_file_backend_roundtrip_and_persistence(tmp_path):
    _crypto_or_skip()
    path = tmp_path / "keyring.cfg"
    # A store over the real encrypted-file backend persists across instances.
    store = CredentialStore(backend=_enc_backend(path))
    store.set("127.0.0.1:8080", "admin", "admin", "admin123")
    assert store.get("127.0.0.1:8080", "admin") == Credential("admin", "admin123")
    assert path.exists()
    # Secrets are not stored in cleartext on disk.
    assert b"admin123" not in path.read_bytes()
    # A fresh backend instance (same file + passphrase) reads it back.
    reopened = CredentialStore(backend=_enc_backend(path))
    assert reopened.get("127.0.0.1:8080", "admin") == Credential("admin", "admin123")
    reopened.delete("127.0.0.1:8080", "admin")
    assert reopened.get("127.0.0.1:8080", "admin") is None


def test_encrypted_file_backend_wrong_passphrase_fails_loud(tmp_path):
    _crypto_or_skip()
    path = tmp_path / "keyring.cfg"
    CredentialStore(backend=_enc_backend(path)).set("h", "admin", "u", "pw")
    from fuzzlab.core.credentials import _encrypted_file_backend
    wrong = _encrypted_file_backend(str(path), {"FUZZLAB_KEYRING_PASSPHRASE": "nope"})
    with pytest.raises(CredentialError):
        wrong.get_password("fuzzlab", "h|admin")


def test_encrypted_file_backend_requires_passphrase(tmp_path):
    from fuzzlab.core.credentials import _encrypted_file_backend
    with pytest.raises(CredentialError):
        _encrypted_file_backend(str(tmp_path / "k.cfg"), {})
