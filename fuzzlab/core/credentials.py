"""Per-host credential store (decision D12).

Credentials are saved associated to a host (keyed by ``(host, identity)``), never
in the project store or the repo. The session manager looks up a host's
credentials and passes them when it authenticates to that host.

Backend resolution (auto, config-overridable):
1. OS Secret Service (gnome-keyring/KWallet) — interactive desktop.
2. Encrypted-file backend for headless/CI/containers, unlocked by
   ``FUZZLAB_KEYRING_PASSPHRASE`` at ``FUZZLAB_KEYRING_PATH``. It is a single
   AES-Fernet-encrypted JSON file (key derived from the passphrase via PBKDF2),
   implemented on the ``cryptography`` library — the same library the OS-keyring
   dependency already pulls in (no PyCrypto/pycryptodome).
3. Gated, lab-only env fallback (default off): ``FUZZLAB_CRED_<HOST>_<IDENTITY>``,
   honored only when enabled and the host is in lab scope.

The backend is injectable (any object with ``get_password``/``set_password``/
``delete_password``) so the store's logic is testable without a real keyring.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

SERVICE = "fuzzlab"


class CredentialError(RuntimeError):
    """Raised when the credential store cannot be used as requested."""


@dataclass(frozen=True)
class Credential:
    username: str
    password: str

    def __repr__(self) -> str:  # never leak the password in logs/tracebacks
        return f"Credential(username={self.username!r}, password='***')"


class _Backend(Protocol):
    def get_password(self, service: str, account: str) -> str | None: ...
    def set_password(self, service: str, account: str, password: str) -> None: ...
    def delete_password(self, service: str, account: str) -> None: ...


def _norm(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", value).upper()


class CredentialStore:
    def __init__(self, backend: _Backend | None = None, allow_env: bool = False,
                 scope_hosts: list[str] | None = None,
                 environ: Mapping[str, str] | None = None):
        self._backend = backend if backend is not None else _default_backend()
        self._allow_env = allow_env
        self._scope = set(scope_hosts or [])
        self._environ = os.environ if environ is None else environ

    @classmethod
    def open(cls, config: Any) -> "CredentialStore":
        """Build from a Config: resolve the backend and env-fallback policy."""
        environ = os.environ
        return cls(
            backend=_default_backend(environ),
            allow_env=bool(config.get("allow_env_credentials", False)),
            scope_hosts=list(config.get("scope_hosts", [])),
            environ=environ,
        )

    @staticmethod
    def _account(host: str, identity: str) -> str:
        return f"{host}|{identity}"

    def set(self, host: str, identity: str, username: str, password: str) -> None:
        secret = json.dumps({"username": username, "password": password})
        self._backend.set_password(SERVICE, self._account(host, identity), secret)

    def get(self, host: str, identity: str) -> Credential | None:
        # Gated, lab-only env fallback takes precedence when enabled + in scope.
        if self._allow_env and host in self._scope:
            env_cred = self._from_env(host, identity)
            if env_cred is not None:
                return env_cred
        raw = self._backend.get_password(SERVICE, self._account(host, identity))
        if not raw:
            return None
        data = json.loads(raw)
        return Credential(username=data["username"], password=data["password"])

    def require(self, host: str, identity: str) -> Credential:
        cred = self.get(host, identity)
        if cred is None:
            raise CredentialError(
                f"no credentials for identity {identity!r} on host {host!r}; "
                f"save them with `fuzzlab session set-credential`"
            )
        return cred

    def delete(self, host: str, identity: str) -> None:
        try:
            self._backend.delete_password(SERVICE, self._account(host, identity))
        except Exception:  # noqa: BLE001 - deleting a missing entry is not an error
            pass

    def _from_env(self, host: str, identity: str) -> Credential | None:
        key = f"FUZZLAB_CRED_{_norm(host)}_{_norm(identity)}"
        value = self._environ.get(key)
        if not value:
            return None
        username, sep, password = value.partition(":")
        if not sep:
            raise CredentialError(f"{key} must be 'username:password'")
        return Credential(username=username, password=password)


def _default_backend(environ: Mapping[str, str] | None = None):
    """Resolve a keyring backend: encrypted-file when a path is set, else OS keyring."""
    environ = os.environ if environ is None else environ
    path = environ.get("FUZZLAB_KEYRING_PATH")
    if path:
        return _encrypted_file_backend(path, environ)
    import keyring
    return keyring


def _encrypted_file_backend(path: str, environ: Mapping[str, str]):
    """Headless/CI backend: an AES-Fernet-encrypted file unlocked by an env passphrase.

    Implemented on the ``cryptography`` library (already present via the OS-keyring
    dependency), not PyCrypto. The store's own logic is covered by tests using an
    injected in-memory backend; this backend's round-trip is covered by a test that
    skips when ``cryptography`` is unavailable.
    """
    passphrase = environ.get("FUZZLAB_KEYRING_PASSPHRASE")
    if not passphrase:
        raise CredentialError(
            "FUZZLAB_KEYRING_PATH is set but FUZZLAB_KEYRING_PASSPHRASE is not; "
            "the encrypted keyring needs a passphrase"
        )
    return _CryptographyFileBackend(path, passphrase)


class _CryptographyFileBackend:
    """A single AES-Fernet-encrypted JSON file of ``{service:account -> secret}``.

    The Fernet key is derived from the passphrase with PBKDF2-HMAC-SHA256 over a
    random per-file salt stored in the file header. Uses ``cryptography`` only.
    """

    _MAGIC = b"FZLB1\n"
    _ITERATIONS = 200_000

    def __init__(self, path: str, passphrase: str):
        self._path = Path(path)
        self._passphrase = passphrase.encode("utf-8")

    def _fernet(self, salt: bytes):
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                         iterations=self._ITERATIONS)
        return Fernet(base64.urlsafe_b64encode(kdf.derive(self._passphrase)))

    def _load(self) -> tuple[bytes | None, dict[str, str]]:
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            return None, {}
        if not raw.startswith(self._MAGIC):
            raise CredentialError(
                f"{self._path} is not a fuzzlab encrypted keyring file")
        body = raw[len(self._MAGIC):]
        salt, token = body[:16], body[16:]
        try:
            from cryptography.fernet import InvalidToken
        except Exception as exc:  # pragma: no cover - environment dependent
            raise CredentialError(f"cryptography unavailable: {exc}") from exc
        try:
            data = json.loads(self._fernet(salt).decrypt(token).decode("utf-8"))
        except InvalidToken as exc:
            raise CredentialError(
                "cannot decrypt the keyring file — wrong "
                "FUZZLAB_KEYRING_PASSPHRASE or corrupt file") from exc
        return salt, data

    def _save(self, salt: bytes | None, data: dict[str, str]) -> None:
        if salt is None:
            salt = os.urandom(16)
        token = self._fernet(salt).encrypt(json.dumps(data).encode("utf-8"))
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(self._path.name + ".tmp")
        tmp.write_bytes(self._MAGIC + salt + token)
        os.chmod(tmp, 0o600)               # secrets: owner-only
        os.replace(tmp, self._path)

    def get_password(self, service: str, account: str) -> str | None:
        _, data = self._load()
        return data.get(f"{service}:{account}")

    def set_password(self, service: str, account: str, password: str) -> None:
        salt, data = self._load()
        data[f"{service}:{account}"] = password
        self._save(salt, data)

    def delete_password(self, service: str, account: str) -> None:
        salt, data = self._load()
        if data.pop(f"{service}:{account}", None) is not None:
            self._save(salt, data)
