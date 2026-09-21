"""Per-host credential store (decision D12).

Credentials are saved associated to a host (keyed by ``(host, identity)``), never
in the project store or the repo. The session manager looks up a host's
credentials and passes them when it authenticates to that host.

Backend resolution (auto, config-overridable):
1. OS Secret Service (gnome-keyring/KWallet) — interactive desktop.
2. Encrypted-file backend (`keyrings.alt`) for headless/CI/containers, unlocked by
   ``FUZZLAB_KEYRING_PASSPHRASE`` at ``FUZZLAB_KEYRING_PATH``.
3. Gated, lab-only env fallback (default off): ``FUZZLAB_CRED_<HOST>_<IDENTITY>``,
   honored only when enabled and the host is in lab scope.

The backend is injectable (any object with ``get_password``/``set_password``/
``delete_password``) so the store's logic is testable without a real keyring.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
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
    """Headless/CI backend: an AES-encrypted file unlocked by an env passphrase.

    Validated on a host with a working ``cryptography`` build; the store's own
    logic is covered by tests using an injected in-memory backend.
    """
    passphrase = environ.get("FUZZLAB_KEYRING_PASSPHRASE")
    if not passphrase:
        raise CredentialError(
            "FUZZLAB_KEYRING_PATH is set but FUZZLAB_KEYRING_PASSPHRASE is not; "
            "the encrypted keyring needs a passphrase"
        )
    try:
        from keyrings.alt.file import EncryptedKeyring
    except Exception as exc:  # pragma: no cover - environment dependent
        raise CredentialError(f"encrypted keyring backend unavailable: {exc}") from exc

    class _EnvEncryptedKeyring(EncryptedKeyring):
        @property
        def keyring_key(self) -> str:
            return passphrase

        @keyring_key.setter
        def keyring_key(self, value: str) -> None:  # ignore internal prompts
            pass

    backend = _EnvEncryptedKeyring()
    backend.file_path = path
    return backend
