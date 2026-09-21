"""Layered configuration, hashed onto the run.

Precedence (lowest to highest): built-in defaults -> config file -> environment
variables (``FUZZLAB_*``) -> explicit CLI/caller overrides. The merged config is
validated and given a stable hash so every run records exactly what it ran under
(a cross-cutting concern in ARCHITECTURE.md).

Secrets are never stored here by value: config may hold a *reference* (e.g. a
keyring key name), never a credential. The session manager (Phase 1) resolves
references from the OS keyring.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

# Built-in defaults. Safety-relevant values are intentionally conservative.
DEFAULTS: dict[str, Any] = {
    # Networking / scope. Lab-only: the target must resolve to loopback.
    "target_base_url": "http://localhost",
    "scope_hosts": ["localhost", "127.0.0.1"],
    # Request budget (a first-class resource; see budget.py).
    "budget_total": 5000,
    "budget_per_component": {},
    # Timing measurements run at concurrency 1 per host.
    "timing_concurrency": 1,
    # Safety gates.
    "authorized": False,          # tools that send traffic require this to be true
    "allow_destructive": False,   # destructive payload classes are off by default
    # Storage.
    "store_path": "fuzzlab.db",
    # Ground-truth label contract (read out-of-band from disk; D9).
    "ground_truth_dir": "lab/ground-truth",
    # Web control panel (D11): loopback only.
    "web_host": "127.0.0.1",
    "web_port": 8787,
}

_ENV_PREFIX = "FUZZLAB_"

# Keys whose value is secret-referencing and must never be logged/serialized raw.
_REDACT_KEYS = {"password", "secret", "token", "credential", "cookie", "authorization"}


def _coerce(default: Any, raw: str) -> Any:
    """Coerce an environment string to the type of its default value."""
    if isinstance(default, bool):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(default, int) and not isinstance(default, bool):
        return int(raw)
    if isinstance(default, float):
        return float(raw)
    if isinstance(default, (list, dict)):
        return json.loads(raw)
    return raw


def _deep_merge(base: dict[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in overlay.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _from_env(defaults: Mapping[str, Any], environ: Mapping[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, default in defaults.items():
        env_key = _ENV_PREFIX + key.upper()
        if env_key in environ:
            out[key] = _coerce(default, environ[env_key])
    return out


@dataclass(frozen=True)
class Config:
    """An immutable, validated view over the merged configuration."""

    values: dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        return self.values[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def hash(self) -> str:
        """A stable content hash of the config, recorded on the run row."""
        canonical = json.dumps(self.values, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def redacted(self) -> dict[str, Any]:
        """A copy safe to log: secret-referencing keys masked."""
        return _redact(self.values)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            if any(token in key.lower() for token in _REDACT_KEYS):
                out[key] = "***"
            else:
                out[key] = _redact(val)
        return out
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _validate(values: Mapping[str, Any]) -> None:
    if int(values.get("budget_total", 0)) < 0:
        raise ValueError("budget_total must be >= 0")
    if int(values.get("timing_concurrency", 1)) != 1:
        # Timing measurements must run serialized per host; a value other than 1
        # would silently invalidate differential-timing confirmation.
        raise ValueError("timing_concurrency must be 1 (timing runs at concurrency 1)")
    scope = values.get("scope_hosts", [])
    if not isinstance(scope, list) or not scope:
        raise ValueError("scope_hosts must be a non-empty list (lab-only scope)")


def load_config(
    file_path: str | os.PathLike[str] | None = None,
    overrides: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] | None = None,
) -> Config:
    """Load and merge configuration in precedence order, then validate.

    defaults -> file (JSON) -> environment (``FUZZLAB_*``) -> explicit overrides.
    """
    environ = os.environ if environ is None else environ
    merged = dict(DEFAULTS)

    if file_path is not None:
        path = Path(file_path)
        if path.exists():
            merged = _deep_merge(merged, json.loads(path.read_text(encoding="utf-8")))

    merged = _deep_merge(merged, _from_env(DEFAULTS, environ))

    if overrides:
        merged = _deep_merge(merged, dict(overrides))

    _validate(merged)
    return Config(values=merged)
