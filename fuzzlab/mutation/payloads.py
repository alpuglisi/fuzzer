"""Payload pool — the consumer for the `register_payload_source` plugin hook (Phase 10).

Aggregates seed payloads per vulnerability class from a small built-in catalog plus any
plugin-contributed **payload sources** (the `register_payload_source` hook, FR-PLUG-2),
so the mutation engine has extra bases to evolve against a filter. A payload source is any
object with ``payloads_for(vuln_class, sink_context=None) -> list[str]``.

This wires the last plugin hook end-to-end: `PluginManager.payload_sources()` returns the
registered sources, `PayloadPool.from_plugins` folds them in, and `MutationSearch.search_pool`
consumes the pool.
"""

from __future__ import annotations

from typing import Protocol

# A tiny built-in seed catalog — the classic bases the mutation engine evolves. Plugins
# extend this via register_payload_source; they never need to replace it.
_BUILTIN: dict[str, list[str]] = {
    "sql-injection": ["' OR '1'='1", "1' UNION SELECT NULL-- -", "1 AND SLEEP(5)"],
    "xss": ["<script>alert(1)</script>", "<svg onload=alert(1)>"],
    "command-injection": [";id", "| id", "$(id)"],
    "file-inclusion": ["../../etc/passwd", "....//....//etc/passwd"],
}


class PayloadSource(Protocol):
    def payloads_for(self, vuln_class: str, sink_context: str | None = None) -> list[str]:
        ...


class PayloadPool:
    """Seed payloads per class, from built-ins + plugin-contributed sources."""

    def __init__(self, sources: list[PayloadSource] | None = None,
                 builtins: dict[str, list[str]] | None = None):
        self.sources = list(sources or [])
        self._builtins = _BUILTIN if builtins is None else builtins

    @classmethod
    def from_plugins(cls, manager, builtins: dict[str, list[str]] | None = None) -> "PayloadPool":
        """Build a pool from a `PluginManager`'s `register_payload_source` results."""
        return cls(sources=list(manager.payload_sources()), builtins=builtins)

    def payloads(self, vuln_class: str, sink_context: str | None = None) -> list[str]:
        """Deduped, ordered seed payloads for ``vuln_class`` (built-ins first)."""
        out: list[str] = []
        seen: set[str] = set()
        for p in self._builtins.get(vuln_class, []):
            if p not in seen:
                seen.add(p)
                out.append(p)
        for src in self.sources:
            try:
                extra = src.payloads_for(vuln_class, sink_context) or []
            except Exception:                     # noqa: BLE001 - a bad source is skipped
                extra = []
            for p in extra:
                if p and p not in seen:
                    seen.add(p)
                    out.append(p)
        return out
