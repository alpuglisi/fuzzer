"""PluginManager: the toolkit's view of its plugins (Phase 10 T10.1).

Loads plugins (from entry points or an explicit list), holds the `HookRegistry`, exposes
the dispatch surface the pipeline calls, and records the active set onto a run
(NFR-PLUG-reproducible, migration 10). With **zero plugins every method is a no-op** —
`on_request` returns its input unchanged, notifications do nothing, and the registration
collectors return empty lists — so the toolkit runs exactly as before (D6/NFR-PLUG-optional).
"""

from __future__ import annotations

from fuzzlab.plugins.discovery import GROUP, discover
from fuzzlab.plugins.hooks import (ON_CANDIDATE, ON_FINDING, ON_REQUEST, ON_RESPONSE,
                                   REGISTER_ORACLE, REGISTER_PAYLOAD_SOURCE, REGISTER_RULES)
from fuzzlab.plugins.registry import HookRegistry, PluginInfo


class PluginManager:
    def __init__(self, plugins=None, logger=None):
        self.registry = HookRegistry(logger=logger)
        for plugin in (plugins or []):
            self.registry.register(plugin)

    @classmethod
    def from_entry_points(cls, group: str = GROUP, entry_points=None, logger=None):
        return cls(plugins=discover(group, entry_points, logger=logger), logger=logger)

    # --- mutation / observation dispatch (called along the pipeline) ---------
    def on_request(self, request):
        return self.registry.chain(ON_REQUEST, request)

    def on_response(self, request, response) -> None:
        self.registry.notify(ON_RESPONSE, request, response)

    def on_candidate(self, candidate) -> None:
        self.registry.notify(ON_CANDIDATE, candidate)

    def on_finding(self, finding) -> None:
        self.registry.notify(ON_FINDING, finding)

    # --- registration collectors (called at startup) ------------------------
    def rules(self) -> list:
        return self.registry.collect(REGISTER_RULES)

    def payload_sources(self) -> list:
        return self.registry.collect(REGISTER_PAYLOAD_SOURCE)

    def oracles(self) -> list:
        """Plugin-contributed oracles — the ONLY plugin path to a finding-writer."""
        return self.registry.collect(REGISTER_ORACLE)

    # --- introspection / reproducibility ------------------------------------
    def active(self) -> list[PluginInfo]:
        return self.registry.active()

    def disabled(self) -> set[str]:
        return self.registry.disabled()

    def record(self, store, run_id: int) -> int:
        """Write the active plugin set/versions onto the run (migration 10)."""
        infos = self.active()
        for info in infos:
            store.conn.execute(
                "INSERT INTO run_plugin (run_id, name, version, priority) VALUES (?,?,?,?)",
                (run_id, info.name, info.version, info.priority))
        store.conn.commit()
        return len(infos)
