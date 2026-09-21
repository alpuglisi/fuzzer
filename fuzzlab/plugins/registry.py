"""Hook registry with priority ordering and contained isolation (Phase 10 T10.1).

Plugins are plain objects that carry a ``name`` (and optional ``version``/``priority``)
and implement any subset of the hooks. The registry orders them by priority, dispatches
each hook by its kind, and **contains failures**: a plugin that raises is logged and
**disabled** for the rest of the run — it never aborts the run (FR-PLUG-3, NFR-PLUG-safe).

Observation-hook return values are ignored, which is how the oracle/advisory split holds
through plugins (FR-PLUG-5): only an oracle contributed via ``register_oracle`` reaches
the finding-writer path; an ``on_finding``/``on_candidate`` observer cannot write labels.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PluginInfo:
    name: str
    version: str = "0"
    priority: int = 100          # ascending: lower runs first


def plugin_info(plugin) -> PluginInfo:
    return PluginInfo(
        name=str(getattr(plugin, "name", type(plugin).__name__)),
        version=str(getattr(plugin, "version", "0")),
        priority=int(getattr(plugin, "priority", 100)),
    )


class HookRegistry:
    def __init__(self, logger=None):
        self._plugins: list[tuple[PluginInfo, object]] = []
        self._disabled: set[str] = set()
        self._log = logger

    def register(self, plugin) -> PluginInfo:
        info = plugin_info(plugin)
        self._plugins.append((info, plugin))
        self._plugins.sort(key=lambda t: (t[0].priority, t[0].name))  # deterministic
        return info

    # --- dispatch ------------------------------------------------------------
    def _active(self, hook: str):
        for info, plugin in self._plugins:
            if info.name in self._disabled:
                continue
            fn = getattr(plugin, hook, None)
            if callable(fn):
                yield info, fn

    def _guard(self, info: PluginInfo, fn, *args):
        """Run one plugin hook; on error disable the plugin and keep the run alive."""
        try:
            return True, fn(*args)
        except Exception as exc:      # noqa: BLE001 - contain any plugin error
            self._disabled.add(info.name)
            if self._log:
                self._log.warning("plugin disabled after error",
                                  extra={"plugin": info.name, "error": repr(exc)})
            return False, None

    def chain(self, hook: str, value, *extra):
        """Mutation fold: thread ``value`` through each plugin; None keeps the prior."""
        for info, fn in self._active(hook):
            ok, result = self._guard(info, fn, value, *extra)
            if ok and result is not None:
                value = result
        return value

    def notify(self, hook: str, *args) -> None:
        """Observation fan-out: call every plugin; **ignore** returns (advisory split)."""
        for info, fn in self._active(hook):
            self._guard(info, fn, *args)

    def collect(self, hook: str, *args) -> list:
        """Registration: gather non-None returns (a list return is flattened)."""
        out: list = []
        for info, fn in self._active(hook):
            ok, result = self._guard(info, fn, *args)
            if ok and result is not None:
                out.extend(result if isinstance(result, (list, tuple)) else [result])
        return out

    # --- introspection -------------------------------------------------------
    def active(self) -> list[PluginInfo]:
        return [info for info, _ in self._plugins if info.name not in self._disabled]

    def disabled(self) -> set[str]:
        return set(self._disabled)
