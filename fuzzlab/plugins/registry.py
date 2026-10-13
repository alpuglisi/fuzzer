"""Hook registry with priority ordering and contained isolation (Phase 10 T10.1).

Plugins are plain objects that carry a ``name`` (and optional ``version``/``priority``/
``config``) and implement any subset of the hooks. The registry orders them by priority,
dispatches each hook by its kind, and **contains failures**: a plugin that raises is
logged and **disabled** for the rest of the run — it never aborts the run (FR-PLUG-3,
NFR-PLUG-safe). The first contained error per plugin is kept for the run record.

Observation-hook return values are ignored, which is how the oracle/advisory split holds
through plugins (FR-PLUG-5): only an oracle contributed via ``register_oracle`` reaches
the finding-writer path; an ``on_finding``/``on_candidate`` observer cannot write labels.
The two hooks that receive the store (``after_run``, a contributed prioritizer) run under
the advisory write guard instead (`guard.py`, FR-PLUG-6).
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class PluginInfo:
    name: str
    version: str = "0"
    priority: int = 100          # ascending: lower runs first
    config: str = ""             # canonical JSON of the plugin's options ("" = none)


def plugin_config(plugin) -> str:
    """A plugin's ``config`` dict as canonical JSON — the one serialisation (PA-0003).
    Anything that is not a JSON-serialisable dict is recorded as ``""``."""
    cfg = getattr(plugin, "config", None)
    if not isinstance(cfg, dict):
        return ""
    try:
        return json.dumps(cfg, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        return ""


def plugin_info(plugin) -> PluginInfo:
    """A plugin's metadata. Raises on malformed metadata (e.g. ``priority="high"``, or a
    bool priority, which ``int()`` would silently read as 0/1); `HookRegistry.register`
    contains that as a rejection (BUG-0076)."""
    priority = getattr(plugin, "priority", 100)
    if isinstance(priority, bool):
        raise ValueError(f"priority must be an integer, got {priority!r}")
    return PluginInfo(
        name=str(getattr(plugin, "name", type(plugin).__name__)),
        version=str(getattr(plugin, "version", "0")),
        priority=int(priority),
        config=plugin_config(plugin),
    )


def _fallback_name(plugin) -> str:
    """A name to report a plugin by when its own metadata cannot be read."""
    try:
        return str(getattr(plugin, "name", type(plugin).__name__))
    except Exception:                               # noqa: BLE001 - name itself broken
        return type(plugin).__name__


class HookRegistry:
    def __init__(self, logger=None):
        self._plugins: list[tuple[PluginInfo, object]] = []
        self._disabled: set[str] = set()
        self._errors: dict[str, str] = {}
        self._rejected: list[PluginInfo] = []
        self._rejected_why: list[str] = []            # parallel to `_rejected`
        self._log = logger

    def _reject(self, info: PluginInfo, why: str) -> None:
        self._rejected.append(info)
        self._rejected_why.append(why)
        if self._log:
            self._log.warning(f"plugin refused: {why}", extra={"plugin": info.name})

    def register(self, plugin) -> PluginInfo | None:
        """Register ``plugin``; refuse (log, return None) a plugin whose metadata cannot
        be read — every exception, contained like any other per-plugin failure so one bad
        plugin never takes the others down (BUG-0076, FR-PLUG-3) — or a name already
        registered (two plugins sharing a name would otherwise share one disabled
        flag)."""
        try:
            info = plugin_info(plugin)
        except Exception as exc:                     # noqa: BLE001 - containment boundary
            self._reject(PluginInfo(name=_fallback_name(plugin)),
                         f"invalid metadata: {type(exc).__name__}: {exc}")
            return None
        if any(i.name == info.name for i, _ in self._plugins):
            self._reject(info, "duplicate name")
            return None
        self._plugins.append((info, plugin))
        self._plugins.sort(key=lambda t: (t[0].priority, t[0].name))  # deterministic
        return info

    # --- dispatch ------------------------------------------------------------
    def handlers(self, hook: str):
        """``(info, bound hook)`` of every enabled plugin implementing ``hook``, in
        priority order."""
        for info, plugin in self._plugins:
            if info.name in self._disabled:
                continue
            try:
                fn = getattr(plugin, hook, None)       # a raising attribute is contained
            except Exception as exc:                   # noqa: BLE001 - (BUG-0076 sweep)
                self.fail(info, repr(exc))
                continue
            if callable(fn):
                yield info, fn

    _active = handlers           # internal alias kept for the dispatchers below

    def fail(self, info: PluginInfo, error: str) -> None:
        """Disable ``info``'s plugin for the rest of the run, keeping its first error."""
        self._disabled.add(info.name)
        self._errors.setdefault(info.name, error)
        if self._log:
            self._log.warning("plugin disabled after error",
                              extra={"plugin": info.name, "error": error})

    def contain(self, info: PluginInfo, fn, *args):
        """Run one plugin hook: ``(ok, result, error)``; on error the plugin is disabled
        and the run continues."""
        try:
            return True, fn(*args), None
        except Exception as exc:      # noqa: BLE001 - contain any plugin error
            error = repr(exc)
            self.fail(info, error)
            return False, None, error

    def _guard(self, info: PluginInfo, fn, *args):
        ok, result, _ = self.contain(info, fn, *args)
        return ok, result

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

    # --- per-run scope -------------------------------------------------------
    def reset(self) -> None:
        """Start a new run's containment scope: re-enable every plugin."""
        self._disabled.clear()
        self._errors.clear()

    # --- introspection -------------------------------------------------------
    def registered(self) -> list[PluginInfo]:
        return [info for info, _ in self._plugins]

    def active(self) -> list[PluginInfo]:
        return [info for info, _ in self._plugins if info.name not in self._disabled]

    def disabled(self) -> set[str]:
        return set(self._disabled)

    def errors(self) -> dict[str, str]:
        return dict(self._errors)

    def rejected(self) -> list[PluginInfo]:
        return list(self._rejected)

    def rejections(self) -> list[tuple[PluginInfo, str]]:
        """Each refused plugin with why it was refused."""
        return list(zip(self._rejected, self._rejected_why))
