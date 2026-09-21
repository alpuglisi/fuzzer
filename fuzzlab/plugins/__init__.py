"""Plugin system (component #13, Phase 10).

Extend the toolkit — ML models, extra rules, custom oracles, payload sources — without
editing core, via `importlib.metadata` entry points on a hook registry (D6). Plugins are
contained (a failure disables just that plugin), ordered by priority, and bound by the
oracle/advisory split (only a `register_oracle` plugin reaches the finding-writer). The
toolkit runs fully with zero plugins.
"""

from __future__ import annotations

from fuzzlab.plugins.discovery import GROUP, discover
from fuzzlab.plugins.hooks import (ALL_HOOKS, MUTATION_HOOKS, OBSERVATION_HOOKS,
                                   REGISTRATION_HOOKS)
from fuzzlab.plugins.manager import PluginManager
from fuzzlab.plugins.registry import HookRegistry, PluginInfo, plugin_info

__all__ = [
    "PluginManager",
    "HookRegistry",
    "PluginInfo",
    "plugin_info",
    "discover",
    "GROUP",
    "ALL_HOOKS",
    "MUTATION_HOOKS",
    "OBSERVATION_HOOKS",
    "REGISTRATION_HOOKS",
]
