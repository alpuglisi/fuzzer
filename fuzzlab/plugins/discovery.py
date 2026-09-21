"""Entry-point plugin discovery (Phase 10 T10.1, FR-PLUG-1).

Plugins are distributed as ``importlib.metadata`` entry points in the ``fuzzlab.plugins``
group; each loads to a plugin object (or a zero-arg factory returning one). Discovery is
contained — a broken entry point is logged and skipped, never fatal. For tests, an
``entry_points`` iterable can be injected (each item needs a ``.load()``), so no real
package install is required.
"""

from __future__ import annotations

GROUP = "fuzzlab.plugins"


def _entry_points(group: str):
    import importlib.metadata as im
    try:
        eps = im.entry_points(group=group)          # Python 3.10+
    except TypeError:                                # older API returns a dict
        eps = im.entry_points().get(group, [])
    return list(eps)


def discover(group: str = GROUP, entry_points=None, logger=None) -> list:
    """Return plugin objects from the entry-point group (or an injected iterable)."""
    eps = _entry_points(group) if entry_points is None else list(entry_points)
    plugins = []
    for ep in eps:
        try:
            loaded = ep.load()
            plugins.append(loaded() if callable(loaded) else loaded)
        except Exception as exc:                     # noqa: BLE001 - skip a bad plugin
            if logger:
                logger.warning("plugin failed to load",
                               extra={"entry_point": getattr(ep, "name", "?"),
                                      "error": repr(exc)})
    return plugins
