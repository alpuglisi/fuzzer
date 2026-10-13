"""PluginManager: the toolkit's view of its plugins (Phase 10 T10.1, CC-PLUG-0005).

Loads plugins (from entry points or an explicit list), holds the `HookRegistry`, exposes
the dispatch surface the pipeline calls, and records the active set onto a run
(NFR-PLUG-reproducible, migrations 10 and 15). With **zero plugins every method is a
no-op** — `on_request` returns its input unchanged, notifications do nothing, the
registration collectors return empty lists, and `after_run` returns `[]` — so the
toolkit runs exactly as before (D6/NFR-PLUG-optional).

The two hooks that receive the store run under the advisory write guard (`guard.py`,
FR-PLUG-6):

- ``after_run(store, run_id)`` — each plugin is **one unit of work** (FR-PLUG-7): the
  scan's results are committed first; a plugin that fails has its uncommitted writes
  rolled back (writes it committed itself cannot be undone); a plugin that adds a
  `run_metrics` key the run already has (shadowing the oracle's scored metrics) has
  those rows deleted and fails; a plugin that switches the connection's transaction
  mode fails (everything it wrote is then committed and cannot be undone).
- a contributed **budget prioritizer** (FR-PLUG-8) runs read-only; one that raises or
  returns a malformed order fails, and the budget is spent in row order instead
  (`FailedBudgetOrder`) — never "confirm everything", which would exceed the cap.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fuzzlab.plugins.discovery import GROUP, discover
from fuzzlab.plugins.guard import ADVISORY, READ_ONLY, guarded
from fuzzlab.plugins.hooks import (AFTER_RUN, ON_CANDIDATE, ON_FINDING, ON_REQUEST,
                                   ON_RESPONSE, REGISTER_ORACLE, REGISTER_PAYLOAD_SOURCE,
                                   REGISTER_PRIORITIZER, REGISTER_RULES)
from fuzzlab.plugins.registry import HookRegistry, PluginInfo


@dataclass
class HookOutcome:
    """One `after_run` plugin's result (``ok``) or its contained error."""
    info: PluginInfo
    ok: bool
    result: Any = None
    error: str | None = None


@dataclass
class FailedBudgetOrder:
    """The order used when the budget prioritizer failed: the candidates in row order,
    so the confirmation cap still holds. Carries every field the pipeline reads."""
    order: list[int]
    error: str
    method: str = "row-order (prioritizer failed)"
    training_rows: int = 0
    training_positives: int = 0
    seed: int = 0
    model_sha256: str | None = None


class PluginConflict(ValueError):
    """More than one plugin contributes a budget prioritizer."""


def _invalid_order(res, ids: list[int]) -> str | None:
    """Why ``res`` is not a usable prioritizer order for ``ids`` (None if it is)."""
    order = getattr(res, "order", None)
    if not isinstance(order, (list, tuple)) or not all(
            isinstance(i, int) and not isinstance(i, bool) for i in order):
        return "prioritizer returned no list of candidate ids as `order`"
    if not set(order) <= set(ids):
        return "prioritizer ordered candidate ids it was not given"
    if not isinstance(getattr(res, "method", None), str):
        return "prioritizer order has no `method` string"
    for attr in ("training_rows", "training_positives"):
        val = getattr(res, attr, None)
        if not isinstance(val, int) or isinstance(val, bool):
            return f"prioritizer order has no integer `{attr}`"
    return None


def _tx_mode(conn) -> tuple:
    return conn.isolation_level, getattr(conn, "autocommit", None)


def _restore_tx_mode(conn, mode: tuple) -> None:
    isolation, autocommit = mode
    if autocommit is not None and conn.autocommit != autocommit:
        conn.autocommit = autocommit             # first: it overrides isolation_level
    if conn.isolation_level != isolation:
        conn.isolation_level = isolation


class PluginManager:
    def __init__(self, plugins=None, logger=None):
        self.registry = HookRegistry(logger=logger)
        for plugin in (plugins or []):
            self.registry.register(plugin)
        self._prioritizers: list[tuple[PluginInfo, Any]] | None = None
        self._scopes = 0                          # runs recorded so far

    @classmethod
    def from_entry_points(cls, group: str = GROUP, entry_points=None, logger=None,
                          extra=None):
        """Entry-point plugins, after ``extra`` (registered first, so a built-in keeps
        its name if an entry point reuses it)."""
        return cls(plugins=list(extra or []) + discover(group, entry_points, logger=logger),
                   logger=logger)

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

    # --- budget prioritizer (FR-PLUG-8) --------------------------------------
    def prioritizers(self) -> list[tuple[PluginInfo, Any]]:
        """``(info, callable)`` per plugin contributing a prioritizer — collected once
        per manager, so every caller sees the same answer."""
        if self._prioritizers is None:
            found = []
            for info, fn in list(self.registry.handlers(REGISTER_PRIORITIZER)):
                ok, res, _ = self.registry.contain(info, fn)
                if not ok or res is None:
                    continue
                if callable(res):
                    found.append((info, res))
                else:
                    self.registry.fail(info, "register_prioritizer returned a "
                                             f"non-callable {type(res).__name__}")
            self._prioritizers = found
        return list(self._prioritizers)

    def guarded_prioritizer(self):
        """The one contributed prioritizer, wrapped (read-only guard, validated return,
        failure → `FailedBudgetOrder`); ``None`` when no plugin contributes one. Raises
        `PluginConflict` when more than one does."""
        found = self.prioritizers()
        if not found:
            return None
        if len(found) > 1:
            raise PluginConflict("only one plugin may order the budget: "
                                 + ", ".join(info.name for info, _ in found))
        info, fn = found[0]
        registry = self.registry

        def run(store, run_id, candidate_ids):
            ids = list(candidate_ids)
            if info.name in registry.disabled():
                return FailedBudgetOrder(order=ids, error=registry.errors().get(
                    info.name, "disabled earlier in the run"))
            store.conn.commit()                  # nothing of the pipeline's is at stake
            mode = _tx_mode(store.conn)
            with guarded(store.conn, READ_ONLY):
                ok, res, error = registry.contain(info, fn, store, run_id, ids)
            if _tx_mode(store.conn) != mode:
                _restore_tx_mode(store.conn, mode)
                error = error or "changed the connection's transaction mode"
                ok = False
                registry.fail(info, error)
            store.conn.rollback()                # a read-only call leaves nothing
            if ok:
                if res is None:
                    return None                  # valid "no usable labels": confirm all
                error = _invalid_order(res, ids)
                if error is None:
                    return res
                registry.fail(info, error)
            return FailedBudgetOrder(order=ids, error=error)

        run.plugin_name = info.name
        return run

    # --- post-run stages (FR-PLUG-7) -----------------------------------------
    def after_run(self, store, run_id: int) -> list[HookOutcome]:
        conn = store.conn
        conn.commit()                            # the scan's results belong to the run
        outcomes: list[HookOutcome] = []
        for info, fn in list(self.registry.handlers(AFTER_RUN)):
            mode = _tx_mode(conn)
            before_max = conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM run_metrics").fetchone()[0]
            before_keys = {r[0] for r in conn.execute(
                "SELECT key FROM run_metrics WHERE run_id=?", (run_id,))}
            with guarded(conn, ADVISORY):
                ok, result, error = self.registry.contain(info, fn, store, run_id)
            problem = None
            if _tx_mode(conn) != mode:
                problem = ("changed the connection's transaction mode; its writes were "
                           "committed and could not be rolled back")
                _restore_tx_mode(conn, mode)     # restore, THEN roll back
            if not ok or problem:
                conn.rollback()
            shadow = self._shadowing_metrics(conn, run_id, before_max, before_keys)
            if shadow:
                conn.rollback()
                marks = ",".join("?" * len(shadow))
                conn.execute(f"DELETE FROM run_metrics WHERE id IN ({marks})",
                             [i for i, _ in shadow])
                problem = problem or ("wrote run_metrics key(s) the run already has or "
                                      "for another run: "
                                      + ", ".join(sorted({k for _, k in shadow})))
            conn.commit()
            if ok and problem:
                self.registry.fail(info, problem)
                ok, error = False, problem
            outcomes.append(HookOutcome(info=info, ok=ok, result=result if ok else None,
                                        error=error))
        return outcomes

    @staticmethod
    def _shadowing_metrics(conn, run_id, before_max, before_keys) -> list[tuple[int, str]]:
        rows = conn.execute("SELECT id, run_id, key FROM run_metrics WHERE id > ? "
                            "ORDER BY id", (before_max,)).fetchall()
        counts: dict[str, int] = {}
        for _, _, key in rows:
            counts[key] = counts.get(key, 0) + 1
        return [(row_id, key) for row_id, row_run, key in rows
                if row_run != run_id or key in before_keys or counts[key] > 1]

    # --- introspection / reproducibility ------------------------------------
    def active(self) -> list[PluginInfo]:
        return self.registry.active()

    def disabled(self) -> set[str]:
        return self.registry.disabled()

    def errors(self) -> dict[str, str]:
        return self.registry.errors()

    def rejected(self) -> list[PluginInfo]:
        return self.registry.rejected()

    def rejections(self) -> list[tuple[PluginInfo, str]]:
        return self.registry.rejections()

    def record(self, store, run_id: int) -> int:
        """Start the run's plugin scope and write every registered plugin onto it
        (migrations 10 + 15). From the second run on, containment from the previous run
        is cleared first; a failure before the first run (e.g. at registration) is kept
        and recorded as ``failed``."""
        if self._scopes:
            self.registry.reset()
        self._scopes += 1
        disabled, errors = self.registry.disabled(), self.registry.errors()
        infos = self.registry.registered()
        for info in infos:
            failed = info.name in disabled
            store.conn.execute(
                "INSERT INTO run_plugin (run_id, name, version, priority, config, status, "
                "error) VALUES (?,?,?,?,?,?,?)",
                (run_id, info.name, info.version, info.priority, info.config,
                 "failed" if failed else "attached", errors.get(info.name) if failed else None))
        store.conn.commit()
        return len(infos)

    def finalize(self, store, run_id: int) -> None:
        """Close the run's plugin record: each plugin ``ok``, or ``failed`` + its error."""
        disabled, errors = self.registry.disabled(), self.registry.errors()
        for info in self.registry.registered():
            failed = info.name in disabled
            store.conn.execute(
                "UPDATE run_plugin SET status=?, error=? WHERE run_id=? AND name=?",
                ("failed" if failed else "ok", errors.get(info.name) if failed else None,
                 run_id, info.name))
        store.conn.commit()
