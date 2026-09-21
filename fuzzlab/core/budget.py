"""Request budget and the per-host timing mutex.

Every component checks requests out of one shared budget, with optional
per-component caps. Timing-sensitive traffic must run at concurrency 1 per host
so a differential-timing oracle is not corrupted by overlapping load; the budget
manager owns that mutex rather than leaving it to convention (a cross-cutting
concern in ARCHITECTURE.md).
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator


class BudgetExceeded(RuntimeError):
    """Raised when a checkout would exceed the total or a component cap."""


class RequestBudget:
    def __init__(self, total: int, per_component: dict[str, int] | None = None):
        if total < 0:
            raise ValueError("total budget must be >= 0")
        self._total = total
        self._per_component = dict(per_component or {})
        self._used = 0
        self._used_by: dict[str, int] = {}
        self._lock = threading.Lock()
        self._host_locks: dict[str, threading.Lock] = {}
        self._host_locks_guard = threading.Lock()

    def checkout(self, component: str, n: int = 1) -> None:
        """Reserve ``n`` requests for ``component`` or raise ``BudgetExceeded``."""
        with self._lock:
            if self._used + n > self._total:
                raise BudgetExceeded(
                    f"total budget exhausted: {self._used}+{n} > {self._total}"
                )
            cap = self._per_component.get(component)
            new_component_used = self._used_by.get(component, 0) + n
            if cap is not None and new_component_used > cap:
                raise BudgetExceeded(
                    f"component '{component}' cap exhausted: {new_component_used} > {cap}"
                )
            self._used += n
            self._used_by[component] = new_component_used

    def remaining(self) -> int:
        with self._lock:
            return self._total - self._used

    def used(self, component: str | None = None) -> int:
        with self._lock:
            return self._used if component is None else self._used_by.get(component, 0)

    def _host_lock(self, host: str) -> threading.Lock:
        with self._host_locks_guard:
            lock = self._host_locks.get(host)
            if lock is None:
                lock = threading.Lock()
                self._host_locks[host] = lock
            return lock

    @contextmanager
    def timing_lock(self, host: str) -> Iterator[None]:
        """Serialize timing-sensitive requests to ``host`` (concurrency 1)."""
        lock = self._host_lock(host)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()
