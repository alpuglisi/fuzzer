"""Per-request database-fault signal: the injected source and its fake.

`DbFaultSource` is the seam: given a request's correlation id, report whether that
request provoked a database **error/warning** (SQL syntax error, truncation, etc.).
The live implementation reads the same per-request side channel the coverage shim
writes (on-host, T3.4): `cov.php` records a `db_fault`/`db_error` marker for the
request keyed by its `X-Fzl-Cov` id, so the fault is attributed to exactly one
request with no racy log-tailing. Tests use `InMemoryDbFaultSource`. This is a strong
corroborating signal for SQLi (M10) and a reward tier — it is *not* a finding on its
own (the oracle still confirms).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol, runtime_checkable

from fuzzlab.greybox.coverage import sanitize_cid


@dataclass(frozen=True)
class DbFault:
    """A database fault attributed to a request."""
    faulted: bool
    detail: str = ""            # short message (e.g. the SQL error text), for evidence


@runtime_checkable
class DbFaultSource(Protocol):
    def fault_for(self, request_id: str) -> DbFault:
        ...


class InMemoryDbFaultSource:
    """Test/offline fake: canned faults keyed by request id (default: no fault)."""

    def __init__(self, by_request: Mapping[str, DbFault] | None = None):
        self._by_request = dict(by_request or {})

    def set(self, request_id: str, fault: DbFault) -> None:
        self._by_request[request_id] = fault

    def fault_for(self, request_id: str) -> DbFault:
        return self._by_request.get(request_id, DbFault(faulted=False))


class FileDbFaultSource:
    """Live source: reads the lab shim's per-request DB-fault marker (T3.4).

    Shares the coverage shim's side channel: ``cov.php`` records ``db_fault`` (bool)
    and a short ``db_error`` string in the same JSON file it names by the sanitized
    ``X-Fzl-Cov`` id. A missing/undecodable file means "no fault observed" (default),
    never a raise — an uninstrumented request simply reports no fault.
    """

    def __init__(self, directory: str | Path = "/tmp/fzl-cov"):
        self._dir = Path(directory)

    def fault_for(self, request_id: str) -> DbFault:
        path = self._dir / sanitize_cid(request_id)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return DbFault(faulted=False)
        if not isinstance(data, Mapping):
            return DbFault(faulted=False)
        return DbFault(faulted=bool(data.get("db_fault")),
                       detail=str(data.get("db_error", ""))[:500])
