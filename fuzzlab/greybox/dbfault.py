"""Per-request database-fault signal: the injected source and its fake.

`DbFaultSource` is the seam: given a request's correlation id, report whether that
request provoked a database **error/warning** (SQL syntax error, truncation, etc.).
The live implementation tails MariaDB's error/general log or a DB-proxy error hook
on the instrumented lab (on-host, T3.4); tests use `InMemoryDbFaultSource`. This is
a strong corroborating signal for SQLi (M10) and a reward tier — it is *not* a
finding on its own (the oracle still confirms).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable


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
