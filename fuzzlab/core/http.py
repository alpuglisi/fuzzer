"""Session-aware HTTP send seam.

One place all traffic goes through, so scope, budget, the timing mutex, raw-byte
recording, and (from Phase 1) the session manager are enforced uniformly rather
than reimplemented per tool. The real session manager arrives in Phase 1; here
the seam accepts an optional ``session`` addon exposing ``prepare``/``observe``.

Safety: every request's host must be in scope (lab-only), and the transport is
injectable so tests never touch the network.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from fuzzlab.core.budget import RequestBudget


class OutOfScope(RuntimeError):
    """Raised when a request targets a host outside the configured scope."""


@dataclass
class Request:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    identity: str = "anonymous"
    timing: bool = False          # timing-sensitive -> serialized per host
    component: str = "http"


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float


# transport(method, url, headers, body, timeout) -> (status, headers, body_bytes)
Transport = Callable[[str, str, Mapping[str, str], bytes | None, float], tuple[int, dict[str, str], bytes]]


def _requests_transport(method: str, url: str, headers: Mapping[str, str],
                        body: bytes | None, timeout: float):
    import requests  # imported lazily so core has no hard runtime import cost

    resp = requests.request(
        method, url, headers=dict(headers), data=body, timeout=timeout,
        allow_redirects=False,
    )
    return resp.status_code, dict(resp.headers), resp.content


class HttpClient:
    def __init__(self, budget: RequestBudget, scope_hosts: list[str],
                 session: Any | None = None, store: Any | None = None,
                 run_id: int | None = None, transport: Transport | None = None,
                 timeout: float = 15.0, plugins: Any | None = None):
        self._budget = budget
        self._scope = set(scope_hosts)
        self._session = session
        self._store = store
        self._run_id = run_id
        self._transport = transport or _requests_transport
        self._timeout = timeout
        self._plugins = plugins       # optional PluginManager (on_request/on_response)

    def _check_scope(self, url: str) -> str:
        host = urlparse(url).hostname or ""
        if host not in self._scope:
            raise OutOfScope(f"host {host!r} not in scope {sorted(self._scope)}")
        return host

    def send(self, request: Request) -> Response:
        host = self._check_scope(request.url)
        self._budget.checkout(request.component, 1)
        if self._session is not None:
            self._session.prepare(request, request.identity)
        if self._plugins is not None:                      # on_request: plugins may edit
            request = self._plugins.on_request(request)
            host = self._check_scope(request.url)          # re-check if a plugin retargeted

        def _do() -> Response:
            start = time.perf_counter()
            status, headers, body = self._transport(
                request.method, request.url, request.headers, request.body, self._timeout
            )
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return Response(status=status, headers=headers, body=body, elapsed_ms=elapsed_ms)

        if request.timing:
            with self._budget.timing_lock(host):
                response = _do()
        else:
            response = _do()

        if self._plugins is not None:                      # on_response: observe only
            self._plugins.on_response(request, response)
        self._record(request, response)
        if self._session is not None:
            self._session.observe(request, response, request.identity)
        return response

    def _record(self, request: Request, response: Response) -> None:
        if self._store is None or self._run_id is None:
            return
        req_sha = self._store.put_body(request.body) if request.body else None
        resp_sha = self._store.put_body(response.body) if response.body else None
        self._store.conn.execute(
            "INSERT INTO flow (run_id, identity, method, url, status, elapsed_ms, "
            "req_body_sha, resp_body_sha) VALUES (?,?,?,?,?,?,?,?)",
            (self._run_id, request.identity, request.method, request.url,
             response.status, response.elapsed_ms, req_sha, resp_sha),
        )
        self._store.conn.commit()
