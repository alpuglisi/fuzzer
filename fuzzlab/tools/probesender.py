"""Probe senders that adapt the tools' HTTP to the oracle's `Sender` interface.

The oracle needs the full response (text + headers + elapsed) to confirm, so these
return a `Probe`. Two flavors: authenticated (via the core seam + session manager)
and standalone (plain requests). Built by `make_probe_sender`.
"""

from __future__ import annotations

import time

from fuzzlab.oracle.probe import Probe
from fuzzlab.tools.authhttp import make_authenticated_client, with_query_param


class SeamProbeSender:
    """Authenticated: routes through the core HTTP seam + session manager."""

    def __init__(self, client, identity: str = "anonymous"):
        self._client = client
        self._identity = identity

    def send(self, url: str, param: str, value: str, timing: bool = False,
             method: str = "GET", location: str = "query") -> Probe:
        from urllib.parse import urlencode

        from fuzzlab.core.http import Request
        if location == "body":
            req = Request(method.upper(), url,
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          body=urlencode({param: value}).encode(),
                          identity=self._identity, timing=timing, component="oracle")
        else:
            req = Request(method.upper(), with_query_param(url, param, value),
                          identity=self._identity, timing=timing, component="oracle")
        r = self._client.send(req)
        return Probe(status=r.status, text=r.body.decode("utf-8", "replace"),
                     elapsed=r.elapsed_ms / 1000.0, headers=dict(r.headers))


class RequestsProbeSender:
    """Standalone: plain requests, no auth (unauthenticated confirmation)."""

    def __init__(self, session=None, timeout: float = 15.0):
        import requests
        self._session = session or requests.Session()
        self._timeout = timeout

    def send(self, url: str, param: str, value: str, timing: bool = False,
             method: str = "GET", location: str = "query") -> Probe:
        import requests
        # `allow_redirects=False` (BUG-0039): a confirmation strategy that reads
        # the raw `Location` header (e.g. `OpenRedirectStrategy`) needs the
        # redirect response itself, not whatever page following it lands on --
        # and a payload that *is* a redirect target (an attacker-controlled URL)
        # can point anywhere, including a host this sandbox's own egress policy
        # or a real network simply cannot reach, which `requests` surfaces as an
        # uncaught connection error while trying to follow it. Matches
        # `fuzzlab.core.http`'s authenticated client, which already sets this
        # (see that module's own request-building code) -- this was a real
        # inconsistency between the two `Sender` implementations, not a
        # deliberate difference.
        kwargs = {"timeout": self._timeout, "allow_redirects": False}
        if location == "body":
            kwargs["data"] = {param: value}          # form-encoded body
        else:
            kwargs["params"] = {param: value}        # query string
        start = time.perf_counter()
        try:
            r = self._session.request(method.upper(), url, **kwargs)
            return Probe(status=r.status_code, text=r.text,
                         elapsed=time.perf_counter() - start, headers=dict(r.headers))
        except requests.Timeout:
            return Probe(status=0, text="", elapsed=float(self._timeout))


def make_probe_sender(target_url: str, identity: str | None = None,
                      timeout: float = 15.0):
    """Authenticated sender when an identity is given, else a standalone one."""
    if identity:
        client = make_authenticated_client(target_url, identity, timeout)
        return SeamProbeSender(client, identity)
    return RequestsProbeSender(timeout=timeout)
