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
             method: str = "GET", location: str = "query",
             content_type: str | None = None) -> Probe:
        from urllib.parse import urlencode

        from fuzzlab.core.http import Request
        if location == "header":
            req = Request(method.upper(), url, headers={param: value},
                          identity=self._identity, timing=timing, component="oracle")
        elif location == "body" and content_type:
            # A whole-body point (`param="body"`, no single named field): send
            # `value` as the raw body at the ground truth's own declared
            # content type -- never assume JSON for every body point (some
            # are XML/binary-serialized; CC-FUZZ-0028/FR-FUZZ-15). A
            # multipart body (`UnrestrictedFileUploadContentTypeTrustStrategy`,
            # CC-FUZZ-0036) may carry genuinely binary content (real image
            # magic bytes) round-tripped through this `str`-only parameter as
            # latin-1 (lossless 1:1 byte<->codepoint) -- re-encoded the same
            # way here, never utf-8, which would corrupt any byte >= 0x80.
            body_bytes = (value.encode("latin-1") if content_type.startswith("multipart/")
                         else value.encode("utf-8"))
            req = Request(method.upper(), url, headers={"Content-Type": content_type},
                          body=body_bytes,
                          identity=self._identity, timing=timing, component="oracle")
        elif location == "body":
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
             method: str = "GET", location: str = "query",
             content_type: str | None = None) -> Probe:
        import requests
        kwargs = {"timeout": self._timeout}
        if location == "header":
            kwargs["headers"] = {param: value}
        elif location == "body" and content_type:
            # Whole-body point at its own declared content type -- never
            # assume JSON for every body point (CC-FUZZ-0028/FR-FUZZ-15). A
            # multipart body may carry genuinely binary content (real image
            # magic bytes) round-tripped as latin-1 -- see the matching
            # comment in `SeamProbeSender.send` above (CC-FUZZ-0036).
            kwargs["data"] = (value.encode("latin-1") if content_type.startswith("multipart/")
                              else value.encode("utf-8"))
            kwargs["headers"] = {"Content-Type": content_type}
        elif location == "body":
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
