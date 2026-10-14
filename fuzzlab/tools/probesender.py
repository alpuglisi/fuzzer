"""Probe senders that adapt the tools' HTTP to the oracle's `Sender` interface.

The oracle needs the full response (text + headers + elapsed) to confirm, so these
return a `Probe`. Two flavors: authenticated (via the core seam + session manager)
and standalone (plain requests). Built by `make_probe_sender`.
"""

from __future__ import annotations

import time

from fuzzlab.core.urls import check_send_url, url_key
from fuzzlab.oracle.probe import Probe
from fuzzlab.tools.authhttp import make_auth, with_query, with_query_param


class _ExplicitAllowance:
    """``allow_explicit``: the operator-enumerated (ground-truth) URLs a sender may
    probe even when they look destructive (NFR-FUZZ-safe, CC-FUZZ-0060)."""

    _explicit: frozenset[str] = frozenset()

    def allow_explicit(self, urls) -> None:
        self._explicit = frozenset(self._explicit | {url_key(u) for u in urls if u})


class SeamProbeSender(_ExplicitAllowance):
    """Authenticated: routes through the core HTTP seam + session manager.

    NFR-FUZZ-safe (BUG-0112): a probe to one of the session's auth endpoints (the login
    page and form action) is sent **anonymously**, so it can neither log the run's
    session out nor re-authenticate it. ``manager``/``base_url`` let the sender log in
    once before its first probe, so those endpoints are known.
    """

    def __init__(self, client, identity: str = "anonymous", manager=None,
                 base_url: str | None = None):
        self._client = client
        self._identity = identity
        self._manager = manager
        self._base_url = base_url
        self._ensured = False
        self.auth_endpoint_anonymous_sends = 0

    def _identity_for(self, url: str) -> str:
        if self._manager is None or self._identity == "anonymous":
            return self._identity
        if not self._ensured:
            from urllib.parse import urlparse

            from fuzzlab.session.manager import _directory
            # Only the operator's own base is operator input; a probe URL is not
            # (its directory, never exempt, never remembered) — BUG-0113.
            if self._base_url:
                self._manager.ensure(urlparse(self._base_url).hostname or "",
                                     self._identity, self._base_url, operator=True)
            else:
                self._manager.ensure(urlparse(url).hostname or "", self._identity,
                                     _directory(url))
            self._ensured = True
        if self._manager.is_auth_endpoint(url):
            self.auth_endpoint_anonymous_sends += 1
            return "anonymous"
        return self._identity

    def send(self, url: str, param: str, value: str, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None) -> Probe:
        from urllib.parse import urlencode

        from fuzzlab.core.http import Request
        check_send_url(url, self._explicit)              # NFR-FUZZ-safe (BUG-0112)
        identity = self._identity_for(url)
        if entries is not None and location in ("query", "body"):
            # a form point: the whole entry list, the fuzzed field already set
            req = (Request(method.upper(), url,
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           body=urlencode(list(entries)).encode(), identity=identity,
                           timing=timing, component="oracle")
                   if location == "body" else
                   Request(method.upper(), with_query(url, entries), identity=identity,
                           timing=timing, component="oracle"))
        elif location == "header":
            req = Request(method.upper(), url, headers={param: value},
                          identity=identity, timing=timing, component="oracle")
        elif location == "body" and content_type:
            # A whole-body point (`param="body"`, no single named field): send
            # `value` as the raw body at the ground truth's own declared
            # content type -- never assume JSON for every body point (some
            # are XML/binary-serialized; CC-FUZZ-0028/FR-FUZZ-15). A
            # multipart body (`UnrestrictedFileUploadContentTypeTrustStrategy`,
            # CC-FUZZ-0040) may carry genuinely binary content (real image
            # magic bytes) round-tripped through this `str`-only parameter as
            # latin-1 (lossless 1:1 byte<->codepoint) -- re-encoded the same
            # way here, never utf-8, which would corrupt any byte >= 0x80.
            body_bytes = (value.encode("latin-1") if content_type.startswith("multipart/")
                         else value.encode("utf-8"))
            req = Request(method.upper(), url, headers={"Content-Type": content_type},
                          body=body_bytes,
                          identity=identity, timing=timing, component="oracle")
        elif location == "body":
            req = Request(method.upper(), url,
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          body=urlencode({param: value}).encode(),
                          identity=identity, timing=timing, component="oracle")
        else:
            req = Request(method.upper(), with_query_param(url, param, value),
                          identity=identity, timing=timing, component="oracle")
        r = self._client.send(req)
        return Probe(status=r.status, text=r.body.decode("utf-8", "replace"),
                     elapsed=r.elapsed_ms / 1000.0, headers=dict(r.headers))


class RequestsProbeSender(_ExplicitAllowance):
    """Standalone: plain requests, no auth (unauthenticated confirmation)."""

    def __init__(self, session=None, timeout: float = 15.0):
        import requests
        if session is None:
            from fuzzlab.core.http import DEFAULT_BROWSER_HEADERS
            session = requests.Session()
            session.headers.update(DEFAULT_BROWSER_HEADERS)
        self._session = session
        self._timeout = timeout

    def send(self, url: str, param: str, value: str, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None) -> Probe:
        import requests
        # `allow_redirects=False` (BUG-0039, strengthened by BUG-0044/PA-0046
        # to cover every sender, not just this one): a confirmation strategy
        # that reads the raw `Location` header (e.g. `OpenRedirectStrategy`)
        # needs the redirect response itself, not whatever page following it
        # lands on -- and a payload that *is* a redirect target (an
        # attacker-controlled URL) can point anywhere, including a host this
        # sandbox's own egress policy or a real network simply cannot reach,
        # which `requests` surfaces as an uncaught connection error while
        # trying to follow it. Silently following redirects can also crash
        # outright (`requests.exceptions.TooManyRedirects`) the first time a
        # caller-controlled value echoed into a real `Location:` header
        # resolves to a self-referencing relative reference (e.g. a bare
        # `#...` fragment payload -- unchanged by a redirect, so the same URL
        # is refetched forever). Matches `fuzzlab.core.http`'s authenticated
        # client, which already sets this (see that module's own
        # request-building code) -- this was a real inconsistency between
        # the two `Sender` implementations, not a deliberate difference.
        check_send_url(url, self._explicit)              # NFR-FUZZ-safe (BUG-0112)
        # Anonymous means anonymous: no cookie a probe response set (a payload that
        # logs in, say) rides along on later probes (BUG-0112).
        jar = getattr(self._session, "cookies", None)   # an injected session may have none
        if jar is not None:
            jar.clear()
        kwargs = {"timeout": self._timeout, "allow_redirects": False}
        if entries is not None and location == "body":   # a form point (forms phase 1)
            kwargs["data"] = list(entries)
        elif entries is not None and location == "query":
            url = with_query(url, entries)
        elif location == "header":
            kwargs["headers"] = {param: value}
        elif location == "body" and content_type:
            # Whole-body point at its own declared content type -- never
            # assume JSON for every body point (CC-FUZZ-0032/FR-FUZZ-19). A
            # multipart body may carry genuinely binary content (real image
            # magic bytes) round-tripped as latin-1 -- see the matching
            # comment in `SeamProbeSender.send` above (CC-FUZZ-0040).
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
        manager, client = make_auth(target_url, timeout)
        return SeamProbeSender(client, identity, manager=manager, base_url=target_url)
    return RequestsProbeSender(timeout=timeout)
