"""Probe senders that adapt the tools' HTTP to the oracle's `Sender` interface.

The oracle needs the full response (text + headers + elapsed) to confirm, so these
return a `Probe`. Two flavors: authenticated (via the core seam + session manager)
and standalone (plain requests). Built by `make_probe_sender`.
"""

from __future__ import annotations

import threading
import time

from fuzzlab.core.urls import check_send_url, to_path, url_key
from fuzzlab.oracle.probe import Probe
from fuzzlab.tools.authhttp import with_query, with_query_param


class _ExplicitAllowance:
    """``allow_explicit``: the operator-enumerated (ground-truth) URLs a sender may
    probe even when they look destructive (NFR-FUZZ-safe, CC-FUZZ-0060)."""

    _explicit: frozenset[str] = frozenset()

    def allow_explicit(self, urls) -> None:
        self._explicit = frozenset(self._explicit | {url_key(u) for u in urls if u})


#: The most isolated sessions one run creates (FR-FUZZ-44): bounds extra logins, and
#: with them lockout and rate-limit exposure. Further isolated paths go anonymous.
MAX_ISOLATED_SESSIONS = 32
#: Failed isolated login attempts after which a run creates no more (the breaker).
MAX_FAILED_ISOLATED_LOGINS = 2


class _Copy:
    """One path's isolated session: its manager (a `SessionManager.isolated_copy`) and
    the `HttpClient` built on it."""

    def __init__(self, manager, client):
        self.manager = manager
        self.client = client
        self.label = manager.label


class SeamProbeSender(_ExplicitAllowance):
    """Authenticated: routes through the core HTTP seam + session manager.

    NFR-FUZZ-safe (BUG-0112): a probe to one of the session's auth endpoints (the login
    page and form action) is sent **anonymously**, so it can neither log the run's
    session out nor re-authenticate it. ``manager``/``base_url`` let the sender log in
    once before its first probe, so those endpoints are known.

    NFR-FUZZ-safe (FR-FUZZ-44): the run's session is **never** sent to a path registered
    with `isolate` (a path with an in-app login form). Such a send goes out on that
    path's own isolated session of the same identity — a separate login, verified
    distinct, never persisted, labelled ``<identity>#isolated:<n>`` — or, when none can
    be had (no ``isolated_client`` factory, a failed or non-distinct login, a cap, a
    tripped breaker), anonymously. A probe that re-binds a session server-side can then
    only re-bind the throwaway one.
    """

    def __init__(self, client, identity: str = "anonymous", manager=None,
                 base_url: str | None = None, isolated_client=None):
        self._client = client
        self._identity = identity
        self._manager = manager
        self._base_url = base_url
        self._ensured = False
        self.auth_endpoint_anonymous_sends = 0
        # -- isolation (FR-FUZZ-44) --
        self._isolated_client = isolated_client     # SessionManager -> HttpClient
        self._isolated_keys: frozenset[str] = frozenset()
        # LOCKING (reviewers A/B): a plain Lock, NOT an RLock, and it is NEVER held
        # across a network send, a login or `verify_live` — it guards only the in-memory
        # isolation state below. The main manager's logout listener (`_on_main_logout`)
        # runs inside a main send's `observe` and takes only this lock, briefly, so it
        # can never wait on a send. Copy creation is single-flight per path under a
        # per-path lock that the listener never takes.
        self._iso_lock = threading.Lock()
        self._path_locks: dict[str, threading.Lock] = {}
        self._copies: dict[str, _Copy] = {}          # live copies, by path key
        self._all_copies: list[_Copy] = []           # every copy ever made (counts)
        self._failed: dict[str, str] = {}            # path key -> why it is anonymous
        self._labels: dict[str, str] = {}            # path key -> its copy's label
        self._breaker: dict | None = None
        self._listening = False
        self._verified_first = False
        self._counts = {"sends": 0, "anonymous_sends": 0, "failed_logins": 0,
                        "verifications": 0, "send_ordinal": 0}
        self._first_copy_login_send: int | None = None
        self._run_host: str | None = None

    # -- isolation (FR-FUZZ-44) -------------------------------------------------
    def isolate(self, urls) -> None:
        """Never send the run's session to these paths (``url_key``: origin + path)."""
        keys = {url_key(u) for u in urls if u}
        with self._iso_lock:
            self._isolated_keys = frozenset(self._isolated_keys | keys)

    def isolated_copy_logins(self) -> int:
        """Isolated-copy login attempts so far in this run, successful or not (lane A's
        header breaker reads it: a logout after a copy login is this breaker's case)."""
        with self._iso_lock:
            copies = list(self._all_copies)
        return sum(c.manager.login_attempts() for c in copies)

    def isolation_report(self) -> dict:
        """Counts, the breaker and per-path failures — paths, labels and reasons only,
        never a credential value."""
        logins = self.isolated_copy_logins()
        with self._iso_lock:
            return {
                "paths": len(self._isolated_keys),
                "sessions": len(self._all_copies),
                "logins": logins,
                "verifications": self._counts["verifications"],
                "sends": self._counts["sends"],
                "anonymous_sends": self._counts["anonymous_sends"],
                "failed_logins": self._counts["failed_logins"],
                "first_copy_login_send": self._first_copy_login_send,
                "breaker": dict(self._breaker) if self._breaker else None,
                "failures": [{"path": to_path(k), "label": self._labels.get(k),
                              "reason": r} for k, r in sorted(self._failed.items())],
            }

    def _target_host(self, url: str) -> str:
        """The run's target host: the operator's base URL's, else this URL's."""
        from urllib.parse import urlparse
        return urlparse(self._base_url or url).hostname or ""

    def _listen(self, url: str) -> None:
        """Register the main-logout listener once, before the first copy login starts
        (reviewer B); it stays inert until a copy is live."""
        with self._iso_lock:
            if self._listening or self._manager is None:
                return
            self._listening = True
            self._run_host = self._target_host(url)
        self._manager.add_logout_listener(self._on_main_logout)   # idempotent too

    def _on_main_logout(self, host: str, identity: str) -> None:
        """The run's session was logged out while a copy was live: treat it as a
        single-session app (FR-FUZZ-44). Runs inside the main send that observed it;
        only the run's own identity on the run's target host counts."""
        if identity != self._identity or host != self._run_host:
            return
        with self._iso_lock:
            if not self._copies:
                return                                # inert until a copy is live
            self._trip_single_session_locked(
                "the run's session was logged out while an isolated session was live")

    def _trip_single_session_locked(self, why: str) -> None:
        self._breaker = {"trip": "single-session", "reason": f"single-session app: {why}"}
        for copy in self._copies.values():
            self._manager.release_copy(copy.manager)
        self._copies.clear()

    def _fail_locked(self, key: str, reason: str) -> None:
        self._failed.setdefault(key, reason)

    def _anonymous_locked(self, key: str, reason: str):
        self._fail_locked(key, reason)
        self._counts["anonymous_sends"] += 1
        return self._client, "anonymous", None

    def _route_isolated(self, url: str):
        """``(client, identity, copy)`` for a send to an isolated path: the path's own
        copy, or the main client sent anonymously (``copy`` None)."""
        key = url_key(url)
        self._listen(url)
        with self._iso_lock:
            route = self._existing_route_locked(key)
            if route is not None:
                return route
            path_lock = self._path_locks.setdefault(key, threading.Lock())
        with path_lock:                       # single-flight creation for this path
            with self._iso_lock:
                route = self._existing_route_locked(key)
                if route is not None:
                    return route
                ordinal = len(self._all_copies) + 1
            copy = self._create_copy(key, url, ordinal)
            with self._iso_lock:
                tripped = self._breaker and self._breaker["trip"] == "single-session"
                if copy is not None and not tripped:
                    self._copies[key] = copy
                    self._counts["sends"] += 1
                    return copy.client, copy.label, copy
            if copy is not None:                  # the breaker tripped meanwhile
                self._manager.release_copy(copy.manager)
            with self._iso_lock:
                return self._anonymous_locked(
                    key, self._breaker["reason"] if tripped else
                    self._failed.get(key, "no isolated session"))

    def _existing_route_locked(self, key: str):
        if self._breaker and self._breaker["trip"] == "single-session":
            return self._anonymous_locked(key, self._breaker["reason"])
        copy = self._copies.get(key)
        if copy is not None:
            self._counts["sends"] += 1
            return copy.client, copy.label, copy
        if key in self._failed:
            return self._anonymous_locked(key, self._failed[key])
        if self._isolated_client is None or self._manager is None:
            return self._anonymous_locked(key, "no isolated client")
        if self._breaker:                                       # failed-logins trip
            return self._anonymous_locked(key, self._breaker["reason"])
        if len(self._all_copies) >= MAX_ISOLATED_SESSIONS:
            return self._anonymous_locked(key, "isolated-session cap")
        return None

    def _create_copy(self, key: str, url: str, ordinal: int):
        """Log a new copy in (network; no sender lock held). None when it fails."""
        from urllib.parse import urlparse

        from fuzzlab.session.manager import (IsolatedLoginFailed, LoginCapReached,
                                             _directory)
        manager = self._manager.isolated_copy(self._identity, ordinal=ordinal)
        copy = _Copy(manager, self._isolated_client(manager))
        with self._iso_lock:
            self._all_copies.append(copy)
            self._labels[key] = copy.label
            if self._first_copy_login_send is None:
                self._first_copy_login_send = self._counts["send_ordinal"]
        try:
            if self._base_url:
                manager.ensure(urlparse(self._base_url).hostname or "", self._identity,
                               self._base_url, operator=True)
            else:
                manager.ensure(urlparse(url).hostname or "", self._identity,
                               _directory(url))
        except IsolatedLoginFailed as exc:     # the one class a copy login fails with
            self._manager.release_copy(manager)
            with self._iso_lock:
                self._fail_locked(key, str(exc))
                if not isinstance(exc, LoginCapReached):
                    self._count_failed_login_locked()
            return None
        if not self._verify_main(url, first_only=True):
            self._manager.release_copy(manager)
            return None
        return copy

    def _count_failed_login_locked(self) -> None:
        self._counts["failed_logins"] += 1
        if self._counts["failed_logins"] >= MAX_FAILED_ISOLATED_LOGINS and \
                self._breaker is None:
            self._breaker = {"trip": "failed-logins",
                             "reason": f"isolated logins failed "
                                       f"{self._counts['failed_logins']} times"}

    def _verify_main(self, url: str, *, first_only: bool) -> bool:
        """After a copy login, is the run's session still logged in? (single-session
        apps; reviewer B). Runs after the run's first copy login, and after every copy
        re-login. False trips the breaker."""
        from fuzzlab.session.manager import SessionAuthError, _directory
        with self._iso_lock:
            if first_only and self._verified_first:
                return True
            self._verified_first = True
            self._counts["verifications"] += 1
        base = self._base_url or _directory(url)
        try:
            alive = self._manager.verify_live(self._target_host(url), self._identity, base)
        except SessionAuthError:             # an unapproved hop: cannot verify -> trip
            alive = False
        if not alive:
            with self._iso_lock:
                self._trip_single_session_locked(
                    "the isolated login logged the run's session out")
        return alive

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
        from fuzzlab.session.manager import IsolatedLoginFailed
        check_send_url(url, self._explicit)              # NFR-FUZZ-safe (BUG-0112)
        identity = self._identity_for(url)
        with self._iso_lock:
            self._counts["send_ordinal"] += 1
        client, copy = self._client, None
        if identity != "anonymous" and url_key(url) in self._isolated_keys:
            client, identity, copy = self._route_isolated(url)  # FR-FUZZ-44
        if copy is None:
            return self._send_on(client, identity, url, param, value, timing, method,
                                 location, content_type, entries)
        before = copy.manager.login_attempts()
        try:
            probe = self._send_on(client, identity, url, param, value, timing, method,
                                  location, content_type, entries)
        except IsolatedLoginFailed as exc:   # the copy could not re-log in: anonymous
            from fuzzlab.session.manager import LoginCapReached
            key = url_key(url)
            self._manager.release_copy(copy.manager)
            with self._iso_lock:
                self._copies.pop(key, None)
                self._fail_locked(key, str(exc))
                if not isinstance(exc, LoginCapReached):
                    self._count_failed_login_locked()
                self._counts["anonymous_sends"] += 1
            return self._send_on(self._client, "anonymous", url, param, value, timing,
                                 method, location, content_type, entries)
        if copy.manager.login_attempts() > before:     # the copy re-logged in
            self._verify_main(url, first_only=False)
        return probe

    def _send_on(self, client, identity, url, param, value, timing, method, location,
                 content_type, entries) -> Probe:
        from urllib.parse import urlencode

        from fuzzlab.core.http import Request
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
        r = client.send(req)
        return Probe(status=r.status, text=r.body.decode("utf-8", "replace"),
                     elapsed=r.elapsed_ms / 1000.0, headers=dict(r.headers))


class RequestsProbeSender(_ExplicitAllowance):
    """Standalone: plain requests, no auth (unauthenticated confirmation).

    Isolated by construction (FR-FUZZ-44): it has no session and clears its jar before
    every send, so `isolate` only counts; nothing can re-bind a run's session."""

    def isolate(self, urls) -> None:
        self._isolated_keys = frozenset(self._isolated_keys | {url_key(u) for u in urls
                                                              if u})

    def isolated_copy_logins(self) -> int:
        return 0

    def isolation_report(self) -> dict:
        return {"paths": len(self._isolated_keys), "sessions": 0, "logins": 0,
                "verifications": 0, "sends": 0,
                "anonymous_sends": self._isolated_sends, "failed_logins": 0,
                "first_copy_login_send": None, "breaker": None, "failures": []}

    def __init__(self, session=None, timeout: float = 15.0):
        import requests
        self._isolated_keys: frozenset[str] = frozenset()
        self._isolated_sends = 0
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
        if url_key(url) in self._isolated_keys:
            self._isolated_sends += 1
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
        from fuzzlab.tools.authhttp import make_auth_with_isolation
        manager, client, isolated_client = make_auth_with_isolation(target_url, timeout)
        return SeamProbeSender(client, identity, manager=manager, base_url=target_url,
                               isolated_client=isolated_client)
    return RequestsProbeSender(timeout=timeout)
