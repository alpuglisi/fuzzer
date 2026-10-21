"""Probe senders that adapt the tools' HTTP to the oracle's `Sender` interface.

The oracle needs the full response (text + headers + elapsed) to confirm, so these
return a `Probe`. Two flavors: authenticated (via the core seam + session manager)
and standalone (plain requests). Built by `make_probe_sender`.
"""

from __future__ import annotations

import functools
import sys
import threading
import time
import types

from fuzzlab.core.http import check_send_header
from fuzzlab.core.jsonbody import ENCTYPE as JSON_ENCTYPE
from fuzzlab.core.jsonbody import LOCATION as JSON_LOCATION
from fuzzlab.core.jsonbody import JsonPlacementError, body_for
from fuzzlab.core.urls import (DestructiveUrlRefused, PathPlacementError, bind_query,
                               canonical_origin, check_send_url, path_placeholder,
                               place_path_param, place_query_param, to_path,
                               transaction_reason, url_key)
from fuzzlab.oracle.probe import (PRG_ANY_METHOD, PRG_GET_ONLY, PRG_OBSERVED,
                                  PRG_UNOBSERVED, REDIRECT_STATUSES, HeaderPointsStopped,
                                  Probe, ProbeUnobserved, UnplaceableLocation,
                                  attempt_record, note_attempts)

#: A path-segment point's location (FR-FUZZ-57): ``param`` names the URL template's
#: ``{param}`` segment.
PATH_LOCATION = "path"


def _json_body(param: str, value: str, entries, content_type=None) -> bytes:
    """A ``json`` send's body (`core.jsonbody.body_for`), or `UnplaceableLocation` when
    the leaf cannot be placed -- or when the send is a raw whole body (``content_type``
    set: XML, multipart), which a JSON leaf cannot carry: refused before any session
    routing or send, never reinterpreted (PA-0115)."""
    if content_type:
        raise UnplaceableLocation(f"a raw {content_type} body cannot be a JSON leaf")
    try:
        return body_for(param, value, entries)
    except JsonPlacementError as exc:
        raise UnplaceableLocation(f"cannot place JSON leaf {param!r}: {exc}") from exc


def _path_url(url: str, param: str, value: str) -> str:
    """A ``path`` send's URL (`core.urls.place_path_param`), or `UnplaceableLocation`
    when its template does not hold the parameter as one segment (PA-0115)."""
    try:
        return place_path_param(url, param, value)
    except PathPlacementError as exc:
        raise UnplaceableLocation(f"cannot place path parameter {param!r}: {exc}") from exc


def _skipped(reason: str) -> str:
    return f"skipped: {reason}"


def _own_segment(location: str, param: str) -> str | None:
    """A path point's own segment in its template (``{param}``, FR-FUZZ-57), which a PRG
    follow-up's target must not keep (FR-FUZZ-69); None for every other location."""
    return path_placeholder(param) if location == PATH_LOCATION else None


def _placed_value(location: str, value) -> str | None:
    """A path point's placed value (FR-FUZZ-57), which a PRG follow-up's target must not
    hold however the server wrote it (FR-FUZZ-69); None for every other location."""
    return str(value) if location == PATH_LOCATION else None


def _re_sends(path: str, own_segment: str | None, own_value: str | None) -> bool:
    """Whether a path point's follow-up target (its ``path``) would re-send the payload
    (FR-FUZZ-69): it keeps the point's own segment (a ``Location`` resolved against the
    template: ``#top``, ``edit``), or it holds the placed value as whole segments,
    however the server wrote it (``/p/<payload>/edit``, an absolute path or URL built
    from the request). The value is compared as written and percent-decoded, so a
    server that re-encodes it (``%2A`` for ``*``, or the reverse) is still caught, and a
    value with a ``/`` the server wrote raw spans its segments."""
    from urllib.parse import unquote
    if own_segment is not None and own_segment in path.split("/"):
        return True
    return bool(own_value) and any(f"/{own_value}/" in f"/{spelled}/"
                                   for spelled in (path, unquote(path)))


#: The browser redirect behaviour a PRG follow-up emulates (FR-FUZZ-49), rule by rule
#: (PA-0111), each with the spec step it follows or the deliberate divergence it is.
#: Fetch = WHATWG Fetch, "HTTP-redirect fetch"; every rule has a fixture in
#: ``tests/test_prg_observation.py`` (a guard fails on one without).
PRG_RULES: dict[str, str] = {
    "303-becomes-get": "Fetch HTTP-redirect fetch step 12 (RFC 9110 §15.4.4): a 303 "
                       "after a non-GET/HEAD request is followed with GET and no body",
    "301-302-post-becomes-get": "Fetch step 12 (RFC 9110 §15.4.2/§15.4.3 note): a 301 "
                                "or 302 after POST is followed with GET and no body",
    "get-redirect-stays-get": "Fetch step 12: a redirect after GET is followed with GET",
    "307-308-keep-the-body": "RFC 9110 §15.4.8/§15.4.9 (Fetch step 12 does not apply): "
                             "a 307/308 re-sends the method and body, so it is followed "
                             "only after a GET; after any other method it is never "
                             "followed (no probe body is re-sent)",
    "location-relative": "Fetch 'location URL' step 3: Location is parsed relative to "
                         "the request's URL -- divergence for a point whose payload is "
                         "in its URL: the probe's own URL, never the placed one (a "
                         "query point's URL without the payload, FR-FUZZ-64; a path "
                         "point's template, FR-FUZZ-69)",
    "location-fragment-not-sent": "Fetch 'location URL' step 4 / URL serializer with "
                                  "exclude-fragment: a fragment is never sent",
    "no-location-no-redirect": "Fetch 'location URL' step 2: a redirect status without "
                               "Location is the final response (no observation)",
    "no-body-no-payload": "Fetch step 12: the request body and its body headers are "
                          "removed; the follow-up carries no payload parameter either",
    "own-segment-never-refetched": "divergence (a browser fetches the Location resolved "
                                   "against the placed URL): a path point's target that "
                                   "keeps the point's own segment (#top, a relative "
                                   "path or query) or holds the placed value however "
                                   "the server wrote it (an absolute path or URL) "
                                   "would carry the payload again, never the page the "
                                   "probe led to; it is refused, nothing is sent "
                                   "(FR-FUZZ-69, BUG-0542)",
    "one-hop": "divergence (Fetch step 5 allows 20 redirects): one hop; a redirect in "
               "the follow-up's response is no observation",
    "same-origin-only": "divergence (a browser follows any origin): only the probed "
                        "URL's own origin, through every send gate",
    "no-response-cookie-adopted": "divergence (a browser stores a 3xx's Set-Cookie "
                                  "before following): the follow-up carries the route's "
                                  "own session state only, as every probe does (the "
                                  "seam adopts no response cookie; anonymous stays "
                                  "anonymous, BUG-0112)",
}


def prg_target(probe: Probe, url: str, method: str,
               explicit: frozenset[str] = frozenset(),
               own_segment: str | None = None,
               own_value: str | None = None) -> tuple[str | None, str | None]:
    """The PRG follow-up a probe's response calls for (FR-FUZZ-49): ``(target, None)``
    to follow, ``(None, None)`` when the response is not a PRG redirect at all, or
    ``(None, "skipped: <reason>")`` when it is one but a gate refuses the target. The
    one rule both probe senders apply (PA-0003); each adds its own session gates
    (auth endpoints, isolation, the header breaker).

    ``url`` is the probe's **own** URL, never the placed one (FR-FUZZ-64, FR-FUZZ-69):
    the URL itself for a body, header or JSON point, a query point's URL without its
    payload, a path point's template. ``own_segment`` is a path point's ``{param}``
    (`_own_segment`), ``own_value`` the value placed in it (`_placed_value`).

    A PRG redirect is `PRG_ANY_METHOD` after any method, or `PRG_GET_ONLY` after a GET
    only. Its target (``Location`` resolved against ``url``, fragment dropped) must not
    re-send a path point's payload (`_re_sends`): neither keep ``own_segment``
    (``#top``, ``edit``, ``?tab=2``) nor hold ``own_value`` as whole segments, however
    the server wrote it (``/p/<payload>/edit``, an absolute path or URL). Both name the
    resource the payload is in -- ``edit`` and ``/p/<payload>/edit`` are one browser
    request -- whose answer is never the page the probe's own request led to (a page
    that renders its own URL would read as the probe's stored result), and no
    payload-free URL names it: refused (``"skipped: the follow-up would re-send the
    payload"``), never sent (PA-0115(1)). The target must be the probed URL's own
    origin (`canonical_origin`), pass `check_send_url` as a GET, and be neither a
    transaction (`transaction_reason`), an account endpoint (`account_endpoint_reason`)
    nor a login page (`redirect_is_logout`, BUG-0122; that redirect is the session's own
    logout handling)."""
    from urllib.parse import urldefrag, urljoin, urlsplit

    from fuzzlab.session.browserlogin import account_endpoint_reason
    from fuzzlab.session.detect import redirect_is_logout
    status = probe.status
    if status not in REDIRECT_STATUSES:
        return None, None
    if status not in PRG_ANY_METHOD:
        if not (status in PRG_GET_ONLY and method.upper() == "GET"):
            return None, _skipped(f"a {status} after {method.upper()} re-sends its body")
    location = next((v for k, v in (probe.headers or {}).items()
                     if k.lower() == "location"), "").strip()
    if not location:
        return None, _skipped("no Location")
    try:
        target = urldefrag(urljoin(url, location))[0]
        keeps = _re_sends(urlsplit(target).path, own_segment, own_value)
    except ValueError:
        return None, _skipped("unparsable Location")
    if keeps:                                    # FR-FUZZ-69 (BUG-0542)
        return None, _skipped("the follow-up would re-send the payload")
    origin = canonical_origin(target)
    if origin is None or origin != canonical_origin(url) or \
            not target.lower().startswith(("http://", "https://")):
        return None, _skipped("another origin")
    try:
        check_send_url(target, explicit, method="GET")
    except DestructiveUrlRefused:
        return None, _skipped("destructive target")
    if transaction_reason(target) is not None:
        return None, _skipped("transaction target")
    if account_endpoint_reason(target) is not None:
        return None, _skipped("account target")
    if redirect_is_logout(location, url, None):
        return None, _skipped("login page")
    return target, None


def _observation(followed: Probe, target: str) -> tuple[Probe | None, str]:
    """A sent follow-up's outcome: itself (its ``url`` set), or no observation when it
    was answered with another redirect (one hop only)."""
    if followed.status in REDIRECT_STATUSES:
        return None, PRG_UNOBSERVED
    followed.url = target
    return followed, PRG_OBSERVED


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


def _chain(exc: BaseException) -> list[BaseException]:
    """``exc`` and what it wraps: ``__cause__``, ``__context__`` and exception
    arguments (``requests`` puts the urllib3 error in ``args``, urllib3 its cause)."""
    out: list[BaseException] = []
    todo = [exc]
    while todo and len(out) < 12:
        e = todo.pop(0)
        if any(e is seen for seen in out):
            continue
        out.append(e)
        todo += [a for a in (e.__cause__, e.__context__, *getattr(e, "args", ()))
                 if isinstance(a, BaseException)]
    return out


def _is_timeout(exc: BaseException) -> bool:
    """A timeout, including one while reading the body (``requests`` reports that as
    a ``ConnectionError`` wrapping urllib3's ``ReadTimeoutError``). urllib3's
    ``NewConnectionError`` (refused, unreachable) subclasses its connect-timeout error
    but is not a timeout."""
    import requests
    from urllib3.exceptions import NewConnectionError
    from urllib3.exceptions import TimeoutError as Urllib3Timeout
    chain = _chain(exc)
    if any(isinstance(e, NewConnectionError) for e in chain):
        return False
    return any(isinstance(e, (requests.Timeout, Urllib3Timeout, TimeoutError)) for e in chain)


def _is_connect_timeout(exc: BaseException) -> bool:
    """A timeout before the request was sent (connect), which proves nothing about
    the server's latency (M7). urllib3's NewConnectionError is not one."""
    import requests
    from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
    chain = _chain(exc)
    if any(isinstance(e, NewConnectionError) for e in chain):
        return False
    return any(isinstance(e, (requests.ConnectTimeout, ConnectTimeoutError))
               for e in chain)


def _unobserved(exc: BaseException) -> ProbeUnobserved | None:
    """``ProbeUnobserved`` when a sent probe got no complete response (BUG-0147): the
    connection was reset or aborted, or the body was cut off or undecodable, or the
    bounded reader stopped it (`core.bodyread.BodyIncomplete`: over a ceiling, past its
    deadline, an unbounded coding; SP-60, BUG-0536 -- never re-sent, and never latency
    evidence: a body that kept arriving proves no delay). Else None, and the caller
    re-raises the original:
    - a timeout is not one (each sender has its own rule for it, `_is_timeout`);
    - a target that cannot be reached at all (refused, DNS, TLS, proxy) is not one: it
      fails loudly, so a dead target never turns every candidate inconclusive.
    The message names the error classes only, never the payload or URL."""
    import requests
    from urllib3.exceptions import NewConnectionError, ProxyError, SSLError

    from fuzzlab.core.bodyread import BodyIncomplete
    if isinstance(exc, BodyIncomplete):
        return ProbeUnobserved(f"no complete response: incomplete body ({exc.reason})")
    if not isinstance(exc, (requests.ConnectionError, requests.exceptions.ChunkedEncodingError,
                            requests.exceptions.ContentDecodingError)) or _is_timeout(exc):
        return None
    chain = _chain(exc)
    if any(isinstance(e, (NewConnectionError, ProxyError, SSLError, requests.exceptions.SSLError,
                          requests.exceptions.ProxyError, ConnectionRefusedError))
           for e in chain):
        return None
    root = next((e for e in reversed(chain)
                 if not type(e).__module__.startswith(("requests", "urllib3"))), exc)
    cause = type(root).__name__ if type(root).__module__ == "builtins" or \
        type(root).__module__ == "http.client" else \
        f"{type(root).__module__}.{type(root).__name__}"
    return ProbeUnobserved(f"no response: {type(exc).__name__} ({cause})")


# -- each try as evidence (FR-FUZZ-61) ------------------------------------------------
def _failed_try(exc: BaseException) -> str | None:
    """A try that failed with ``exc``: its `ATTEMPT_OUTCOMES` value, or None when the
    request never left the client (``requests`` refused to build it: an invalid URL
    or header value)."""
    import requests
    if _is_timeout(exc):
        return "timeout"
    if _unobserved(exc) is not None:
        return "unobserved"
    if isinstance(exc, requests.ConnectionError):   # refused, DNS, TLS, proxy
        return "error"
    return None


@functools.cache
def _transport_code() -> types.CodeType | None:
    """The code of `core.http.HttpClient.send`'s transport step (``_do``): the one
    place the seam's request goes to the network."""
    from fuzzlab.core.http import HttpClient
    return next((c for c in HttpClient.send.__code__.co_consts
                 if isinstance(c, types.CodeType) and c.co_name == "_do"), None)


def _reached_transport(exc: BaseException, caller) -> bool:
    """Did ``exc`` come out of the seam's transport step, in the send ``caller`` (the
    sender's own frame) made? `HttpClient.send` also runs the session's ``prepare`` -- a
    login on the probe's way, with its own fetcher -- before it; an error there means
    the probe itself never went out. Read from the exception's own traceback, so
    nothing about the send changes. A transport frame counts only when it was called
    from ``caller``: an exception instance raised again keeps the frames of its earlier
    raise."""
    code = _transport_code()
    tb = exc.__traceback__
    while tb is not None and code is not None:
        frame = tb.tb_frame
        if frame.f_code is code:
            back = frame.f_back
            for _hop in range(4):           # _do <- HttpClient.send <- caller
                if back is None:
                    break
                if back is caller:
                    return True
                back = back.f_back
        tb = tb.tb_next
    return False


def _follow_up_record(target: str, outcome: str, attempts, *, status: int | None = None,
                      elapsed: float = 0.0, error: str | None = None) -> dict:
    """`Probe.prg_sent`: the PRG follow-up a sender sent, observed or not (BUG-0510)."""
    return {"url": target, "outcome": outcome, "status": status,
            "elapsed_ms": round(elapsed * 1000, 1), "error": error,
            "attempts": list(attempts)}


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

    **Header breaker** (forms phase 2, FR-FUZZ-43). An app that binds its session to a
    request header (User-Agent, say) logs the session out when a header probe changes
    it. The sender listens to its main manager's logouts (``add_logout_listener``,
    FR-SESS-16): a logout seen on a header probe's response, or on the first main send
    after one, stops every later header probe of the run (`HeaderPointsStopped`, raised
    before the send). The next main send re-logs in once, and no header probe ever
    rides on that session. Sends are sequential (the pipeline confirms on one thread),
    so "the previous main send" is well defined. A logout that follows an isolated copy
    login (lane B's per-path session copies, `isolated_copy_logins`) is not
    attributed to the header probe; that sender's own breaker owns it.
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
        self._run_url: str | None = None

        # -- header breaker (FR-FUZZ-43) --
        self.header_stop_reason: str | None = None
        self._current: tuple[str, str, str] | None = None   # (location, param, url)
        self._last_main_was_header: tuple[str, str] | None = None   # (param, url)
        self._copies_at_header = 0
        add = getattr(manager, "add_logout_listener", None)
        if add is not None and identity != "anonymous":
            add(self._on_logout)


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

    @property
    def session_out_of_origin(self) -> int:
        """Sends made without the session because their origin is not one of its
        origins (FR-SESS-20): the run's manager's and every isolated copy's."""
        with self._iso_lock:
            copies = list(self._all_copies)
        managers = ([self._manager] if self._manager is not None else []) + \
            [c.manager for c in copies]
        return sum(int(getattr(m, "out_of_origin_sends", 0) or 0) for m in managers)

    def _target_host(self, url: str) -> str:
        """The run's target host: the operator's base URL's, else this URL's."""
        from urllib.parse import urlparse
        return urlparse(self._base_url or url).hostname or ""

    def _run_origins(self, target_url: str | None) -> frozenset[str]:
        """The origins of the run's session for ``target_url`` (the operator's base, else
        the probed URL): what a logout's origin is compared with (FR-SESS-20, O9), never
        a host. Before any session exists, the target's own origin."""
        from fuzzlab.core.urls import origin_scope
        if not target_url:
            return frozenset()
        found = self._manager.session_origins_for(target_url, self._identity) \
            if self._manager is not None else frozenset()
        return found or origin_scope(target_url)

    def _listen(self, url: str) -> None:
        """Register the main-logout listener once, before the first copy login starts
        (reviewer B); it stays inert until a copy is live."""
        with self._iso_lock:
            if self._listening or self._manager is None:
                return
            self._listening = True
            self._run_url = self._base_url or url
        self._manager.add_logout_listener(self._on_main_logout)   # idempotent too

    def _on_main_logout(self, origin: str, identity: str) -> None:
        """The run's session was logged out while a copy was live: treat it as a
        single-session app (FR-FUZZ-44). Runs inside the main send that observed it;
        only the run's own identity on one of the run's session's origins counts
        (FR-SESS-20: another port of the same host is another app)."""
        if identity != self._identity or origin not in self._run_origins(self._run_url):
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
                self._fail_locked(key, exc.reason)   # fixed text, never a URL
                if not isinstance(exc, LoginCapReached):
                    self._count_failed_login_locked()
            return None
        except Exception as exc:
            if _unobserved(exc) is None:
                raise
            # its login got no response (BUG-0147): a failed login, never a half-made
            # copy; the path's probes go anonymous, as after any failed copy login
            self._manager.release_copy(manager)
            with self._iso_lock:
                self._fail_locked(key, "isolated login got no response")
                self._count_failed_login_locked()
            return None
        try:
            verified = self._verify_main(url, first_only=True)
        except Exception as exc:
            if _unobserved(exc) is not None:   # unverified: never kept (BUG-0147)
                self._manager.release_copy(manager)
            raise
        if not verified:
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
        except Exception as exc:
            if _unobserved(exc) is not None and first_only:
                with self._iso_lock:         # no response: checked again next time
                    self._verified_first = False
            raise
        if not alive:
            with self._iso_lock:
                self._trip_single_session_locked(
                    "the isolated login logged the run's session out")
        return alive

    def _copy_logins(self) -> int:
        # isolated-copy login attempts so far (FR-FUZZ-44), never this run's own logins
        return self.isolated_copy_logins()

    def _header_target_url(self) -> str | None:
        """The run's target: the operator's base URL, else the URL of the main send in
        progress or last made."""
        if self._base_url:
            return self._base_url
        for seen in (self._current, self._last_main_was_header):
            if seen is not None:
                return seen[-1]
        return None

    def _on_logout(self, origin: str, identity: str) -> None:
        """Told by the main manager inside the send that observed a logout. Records
        only; never raises, so that probe's response is kept. Only a logout on one of
        the run's session's origins counts (FR-SESS-20, O9; never a host compare)."""
        if self.header_stop_reason is not None or identity != self._identity:
            return
        from urllib.parse import urlsplit
        if origin not in self._run_origins(self._header_target_url()):
            return                                   # not the run's target (reviewers)
        current = self._current
        if current is not None and current[0] == "header":
            culprit = (current[1], current[2])
        elif self._last_main_was_header is not None:
            culprit = self._last_main_was_header
        else:
            return                                   # not after a header probe
        if self._copy_logins() > self._copies_at_header:
            return                                   # an isolated copy login since then
        self.header_stop_reason = (f"session bound to a probed header ({culprit[0]} on "
                                   f"{urlsplit(culprit[1]).path or '/'})")

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

    #: Makes PRG follow-ups (FR-FUZZ-49).
    prg_capable = True

    def send(self, url: str, param: str, value: str, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False) -> Probe:
        """A probe. Every gate runs first; then the session's own network calls on its
        way (a first login, an isolated copy's login, a liveness check) map a transport
        failure the same way as the probe's send (BUG-0147)."""
        # every gate before any routing: a stopped or refused header probe never causes
        # an isolated copy login (reviewers A/B, forms phase 2 merge)
        if location == "header" and self.header_stop_reason is not None:
            raise HeaderPointsStopped(self.header_stop_reason)
        # NFR-FUZZ-safe (BUG-0112); a crawl-sourced DELETE too (FR-FUZZ-47). A path
        # point is judged on its template, never on the payload in its segment
        check_send_url(url, self._explicit, method=method)
        own = url              # what a PRG follow-up is resolved against (FR-FUZZ-69)
        if location == PATH_LOCATION:                    # placed here, or refused
            url = _path_url(url, param, value)
        if location == JSON_LOCATION:                    # placeable, or refused here
            _json_body(param, value, entries, content_type)
        if location == "header":
            check_send_header(param, url, self._explicit)   # FR-FUZZ-43 (PA-0083(1))
        try:
            return self._send(url, param, value, timing, method, location, content_type,
                              entries, prg, own)
        except Exception as exc:
            unobserved = _unobserved(exc)
            if unobserved is None:
                raise
            raise unobserved from exc

    def _send(self, url, param, value, timing, method, location, content_type, entries,
              prg, own) -> Probe:
        """The probe's routing and network, after `send`'s gates. ``own`` is the probe's
        own URL (a path point's template), which a PRG follow-up is resolved against."""
        identity = self._identity_for(url)
        with self._iso_lock:
            self._counts["send_ordinal"] += 1
        client, copy = self._client, None
        if identity != "anonymous" and url_key(url) in self._isolated_keys:
            client, identity, copy = self._route_isolated(url)  # FR-FUZZ-44

        def send_on(on_client, on_identity):
            return self._send_on(on_client, on_identity, url, param, value, timing,
                                 method, location, content_type, entries)
        if copy is None:
            probe = send_on(client, identity)
        else:
            probe = self._on_copy(copy, url, send_on)
            if probe is None:                  # the copy could not re-log in: anonymous
                with self._iso_lock:
                    self._counts["anonymous_sends"] += 1
                client, identity, copy = self._client, "anonymous", None
                probe = send_on(client, identity)
        if prg and not timing:                 # FR-FUZZ-49; a timing send never follows
            self._follow(probe, client, identity, copy, url, param, value, method,
                         location, own)
        return probe

    def _on_copy(self, copy, url, send_on):
        """``send_on(client, label)`` on ``copy`` (the isolated session of ``url``'s
        path), or None when the copy could not re-log in: it is then released and the
        path's later sends go anonymous (FR-FUZZ-44). A re-login is verified."""
        from fuzzlab.session.manager import IsolatedLoginFailed, LoginCapReached
        before = copy.manager.login_attempts()
        try:
            probe = send_on(copy.client, copy.label)
        except ProbeUnobserved:
            if copy.manager.login_attempts() > before:   # the copy re-logged in first
                self._verify_main(url, first_only=False)
            raise
        except IsolatedLoginFailed as exc:
            key = url_key(url)
            self._manager.release_copy(copy.manager)
            with self._iso_lock:
                self._copies.pop(key, None)
                self._fail_locked(key, exc.reason)   # fixed text, never a URL
                if not isinstance(exc, LoginCapReached):
                    self._count_failed_login_locked()
            return None
        if copy.manager.login_attempts() > before:     # the copy re-logged in
            self._verify_main(url, first_only=False)
        return probe

    # -- post/redirect/get observation (FR-FUZZ-49) -------------------------------
    def _prg_session_gate(self, target: str, identity: str, copy,
                          location: str) -> str | None:
        """This sender's own gates on a follow-up target, after `prg_target`'s: never
        an auth endpoint, never once the header breaker stopped a header probe's run,
        and never an isolated path from the run's session (FR-FUZZ-44)."""
        if self._manager is not None and self._manager.is_auth_endpoint(target):
            return _skipped("auth endpoint")
        if location == "header" and self.header_stop_reason is not None:
            return _skipped("header breaker")
        if copy is None and identity != "anonymous" and \
                url_key(target) in self._isolated_keys:
            return _skipped("isolated path")
        return None

    def _follow(self, probe: Probe, client, identity: str, copy, url: str, param: str,
                value, method: str, location: str, own: str) -> None:
        """One plain GET of the probe's PRG target, on the probe's own route (the run's
        session, the path's isolated copy, or anonymous), through the client (budget,
        scope, session observe) and the header breaker as part of the probe; attached
        as ``probe.followed`` (FR-FUZZ-49, P3/P4). The target is resolved against
        ``own``, the probe's own URL; ``url`` (the request it sent) routes and
        attributes it, as it did the probe; a path point's ``value`` is never re-sent
        (FR-FUZZ-69)."""
        from fuzzlab.core.http import Request
        target, why = prg_target(probe, own, method, self._explicit,
                                 _own_segment(location, param),
                                 _placed_value(location, value))
        if target is not None:
            why = self._prg_session_gate(target, identity, copy, location)
        if target is None or why is not None:
            probe.prg = why
            return

        def dispatch(on_client, on_identity):
            req = Request("GET", target, identity=on_identity, component="oracle")
            return self._dispatch(on_client, on_identity, req, location, param, url)
        try:
            if copy is None:
                followed = dispatch(client, identity)
            else:
                followed = self._on_copy(copy, url, dispatch)
                if followed is None:
                    probe.prg = _skipped("isolated session lost")
                    return
        except ProbeUnobserved as exc:         # the follow-up got no response (BUG-0147)
            probe.prg = PRG_UNOBSERVED
            if exc.attempts:                   # it went out (not a login on its way)
                probe.prg_sent = _follow_up_record(
                    target, "unobserved", exc.attempts,
                    error=type(exc.__cause__ or exc).__name__)
            return
        probe.prg_sent = _follow_up_record(target, "response", followed.attempts,
                                           status=followed.status,
                                           elapsed=followed.elapsed)
        probe.followed, probe.prg = _observation(followed, target)

    def _send_on(self, client, identity, url, param, value, timing, method, location,
                 content_type, entries) -> Probe:
        from urllib.parse import urlencode

        from fuzzlab.core.http import Request
        if location == JSON_LOCATION:
            # one leaf of a JSON body (forms phase 3, FR-CORE-36): the whole body
            # rebuilt from its entries, types kept, the leaf set to the payload string
            req = Request(method.upper(), url, headers={"Content-Type": JSON_ENCTYPE},
                          body=_json_body(param, value, entries, content_type),
                          identity=identity,
                          timing=timing, component="oracle")
        elif entries is not None and location in ("query", "body"):
            # a form point: the whole entry list, the fuzzed field already set
            req = (Request(method.upper(), url,
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           body=urlencode(list(entries)).encode(), identity=identity,
                           timing=timing, component="oracle")
                   if location == "body" else       # the bound rule (FR-FUZZ-64, SP-42)
                   Request(method.upper(), bind_query(url, entries, param, value),
                           identity=identity, timing=timing, component="oracle"))
        elif location == "header":
            req = Request(method.upper(), url, headers={param: value},
                          identity=identity, timing=timing, component="oracle")
        elif location == PATH_LOCATION:                  # already placed by `send`
            req = Request(method.upper(), url, identity=identity, timing=timing,
                          component="oracle")
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
            # the standalone rule (FR-FUZZ-64, SP-42): the URL's own query, the first
            # occurrence in place. Also an unknown location such as `fragment` (BUG-0115
            # instance 4, pinned by a strict xfail, unchanged here)
            req = Request(method.upper(), place_query_param(url, param, value),
                          identity=identity, timing=timing, component="oracle")
        return self._dispatch(client, identity, req, location, param, url)

    def _dispatch(self, client, identity, req, location, param, url) -> Probe:
        """Send ``req`` for the probe of ``(location, param, url)``: the header
        breaker's bookkeeping attributes what it observes to that probe (a PRG
        follow-up is part of its probe, FR-FUZZ-49).

        The seam makes one try per dispatch (it never re-sends: each request has a
        fresh connection, BUG-0147). That try is recorded (FR-FUZZ-61) when it reached
        the transport: an error in the session's ``prepare`` (a login on the way) is no
        try of this request."""
        main = identity != "anonymous" and identity == self._identity
        if main and location == "header":
            self._copies_at_header = self._copy_logins()
        self._current = (location, param, url) if main else None
        start = time.perf_counter()
        try:
            r = client.send(req)
        except Exception as exc:
            reached = _reached_transport(exc, sys._getframe())
            outcome = _failed_try(exc) if reached else None
            tries = [attempt_record(1, outcome, elapsed=time.perf_counter() - start,
                                    error=type(exc).__name__)] if outcome else []
            unobserved = _unobserved(exc)       # a timeout still raises, as before
            if unobserved is None:
                note_attempts(exc, tries)
                raise
            unobserved.attempts = tries
            raise unobserved from exc           # no response: no verdict, the run goes on
        finally:
            self._current = None
            if main:     # sent, answered or not: a later logout is blamed on it
                self._last_main_was_header = (param, url) if location == "header" else None
        return Probe(status=r.status, text=r.body.decode("utf-8", "replace"),
                     elapsed=r.elapsed_ms / 1000.0, headers=dict(r.headers),
                     session=self._session_note(req),
                     credentialed=identity != "anonymous" and self._session_note(req) is None,
                     attempts=[attempt_record(1, "response", status=r.status,
                                              elapsed=r.elapsed_ms / 1000.0)],
                     # FR-FUZZ-65: what `prepare` recorded on this request, read, never
                     # recomputed (core.http.Request's field, CC-CORE-0070)
                     session_lost=getattr(req, "session_lost", False) is True)

    @staticmethod
    def _session_note(req) -> str | None:
        """What the session manager's `prepare` recorded on this request (FR-SESS-20,
        R6): ``"anonymous (out of origin)"`` when it withheld the run's (or the copy's)
        session because the URL is on another origin; else None. Read, never
        recomputed."""
        note = req.session_decision         # core.http.Request's field (CC-CORE-0054)
        return note if isinstance(note, str) else None


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
            from fuzzlab.core import bodyread
            from fuzzlab.core.http import DEFAULT_BROWSER_HEADERS
            # every body read bounded (SP-60, BUG-0536): an incomplete one raises
            # `BodyIncomplete`, which `_unobserved` makes "not observed"
            session = bodyread.bound(requests.Session())
            session.headers.update(DEFAULT_BROWSER_HEADERS)
        self._session = session
        self._timeout = timeout

    #: Makes PRG follow-ups (FR-FUZZ-49), anonymously like every send.
    prg_capable = True

    def send(self, url: str, param: str, value: str, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False) -> Probe:
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
        # NFR-FUZZ-safe (BUG-0112); a crawl-sourced DELETE too (FR-FUZZ-47)
        check_send_url(url, self._explicit, method=method)
        own = url              # what a PRG follow-up is resolved against (FR-FUZZ-69)
        if location == PATH_LOCATION:                    # FR-FUZZ-57: placed, or refused
            url = _path_url(url, param, value)
        body = (_json_body(param, value, entries, content_type)
                if location == JSON_LOCATION else None)
        if url_key(url) in self._isolated_keys:
            self._isolated_sends += 1
        # Anonymous means anonymous: no cookie a probe response set (a payload that
        # logs in, say) rides along on later probes (BUG-0112).
        jar = getattr(self._session, "cookies", None)   # an injected session may have none
        if jar is not None:
            jar.clear()
        kwargs = {"timeout": self._timeout, "allow_redirects": False}
        # where the request goes; a PRG follow-up is resolved against `own`, the
        # probe's own URL, never the placed one (FR-FUZZ-49, FR-FUZZ-64, FR-FUZZ-69)
        wire = url
        if body is not None:                             # a JSON leaf (FR-CORE-36)
            kwargs["data"] = body
            kwargs["headers"] = {"Content-Type": JSON_ENCTYPE}
        elif entries is not None and location == "body":   # a form point (forms phase 1)
            kwargs["data"] = list(entries)
        elif entries is not None and location == "query":
            wire = bind_query(url, entries, param, value)    # the bound rule (SP-42)
        elif location == "header":
            check_send_header(param, url, self._explicit)   # FR-FUZZ-43 (PA-0083(1))
            kwargs["headers"] = {param: value}
        elif location == PATH_LOCATION:
            pass                                     # the value is in the URL already
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
            # the standalone rule (SP-42): the first occurrence in place. Also an unknown
            # location such as `fragment` (BUG-0115 instance 4, pinned, unchanged here)
            wire = place_query_param(url, param, value)
        probe = self._request(method.upper(), wire, kwargs)
        if prg and not timing:                 # FR-FUZZ-49; a timing send never follows
            self._follow(probe, own, method, _own_segment(location, param),
                         _placed_value(location, value))
        return probe

    #: Methods re-sent once after a connection failed with no response (RFC 9110
    #: 9.2.2: idempotent): the pooled connection may have been closing (BUG-0147); the
    #: retry opens a fresh one. A cut-off or undecodable body is never re-sent: the
    #: server had already answered.
    RETRY_ON_RESET = frozenset({"GET", "HEAD", "OPTIONS"})

    def _request(self, method: str, url: str, kwargs: dict) -> Probe:
        """Each try is recorded where it happens (FR-FUZZ-61): ``tries`` gains one
        `attempt_record` per request that went out, the failing one before a re-send
        included, and travels on the outcome (`Probe.attempts`,
        `ProbeUnobserved.attempts`, or `note_attempts` on an error re-raised
        unchanged)."""
        import requests
        tries: list[dict] = []
        for attempt in (1, 2):
            start = time.perf_counter()
            try:
                r = self._session.request(method, url, **kwargs)
                text = r.text
                elapsed = time.perf_counter() - start
                tries.append(attempt_record(attempt, "response", status=r.status_code,
                                            elapsed=elapsed))
                return Probe(status=r.status_code, text=text, elapsed=elapsed,
                             headers=dict(r.headers), resent=attempt - 1, attempts=tries,
                             credentialed=False)
            except Exception as exc:
                spent = time.perf_counter() - start
                if _is_timeout(exc):        # the body's read included (BUG-0147)
                    tries.append(attempt_record(attempt, "timeout", elapsed=spent,
                                                error=type(exc).__name__))
                    return Probe(status=0, text="", elapsed=float(self._timeout),
                                 resent=attempt - 1, attempts=tries, credentialed=False,
                                 timeout="connect" if _is_connect_timeout(exc) else "read")
                unobserved = _unobserved(exc)
                if unobserved is None:
                    if isinstance(exc, requests.ConnectionError):   # refused, DNS, ...
                        tries.append(attempt_record(attempt, "error", elapsed=spent,
                                                    error=type(exc).__name__))
                    note_attempts(exc, tries)
                    raise
                tries.append(attempt_record(attempt, "unobserved", elapsed=spent,
                                            error=type(exc).__name__))
                if attempt == 1 and method.upper() in self.RETRY_ON_RESET and \
                        isinstance(exc, requests.ConnectionError):
                    continue
                unobserved.resent = attempt - 1
                unobserved.attempts = tries
                raise unobserved from exc   # no response: no verdict, the run goes on
        raise AssertionError("unreachable")

    def _follow(self, probe: Probe, own: str, method: str,
                own_segment: str | None = None, own_value: str | None = None) -> None:
        """One plain GET of the probe's PRG target (`prg_target`, resolved against
        ``own``, the probe's own URL: FR-FUZZ-69), anonymous like the probe: the jar is
        cleared first (BUG-0112), no redirect is followed."""
        target, why = prg_target(probe, own, method, self._explicit, own_segment,
                                 own_value)
        if target is None:
            probe.prg = why
            return
        if url_key(target) in self._isolated_keys:
            self._isolated_sends += 1
        jar = getattr(self._session, "cookies", None)
        if jar is not None:
            jar.clear()
        try:
            followed = self._request("GET", target, {"timeout": self._timeout,
                                                     "allow_redirects": False})
        except ProbeUnobserved as exc:         # the follow-up got no response (BUG-0147)
            probe.prg, probe.resent = PRG_UNOBSERVED, probe.resent + exc.resent
            probe.prg_sent = _follow_up_record(target, "unobserved", exc.attempts,
                                               error=type(exc.__cause__ or exc).__name__)
            return
        probe.resent += followed.resent
        probe.prg_sent = _follow_up_record(
            target, "timeout" if followed.status == 0 else "response", followed.attempts,
            status=followed.status or None, elapsed=followed.elapsed)
        if followed.status == 0:               # timed out: no observation
            probe.prg = PRG_UNOBSERVED
            return
        probe.followed, probe.prg = _observation(followed, target)


def make_probe_sender(target_url: str, identity: str | None = None,
                      timeout: float = 15.0, auth_origins=()):
    """Authenticated sender when an identity is given, else a standalone one.
    ``auth_origins`` (``--auth-origin``, FR-SESS-20) go to the session manager."""
    if identity:
        from fuzzlab.tools.authhttp import make_auth_with_isolation
        manager, client, isolated_client = make_auth_with_isolation(
            target_url, timeout, auth_origins=auth_origins)
        return SeamProbeSender(client, identity, manager=manager, base_url=target_url,
                               isolated_client=isolated_client)
    return RequestsProbeSender(timeout=timeout)
