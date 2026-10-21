"""Session-aware HTTP send seam.

One place all traffic goes through, so scope, budget, the timing mutex, raw-byte
recording, and (from Phase 1) the session manager are enforced uniformly rather
than reimplemented per tool. The real session manager arrives in Phase 1; here
the seam accepts an optional ``session`` addon exposing ``prepare``/``observe``.

Safety: every request's host must be in scope (lab-only), and the transport is
injectable so tests never touch the network.
"""

from __future__ import annotations

import functools
import re
import threading
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from fuzzlab.core.budget import RequestBudget

# Shared default browser headers for every tool that opens a bare
# `requests.Session()` (crawler, auditor, blind-SQLi fuzzer). `requests`' own
# defaults (`User-Agent: python-requests/x.y`, `Accept: */*`, no
# `Accept-Language`) are trivially fingerprintable, and several real external
# targets serve reduced/interstitial content -- or an outright 403 -- to a
# request whose headers don't hang together as a real browser's would
# (BUG-0059/BUG-0060): a UA claiming Chrome with a bare `Accept: */*` and no
# `Accept-Language` is itself a mismatch several WAFs specifically check for,
# a UA fix alone does not clear it. A single shared dict here means fixing or
# rotating this never needs a per-tool hand-maintained copy (PA-0027).
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

DEFAULT_BROWSER_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


class OutOfScope(RuntimeError):
    """Raised when a request targets a host outside the configured scope."""


# --- header injection points (forms phase 2, FR-CORE-32, PA-0003) ----------------------
#: Request headers a crawl-sourced header point may never carry, by class. Whole names,
#: compared case-insensitively (PA-0022).
HEADER_POINT_DENY: dict[str, frozenset[str]] = {
    # message framing / hop-by-hop: smuggling stays dual-use and default-off
    "framing": frozenset({
        "content-length", "transfer-encoding", "connection", "keep-alive", "te",
        "trailer", "upgrade", "expect", "proxy-connection", "content-type",
        "content-encoding"}),
    # request routing: could move a probe to another vhost or past the URL gate
    "routing": frozenset({
        "host", "forwarded", "x-forwarded-host", "x-host", "x-original-url",
        "x-rewrite-url", "x-forwarded-proto", "x-forwarded-scheme", "x-forwarded-ssl",
        "x-forwarded-port", "x-forwarded-prefix", "x-forwarded-server", "x-forwarded-uri",
        "x-original-host", "x-http-host-override"}),
    # method override: a GET could become a DELETE
    "method override": frozenset({
        "x-http-method-override", "x-http-method", "x-method-override"}),
    # credentials: the session's own material (plus any name redaction calls secret)
    "credential": frozenset({
        "cookie", "cookie2", "authorization", "proxy-authorization"}),
}
#: RFC 7230 ``token`` (a header field-name), at most 64 characters.
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")


class HeaderPointRefused(ValueError):
    """A header point names a header no crawl-sourced probe may set."""


def header_point_refusal(name) -> str | None:
    """Why a crawl-sourced header point may not probe header ``name``, or None.

    The one rule for the ``auto --header-points`` names and every sender's header
    branch (`check_send_header`). ``X-Forwarded-For``, ``X-Real-IP`` and ``Client-IP``
    are allowed: they change no routing."""
    from fuzzlab.core.redaction import is_sensitive_name
    if not isinstance(name, str) or not _HEADER_TOKEN.fullmatch(name):
        return f"{name!r} is not a header name (RFC 7230 token, at most 64 characters)"
    low = name.lower()
    for kind, names in HEADER_POINT_DENY.items():
        if low in names:
            return f"{name} is a {kind} header"
    if is_sensitive_name(name):
        return f"{name} names a credential"
    return None


def check_send_header(name: str, url: str, explicit: frozenset[str] = frozenset()) -> None:
    """Refuse a header probe the rule forbids unless its URL was explicitly enumerated
    (ground truth's own header points: ``Authorization``, signature headers). Every
    sender's header branch calls this (PA-0083(1))."""
    reason = header_point_refusal(name)
    if reason is None:
        return
    from fuzzlab.core.urls import url_key
    if url_key(url) not in explicit:
        raise HeaderPointRefused(f"refusing to probe header {name!r}: {reason}")


@dataclass
class Request:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    identity: str = "anonymous"
    timing: bool = False          # timing-sensitive -> serialized per host
    component: str = "http"
    #: What the session addon decided for this request, when it did not apply the
    #: identity's session: ``"anonymous (out of origin)"`` (FR-SESS-20, CC-CORE-0054).
    #: Set by ``prepare``; the sender that built the request reads it after the send.
    session_decision: str | None = None
    #: The generation of the session state ``prepare`` applied to this request
    #: (FR-SESS-23, CC-CORE-0070): the session addon's ``observe`` ignores an answer from
    #: another generation. None: no session was applied, or the addon does not say.
    session_generation: int | None = None
    #: True when ``prepare`` applied a session it already knew to be lost and could not
    #: yet recover (FR-SESS-23's re-login budget spent on an identity with no stable
    #: protected resource; CC-CORE-0070). The sender that built the request carries it
    #: to its reader, and the oracle reads any answer to such a request as not
    #: comparable (FR-FUZZ-65). The seam itself never changes either field; it reads
    #: ``session_generation`` only to key its transport's pool (FR-CORE-509).
    session_lost: bool = False


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float


# transport(method, url, headers, body, timeout) -> (status, headers, body_bytes)
Transport = Callable[[str, str, Mapping[str, str], bytes | None, float], tuple[int, dict[str, str], bytes]]


# --- the default transport: pooled per (origin, identity, generation) (FR-CORE-509) -----
#: A pooled session no send has used for this long is dropped before its next send, so
#: a reuse rarely races a server's own idle close: Node's http server and Apache httpd
#: both close an idle keep-alive connection after 5 s by default.
POOL_IDLE_SECONDS = 4.0
#: At most this many pooled sessions per transport; the least recently used goes first.
MAX_POOLED_SESSIONS = 32


@functools.lru_cache(maxsize=1)
def _no_cookie_jar():
    """A ``requests`` cookie jar that keeps nothing. The seam sets every request's
    ``Cookie`` header itself (the session addon); a pooled session's own jar would
    otherwise fill from the answers' ``Set-Cookie`` and add them to later requests that
    were meant to go without (an anonymous send, a control)."""
    from requests.cookies import RequestsCookieJar

    class NoCookies(RequestsCookieJar):
        def set_cookie(self, cookie, *args, **kwargs):
            return None
    return NoCookies


def _new_session():
    """A bounded (SP-60) ``requests`` session whose jar keeps nothing."""
    import requests  # imported lazily so core has no hard runtime import cost

    from fuzzlab.core import bodyread
    session = bodyread.bound(requests.Session())
    if not isinstance(session, requests.sessions.Session):
        return session                       # a test's in-memory stand-in, as given
    session.cookies = _no_cookie_jar()()
    return session


def _exchange(session, method: str, url: str, headers: Mapping[str, str],
              body: bytes | None, timeout: float):
    # The body is read bounded (SP-60, BUG-0536): wire and decoded ceilings and a
    # wall-clock deadline; an incomplete one raises `bodyread.BodyIncomplete`, never
    # comes back short.
    jar = getattr(session, "cookies", None)
    if type(jar) is _no_cookie_jar():
        jar.clear()                              # belt and braces: it keeps nothing
    resp = session.request(method, url, headers=dict(headers), data=body,
                           timeout=timeout, allow_redirects=False)
    return resp.status_code, dict(resp.headers), resp.content


def _close_session(session) -> None:
    try:
        session.close()
    except Exception:                            # noqa: BLE001 - closing only
        pass


class _Pooled:
    """One pooled session, the sends using it now, when one last finished, and whether
    it was retired (closed once its last send is done)."""
    __slots__ = ("session", "inflight", "last_used", "retired", "pooled")

    def __init__(self, session, now: float, *, pooled: bool = True):
        self.session = session
        self.inflight = 0
        self.last_used = now
        self.retired = not pooled
        self.pooled = pooled


class PooledTransport:
    """The seam's default transport (FR-CORE-509, BUG-0549): one pooled, bounded
    (SP-60) ``requests`` session per (origin, identity, session generation).

    - **Never shared across identities or generations.** The key is the request's
      canonical origin (SP-05), its identity and the ``session_generation`` its
      session addon applied (FR-SESS-23). A newer generation of an (origin, identity)
      retires the older ones' sessions; a send prepared on an older generation than
      the newest seen gets a session of its own, closed after it, and displaces
      nothing. ``None`` (no session applied) is its own key.
    - **A body never shares a connection.** A send that carries body bytes goes on a
      session of its own, closed after it: whether the target read the body cannot be
      observed, and one that did not (CL.0) would put its bytes at the head of the next
      request on that connection.
    - **No cookie state.** Each session's jar keeps nothing (`_no_cookie_jar`), and is
      cleared before each send: the seam sets ``Cookie`` explicitly.
    - **Lifecycle.** A retired session is closed when its last send in flight is done,
      never under one. A session idle past ``idle_seconds`` is retired before its next
      send; at most ``max_sessions`` are kept (the least recently used goes). `close`
      retires them all; a send after it gets a session of its own, closed after it.
    - **One try per send.** The transport never re-sends. A send that fails, on a
      reused connection the peer closed before any answer too, raises as any transport
      failure (SP-34), so every request the target receives is one the sender above
      made and recorded (FR-FUZZ-61, PA-0510). urllib3 drops a pooled connection it
      finds closed before reusing it, and the idle retirement keeps a reuse under the
      usual 5 s server idle close.
    - **A connection is kept only after an exactly framed exchange** (BUG-0549 review
      round 2). The sessions' pools are SP-60's: a connection whose answer was followed
      by any byte, buffered with the answer, waiting in the TLS layer or on the socket,
      is closed when it is returned, never reused (`bodyread.exact_end`). Before, urllib3
      kept it, and a stray answer could be read as the next send's.

    Thread-safe: the bookkeeping is under one lock, and ``requests`` sessions with no
    cookie state are shared by concurrent sends (urllib3's pools are thread-safe).
    """

    def __init__(self, *, idle_seconds: float | None = None,
                 max_sessions: int | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self._idle = POOL_IDLE_SECONDS if idle_seconds is None else idle_seconds
        self._max = MAX_POOLED_SESSIONS if max_sessions is None else max_sessions
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple, _Pooled] = OrderedDict()
        self._newest: dict[tuple, int] = {}
        self._closed = False

    def __call__(self, method: str, url: str, headers: Mapping[str, str],
                 body: bytes | None, timeout: float, *, identity: str = "anonymous",
                 generation: int | None = None):
        entry = self._checkout(url, identity, generation, own=bool(body))
        try:
            return _exchange(entry.session, method, url, headers, body, timeout)
        finally:
            self._checkin(entry)

    def close(self) -> None:
        """Retire every pooled session (each closed once its sends are done)."""
        with self._lock:
            self._closed = True
            doomed = [self._retire(key) for key in list(self._entries)]
        self._close_all(doomed)

    # -- bookkeeping, under the lock ------------------------------------------------
    def _checkout(self, url: str, identity: str, generation, *, own: bool) -> _Pooled:
        from fuzzlab.core.urls import canonical_origin
        origin = canonical_origin(url)
        doomed: list[_Pooled | None] = []
        with self._lock:
            now = self._clock()
            entry = None
            if not self._closed and origin is not None:
                entry = self._pooled_entry(origin, identity, generation, now, doomed,
                                           own=own)
            if entry is not None:
                entry.inflight += 1
        self._close_all(doomed)
        if entry is None:                    # a session of its own, closed after the send
            entry = _Pooled(_new_session(), now, pooled=False)
            entry.inflight = 1
        return entry

    def _pooled_entry(self, origin, identity, generation, now, doomed, *, own: bool):
        """The pooled session for the key, after the generation bookkeeping (which a
        send on a session of its own, ``own``, still does); None for such a send."""
        if isinstance(generation, int) and not isinstance(generation, bool):
            who = (origin, identity)
            newest = self._newest.get(who)
            if newest is not None and generation < newest:
                return None                      # a late send of a replaced generation
            if newest is None or generation > newest:
                self._newest[who] = generation
                doomed.extend(self._retire(key) for key in list(self._entries)
                              if key[:2] == who and isinstance(key[2], int)
                              and not isinstance(key[2], bool) and key[2] < generation)
        if own:
            return None                          # a send with a body: never pooled
        key = (origin, identity, generation)
        entry = self._entries.get(key)
        if entry is not None and entry.inflight == 0 and now - entry.last_used > self._idle:
            doomed.append(self._retire(key))
            entry = None
        if entry is None:
            while len(self._entries) >= max(1, self._max):
                doomed.append(self._retire(next(iter(self._entries))))
            entry = self._entries[key] = _Pooled(_new_session(), now)
        else:
            self._entries.move_to_end(key)
        return entry

    def _retire(self, key) -> _Pooled | None:
        """Take ``key``'s session out of the pool; return it when it can close now."""
        entry = self._entries.pop(key)
        entry.retired = True
        return entry if entry.inflight == 0 else None

    def _checkin(self, entry: _Pooled) -> None:
        with self._lock:
            entry.inflight -= 1
            entry.last_used = self._clock()
            done = entry.retired and entry.inflight == 0
        if done:
            self._close_all([entry])

    @staticmethod
    def _close_all(entries) -> None:
        for entry in entries:
            if entry is not None:
                _close_session(entry.session)


def _content_type(headers) -> str:
    """The Content-Type of a header mapping, looked up case-insensitively."""
    for name, value in (headers or {}).items():
        if str(name).lower() == "content-type":
            return value if isinstance(value, str) else bytes(value).decode("latin-1")
    return ""


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
        # The default transport is pooled per (origin, identity, generation) and owned
        # by this client: closed by `close`, or when the client is collected
        # (FR-CORE-509, BUG-0549). An injected transport is the caller's.
        self._transport = transport or PooledTransport()
        self._keyed = isinstance(self._transport, PooledTransport)
        self._finalizer = (weakref.finalize(self, self._transport.close)
                           if transport is None else None)
        self._timeout = timeout
        self._plugins = plugins       # optional PluginManager (on_request/on_response)

    def close(self) -> None:
        """Drop the pooled connections of the transport this client made (idempotent;
        a send after it still works, on a connection closed after it)."""
        if self._finalizer is not None:
            self._finalizer()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

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
            prepared_url = request.url
            request = self._plugins.on_request(request)
            host = self._check_scope(request.url)          # re-check if a plugin retargeted
            if self._session is not None and request.url != prepared_url:
                # a retarget must not carry the session elsewhere or over http (BUG-0098)
                self._session.authorize(request, request.identity,
                                        prepared_host=urlparse(prepared_url).hostname or "")

        def _do() -> Response:
            start = time.perf_counter()
            if self._keyed:      # the pool key: the identity and the session generation
                status, headers, body = self._transport(
                    request.method, request.url, request.headers, request.body,
                    self._timeout, identity=request.identity,
                    generation=request.session_generation)
            else:
                status, headers, body = self._transport(
                    request.method, request.url, request.headers, request.body,
                    self._timeout)
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
        """Persist the flow **redacted** through the one storage boundary
        (`core.redaction`, BUG-0099): the URL's sensitive query values and the bodies'
        sensitive fields never reach the store; the wire request is never modified."""
        if self._store is None or self._run_id is None:
            return
        from fuzzlab.core.redaction import redact_body, redact_url
        req_body = redact_body(request.body, _content_type(request.headers)) \
            if request.body else None
        resp_body = redact_body(response.body, _content_type(response.headers)) \
            if response.body else None
        req_sha = self._store.put_body(req_body) if req_body else None
        resp_sha = self._store.put_body(resp_body) if resp_body else None
        self._store.conn.execute(
            "INSERT INTO flow (run_id, identity, method, url, status, elapsed_ms, "
            "req_body_sha, resp_body_sha) VALUES (?,?,?,?,?,?,?,?)",
            (self._run_id, request.identity, request.method, redact_url(request.url),
             response.status, response.elapsed_ms, req_sha, resp_sha),
        )
        self._store.conn.commit()
