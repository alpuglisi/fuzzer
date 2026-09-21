"""LAB-owned session helper for build-time oracle confirmation (§3.2 of
``docs/LAB_IMPLEMENTATION_PLAN.md``).

Some manifest cells (stored-XSS and other second-order sinks) need the
build-time oracle-confirmation code (see ``oracle_wrapper.py``) to hold onto
a couple of **known, generator-controlled test-account** cookies while it
confirms a cell's verdict: a payload is submitted while logged in as one test
identity and the sink is observed under another (or the same) identity. This
module is that narrow session-holder -- nothing more.

It is deliberately **not** the toolkit's own separate "Session manager"
component (a different roadmap track, built for adversarial tools attacking
an *unknown* target, with re-auth-on-expiry, JWT handling, and
auto-exclusion of auth endpoints). Explicitly out of scope here:

* re-auth on expiry,
* JWT handling,
* auto-exclusion of auth endpoints,
* anything defending against an unknown/adversarial target.

This helper only ever talks to identities this project's own generator
created (``identities.yaml`` -- see §3.1 / ``fuzzlab.labgen.identity``), so
none of the above applies: the identity set is closed and known ahead of
time, and a "session" is nothing but a cookie jar keyed by identity id.

**Follows, does not invent, a session-management pattern.** Rather than
build a new callback shape, this module mirrors ``oracle_wrapper.py``'s
``SessionRefresh`` type (``Callable[[], Mapping[str, str]]``) exactly:
``IdentitySessionStore.refresh_session_for(identity_id)`` returns a
zero-argument callable of that exact shape, suitable to pass straight into
any ``*OracleRequest.refresh_session`` field. Cookie extraction follows the
same convention ``oracle_wrapper._resolve_session`` uses on the consumer
side: a ``"Set-Cookie"`` (or ``"Cookie"``) response header key, matched
case-insensitively, has its first ``name=value`` pair split out as the
session cookie; every other returned header is carried through unchanged.

``fuzzlab.labgen.identity`` (lane L-P2.1) is being built concurrently and
does not exist yet in this worktree. This module therefore accepts anything
duck-typing as ``IdentityLike`` (an object with an ``id: str`` attribute) --
including plain strings are *not* accepted, since ``identities.yaml``
identities carry more than a bare id and callers should pass the real
objects once available. **Once L-P2.1 merges, swap the import at the top of
this file for ``from fuzzlab.labgen.identity import Identity`` and drop the
local ``IdentityLike`` fallback Protocol** -- structurally nothing else here
should need to change, since ``Identity`` already satisfies the Protocol.
"""

from __future__ import annotations

import dataclasses
from typing import Callable, Dict, Mapping, Protocol, Sequence, runtime_checkable

try:  # pragma: no cover -- exercised once lane L-P2.1 lands.
    from fuzzlab.labgen.identity import Identity as IdentityLike  # type: ignore
except ImportError:
    @runtime_checkable
    class IdentityLike(Protocol):  # type: ignore[no-redef]
        """Minimal duck-type stand-in for the real, concurrently-being-built
        ``fuzzlab.labgen.identity.Identity`` (lane L-P2.1). Only the field
        this module actually uses is declared; swap for the real import once
        that lane merges (see module docstring)."""

        id: str


__all__ = [
    "IdentityLike",
    "LoginTransport",
    "Session",
    "UnknownIdentityError",
    "DuplicateIdentityError",
    "IdentitySessionStore",
]

# Mirrors `oracle_wrapper.SessionRefresh` exactly -- see that module's
# docstring for the "Cookie" key-splitting convention this module produces
# output for.
SessionRefresh = Callable[[], Mapping[str, str]]

# What actually performs a login for one identity: given an identity id,
# returns the raw response headers from the login endpoint (e.g. a
# `Set-Cookie` header), the same shape `SessionRefresh` returns. Real
# implementations wrap an HTTP client; tests inject a fake (see
# tests/test_labgen_identity_session.py), matching oracle_wrapper.py's own
# injected-fake-runner convention.
LoginTransport = Callable[[str], Mapping[str, str]]


class UnknownIdentityError(KeyError):
    """Raised by `login()`/`refresh_session_for()` for an identity id this
    store was never given -- this helper only ever talks to identities the
    generator itself declared, never an arbitrary id (see module docstring:
    "only ever talks to identities this project's own generator created")."""


class DuplicateIdentityError(ValueError):
    """Raised at construction time for a duplicate identity id -- fail loud,
    matching `load_labels`'s duplicate-`case_id` convention referenced in
    §3.1's test plan for `fuzzlab.labgen.identity`."""


@dataclasses.dataclass(frozen=True)
class Session:
    """One identity's current session: a resolved header set ready to send
    on a subsequent request, in the exact shape a `SessionRefresh` callable
    returns (a "Cookie" key, if any, already split out from the login
    response, plus any other headers the login response carried)."""

    identity_id: str
    headers: Mapping[str, str]


def _split_cookie(response_headers: Mapping[str, str]) -> Dict[str, str]:
    """Resolve a login response's headers into the `SessionRefresh` output
    shape: a `Set-Cookie` (or `Cookie`) key, matched case-insensitively, has
    its first `name=value` pair kept as the session's `"Cookie"` header;
    every other header passes through unchanged. Mirrors the split
    `oracle_wrapper._resolve_session` performs on the consumer side, just
    run once here at login time instead of once per attempt there."""
    resolved: Dict[str, str] = {}
    for key, value in response_headers.items():
        if key.lower() in ("set-cookie", "cookie"):
            # A Set-Cookie value may carry attributes ("id=abc; Path=/;
            # HttpOnly") -- only the leading name=value pair is a cookie to
            # send back.
            first_pair = value.split(";", 1)[0].strip()
            if first_pair:
                resolved["Cookie"] = first_pair
        else:
            resolved[key] = value
    return resolved


class IdentitySessionStore:
    """One cookie jar per known test identity.

    Construct with the closed set of identities the generator declared (see
    `identities.yaml` / `fuzzlab.labgen.identity.load_identities` once
    L-P2.1 lands) and a `login_transport` that actually performs a login for
    one identity id. Build-time oracle confirmation code then calls
    `login(identity_id)` to obtain that identity's current `Session`, or
    `refresh_session_for(identity_id)` to get a `SessionRefresh`-shaped
    callable to hand straight to an `oracle_wrapper` request's
    `refresh_session` field.
    """

    def __init__(self, identities: Sequence[IdentityLike], login_transport: LoginTransport) -> None:
        seen: Dict[str, IdentityLike] = {}
        for identity in identities:
            if identity.id in seen:
                raise DuplicateIdentityError(
                    f"duplicate identity id {identity.id!r} -- identity ids must be unique"
                )
            seen[identity.id] = identity
        self._known_ids = frozenset(seen)
        self._login_transport = login_transport
        self._jars: Dict[str, Session] = {}

    def login(self, identity_id: str) -> Session:
        """Log in as `identity_id` and store the resulting session, replacing
        (never duplicating) any prior session held for that identity. Two
        calls for the same identity refresh its single jar entry in place."""
        if identity_id not in self._known_ids:
            raise UnknownIdentityError(
                f"unknown identity id {identity_id!r} -- this store only holds sessions "
                "for identities it was constructed with"
            )
        raw_headers = self._login_transport(identity_id)
        session = Session(identity_id=identity_id, headers=_split_cookie(raw_headers))
        self._jars[identity_id] = session  # overwrite: refresh, never duplicate
        return session

    def current(self, identity_id: str) -> Session:
        """Return the session currently held for `identity_id` without
        triggering a fresh login. Raises `UnknownIdentityError` for an id
        this store was never given, and `KeyError` if `login()` has never
        been called yet for a known id."""
        if identity_id not in self._known_ids:
            raise UnknownIdentityError(
                f"unknown identity id {identity_id!r} -- this store only holds sessions "
                "for identities it was constructed with"
            )
        return self._jars[identity_id]

    def refresh_session_for(self, identity_id: str) -> SessionRefresh:
        """Return a zero-argument callable of exactly `oracle_wrapper`'s
        `SessionRefresh` shape (`Callable[[], Mapping[str, str]]`), suitable
        to pass straight into any `*OracleRequest.refresh_session` field.
        Each call re-logs-in as `identity_id` (refreshing that identity's
        jar entry) and returns the resulting headers."""
        def _refresh() -> Mapping[str, str]:
            return self.login(identity_id).headers
        return _refresh
