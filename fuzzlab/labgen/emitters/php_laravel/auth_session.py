"""Build-time session establishment for this stack's migrated **login** page
(lane L-P3.3c-G3, ``docs/LAB_IMPLEMENTATION_PLAN.md`` §4.3.6).

A login page is the one migrated page whose behavior is *establishing a
session*: ``puppy-fort-factory/login.php`` sets ``$_SESSION['user_id']`` /
``$_SESSION['username']`` and redirects, and the emitted Laravel controller
reproduces that (``session()->put(...)`` + ``redirect('/profile.php')`` -- see
``php_laravel``'s ``_SESSION_LOGIN_KEY``). Any build-time oracle confirmation
that wants to *use* that page -- log in as a known test identity and carry the
resulting cookie onto a subsequent request -- needs a cookie jar per identity.

**This module deliberately does not implement one.** That helper already
exists and is LAB-owned: :mod:`fuzzlab.labgen.identity_session` (lane L-P2.2),
whose :class:`~fuzzlab.labgen.identity_session.IdentitySessionStore` is
exactly "one cookie jar per known test identity", already produces callables
of :mod:`fuzzlab.labgen.oracle_wrapper`'s ``SessionRefresh`` shape, and
already owns the ``Set-Cookie`` splitting convention. Re-inventing a session
holder here is precisely what PA-0001/PA-0021 forbid (a second, independent
derivation of a convention another module already owns), so everything below
is *adaptation only*:

* the **URL** to post the login form to -- this stack's own
  ``served_url_for``, never re-derived here (the same single-source split
  :mod:`fuzzlab.labgen.emitters.php_laravel.identifier_sqli` uses), which for
  the migrated page is the real app's ``/login.php``;
* the **field names** to post -- this stack's own page profile
  (``param_name``/``password_param``), never duplicated here;
* the **transport**, which is injected. Nothing in this module opens a socket:
  it builds a ``LoginTransport`` closure over a caller-supplied poster, so the
  module is fully offline-testable and, per D11/the lab-only rule, sending
  traffic stays the caller's explicit, ``--authorized``-gated decision.

Credentials are supplied as a ``password_for`` **callable**, not a mapping of
stored passwords: an :class:`~fuzzlab.labgen.identity.Identity` carries only
``id``/``role`` (no credential fields), and D12 keeps credentials in the OS
keyring rather than in this repo -- a callable lets the caller resolve each
one from wherever it really lives without this module ever holding it.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

from fuzzlab.labgen.emitters.php_laravel import (
    _PAGE_PROFILES,
    _SESSION_LOGIN_KEY,
    served_url_for,
)
from fuzzlab.labgen.identity_session import (
    IdentityLike,
    IdentitySessionStore,
    LoginTransport,
    SessionRefresh,
)
from fuzzlab.labgen.schema import Cell

__all__ = [
    "AuthSessionError",
    "LoginPoster",
    "PasswordResolver",
    "is_login_cell",
    "login_url_for",
    "login_fields_for",
    "login_transport_for",
    "session_store_for",
    "refresh_session_for_cell",
]


class AuthSessionError(ValueError):
    """Raised when a cell cannot honestly be used to establish a session (it is
    not a login cell, or its page profile lacks the field names a login post
    needs). Fail-closed, mirroring ``identifier_sqli``'s own refusals -- never
    a guessed parameter name."""


#: What actually performs the HTTP POST, injected by the caller: given the URL
#: path and the form fields, return the response headers (e.g. a
#: ``Set-Cookie``). Exactly the shape
#: :class:`~fuzzlab.labgen.identity_session.IdentitySessionStore` then splits a
#: cookie out of -- this module adds no convention of its own.
LoginPoster = Callable[[str, Mapping[str, str]], Mapping[str, str]]

#: Resolves one identity id to the password to log in with (from the OS keyring
#: / credential store per D12 -- never stored in this repo).
PasswordResolver = Callable[[str], str]


def is_login_cell(cell: Cell) -> bool:
    """Whether ``cell``'s page is a login page -- i.e. its page profile
    declares the session-establishment tail (``session_login``). Derived from
    the profile, never from a name match on the route path (PA-0008's
    "authoritative capability probe, not a fragile name string")."""
    return bool(_PAGE_PROFILES.get(cell.route.path, {}).get(_SESSION_LOGIN_KEY))


def login_url_for(cell: Cell) -> str:
    """The URL path this login cell is actually served at.

    Delegates to the emitter's own ``served_url_for``, so this is the real
    app's ``/login.php`` for the cell that owns that page and the cell's variant
    URL for an authored twin -- a distinction this module must never re-derive
    (PA-0001).
    """
    if not is_login_cell(cell):
        raise AuthSessionError(
            f"{cell.cell_id}: route {cell.route.path!r} is not a login page (its php_laravel "
            f"page profile declares no {_SESSION_LOGIN_KEY!r} tail) -- there is no session for "
            "this cell to establish"
        )
    return served_url_for(cell)


def login_fields_for(cell: Cell, *, username: str, password: str) -> dict[str, str]:
    """The login form body for ``cell``, keyed by the **page profile's own**
    parameter names (``param_name``/``password_param``) rather than by names
    restated here."""
    profile: Mapping[str, Any] = _PAGE_PROFILES.get(cell.route.path, {})
    if not is_login_cell(cell):
        raise AuthSessionError(
            f"{cell.cell_id}: not a login cell -- see login_url_for() for the same refusal"
        )
    missing = [key for key in ("param_name", "password_param") if key not in profile]
    if missing:
        raise AuthSessionError(
            f"{cell.cell_id}: page profile for {cell.route.path!r} is missing {missing} -- a "
            "login post cannot be built without the page's own field names (refusing to guess)"
        )
    return {profile["param_name"]: username, profile["password_param"]: password}


def login_transport_for(
    cell: Cell, *, poster: LoginPoster, password_for: PasswordResolver
) -> LoginTransport:
    """A :data:`~fuzzlab.labgen.identity_session.LoginTransport` that logs an
    identity in through ``cell``'s generated login page.

    The returned callable has exactly the shape ``IdentitySessionStore``
    expects (``identity_id -> response headers``); the identity's own id is
    posted as the username, which is what this generator's identities are: the
    closed, generator-created set ``identity_session`` documents as its only
    subject.
    """
    url = login_url_for(cell)

    def _login(identity_id: str) -> Mapping[str, str]:
        fields = login_fields_for(
            cell, username=identity_id, password=password_for(identity_id)
        )
        return poster(url, fields)

    return _login


def session_store_for(
    cell: Cell,
    identities: Sequence[IdentityLike],
    *,
    poster: LoginPoster,
    password_for: PasswordResolver,
) -> IdentitySessionStore:
    """The LAB-owned :class:`IdentitySessionStore` wired to ``cell``'s login
    page -- the whole point of this module. Duplicate-identity rejection, the
    one-jar-per-identity invariant and the ``Set-Cookie`` split all stay that
    class's behavior, unchanged and unreimplemented."""
    return IdentitySessionStore(
        identities, login_transport_for(cell, poster=poster, password_for=password_for)
    )


def refresh_session_for_cell(
    cell: Cell,
    identities: Sequence[IdentityLike],
    identity_id: str,
    *,
    poster: LoginPoster,
    password_for: PasswordResolver,
) -> SessionRefresh:
    """A ready-to-use ``SessionRefresh`` callable for ``identity_id`` against
    ``cell``'s login page, suitable to hand straight to any
    ``*OracleRequest.refresh_session`` field (``oracle_wrapper``'s own shape --
    see :meth:`IdentitySessionStore.refresh_session_for`)."""
    store = session_store_for(
        cell, identities, poster=poster, password_for=password_for
    )
    return store.refresh_session_for(identity_id)
