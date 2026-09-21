"""Offline tests for `fuzzlab.labgen.identity_session` (LAB-owned session
helper for build-time oracle confirmation -- see §3.2 of
docs/LAB_IMPLEMENTATION_PLAN.md). Every case uses a fake login transport, the
same injected-fake convention as test_labgen_oracle_wrapper.py; no real HTTP
server is needed.
"""

import dataclasses

import pytest

from fuzzlab.labgen.identity_session import (
    DuplicateIdentityError,
    IdentitySessionStore,
    Session,
    UnknownIdentityError,
)


@dataclasses.dataclass(frozen=True)
class _FakeIdentity:
    """A minimal stand-in satisfying `IdentityLike` (an `id: str` field) --
    exactly what the real `fuzzlab.labgen.identity.Identity` will provide
    once lane L-P2.1 merges."""

    id: str


class FakeLoginTransport:
    """A scripted login transport: returns queued response-header maps in
    order per identity, and records every identity id it was called with."""

    def __init__(self, responses_by_identity):
        self._responses = {k: list(v) for k, v in responses_by_identity.items()}
        self.calls = []

    def __call__(self, identity_id):
        self.calls.append(identity_id)
        queue = self._responses.get(identity_id, [])
        if not queue:
            raise AssertionError(f"FakeLoginTransport called for {identity_id!r} more times than scripted")
        return queue.pop(0)


IDENTITIES = [_FakeIdentity(id="user_a"), _FakeIdentity(id="user_b")]


def test_login_returns_session_with_cookie_split_from_set_cookie_header():
    transport = FakeLoginTransport({
        "user_a": [{"Set-Cookie": "sid=aaa111; Path=/; HttpOnly"}],
    })
    store = IdentitySessionStore(IDENTITIES, transport)

    session = store.login("user_a")

    assert isinstance(session, Session)
    assert session.identity_id == "user_a"
    assert session.headers == {"Cookie": "sid=aaa111"}


def test_login_preserves_other_headers_alongside_cookie():
    transport = FakeLoginTransport({
        "user_a": [{"Set-Cookie": "sid=aaa111", "X-CSRF-Token": "tok-1"}],
    })
    store = IdentitySessionStore(IDENTITIES, transport)

    session = store.login("user_a")

    assert session.headers == {"Cookie": "sid=aaa111", "X-CSRF-Token": "tok-1"}


def test_two_identities_cookies_stay_isolated_across_sequential_logins():
    transport = FakeLoginTransport({
        "user_a": [{"Set-Cookie": "sid=aaa111"}],
        "user_b": [{"Set-Cookie": "sid=bbb222"}],
    })
    store = IdentitySessionStore(IDENTITIES, transport)

    session_a = store.login("user_a")
    session_b = store.login("user_b")

    # Neither identity's cookie leaked into the other's session or jar.
    assert session_a.headers == {"Cookie": "sid=aaa111"}
    assert session_b.headers == {"Cookie": "sid=bbb222"}
    assert store.current("user_a").headers == {"Cookie": "sid=aaa111"}
    assert store.current("user_b").headers == {"Cookie": "sid=bbb222"}
    assert transport.calls == ["user_a", "user_b"]


def test_login_twice_for_same_identity_refreshes_rather_than_duplicates():
    transport = FakeLoginTransport({
        "user_a": [{"Set-Cookie": "sid=aaa111"}, {"Set-Cookie": "sid=aaa222"}],
    })
    store = IdentitySessionStore(IDENTITIES, transport)

    first = store.login("user_a")
    second = store.login("user_a")

    assert first.headers == {"Cookie": "sid=aaa111"}
    assert second.headers == {"Cookie": "sid=aaa222"}
    # A single jar entry was replaced in place, not appended to -- `current`
    # reflects only the latest login, and the transport was invoked exactly
    # twice (once per explicit `login()` call, no hidden extra logins).
    assert store.current("user_a").headers == {"Cookie": "sid=aaa222"}
    assert transport.calls == ["user_a", "user_a"]


def test_login_unknown_identity_raises_without_calling_transport():
    transport = FakeLoginTransport({})
    store = IdentitySessionStore(IDENTITIES, transport)

    with pytest.raises(UnknownIdentityError):
        store.login("user_z")
    assert transport.calls == []


def test_current_unknown_identity_raises():
    store = IdentitySessionStore(IDENTITIES, FakeLoginTransport({}))
    with pytest.raises(UnknownIdentityError):
        store.current("user_z")


def test_current_before_any_login_raises_key_error():
    store = IdentitySessionStore(IDENTITIES, FakeLoginTransport({}))
    with pytest.raises(KeyError):
        store.current("user_a")


def test_duplicate_identity_id_rejected_at_construction():
    with pytest.raises(DuplicateIdentityError):
        IdentitySessionStore(
            [_FakeIdentity(id="user_a"), _FakeIdentity(id="user_a")],
            FakeLoginTransport({}),
        )


def test_refresh_session_for_matches_oracle_wrapper_session_refresh_shape():
    """`refresh_session_for` must return a zero-arg callable returning a
    Mapping[str, str] -- exactly `oracle_wrapper.SessionRefresh`'s shape --
    so it can be passed straight into a `*OracleRequest.refresh_session`
    field without any adapter."""
    transport = FakeLoginTransport({
        "user_a": [{"Set-Cookie": "sid=aaa111"}, {"Set-Cookie": "sid=aaa222"}],
    })
    store = IdentitySessionStore(IDENTITIES, transport)

    refresh = store.refresh_session_for("user_a")
    first = refresh()
    second = refresh()

    assert first == {"Cookie": "sid=aaa111"}
    assert second == {"Cookie": "sid=aaa222"}
    assert transport.calls == ["user_a", "user_a"]


def test_refresh_session_for_isolated_per_identity():
    transport = FakeLoginTransport({
        "user_a": [{"Set-Cookie": "sid=aaa111"}],
        "user_b": [{"Set-Cookie": "sid=bbb222"}],
    })
    store = IdentitySessionStore(IDENTITIES, transport)

    refresh_a = store.refresh_session_for("user_a")
    refresh_b = store.refresh_session_for("user_b")

    assert refresh_a() == {"Cookie": "sid=aaa111"}
    assert refresh_b() == {"Cookie": "sid=bbb222"}


def test_composes_with_oracle_wrapper_resolve_session_convention():
    """Sanity check that this module's output slots directly into
    `oracle_wrapper`'s own session-resolution convention (a "Cookie" key
    split out, everything else passed through as a header) without any
    further transformation."""
    from fuzzlab.labgen.oracle_wrapper import SqlInjectionOracleRequest, _resolve_session

    transport = FakeLoginTransport({
        "user_a": [{"Set-Cookie": "sid=aaa111", "X-CSRF-Token": "tok-1"}],
    })
    store = IdentitySessionStore(IDENTITIES, transport)

    request = SqlInjectionOracleRequest(
        target_url="http://127.0.0.1/profile",
        param_name="id",
        refresh_session=store.refresh_session_for("user_a"),
    )
    cookie, headers = _resolve_session(request)

    assert cookie == "sid=aaa111"
    assert headers == {"X-CSRF-Token": "tok-1"}
