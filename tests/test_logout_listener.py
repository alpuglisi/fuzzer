"""FR-SESS-16: `SessionManager.add_logout_listener` — told when observe() logs a session
out, so forms phase 2's breakers (lane A's header breaker, lane B's single-session
breaker) can react inside the send that saw it, without counting logins."""

import pytest

from fuzzlab.core.http import Request, Response
from fuzzlab.session.manager import SessionManager
from tests.test_session_manager import LOGIN_HTML, CookieLoginFetcher, _factory, _store


def _mgr():
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    mgr.ensure("localhost", "admin", "http://localhost")
    return mgr


REQ = Request("GET", "http://localhost/profile.php", identity="admin")
LOGGED_OUT = Response(200, {}, LOGIN_HTML.encode(), 5.0)
FINE = Response(200, {}, b"<html>welcome admin</html>", 5.0)


def test_listener_told_once_per_logout_with_host_and_identity():
    mgr, seen = _mgr(), []
    mgr.add_logout_listener(lambda host, identity: seen.append((host, identity)))
    mgr.observe(REQ, FINE, "admin")
    assert seen == []
    mgr.observe(REQ, LOGGED_OUT, "admin")
    mgr.observe(REQ, LOGGED_OUT, "admin")        # already invalid: not told again
    assert seen == [("localhost", "admin")]
    mgr.prepare(REQ, "admin")                    # re-login; a new logout is told again
    mgr.observe(REQ, LOGGED_OUT, "admin")
    assert seen == [("localhost", "admin")] * 2


def test_adding_the_same_listener_twice_registers_it_once():
    mgr, seen = _mgr(), []
    listener = lambda host, identity: seen.append(identity)
    mgr.add_logout_listener(listener)
    mgr.add_logout_listener(listener)
    mgr.observe(REQ, LOGGED_OUT, "admin")
    assert seen == ["admin"]


def test_another_managers_logout_is_not_told():
    """Lane B's isolated copies are separate managers: their logouts never reach the
    main manager's listeners."""
    main, other, seen = _mgr(), _mgr(), []
    main.add_logout_listener(lambda host, identity: seen.append(identity))
    other.observe(REQ, LOGGED_OUT, "admin")
    assert seen == []


def test_a_listener_error_propagates_after_the_state_is_invalid():
    """PA-0106: never swallowed; the session is already marked invalid first."""
    mgr = _mgr()

    def boom(host, identity):
        raise RuntimeError("listener failed")
    mgr.add_logout_listener(boom)
    with pytest.raises(RuntimeError, match="listener failed"):
        mgr.observe(REQ, LOGGED_OUT, "admin")
    assert not mgr._state[("localhost", "admin")].valid


def test_concurrent_sends_seeing_one_logout_tell_the_listener_once():
    """Reviewer B: the valid->invalid check-and-set is atomic across threads."""
    import threading
    mgr, seen = _mgr(), []
    mgr.add_logout_listener(lambda host, identity: seen.append(identity))
    start = threading.Barrier(8)

    def send():
        start.wait()
        mgr.observe(REQ, LOGGED_OUT, "admin")
    threads = [threading.Thread(target=send) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=10)
    assert seen == ["admin"]
