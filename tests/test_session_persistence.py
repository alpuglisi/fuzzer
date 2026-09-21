"""Tests for non-secret session-state persistence (T1.7)."""

from fuzzlab.core.store import Store
from fuzzlab.session.manager import SessionManager
from tests.test_session_manager import CookieLoginFetcher, _factory, _store


def test_login_persists_non_secret_state_only(tmp_path):
    with Store(tmp_path / "u.db") as store:
        mgr = SessionManager(_store(), scope_hosts=["localhost"],
                             fetch_factory=_factory(CookieLoginFetcher()), store=store)
        mgr.ensure("localhost", "admin", "http://localhost")

        rec = store.get_session_state("localhost", "admin")
        assert rec is not None
        assert rec["host"] == "localhost" and rec["identity"] == "admin"
        assert rec["kind"] == "cookie" and rec["valid"] == 1
        assert rec["login_url"] == "http://localhost/login.php"
        # No secret is ever written: the row has no cookie/token/password field,
        # and the live cookie value must not appear anywhere in it.
        assert "sess1" not in str(rec)
        assert "PHPSESSID" not in str(rec)


def test_resume_reads_persisted_state_in_a_fresh_manager(tmp_path):
    db = tmp_path / "u.db"
    with Store(db) as store:
        mgr = SessionManager(_store(), scope_hosts=["localhost"],
                             fetch_factory=_factory(CookieLoginFetcher()), store=store)
        mgr.ensure("localhost", "admin", "http://localhost")

    # A brand-new manager on the same store resumes the known (non-secret) state.
    with Store(db) as store2:
        mgr2 = SessionManager(_store(), scope_hosts=["localhost"],
                              fetch_factory=_factory(CookieLoginFetcher()), store=store2)
        rec = mgr2.persisted_state("localhost", "admin")
        assert rec is not None and rec["kind"] == "cookie"
        assert mgr2.persisted_state("localhost", "user") is None


def test_logout_updates_persisted_validity(tmp_path):
    from fuzzlab.core.http import Request, Response

    with Store(tmp_path / "u.db") as store:
        mgr = SessionManager(_store(), scope_hosts=["localhost"],
                             fetch_factory=_factory(CookieLoginFetcher()), store=store)
        mgr.ensure("localhost", "admin", "http://localhost")
        assert store.get_session_state("localhost", "admin")["valid"] == 1
        # A login-page response => logged out => persisted valid flips to 0.
        login_html = b"<form><input type=password name=password></form>"
        req = Request("GET", "http://localhost/profile.php", identity="admin")
        mgr.observe(req, Response(200, {}, login_html, 5.0), "admin")
        assert store.get_session_state("localhost", "admin")["valid"] == 0


def test_no_store_means_no_persistence():
    # Without a store, persisted_state is simply empty (no crash).
    mgr = SessionManager(_store(), scope_hosts=["localhost"],
                         fetch_factory=_factory(CookieLoginFetcher()))
    mgr.ensure("localhost", "admin", "http://localhost")
    assert mgr.persisted_state("localhost", "admin") is None
