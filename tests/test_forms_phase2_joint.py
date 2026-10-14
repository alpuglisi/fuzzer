"""Forms phase 2, lanes A and B together: the header breaker (FR-FUZZ-43) and session
isolation (FR-FUZZ-44) on one real `SeamProbeSender`, driven through lane B's real copy
logins (no accessor stand-in). Reviewers A and B, merge conditions 1-5."""

from __future__ import annotations

import pytest

from fuzzlab.core.http import HeaderPointRefused
from fuzzlab.oracle.probe import HeaderPointsStopped
from tests.test_login_form_isolation import BASE, FakeApp, _probe_form, _seam

PAGE = BASE + "page.php"
FORM = BASE + "sqli_3.php"


class _UaBoundApp(FakeApp):
    """Any request carrying a probed User-Agent logs its session out."""

    def transport(self, method, url, headers, body, timeout):
        from tests.test_login_form_isolation import _sid_of
        if "User-Agent" in headers:
            self.sessions.pop(_sid_of(headers.get("Cookie")), None)
        return super().transport(method, url, headers, body, timeout)


def _header(sender, url=PAGE, name="User-Agent"):
    return sender.send(url, name, "fz-probe", location="header")


def test_the_accessor_is_lane_bs_real_method():
    _mgr, _client, sender = _seam(FakeApp())
    assert sender._copy_logins.__func__.__code__.co_names.count("isolated_copy_logins") == 1
    assert "isolated_copy_logins" not in vars(sender)               # never overridden


def test_a_copy_login_that_logs_main_out_is_lane_bs_case_not_the_header_breakers():
    app = FakeApp(single_session="lazy", public_base=True)
    _mgr, _client, sender = _seam(app)
    sender.isolate([FORM])
    _header(sender)                                    # main header probe (UA not bound)
    _probe_form(sender, login="a")                     # a real copy login; verify passes
    assert sender.isolated_copy_logins() == 1
    sender.send(PAGE, "id", "1")                       # observes the lazy logout
    assert sender.header_stop_reason is None
    assert sender.isolation_report()["breaker"]["trip"] == "single-session"
    _header(sender)                                    # header probing goes on
    assert app.requests[-1][4].get("User-Agent") == "fz-probe"
    assert app.login_posts == 3                        # main, copy, one main re-login
    main_sids = {app.issued[0], app.issued[2]}
    assert all(r[2] not in main_sids for r in app.requests if r[1] == "/app/sqli_3.php")


def test_a_ua_bound_session_with_a_live_copy_trips_both_breakers_once():
    app = _UaBoundApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([FORM])
    _probe_form(sender, login="a")                     # main login, copy login, verified
    assert sender.isolated_copy_logins() == 1 and app.login_posts == 2
    _header(sender)                                    # logs main out
    assert sender.header_stop_reason and "User-Agent" in sender.header_stop_reason
    assert sender.isolation_report()["breaker"]["trip"] == "single-session"
    with pytest.raises(HeaderPointsStopped):
        _header(sender)                                # no header probe after the trip
    sender.send(PAGE, "id", "1")
    assert app.login_posts == 3                        # exactly one main re-login
    _probe_form(sender, login="b")
    assert app.requests[-1][2] is None                 # isolated sends now anonymous


def test_a_header_probe_to_an_isolated_path_rides_its_copy():
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([FORM])
    _header(sender, url=FORM)
    to_form = [r for r in app.requests if r[1] == "/app/sqli_3.php"]
    assert to_form[-1][2] not in (None, app.issued[0])   # the copy's sid, not main's
    assert sender._last_main_was_header is None          # not a main send
    before = sender.isolated_copy_logins()
    with pytest.raises(HeaderPointRefused):
        _header(sender, url=FORM, name="X-Forwarded-Host")  # the gate still applies
    assert sender.isolated_copy_logins() == before


def test_a_stopped_or_refused_header_never_causes_a_copy_login():
    app = FakeApp()
    _mgr, _client, sender = _seam(app)
    sender.isolate([FORM])
    sender.header_stop_reason = "session bound to a probed header (test)"
    with pytest.raises(HeaderPointsStopped):
        _header(sender, url=FORM)
    sender.header_stop_reason = None
    with pytest.raises(HeaderPointRefused):
        _header(sender, url=FORM, name="Host")
    assert sender.isolated_copy_logins() == 0 and app.login_posts == 0
