"""The session material a send carries (FR-SESS-24, SP-75; BUG-0557).

`SessionManager.prepare` applies a state's cookies and headers to a request. Inside a
`material_frame` it records what it applied (`AppliedMaterial`: the state's generation
and a keyed digest, never a value) and, given an expected material, refuses a send whose
material changed -- a re-login, or a cookie a live health check rotated in place -- before
it applies anything (`SessionMaterialChanged`). This is what lets the probe sender keep a
value bound from a page (FR-FUZZ-67) on the session that page was fetched on.

Each test drives the real manager; the health GET is a fetcher double standing in for a
live answer that rotates the session id, and nothing goes to the network.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.http import Request
from fuzzlab.session.manager import (AppliedMaterial, FetchResponse, SessionManager,
                                     SessionMaterialChanged, material_frame)
from fuzzlab.session.state import SessionState

ORIGIN = "http://127.0.0.1:8080"
SID, ROTATED, BEARER = "s1-7f3c9a", "s2-91d0be", "Bearer tok-55e1"


class _Rotating:
    """The health GET's fetcher: a live 200 that sets a new value of ``sid``."""

    def get(self, url, headers=None, allow_redirects=True):
        return FetchResponse(200, {"Content-Type": "text/html"}, "<h1>hi</h1>", url,
                             ("http",))

    def post(self, *a, **k):
        raise AssertionError("a health fetcher never posts")

    def cookies(self):
        return {"sid": ROTATED}


def _manager():
    mgr = SessionManager(None, scope_hosts=["127.0.0.1"], browser_login=False,
                         fetch_factory=lambda: None, health_fetch_factory=_Rotating)
    return mgr, _adopt(mgr)


def _adopt(mgr, sid=SID):
    return mgr.adopt(SessionState("127.0.0.1", "alice", kind="cookie",
                                  cookies={"sid": sid},
                                  headers={"Authorization": BEARER},
                                  origins=frozenset({ORIGIN})),
                     protected_probe=ORIGIN + "/me")


def _prepared(mgr, url=ORIGIN + "/form", **frame):
    req = Request("GET", url, identity="alice")
    with material_frame(**frame) as carried:
        mgr.prepare(req, "alice")
    return req, carried.applied


def test_a_send_bound_to_its_fetchs_material_is_refused_after_a_live_check_rotates_it():
    """A live health check adopts a rotated id in place, in the same generation (N-R3-2).
    A send expecting the fetch's material is refused before anything is applied; one
    expecting the new material carries the new id."""
    mgr, state = _manager()
    fetch, fetched = _prepared(mgr)
    assert fetch.headers["Cookie"] == f"sid={SID}" and fetched.generation == 1

    health, _moved = mgr.check_health("127.0.0.1", "alice", use_cache=False)
    assert health.state == "live" and state.cookies["sid"] == ROTATED
    assert state.generation == 1                         # the same generation

    send = Request("POST", ORIGIN + "/do", identity="alice")
    with pytest.raises(SessionMaterialChanged) as info:
        with material_frame(expect=fetched):
            mgr.prepare(send, "alice")
    assert "Cookie" not in send.headers and "Authorization" not in send.headers
    assert send.session_generation is None               # nothing was applied
    assert SID not in str(info.value) and ROTATED not in str(info.value)

    again, now = _prepared(mgr)
    assert again.headers["Cookie"] == f"sid={ROTATED}" and now != fetched
    _bound, same = _prepared(mgr, expect=now)              # unchanged since: it goes
    assert same == now


def test_a_new_generation_with_the_same_cookies_is_other_material():
    """A re-login (here a re-adopt) that hands back the same id and header is another
    generation: a send expecting the old one is refused."""
    mgr, _state = _manager()
    _req, fetched = _prepared(mgr)
    _adopt(mgr)                                          # generation 2, same values
    with pytest.raises(SessionMaterialChanged):
        _prepared(mgr, expect=fetched)
    _req, now = _prepared(mgr)
    assert now.generation == 2 and now.digest == fetched.digest


def test_a_send_with_no_session_records_none_and_a_bound_one_must_match_it():
    """An out-of-origin send carries no session: its material is None. A send expecting
    None (its setup carried no session) is refused where it would carry one."""
    mgr, _state = _manager()
    out, none = _prepared(mgr, url="http://127.0.0.1:9090/form")
    assert none is None and "Cookie" not in out.headers
    assert mgr.out_of_origin_sends == 1
    with pytest.raises(SessionMaterialChanged):
        _prepared(mgr, expect=None)
    _same, still_none = _prepared(mgr, url="http://127.0.0.1:9090/x", expect=None)
    assert still_none is None and mgr.out_of_origin_sends == 2


def test_the_material_is_a_keyed_digest_never_a_value():
    mgr, state = _manager()
    _req, one = _prepared(mgr)
    _req, same = _prepared(mgr)
    assert isinstance(one, AppliedMaterial) and one == same
    shown = repr(one) + str(one.digest)
    for secret in (SID, BEARER, "tok-55e1", "s1-7f3c9a"):
        assert secret not in shown
    state.headers = {"Authorization": "Bearer other"}    # a header is material too
    _req, other = _prepared(mgr)
    assert other.generation == one.generation and other.digest != one.digest


def test_only_the_first_prepare_inside_a_frame_settles_it():
    """A frame is one send's: a second `prepare` on the thread inside it (none does today)
    neither re-records nor is checked against it."""
    mgr, _state = _manager()
    _req, fetched = _prepared(mgr)
    with material_frame(expect=fetched) as frame:
        mgr.prepare(Request("GET", ORIGIN + "/a", identity="alice"), "alice")
        _adopt(mgr)
        mgr.prepare(Request("GET", ORIGIN + "/b", identity="alice"), "alice")
    assert frame.prepared and frame.applied == fetched
