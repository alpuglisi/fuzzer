"""The contract runner's outcomes (CC-FUZZ-0105, FR-FUZZ-52; AU-OUTCOME; audit defects
15, 16 and the runner half of 17; BUG-0528, BUG-0529; draft
`docs/components/07-fuzzing-harness-and-oracle/DRAFT-AU-OUTCOME.md`).

An incomplete exchange, an unobserved state assertion or an answer that is not the
application's (a throttle or unavailable server, credentials not accepted, a policy block)
must never become a pass, a baseline, or a finding by status class alone.

Every test drives the real `Runner.send` / `Runner.judge` through a fake session whose
responses fail the way the real `requests` stack was measured to fail (MULTI_AGENT_
ORCHESTRATION §7): a body cut after a 200's headers raises
``ChunkedEncodingError(ProtocolError)`` while iterating, a stalled body raises
``ConnectionError(ReadTimeoutError)``, both with the status already known. The last
test pins that fact on a loopback socket.

Written first (Phase 1): each test that asserts the new behaviour fails on 8100959 for its
stated reason; the tests marked "pin" pass there and must keep passing."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import pytest
import requests
from urllib3.exceptions import ProtocolError, ReadTimeoutError

from fuzzlab.core.net import require_loopback
from fuzzlab.disco.contract import Contract
from fuzzlab.disco.runner import Runner
from tests.test_disco_contract import FakeSession, contract_doc

CUT = requests.exceptions.ChunkedEncodingError(
    ProtocolError("Connection broken: IncompleteRead(15 bytes read, 985 more expected)"))
STALL = requests.ConnectionError(ReadTimeoutError(None, None, "Read timed out."))


class Resp:
    """A streamed response: its chunks, then optionally an exception raised mid-body;
    counts ``close()``."""

    def __init__(self, status=200, chunks=(b"{}",), raise_after=None, headers=None):
        self.status_code = status
        self.headers = headers or {"Content-Type": "application/json"}
        self.chunks, self.raise_after, self.closed = list(chunks), raise_after, 0

    def iter_content(self, n):
        yield from self.chunks
        if self.raise_after is not None:
            raise self.raise_after

    def close(self):
        self.closed += 1


LOGIN_EP = {"id": "ep_login", "method": "POST", "path": "/api/login",
            "content_type": "application/json"}
SESSION_EP = {"id": "ep_session", "method": "POST", "path": "/api/session",
              "content_type": "application/json"}
REGISTER_EP = {"id": "ep_register", "method": "POST", "path": "/api/register",
               "content_type": "application/json"}
USERS_EP = {"id": "ep_users", "method": "GET", "path": "/api/users/{p1}"}


def one_case(oracle=None, endpoint="ep_010", request=None, auth="anon", setup=()):
    """The spec contract reduced to one case on ``endpoint`` (plus credential endpoints:
    a login URL, one that is not, an account creation; and a user resource that is
    none)."""
    doc = contract_doc()
    doc["endpoints"] += [dict(LOGIN_EP), dict(SESSION_EP), dict(REGISTER_EP),
                         dict(USERS_EP)]
    case = doc["test_cases"][0]
    case.update(endpoint=endpoint, setup=list(setup), auth_profile=auth,
                request=request or {"path_params": {"p1": "3"}},
                oracle=oracle or {"expect_status_class": ["2xx"], "findings_if": []})
    return doc


def run_one(doc, routes, **kw):
    r = Runner(Contract(doc), authorized=True, session=FakeSession(routes),
               sleep=lambda s: None, **kw)
    return r, r.run()


def _raise(exc):
    def f(url, kw):
        raise exc
    return f


ORDER = ("GET", "/api/orders/3")


# --- defect 15: an incomplete exchange (BUG-0528) ----------------------------------------

INCOMPLETE = {
    "cut after the headers": lambda: Resp(200, [b'{"id": 3, "to'], raise_after=CUT),
    "stalled after the headers": lambda: Resp(200, [b'{"id": 3, "to'], raise_after=STALL),
    "over max_body_bytes": lambda: Resp(200, [b"x" * 4000, b"y" * 4000]),
}


@pytest.mark.parametrize("shape", sorted(INCOMPLETE))
def test_an_incomplete_200_is_never_a_pass_nor_the_endpoints_baseline(shape):
    """Audit 15 (reproduced): a 200 whose body did not arrive whole is matched as if it
    had and passes. Wanted: an ``error`` naming the incompleteness, no baseline."""
    r, [res] = run_one(one_case(), {ORDER: lambda u, kw: INCOMPLETE[shape]()})
    assert res["verdict"] == "error", res
    assert "incomplete" in (res.get("reason") or ""), res
    assert r._baseline("ep_010") is None


def test_a_body_that_arrives_after_the_deadline_is_not_a_pass():
    """The deadline passed while the body was read (a drip under the read timeout,
    measured: a 1 s deadline took 3 s on the real stack); the exchange is late, so it
    is judged only by a latency rule."""
    clock = {"t": 0.0}

    def late(url, kw):
        clock["t"] += 10.0                        # 10 s pass while the body is read
        return Resp(200, [b'{"id": 3, "total": 1}'])
    r = Runner(Contract(one_case()), authorized=True, session=FakeSession({ORDER: late}),
               clock=lambda: clock["t"], sleep=lambda s: None)
    [res] = r.run()
    assert res["verdict"] == "error" and "incomplete" in res["reason"], res
    assert r._baseline("ep_010") is None


def test_an_incomplete_exchange_never_suppresses_a_later_cases_match():
    """Audit 15's poisoned baseline: a cut body admitted as the endpoint's baseline
    hides a later complete answer's match (`body_matches` is skipped when the baseline
    shows it)."""
    doc = one_case()
    first = doc["test_cases"][0]
    second = json.loads(json.dumps(first))
    second["id"] = "tc_second"
    second["oracle"] = {"expect_status_class": ["2xx"],
                        "findings_if": [{"body_matches": ["debug: "]}]}
    doc["test_cases"] = [first, second]
    answers = iter([Resp(200, [b'{"msg": "debug: q=1", "to'], raise_after=CUT),
                    Resp(200, [b'{"msg": "debug: q=2"}'])])
    _r, (one, two) = run_one(doc, {ORDER: lambda u, kw: next(answers)})
    assert one["verdict"] == "error"
    assert two["verdict"] == "finding" and two["matched"] == ["body_matches"], two


def test_a_clean_complete_answer_is_the_endpoints_baseline():
    """Pin (M10): the one reachable case of baseline admission -- a complete application
    answer below 400 that matched nothing is admitted. An over-narrowed admission fails."""
    r, [res] = run_one(one_case(), {ORDER: Resp(200, [b'{"id": 3, "total": 1}'])})
    assert res["verdict"] == "pass"
    assert r._baseline("ep_010") is not None and r._baseline("ep_010").status == 200


@pytest.mark.parametrize("shape", ["complete", "cut", "over the cap"])
def test_the_response_is_closed_on_every_exit(shape):
    """Audit 15: ``resp.close()`` was skipped when iterating raised."""
    resp = {"complete": Resp(200, [b"{}"]),
            "cut": Resp(200, [b"{"], raise_after=CUT),
            "over the cap": Resp(200, [b"x" * 5000])}[shape]
    r, _ = run_one(one_case(), {ORDER: resp})
    assert resp.closed == 1


def test_an_incomplete_body_is_never_written_to_evidence(tmp_path):
    """M3 (reviewer A, measured): the redactor keeps a cut JSON body it can only sniff
    (served ``text/plain``) with its secret. An incomplete exchange writes an "omitted
    (incomplete)" marker and its byte count, never its bytes."""
    body = b'{"password": "SECRETPW", "pad": "' + b"x" * 5000
    _r, [res] = run_one(one_case(), {ORDER: Resp(
        200, [body], headers={"Content-Type": "text/plain"})}, evidence_dir=tmp_path)
    blob = "".join(Path(p).read_text() for p in res.get("evidence", {}).values())
    assert "SECRETPW" not in blob
    assert "omitted (incomplete)" in blob, blob[:300]


def test_a_timeout_matches_a_latency_rule_only_when_it_proves_the_bound():
    """The narrow exception: a read timeout proves the answer took at least
    ``timeout_ms``. It matches ``latency_ms_gt`` only when ``timeout_ms`` reaches the
    rule's bound (2000 ms proves nothing about 5000 ms), before or after the headers."""
    before = requests.ReadTimeout()

    def oracle(bound):
        return {"expect_status_class": ["4xx"], "findings_if": [{"latency_ms_gt": bound}]}
    _r, [unproven] = run_one(one_case(oracle(5000)), {ORDER: _raise(before)})
    assert unproven["verdict"] == "error", unproven
    _r, [proven] = run_one(one_case(oracle(1000)), {ORDER: _raise(before)})
    assert proven["verdict"] == "finding" and proven["matched"] == ["latency_ms_gt"]
    _r, [after] = run_one(one_case(oracle(1000)),
                          {ORDER: lambda u, kw: Resp(200, [b"{"], raise_after=STALL)})
    assert after["verdict"] == "finding" and after["matched"] == ["latency_ms_gt"], after


def test_a_connect_timeout_never_proves_latency():
    """M7: no request reached the server, so nothing about its latency is known."""
    oracle = {"expect_status_class": ["4xx"], "findings_if": [{"latency_ms_gt": 1000}]}
    _r, [res] = run_one(one_case(oracle), {ORDER: _raise(requests.ConnectTimeout())})
    assert res["verdict"] == "error", res


def test_an_incomplete_setup_step_is_an_error_not_a_success():
    """A setup step is an exchange too: one whose body was cut is no setup."""
    step = {"call": "ep_009", "body": {"name": "seed"}}
    doc = one_case(oracle={"expect_status_class": ["4xx"], "findings_if": []},
                   setup=[step])
    _r, [res] = run_one(doc, {
        ("POST", "/api/orders"): lambda u, kw: Resp(201, [b'{"id": 4'], raise_after=CUT),
        ORDER: Resp(400, [b'{"error": "bad"}'])})
    assert res["verdict"] == "error" and "setup step 1" in res["reason"], res


def test_a_setup_login_redirected_back_to_the_login_page_fails_the_setup():
    """A8: a failed form login answers with a redirect to its login page; the setup
    never logged in, so the case cannot run as written."""
    step = {"call": "ep_login", "body": {"username": "u", "password": "p"}}
    doc = one_case(oracle={"expect_status_class": ["4xx"], "findings_if": []},
                   setup=[step])
    _r, [res] = run_one(doc, {
        ("POST", "/api/login"): Resp(302, [b""], headers={"Location": "/login?error=1"}),
        ORDER: Resp(400, [b'{"error": "bad"}'])})
    assert res["verdict"] == "error" and "setup step 1" in res["reason"], res


def test_a_setup_registration_redirected_to_the_login_page_is_its_success():
    """Pin (ADOPT 5): a step that creates an account and is sent on to the login page
    ("now log in") set up what it was for; only a login sent back to it failed."""
    step = {"call": "ep_register", "body": {"username": "u", "password": "p"}}
    doc = one_case(oracle={"expect_status_class": ["4xx"], "findings_if": []},
                   setup=[step])
    _r, [res] = run_one(doc, {
        ("POST", "/api/register"): Resp(302, [b""], headers={"Location": "/login"}),
        ORDER: Resp(400, [b'{"error": "bad"}'])})
    assert res["verdict"] == "pass", res


# --- defect 16: an unobserved state assertion (BUG-0528) --------------------------------

STATE_RULE = {"state_check": {"call": "ep_010", "path_params": {"p1": "3"},
                              "assert_jsonpath": "$.total >= 0"}}
MAIN = ("POST", "/api/orders/3/items")
#: A body that *satisfies* the assertion: each row below is unobserved for one reason
#: only, so each branch fails on its own revert (M8).
SATISFYING = b'{"id": 3, "total": 50}'


def state_case(*rules):
    return one_case(oracle={"expect_status_class": ["4xx"], "findings_if": list(rules)},
                    endpoint="ep_017", request={"path_params": {"p1": "3"},
                                                "body": {"quantity": -5}})


UNOBSERVED_READS = {
    # not JSON
    "an HTML page": lambda: Resp(200, [b"<form><input type=password></form>"],
                                 headers={"Content-Type": "text/html"}),
    # the path cannot be evaluated
    "JSON without the path": lambda: Resp(200, [b'{"id": 3}']),
    # not a complete application 2xx, with a body that satisfies the assertion
    "a 401": lambda: Resp(401, [SATISFYING]),
    "a 403": lambda: Resp(403, [SATISFYING]),
    "a 404": lambda: Resp(404, [SATISFYING]),
    "a 429": lambda: Resp(429, [SATISFYING]),
    "a 502": lambda: Resp(502, [SATISFYING]),
    "a 503": lambda: Resp(503, [SATISFYING]),
    "a redirect to the login page": lambda: Resp(
        302, [SATISFYING], headers={"Content-Type": "application/json", "Location": "/login"}),
    # incomplete: cut after a complete document, and no response at all
    "a body cut after a complete document": lambda: Resp(200, [SATISFYING], raise_after=CUT),
    "no response": None,
}


@pytest.mark.parametrize("read", sorted(UNOBSERVED_READS))
def test_an_unobserved_state_check_is_never_a_pass(read):
    """Audit 16 (reproduced): a state read that could not be evaluated returned None,
    which `judge` ignores; a read that was not the application's complete 2xx answer was
    evaluated as if it were. Wanted: ``error`` naming the state check and why."""
    make = UNOBSERVED_READS[read]
    reset = requests.ConnectionError(ConnectionResetError(104, "reset"))
    _r, [res] = run_one(state_case(STATE_RULE), {
        MAIN: Resp(400, [b'{"error": "bad quantity"}']),
        ORDER: _raise(reset) if make is None else (lambda u, kw: make())})
    assert res["verdict"] == "error", res
    assert "state check 1" in (res.get("reason") or ""), res


@pytest.mark.parametrize("why", ["cannot be prepared", "out of scope"])
def test_a_state_check_that_cannot_be_sent_is_never_a_pass(why):
    rule = json.loads(json.dumps(STATE_RULE))
    doc = state_case(rule)
    if why == "cannot be prepared":
        del rule["state_check"]["path_params"]           # {p1} has no value
        doc["test_cases"][0]["oracle"]["findings_if"] = [rule]
    else:
        doc["endpoints"][1]["origin"] = "http://127.0.0.1:9999/"
    _r, [res] = run_one(doc, {MAIN: Resp(400, [b'{"error": "bad quantity"}'])})
    assert res["verdict"] == "error" and "state check 1" in res["reason"], res


def test_a_violated_state_check_is_a_finding_and_a_satisfied_one_passes():
    """Pin: an evaluated assertion decides as before."""
    _r, [bad] = run_one(state_case(STATE_RULE), {
        MAIN: Resp(400, [b"{}"]), ORDER: Resp(200, [b'{"id": 3, "total": -50}'])})
    assert bad["verdict"] == "finding" and bad["matched"] == ["state_check"]
    _r, [good] = run_one(state_case(STATE_RULE), {
        MAIN: Resp(400, [b"{}"]), ORDER: Resp(200, [SATISFYING])})
    assert good["verdict"] == "pass"


def test_every_state_check_must_be_evaluated_for_a_pass():
    other = {"state_check": {"call": "ep_010", "path_params": {"p1": "3"},
                             "assert_jsonpath": "$.owner == \"alice\""}}
    _r, [res] = run_one(state_case(STATE_RULE, other), {
        MAIN: Resp(400, [b"{}"]), ORDER: Resp(200, [SATISFYING])})
    assert res["verdict"] == "error" and "state check 2" in res["reason"], res


def test_an_observed_finding_stands_and_names_the_unobserved_state_check():
    """Evidence already observed still counts (PA-0137(1)); the unobserved check is
    recorded on the result. A state check is numbered among the case's state checks."""
    _r, [res] = run_one(state_case({"status_class": "5xx"}, STATE_RULE), {
        MAIN: Resp(500, [b"{}"]), ORDER: Resp(429, [SATISFYING])})
    assert res["verdict"] == "finding" and "status_class:5xx" in res["matched"]
    assert [u["check"] for u in res.get("unobserved", [])] == [1], res


# --- defect 17, the runner: answers that are not the application's (BUG-0529) -----------

def status_case(expect, rules=(), auth="user_a", endpoint="ep_010", request=None):
    return one_case(oracle={"expect_status_class": list(expect), "findings_if": list(rules)},
                    auth=auth, endpoint=endpoint, request=request)


THROTTLED = {
    "429, no expectation": ([], 429, {}),
    "429, 4xx expected": (["4xx"], 429, {}),
    "429, 2xx expected": (["2xx"], 429, {}),
    "503 with Retry-After, 4xx expected": (["4xx"], 503, {"Retry-After": "30"}),
    "503, 4xx expected": (["4xx"], 503, {}),
}


@pytest.mark.parametrize("shape", sorted(THROTTLED))
def test_a_throttled_answer_is_never_judged_by_its_status_class(shape, monkeypatch):
    """Audit 17 (reproduced): a 429 with an empty oracle passes, and one outside the
    expected class is a finding. Neither observed the endpoint. (A 503 is "throttle or
    unavailable" by policy, not measurement.)"""
    monkeypatch.setenv("DISCO_TOKEN_A", "T")
    expect, status, headers = THROTTLED[shape]
    _r, [res] = run_one(status_case(expect), {ORDER: Resp(
        status, [b'{"error": "slow down"}'],
        headers={"Content-Type": "application/json", **headers})})
    assert res["verdict"] == "error" and "throttle" in res["reason"], res


def test_a_throttled_answer_is_judged_where_the_case_names_its_status(monkeypatch):
    """Pin."""
    monkeypatch.setenv("DISCO_TOKEN_A", "T")
    _r, [res] = run_one(status_case(["2xx"], [{"status_in": [429]}]),
                        {ORDER: Resp(429, [b"{}"])})
    assert res["verdict"] == "finding" and "status_in" in res["matched"]


REFUSED = {
    "401 where 2xx is expected": (["2xx"], 401, {}, "credentials not accepted"),
    "401 with no expectation": ([], 401, {}, "credentials not accepted"),
    "a redirect to the login page where 2xx is expected": (
        ["2xx"], 302, {"Location": "/login"}, "credentials not accepted"),
    "a lowercase location to the login page where 2xx is expected": (
        ["2xx"], 302, {"location": "/login"}, "credentials not accepted"),
    "403 where 2xx is expected": (["2xx"], 403, {}, "policy"),
    "403 with no expectation": ([], 403, {}, "policy"),
}


@pytest.mark.parametrize("shape", sorted(REFUSED))
def test_a_refusal_the_case_does_not_expect_is_an_error_not_a_verdict(shape, monkeypatch):
    """A credentialed case (bearer profile ``user_a``): its credential refused, or a
    policy block it does not expect, observed nothing of the endpoint."""
    monkeypatch.setenv("DISCO_TOKEN_A", "T")
    expect, status, headers, words = REFUSED[shape]
    _r, [res] = run_one(status_case(expect), {ORDER: Resp(
        status, [b"{}"], headers={"Content-Type": "application/json", **headers})})
    assert res["verdict"] == "error" and words in res["reason"], res


def test_a_credentialed_401_is_credentials_not_accepted_even_where_4xx_is_expected(
        monkeypatch):
    """M1 (flipped pin): a profile that sends a credential and gets 401 tested nothing;
    only ``status_in`` naming 401 judges it."""
    monkeypatch.setenv("DISCO_TOKEN_A", "T")
    _r, [res] = run_one(status_case(["4xx"]), {ORDER: Resp(401, [b"{}"])})
    assert res["verdict"] == "error" and "credentials not accepted" in res["reason"], res


def test_a_credentialed_401_at_a_user_resource_is_credentials_not_accepted(monkeypatch):
    """B1 (review round 3, measured): ``/api/users/42`` names a user, not a credential
    submission -- the account-endpoint test of the login window
    (`browserlogin.account_endpoint_reason`) would call it one and pass the case."""
    monkeypatch.setenv("DISCO_TOKEN_A", "T")
    doc = status_case(["4xx"], endpoint="ep_users", request={"path_params": {"p1": "42"}})
    _r, [res] = run_one(doc, {("GET", "/api/users/42"): Resp(401, [b"{}"])})
    assert res["verdict"] == "error" and "credentials not accepted" in res["reason"], res


@pytest.mark.parametrize("token", ["Bearer forged.token.value", ""],
                         ids=["a forged token", "an empty token"])
def test_a_case_that_replaces_the_credential_is_judged_under_its_expectation(
        token, monkeypatch):
    """Pin (ADOPT 3): a case whose own ``Authorization`` replaces the profile's (D69)
    did not carry the run's credential, so its 401 is the endpoint's answer to the token
    it sent -- an auth-bypass case expecting 4xx passes."""
    monkeypatch.setenv("DISCO_TOKEN_A", "T")
    doc = status_case(["4xx"], request={"path_params": {"p1": "3"},
                                        "headers": {"Authorization": token}})
    _r, [res] = run_one(doc, {ORDER: Resp(401, [b"{}"])})
    assert res["verdict"] == "pass", res


def test_a_credentialed_401_is_judged_where_status_in_names_it(monkeypatch):
    """Pin."""
    monkeypatch.setenv("DISCO_TOKEN_A", "T")
    _r, [res] = run_one(status_case(["2xx"], [{"status_in": [401]}]),
                        {ORDER: Resp(401, [b"{}"])})
    assert res["verdict"] == "finding" and "status_in" in res["matched"], res


def test_a_policy_refusal_is_judged_where_4xx_is_expected(monkeypatch):
    """Pin (coordinator answer 6, any case type)."""
    monkeypatch.setenv("DISCO_TOKEN_A", "T")
    _r, [res] = run_one(status_case(["4xx"]), {ORDER: Resp(403, [b"{}"])})
    assert res["verdict"] == "pass", res


def test_an_anonymous_401_is_the_handlers_answer():
    """Pin (M1): with no credential sent, a 401 is the endpoint's own refusal."""
    _r, [res] = run_one(status_case(["4xx"], auth="anon"), {ORDER: Resp(401, [b"{}"])})
    assert res["verdict"] == "pass", res


def test_a_credentialed_login_redirect_is_an_error_even_where_3xx_is_expected(
        monkeypatch):
    """A2: a redirect to the login page of a credentialed case is its session refused."""
    monkeypatch.setenv("DISCO_TOKEN_A", "T")
    _r, [res] = run_one(status_case(["3xx"]), {ORDER: Resp(
        302, [b""], headers={"Location": "/login"})})
    assert res["verdict"] == "error" and "credentials not accepted" in res["reason"], res


def test_an_anonymous_login_redirect_is_judged_where_3xx_is_expected():
    """Pin (A2)."""
    _r, [res] = run_one(status_case(["3xx"], auth="anon"), {ORDER: Resp(
        302, [b""], headers={"Location": "/login"})})
    assert res["verdict"] == "pass", res


@pytest.mark.parametrize("endpoint,path,body", [
    ("ep_login", "/api/login", {"username": "u"}),
    ("ep_session", "/api/session", {"username": "u", "password": "p"}),
], ids=["a login URL", "a password field"])
def test_a_credential_submissions_own_401_is_its_answer(endpoint, path, body,
                                                       monkeypatch):
    """Pin (A1, M2): submitting credentials -- to an SP-16 login URL, or with a password
    field -- and being refused is the endpoint's answer, never a lost session. Each id
    holds on one rule alone."""
    monkeypatch.setenv("DISCO_TOKEN_A", "T")
    doc = status_case(["4xx"], endpoint=endpoint, request={"body": body})
    _r, [res] = run_one(doc, {("POST", path): Resp(401, [b'{"error": "bad login"}'])})
    assert res["verdict"] == "pass", res


def test_a_gateway_answer_is_judged_by_the_5xx_rule():
    """Pin (M6): the runner may judge a 502 or 504 under its 5xx rule."""
    _r, [res] = run_one(status_case(["4xx"], auth="anon"), {ORDER: Resp(502, [b"{}"])})
    assert res["verdict"] == "finding" and "status_class:5xx" in res["matched"], res


# --- the platform fact, pinned on a loopback socket (§7) ---------------------------------

def _raw_server(script):
    """A loopback server answering each connection with ``script(conn)`` on its own
    thread. Returns (port, stop)."""
    host = require_loopback("127.0.0.1")
    srv = socket.socket()
    srv.bind((host, 0))
    srv.listen(8)
    done = threading.Event()

    def one(conn):
        try:
            conn.recv(65536)
            script(conn, done)
        except OSError:
            pass
        finally:
            conn.close()

    def accept():
        while not done.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=one, args=(conn,), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()

    def stop():
        done.set()
        srv.close()
    return srv.getsockname()[1], stop


HEAD = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"


def _cut_cl(conn, done):
    conn.sendall(HEAD + b"Content-Length: 1000\r\n\r\n" + b'{"items": [1, 2')


def _cut_chunked(conn, done):
    conn.sendall(HEAD + b"Transfer-Encoding: chunked\r\n\r\n20\r\n" + b'{"items": [1, 2')


def _stall(conn, done):
    conn.sendall(HEAD + b"Content-Length: 1000\r\n\r\n" + b'{"items": [')
    done.wait(2.0)


@pytest.mark.parametrize("script", [_cut_cl, _cut_chunked, _stall],
                         ids=["cut Content-Length", "cut chunked", "stalled"])
def test_a_real_200_cut_or_stalled_after_its_headers_is_an_error(script):
    """Measured on requests 2.34 / urllib3 2.8: the status is known when iterating the
    body raises (ChunkedEncodingError for a cut, ConnectionError(ReadTimeoutError) for a
    stall). The runner must not judge what it read."""
    port, stop = _raw_server(script)
    try:
        doc = {"contract_version": "1.0",
               "run": {"id": "r", "target": {"base_url": f"http://127.0.0.1:{port}/",
                                             "scope_allowlist": [f"127.0.0.1:{port}"]},
                       "limits": {"rps": 1000, "timeout_ms": 300, "max_body_bytes": 65536},
                       "reset_hook": None},
               "auth_profiles": [{"id": "anon", "kind": "none"}],
               "endpoints": [{"id": "ep_1", "method": "GET", "path": "/api/items"}],
               "test_cases": [{"id": "tc_1", "endpoint": "ep_1", "class": "type",
                               "auth_profile": "anon", "request": {},
                               "oracle": {"expect_status_class": ["2xx"], "findings_if": []},
                               "safety": {"destructive": False}}],
               "results": []}
        r = Runner(Contract(doc), authorized=True)
        t0 = time.monotonic()
        [res] = r.run()
        assert time.monotonic() - t0 < 30                 # a smoke bound only (PA-0526)
        assert res["status"] == 200 and res["verdict"] == "error", res
        assert r._baseline("ep_1") is None
    finally:
        stop()
