"""Non-comparable controls (CC-FUZZ-0105, FR-FUZZ-63; also CC-MUT-0403's live filter;
AU-OUTCOME; audit defect 17, the oracle half; BUG-0529; draft
`docs/components/07-fuzzing-harness-and-oracle/DRAFT-AU-OUTCOME.md`).

A confirmation that rests on a control or a baseline (a signature absent from a benign
control, a slot of a differential, a timing baseline) holds only when that control got
the application's own answer. A throttle or unavailable server, a timeout, a gateway, a
refused credential, a policy block or a redirect to the login page proves nothing about
the probe: the candidate is inconclusive, never confirmed and never a negative.

Each test drives the real strategy through the real `Oracle.confirm_outcome` with a
scripted sender (or the real `RequestsProbeSender` over a fake session). A scripted
probe says nothing of its credential, so it counts as carrying the run's credential
(fail closed). Written first (Phase 1): each test that asserts the new behaviour fails
on 8100959 for its stated reason; the tests marked "pin" pass there and must keep
passing."""

from __future__ import annotations

import ast
import inspect
import json
import textwrap
import types

import pytest
import requests

from fuzzlab.oracle import Oracle
from fuzzlab.oracle.probe import PRG_UNOBSERVED, Candidate, Probe
from fuzzlab.oracle.strategies import (CrossAccountReplayStrategy,
                                       GreyboxConfirmationStrategy,
                                       HttpHeaderInjectionCrlfStrategy, NoSqlOperatorStrategy,
                                       PathTraversalFsPathReadStrategy, PathTraversalStrategy,
                                       PeerAccounts, ReflectedXssStrategy, RegexDosStrategy,
                                       SqliBooleanStrategy, SqliErrorStrategy,
                                       SqliTimingStrategy)

HOST = "http://127.0.0.1:9"


class Script:
    """A target answering each probe by its value (a bound form point's value is read
    from its entries, as the real senders place it)."""

    def __init__(self, answer):
        self.answer, self.sent = answer, []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        if entries is not None and location != "json":
            value = dict(entries).get(param, value)
        self.sent.append(value)
        return self.answer(value, timing)


def outcome(strategy, candidate, sender, **oracle_kw):
    """(confirmed?, inconclusive?) as the pipeline reads `confirm_outcome`."""
    verdict, unsure = Oracle(strategies=[strategy], **oracle_kw).confirm_outcome(
        candidate, sender)
    return verdict is not None and verdict.confirmed, unsure is not None


#: Answers that are not the application's answer to the value sent.
NOT_THE_APPLICATIONS = {
    "a throttle (429)": lambda: Probe(429, "Too Many Requests: rate limited", 0.0),
    "unavailable (503, Retry-After)": lambda: Probe(503, "busy", 0.0,
                                                    headers={"Retry-After": "30"}),
    "unavailable (503)": lambda: Probe(503, "Service Temporarily Unavailable", 0.0),
    "a gateway (502)": lambda: Probe(502, "Bad Gateway", 0.0),
    "a gateway (504)": lambda: Probe(504, "Gateway Timeout", 0.0),
    "a timeout (the plain sender's status 0)": lambda: Probe(0, "", 10.0),
    "credentials refused (401)": lambda: Probe(401, "Unauthorized", 0.0),
    "a redirect to the login page": lambda: Probe(302, "", 0.0,
                                                  headers={"Location": "/login"}),
    "a lowercase location to the login page": lambda: Probe(302, "", 0.0,
                                                            headers={"location": "/login"}),
    "a policy block (403)": lambda: Probe(403, "Forbidden", 0.0),
}

SQL_ERROR = "<p>You have an error in your SQL syntax; check the manual near ''''</p>"
PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"


def _sqli(control):
    def answer(value, timing):
        if value.startswith(("fz", "1fz")):                   # `_sqli_token` controls
            return control()
        return Probe(500, SQL_ERROR, 0.0)
    return SqliErrorStrategy(), Candidate(f"{HOST}/items", "q", category="sql-injection"), \
        Script(answer)


def _traversal(cls):
    def make(control):
        def answer(value, timing):
            return control() if value == "passwd" else Probe(200, PASSWD, 0.0)
        return cls(), Candidate(f"{HOST}/clips/export", "filename",
                                category=cls.category), Script(answer)
    return make


def _crlf(control):
    def answer(value, timing):
        if "\r\n" not in value:
            return control()
        name, _sep, token = value.split("\r\n", 1)[1].partition(": ")
        return Probe(302, "", 0.0, headers={"Location": "fuzzlab-ok", name: token})
    return HttpHeaderInjectionCrlfStrategy(), Candidate(
        f"{HOST}/channels/redirect", "destination", category="http-header-injection"), \
        Script(answer)


SIGNATURE_STRATEGIES = {
    "SqliErrorStrategy": _sqli,
    "PathTraversalStrategy": _traversal(PathTraversalStrategy),
    "PathTraversalFsPathReadStrategy": _traversal(PathTraversalFsPathReadStrategy),
    "HttpHeaderInjectionCrlfStrategy": _crlf,
}


@pytest.mark.parametrize("control", sorted(NOT_THE_APPLICATIONS))
@pytest.mark.parametrize("name", sorted(SIGNATURE_STRATEGIES))
def test_a_signature_absent_from_a_control_that_is_not_the_applications_never_confirms(
        name, control):
    """Audit 17 (reproduced for SQLi: a quote's SQL error, then ``429 rate limited`` for
    the benign control, confirms). The PA-0002 sweep: every strategy whose control's
    *missing* marker is its evidence."""
    strategy, candidate, sender = SIGNATURE_STRATEGIES[name](NOT_THE_APPLICATIONS[control])
    assert outcome(strategy, candidate, sender) == (False, True)


@pytest.mark.parametrize("control", [
    lambda: Probe(200, "<p>No results</p>", 0.0),
    lambda: Probe(404, "not found", 0.0),
], ids=["a 200 page", "a 404"])
@pytest.mark.parametrize("name", sorted(SIGNATURE_STRATEGIES))
def test_an_application_answer_to_the_control_still_confirms(name, control):
    """Pin: the vulnerable path-traversal twin answers the ``passwd`` control with 404
    "not found" (`go_net_http/templates/sinks/unconfined_path.go.j2`)."""
    strategy, candidate, sender = SIGNATURE_STRATEGIES[name](control)
    assert outcome(strategy, candidate, sender) == (True, False)


def test_a_login_endpoints_own_401_is_its_answer_and_still_confirms():
    """Pin, measured shape: Juice Shop's login answers a failed login with ``401
    Invalid email or password.`` and a quote with ``500 SQLITE_ERROR``
    (`tests/test_json_points.py::JsonLoginApp`). A 401 from an SP-16 login URL is that
    endpoint's answer, not a lost session."""
    def answer(value, timing):
        if value.startswith(("fz", "1fz")):
            return Probe(401, "Invalid email or password.", 0.0)
        return Probe(500, '{"error":{"message":"SQLITE_ERROR: unrecognized token: \\"\'\\""}}',
                     0.0)
    candidate = Candidate(f"{HOST}/rest/user/login", "email", category="sql-injection")
    assert outcome(SqliErrorStrategy(), candidate, Script(answer)) == (True, False)


@pytest.mark.parametrize("url,field,entries,control", [
    ("/j_security_check", "j_username", (("j_username", "a"), ("j_password", "x")),
     lambda: Probe(302, "", 0.0, headers={"Location": "/login?error"})),
    ("/register", "username", (("username", "a"), ("email", "a@lab.test")),
     lambda: Probe(302, "", 0.0, headers={"Location": "/login"})),
    ("/api/authenticate", "username", (("username", "a"), ("password", "x")),
     lambda: Probe(401, '{"error": "bad credentials"}', 0.0)),
], ids=["a password field (j_security_check)", "an account endpoint (register)",
        "a password field (api/authenticate, 401)"])
def test_a_credential_submissions_own_refusal_is_its_answer_and_still_confirms(
        url, field, entries, control):
    """Pin (M2, reviewer A's measured shapes): a credential submission is never a
    session loss -- a password field among the point's entries, or a path naming account
    creation or a password reset (`session.detect.CREDENTIAL_PATH_TOKENS`, B1), or an
    SP-16 login URL. Each id holds on one rule alone (none of these URLs is an SP-16
    login URL)."""
    def answer(value, timing):
        return control() if value.startswith(("fz", "1fz")) else Probe(500, SQL_ERROR, 0.0)
    candidate = Candidate(f"{HOST}{url}", field, method="POST", location="body",
                          category="sql-injection", base_entries=entries)
    assert outcome(SqliErrorStrategy(), candidate, Script(answer)) == (True, False)


def test_a_json_points_password_leaf_makes_its_refusal_the_endpoints_answer():
    """Pin (ADOPT 1, reviewer B): a JSON point's entries are named by path tuples; the
    password leaf is read by its `jsonbody.display_name` (`is_credential_name` takes a
    string: a tuple raised TypeError, measured). ``/api/session`` is no login URL and
    names no account endpoint: the leaf alone makes it a credential submission."""
    def answer(value, timing):
        return Probe(401, '{"error": "bad credentials"}', 0.0) \
            if value.startswith(("fz", "1fz")) else Probe(500, SQL_ERROR, 0.0)
    candidate = Candidate(f"{HOST}/api/session", "email", method="POST", location="json",
                          category="sql-injection",
                          base_entries=((("email",), "a@b.co"), (("password",), "x")))
    assert outcome(SqliErrorStrategy(), candidate, Script(answer)) == (True, False)


# --- the per-probe credential (M2; the approved `tools/probesender.py` lines) ------------

class _Refusing:
    """A `requests` session for the real `RequestsProbeSender`: the benign control
    answers 401, a quote answers with a SQL error."""
    cookies = None

    def request(self, method, url, **kw):
        if str((kw.get("params") or {}).get("q", "")).startswith(("fz", "1fz")):
            return types.SimpleNamespace(status_code=401, text="Unauthorized", headers={})
        return types.SimpleNamespace(status_code=500, text=SQL_ERROR, headers={})


def test_the_anonymous_plain_senders_401_is_the_applications_answer():
    """Pin (M2): `RequestsProbeSender` sends no credential (it clears its jar before
    every send), and says so on each probe, so a 401 to its control is the endpoint's
    own answer, not a refused credential."""
    from fuzzlab.tools.probesender import RequestsProbeSender
    sender = RequestsProbeSender(session=_Refusing(), timeout=1.0)
    candidate = Candidate(f"{HOST}/items", "q", category="sql-injection")
    assert outcome(SqliErrorStrategy(), candidate, sender) == (True, False)


def _refusing_transport(method, url, headers, body, timeout):
    from urllib.parse import parse_qs, urlsplit
    value = parse_qs(urlsplit(url).query).get("q", [""])[0]
    if value.startswith(("fz", "1fz")):
        return 401, {"Content-Type": "text/html"}, b"Unauthorized"
    return 500, {"Content-Type": "text/html"}, SQL_ERROR.encode()


@pytest.mark.parametrize("identity,expected", [
    ("anonymous", (True, False)), ("alice", (False, True))],
    ids=["anonymous: the endpoint's answer", "a session: its credential refused"])
def test_a_seam_senders_probe_says_whether_it_carried_a_credential(identity, expected):
    """M2: the seam sender's probe carries ``credentialed`` -- False for an anonymous
    send (or one whose session the manager withheld), True for an identity's send -- so
    the same 401 to a control is the endpoint's answer or a refused credential."""
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient
    from fuzzlab.tools.probesender import SeamProbeSender
    client = HttpClient(RequestBudget(100), ["127.0.0.1"], transport=_refusing_transport)
    sender = SeamProbeSender(client, identity)
    candidate = Candidate(f"{HOST}/items", "q", category="sql-injection")
    assert outcome(SqliErrorStrategy(), candidate, sender) == expected


def test_a_follow_up_carries_its_requests_credential_fact():
    """A PRG follow-up is sent by the same sender as its request: an uncredentialed
    request's follow-up answered 401 is the application's answer (the control observed
    alike, without the signature), not a refused credential."""
    def answer(value, timing):
        if value.startswith(("fz", "1fz")):
            return Probe(303, "", 0.0, headers={"Location": "/items"}, prg="observed",
                         credentialed=False,
                         followed=Probe(401, "Unauthorized", 0.0, url=f"{HOST}/items"))
        return _prg(Probe(200, SQL_ERROR, 0.0, url=f"{HOST}/items"))
    candidate = Candidate(f"{HOST}/items", "q", method="POST", location="body",
                          category="sql-injection")
    assert outcome(SqliErrorStrategy(), candidate, Script(answer)) == (True, False)


# --- PRG follow-ups (FR-FUZZ-49) ---------------------------------------------------------

def _prg(followed):
    return Probe(303, "", 0.0, headers={"Location": "/items"}, prg="observed",
                 followed=followed)


@pytest.mark.parametrize("follow_up", [
    lambda: Probe(429, "rate limited", 0.0, url=f"{HOST}/items"),
    lambda: Probe(401, "Unauthorized", 0.0, url=f"{HOST}/items"),
    lambda: Probe(403, "Forbidden", 0.0, url=f"{HOST}/items"),
    lambda: Probe(502, "Bad Gateway", 0.0, url=f"{HOST}/items"),
], ids=["429", "401", "403", "502"])
def test_a_controls_prg_follow_up_that_is_not_the_applications_never_confirms(follow_up):
    """A signature seen through a PRG follow-up needs the control's own follow-up; one
    that is not the application's answer is no observation of it. The 401, 403 and 502
    are seen only by the control rule (layer 2), never by layer 1. (A follow-up answered
    by a redirect -- to a login page or anywhere -- is never a ``followed`` probe: the
    senders record it as ``PRG_UNOBSERVED``, below; ADOPT 6.)"""
    def answer(value, timing):
        if value.startswith(("fz", "1fz")):
            return _prg(follow_up())
        return _prg(Probe(200, SQL_ERROR, 0.0, url=f"{HOST}/items"))
    candidate = Candidate(f"{HOST}/items", "q", method="POST", location="body",
                          category="sql-injection")
    assert outcome(SqliErrorStrategy(), candidate, Script(answer)) == (False, True)


def _unobserved_follow_up():
    return Probe(303, "", 0.0, headers={"Location": "/items"}, prg=PRG_UNOBSERVED)


@pytest.mark.parametrize("name", ["SqliErrorStrategy", "PathTraversalStrategy",
                                  "PathTraversalFsPathReadStrategy"])
def test_a_control_whose_follow_up_got_no_observation_is_inconclusive(name):
    """M4 (reviewers A and B, measured): the control's follow-up was sent but got no
    observation (``PRG_UNOBSERVED``); today that is a negative. The three strategies
    that read a control through PRG (`strategies.py:491, :1188, :1267`)."""
    strategy, candidate, _s = SIGNATURE_STRATEGIES[name](_unobserved_follow_up)
    positive = Probe(200, SQL_ERROR if name == "SqliErrorStrategy" else PASSWD, 0.0,
                     url=candidate.url)
    control = "fz" if name == "SqliErrorStrategy" else "passwd"

    def answer(value, timing):
        if value.startswith(control) or value.startswith("1fz"):
            return _unobserved_follow_up()
        return Probe(303, "", 0.0, headers={"Location": "/x"}, prg="observed",
                     followed=positive)
    candidate = Candidate(candidate.url, candidate.param, method="POST", location="body",
                          category=candidate.category)
    assert outcome(strategy, candidate, Script(answer)) == (False, True)


def test_a_payload_whose_follow_up_got_no_observation_is_inconclusive():
    """M4 as narrowed by B2: the payloads' own follow-ups got no observation; each
    payload's own response is still read and every payload runs, and a run that then
    decides nothing is not comparable, never a negative."""
    candidate = Candidate(f"{HOST}/items", "q", method="POST", location="body",
                          category="sql-injection")
    sender = Script(lambda v, t: _unobserved_follow_up())
    assert outcome(SqliErrorStrategy(), candidate, sender) == (False, True)
    assert sender.sent == list(SqliErrorStrategy._probes)       # every payload ran


@pytest.mark.parametrize("name", ["SqliErrorStrategy", "PathTraversalStrategy",
                                  "PathTraversalFsPathReadStrategy"])
def test_a_direct_signature_with_a_control_whose_follow_up_got_none_still_confirms(name):
    """Pin (B2, reviewer B): the payload showed its signature in its own response, so no
    control's follow-up is needed -- the control's own answer (no signature) decides. A
    true positive today for all three; a rule that raised on any unobserved follow-up
    lost it."""
    strategy, candidate, _s = SIGNATURE_STRATEGIES[name](_unobserved_follow_up)
    positive = Probe(500, SQL_ERROR, 0.0) if name == "SqliErrorStrategy" else \
        Probe(200, PASSWD, 0.0)
    control = "fz" if name == "SqliErrorStrategy" else "passwd"

    def answer(value, timing):
        if value.startswith(control) or value.startswith("1fz"):
            return _unobserved_follow_up()
        return positive
    candidate = Candidate(candidate.url, candidate.param, method="POST", location="body",
                          category=candidate.category)
    assert outcome(strategy, candidate, Script(answer)) == (True, False)


def test_a_control_showing_the_signature_is_a_negative_whatever_its_follow_up():
    """Pin (B2): the control's own answer already shows the SQL error, so the signature
    is not the quote's -- a real negative; that the control's follow-up got no
    observation changes nothing (only a payload's unobserved follow-up makes a final
    None not comparable)."""
    def answer(value, timing):
        if value.startswith(("fz", "1fz")):
            return Probe(303, SQL_ERROR, 0.0, headers={"Location": "/items"},
                         prg=PRG_UNOBSERVED)
        return Probe(500, SQL_ERROR, 0.0)
    candidate = Candidate(f"{HOST}/items", "q", method="POST", location="body",
                          category="sql-injection")
    assert outcome(SqliErrorStrategy(), candidate, Script(answer)) == (False, False)


# --- cross-account replay: the other value is its control, the replays its evidence -----

_ALICES = lambda: Script(lambda v, t: Probe(200, "record of alice: secret", 0.0))  # noqa


def _cross(control, accounts=None, path="/record"):
    owner = Script(lambda v, t: Probe(200, "record of alice: secret", 0.0)
                   if v == "r-alice-1" else control())
    accounts = accounts or PeerAccounts(sender=_ALICES(), owner="alice", peer_name="bob")
    candidate = Candidate(f"{HOST}{path}", "record_id", category="access-control",
                          base_entries=(("record_id", "r-alice-1"),))
    return CrossAccountReplayStrategy(accounts), candidate, owner


@pytest.mark.parametrize("control", sorted(set(NOT_THE_APPLICATIONS)
                                           - {"a policy block (403)"}))
def test_a_cross_account_control_that_is_not_the_applications_never_confirms(control):
    """The owner's request with another value must show it is not the owner's view
    whatever the value (a banner page). A throttled or logged-out answer cannot."""
    assert outcome(*_cross(NOT_THE_APPLICATIONS[control])) == (False, True)


def test_a_cross_account_control_the_app_itself_denies_still_confirms():
    """Pin, declared by the strategy: an app's own 403 for an id that is not the owner's
    is its answer (an API that hides foreign ids)."""
    assert outcome(*_cross(lambda: Probe(403, "forbidden", 0.0))) == (True, False)


NOT_FOUND = lambda: Probe(404, "not found", 0.0)                       # noqa: E731


def _replays(peer=None, anonymous=None):
    return PeerAccounts(sender=peer, owner="alice", peer_name="bob", anonymous=anonymous)


@pytest.mark.parametrize("accounts", [
    lambda: _replays(peer=Script(lambda v, t: Probe(429, "rate limited", 0.0))),
    lambda: _replays(peer=Script(lambda v, t: Probe(401, "Unauthorized", 0.0))),
    lambda: _replays(anonymous=Script(lambda v, t: Probe(0, "", 15.0))),
    lambda: _replays(peer=Script(lambda v, t: Probe(502, "Bad Gateway", 0.0))),
    lambda: _replays(anonymous=Script(lambda v, t: Probe(504, "Gateway Timeout", 0.0))),
], ids=["the peer is throttled", "the peer's credential is refused",
        "the unauthenticated replay times out", "the peer gets a gateway (502)",
        "the unauthenticated replay gets a gateway (504)"])
def test_a_replay_that_is_not_the_applications_is_inconclusive_never_a_negative(accounts):
    """M5 (reviewer B, measured: today a negative), and ADOPT 4's gateway rows: each
    replay is compared (`_compared`, application or policy answers only); a credentialed
    peer's refused credential is not a denial of the owner's object, and an
    intermediary's 502/504 denies nothing."""
    assert outcome(*_cross(NOT_FOUND, accounts())) == (False, True)


def test_a_peer_replay_refused_at_an_account_resource_is_inconclusive():
    """B1 (review round 3, the Netflix-clone BOLA shape): ``/api/account/billing`` names
    an account resource, not a credential submission, so the peer's 401 is its refused
    credential -- the account-endpoint test of the login window would have called the
    replay a credential submission and the 401 a real denial (a negative)."""
    accounts = _replays(peer=Script(lambda v, t: Probe(401, "Unauthorized", 0.0)))
    assert outcome(*_cross(NOT_FOUND, accounts, path="/api/account/billing")) == \
        (False, True)


def test_an_unauthenticated_replay_refused_with_401_is_a_real_negative():
    """Pin (M5): with no credential sent, a 401 is the endpoint's own denial."""
    accounts = _replays(anonymous=Script(lambda v, t: Probe(401, "Unauthorized", 0.0)))
    assert outcome(*_cross(NOT_FOUND, accounts)) == (False, False)


# --- differentials: every slot compared --------------------------------------------------

def _boolean(base, disc):
    """The numeric family: B ``1``, V ``1 AND 1=1``, D ``1 AND 1=2``."""
    def answer(value, timing):
        return disc() if "1=2" in value else base()
    return SqliBooleanStrategy(), Candidate(f"{HOST}/items", "id",
                                            category="sql-injection"), Script(answer)


PAGE = "<html>" + "<li>item</li>" * 30 + "</html>"
LONG_500 = lambda: Probe(500, "E" * 300, 0.0)                         # noqa: E731


@pytest.mark.parametrize("base", ["a throttle (429)",
                                  "a timeout (the plain sender's status 0)",
                                  "credentials refused (401)",
                                  "a redirect to the login page"])
def test_a_differential_whose_baseline_and_variant_are_not_the_applications_never_confirms(
        base):
    """B0, V and the re-sent B are the controls of the bracketed engine. The 401 and the
    login redirect reach only the control rule (layer 2): they fail on its revert."""
    assert outcome(*_boolean(NOT_THE_APPLICATIONS[base], LONG_500)) == (False, True)


def test_a_differential_whose_d_is_a_refused_credential_never_confirms():
    """D admits application and policy answers only; a 401 to D is the run's credential
    refused, not the database's answer."""
    assert outcome(*_boolean(lambda: Probe(200, PAGE, 0.0),
                             NOT_THE_APPLICATIONS["credentials refused (401)"])) == \
        (False, True)


def test_a_differential_whose_d_the_app_denies_still_confirms():
    """Pin, declared: SQL families' V and D carry the same characters, so a policy
    filter cannot single D out; an app that answers a false condition with 403 is
    evaluating it."""
    assert outcome(*_boolean(lambda: Probe(200, PAGE, 0.0),
                             lambda: Probe(403, "Forbidden", 0.0))) == (True, False)


def test_a_nosql_differential_whose_operator_probe_is_blocked_never_confirms():
    """D (``$ne``) and V (``$in``) differ in the operator's name: a filter that blocks
    ``$ne`` answers D alone, every round. Layer 2 only (a 403 is not layer 1's)."""
    entries = ((("email",), "a@b.co"), (("password",), "x"))

    def answer(value, timing):
        body = json.loads(value)
        if isinstance(body.get("email"), dict) and "$ne" in body["email"]:
            return Probe(403, "Forbidden", 0.0)
        return Probe(200, "Bad Credentials", 0.0)
    candidate = Candidate(f"{HOST}/login", "email", method="POST", location="json",
                          category="nosql-injection", base_entries=entries)
    assert outcome(NoSqlOperatorStrategy(), candidate, Script(answer)) == (False, True)


# --- timing baselines --------------------------------------------------------------------

@pytest.mark.parametrize("base", ["a throttle (429)", "credentials refused (401)",
                                  "a redirect to the login page", "a policy block (403)"])
def test_a_redos_baseline_that_is_not_the_applications_never_confirms(base):
    """A fast refusal (2 ms) as the baseline makes ordinary 60 ms answers look 30x
    slower. The 401, login redirect and 403 rows reach only the sample rule (layer 2)."""
    def answer(value, timing):
        if value == RegexDosStrategy.benign_probe:
            refusal = NOT_THE_APPLICATIONS[base]()
            refusal.elapsed = 0.002
            return refusal
        return Probe(200, "results", 0.06)
    candidate = Candidate(f"{HOST}/search", "pattern", category="regular-expression")
    assert outcome(RegexDosStrategy(), candidate, Script(answer)) == (False, True)


def _timed_out(kind):
    probe = Probe(0, "", 10.0)
    if kind:
        probe.timeout = kind            # set after construction: no new keyword needed
    return probe


@pytest.mark.parametrize("kind", [None, "read"],
                         ids=["a stand-in of no stated kind", "a read timeout"])
def test_a_timing_baseline_that_timed_out_is_inconclusive_never_a_negative(kind):
    """PA-0137(4): a baseline that was never observed decides nothing. A read timeout
    is latency evidence for a payload (layer 1 keeps it), never a baseline sample: that
    row reaches only the sample rule (layer 2)."""
    def answer(value, timing):
        return _timed_out(kind) if value == "1" else Probe(200, "ok", 0.05)
    candidate = Candidate(f"{HOST}/items", "id", category="sql-injection")
    assert outcome(SqliTimingStrategy(), candidate, Script(answer)) == (False, True)


class _Timeouts:
    """A `requests` session for the real `RequestsProbeSender`: the benign value answers
    at once, every other value raises ``exc``."""
    cookies = None

    def __init__(self, exc):
        self.exc = exc

    def request(self, method, url, **kw):
        if (kw.get("params") or {}).get("pattern") == RegexDosStrategy.benign_probe:
            return types.SimpleNamespace(status_code=200, text="results", headers={})
        raise self.exc


@pytest.mark.parametrize("exc,expected", [
    (requests.ConnectTimeout(), (False, True)),
    (requests.ReadTimeout(), (True, False)),
], ids=["a connect timeout is no latency", "pin: a read timeout is"])
def test_only_a_read_timeout_is_latency_evidence(exc, expected):
    """M7 (reviewer B, measured: `_is_timeout(ConnectTimeout())` is True). Through the
    real `RequestsProbeSender`, a connect timeout is a status-0 probe of the full timeout,
    which ReDoS reads as a 1 s delay; no request reached the server."""
    from fuzzlab.tools.probesender import RequestsProbeSender
    sender = RequestsProbeSender(session=_Timeouts(exc), timeout=1.0)
    candidate = Candidate(f"{HOST}/search", "pattern", category="regular-expression")
    assert outcome(RegexDosStrategy(), candidate, sender) == expected


def test_a_throttled_probe_is_no_observation_never_a_negative():
    """Every response a mechanism reads: a 429 to its first probe ends it, unobserved."""
    candidate = Candidate(f"{HOST}/search", "q", category="xss")
    sender = Script(lambda v, t: Probe(429, "rate limited", 0.0))
    assert outcome(ReflectedXssStrategy(), candidate, sender) == (False, True)


# --- greybox: the correlated send is read too (A5) ---------------------------------------

def test_a_throttled_correlated_probe_is_inconclusive_never_a_negative():
    """A throttled correlated probe never reached the sink, so no coverage is no
    evidence of a secure point."""
    from fuzzlab.greybox.coverage import InMemoryCoverageSource

    class Correlating(Script):
        def send_correlated(self, url, param, value, *, method="GET", location="query"):
            return Probe(429, "rate limited", 0.0), "cid-1"
    strategy = GreyboxConfirmationStrategy(coverage=InMemoryCoverageSource({}))
    candidate = Candidate(f"{HOST}/item.php", "id", category="sql-injection")
    sender = Correlating(lambda v, t: Probe(200, "ok", 0.0))
    assert outcome(strategy, candidate, sender) == (False, True)


# --- the scheduler: a non-comparable run charges cost, never a success estimate (A7) ----

class RecordingScheduler:
    def __init__(self):
        self.updates, self.charges = [], []

    def order(self, ctx, arms):
        return list(arms)

    def update(self, ctx, arm, reward, cost=1.0):
        self.updates.append((arm, reward, cost))

    def charge(self, ctx, arm, cost=1.0):
        self.charges.append((arm, cost))


def test_a_non_comparable_run_charges_its_cost_and_leaves_the_arms_estimate():
    strategy, candidate, sender = _sqli(NOT_THE_APPLICATIONS["a throttle (429)"])
    sched = RecordingScheduler()
    result = outcome(strategy, candidate, sender, scheduler=sched)
    assert sched.updates == [], sched.updates             # no success estimate moved
    assert [arm for arm, _c in sched.charges] == [strategy.arm]
    assert sched.charges[0][1] >= 2                       # the probe and its control
    assert result == (False, True)


# --- the live WAF filter (CC-MUT-0403, M11) ----------------------------------------------

BLOCKED = "1 union select 1"


class _WafSender:
    """Blocks exactly `BLOCKED` (403); answers every other value with ``other``."""

    def __init__(self, other):
        self.other = other

    def send(self, url, param, value, method="GET", location="query", **kw):
        if value == BLOCKED:
            return Probe(403, "Request blocked: sqli-union-select", 0.0)
        return self.other()


@pytest.mark.parametrize("other,words", [
    (lambda: Probe(429, "rate limited", 0.0), "throttle"),
    (lambda: Probe(0, "", 10.0), "incomplete"),
], ids=["429", "status 0"])
def test_a_live_filter_never_reads_a_non_observation_as_allowed(other, words):
    """M11 (sweep miss): `livefilter` read every non-403 as "allow", so the WAF learner
    recorded a bypass for a throttled or unanswered variant."""
    from fuzzlab.mutation.livefilter import HttpFilter
    flt = HttpFilter(_WafSender(other), f"{HOST}/search.php", "q")
    with pytest.raises(Exception, match=words):
        flt.caught("harmless")
    with pytest.raises(Exception, match=words):
        flt.evaluate("harmless")


def test_a_throttled_variant_is_never_an_evasion():
    from fuzzlab.mutation.livefilter import HttpFilter
    from fuzzlab.mutation.search import MutationSearch
    flt = HttpFilter(_WafSender(lambda: Probe(429, "rate limited", 0.0)),
                     f"{HOST}/search.php", "q")
    with pytest.raises(Exception, match="throttle"):
        MutationSearch(flt, seed=0, budget=10).search(BLOCKED, "sql-injection")


# --- the blind SQLi dataset builder: no non-application sample is a timing label (A4) ---

class _Sample(tuple):
    """``(latency, status, size)`` as `get()` returns it, plus the answer's headers."""

    def __new__(cls, latency, status, size, headers=None):
        self = super().__new__(cls, (latency, status, size))
        self.headers = dict(headers or {})
        return self


class _Get:
    def __init__(self, answers):
        self.answers = answers

    def get(self, url, param, value, timeout):
        return self.answers(str(value))


def _alternating(other):
    calls = iter(range(100))
    return _Get(lambda v: other() if next(calls) % 2 else _Sample(0.3, 200, 5000))


@pytest.mark.parametrize("other", [
    lambda: _Sample(0.002, 429, 12),
    lambda: _Sample(0.002, 302, 0, {"Location": "/login"}),
    lambda: _Sample(0.002, 502, 0),
], ids=["429", "a redirect to the login page", "502"])
def test_a_blind_sqli_baseline_never_averages_a_non_application_sample(other):
    from fuzzlab.tools.blind_sqli_fuzzer import establish_baseline
    base = establish_baseline(_alternating(other), f"{HOST}/item", "id", 10, 5)
    assert base["samples"] == 5 and base["avg_time"] == pytest.approx(0.3), base


def test_a_blind_sqli_baseline_of_throttled_samples_is_not_comparable():
    """A4: "could not reach the target" is wrong when every sample was answered."""
    from fuzzlab.tools.blind_sqli_fuzzer import establish_baseline
    with pytest.raises(Exception, match="not comparable"):
        establish_baseline(_Get(lambda v: _Sample(0.002, 429, 12)), f"{HOST}/item", "id",
                           10, 5)


def _cycle(answer):
    from fuzzlab.tools.blind_sqli_fuzzer import run_fuzzing_cycle
    args = types.SimpleNamespace(sigma=3.0, min_delay=2.0, repeats=2, timeout=5, pause=0)
    base = {"avg_time": 0.3, "std_dev_time": 0.01, "avg_size": 5000, "samples": 10}
    payloads = [{"text": "1' AND SLEEP(5)-- -", "family": "time", "is_malicious": 1,
                 "expected_delay": 5}]
    return run_fuzzing_cycle(_Get(lambda v: answer()), f"{HOST}/item", "id", base,
                             payloads, args)


@pytest.mark.parametrize("answer", [lambda: _Sample(0.002, 429, 12),
                                    lambda: _Sample(0.002, 403, 30)], ids=["429", "403"])
def test_a_blind_sqli_payload_not_answered_by_the_application_is_never_a_row(answer):
    assert _cycle(answer) == []


def test_a_blind_sqli_payload_answered_504_stays_a_timing_observation():
    """Pin (A4): a gateway that timed out waiting for a sleeping query observed its
    latency; the baseline skips a 504, the payload keeps it."""
    rows = _cycle(lambda: _Sample(5.2, 504, 0))
    assert len(rows) == 1 and rows[0]["time_delay_detected"] == 1


# --- the discovery table and the send guard (M9; PA-0529(4)) ----------------------------

#: How every default strategy reads its controls (FR-FUZZ-63): (kind, reason). A
#: control reader's kind names which sends the send guard checks.
CONTROL_READING = {
    "SqliErrorStrategy": ("negative-control", "the signature must be absent from a "
                          "compared benign control"),
    "SqliBooleanStrategy": ("differential", "B0, V and B are controls; D admits policy"),
    "SqliEvaluationMarkerStrategy": ("positive", "two evaluated markers; layer 1"),
    "SqliTimingStrategy": ("timing-baseline", "`_confirm_timing`'s samples"),
    "NoSqlOperatorStrategy": ("differential", "B, V and D, application only"),
    "ReflectedXssStrategy": ("positive", "a reflected marker; layer 1"),
    "DomXssStrategy": ("browser", "the browser executes; no HTTP control"),
    "StoredXssStrategy": ("browser", "the browser executes; no HTTP control"),
    "OpenRedirectStrategy": ("positive", "the raw redirect is the evidence; layer 1"),
    "SstiStrategy": ("positive", "an evaluated product; an absence disqualifies"),
    "GoTemplateSstiStrategy": ("positive", "an evaluated marker; an absence disqualifies"),
    "SpelInjectionStrategy": ("positive", "an evaluated product; an absence disqualifies"),
    "PriceIntegrityBypassStrategy": ("positive", "a canary in the answer; layer 1"),
    "CsvFormulaInjectionStrategy": ("positive", "a formula in the export; layer 1"),
    "PathTraversalStrategy": ("negative-control", "the marker must be absent from a "
                              "compared control"),
    "CommandInjectionStrategy": ("timing-baseline", "`_confirm_timing`'s samples"),
    "CommandInjectionOobStrategy": ("callback", "an OOB callback; layer 1 waits"),
    "RegexDosStrategy": ("timing-baseline", "its own baseline samples"),
    "SsrfInBandMarkerStrategy": ("positive", "an HMAC proof; layer 1"),
    "SsrfOobStrategy": ("callback", "an OOB callback; layer 1 waits"),
    "CrossAccountReplayStrategy": ("replay", "the owner's request, the other-value "
                                   "control and every replay are compared"),
    "AccessControlIdorStrategy": ("positive", "two ids' own data; layer 1"),
    "InsecureDeserializationTypeConfusionStrategy": ("positive", "two positive answers"),
    "XxeInBandMarkerStrategy": ("positive", "an HMAC proof; layer 1"),
    "XxeOobStrategy": ("callback", "an OOB callback; layer 1 waits"),
    "JwtAlgNoneConfusionStrategy": ("rejection-control", "its control's rejection "
                                    "(401/403) is the evidence; status guard allowance"),
    "PredictableTokenSourceStrategy": ("positive", "two positive answers"),
    "MassAssignmentPrivilegedFieldStrategy": ("positive", "two positive answers"),
    "UnrestrictedFileUploadContentTypeTrustStrategy": ("positive", "positive answers"),
    "PriceTrustDifferentialStrategy": ("positive", "two positive answers"),
    "HttpHeaderInjectionCrlfStrategy": ("negative-control", "the header must be absent "
                                        "from a compared control"),
    "PathTraversalFsPathReadStrategy": ("negative-control", "the marker must be absent "
                                        "from a compared control"),
    "GreyboxConfirmationStrategy": ("positive", "coverage through `send_correlated`; "
                                    "layer 1"),
}
#: The kinds whose sends the guard checks, and the shared engines each one runs.
CONTROL_READERS = {"negative-control": (), "differential": ("_differential",),
                   "timing-baseline": ("_confirm_timing",), "replay": ()}
_SEND_NAMES = frozenset({"_send", "send", "send_correlated"})
_REQUIRES = frozenset({"require_observed", "require_comparable"})


def _table_problems(classes) -> list[str]:
    names = {c.__name__ for c in classes}
    return ([f"unclassified: {n}" for n in sorted(names - set(CONTROL_READING))]
            + [f"stale row: {n}" for n in sorted(set(CONTROL_READING) - names)])


def test_every_default_strategy_says_how_it_reads_controls(monkeypatch):
    """M9: the table names every default strategy, once, with a kind and a reason; a new
    strategy fails until it says how it reads controls. Proven on a synthetic strategy
    appended through `monkeypatch`."""
    from fuzzlab.oracle import strategies as S
    assert _table_problems(type(s) for s in S.default_strategies()) == []
    assert all(len(row) == 2 and all(row) for row in CONTROL_READING.values())

    class SyntheticControlReader(S.ConfirmationStrategy):
        pass
    real = S.default_strategies
    monkeypatch.setattr(S, "default_strategies",
                        lambda *a, **k: real(*a, **k) + [SyntheticControlReader()])
    assert _table_problems(type(s) for s in S.default_strategies()) == \
        ["unclassified: SyntheticControlReader"]


def _role(expr):
    """``trace.role("x")``'s literal role; a non-literal role reads as None (a control);
    False when ``expr`` is no role at all."""
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) \
            and expr.func.attr == "role":
        arg = expr.args[0] if expr.args else None
        return arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) \
            else None
    return False


def _unguarded_sends(source: str) -> list[int]:
    """The line of every send in ``source`` that is neither compared (`_compared`, or a
    send whose result `require_observed` / `require_comparable` reads) nor lexically
    inside ``with trace.role("mutation")`` with a literal role."""
    bad: list[int] = []

    def name(f):
        return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)

    def visit(node, mutation: bool, required: bool):
        if isinstance(node, ast.With):
            here = any(_role(i.context_expr) == "mutation" for i in node.items)
            for item in node.items:
                visit(item.context_expr, mutation, False)
            for stmt in node.body:
                visit(stmt, mutation or here, False)
            return
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in _SEND_NAMES \
                    and not (mutation or required):
                bad.append(node.lineno)
            inner = name(node.func) in _REQUIRES
            for child in ast.iter_child_nodes(node):
                visit(child, mutation, inner)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, mutation, False)
    visit(ast.parse(textwrap.dedent(source)), False, False)
    return bad


def _reader_sources():
    from fuzzlab.oracle import strategies as S
    for strategy in S.default_strategies():
        kind, _why = CONTROL_READING[type(strategy).__name__]
        if kind in CONTROL_READERS:
            yield type(strategy).__name__, inspect.getsource(type(strategy))
            for engine in CONTROL_READERS[kind]:
                yield f"{type(strategy).__name__} via {engine}", inspect.getsource(
                    getattr(S.ConfirmationStrategy, engine))


def test_every_send_of_a_control_reader_is_compared_or_a_declared_mutation():
    """M9 (PA-0529(4)): every send in a control reader's methods, and in the shared
    engine its row names, is compared or a literal mutation. Keyed on the table, so a new
    control reader is checked once it is classified."""
    offenders = {where: lines for where, src in _reader_sources()
                 if (lines := _unguarded_sends(src))}
    assert offenders == {}, offenders
    assert sum(1 for _ in _reader_sources()) >= 10           # the guard read something


def test_the_send_guard_catches_its_synthetic_offenders():
    """PA-0034(2): the guard fails on SqliError's control reverted to `_send`, on an
    untagged control send, and on a send under a non-literal role; a send whose result
    a `require_*` reads passes."""
    src = inspect.getsource(SqliErrorStrategy)
    compared = 'self._compared(sender, candidate, value, role="control")'
    assert compared in src
    assert _unguarded_sends(src.replace(compared, "self._send(sender, candidate, value)"))
    untagged = '''
class Synthetic:
    def confirm(self, candidate, sender):
        with trace.role("mutation"):
            probe = self._send(sender, candidate, "'")
        control = self._send(sender, candidate, "benign")
        return probe, control
'''
    assert _unguarded_sends(untagged) == [6]
    variable = '''
class Synthetic:
    def confirm(self, candidate, sender, role="mutation"):
        with trace.role(role):
            return sender.send(candidate.url, candidate.param, "x")
'''
    assert _unguarded_sends(variable) == [5]
    required = '''
class Synthetic:
    def confirm(self, candidate, sender):
        require_comparable(self._send(sender, candidate, "x"), url="u", role="control")
'''
    assert _unguarded_sends(required) == []
