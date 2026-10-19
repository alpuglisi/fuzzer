"""Path-segment parameters (FR-FUZZ-57), per-account values (FR-LAB-309) and runs that
log no account in (FR-FUZZ-58): `core.urls.place_path_param`, the ground truth's `path`
points and `account_value`, the credential store's account attributes, the
`--no-login` cross-account check, and secdevlabs-ecommerce-api's bootstrap. Fake apps
and stores stand for the target and the keyring."""

from __future__ import annotations

import json
import re

import pytest

from fuzzlab.core.urls import PathPlacementError, place_path_param
from fuzzlab.labels import contract
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import CrossAccountReplayStrategy, PeerAccounts


def test_a_path_value_replaces_its_one_segment_percent_encoded():
    assert place_path_param("http://h/ticket/{id}?format=json", "id", "a/b c'") == \
        "http://h/ticket/a%2Fb%20c%27?format=json"
    assert place_path_param("http://h/u/{uid}/t/{tid}", "tid", "7") == "http://h/u/{uid}/t/7"
    for url in ("http://h/ticket", "http://h/{id}/{id}", "http://h/x{id}", "http://h/?q={id}"):
        with pytest.raises(PathPlacementError):
            place_path_param(url, "id", "1")


# --- the ground truth --------------------------------------------------------------
def _write(tmp_path, cases, points):
    (tmp_path / "labels.json").write_text(json.dumps(
        {"version": 1, "target": "t", "cases": cases}))
    (tmp_path / "injection-points.json").write_text(json.dumps(
        {"version": 1, "target": "t", "points": points}))
    rows = ["case_id,url,method,param,location,category,expected_vulnerable,"
            "primary_endpoint,primary_role,related_endpoints,flow_variant"]
    rows += [f"{c['case_id']},{c['url']},{c['method']},{c['param']},{c['location']},"
             f"{c['vuln_class']},{str(c['expected_vulnerable']).lower()},{c['url']},"
             f"sink,,direct" for c in cases]
    (tmp_path / "expectedresults.csv").write_text("\n".join(rows) + "\n")


def _case(cid="TC-0001", url="/ticket/{id}", param="id", location="path", vuln=True):
    return {"case_id": cid, "url": url, "method": "GET", "param": param,
            "location": location, "vuln_class": "access_control", "sink_context": "none",
            "expected_vulnerable": vuln, "rendering": "server-json"}


def _point(url="/ticket/{id}", param="id", location="path", **kw):
    return {"url": url, "method": "GET", "param": param, "location": location,
            "rendering": "server-json", **kw}


def test_a_path_point_names_its_parameter_as_one_segment(tmp_path):
    _write(tmp_path, [_case(), _case("TC-0002", param="format", location="query",
                                     vuln=False)],
           [_point(account_value="user_id"), _point(param="format", location="query")])
    gt = contract.load(tmp_path)
    assert gt.points[0].account_value == "user_id"
    for bad_url in ("/ticket/id", "/ticket/x{id}"):
        _write(tmp_path, [_case(url=bad_url)], [_point()])
        with pytest.raises(contract.ContractError, match="one segment"):
            contract.load(tmp_path)
        _write(tmp_path, [_case()], [_point(url=bad_url)])
        with pytest.raises(contract.ContractError, match="one segment"):
            contract.load(tmp_path)
    _write(tmp_path, [_case()], [_point(account_value="User-Id")])
    with pytest.raises(contract.ContractError):
        contract.load(tmp_path)


def test_auto_keeps_the_template_and_carries_the_accounts_own_value(tmp_path):
    from fuzzlab.harness.auto import points_from_ground_truth
    _write(tmp_path, [_case()], [_point(account_value="user_id")])
    gt = contract.load(tmp_path)
    points, skipped = points_from_ground_truth(gt, "http://127.0.0.1:3079/")
    assert points == [] and "needs the run's own account's 'user_id'" in skipped[0][3]
    (p,), _ = points_from_ground_truth(gt, "http://127.0.0.1:3079/",
                                       account_values={"user_id": "u-1"})
    assert (p.url, p.location, p.base_entries) == \
        ("http://127.0.0.1:3079/ticket/{id}", "path", (("id", "u-1"),))


def test_a_json_leaf_takes_the_accounts_own_value(tmp_path):
    from fuzzlab.harness.auto import points_from_ground_truth
    _write(tmp_path, [_case(url="/orders", param="owner", location="body")],
           [_point(url="/orders", param="owner", location="body",
                   json_body={"owner": "x", "note": "n"}, account_value="user_id")])
    (p,), _ = points_from_ground_truth(contract.load(tmp_path), "http://h/",
                                       account_values={"user_id": "u-1"})
    assert dict(p.base_entries) == {("owner",): "u-1", ("note",): "n"}


# --- the cross-account check on a path point, with and without sessions -------------
TICKETS = {"u-alice": "alice", "u-bob": "bob"}


class _Api:
    """``GET /ticket/{id}`` as seen by ``user`` (None: no session): ``open`` answers
    any caller, ``owner`` only the ticket's owner."""

    def __init__(self, mode, user=None):
        self.mode, self.user, self.urls = mode, user, []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        assert location == "path"
        url = place_path_param(url, param, value)
        self.urls.append(url)
        owner = TICKETS.get(url.rsplit("/", 1)[1])
        if owner is None:
            return Probe(400, '{"result":"error"}', 0.0)
        if self.mode == "owner" and owner != self.user:
            return Probe(403, "forbidden", 0.0)
        return Probe(200, json.dumps({"username": owner, "ticket": "t"}), 0.0)


def _cand():
    return Candidate(url="http://127.0.0.1:9/ticket/{id}", param="id", method="GET",
                     location="path", category="access-control",
                     base_entries=(("id", "u-alice"),))


def test_no_login_confirms_an_unauthenticated_read_of_the_accounts_own_object():
    accounts = PeerAccounts(sender=None, owner="alice", peer_name="bob",
                            anonymous=_Api("open"))
    v = CrossAccountReplayStrategy(accounts).confirm(_cand(), _Api("open"))
    assert v is not None and v.evidence == {"who": "anonymous", "param": "id",
                                            "status": [200, 200]}
    assert "u-alice" not in json.dumps(v.evidence)
    assert accounts.anonymous.urls == ["http://127.0.0.1:9/ticket/u-alice"] * 2


def test_an_owner_check_gives_no_verdict_with_or_without_sessions():
    for peer_sender in (None, _Api("owner", "bob")):
        accounts = PeerAccounts(sender=peer_sender, owner="alice", peer_name="bob",
                                anonymous=_Api("owner"))
        assert CrossAccountReplayStrategy(accounts).confirm(
            _cand(), _Api("owner", "alice")) is None


def test_an_id_shaped_path_segment_draws_the_access_control_rule():
    from fuzzlab.audit.rules import load_rules
    (rule,) = [r for r in load_rules() if r.id == "R-ACCESS-CONTROL-PATH"]
    rx = rule.when["name_regex"]
    hits = [n for n in ("id", "user_id", "userId", "ticket-id", "uuid", "ID", "paid",
                        "video", "userid", "idea") if re.search(rx, n, re.I)]
    assert hits == ["id", "user_id", "userId", "ticket-id", "uuid", "ID"]
    assert rule.when["location_in"] == ["path"] and rule.when["method_in"] == ["GET"]


# --- account values in the credential store -----------------------------------------
class _Keyring:
    def __init__(self):
        self.data = {}

    def get_password(self, service, account):
        return self.data.get((service, account))

    def set_password(self, service, account, password):
        self.data[(service, account)] = password

    def delete_password(self, service, account):
        self.data.pop((service, account), None)


def test_account_values_live_with_the_credential():
    from fuzzlab.core.credentials import CredentialError, CredentialStore
    store = CredentialStore(backend=_Keyring())
    with pytest.raises(CredentialError, match="no credential"):
        store.set_attributes("127.0.0.1", "a", {"user_id": "u-1"})
    store.set("127.0.0.1", "a", "alice", "pw")
    store.set_attributes("127.0.0.1", "a", {"user_id": "u-1"})
    assert store.attributes("127.0.0.1", "a") == {"user_id": "u-1"}
    assert store.get("127.0.0.1", "a").password == "pw"
    for bad in ({"User": "x"}, {"user_id": ""}, {"user_id": 5}):
        with pytest.raises(CredentialError):
            store.set_attributes("127.0.0.1", "a", bad)
    store.set("127.0.0.1", "a", "alice", "pw2")       # a new credential: values gone
    assert store.attributes("127.0.0.1", "a") == {}
    assert store.attributes("127.0.0.1", "nobody") == {}


def test_no_login_needs_an_identity_and_reads_only_stored_usernames(tmp_path, capsys,
                                                                     monkeypatch):
    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.harness import auto_cli
    base = ["--base-url", "http://127.0.0.1:9/", "--store", str(tmp_path / "s.db"),
            "--categories", "access-control", "--authorized"]
    with pytest.raises(SystemExit):
        auto_cli.main(base + ["--no-login"])
    assert "--no-login needs --identity" in capsys.readouterr().err
    store = CredentialStore(backend=_Keyring())
    store.set("127.0.0.1", "a", "alice", "pw")
    monkeypatch.setattr("fuzzlab.core.credentials.CredentialStore.open",
                        classmethod(lambda cls, cfg: store))
    args = auto_cli.build_parser().parse_args(base + ["--identity", "a", "--no-login"])
    auto_cli._precheck_peer(auto_cli.build_parser(), args)
    assert args.peer_names == ("alice", "")
    store.set_attributes("127.0.0.1", "a", {"user_id": "u-1"})
    assert auto_cli._account_values(args) == {"user_id": "u-1"}


# --- secdevlabs-ecommerce-api's bootstrap --------------------------------------------
def test_the_ecommerce_bootstrap_registers_verifies_and_reads_the_user_id():
    from types import SimpleNamespace as NS

    from fuzzlab.lab_fixtures import external as ext
    users = {}

    class Resp:
        def __init__(self, status, body=None):
            self.status_code, self._body = status, body

        def json(self):
            if self._body is None:
                raise ValueError("no JSON")
            return self._body

        def close(self):
            pass

    class Client:
        origin = "http://127.0.0.1:3079"

        def request(self, method, path, *, anonymous=False, json=None, params=None, **kw):
            if path == "/healthcheck":
                return Resp(200)
            if path == "/register":                  # the app refuses a taken name
                if json["username"] in users:
                    return Resp(400, {"result": "error"})
                users[json["username"]] = json["password"]
                return Resp(201)
            if path == "/login":
                assert params == {"format": "json"}
                if users.get(json["username"]) != json["password"]:
                    return Resp(400, {"result": "error"})
                return Resp(200, {"user_id": f"id-{json['username']}"})
            raise AssertionError((method, path))
    cred = NS(username="fuzzlab_user", password="pw")
    assert ext.bootstrap_secdevlabs_ecommerce_api(Client(), cred, deadline=1,
                                                  sleep=lambda s: None) == \
        ["account registered", "login verified"]
    assert ext.ecommerce_account_attributes(Client(), cred) == {"user_id": "id-fuzzlab_user"}
    users["fuzzlab_user"] = "other"
    with pytest.raises(ext.ExternalLabError, match="registration failed.*another password"):
        ext.bootstrap_secdevlabs_ecommerce_api(Client(), cred, deadline=1)


def test_bootstrap_stores_each_accounts_values_after_its_credential(monkeypatch):
    from types import SimpleNamespace as NS

    from fuzzlab.core.credentials import CredentialStore
    from fuzzlab.lab_fixtures import external as ext
    keyring = CredentialStore(backend=_Keyring())
    opened = CredentialStore(backend=_Keyring())
    monkeypatch.setitem(ext._BOOTSTRAPS, "secdevlabs-ecommerce-api",
                        lambda client, cred, deadline: ["login verified"])
    monkeypatch.setitem(ext._ACCOUNT_ATTRIBUTES, "secdevlabs-ecommerce-api",
                        lambda client, cred: {"user_id": "id-" + cred.username})
    monkeypatch.setattr(ext, "_LabClient", lambda origin, session_factory=None:
                        NS(origin=origin))
    res = ext.bootstrap("secdevlabs-ecommerce-api", keyring_store=keyring,
                        opened_store=opened)
    assert keyring.attributes("127.0.0.1", "sdl-ecommerce-user") == \
        {"user_id": "id-fuzzlab_user"}
    assert keyring.attributes("127.0.0.1", "sdl-ecommerce-peer") == \
        {"user_id": "id-fuzzlab_peer"}
    assert "account values stored: user_id" in res.notes and res.peers
