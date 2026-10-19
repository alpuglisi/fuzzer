"""NoSQL operator injection (FR-FUZZ-54): `core.jsonbody.body_with`, the
`NoSqlOperatorStrategy` differential, the ground truth's `json_body` points and their
place in the pipeline. Fake servers stand for the target: a Mongo-like matcher (the
flaw), a server that stringifies objects, one that rejects them, and a noisy one."""

from __future__ import annotations

import json
import random

import pytest

from fuzzlab.core import jsonbody
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import NoSqlOperatorStrategy

USERS = [{"email": "alice@lab.test", "password": "s3cret"},
         {"email": "bob@lab.test", "password": "hunter2"}]
ENTRIES = ((("email",), "a@b.co"), (("password",), "x"), (("remember",), True))


def _match(cond, value) -> bool:
    if isinstance(cond, dict):
        if "$ne" in cond:
            return value != cond["$ne"]
        if "$in" in cond:
            return value in cond["$in"]
        return False
    return value == cond


class _Server:
    """A login whose `find({email, password})` treats an object as an operator
    (``mongo``), compares its string form (``stringify``), rejects any object
    (``reject``), or answers at random (``noise``)."""

    def __init__(self, mode):
        self.mode, self.bodies = mode, []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        assert content_type == "application/json" and location == "body"
        body = json.loads(value)
        self.bodies.append(body)
        if self.mode == "noise":
            return Probe(200, random.choice(["Bad Credentials", "Welcome"]), 0.0)
        email, pw = body.get("email"), body.get("password")
        if self.mode == "reject" and (isinstance(email, dict) or isinstance(pw, dict)):
            return Probe(400, "bad request", 0.0)
        if self.mode == "stringify":
            email, pw = str(email), str(pw)
        hits = [u["email"] for u in USERS if _match(email, u["email"])
                and _match(pw, u["password"])]
        return Probe(200, "Welcome " + ",".join(hits) if hits else "Bad Credentials", 0.0)


def _cand(param="email", location="json", entries=ENTRIES):
    return Candidate(url="http://127.0.0.1:9/login", param=param, method="POST",
                     location=location, category="nosql-injection", base_entries=entries)


def test_body_with_sets_typed_values_and_refuses_a_leaf_the_body_lacks():
    got = json.loads(jsonbody.body_with(ENTRIES, {"email": {"$ne": "x"}, "password": "p"}))
    assert got == {"email": {"$ne": "x"}, "password": "p", "remember": True}
    nested = ((("user", "email"), "a"), (("user", "tags", 0), "t"))
    assert json.loads(jsonbody.body_with(nested, {"user.tags[0]": {"$in": []}})) == \
        {"user": {"email": "a", "tags": [{"$in": []}]}}
    with pytest.raises(jsonbody.JsonPlacementError):
        jsonbody.body_with(ENTRIES, {"username": "x"})          # never added (PA-0115)
    with pytest.raises(jsonbody.JsonPlacementError):
        jsonbody.body_with(ENTRIES, {"email": float("nan")})


@pytest.mark.parametrize("param", ["email", "password"])
def test_an_operator_reaching_the_query_is_confirmed_on_either_leaf(param):
    server = _Server("mongo")
    v = NoSqlOperatorStrategy().confirm(_cand(param), server)
    assert v is not None and v.confirmed and v.vuln_class == "nosqli"
    assert "alice" not in json.dumps(v.evidence)                 # no matched data kept
    # the target leaf alone decides: siblings carry the always-true operator in V/D
    v_bodies = [b for b in server.bodies if b[param] == {"$in": []}]
    other = "password" if param == "email" else "email"
    assert v_bodies and all(b[other].keys() == {"$ne"} for b in v_bodies)
    assert all(b["remember"] is True for b in server.bodies)     # non-strings untouched


@pytest.mark.parametrize("mode", ["stringify", "reject", "noise"])
def test_no_verdict_where_objects_are_not_operators(mode):
    random.seed(7)
    assert NoSqlOperatorStrategy().confirm(_cand(), _Server(mode)) is None


def test_only_a_string_leaf_of_a_json_point_is_probed():
    server = _Server("mongo")
    assert NoSqlOperatorStrategy().confirm(_cand("remember"), server) is None
    assert NoSqlOperatorStrategy().confirm(_cand(location="body"), server) is None
    assert NoSqlOperatorStrategy().confirm(_cand(entries=None), server) is None
    assert server.bodies == []


def test_a_ground_truth_json_body_point_is_a_json_leaf_point(tmp_path):
    """FR-FUZZ-54: `json_body` makes a ground-truth point carry its siblings; a param
    the body lacks is refused at load."""
    from fuzzlab.labels import contract
    pts = {"version": 1, "target": "t", "points": [
        {"url": "/login", "method": "POST", "param": "email", "location": "body",
         "rendering": "server-json", "json_body": {"email": "a@b.co", "password": "x"}}]}
    (tmp_path / "injection-points.json").write_text(json.dumps(pts))
    (pt,) = contract.load_injection_points(tmp_path)
    assert pt.json_body == {"email": "a@b.co", "password": "x"}
    pts["points"][0]["param"] = "username"
    (tmp_path / "injection-points.json").write_text(json.dumps(pts))
    with pytest.raises(contract.ContractError, match="no such leaf"):
        contract.load_injection_points(tmp_path)


def test_auto_turns_a_json_body_point_into_a_json_leaf_candidate():
    from fuzzlab.harness.auto import points_from_ground_truth
    from fuzzlab.labels.contract import Case, GroundTruth, InjectionPoint
    gt = GroundTruth(target="t", cases=[Case(
        case_id="C1", url="/login", method="POST", param="email", location="body",
        vuln_class="nosqli", sink_context="nosql", expected_vulnerable=True,
        rendering="server-json")], points=[InjectionPoint(
            url="/login", method="POST", param="email", location="body",
            rendering="server-json", json_body={"email": "a@b.co", "password": "x"})])
    (p,), _skipped = points_from_ground_truth(gt, "http://127.0.0.1:9/")
    assert p.location == "json" and p.body_content_type is None
    assert dict(p.base_entries) == {("email",): "a@b.co", ("password",): "x"}


def test_nosqli_is_a_ruled_scoreable_class():
    from fuzzlab.audit.rules import load_rules
    from fuzzlab.core.runmode import to_category
    from fuzzlab.oracle.strategies import _CATEGORY_TO_CLASS, default_strategies
    assert to_category("nosqli") == "nosql-injection"
    assert _CATEGORY_TO_CLASS["nosql-injection"] == "nosqli"
    assert any(r.category == "nosql-injection" and "json" in r.when.get("location_in", [])
               for r in load_rules())
    assert any(s.vuln_class == "nosqli" for s in default_strategies())
