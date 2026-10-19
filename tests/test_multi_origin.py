"""Labs with two origins (FR-LAB-308): a ground-truth point or case may live on another
loopback origin of its lab; `auto` probes it there; the contract refuses an origin off
the machine and a path used on two origins (scoring matches findings by path)."""

from __future__ import annotations

import json

import pytest

from fuzzlab.labels import contract

API = "http://localhost:10017"


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


def _case(cid, url, vuln=True, **kw):
    return {"case_id": cid, "url": url, "method": "POST", "param": "comment",
            "location": "body", "vuln_class": "xss-stored", "sink_context": "js",
            "expected_vulnerable": vuln, "rendering": "js", **kw}


def _point(url, **kw):
    return {"url": url, "method": "POST", "param": "comment", "location": "body",
            "rendering": "server", **kw}


def test_a_case_and_point_on_the_labs_other_origin_load_and_are_probed_there(tmp_path):
    from fuzzlab.harness.auto import points_from_ground_truth
    _write(tmp_path, [_case("TC-0001", "/comments", origin=API), _case("TC-0002", "/", vuln=False)],
           [_point("/comments", origin=API, json_body={"comment": "hi"}), _point("/")])
    gt = contract.load(tmp_path)
    assert gt.cases[0].origin == API and gt.cases[0].key[0] == "/comments"
    points, _skipped = points_from_ground_truth(gt, "http://127.0.0.1:3074/")
    urls = {p.url for p in points}
    assert urls == {API + "/comments", "http://127.0.0.1:3074/"}


@pytest.mark.parametrize("origin", ["http://example.com", "https://10.0.0.5:8443"])
def test_an_origin_off_the_machine_is_refused(tmp_path, origin):
    _write(tmp_path, [_case("TC-0001", "/comments", origin=origin), _case("TC-0002", "/x", False)],
           [_point("/comments")])
    with pytest.raises(contract.ContractError, match="not a loopback origin"):
        contract.load(tmp_path)


def test_a_path_on_two_origins_is_refused(tmp_path):
    _write(tmp_path, [_case("TC-0001", "/comments", origin=API), _case("TC-0002", "/comments", False)],
           [_point("/comments", origin=API)])
    with pytest.raises(contract.ContractError, match="two origins"):
        contract.load(tmp_path)


def test_a_store_endpoint_on_another_origin_must_be_loopback(tmp_path):
    _write(tmp_path, [_case("TC-0001", "/", source_url="http://evil.test/comments"),
                      _case("TC-0002", "/x", False)], [_point("/")])
    with pytest.raises(contract.ContractError, match="source_url"):
        contract.load(tmp_path)


def test_an_origin_is_an_origin_not_a_url(tmp_path):
    _write(tmp_path, [_case("TC-0001", "/comments", origin=API + "/api"),
                      _case("TC-0002", "/x", False)], [_point("/comments")])
    with pytest.raises(contract.ContractError):
        contract.load(tmp_path)
