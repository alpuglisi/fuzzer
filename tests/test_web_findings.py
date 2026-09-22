"""Tests for the R2 Findings workbench (CC-UI-0026, FR-UI-10,
docs/UI_LAYOUT_REDESIGN.md).

Covers the pure query helpers (``results.list_findings``/``finding_facets``/
``finding_detail``/``build_finding_raw_request``), the ``/findings`` and
``/findings/{id}`` routes (real data wiring, no mock data; safe empty-store
rendering), facet/filter behavior, and the "send to Repeater" wiring
(``RepeaterController.create_from_finding`` + its route).
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from fuzzlab.web.proxycontrol import RepeaterController  # noqa: E402
from fuzzlab.web.results import (  # noqa: E402
    build_finding_raw_request,
    finding_detail,
    finding_facets,
    list_findings,
)


def _seed_full(path):
    """One run with a target, a candidate (audit evidence carrying a category), an
    attempt linked to it, and a finding linked to that attempt — the full join chain
    the detail pane and facets read through."""
    with Store(path) as store:
        run_id = store.start_run("auto", "http://127.0.0.1:8080")
        store.conn.execute(
            "INSERT INTO target (run_id, base_url, dbms) VALUES (?,?,?)",
            (run_id, "http://127.0.0.1:8080", "MySQL"))
        cur = store.conn.execute(
            "INSERT INTO candidate (run_id, rule, evidence, sink_context) VALUES (?,?,?,?)",
            (run_id, "rule-sqli-1", json.dumps({"rule_id": "rule-sqli-1",
                                                "category": "sql-injection"}), "html-attr"))
        candidate_id = cur.lastrowid
        cur = store.conn.execute(
            "INSERT INTO attempt (run_id, candidate_id, payload_family, reward, score) "
            "VALUES (?,?,?,?,?)", (run_id, candidate_id, "sqli-error", 1.0, 0.9))
        attempt_id = cur.lastrowid
        cur = store.conn.execute(
            "INSERT INTO finding (run_id, attempt_id, vuln_class, label, confidence, "
            "evidence, url, method, param) VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, attempt_id, "sqli", 1, "error-signature",
             json.dumps({"dbms": "MySQL", "payload": "' OR SLEEP(2)-- -"}),
             "/product.php", "GET", "id"))
        finding_id = cur.lastrowid
        # A second finding, no attempt/candidate link and no payload in evidence —
        # exercises the "derived category is None" and "no payload" paths.
        cur = store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
            "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, "xss", 1, "exec-confirmed", json.dumps({}), "/search.php", "POST", "q"))
        finding2_id = cur.lastrowid
        store.conn.commit()
    return run_id, finding_id, finding2_id


def _client(path, **overrides):
    cfg = load_config(overrides={"store_path": str(path),
                                 "target_base_url": "http://127.0.0.1:8080", **overrides},
                      environ={})
    return TestClient(create_app(cfg)), cfg


# --- pure helpers: list_findings / finding_facets / finding_detail ---------

def test_list_findings_on_empty_store_reads_nothing(tmp_path):
    with Store(tmp_path / "e.db") as store:
        assert list_findings(store) == []
        assert finding_facets(store) == {
            "vuln_classes": [], "confidences": [], "categories": [], "runs": []}


def test_list_findings_wires_real_data_and_derives_category(tmp_path):
    path = tmp_path / "f.db"
    run_id, fid, fid2 = _seed_full(path)
    with Store(path) as store:
        findings = list_findings(store)
        facets = finding_facets(store)
    by_id = {f["id"]: f for f in findings}
    assert len(findings) == 2
    assert by_id[fid]["category"] == "sql-injection"     # derived via attempt->candidate
    assert by_id[fid]["has_evidence"] is True
    assert by_id[fid2]["category"] is None                # no candidate link -> no category
    assert by_id[fid2]["has_evidence"] is False           # evidence == {}
    assert facets["vuln_classes"] == ["sqli", "xss"]
    assert facets["confidences"] == ["error-signature", "exec-confirmed"]
    assert facets["categories"] == ["sql-injection"]
    assert facets["runs"] == [{"id": run_id, "tool": "auto"}]


def test_list_findings_filters_by_each_facet(tmp_path):
    path = tmp_path / "f.db"
    run_id, fid, fid2 = _seed_full(path)
    with Store(path) as store:
        assert [f["id"] for f in list_findings(store, vuln_class="sqli")] == [fid]
        assert [f["id"] for f in list_findings(store, confidence="exec-confirmed")] == [fid2]
        assert [f["id"] for f in list_findings(store, category="sql-injection")] == [fid]
        assert [f["id"] for f in list_findings(store, has_evidence=True)] == [fid]
        assert [f["id"] for f in list_findings(store, has_evidence=False)] == [fid2]
        assert [f["id"] for f in list_findings(store, run_id=run_id)] == [fid2, fid]
        assert list_findings(store, run_id=run_id + 1) == []
        assert list_findings(store, vuln_class="nope") == []


def test_finding_detail_wires_attempt_candidate_and_target(tmp_path):
    path = tmp_path / "f.db"
    run_id, fid, fid2 = _seed_full(path)
    with Store(path) as store:
        detail = finding_detail(store, fid)
        detail2 = finding_detail(store, fid2)
        assert finding_detail(store, 99999) is None
    assert detail["vuln_class"] == "sqli"
    assert detail["category"] == "sql-injection"
    assert detail["target_base_url"] == "http://127.0.0.1:8080"
    assert detail["attempt"]["payload_family"] == "sqli-error"
    assert detail["candidate"]["rule"] == "rule-sqli-1"
    assert detail["evidence"]["payload"] == "' OR SLEEP(2)-- -"
    assert detail2["attempt"] is None and detail2["candidate"] is None


# --- build_finding_raw_request: pure, no store ------------------------------

def test_build_finding_raw_request_get_query():
    raw, host, port, tls = build_finding_raw_request(
        "/product.php", "GET", "id", "' OR 1=1-- -", "http://127.0.0.1:8080")
    assert raw.startswith("GET /product.php?id=")
    assert "Host: 127.0.0.1" in raw
    assert host == "127.0.0.1" and port == 8080 and tls is False


def test_build_finding_raw_request_post_body_with_no_payload():
    raw, host, port, tls = build_finding_raw_request(
        "/search.php", "POST", "q", "", "https://127.0.0.1:8443")
    assert raw.startswith("POST /search.php HTTP/1.1")
    assert "Content-Length: 2" in raw and raw.endswith("q=")
    assert host == "127.0.0.1" and port == 8443 and tls is True


def test_build_finding_raw_request_falls_back_to_default_host():
    raw, host, port, tls = build_finding_raw_request("/x", "GET", "", "", "")
    assert host == "127.0.0.1" and port == 80 and tls is False
    assert raw.startswith("GET /x HTTP/1.1")


# --- routes: real data wiring, empty-store safety, facet filtering ---------

def test_findings_route_renders_with_no_store_at_all(tmp_path):
    path = tmp_path / "missing.db"
    client, _ = _client(path)
    body = client.get("/findings").text
    assert not path.exists()
    assert "No findings match" in body


def test_findings_route_lists_real_findings(tmp_path):
    path = tmp_path / "f.db"
    run_id, fid, fid2 = _seed_full(path)
    client, _ = _client(path)
    body = client.get("/findings").text
    assert f'href="/findings/{fid}"' in body and f'href="/findings/{fid2}"' in body
    assert "sql-injection" in body


def test_findings_route_filters_by_query_params(tmp_path):
    path = tmp_path / "f.db"
    run_id, fid, fid2 = _seed_full(path)
    client, _ = _client(path)
    body = client.get("/findings", params={"vuln_class": "sqli"}).text
    assert f'href="/findings/{fid}"' in body
    assert f'href="/findings/{fid2}"' not in body
    # A blank facet select still submits `name=` — must not 422.
    r = client.get("/findings", params={"run_id": "", "has_evidence": ""})
    assert r.status_code == 200


def test_finding_detail_route_and_404(tmp_path):
    path = tmp_path / "f.db"
    run_id, fid, fid2 = _seed_full(path)
    client, _ = _client(path)
    body = client.get(f"/findings/{fid}").text
    # Evidence renders through Jinja's autoescaping, so the apostrophe comes back
    # as &#39; — assert on the un-escapable substring instead of the raw payload.
    assert "sql-injection" in body and "SLEEP(2)" in body
    r = client.get("/findings/99999")
    assert r.status_code == 404
    assert "Finding 99999 not found" in r.text


def test_api_findings_and_detail(tmp_path):
    path = tmp_path / "f.db"
    run_id, fid, fid2 = _seed_full(path)
    client, _ = _client(path)
    data = client.get("/api/findings").json()
    assert len(data["findings"]) == 2
    assert data["facets"]["categories"] == ["sql-injection"]
    assert client.get(f"/api/findings/{fid}").json()["id"] == fid
    assert client.get("/api/findings/99999").status_code == 404


# --- "send to Repeater" wiring: real, not a dead button ---------------------

def test_create_from_finding_builds_a_real_replayable_tab(tmp_path):
    path = tmp_path / "f.db"
    run_id, fid, fid2 = _seed_full(path)
    ctrl = RepeaterController(load_config(overrides={"store_path": str(path)}, environ={}))
    tab = ctrl.create_from_finding(fid)
    assert tab is not None
    assert tab["host"] == "127.0.0.1" and tab["port"] == 8080
    assert "GET /product.php?id=" in tab["raw"]
    assert ctrl.create_from_finding(99999) is None


def test_repeater_from_finding_route(tmp_path):
    path = tmp_path / "f.db"
    run_id, fid, fid2 = _seed_full(path)
    client, _ = _client(path)
    r = client.post(f"/api/proxy/repeater/from-finding/{fid}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"]
    # the created tab is listed and replayable via the ordinary Repeater routes
    tabs = client.get("/api/proxy/repeater/tabs").json()["tabs"]
    assert any(t["id"] == data["id"] for t in tabs)
    assert client.post("/api/proxy/repeater/from-finding/99999").status_code == 404
