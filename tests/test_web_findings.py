"""Tests for the Findings workbench (U2, CC-UI-0029): read-only findings view,
saved-view round-trip, DOM-safe rendering of untrusted fields, the
"send to Repeater" PRG pivot, and the pure ``build_finding_raw_request`` helper
that pivot uses to reconstruct a replayable request (including the oracle's
recorded payload, when one was captured).
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from fuzzlab.web.findingsview import derive_severity, finding_detail, list_findings  # noqa: E402
from fuzzlab.web.proxycontrol import RepeaterController  # noqa: E402
from fuzzlab.web.results import build_finding_raw_request  # noqa: E402
from fuzzlab.web.savedviews import create_view, list_views  # noqa: E402
from tests._webclient import web_client  # noqa: E402


def _cfg(path, **over):
    return load_config(overrides={"store_path": str(path), **over}, environ={})


def _client(path, **over):
    return web_client(create_app(_cfg(path, **over)))


def _seed(path, evidence=None):
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        aid = store.conn.execute(
            "INSERT INTO attempt (run_id, payload_family, reward, score, uncertainty) "
            "VALUES (?,?,?,?,?)", (run_id, "sqli-error", 1.0, 0.9, 0.05)).lastrowid
        store.conn.execute(
            "INSERT INTO finding (run_id, attempt_id, vuln_class, label, confidence, "
            "evidence, url, method, param) VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, aid, "sqli", 1, "error-signature",
             json.dumps(evidence or {"dbms": "MySQL"}),
             "/product.php", "GET", "id"))
        store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
            "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, "reflected-xss", 1, "dom-reflection", json.dumps({}),
             "/search.php", "GET", "q"))
        store.conn.commit()
        return run_id


# --- read-only findingsview / route -----------------------------------------

def test_derive_severity_bands_known_families():
    assert derive_severity("sqli") == "critical"
    assert derive_severity("reflected-xss") == "high"
    assert derive_severity("open-redirect") == "medium"
    assert derive_severity(None) == "info"
    assert derive_severity("something-nobody-mapped") == "info"


def test_list_findings_reads_the_store(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    with Store(path) as store:
        findings = list_findings(store)
    assert len(findings) == 2
    by_class = {f["vuln_class"]: f for f in findings}
    assert by_class["sqli"]["severity"] == "critical"
    assert by_class["reflected-xss"]["severity"] == "high"


def test_finding_detail_includes_attempt_and_optional_ground_truth(tmp_path):
    path = tmp_path / "f.db"
    _seed(path, evidence={
        "dbms": "MySQL",
        "primary_endpoint": "/checkout/confirm.php",
        "primary_role": "sink",
        "related_endpoints": [{"endpoint": "/cart/add.php", "role": "source"}],
        "flow_variant": "cross_file",
    })
    with Store(path) as store:
        fid = store.conn.execute(
            "SELECT id FROM finding WHERE vuln_class='sqli'").fetchone()["id"]
        detail = finding_detail(store, fid)
    assert detail is not None
    assert detail["severity"] == "critical"
    assert detail["attempt"]["payload_family"] == "sqli-error"
    assert detail["ground_truth"]["primary_endpoint"] == "/checkout/confirm.php"
    assert detail["ground_truth"]["flow_variant"] == "cross_file"

    with Store(path) as store:
        # a finding with no ground-truth keys in its evidence -> None, not {}
        other_id = store.conn.execute(
            "SELECT id FROM finding WHERE vuln_class='reflected-xss'").fetchone()["id"]
        other = finding_detail(store, other_id)
    assert other["ground_truth"] is None


def test_finding_detail_missing_returns_none(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    with Store(path) as store:
        assert finding_detail(store, 9999) is None


def test_api_findings_and_page_are_read_only(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    client = _client(path)
    data = client.get("/api/findings").json()
    assert len(data["findings"]) == 2
    r = client.get("/findings")
    assert r.status_code == 200 and "Findings" in r.text
    # reads only: nothing about hitting this route creates result-table rows
    with Store(path) as store:
        assert store.conn.execute("SELECT COUNT(*) c FROM finding").fetchone()["c"] == 2


def test_findings_page_without_store_shows_no_findings(tmp_path):
    path = tmp_path / "missing.db"
    client = _client(path)
    assert client.get("/api/findings").json()["findings"] == []
    assert not path.exists()


def test_finding_detail_page_renders_untrusted_fields_dom_safe(tmp_path):
    # url/param are attacker-influenced (recorded from a live target); Jinja
    # autoescapes template output, so a payload-shaped value must render as
    # inert escaped text, never break out into markup.
    path = tmp_path / "f.db"
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
            "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, "sqli", 1, "error-signature", json.dumps({"note": "<img src=x onerror=alert(1)>"}),
             "/p.php?x=<script>alert(1)</script>", "GET", "id\"><svg onload=alert(1)>"))
        store.conn.commit()
        fid = store.conn.execute("SELECT id FROM finding").fetchone()["id"]
    body = _client(path).get(f"/findings/{fid}").text
    assert "<script>alert(1)</script>" not in body
    assert "<svg onload=alert(1)>" not in body
    assert "&lt;script&gt;" in body or "&lt;img" in body


def test_finding_not_found_uses_generic_template(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    r = _client(path).get("/findings/9999")
    assert r.status_code == 404
    assert "Finding 9999 not found" in r.text
    assert 'href="/findings"' in r.text


# --- saved views (server-side, GET/POST/PUT/DELETE /api/views) --------------

def test_saved_view_round_trip_via_store_functions(tmp_path):
    path = tmp_path / "f.db"
    with Store(path) as store:
        spec = {"version": 1, "filter": {"text": "sqli", "facets": {"severity": ["critical"]}}}
        view = create_view(store, "finding", "critical sqli", spec, pinned=True)
        assert view["name"] == "critical sqli" and view["is_pinned"] is True
        again = list_views(store, "finding")
        assert len(again) == 1 and again[0]["spec"]["filter"]["text"] == "sqli"


def test_saved_view_round_trip_via_api(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    client = _client(path)
    spec = {"version": 1, "filter": {"text": "", "facets": {"vuln_class": ["sqli"]}}, "sort": {"key": "id", "dir": 1}}
    r = client.post("/api/views", json={"table": "finding", "name": "sqli only", "spec": spec})
    assert r.status_code == 200
    view = r.json()["view"]
    assert view["name"] == "sqli only"

    listed = client.get("/api/views?table=finding").json()["views"]
    assert any(v["id"] == view["id"] for v in listed)

    upd = client.put(f"/api/views/{view['id']}", json={"name": "sqli only (renamed)"})
    assert upd.status_code == 200 and upd.json()["view"]["name"] == "sqli only (renamed)"

    deleted = client.delete(f"/api/views/{view['id']}")
    assert deleted.status_code == 200 and deleted.json()["deleted"] is True
    assert client.get("/api/views?table=finding").json()["views"] == []


def test_saved_view_missing_returns_404(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    client = _client(path)
    assert client.put("/api/views/9999", json={"name": "x"}).status_code == 404
    assert client.delete("/api/views/9999").status_code == 404


def test_create_view_requires_table_and_name(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    client = _client(path)
    r = client.post("/api/views", json={"table": "finding", "name": "", "spec": {}})
    assert r.status_code == 400


# --- "send to Repeater" pivot: PRG + 303, opaque tab id only ----------------

def test_findings_page_uses_a_post_form_not_a_url_seed(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    body = _client(path).get("/findings").text
    assert '<form method="post" action="/findings/repeater/from-finding"' in body
    assert 'name="finding_id"' in body
    assert "raw_request=" not in body


def test_finding_detail_page_has_repeater_pivot_form(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    with Store(path) as store:
        fid = store.conn.execute("SELECT id FROM finding LIMIT 1").fetchone()["id"]
    body = _client(path).get(f"/findings/{fid}").text
    assert '<form method="post" action="/findings/repeater/from-finding"' in body
    assert f'value="{fid}"' in body


def test_send_to_repeater_redirects_303_and_carries_only_the_tab_id(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    with Store(path) as store:
        fid = store.conn.execute(
            "SELECT id FROM finding WHERE vuln_class='sqli'").fetchone()["id"]

    cfg = _cfg(path, target_base_url="http://127.0.0.1:8080")
    client = web_client(create_app(cfg), follow_redirects=False)
    r = client.post("/findings/repeater/from-finding", data={"finding_id": str(fid)})
    assert r.status_code == 303
    assert r.headers["location"].startswith("/proxy?repeater_tab=")

    # an unknown finding id degrades to the default view rather than 404ing the pivot
    r2 = client.post("/findings/repeater/from-finding", data={"finding_id": "999999"})
    assert r2.status_code == 303 and r2.headers["location"] == "/findings"


def test_create_from_finding_reconstructs_a_request_with_the_recorded_payload(tmp_path):
    path = tmp_path / "f.db"
    _seed(path, evidence={"dbms": "MySQL", "payload": "' OR SLEEP(2)-- -"})
    with Store(path) as store:
        fid = store.conn.execute(
            "SELECT id FROM finding WHERE vuln_class='sqli'").fetchone()["id"]
    ctrl = RepeaterController(_cfg(path, target_base_url="http://127.0.0.1:8080"))
    tab = ctrl.create_from_finding(fid)
    assert tab is not None
    assert "GET /product.php?id=" in tab["raw"]
    assert "SLEEP" in tab["raw"]
    assert ctrl.create_from_finding(999999) is None


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
