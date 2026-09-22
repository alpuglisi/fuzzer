"""Tests for the Findings workbench (U2, D11): read views, routes, saved views,
and the send-to-Repeater PRG pivot."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web import findingsview, savedviews  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402


def _seed(path):
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        rows = [
            ("sqli", "error-signature", {"dbms": "MySQL"}, "/product.php", "GET", "id"),
            ("xss-reflected", "reflected-marker", {"marker": "x"}, "/search.php", "GET", "q"),
            ("open-redirect", "location-header", {}, "/go.php", "GET", "url"),
        ]
        for vuln_class, mechanism, evidence, url, method, param in rows:
            store.conn.execute(
                "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
                "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
                (run_id, vuln_class, 1, mechanism, json.dumps(evidence), url, method, param))
        store.conn.commit()
        return run_id


def _client(path, target="http://127.0.0.1:8080"):
    cfg = load_config(overrides={"store_path": str(path), "target_base_url": target},
                      environ={})
    return TestClient(create_app(cfg))


# --- pure view-layer functions ----------------------------------------------

def test_list_findings_severity_and_mechanism(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    with Store(path) as store:
        findings = findingsview.list_findings(store)
        assert len(findings) == 3
        by_class = {f["vuln_class"]: f for f in findings}
        assert by_class["sqli"]["severity"] == "Critical"
        assert by_class["xss-reflected"]["severity"] == "Medium"
        assert by_class["open-redirect"]["severity"] == "Low"
        # `finding.confidence` doubles as the "mechanism" facet per the oracle's
        # write path (fuzzlab/oracle/oracle.py) — surfaced as-is, not renamed.
        assert by_class["sqli"]["confidence"] == "error-signature"


def test_severity_unknown_vuln_class_defaults_to_info():
    assert findingsview.severity_for("some-future-class") == "Info"
    assert findingsview.severity_for(None) == "Info"


def test_finding_detail_notes_ground_truth_gap(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    with Store(path) as store:
        findings = findingsview.list_findings(store)
        detail = findingsview.finding_detail(store, findings[0]["id"])
        assert detail is not None
        assert detail["ground_truth_fields_available"] is False
        assert findingsview.finding_detail(store, 999999) is None


# --- routes ------------------------------------------------------------------

def test_findings_route_renders_shell(tmp_path):
    r = _client(tmp_path / "f.db").get("/findings")
    assert r.status_code == 200
    assert r.template.name == "sections/findings.html"
    assert r.context["active"] == "findings"


def test_api_findings_empty_store_never_creates_it(tmp_path):
    path = tmp_path / "missing.db"
    client = _client(path)
    assert client.get("/api/findings").json() == {"findings": []}
    assert not path.exists()


def test_api_findings_lists_seeded_rows(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    data = _client(path).get("/api/findings").json()
    assert len(data["findings"]) == 3
    assert {f["severity"] for f in data["findings"]} == {"Critical", "Medium", "Low"}


def test_finding_detail_page_and_404(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    client = _client(path)
    fid = client.get("/api/findings").json()["findings"][0]["id"]
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert "/product.php" in r.text or "/search.php" in r.text or "/go.php" in r.text
    # Multi-artifact ground-truth gap is surfaced, not silently blank.
    assert "primary_endpoint" in r.text

    r404 = client.get("/findings/999999")
    assert r404.status_code == 404
    assert "Finding 999999" in r404.text


def test_send_to_repeater_is_prg_303(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    client = _client(path)
    fid = client.get("/api/findings").json()["findings"][0]["id"]
    r = client.post(f"/findings/{fid}/send-to-repeater", follow_redirects=False)
    assert r.status_code == 303
    location = r.headers["location"]
    assert location.startswith("/proxy?repeater_tab=")
    # The redirect target itself must render (query hint, never a 404 — R-07).
    assert client.get(location).status_code == 200
    # And the tab it seeded is real, listed by the repeater controller.
    tabs = client.get("/api/proxy/repeater/tabs").json()["tabs"]
    assert any(str(t["id"]) == location.rsplit("=", 1)[1] for t in tabs)


def test_send_to_repeater_404_for_missing_finding(tmp_path):
    path = tmp_path / "f.db"
    _seed(path)
    r = _client(path).post("/findings/999999/send-to-repeater")
    assert r.status_code == 404


# --- DOM-safety: untrusted url/param/payload render via textContent, and any
# pivot link rejects a javascript: URL (R-03's non-negotiable). The Python
# layer's contribution is: it must never itself HTML-render an unsafe href —
# checked here at the template layer (Jinja autoescaping neutralizes any HTML
# metacharacters in the recorded value), and js/datatable.js's isSafeHref is
# unit-tested at the JS layer (tests/test_datatable_js.py). ---------------

def test_finding_html_field_is_escaped_not_injected(tmp_path):
    path = tmp_path / "f.db"
    with Store(path) as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
            "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, "xss-reflected", 1, "reflected-marker", json.dumps({}),
             "/x.php\"><script>alert(1)</script>", "GET",
             "<img src=x onerror=alert(1)>"))
        store.conn.commit()
    client = _client(path)
    fid = client.get("/api/findings").json()["findings"][0]["id"]
    body = client.get(f"/findings/{fid}").text
    assert "<script>alert(1)</script>" not in body
    assert "<img src=x onerror=alert(1)>" not in body
    # Jinja2 autoescaping turns the metacharacters into entities rather than
    # dropping the value — the untrusted text is still visible, just inert.
    assert "&lt;script&gt;" in body or "&lt;img" in body


# --- saved views (/api/views CRUD + round-trip) ------------------------------

def test_views_crud_round_trip(tmp_path):
    path = tmp_path / "v.db"
    client = _client(path)
    assert client.get("/api/views?table=findings").json() == {"views": []}

    spec = {"version": 1, "filter": {"text": "sqli", "facets": {"severity": ["Critical"]},
                                     "predicates": []}}
    created = client.post("/api/views?table=findings",
                          json={"name": "critical only", "spec": spec}).json()
    assert created["name"] == "critical only" and created["spec"] == spec
    assert created["pinned"] is False

    listed = client.get("/api/views?table=findings").json()["views"]
    assert len(listed) == 1 and listed[0]["id"] == created["id"]

    updated = client.put(f"/api/views/{created['id']}",
                         json={"name": "crit", "pinned": True}).json()
    assert updated["name"] == "crit" and updated["pinned"] is True
    assert updated["spec"] == spec           # untouched fields survive a partial update

    assert client.delete(f"/api/views/{created['id']}").json() == {"deleted": created["id"]}
    assert client.get("/api/views?table=findings").json() == {"views": []}


def test_views_are_scoped_by_table_key(tmp_path):
    path = tmp_path / "v.db"
    client = _client(path)
    client.post("/api/views?table=findings", json={"name": "a", "spec": {}})
    client.post("/api/views?table=recent-runs", json={"name": "b", "spec": {}})
    assert len(client.get("/api/views?table=findings").json()["views"]) == 1
    assert len(client.get("/api/views?table=recent-runs").json()["views"]) == 1


def test_view_create_requires_name(tmp_path):
    path = tmp_path / "v.db"
    r = _client(path).post("/api/views?table=findings", json={"name": "", "spec": {}})
    assert r.status_code == 400


def test_view_update_and_delete_404_for_missing_id(tmp_path):
    path = tmp_path / "v.db"
    client = _client(path)
    assert client.put("/api/views/999999", json={"name": "x"}).status_code == 404
    assert client.delete("/api/views/999999").status_code == 404


def test_views_pure_functions_round_trip(tmp_path):
    path = tmp_path / "v.db"
    with Store(path) as store:
        view = savedviews.create_view(store, "findings", "mine", {"a": 1}, pinned=True)
        assert view["pinned"] is True
        got = savedviews.get_view(store, view["id"])
        assert got["spec"] == {"a": 1}
        updated = savedviews.update_view(store, view["id"], spec={"a": 2})
        assert updated["spec"] == {"a": 2} and updated["name"] == "mine"
        assert savedviews.delete_view(store, view["id"]) is True
        assert savedviews.delete_view(store, view["id"]) is False
        assert savedviews.get_view(store, view["id"]) is None
