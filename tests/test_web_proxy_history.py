"""Tests for the read-only proxy flow history (Phase 2.1)."""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.proxy.history import FlowRecord, HistoryWriter
from fuzzlab.web import proxyview


def _seed(path):
    with Store(path) as store:
        run_id = store.start_run("proxy", "127.0.0.1")
        hw = HistoryWriter(store, run_id, batch_size=1)
        hw.record(FlowRecord(
            method="GET", url="http://127.0.0.1:8080/product.php?id=1", host="127.0.0.1",
            status=200, elapsed_ms=12.5, protocol="http/1.1",
            raw_request=b"GET /product.php?id=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            raw_response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
        hw.record(FlowRecord(
            method="POST", url="http://127.0.0.1:8080/login.php", host="127.0.0.1",
            status=302, elapsed_ms=8.0, protocol="http/1.1",
            raw_request=b"POST /login.php HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            raw_response=b"HTTP/1.1 302 Found\r\n\r\n"))
        hw.flush()


# --- view layer ------------------------------------------------------------

def test_list_flows_newest_first(tmp_path):
    path = tmp_path / "p.db"
    _seed(path)
    with Store(path) as store:
        flows = proxyview.list_flows(store)
        assert len(flows) == 2
        assert flows[0]["method"] == "POST"      # newest first
        assert "/product.php" in flows[1]["url"]
        assert flows[0]["status"] == 302 and flows[0]["protocol"] == "http/1.1"


def test_list_flows_fts_query(tmp_path):
    path = tmp_path / "p.db"
    _seed(path)
    with Store(path) as store:
        assert len(proxyview.list_flows(store, query="product.php")) == 1
        assert proxyview.list_flows(store, query="no-such-thing") == []


def test_flow_detail_decodes_raw(tmp_path):
    path = tmp_path / "p.db"
    _seed(path)
    with Store(path) as store:
        flows = proxyview.list_flows(store)
        det = proxyview.flow_detail(store, flows[1]["id"])
        assert "GET /product.php?id=1" in det["raw_request"]
        assert "200 OK" in det["raw_response"]
        assert det["redacted"] is True
    with Store(path) as store:
        assert proxyview.flow_detail(store, 99999) is None


# --- routes ----------------------------------------------------------------

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from tests._webclient import web_client  # noqa: E402


def _client(path):
    cfg = load_config(overrides={"store_path": str(path)}, environ={})
    return web_client(create_app(cfg))


def test_api_flows_list_and_search(tmp_path):
    path = tmp_path / "p.db"
    _seed(path)
    client = _client(path)
    assert len(client.get("/api/proxy/flows").json()["flows"]) == 2
    hits = client.get("/api/proxy/flows", params={"q": "login.php"}).json()["flows"]
    assert len(hits) == 1 and "/login.php" in hits[0]["url"]


def test_api_flow_detail_and_404(tmp_path):
    path = tmp_path / "p.db"
    _seed(path)
    client = _client(path)
    fid = client.get("/api/proxy/flows").json()["flows"][0]["id"]
    det = client.get(f"/api/proxy/flows/{fid}").json()
    assert "302 Found" in det["raw_response"]
    assert client.get("/api/proxy/flows/99999").status_code == 404


def test_api_flows_missing_store_is_empty_and_creates_nothing(tmp_path):
    path = tmp_path / "missing.db"
    client = _client(path)
    assert client.get("/api/proxy/flows").json()["flows"] == []
    assert not path.exists()


def test_proxy_page_renders_history_ui(tmp_path):
    # Proxy is its own route now (U0/CC-UI-0025), not a hash-switched panel on "/".
    path = tmp_path / "p.db"
    _seed(path)
    body = _client(path).get("/proxy").text
    assert 'id="flow-table"' in body and 'id="flow-search"' in body
    assert 'data-section="proxy"' in body
