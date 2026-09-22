"""Tests for the Diagnostics section (U5): metric charts over `metric_series`
and the read-only store explorer.

Layer A (pure-JS units for LTTB/EMA) lives in tests/js/ and is run here via
`node --test` so `pytest` alone stays the one command that proves the whole
lane green (R-09). Layer B (route/no-JS) is plain TestClient, covering both
the empty-store and seeded-metrics cases the lane's brief calls out, plus the
store explorer's redaction contract. Layer C (real-browser chart assertions
via `window.__charts` + the offscreen table) is test_web_diagnostics_browser.py.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store, log_scalar  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402

_REPO = Path(__file__).resolve().parent.parent
_JS_TESTS = [
    _REPO / "tests" / "js" / "test_downsample.js",
    _REPO / "tests" / "js" / "test_smoothing.js",
]


def test_downsample_and_smoothing_js_units():
    # R-09 layer A: pure-JS units for LTTB/envelope downsampling + EMA
    # smoothing, run via Node's built-in test runner (no new dependency).
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available")
    result = subprocess.run(
        [node, "--test", *[str(p) for p in _JS_TESTS]],
        capture_output=True, text=True, cwd=str(_REPO),
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _client(store_path: str | None = None):
    overrides = {"target_base_url": "http://localhost"}
    if store_path is not None:
        overrides["store_path"] = store_path
    cfg = load_config(overrides=overrides, environ={})
    return TestClient(create_app(cfg))


def _seed_metrics(path: str) -> int:
    with Store(path) as store:
        run_id = store.start_run("gbt", "cfg-1")
        for step in range(30):
            log_scalar(store, run_id, "gbt", "train/loss", step, 1.0 / (step + 1))
        for step in range(12):
            log_scalar(store, run_id, "bandit", "posterior/sqli/mean", step, 0.05 * step)
            log_scalar(store, run_id, "bandit", "regret/cumulative", step, 0.02 * step)
        return run_id


# --- route + no-JS: empty store -------------------------------------------

def test_diagnostics_empty_store(tmp_path):
    client = _client(str(tmp_path / "empty.db"))
    r = client.get("/diagnostics")
    assert r.status_code == 200
    assert r.template.name == "sections/diagnostics.html"
    assert r.context["active"] == "diagnostics"
    assert "No metric series recorded yet" in r.text
    assert "No store file yet" in r.text
    assert 'data-chart-id' not in r.text


# --- route + no-JS: seeded metrics -----------------------------------------

def test_diagnostics_seeded_metrics_renders_charts(tmp_path):
    store_path = str(tmp_path / "seeded.db")
    _seed_metrics(store_path)
    client = _client(store_path)
    r = client.get("/diagnostics")
    assert r.status_code == 200
    body = r.text
    # one chart per populated (source, key) -- grouped by source
    assert 'data-source="gbt"' in body and 'data-key="train/loss"' in body
    assert 'data-source="bandit"' in body and 'data-key="posterior/sqli/mean"' in body
    assert 'data-mode="envelope"' in body  # bandit -> min/max band (R-08)
    assert 'data-mode="line"' in body      # gbt -> plain trend line
    # the offscreen table fallback ships with every chart, pre-populated
    # server-side (R-09/R-11) -- not only built by JS at runtime.
    assert 'class="visually-hidden-table"' in body
    assert "<td>0</td>" in body  # step 0 present in a fallback table
    # each chart's data is embedded for the client wrapper to pick up
    # without a second round-trip
    assert 'data-chart-json="chart-0"' in body
    # the store explorer also has something to show once the store exists
    assert 'id="store-table-form"' in body


def test_diagnostics_api_series_and_data(tmp_path):
    store_path = str(tmp_path / "seeded.db")
    _seed_metrics(store_path)
    client = _client(store_path)

    series = client.get("/api/diagnostics/series").json()["series"]
    keys = {(s["source"], s["key"]) for s in series}
    assert ("gbt", "train/loss") in keys
    assert ("bandit", "posterior/sqli/mean") in keys
    bandit_entry = next(s for s in series if s["key"] == "regret/cumulative")
    assert bandit_entry["mode"] == "envelope"
    gbt_entry = next(s for s in series if s["key"] == "train/loss")
    assert gbt_entry["mode"] == "line"

    data = client.get("/api/diagnostics/series/data",
                      params={"source": "gbt", "key": "train/loss"}).json()
    assert data["mode"] == "line"
    assert len(data["series"]) == 1
    assert len(data["series"][0]["y"]) == 30  # under the 1000-pt cap: no downsampling

    env = client.get("/api/diagnostics/series/data",
                     params={"source": "bandit", "key": "regret/cumulative"}).json()
    assert env["mode"] == "envelope"
    assert "min" in env["series"][0] and "max" in env["series"][0]


def test_diagnostics_series_data_unknown_store_404(tmp_path):
    client = _client(str(tmp_path / "missing.db"))
    r = client.get("/api/diagnostics/series/data", params={"source": "gbt", "key": "x"})
    assert r.status_code == 404


# --- store explorer: redaction -------------------------------------------

def test_store_explorer_redacts_secret_bearing_columns(tmp_path):
    store_path = str(tmp_path / "s.db")
    with Store(store_path) as store:
        store.upsert_session_state({
            "host": "lab.local", "identity": "user1", "kind": "cookie",
            "valid": True, "login_url": "http://lab.local/login",
            "logout_url": None, "token_exp": 1234567.0,
        })
    client = _client(store_path)

    tables = {t["name"]: t for t in client.get("/api/store/tables").json()["tables"]}
    assert "session_state" in tables
    cols = {c["name"]: c["redacted"] for c in tables["session_state"]["columns"]}
    assert cols["token_exp"] is True         # column-name redaction
    assert cols["host"] is False
    assert cols["login_url"] is False

    rows = client.get("/api/store/session_state").json()["rows"]
    assert rows[0]["token_exp"] == "***redacted***"
    assert rows[0]["host"] == "lab.local"    # non-secret columns pass through


def test_store_explorer_never_renders_raw_blob_bytes(tmp_path):
    store_path = str(tmp_path / "s.db")
    secret_bytes = b"GET / HTTP/1.1\r\nAuthorization: Bearer top-secret-token\r\n\r\n"
    with Store(store_path) as store:
        store.put_body(secret_bytes)
    client = _client(store_path)

    r = client.get("/api/store/body")
    payload = r.json()
    assert payload["rows"][0]["data"].startswith("<blob:")
    assert "Bearer" not in r.text
    assert "top-secret-token" not in r.text


def test_store_explorer_unknown_table_404(tmp_path):
    store_path = str(tmp_path / "s.db")
    Store(store_path).close()  # create an empty, migrated store
    client = _client(store_path)
    r = client.get("/api/store/not_a_real_table")
    assert r.status_code == 404


def test_store_explorer_pagination(tmp_path):
    store_path = str(tmp_path / "s.db")
    with Store(store_path) as store:
        for i in range(5):
            store.start_run("gbt", f"cfg-{i}")
    client = _client(store_path)
    r = client.get("/api/store/run", params={"limit": 2, "offset": 0}).json()
    assert r["total"] == 5
    assert len(r["rows"]) == 2
    r2 = client.get("/api/store/run", params={"limit": 2, "offset": 2}).json()
    assert len(r2["rows"]) == 2
    assert r2["rows"][0]["id"] != r["rows"][0]["id"]


def test_diagnostics_route_reads_table_query_param(tmp_path):
    store_path = str(tmp_path / "s.db")
    with Store(store_path) as store:
        store.start_run("gbt", "cfg-1")
    client = _client(store_path)
    r = client.get("/diagnostics", params={"table": "run"})
    assert r.status_code == 200
    assert 'value="run" selected' in r.text or "selected" in r.text
