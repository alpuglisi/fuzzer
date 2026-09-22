"""Tests for the Diagnostics tab + store explorer (U5/CC-UI-0032).

Covers: the pure `fuzzlab.web.diagnostics` query functions (including LTTB
downsampling), the read-only API routes against `run_metrics`/`metric_series`
(no new backend beyond these read routes, per the U5 acceptance criteria),
and the store explorer's injection-safety (table-name validation against
`sqlite_master`, never raw SQL interpolation of caller input).
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store, log_scalar  # noqa: E402
from fuzzlab.web import diagnostics as diag  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402
from tests._webclient import web_client  # noqa: E402


# --- LTTB ---------------------------------------------------------------

def test_lttb_noop_under_threshold():
    xs = [0, 1, 2, 3, 4]
    ys = [1, 2, 3, 2, 1]
    out_x, out_y = diag.lttb(xs, ys, 10)
    assert out_x == xs and out_y == ys


def test_lttb_downsamples_and_keeps_endpoints():
    n = 5000
    xs = list(range(n))
    ys = [float(i % 7) for i in range(n)]
    out_x, out_y = diag.lttb(xs, ys, 1000)
    assert len(out_x) <= 1000
    assert out_x[0] == xs[0] and out_x[-1] == xs[-1]
    assert out_y[0] == ys[0] and out_y[-1] == ys[-1]
    # Monotonic x (LTTB preserves order).
    assert all(out_x[i] <= out_x[i + 1] for i in range(len(out_x) - 1))


def test_lttb_preserves_a_spike_a_naive_stride_would_erase():
    # A flat series with one large spike near the middle: a naive every-Nth
    # stride sample can easily miss a single-point spike; LTTB should not.
    n = 3000
    xs = list(range(n))
    ys = [0.0] * n
    spike_idx = 1500
    ys[spike_idx] = 1000.0
    out_x, out_y = diag.lttb(xs, ys, 300)
    assert max(out_y) > 500  # the spike (or something close to it) survived


# --- pure diagnostics functions over a seeded store ----------------------

def _seed(path):
    with Store(path) as store:
        run1 = store.start_run("auto", "cfg-a")
        run2 = store.start_run("auto", "cfg-b")
        for rid, val in ((run1, 0.9), (run2, 0.7)):
            store.conn.execute(
                "INSERT INTO run_metrics (run_id, key, value) VALUES (?,?,?)",
                (rid, "precision", val))
        for step in range(5):
            log_scalar(store, run1, "gbt", "train/loss", step, 1.0 / (step + 1))
            log_scalar(store, run2, "gbt", "train/loss", step, 2.0 / (step + 1))
        store.conn.execute(
            "INSERT INTO candidate (run_id, score) VALUES (?,?)", (run1, 0.42))
        store.conn.execute(
            "INSERT INTO candidate (run_id, score) VALUES (?,?)", (run1, 0.88))
        store.conn.execute(
            "INSERT INTO bandit_posteriors (context, arm, alpha, beta) VALUES (?,?,?,?)",
            ("default", "sqli", 3.0, 1.0))
        store.conn.execute(
            "INSERT INTO model (name, version, calibration) VALUES (?,?,?)",
            ("classifier", 1, "{}"))
        store.conn.commit()
        return run1, run2


def test_metric_keys_grouped_by_source(tmp_path):
    path = tmp_path / "d.db"
    _seed(path)
    with Store(path) as store:
        keys = diag.metric_keys(store)
    assert "precision" in keys["run_metrics"]
    assert keys["series"]["gbt"] == ["train/loss"]


def test_run_metrics_trend(tmp_path):
    path = tmp_path / "d.db"
    r1, r2 = _seed(path)
    with Store(path) as store:
        trend = diag.run_metrics_trend(store, [r1, r2], ["precision"])
    assert trend["series"]["precision"] == [0.9, 0.7]


def test_metric_series_downsampled_per_run(tmp_path):
    path = tmp_path / "d.db"
    r1, r2 = _seed(path)
    with Store(path) as store:
        out = diag.metric_series_data(store, [r1, r2], "gbt", "train/loss", max_points=3)
    assert set(out["series"].keys()) == {str(r1), str(r2)}
    assert len(out["series"][str(r1)]["steps"]) <= 3


def test_candidate_score_histogram(tmp_path):
    path = tmp_path / "d.db"
    r1, _ = _seed(path)
    with Store(path) as store:
        hist = diag.candidate_score_histogram(store, r1, bins=4)
    assert hist["n"] == 2
    assert sum(hist["counts"]) == 2


def test_bandit_arms_and_model_registry(tmp_path):
    path = tmp_path / "d.db"
    _seed(path)
    with Store(path) as store:
        arms = diag.bandit_arms(store)
        models = diag.model_registry_timeline(store)
    assert arms[0]["context"] == "default" and arms[0]["mean"] == pytest.approx(0.75)
    assert models[0]["name"] == "classifier"


# --- store explorer: read-only + injection-safe ---------------------------

def test_list_tables_excludes_sqlite_internal(tmp_path):
    path = tmp_path / "d.db"
    _seed(path)
    with Store(path) as store:
        tables = diag.list_tables(store)
    assert "run" in tables and "candidate" in tables
    assert not any(t.startswith("sqlite_") for t in tables)


def test_browse_table_returns_rows(tmp_path):
    path = tmp_path / "d.db"
    r1, r2 = _seed(path)
    with Store(path) as store:
        page = diag.browse_table(store, "run", limit=10)
    assert page["table"] == "run"
    assert page["total"] == 2
    assert "id" in page["columns"]


def test_browse_table_rejects_unknown_table(tmp_path):
    path = tmp_path / "d.db"
    _seed(path)
    with Store(path) as store:
        assert diag.browse_table(store, "not_a_real_table") is None


@pytest.mark.parametrize("evil", [
    "run; DROP TABLE run;--",
    "run\" ; DROP TABLE run --",
    "sqlite_master",
    "run/**/UNION/**/SELECT/**/1",
    "run WHERE 1=1; DELETE FROM run",
])
def test_browse_table_rejects_injection_attempts(tmp_path, evil):
    path = tmp_path / "d.db"
    _seed(path)
    with Store(path) as store:
        assert diag.browse_table(store, evil) is None
        assert diag.table_columns(store, evil) is None
        # Confirm the table was NOT dropped/tampered with by any of these.
        assert diag.list_tables(store)  # still has tables
        rows = store.conn.execute("SELECT COUNT(*) c FROM run").fetchone()
        assert rows["c"] == 2


def test_browse_table_binary_column_is_summarized_not_raw_bytes(tmp_path):
    path = tmp_path / "d.db"
    with Store(path) as store:
        store.put_body(b"\x00\x01binary-blob")
        store.conn.commit()
        page = diag.browse_table(store, "body", limit=10)
    cols = page["columns"]
    data_idx = cols.index("data")
    assert isinstance(page["rows"][0][data_idx], str)
    assert "bytes" in page["rows"][0][data_idx]


# --- API routes (no new backend beyond these read routes) -----------------

def _client(path):
    cfg = load_config(overrides={"store_path": str(path),
                                 "target_base_url": "http://127.0.0.1:8080"}, environ={})
    return web_client(create_app(cfg))


def test_diagnostics_page_renders(tmp_path):
    path = tmp_path / "d.db"
    _seed(path)
    client = _client(path)
    r = client.get("/diagnostics")
    assert r.status_code == 200
    assert "diagnostics-root" in r.text
    assert "store-table-select" in r.text


def test_diagnostics_api_routes(tmp_path):
    path = tmp_path / "d.db"
    r1, r2 = _seed(path)
    client = _client(path)

    r = client.get("/api/diagnostics/runs")
    assert r.status_code == 200
    ids = {row["id"] for row in r.json()["runs"]}
    assert {r1, r2} <= ids

    r = client.get("/api/diagnostics/metrics")
    assert r.status_code == 200
    assert "precision" in r.json()["run_metrics"]

    r = client.get(f"/api/diagnostics/trend?run_ids={r1},{r2}&keys=precision")
    assert r.status_code == 200
    assert r.json()["series"]["precision"] == [0.9, 0.7]

    r = client.get(f"/api/diagnostics/series?run_ids={r1},{r2}&source=gbt&key=train/loss")
    assert r.status_code == 200
    assert str(r1) in r.json()["series"]

    r = client.get(f"/api/diagnostics/candidates/{r1}")
    assert r.status_code == 200
    assert r.json()["n"] == 2

    r = client.get("/api/diagnostics/bandit")
    assert r.status_code == 200
    assert r.json()["arms"][0]["arm"] == "sqli"

    r = client.get("/api/diagnostics/models")
    assert r.status_code == 200
    assert r.json()["models"][0]["name"] == "classifier"


def test_diagnostics_routes_are_read_only_no_store_file(tmp_path):
    """Hitting every diagnostics route before the store exists must never
    create the store file (D11/NFR-UI-read-only) — same contract as
    `_read_runs` et al."""
    path = tmp_path / "does-not-exist.db"
    client = _client(path)
    for url in ("/diagnostics", "/api/diagnostics/runs", "/api/diagnostics/metrics",
                "/api/diagnostics/bandit", "/api/diagnostics/models",
                "/api/store/tables"):
        r = client.get(url)
        assert r.status_code == 200
    assert not path.exists()


def test_store_explorer_api_routes(tmp_path):
    path = tmp_path / "d.db"
    _seed(path)
    client = _client(path)

    r = client.get("/api/store/tables")
    assert r.status_code == 200
    tables = r.json()["tables"]
    assert "run" in tables

    r = client.get("/api/store/tables/run?limit=1&offset=0")
    assert r.status_code == 200
    page = r.json()
    assert page["total"] == 2
    assert len(page["rows"]) == 1

    r = client.get("/api/store/tables/run?limit=1&offset=1")
    assert r.status_code == 200
    assert len(r.json()["rows"]) == 1


@pytest.mark.parametrize("evil", [
    "run;DROP TABLE run;--",
    "sqlite_master",
    "../../etc/passwd",
    "run UNION SELECT sql FROM sqlite_master",
])
def test_store_explorer_api_rejects_injection_attempts(tmp_path, evil):
    path = tmp_path / "d.db"
    _seed(path)
    client = _client(path)
    r = client.get(f"/api/store/tables/{evil}")
    assert r.status_code == 404
    # The store must be intact afterward.
    with Store(path) as store:
        assert store.conn.execute("SELECT COUNT(*) c FROM run").fetchone()["c"] == 2


def test_store_explorer_response_never_contains_html_tags_for_rendering():
    """The API hands back plain JSON values (not pre-rendered HTML) — the
    client is responsible for textContent-only rendering (datatable.js). This
    just confirms the server side never wraps a value in markup itself."""
    import json as _json
    from fuzzlab.web.diagnostics import _jsonable
    assert _jsonable(b"<script>evil()</script>") == "<23 bytes>"
    assert _jsonable("<script>evil()</script>") == "<script>evil()</script>"
    # (The literal string value passes through untouched — safety is the
    # client's textContent-only contract, verified by inspection of
    # diagnostics.js/datatable.js below.)


def test_vendored_uplot_present_and_injection_safe_static_serve(tmp_path):
    path = tmp_path / "d.db"
    _seed(path)
    client = _client(path)
    r = client.get("/static/vendor/uplot/uPlot.esm.js")
    assert r.status_code == 200
    assert b"uPlot" in r.content
    r = client.get("/static/vendor/uplot/uPlot.min.css")
    assert r.status_code == 200


def test_js_files_use_textcontent_not_innerhtml():
    """Static guard for the datatable/diagnostics modules' injection-safety
    rule (store rows are untrusted): neither ever assigns innerHTML."""
    import pathlib
    base = pathlib.Path(__file__).parent.parent / "fuzzlab" / "web" / "static" / "js"
    for name in ("datatable.js", "diagnostics.js", "chart.js"):
        text = (base / name).read_text()
        # Only comments in these files may mention innerHTML (to document the
        # rule); no line may actually assign/read `.innerHTML`.
        for line in text.splitlines():
            code = line.split("//", 1)[0]
            assert "innerHTML" not in code, f"{name} must never use innerHTML: {line!r}"
