"""Shipping without ML (FR-ML-6, CC-UI-0041, CC-FUZZ-0050).

A store is seeded *with* ML (`fuzzlab auto --score --rank --anomaly`: model rows, scores,
the ML stages on the run record). A child process then blocks `fuzzlab.ml` the way a
build without the package does (`tests/_no_ml_child.py`) and must still: scan, refuse the
ML flags cleanly before any run row, build the report (models marked unavailable, never
"none"), serve every HTML page, report the ML panels unavailable while keeping the
others, and list the run's stored scores. Then a real browser (PA-0065(3)) loads `/ml`
and the run page from a server running without ML.

The child runs without `-I` (the web extra may live in user site-packages); a missing
web extra or browser fails rather than skips under `FUZZLAB_REQUIRE_BROWSER=1`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from fuzzlab import procutil
from fuzzlab.core.store import Store
from tests._browser import free_port, launch_browser_or_skip, require_modules
from tests.test_auto_budget import _main

REPO = Path(__file__).resolve().parent.parent
CHILD = REPO / "tests" / "_no_ml_child.py"
UNAVAILABLE = "ML components are not installed"
ML_PANELS = {"classifier", "weights", "ranker", "conformal", "anomaly", "disagreement"}


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("noml")
    mp = pytest.MonkeyPatch()
    try:
        assert _main(tmp, mp, "--score", "--rank", "--anomaly") == 0
    finally:
        mp.undo()
    with Store(tmp / "s.db") as store:
        run_id = store.conn.execute("SELECT MAX(id) FROM run").fetchone()[0]
        scored = store.conn.execute(
            "SELECT COUNT(*) FROM candidate WHERE run_id=? AND score IS NOT NULL",
            (run_id,)).fetchone()[0]
        assert scored > 0 and store.conn.execute("SELECT COUNT(*) FROM model").fetchone()[0]
    return tmp / "s.db", run_id, tmp


@pytest.fixture(scope="module")
def child(seeded):
    require_modules(module_level=False)          # web extra: skip, or fail when required
    db, run_id, tmp = seeded
    work = tmp / "child"
    work.mkdir()
    proc = subprocess.run([sys.executable, str(CHILD), "check", str(db), str(run_id),
                           str(work)], capture_output=True, text=True, env=_env(),
                          cwd=str(REPO), timeout=300)
    assert proc.returncode == 0, proc.stderr[-3000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def built_child(seeded, tmp_path_factory):
    """The same checks against a **real no-ML build** (CC-ML-0022): the package is built
    with the FR-ML-6 switch (both lines) and put first on the path — no import blocker."""
    require_modules(module_level=False)
    from tests.test_packaging import _tracked, build_no_ml
    out = build_no_ml(tmp_path_factory.mktemp("nomlbuild"), _tracked())
    db, run_id, tmp = seeded
    work = tmp / "built_child"
    work.mkdir()
    env = _env()
    env["PYTHONPATH"] = str(out) + os.pathsep + env["PYTHONPATH"]
    env["FUZZLAB_NOML_REAL"] = "1"
    proc = subprocess.run([sys.executable, str(CHILD), "check", str(db), str(run_id),
                           str(work)], capture_output=True, text=True, env=env,
                          cwd=str(REPO), timeout=300)    # GT_DIR is repo-relative
    assert proc.returncode == 0, proc.stderr[-3000:]
    return json.loads(proc.stdout.strip().splitlines()[-1]), out


def test_a_real_no_ml_build_passes_the_same_checks(built_child, child):
    got, out = built_child
    assert got["fuzzlab_path"].startswith(str(out))          # the built tree, not the repo
    assert got["ml_blocked"] is True                          # genuinely absent
    assert got["dropped_finders"]                   # the dev-only editable finder is gone
    assert got["scan"]["rc"] == 0 and got["scan"]["findings"] == child["scan"]["findings"]
    assert got["score_flag"]["rc"] == 2 and got["score_flag"]["runs"] == 0
    assert got["flow_anomaly"]["rc"] == 2
    assert got["report"]["models_unavailable"] == child["report"]["models_unavailable"]
    assert got["pages"] == child["pages"]
    assert got["ml_data"] == child["ml_data"]


def test_the_child_really_runs_without_ml(child):
    assert child["ml_blocked"] is True               # not vacuous


def test_a_scan_without_ml_flags_works(child):
    assert child["scan"]["rc"] == 0 and child["scan"]["findings"] > 0


def test_an_ml_flag_is_refused_cleanly_before_any_run(child):
    flag = child["score_flag"]
    assert flag["rc"] == 2 and flag["runs"] == 0
    assert f"{UNAVAILABLE}: --score/--rank/--anomaly need fuzzlab.ml" in flag["stderr"]
    assert "Traceback" not in flag["stderr"]


def test_flow_anomaly_exits_2_with_the_not_installed_message(child):
    """CC-FUZZ-0054: `fuzzlab flow-anomaly` is reached through `import_ml` only."""
    fa = child["flow_anomaly"]
    assert fa["rc"] == 2 and UNAVAILABLE in fa["stderr"] and "Traceback" not in fa["stderr"]


def test_the_report_marks_models_unavailable_and_keeps_the_plugin_record(child):
    rep = child["report"]
    assert rep["models"] == [] and rep["models_unavailable"] == UNAVAILABLE
    assert f"models: unavailable ({UNAVAILABLE})" in rep["text"]
    by = {p["name"]: p for p in rep["plugins"]}
    assert set(by) == {"ml-classifier", "ml-ranker", "ml-anomaly"}
    assert by["ml-classifier"]["config"] == '{"hybrid":false,"model_kind":"auto","train_on":"run"}'
    assert {p["status"] for p in rep["plugins"]} == {"ok"}


def test_every_html_page_is_served(child):
    pages = child["pages"]
    assert "/ml" in pages and any(p.startswith("/runs/") for p in pages)
    assert {p: s for p, s in pages.items() if s != 200} == {}


def test_ml_panels_degrade_and_the_others_do_not(child):
    data = child["ml_data"]
    for panel in ML_PANELS:
        assert data[panel] == [False, UNAVAILABLE], panel
    for panel in ("bandit", "mutation"):
        assert data[panel][1] != UNAVAILABLE, panel


def test_the_run_page_still_lists_the_stored_scores(child):
    html = child["run_page"]
    assert "Model scores (advisory)" in html and UNAVAILABLE in html
    assert "<td>n/a</td>" in html                    # no gate without the model


# --- real browser, server without ML (PA-0065(3)) ---------------------------------

def test_ml_tab_and_run_page_render_without_ml_in_a_real_browser(seeded):
    require_modules(module_level=False)
    from playwright.sync_api import sync_playwright

    from tests.test_web_pages_browser import _Page
    db, run_id, _ = seeded
    port = free_port()
    server_handle = procutil.start_server([sys.executable, str(CHILD), "serve", str(db), str(port), "127.0.0.1"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              env=_env(), cwd=str(REPO))
    server = server_handle.proc
    try:
        assert server.stdout.readline().strip() == "ML_BLOCKED"
        import urllib.request
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        procutil.assert_loopback_only(server_handle)  # BUG-0130: checked after boot
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            try:
                tab = _Page(browser, f"http://127.0.0.1:{port}")
                page = tab.open("/ml")
                page.wait_for_selector(f"text={UNAVAILABLE}")
                assert UNAVAILABLE in page.inner_text("#panel-calibration")
                assert UNAVAILABLE in page.inner_text("#panel-ranker")
                assert tab.problems() == []
                tab.close()
                tab = _Page(browser, f"http://127.0.0.1:{port}")
                page = tab.open(f"/runs/{run_id}")
                assert UNAVAILABLE in page.inner_text("body")
                assert tab.problems() == []
                tab.close()
            finally:
                browser.close()
    finally:
        procutil.stop_server(server_handle)
