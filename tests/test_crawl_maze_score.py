"""`scripts/crawl_maze_score.py` (CC-LAB-0302): a run's requests scored against the
Crawl Maze's expected set, for both discovery tools' outputs. No lab needed."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

from fuzzlab.disco.capture import append_record, make_record

_SPEC = importlib.util.spec_from_file_location(
    "crawl_maze_score", Path(__file__).resolve().parent.parent / "scripts/crawl_maze_score.py")
cms = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cms)

EXPECTED = ["/test/html/body/a/href.found", "/test/html/body/img/src.found",
            "/test/headers/link.found", "/javascript/frameworks/react/index.html.found"]
BASE = "http://127.0.0.1:3061"


def test_a_disco_run_counts_every_request_it_made(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    for path in ("/test/html/body/a/href.found?x=1", "/test/html/body/img/src.found", "/"):
        append_record(run / "capture.jsonl", make_record(
            kind="http", t=1.0, action_id="nav-1", method="GET", url=BASE + path,
            req_headers={}, req_body=None, status=200, res_headers={}, res_body=b""))
    (tmp_path / "exp.json").write_text(json.dumps(EXPECTED))
    result = cms.score(cms.load_expected(str(tmp_path / "exp.json")),
                       cms.requested_disco(run))
    assert result["found"] == 2 and result["total"] == 4
    assert result["missed"] == ["/test/headers/link.found",
                                "/javascript/frameworks/react/index.html.found"]
    assert result["by_category"]["html/body"] == (2, 2)
    assert result["by_category"]["headers"] == (0, 1)


def test_a_spider_db_counts_pages_and_captured_requests(tmp_path):
    db = tmp_path / "s.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE discovered_pages (url TEXT)")
    conn.execute("CREATE TABLE discovered_requests (url TEXT)")
    conn.execute("INSERT INTO discovered_pages VALUES (?)", (BASE + EXPECTED[0],))
    conn.execute("INSERT INTO discovered_requests VALUES (?)", (BASE + EXPECTED[2],))
    conn.commit()
    conn.close()
    assert cms.requested_spider(db) == {EXPECTED[0], EXPECTED[2]}
    assert cms.score(EXPECTED, cms.requested_spider(db))["found"] == 2
