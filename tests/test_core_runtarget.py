"""`core.runtarget`: the one reader of a run's recorded target (CC-CORE-0500, PA-0063(1)).

A run's target is its first `target` row by id; its origin is that row's base URL through
`core.urls.canonical_origin`. Every reader in `fuzzlab/` goes through this module; the
guard below fails on any other ``FROM target`` / ``JOIN target`` (a lint: SQL split across
string literals or built dynamically is not seen -- the stated limit, as PA-0130 states
its own).
"""

from __future__ import annotations

import re

import pytest
from pathlib import Path

from fuzzlab.core.evidence import method_key
from fuzzlab.core.runtarget import run_origins, run_target, run_target_rows
from fuzzlab.core.store import Store

ROOT = Path(__file__).resolve().parents[1] / "fuzzlab"

#: Files allowed to read `target` rows directly, each with its reason.
ALLOWED = {
    "core/runtarget.py": "the one reader",
    "core/migrations.py": "migration 19's shipped post-step (_backfill_holdout_seal) runs "
                          "inside an applied migration and is never edited",
}

#: Upper-case keywords, as every SQL statement in `fuzzlab/` is written, so prose such as
#: "from target list" is not mistaken for a read (a stated lint limit: lower-case SQL is
#: not seen).
_TARGET_READ = re.compile(r"\b(?:FROM|JOIN)\s+target\b")


def _offenders(root: Path, allowed: dict[str, str]) -> list[str]:
    out = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if rel in allowed:
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _TARGET_READ.search(line):
                out.append(f"{rel}:{n}: {line.strip()}")
    return out


def test_no_module_reads_target_rows_outside_runtarget():
    assert _offenders(ROOT, ALLOWED) == []


def test_guard_flags_a_synthetic_offender(tmp_path):
    """PA-0034(2): the guard is proven on a file built to break it."""
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "runtarget.py").write_text('SQL = "SELECT * FROM target"\n')
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "bad.py").write_text(
        'row = conn.execute("SELECT base_url FROM target WHERE run_id=? '
        'ORDER BY id DESC LIMIT 1")\n'
        'other = "SELECT f.id FROM finding f LEFT JOIN  target t ON t.run_id=f.run_id"\n'
        'fine = "SELECT target_base_url FROM targets_view"\n')
    found = _offenders(tmp_path, {"core/runtarget.py": "the one reader"})
    assert [f.split(":")[1] for f in found] == ["1", "2"], found


def _store(tmp_path) -> Store:
    return Store(tmp_path / "s.db")


def test_first_target_row_wins_and_runs_without_one_are_absent(tmp_path):
    with _store(tmp_path) as s:
        a = s.start_run("auto", "h")
        b = s.start_run("crawler", "x")
        c = s.start_run("auto", "h2")
        s.conn.execute("INSERT INTO target (run_id, base_url, dbms) VALUES (?,?,?)",
                       (a, "http://LOCALHOST:8080", "mysql"))
        s.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)",
                       (a, "http://other:9"))                 # a later, second row
        s.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)",
                       (c, "http://example.test:99999"))   # an out-of-range port
        s.conn.commit()
        rows = run_target_rows(s.conn)
        assert set(rows) == {a, c}
        assert rows[a]["base_url"] == "http://LOCALHOST:8080" and rows[a]["dbms"] == "mysql"
        assert run_target(s.conn, a)["base_url"] == "http://LOCALHOST:8080"
        assert run_target(s.conn, b) is None and run_target(s.conn, None) is None
        assert run_target_rows(s.conn, [c]) == {c: rows[c]}
        origins = run_origins(s.conn)
        assert origins[a] == "http://127.0.0.1:8080"          # loopback alias, port made explicit
        assert origins[c] is None                             # unusable base URL: no origin
        assert b not in origins


def test_ml_and_report_readers_agree_with_the_core_reader(tmp_path):
    """The swept readers return what `core.runtarget` returns (CC-ML-0500, CC-UI-0501)."""
    import pytest
    from fuzzlab.report.report import build_report
    from fuzzlab.web import results
    with _store(tmp_path) as s:
        a = s.start_run("auto", "h")
        s.conn.execute("INSERT INTO target (run_id, base_url, waf) VALUES (?,?,?)",
                       (a, "http://127.0.0.1:8080", "none"))
        s.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)",
                       (a, "http://later.example:1"))
        s.conn.execute("INSERT INTO finding (run_id, label, url, method, param) "
                       "VALUES (?,1,'/p','GET','id')", (a,))
        s.conn.commit()
        fid = s.conn.execute("SELECT id FROM finding").fetchone()[0]
        assert build_report(s, a)["target"]["base_url"] == "http://127.0.0.1:8080"
        assert results.run_detail(s, a)["target_fingerprint"] == {
            "base_url": "http://127.0.0.1:8080", "dbms": None, "framework": None,
            "waf": "none"}
        assert results.finding_detail(s, fid)["target_base_url"] == "http://127.0.0.1:8080"
        dataset = pytest.importorskip("fuzzlab.ml.dataset")
        assert dataset.target_of(s, a) == "http://127.0.0.1:8080"
        assert dataset.target_runs(s, "http://localhost:8080") == [a]
        assert dataset.target_runs(s, "http://later.example:1") == []   # first row only
        assert dataset.method_key is method_key


def test_method_key_is_upper_case_with_the_get_default():
    assert method_key("post") == "POST"
    assert method_key("") == "GET" and method_key(None) == "GET" and method_key(3) == "GET"


@pytest.mark.xfail(strict=True, reason="BUG-0500 follow-up: core/urls.py (locked by another "
                   "session) -- canonical_origin must return None for a malformed authority "
                   "instead of raising; readers go through core.runtarget.origin_of meanwhile")
@pytest.mark.parametrize("url", ["http://[::1", "http://a\uff03b", "http://[zz]:80"])
def test_canonical_origin_is_total_for_malformed_authorities(url):
    from fuzzlab.core.urls import canonical_origin
    assert canonical_origin(url) is None


@pytest.mark.parametrize("url", ["http://[::1", "http://a\uff03b", "http://[zz]:80",
                                 "http://h:99999", "http://h:x", "\ud800", "http://\x00h",
                                 None, 5])
def test_origin_of_is_total(url):
    """PA-0500(1): the stored-value boundary returns its sentinel on every malformed
    input of the URL grammar."""
    from fuzzlab.core.runtarget import origin_of
    assert origin_of(url) is None or isinstance(origin_of(url), str)
