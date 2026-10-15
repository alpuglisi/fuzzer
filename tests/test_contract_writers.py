"""Every contract column a reader can depend on has a production writer (PA-0071,
BUG-0069).

BUG-0069: the report read `candidate.feature_version`, which no production code ever
wrote; its test passed because the fixture wrote the column by hand. This guard derives
the columns of the store's contract tables **from the migrated schema** (so a new column
cannot escape by not being listed) and asserts each one has an INSERT or UPDATE writer
somewhere in `fuzzlab/` — or an allowlist entry that says why not. It is proven on a
synthetic writer-less column (PA-0034(2)).
"""

from __future__ import annotations

import re
from pathlib import Path

from fuzzlab.core.store import Store

ROOT = Path(__file__).resolve().parent.parent / "fuzzlab"
CONTRACT_TABLES = ("candidate", "attempt", "flow", "finding", "model", "run_metrics",
                   "run_plugin", "holdout_metric", "holdout_reveal", "target", "run",
                   "project", "launch")                       # migration 22, CC-CORE-0450
#: Columns with no production writer, and why that is acceptable. Readers of these must
#: not present them as recorded facts (BUG-0069).
ALLOWLIST = {
    ("candidate", "features_json"): "features are recomputed on read (FR-ML-5, partial)",
    ("candidate", "feature_version"): "recomputed on read; the report unions it with the "
                                      "versions stages record (BUG-0069)",
    ("attempt", "feature_version"): "attempt features are writer-specific telemetry named "
                                    "by `_schema` in features_json, not a versioned "
                                    "extractor (BUG-0069 sweep)",
    ("attempt", "candidate_id"): "attempts are not yet linked to candidates (FR-ML-1 "
                                 "response-feature classifier is blocked on this)",
    ("attempt", "score"): "reserved for the blocked attempt-screening classifier",
    ("attempt", "uncertainty"): "reserved for the blocked attempt-screening classifier",
    ("finding", "attempt_id"): "findings are not yet linked to attempts; the finding view "
                               "shows no attempt when NULL",
    ("finding", "case_id"): "findings are not yet linked to ground-truth cases; scoring "
                            "matches by url/param/class instead",
}
_DEFAULTED = re.compile(r"DEFAULT", re.I)


def _source() -> str:
    """All of `fuzzlab/`'s Python, with adjacent string literals joined so a SQL
    statement split over several lines reads as one."""
    text = "\n".join(p.read_text() for p in ROOT.rglob("*.py"))
    return re.sub(r'"\s*\n\s*f?"', "", text)


def _columns(store, tables) -> list[tuple[str, str, bool]]:
    out = []
    for t in tables:
        for row in store.conn.execute(f'PRAGMA table_info("{t}")'):
            out.append((t, row[1], row[4] is not None or bool(row[5])))   # default / pk
    return out


def _written(table: str, column: str, src: str) -> bool:
    """An INSERT naming the column, an UPDATE … SET assigning it, or — for SET clauses
    built at run time (`greybox/recorder.py`) — a ``"column=?"`` fragment in source that
    also issues ``UPDATE table``."""
    for m in re.finditer(rf"INSERT (?:OR \w+ )?INTO {table}\s*\(([^)]*)\)", src, re.I):
        if re.search(rf"\b{column}\b", m.group(1)):
            return True
    for m in re.finditer(rf"UPDATE {table}\s+SET\s+(.*?)(?:WHERE|\"|$)", src, re.I | re.S):
        if re.search(rf"\b{column}\s*=", m.group(1)):
            return True
    return bool(re.search(rf"UPDATE {table}\b", src)
                and re.search(rf"[\"']{column}=\?[\"']", src))


def unwritten(store, tables=CONTRACT_TABLES, src: str | None = None):
    src = _source() if src is None else src
    return [(t, c) for t, c, has_default in _columns(store, tables)
            if not has_default and (t, c) not in ALLOWLIST and not _written(t, c, src)]


def test_every_contract_column_has_a_production_writer(tmp_path):
    with Store(tmp_path / "s.db") as store:
        assert unwritten(store) == []


def test_the_allowlist_has_no_stale_entries(tmp_path):
    """An allowlisted column that gains a writer must leave the allowlist."""
    src = _source()
    with Store(tmp_path / "s.db") as store:
        cols = {(t, c) for t, c, _ in _columns(store, CONTRACT_TABLES)}
    for (t, c) in ALLOWLIST:
        assert (t, c) in cols, (t, c)
        assert not _written(t, c, src), f"{t}.{c} now has a writer: drop it from ALLOWLIST"


def test_the_guard_catches_a_writer_less_column(tmp_path):
    with Store(tmp_path / "s.db") as store:
        store.conn.execute("ALTER TABLE candidate ADD COLUMN never_written TEXT")
        assert unwritten(store) == [("candidate", "never_written")]
        # and a writer satisfies it
        assert unwritten(store, src=_source() + '\n"UPDATE candidate SET never_written=?"') \
            == []


def test_attempt_writers_name_their_own_feature_schema(tmp_path):
    """BUG-0069 sweep: attempt feature dicts are writer-specific telemetry, so each
    writer names its schema inside `features_json` (never the core extractor's version)."""
    import ast
    import json
    from fuzzlab.greybox.run import ATTEMPT_FEATURE_SCHEMA
    tree = ast.parse((ROOT / "greybox" / "run.py").read_text())
    dicts = [d for d in ast.walk(tree) if isinstance(d, ast.Dict)
             and any(isinstance(k, ast.Constant) and k.value == "new_lines_vs_baseline"
                     for k in d.keys)]
    assert len(dicts) == 1
    keys = {k.value: v for k, v in zip(dicts[0].keys, dicts[0].values)
            if isinstance(k, ast.Constant)}
    assert isinstance(keys["_schema"], ast.Name) and keys["_schema"].id == \
        "ATTEMPT_FEATURE_SCHEMA" and ATTEMPT_FEATURE_SCHEMA == "greybox/1"
    from fuzzlab.tools import store_adapter
    csv_path = tmp_path / "f.csv"
    csv_path.write_text("payload_family,time_delay_detected,server_response_status\n"
                        "sqli-time,1,200\n")
    with Store(tmp_path / "a.db") as store:
        run = store.start_run("fuzz", "h")
        store_adapter.import_fuzz_csv(csv_path, store, run)
        row = store.conn.execute("SELECT features_json, feature_version FROM attempt"
                                 ).fetchone()
    assert json.loads(row["features_json"])["_schema"] == "fuzz-csv/1"
    assert row["feature_version"] is None
