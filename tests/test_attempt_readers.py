"""BUG-0151's PA-0002 sweep: readers of the ``attempt`` table that assume the pipeline
they read wrote attempt rows. `harness/auto`'s oracle writes `candidate.oracle_status`
and `finding` rows with no ``attempt_id``; only greybox and the fuzz-CSV import write
attempts.

Dispositions (BUG-0151):
- `scripts/funnel_report.py` (the "probed" stage): fixed, CC-FUZZ-0089;
- `web/findingsview.py`: reads an attempt only when the finding has one: correct;
- `report/report.py` (an ``attempts`` count): a count of what exists: correct;
- `greybox/greybox_cli.py`: greybox's own attempts: correct;
- `web/results.py` (a finding's category through finding -> attempt -> candidate):
  **the same defect, not fixed here** (the UI component, outside this lane): an `auto`
  finding has no category facet and a category filter drops it. Pinned below
  (PA-0054(3)), reported.
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.core.store import Store


def _auto_finding(tmp_path):
    """A candidate and its finding as `harness/auto`'s pipeline writes them: the
    finding's columns are `oracle.Oracle._write_finding`'s, with no attempt id."""
    store = Store(str(tmp_path / "u.db"))
    run = store.start_run("auto", "h")
    store.conn.execute("INSERT INTO candidate (run_id, rule, evidence, oracle_status) "
                       "VALUES (?,?,?,?)", (run, "R-SQLI-PARAM", json.dumps(
                           {"url": "http://h/a", "param": "q",
                            "category": "sql-injection"}), "checked"))
    store.conn.execute("INSERT INTO finding (run_id, vuln_class, label, confidence, "
                       "evidence, url, method, param) VALUES (?,?,?,?,?,?,?,?)",
                       (run, "sqli", 1, "error", "{}", "/a", "GET", "q"))
    store.conn.commit()
    return store


def test_the_oracle_writes_findings_without_an_attempt():
    """The premise of the sweep, read from the writer itself."""
    import inspect

    from fuzzlab.oracle import oracle
    src = inspect.getsource(oracle.Oracle._write_finding)
    assert "INSERT INTO finding" in src and "attempt_id" not in src


@pytest.mark.xfail(strict=True, reason=(
    "BUG-0151 sweep: web/results.py derives a finding's category through "
    "finding -> attempt -> candidate, and auto's findings carry no attempt_id, so an "
    "auto finding has no category facet (UI component; not fixed in this lane)"))
def test_an_auto_findings_category_reaches_the_findings_facets(tmp_path):
    from fuzzlab.web.results import finding_facets
    with _auto_finding(tmp_path) as store:
        assert "sql-injection" in finding_facets(store)["categories"]
