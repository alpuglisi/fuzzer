"""Regression coverage for the `fetcher.py --append` occurrence-counter bug
(ERROR_LOG.md "Open / low priority" entry, fixed here): repeated `--append`
runs must not reset an already-migrated database's cumulative `occurrences`
count back to the current row count.
"""
import sqlite3

from fuzzlab.tools.fetcher import log_finding, setup_results_db


def test_fresh_db_starts_empty_and_dedupes_within_a_run(tmp_path):
    db = str(tmp_path / "results.db")
    conn = setup_results_db(db, append=False)
    cursor = conn.cursor()
    log_finding(cursor, "http://x/a", "sqli", "form", "id")
    log_finding(cursor, "http://x/b", "sqli", "form", "id")
    conn.commit()
    cursor.execute("SELECT occurrences FROM findings WHERE target_identifier = 'id'")
    assert cursor.fetchone()[0] == 2
    conn.close()


def test_default_non_append_run_clears_prior_findings(tmp_path):
    db = str(tmp_path / "results.db")
    conn = setup_results_db(db, append=False)
    log_finding(conn.cursor(), "http://x/a", "sqli", "form", "id")
    conn.commit()
    conn.close()

    conn = setup_results_db(db, append=False)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM findings")
    assert cursor.fetchone()[0] == 0
    conn.close()


def test_append_preserves_cumulative_occurrences_across_runs(tmp_path):
    db = str(tmp_path / "results.db")

    conn = setup_results_db(db, append=False)
    cursor = conn.cursor()
    log_finding(cursor, "http://x/a", "sqli", "form", "id")
    log_finding(cursor, "http://x/b", "sqli", "form", "id")
    log_finding(cursor, "http://x/c", "sqli", "form", "id")
    conn.commit()
    conn.close()

    # Second run, --append: setup must not reset the persisted count of 3.
    conn = setup_results_db(db, append=True)
    cursor = conn.cursor()
    cursor.execute("SELECT occurrences FROM findings WHERE target_identifier = 'id'")
    assert cursor.fetchone()[0] == 3          # not reset to 1

    log_finding(cursor, "http://x/d", "sqli", "form", "id")
    log_finding(cursor, "http://x/e", "sqli", "form", "id")
    conn.commit()
    cursor.execute("SELECT occurrences FROM findings WHERE target_identifier = 'id'")
    assert cursor.fetchone()[0] == 5          # 3 prior + 2 this run
    conn.close()

    # A third run confirms the count keeps accumulating, not resetting each time.
    conn = setup_results_db(db, append=True)
    cursor = conn.cursor()
    log_finding(cursor, "http://x/f", "sqli", "form", "id")
    conn.commit()
    cursor.execute("SELECT occurrences FROM findings WHERE target_identifier = 'id'")
    assert cursor.fetchone()[0] == 6
    conn.close()


def test_append_migrates_a_pre_index_database_with_literal_duplicate_rows(tmp_path):
    db = str(tmp_path / "results.db")
    # Simulate a database written by a version that predates the unique index
    # and occurrence counter: one literal row per occurrence, no index.
    conn = sqlite3.connect(db)
    conn.execute('''
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_url TEXT NOT NULL,
            category TEXT NOT NULL,
            transaction_type TEXT NOT NULL,
            target_identifier TEXT NOT NULL,
            html_context TEXT
        )
    ''')
    for url in ("http://x/a", "http://x/b", "http://x/c"):
        conn.execute(
            "INSERT INTO findings (page_url, category, transaction_type, target_identifier) "
            "VALUES (?, 'sqli', 'form', 'id')", (url,))
    conn.commit()
    conn.close()

    conn = setup_results_db(db, append=True)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*), occurrences FROM findings WHERE target_identifier = 'id'")
    rows, occurrences = cursor.fetchone()
    assert rows == 1                          # collapsed to one row
    assert occurrences == 3                   # derived from the 3 duplicate rows
    conn.close()
