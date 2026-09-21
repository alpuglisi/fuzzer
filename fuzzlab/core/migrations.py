"""Numbered, forward-only migration runner.

Each migration is a ``(version, sql)`` pair applied in order inside a
transaction. ``schema_version`` records the highest applied version, so
``migrate`` is idempotent: re-running applies only what is missing. Migrations
are never edited once shipped; a schema change is a new, higher-numbered entry.

The initial migration creates the core tables from ARCHITECTURE.md ("the store
as the contract"), reserving grey-box coverage/fault columns now (Phase 3 fills
them) so later phases add rows, not columns.
"""

from __future__ import annotations

import sqlite3

# --- migration 1: core schema ------------------------------------------------
_M0001 = """
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE run (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    tool        TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    env_profile TEXT,
    notes       TEXT
);

-- Content-addressed request/response bodies, stored once and referenced.
CREATE TABLE body (
    sha256 TEXT PRIMARY KEY,
    length INTEGER NOT NULL,
    data   BLOB NOT NULL
);

-- Target fingerprint (auditor writes; scheduler/fuzzer read).
CREATE TABLE target (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES run(id),
    base_url    TEXT NOT NULL,
    dbms        TEXT,
    framework   TEXT,
    waf         TEXT,
    fingerprint TEXT
);

CREATE TABLE page (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id   INTEGER NOT NULL REFERENCES run(id),
    url      TEXT NOT NULL,
    method   TEXT NOT NULL DEFAULT 'GET',
    status   INTEGER,
    source   TEXT,                       -- 'link' | 'xhr' | ...
    template_cluster_id TEXT,
    discovered_from TEXT,
    UNIQUE(run_id, url, method)
);

CREATE TABLE endpoint (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  INTEGER NOT NULL REFERENCES run(id),
    url     TEXT NOT NULL,
    method  TEXT NOT NULL DEFAULT 'GET',
    source  TEXT,
    UNIQUE(run_id, url, method)
);

CREATE TABLE parameter (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES run(id),
    endpoint_id INTEGER REFERENCES endpoint(id),
    name        TEXT NOT NULL,
    location    TEXT NOT NULL,           -- 'query' | 'body' | 'header' | ...
    example     TEXT
);

CREATE TABLE candidate (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES run(id),
    parameter_id  INTEGER REFERENCES parameter(id),
    rule          TEXT,
    evidence      TEXT,                  -- JSON: per-rule evaluation evidence
    features_json TEXT,
    feature_version INTEGER,
    score         REAL,                  -- written by the ranker (advisory)
    sink_context  TEXT
);

CREATE TABLE flow (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES run(id),
    identity     TEXT,
    method       TEXT,
    url          TEXT,
    status       INTEGER,
    elapsed_ms   REAL,
    req_body_sha TEXT REFERENCES body(sha256),
    resp_body_sha TEXT REFERENCES body(sha256),
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE attempt (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES run(id),
    candidate_id  INTEGER REFERENCES candidate(id),
    payload_family TEXT,
    features_json TEXT,
    feature_version INTEGER,
    reward        REAL,
    score         REAL,                  -- classifier score (advisory)
    uncertainty   REAL,                  -- classifier uncertainty (advisory)
    coverage      TEXT,                  -- reserved: grey-box coverage signal (Phase 3)
    db_fault      INTEGER,               -- reserved: grey-box DB-fault signal (Phase 3)
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Only the oracle writes findings (labels). ML never writes here.
CREATE TABLE finding (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES run(id),
    attempt_id   INTEGER REFERENCES attempt(id),
    case_id      TEXT,                   -- opaque ground-truth case id (D9)
    vuln_class   TEXT,
    label        INTEGER NOT NULL,       -- 1 confirmed
    confidence   TEXT,
    evidence     TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE bandit_posteriors (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    context    TEXT NOT NULL,
    arm        TEXT NOT NULL,
    alpha      REAL NOT NULL DEFAULT 1.0,
    beta       REAL NOT NULL DEFAULT 1.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(context, arm)
);

CREATE TABLE model (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    version       INTEGER NOT NULL,
    feature_version INTEGER,
    calibration   TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(name, version)
);

CREATE TABLE request_budget (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER NOT NULL REFERENCES run(id),
    component  TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    cap        INTEGER
);

CREATE TABLE run_metrics (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER NOT NULL REFERENCES run(id),
    key        TEXT NOT NULL,
    value      REAL
);

CREATE INDEX idx_page_run ON page(run_id);
CREATE INDEX idx_endpoint_run ON endpoint(run_id);
CREATE INDEX idx_candidate_run ON candidate(run_id);
CREATE INDEX idx_attempt_run ON attempt(run_id);
CREATE INDEX idx_finding_run ON finding(run_id);
CREATE INDEX idx_flow_run ON flow(run_id);
"""

# --- migration 2: self-describing findings ----------------------------------
# The integration harness scores detections by (url, method, param, vuln_class),
# so a finding must carry its own location rather than only an attempt/candidate
# reference. Added as a new migration (the registry is append-only).
_M0002 = """
ALTER TABLE finding ADD COLUMN url TEXT;
ALTER TABLE finding ADD COLUMN method TEXT;
ALTER TABLE finding ADD COLUMN param TEXT;
"""

# Ordered registry. Append new migrations; never edit an applied one.
MIGRATIONS: list[tuple[int, str]] = [
    (1, _M0001),
    (2, _M0002),
]


def _ensure_version_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "  version INTEGER PRIMARY KEY,"
        "  applied_at TEXT NOT NULL DEFAULT (datetime('now'))"
        ")"
    )


def current_version(conn: sqlite3.Connection) -> int:
    _ensure_version_table(conn)
    row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
    value = row["v"] if isinstance(row, sqlite3.Row) else row[0]
    return int(value) if value is not None else 0


def migrate(conn: sqlite3.Connection) -> int:
    """Apply all pending migrations in order. Idempotent. Returns new version."""
    _ensure_version_table(conn)
    have = current_version(conn)
    for version, sql in sorted(MIGRATIONS):
        if version <= have:
            continue
        with conn:  # transaction: all-or-nothing per migration
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)", (version,)
            )
    return current_version(conn)
