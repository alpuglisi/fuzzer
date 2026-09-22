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

# --- migration 3: non-secret session-state persistence ----------------------
# The session manager persists only NON-SECRET session metadata (host, identity,
# kind, validity, endpoints, token expiry) so a crashed run resumes / an audit
# trail exists. Secrets (cookies, tokens, credentials) are never stored here.
_M0003 = """
CREATE TABLE session_state (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT NOT NULL,
    identity   TEXT NOT NULL,
    kind       TEXT,
    valid      INTEGER,
    login_url  TEXT,
    logout_url TEXT,
    token_exp  REAL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(host, identity)
);
"""

# --- migration 4: full rule-evaluation logging (negatives) -------------------
# The auditor's rules-as-data engine records EVERY per-(injection point, rule)
# evaluation — fired and not-fired — so the store holds negatives, not just hits
# (a trainable dataset). Fired evaluations also emit a `candidate` row as before.
_M0004 = """
CREATE TABLE evaluation (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           INTEGER NOT NULL REFERENCES run(id),
    url              TEXT NOT NULL,
    method           TEXT NOT NULL DEFAULT 'GET',
    param            TEXT,
    location         TEXT,
    rule_id          TEXT NOT NULL,
    category         TEXT,
    transaction_type TEXT,
    fired            INTEGER NOT NULL,        -- 1 emitted a candidate, 0 negative
    sink_context     TEXT,
    evidence         TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_evaluation_run ON evaluation(run_id);
CREATE INDEX idx_evaluation_fired ON evaluation(run_id, fired);
"""

# --- migration 5: bandit cost tracking (Phase 4 T4.4) ------------------------
# Cost-normalized selection needs the mean cost per (context, arm). Persist the
# running sum/count next to the reward posterior so cost learning survives runs.
_M0005 = """
ALTER TABLE bandit_posteriors ADD COLUMN cost_sum REAL NOT NULL DEFAULT 0;
ALTER TABLE bandit_posteriors ADD COLUMN cost_n INTEGER NOT NULL DEFAULT 0;
"""

# --- migration 6: proxy flow history (Phase 6 T6.3) --------------------------
# The intercepting proxy records flows with BYTE-EXACT raw request/response bytes
# (content-addressed via `body`, like decoded bodies), plus the host and an in-scope
# flag, and an FTS5 index for searchable history. `repeater_tab` persists repeater
# tabs (a saved raw request + its target) so they survive across sessions.
_M0006 = """
ALTER TABLE flow ADD COLUMN host TEXT;
ALTER TABLE flow ADD COLUMN in_scope INTEGER;
ALTER TABLE flow ADD COLUMN req_raw_sha TEXT REFERENCES body(sha256);
ALTER TABLE flow ADD COLUMN resp_raw_sha TEXT REFERENCES body(sha256);

-- Standalone FTS5 index over the searchable head fields; the proxy's history
-- writer is the sole populator (batched), so no content-sync triggers are needed.
CREATE VIRTUAL TABLE flow_fts USING fts5(
    url, method, host, req_head, resp_head,
    flow_id UNINDEXED
);

CREATE TABLE repeater_tab (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER REFERENCES run(id),
    name        TEXT,
    host        TEXT,
    port        INTEGER,
    use_tls     INTEGER NOT NULL DEFAULT 0,
    raw_request BLOB NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

# --- migration 7: candidate ranker scores (Phase 7 T7.2) ---------------------
# The candidate ranker (A.2) writes an ADVISORY ranking score + uncertainty per
# candidate, kept separate from the Phase-5 detection classifier's `candidate.score`
# so both models can coexist (the ranker orders at zero request cost; the classifier
# screens attempts). Advisory only — never a label.
_M0007 = """
ALTER TABLE candidate ADD COLUMN rank_score REAL;
ALTER TABLE candidate ADD COLUMN rank_uncertainty REAL;
"""

# --- migration 8: mutation-engine payload variants (Phase 8 T8.5) ------------
# The mutation engine records the PROVENANCE of each accepted variant: which operator
# chain produced it, which WAF rule it bypassed, the semantics-validator verdict, and
# any grey-box coverage gain. Variants are still sent through the `attempt` path; this
# table is for reuse and analysis. Additive; no existing row changes.
_M0008 = """
CREATE TABLE payload_variant (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER REFERENCES run(id),
    vuln_class    TEXT,
    base_payload  TEXT NOT NULL,
    variant       TEXT NOT NULL,
    operators     TEXT,              -- JSON list of operator ids (the chain applied)
    sink_context  TEXT,
    bypassed_rule TEXT,              -- WAF rule id it evaded, if any
    semantics_ok  INTEGER,          -- semantics-validator verdict (1/0)
    coverage_gain REAL,             -- grey-box coverage delta, if measured
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_payload_variant_run ON payload_variant(run_id);
"""

# --- migration 9: flow protocol tag (Phase 9 T9.1) ---------------------------
# The proxy now records WebSocket and HTTP/2 flows alongside HTTP/1.1; a `protocol`
# tag ('http/1.1' | 'h2' | 'ws') distinguishes them in history. Additive; existing
# rows read as NULL (treated as http/1.1 by the writer's default).
_M0009 = """
ALTER TABLE flow ADD COLUMN protocol TEXT;
"""

# --- migration 10: active-plugin recording (Phase 10 T10.1) ------------------
# The plugin manager records exactly which plugins/versions were active on a run
# (NFR-PLUG-reproducible), so a reproducible report can name what produced a result.
# Additive; a run with zero plugins simply writes no rows.
_M0010 = """
CREATE TABLE run_plugin (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER REFERENCES run(id),
    name       TEXT NOT NULL,
    version    TEXT,
    priority   INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_run_plugin_run ON run_plugin(run_id);
"""

# --- migration 11: cross-run scalar time series (Phase 4b, B0 / CC-CORE-0018) -
# A generic, TensorBoard/MLflow-shaped scalar log: any subsystem (GBT/logistic
# training curves, the bandit loop's posterior/regret, coverage-frontier growth,
# MutationSearch reward/novelty, stage wall-clock/throughput, ...) writes rows
# here instead of inventing its own metrics table. `source` is the subsystem
# bucket (mirrors existing `run_metrics` prefixes: 'gbt', 'logreg', 'bandit',
# 'coverage', 'rank', 'ml'); `key` is a bounded, slash-delimited path
# ('train/loss', 'regret/cumulative', 'posterior/arm_3/mean',
# 'coverage/lines') — never a per-example/feature key; distributions are
# stored pre-binned by the writer, not as raw per-key blowup. `value` is
# REAL NOT NULL; non-finite values (NaN/inf) are rejected by the writer
# (log_scalar), not representable here — no `is_nan` column, no NaN
# read-branch. Two indexes serve the two access patterns: one series within a
# run (run_id, source, key, step), and one series overlaid across runs
# (source, key, run_id, step). Additive; no existing table/column changes.
_M0011 = """
CREATE TABLE metric_series (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  INTEGER NOT NULL REFERENCES run(id),
    source  TEXT NOT NULL,
    key     TEXT NOT NULL,
    step    INTEGER NOT NULL,
    ts      TEXT NOT NULL DEFAULT (datetime('now')),
    value   REAL NOT NULL
);
CREATE INDEX idx_metric_series_run ON metric_series(run_id, source, key, step);
CREATE INDEX idx_metric_series_overlay ON metric_series(source, key, run_id, step);
"""

# --- migration 12: saved views (U2, CC-UI-0029, R-03) -----------------------
# The Findings workbench's faceted filters/quick-filter/sort/columns are saved
# server-side (durable, shared across the panel's own readers) rather than in
# `localStorage` (per-viewer only — reserved for throwaway UI state like the
# last-selected view id). `table_key` names the logical dataset the view is
# over ('finding' first; other workbenches can reuse this table later).
# `spec_json` is opaque to the store — `{version, name, pinned, filter:
# {text, facets, predicates}, sort, columns}` (see `fuzzlab.web.savedviews`).
# Additive; no existing table/column changes.
_M0012 = """
CREATE TABLE saved_views (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    table_key  TEXT NOT NULL,
    name       TEXT NOT NULL,
    spec_json  TEXT NOT NULL,
    is_pinned  INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_saved_views_table ON saved_views(table_key);
"""

# Ordered registry. Append new migrations; never edit an applied one.
MIGRATIONS: list[tuple[int, str]] = [
    (1, _M0001),
    (2, _M0002),
    (3, _M0003),
    (4, _M0004),
    (5, _M0005),
    (6, _M0006),
    (7, _M0007),
    (8, _M0008),
    (9, _M0009),
    (10, _M0010),
    (11, _M0011),
    (12, _M0012),
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
