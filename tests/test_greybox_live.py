"""Tests for the live grey-box last mile (T3.2–T3.7): file-backed sources, the
script-backed lab reset, and the `run_greybox` driver — all offline, no lab."""

import json

import pytest

from fuzzlab.core.store import Store
from fuzzlab.greybox.coverage import FileCoverageSource, sanitize_cid
from fuzzlab.greybox.dbfault import FileDbFaultSource
from fuzzlab.greybox.reset import LabControlError, ScriptLabControl
from fuzzlab.greybox.run import (GreyboxPoint, ProbeSpec, RequestsCorrelatingSender,
                                 mutation_variant_probes, run_greybox)
from fuzzlab.oracle.probe import Probe


# --- file-backed sources (read the shim side channel) ------------------------
def _write_shim(directory, cid, *, files=None, db_fault=False, db_error=""):
    payload = {"files": files or {}, "db_fault": db_fault, "db_error": db_error}
    (directory / sanitize_cid(cid)).write_text(json.dumps(payload), encoding="utf-8")


def test_file_coverage_source_reads_shim(tmp_path):
    _write_shim(tmp_path, "abc123", files={"/var/www/html/login.php": [24, 25, 28]})
    src = FileCoverageSource(tmp_path)
    assert src.lines_for("abc123") == {"/var/www/html/login.php": {24, 25, 28}}


def test_file_coverage_source_missing_is_empty(tmp_path):
    assert FileCoverageSource(tmp_path).lines_for("nope") == {}


def test_file_coverage_source_accepts_bare_map(tmp_path):
    (tmp_path / "r1").write_text(json.dumps({"/var/www/html/x.php": [1, 2]}))
    assert FileCoverageSource(tmp_path).lines_for("r1") == {"/var/www/html/x.php": {1, 2}}


def test_file_coverage_source_sanitizes_cid(tmp_path):
    # A traversal-y id resolves to the same sanitized file, never outside the dir.
    _write_shim(tmp_path, "..%2fetc", files={"/var/www/html/a.php": [1]})
    assert FileCoverageSource(tmp_path).lines_for("../%2fetc") \
        == {"/var/www/html/a.php": {1}}


def test_file_dbfault_source_reads_marker(tmp_path):
    _write_shim(tmp_path, "cid1", db_fault=True, db_error="You have an error in your SQL syntax")
    f = FileDbFaultSource(tmp_path).fault_for("cid1")
    assert f.faulted and "SQL syntax" in f.detail


def test_file_dbfault_source_default_no_fault(tmp_path):
    _write_shim(tmp_path, "cid2", files={"/var/www/html/a.php": [1]})
    assert FileDbFaultSource(tmp_path).fault_for("cid2").faulted is False
    assert FileDbFaultSource(tmp_path).fault_for("absent").faulted is False


# --- script-backed lab reset -------------------------------------------------
def test_script_lab_control_invokes_snapshot_and_restore():
    calls = []
    lc = ScriptLabControl("/opt/lab/labctl.sh", runner=lambda cmd: calls.append(cmd))
    lc.snapshot("baseline")
    lc.reset("baseline")
    assert calls == [["/opt/lab/labctl.sh", "snapshot", "baseline"],
                     ["/opt/lab/labctl.sh", "restore", "baseline"]]


def test_script_lab_control_raises_on_failure():
    def boom(cmd):
        raise RuntimeError("exit 1")
    with pytest.raises(LabControlError):
        ScriptLabControl("/x/labctl.sh", runner=boom).snapshot()


# --- the run_greybox driver --------------------------------------------------
class FakeSender:
    """Serves canned coverage/faults keyed by the correlation id it hands out.

    Models the real flow: each send returns a Probe and a fresh id; the test's
    in-memory sources are pre-seeded for the ids this sender will produce, in order.
    """

    def __init__(self, script):
        # script: list of (Probe, coverage_map, db_fault) in send order
        self._script = list(script)
        self._i = 0
        self.cov = {}
        self.faults = {}
        self.sent = []

    def send_correlated(self, url, param, value, *, method="GET", location="query"):
        probe, cov, fault = self._script[self._i]
        cid = f"cid{self._i}"
        self._i += 1
        self.cov[cid] = cov
        self.faults[cid] = fault
        self.sent.append((url, param, value, method, location))
        return probe, cid


class DictCoverage:
    def __init__(self, sender):
        self._s = sender

    def lines_for(self, cid):
        return {f: set(v) for f, v in self._s.cov.get(cid, {}).items()}


class DictFault:
    def __init__(self, sender):
        from fuzzlab.greybox.dbfault import DbFault
        self._s = sender
        self._DbFault = DbFault

    def fault_for(self, cid):
        return self._DbFault(faulted=bool(self._s.faults.get(cid)))


def test_run_greybox_writes_enriched_attempts_and_reward_ordering(tmp_path):
    # One point, two probes: the benign baseline is the control (reward ~0), the SQLi '\''
    # probe reaches the error branch BEYOND the baseline (per-point new lines) AND faults.
    app = "/var/www/html/product.php"
    probes = (ProbeSpec("baseline", "1", "baseline"),
              ProbeSpec("sqli-error", "'", "sqli"))
    sender = FakeSender([
        (Probe(200, "ok"), {app: [10, 11]}, False),                    # baseline
        (Probe(500, "You have an error in your SQL syntax"),
         {app: [10, 11, 40, 41, 42]}, True),                           # sqli error
    ])
    cov, fault = DictCoverage(sender), DictFault(sender)
    point = GreyboxPoint(url="http://127.0.0.1:8080/product.php", param="id",
                         method="GET", location="query", vuln_class="sqli-error")
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("greybox", "127.0.0.1")
        summary = run_greybox(base_url="http://127.0.0.1:8080", store=store,
                              run_id=run_id, points=[point], sender=sender,
                              coverage_source=cov, dbfault_source=fault,
                              probes=probes)
        rows = store.conn.execute(
            "SELECT payload_family, reward, db_fault, coverage FROM attempt "
            "WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
        metrics = dict(store.conn.execute(
            "SELECT key, value FROM run_metrics WHERE run_id=?", (run_id,)).fetchall())

    assert summary["attempts"] == 2
    assert summary["db_faults"] == 1
    fam = {r["payload_family"]: r for r in rows}
    # SQLi error probe: db_fault set, reaches new code + fault => strictly higher reward.
    assert fam["sqli-error"]["db_fault"] == 1
    assert fam["baseline"]["db_fault"] == 0
    assert fam["sqli-error"]["reward"] > fam["baseline"]["reward"]
    # BUG-0016: the benign baseline is the control — it must NOT earn reward from
    # global-frontier novelty; new-code reward comes from the attack's per-point diff.
    assert fam["baseline"]["reward"] == 0.0
    assert summary["newcode_reward"] == fam["sqli-error"]["reward"] > 0
    assert summary["baseline_reward"] == 0.0
    assert summary["coverage_lines_seen"] == 7          # 2 (baseline) + 5 (sqli)
    # Coverage blob persisted for both.
    assert json.loads(fam["baseline"]["coverage"])["n_lines"] == 2
    # M10 (advisory) confirms the sqli case (sink file covered + db_fault).
    assert summary["m10_would_confirm"] == 1
    # Grey-box run_metrics recorded.
    assert metrics["greybox_attempts"] == 2
    assert metrics["greybox_db_faults"] == 1


def test_attack_novelty_is_per_point_not_global_frontier(tmp_path):
    """BUG-0016 regression: an attack's new-code credit is measured against its OWN
    point's baseline, so a second point's attack still shows new lines even when those
    lines were already globally seen by the first point (the global frontier must not
    starve per-point novelty, and benign baselines must never consume it)."""
    a1, a2, db = ("/var/www/html/search.php", "/var/www/html/product.php",
                  "/var/www/html/db.php")
    probes = (ProbeSpec("baseline", "1", "baseline"),
              ProbeSpec("sqli-error", "'", "sqli"))
    sender = FakeSender([
        (Probe(200, "ok"), {a1: [10]}, False),                       # p1 baseline
        (Probe(500, "SQL syntax"), {a1: [10], db: [99]}, True),      # p1 sqli -> +db:99
        (Probe(200, "ok"), {a2: [20]}, False),                       # p2 baseline
        (Probe(500, "SQL syntax"), {a2: [20], db: [99]}, True),      # p2 sqli -> +db:99
    ])
    cov, fault = DictCoverage(sender), DictFault(sender)
    pts = [GreyboxPoint("http://h/search.php", "q", "GET", "query", "sqli-error"),
           GreyboxPoint("http://h/product.php", "id", "GET", "query", "sqli-error")]
    with Store(tmp_path / "u.db") as store:
        rid = store.start_run("greybox", "h")
        summary = run_greybox(base_url="http://h", store=store, run_id=rid, points=pts,
                              sender=sender, coverage_source=cov, dbfault_source=fault,
                              probes=probes)
        rows = store.conn.execute(
            "SELECT payload_family, "
            "json_extract(features_json,'$.new_lines_vs_baseline') AS nl "
            "FROM attempt WHERE run_id=? ORDER BY id", (rid,)).fetchall()

    sqli = [r for r in rows if r["payload_family"] == "sqli-error"]
    assert len(sqli) == 2 and all(r["nl"] == 1 for r in sqli)   # BOTH show +1 vs baseline
    assert summary["newcode_reward"] > 0
    assert summary["baseline_reward"] == 0.0                    # controls earn nothing
    assert summary["coverage_lines_seen"] > 0                   # shim clearly produced data


def test_run_greybox_resets_between_stateful_points(tmp_path):
    from fuzzlab.greybox.reset import FakeLabControl
    probes = (ProbeSpec("baseline", "1", "baseline"),)
    sender = FakeSender([(Probe(200, "ok"), {}, False),
                         (Probe(200, "ok"), {}, False)])
    cov, fault = DictCoverage(sender), DictFault(sender)
    lc = FakeLabControl()
    pts = [GreyboxPoint("http://h/a.php", "x", "GET", "query"),
           GreyboxPoint("http://h/b.php", "y", "POST", "body")]
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("greybox", "h")
        run_greybox(base_url="http://h", store=store, run_id=run_id, points=pts,
                    sender=sender, coverage_source=cov, dbfault_source=fault,
                    lab_control=lc, reset_between=True, probes=probes)
    # snapshot once at start; restore once after the POST point (GET point does not reset).
    assert ("snapshot", "baseline") in lc.calls
    assert lc.reset_count == 1


# --- T8.5 wiring: mutation-engine variants in the main attempt path ----------
def test_mutation_variant_probes_generates_preserving_variants():
    base = (ProbeSpec("baseline", "1", "baseline"),
            ProbeSpec("sqli-error", "1' OR 1=1 -- -", "sqli"))
    variants = mutation_variant_probes(base, max_variants=2)
    # The baseline probe never yields variants; only the sqli attack does.
    assert variants and all(v.kind == "sqli" for v in variants)
    assert all(v.base == "1' OR 1=1 -- -" for v in variants)
    assert all(v.family.startswith("mutation:") for v in variants)
    # Bounded to max_variants.
    assert len(variants) <= 2
    # url-encode is skipped (double-encoding through the probe transport).
    assert all(v.operators != ("url-encode",) for v in variants)


def test_mutation_variant_probes_none_for_unclassed_kind():
    base = (ProbeSpec("custom", "whatever", "other"),)
    assert mutation_variant_probes(base) == []


def test_run_greybox_consumes_mutation_variants_into_attempt_path(tmp_path):
    """The main harness's attempt loop (not just `mutate-run`) now sends mutation-engine
    variants and records the accepted ones to `payload_variant` (T8.5 wiring, C1)."""
    app = "/var/www/html/search.php"
    base_payload = "1' OR 1=1 -- -"
    probes = (ProbeSpec("baseline", "1", "baseline"),
              ProbeSpec("sqli-error", base_payload, "sqli"))
    point = GreyboxPoint(url="http://h/search.php", param="q", method="GET",
                         location="query", vuln_class="sqli")

    # Figure out how many variants will actually be generated for this base payload,
    # so the fake sender's script matches 1:1 (baseline, base attack, then N variants).
    n_variants = len(mutation_variant_probes(
        [p for p in probes if p.kind != "baseline"], max_variants=2))
    assert n_variants >= 1        # sanity: this base payload does mutate

    script = [
        (Probe(200, "ok"), {app: [10, 11]}, False),                          # baseline
        (Probe(500, "You have an error in your SQL syntax"),
         {app: [10, 11, 40]}, True),                                         # base sqli
    ]
    # Every mutation variant also "hits" (error status + new coverage), so all get
    # recorded as accepted variants.
    for i in range(n_variants):
        script.append((Probe(500, "You have an error in your SQL syntax"),
                       {app: [10, 11, 40, 50 + i]}, True))
    sender = FakeSender(script)
    cov, fault = DictCoverage(sender), DictFault(sender)

    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("greybox", "h")
        summary = run_greybox(base_url="http://h", store=store, run_id=run_id,
                              points=[point], sender=sender, coverage_source=cov,
                              dbfault_source=fault, probes=probes,
                              mutation_variants=True, max_mutation_variants=2)

        variant_rows = store.conn.execute(
            "SELECT base_payload, variant, operators, vuln_class, coverage_gain "
            "FROM payload_variant WHERE run_id=?", (run_id,)).fetchall()
        attempt_families = [r["payload_family"] for r in store.conn.execute(
            "SELECT payload_family FROM attempt WHERE run_id=? ORDER BY id",
            (run_id,)).fetchall()]

    # attempts: baseline + base sqli + the mutation variants, all through the same loop.
    assert summary["attempts"] == 2 + n_variants
    assert summary["mutation_variants_probed"] == n_variants
    assert summary["mutation_variants_recorded"] == n_variants
    assert sum(1 for f in attempt_families if f.startswith("mutation:")) == n_variants
    # Written back to payload_variant with correct provenance (T8.5's write-back path).
    assert len(variant_rows) == n_variants
    for row in variant_rows:
        assert row["base_payload"] == base_payload
        assert row["vuln_class"] == "sql-injection"
        assert row["coverage_gain"] and row["coverage_gain"] > 0
        assert json.loads(row["operators"])


def test_run_greybox_mutation_variants_off_by_default(tmp_path):
    """Backward-compatible default: no mutation traffic unless explicitly opted in."""
    app = "/var/www/html/a.php"
    probes = (ProbeSpec("baseline", "1", "baseline"),
              ProbeSpec("sqli-error", "'", "sqli"))
    sender = FakeSender([
        (Probe(200, "ok"), {app: [1]}, False),
        (Probe(500, "SQL syntax"), {app: [1, 2]}, True),
    ])
    cov, fault = DictCoverage(sender), DictFault(sender)
    point = GreyboxPoint("http://h/a.php", "id", "GET", "query", "sqli")
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("greybox", "h")
        summary = run_greybox(base_url="http://h", store=store, run_id=run_id,
                              points=[point], sender=sender, coverage_source=cov,
                              dbfault_source=fault, probes=probes)
        n_variants = store.conn.execute(
            "SELECT COUNT(*) AS n FROM payload_variant WHERE run_id=?",
            (run_id,)).fetchone()["n"]
    assert summary["attempts"] == 2                # no extra mutation probes sent
    assert summary["mutation_variants_probed"] == 0
    assert summary["mutation_variants_recorded"] == 0
    assert n_variants == 0


# --- B0's coverage-frontier emitter (CC-FUZZ-0021): metric_series rows -------

def test_run_greybox_emits_coverage_metric_series(tmp_path):
    """Each attempt writes a `metric_series` row (source='coverage',
    key='coverage/lines') tracking the run-wide frontier's growth, additive
    alongside the existing `greybox_frontier_size` run_metrics total."""
    app = "/var/www/html/product.php"
    probes = (ProbeSpec("baseline", "1", "baseline"),
              ProbeSpec("sqli-error", "'", "sqli"))
    sender = FakeSender([
        (Probe(200, "ok"), {app: [10, 11]}, False),                    # baseline
        (Probe(500, "You have an error in your SQL syntax"),
         {app: [10, 11, 40, 41, 42]}, True),                           # sqli error
    ])
    cov, fault = DictCoverage(sender), DictFault(sender)
    point = GreyboxPoint(url="http://127.0.0.1:8080/product.php", param="id",
                         method="GET", location="query", vuln_class="sqli-error")
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("greybox", "127.0.0.1")
        summary = run_greybox(base_url="http://127.0.0.1:8080", store=store,
                              run_id=run_id, points=[point], sender=sender,
                              coverage_source=cov, dbfault_source=fault,
                              probes=probes)
        rows = store.conn.execute(
            "SELECT source, key, step, value FROM metric_series "
            "WHERE run_id=? ORDER BY step", (run_id,)).fetchall()

    assert [dict(r) for r in rows] == [
        {"source": "coverage", "key": "coverage/lines", "step": 1, "value": 2.0},
        {"source": "coverage", "key": "coverage/lines", "step": 2, "value": 5.0},
    ]
    # Matches the run-wide frontier total recorded via the pre-existing path.
    assert rows[-1]["value"] == summary["novel_lines"]


def test_run_greybox_coverage_metric_series_isolated_per_run(tmp_path):
    """Two runs against the same store don't cross-contaminate each other's
    coverage/lines series (metric_series is keyed by run_id)."""
    app = "/var/www/html/a.php"
    probes = (ProbeSpec("baseline", "1", "baseline"),)
    with Store(tmp_path / "u.db") as store:
        for expected_lines in (1, 3):
            sender = FakeSender([(Probe(200, "ok"), {app: list(range(expected_lines))}, False)])
            cov, fault = DictCoverage(sender), DictFault(sender)
            point = GreyboxPoint("http://h/a.php", "id", "GET", "query", None)
            run_id = store.start_run("greybox", "h")
            run_greybox(base_url="http://h", store=store, run_id=run_id,
                       points=[point], sender=sender, coverage_source=cov,
                       dbfault_source=fault, probes=probes)
            values = [r["value"] for r in store.conn.execute(
                "SELECT value FROM metric_series WHERE run_id=? AND key='coverage/lines' "
                "ORDER BY step", (run_id,)).fetchall()]
            assert values == [float(expected_lines)]


def test_requests_correlating_sender_sets_header(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200
        text = "ok"
        headers = {}

    class _Session:
        def request(self, method, url, **kwargs):
            captured["method"] = method
            captured["headers"] = kwargs.get("headers")
            captured["params"] = kwargs.get("params")
            return _Resp()

    sender = RequestsCorrelatingSender(session=_Session(),
                                       id_factory=lambda: "fixedid")
    probe, cid = sender.send_correlated("http://h/x.php", "id", "1")
    assert cid == "fixedid"
    assert captured["headers"]["X-Fzl-Cov"] == "fixedid"
    assert captured["params"] == {"id": "1"}
    assert probe.status == 200
