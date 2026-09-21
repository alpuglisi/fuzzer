"""Tests for the live grey-box last mile (T3.2–T3.7): file-backed sources, the
script-backed lab reset, and the `run_greybox` driver — all offline, no lab."""

import json

import pytest

from fuzzlab.core.store import Store
from fuzzlab.greybox.coverage import FileCoverageSource, sanitize_cid
from fuzzlab.greybox.dbfault import FileDbFaultSource
from fuzzlab.greybox.reset import LabControlError, ScriptLabControl
from fuzzlab.greybox.run import (GreyboxPoint, ProbeSpec, RequestsCorrelatingSender,
                                 run_greybox)
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
    # One point, two probes: baseline reaches product.php (novel), the SQLi '\'' probe
    # reaches the error branch (more novel lines) AND faults the DB.
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
    # Coverage blob persisted for both.
    assert json.loads(fam["baseline"]["coverage"])["n_lines"] == 2
    # M10 (advisory) confirms the sqli case (sink file covered + db_fault).
    assert summary["m10_would_confirm"] == 1
    # Grey-box run_metrics recorded.
    assert metrics["greybox_attempts"] == 2
    assert metrics["greybox_db_faults"] == 1


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
