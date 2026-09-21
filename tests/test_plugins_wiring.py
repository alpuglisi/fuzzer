"""Phase 10 T10.2: plugin hooks wired into the HTTP seam, auditor, and oracle."""

import contextlib

from fuzzlab.audit.engine import InjectionPoint, evaluate
from fuzzlab.audit.rules import Rule
from fuzzlab.core.http import HttpClient, Request
from fuzzlab.core.store import Store
from fuzzlab.oracle.oracle import Oracle
from fuzzlab.oracle.probe import Candidate, Verdict
from fuzzlab.plugins import PluginManager


# --- fakes -------------------------------------------------------------------
class _Budget:
    def checkout(self, component, n): pass
    def timing_lock(self, host): return contextlib.nullcontext()


class _AlwaysOracle:
    """A register_oracle plugin: contributes an always-confirming strategy."""
    name = "always-oracle"
    arm = "sqli:plugin"

    def applies(self, candidate): return True
    def confirm(self, candidate, sender):
        return Verdict(confirmed=True, vuln_class="sqli", mechanism="plugin-oracle")
    def register_oracle(self): return self


# --- HTTP seam (on_request / on_response) ------------------------------------
def test_http_on_request_mutates_and_on_response_observes():
    seen_headers, seen_responses = {}, []

    class HeaderPlugin:
        name = "hdr"
        def on_request(self, req):
            req.headers["X-Plugin"] = "1"
            return req
        def on_response(self, req, resp):
            seen_responses.append(resp.status)

    def transport(method, url, headers, body, timeout):
        seen_headers.update(headers)
        return (200, {"Content-Type": "text/html"}, b"ok")

    client = HttpClient(_Budget(), ["127.0.0.1"], transport=transport,
                        plugins=PluginManager(plugins=[HeaderPlugin()]))
    resp = client.send(Request("GET", "http://127.0.0.1/x"))
    assert resp.status == 200
    assert seen_headers.get("X-Plugin") == "1"      # on_request mutation reached the wire
    assert seen_responses == [200]                  # on_response observed


def test_http_no_plugins_is_unchanged():
    def transport(method, url, headers, body, timeout):
        return (204, {}, b"")
    client = HttpClient(_Budget(), ["127.0.0.1"], transport=transport)   # no plugins
    assert client.send(Request("GET", "http://127.0.0.1/x")).status == 204


# --- auditor (register_rules / on_candidate) ---------------------------------
def test_auditor_register_rules_and_on_candidate(tmp_path):
    seen = []

    class RulePlugin:
        name = "rules"
        def register_rules(self):
            return [Rule(id="plugin-sqli", category="sql-injection",
                         transaction_type="SQL Injection", when={"always": True})]
        def on_candidate(self, cand):
            seen.append(cand["rule_id"])

    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        point = InjectionPoint(url="http://h/p.php", param="id")
        counts = evaluate([point], store, run_id, rules=[],   # no built-in rules
                          plugins=PluginManager(plugins=[RulePlugin()]))
        assert counts["candidate"] == 1                # the plugin rule fired
        assert seen == ["plugin-sqli"]                 # on_candidate observed it
        n = store.conn.execute("SELECT COUNT(*) c FROM candidate WHERE run_id=?",
                               (run_id,)).fetchone()["c"]
        assert n == 1


def test_auditor_no_plugins_unchanged(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        counts = evaluate([InjectionPoint("http://h/p.php", "id")], store, run_id, rules=[])
        assert counts["candidate"] == 0                # no rules, no plugins → nothing


# --- oracle (register_oracle / on_finding) -----------------------------------
def test_oracle_register_oracle_and_on_finding(tmp_path):
    findings_seen = []

    class ObserverPlugin:
        name = "obs"
        def on_finding(self, f): findings_seen.append(f["vuln_class"])

    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        mgr = PluginManager(plugins=[_AlwaysOracle(), ObserverPlugin()])
        oracle = Oracle(strategies=[], store=store, run_id=run_id, plugins=mgr)
        verdict = oracle.confirm(Candidate(url="http://h/p.php", param="id"), sender=None)
        assert verdict is not None and verdict.confirmed
        # the plugin oracle wrote a finding (the only plugin path to a writer)
        n = store.conn.execute("SELECT COUNT(*) c FROM finding WHERE run_id=?",
                               (run_id,)).fetchone()["c"]
        assert n == 1
        assert findings_seen == ["sqli"]               # on_finding observed it


def test_observer_alone_cannot_write_a_finding(tmp_path):
    class ObserverOnly:
        name = "obs"
        def on_finding(self, f): return {"forged": True}   # return is ignored

    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "h")
        oracle = Oracle(strategies=[], store=store, run_id=run_id,
                        plugins=PluginManager(plugins=[ObserverOnly()]))
        assert oracle.confirm(Candidate(url="http://h/p.php", param="id"), None) is None
        n = store.conn.execute("SELECT COUNT(*) c FROM finding").fetchone()["c"]
        assert n == 0                                   # no strategy → no finding


# --- end to end: run records the active plugin set ---------------------------
def test_run_auto_records_active_plugins(tmp_path):
    from fuzzlab.harness.auto import run_auto

    class Noop:
        name = "noop"
        version = "2.0"

    class _Sender:
        def send(self, url, param, value, timing=False, method="GET", location="query"):
            from types import SimpleNamespace
            return SimpleNamespace(status=200, headers={}, text="", elapsed_ms=1.0)

    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("auto", "127.0.0.1:8080")
        run_auto(base_url="http://127.0.0.1:8080", store=store, run_id=run_id,
                 sender=_Sender(), mode="manual", selected_categories=["sql-injection"],
                 points_source="crawl", plugins=PluginManager(plugins=[Noop()]))
        row = store.conn.execute(
            "SELECT name, version FROM run_plugin WHERE run_id=?", (run_id,)).fetchone()
        assert row["name"] == "noop" and row["version"] == "2.0"
