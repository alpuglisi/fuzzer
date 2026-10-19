"""Cross-account access control (FR-FUZZ-55): `CrossAccountReplayStrategy` replays the
run's own account's request as a peer account and unauthenticated; `--peer-identity`
is checked before the store opens. Fake senders stand for one app seen by each user."""

from __future__ import annotations

import pytest

from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import CrossAccountReplayStrategy, PeerAccounts

RECORDS = {"r-alice-1": "alice", "r-bob-1": "bob"}


class _App:
    """``GET /record?record_id=V`` as seen by ``user`` (None: no session). ``mode``:
    ``broken`` (anyone logged in reads any record), ``open`` (no session needed),
    ``ok`` (owner only), ``banner`` (every page names alice, whatever V)."""

    def __init__(self, mode, user):
        self.mode, self.user, self.sent = mode, user, []

    def send(self, url, param, value, timing=False, method="GET", location="query",
             content_type=None, entries=None, prg=False):
        if entries is not None:
            value = dict(entries).get(param, value)
        self.sent.append(value)
        owner = RECORDS.get(value)
        if self.mode == "banner":
            return Probe(200, "site by alice. nothing here", 0.0)
        if self.user is None and self.mode != "open":
            return Probe(302, "", 0.0)
        if owner is None:
            return Probe(404, "not found", 0.0)
        if self.mode == "ok" and owner != self.user:
            return Probe(403, "forbidden", 0.0)
        return Probe(200, f"record of {owner}: secret", 0.0)


def _cand(method="GET", location="query", entries=(("record_id", "r-alice-1"),)):
    return Candidate(url="http://127.0.0.1:9/record", param="record_id", method=method,
                     location=location, category="access-control", base_entries=entries)


def _run(mode, anon_mode=None, peer=True):
    accounts = PeerAccounts(sender=_App(mode, "bob"), owner="alice", peer_name="bob",
                            anonymous=_App(anon_mode or mode, None)) if peer else None
    return CrossAccountReplayStrategy(accounts).confirm(_cand(), _App(mode, "alice")), \
        accounts


def test_another_account_reading_the_owners_record_is_confirmed():
    v, accounts = _run("broken")
    assert v is not None and v.confirmed and v.vuln_class == "access_control"
    assert v.evidence["who"] == "peer" and "secret" not in str(v.evidence)
    assert accounts.sender.sent == ["r-alice-1", "r-alice-1"]     # A's own value, twice


def test_an_unauthenticated_read_is_confirmed_when_the_peer_is_refused():
    accounts = PeerAccounts(sender=_App("ok", "bob"), owner="alice", peer_name="bob",
                            anonymous=_App("open", None))
    v = CrossAccountReplayStrategy(accounts).confirm(_cand(), _App("ok", "alice"))
    assert v is not None and v.evidence["who"] == "anonymous"


@pytest.mark.parametrize("mode", ["ok", "banner"])
def test_no_verdict_for_an_owner_check_or_a_page_that_always_names_the_owner(mode):
    v, _accounts = _run(mode)
    assert v is None


def test_a_peer_session_with_no_response_is_inconclusive_not_negative():
    """PA-0153: the peer's own transport failing mid-check is "no verdict"."""
    from fuzzlab.oracle.oracle import Oracle
    from fuzzlab.oracle.probe import ProbeUnobserved

    class Dead:
        def send(self, *a, **kw):
            raise ProbeUnobserved("no response: ConnectionError")
    accounts = PeerAccounts(sender=Dead(), owner="alice", peer_name="bob")
    confirmed, inconclusive = Oracle(strategies=[CrossAccountReplayStrategy(accounts)]) \
        .confirm_outcome(_cand(), _App("broken", "alice"))
    assert confirmed is None and inconclusive is not None and inconclusive.inconclusive


def test_no_peer_no_post_no_value_no_probe():
    app = _App("broken", "alice")
    assert CrossAccountReplayStrategy(None).confirm(_cand(), app) is None
    accounts = PeerAccounts(sender=_App("broken", "bob"), owner="alice", peer_name="bob")
    s = CrossAccountReplayStrategy(accounts)
    assert s.confirm(_cand(method="POST"), app) is None
    assert s.confirm(_cand(entries=None), app) is None
    assert app.sent == []


def test_peer_identity_is_refused_before_the_store_opens(tmp_path, capsys, monkeypatch):
    from fuzzlab.harness import auto_cli
    base = ["--base-url", "http://127.0.0.1:9/", "--store", str(tmp_path / "s.db"),
            "--categories", "access-control", "--authorized"]
    with pytest.raises(SystemExit):
        auto_cli.main(base + ["--peer-identity", "b"])
    assert "needs --identity" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        auto_cli.main(base + ["--identity", "a", "--peer-identity", "a"])
    assert "another account" in capsys.readouterr().err

    class Store:
        def get(self, host, ident):
            return None
    monkeypatch.setattr("fuzzlab.core.credentials.CredentialStore.open",
                        classmethod(lambda cls, cfg: Store()))
    with pytest.raises(SystemExit):
        auto_cli.main(base + ["--identity", "a", "--peer-identity", "b"])
    assert "no stored credential for identity 'a'" in capsys.readouterr().err
    assert not (tmp_path / "s.db").exists()


def test_run_auto_traces_the_peer_and_unauthenticated_replays(tmp_path, monkeypatch):
    """BUG-0513: every sender a strategy is given passes the trace. The peer's and the
    unauthenticated replays are the evidence of an access finding: each is an exchange
    with its own identity, and the strategy's run cites them."""
    import json

    from fuzzlab.core import trace
    from fuzzlab.core.store import Store
    from fuzzlab.harness import auto
    from fuzzlab.harness.pipeline import PipelineResult

    def pipeline(points, store, run_id, sender, plan, *, peer=None, **_kw):
        with trace.test_scope("t1"), trace.strategy_scope("cross-account"):
            verdict = CrossAccountReplayStrategy(peer).confirm(_cand(), sender)
            cited = trace.collected()
        assert verdict is not None and verdict.confirmed
        pipeline.cited = cited
        return PipelineResult(plan=plan, points_audited=0, candidates=[], negatives=[],
                              findings=[], metrics={})
    monkeypatch.setattr(auto, "run_pipeline", pipeline)
    monkeypatch.setattr(auto, "_points_from_store", lambda *a, **k: [], raising=False)
    accounts = PeerAccounts(sender=_App("broken", "bob"), owner="alice", peer_name="bob",
                            anonymous=_App("broken", None))
    alice = _App("broken", "alice")
    alice._identity = "alice"
    with Store(tmp_path / "s.db") as store:
        run = store.start_run("auto", "h")
        auto.run_auto(base_url="http://127.0.0.1:9/", store=store, run_id=run,
                      sender=alice, mode="manual",
                      selected_categories=["access-control"], points_source="crawl",
                      peer=accounts)
        rows = [(r["key"], json.loads(r["body"])) for r in store.conn.execute(
            "SELECT key, body FROM trace_event WHERE run_id=? AND kind='exchange' "
            "ORDER BY seq", (run,))]
    # A's own view and the other-value check, then B's two replays, which confirm
    assert [b["identity"] for _k, b in rows] == ["alice", "alice", "bob", "bob"]
    assert len(rows) == len(alice.sent) + len(accounts.sender.sent)
    assert pipeline.cited == [k for k, _b in rows]              # the finding cites all
