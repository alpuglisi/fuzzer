"""The destructive gate sits at the send (BUG-0082, FR-MUT-9, PA-0083).

`catalog.record_variant` said a destructive variant is "never persisted or sent", but it
gated only the record: `mutate-run` sent 10 of 10 destructive payloads with
`allow_destructive=False`, and greybox sent its mutation variants unchecked.
"""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.greybox.run import GreyboxPoint, ProbeSpec, run_greybox
from fuzzlab.mutation.catalog import is_destructive, refuse_destructive
from fuzzlab.mutation.livefilter import DestructiveRefused, HttpFilter
from fuzzlab.mutation.run import run_mutation
from fuzzlab.oracle.probe import Probe
from tests.test_greybox_live import DictCoverage, DictFault, FakeSender


class _Waf:
    """Blocks everything; records every value that left the process."""

    def __init__(self, status=403):
        self.sent, self.status = [], status

    def send(self, url, param, value, timing=False, **kw):
        self.sent.append(value)
        return Probe(self.status, "blocked by waf rule sqli-stacked-query")


@pytest.mark.parametrize("payload", [
    "1; DROP TABLE users-- -", "DR/**/OP TABLE x", "%44ROP TABLE x", "%2544ROP TABLE x",
    "dRoP TABLE x", "DROP+TABLE+x", "DR\x00OP TABLE x", "1;#\nDROP TABLE x",
    "1; rm -rf /", "1;shutdown",
    "1; INSERT -- x\nINTO t VALUES(1)",          # only the comment-stripped form matches
])
def test_obfuscated_destructive_payloads_are_refused(payload):
    assert refuse_destructive(payload) and not refuse_destructive(payload, True)


@pytest.mark.parametrize("payload", [
    "1' OR '1'='1", "1 UNION SELECT 1--", "<script>alert(1)</script>", "updated",
    "1 AND SLEEP(5)", "{{7*7}}", "../../etc/passwd",
])
def test_ordinary_payloads_pass(payload):
    assert not refuse_destructive(payload)


def _run(tmp_path, bases, allow=False):
    waf = _Waf()
    with Store(tmp_path / "m.db") as store:
        rid = store.start_run("mutate", "h")
        out = run_mutation(url="http://127.0.0.1:8080/p", param="id", store=store,
                           run_id=rid, sender=waf, bases=bases, allow_destructive=allow,
                           budget=10)
    return waf, out


def test_a_destructive_base_is_never_sent_nor_any_variant(tmp_path):
    waf, out = _run(tmp_path, ["1; DROP TABLE users-- -"])
    assert waf.sent == []                                     # it used to send 10 of 10
    assert out["refused"] == 1 and out["blocked"] == 0        # never a fake WAF block
    assert "allow-destructive" in out["results"][0]["refused"]


def test_allow_destructive_sends_it(tmp_path):
    waf, out = _run(tmp_path, ["1; DROP TABLE users-- -"], allow=True)
    assert waf.sent and any(is_destructive(v) for v in waf.sent) and out["refused"] == 0


def test_a_variant_that_turns_destructive_is_not_sent(tmp_path, monkeypatch):
    """A non-destructive base whose operator output looks destructive: skipped, counted
    as refused, never reported as caught."""
    from fuzzlab.mutation import search as search_mod
    from fuzzlab.mutation.operators import MutationOperator

    evil = MutationOperator("evil", "comment", ("sql-injection",),
                            lambda p: [p + "; DR/**/OP TABLE x"])
    monkeypatch.setattr(search_mod, "default_operators", lambda vc: [evil])
    waf, out = _run(tmp_path, ["1' OR 1=1-- -"])
    assert all(not refuse_destructive(v) for v in waf.sent)
    assert out["refused"] >= 1 and out["results"][0]["refused_variants"] >= 1


def test_the_live_filter_refuses_at_the_send_itself():
    waf = _Waf()
    flt = HttpFilter(waf, "http://h/p", "id")
    with pytest.raises(DestructiveRefused):
        flt.caught("1; DROP TABLE t")
    assert waf.sent == []


def test_greybox_never_sends_a_destructive_probe(tmp_path):
    probes = (ProbeSpec("baseline", "1", "baseline"),
              ProbeSpec("sqli-stacked", "1; DROP TABLE t", "sqli"))
    sender = FakeSender([(Probe(200, "ok"), {}, False)])
    pts = [GreyboxPoint("http://h/a.php", "x", "GET", "query", "sqli")]
    with Store(tmp_path / "g.db") as store:
        rid = store.start_run("greybox", "h")
        summary = run_greybox(base_url="http://h", store=store, run_id=rid, points=pts,
                              sender=sender, coverage_source=DictCoverage(sender),
                              dbfault_source=DictFault(sender), probes=probes)
    assert [s[2] for s in sender.sent] == ["1"]
    assert summary["destructive_refused"] == 1
