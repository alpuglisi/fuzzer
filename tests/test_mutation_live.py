"""Live WAF-evasion last mile (Phase 8, runbook Part J): the HTTP `Filter` adapter and
the run/record driver. Offline — a fake sender models the WAF (block on `union select`),
so the wiring (HttpFilter -> MutationSearch -> payload_variant) is verified without a lab.
"""

import re

from fuzzlab.core.store import Store
from fuzzlab.mutation.catalog import list_variants
from fuzzlab.mutation.livefilter import HttpFilter, parse_rule_ids
from fuzzlab.mutation.run import run_mutation
from fuzzlab.oracle.probe import Probe

_BLOCK_BODY = ("<h1>403 &mdash; request blocked by the lab filter</h1>"
               "<p>matched: sqli-union-select</p>")


class FakeWafSender:
    """Models the naive WAF: block a value matching `union\\s+select` (mirrors the
    offline FilterModel rule), else allow. Records what it was sent."""

    def __init__(self):
        self.sent = []

    def send(self, url, param, value, timing=False, method="GET", location="query"):
        self.sent.append((url, param, value, method, location))
        if re.search(r"union\s+select", value, re.I):
            return Probe(status=403, text=_BLOCK_BODY, elapsed=0.01, headers={})
        return Probe(status=200, text="<html>results</html>", elapsed=0.01, headers={})


def test_parse_rule_ids_from_block_page():
    assert parse_rule_ids(_BLOCK_BODY) == ["sqli-union-select"]
    assert parse_rule_ids("") == []


def test_http_filter_maps_block_status_to_caught():
    flt = HttpFilter(FakeWafSender(), "http://lab/search.php", "q")
    assert flt.caught("1 union select 1") is True
    assert flt.caught("harmless") is False
    ev = flt.evaluate("1 union select 1")
    assert ev.action == "block" and ev.hits == ["sqli-union-select"]
    assert flt.evaluate("harmless").action == "allow"


def test_run_mutation_finds_and_records_a_bypass(tmp_path):
    sender = FakeWafSender()
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("mutate", "lab")
        summary = run_mutation(
            url="http://lab/search.php", param="q", store=store, run_id=run_id,
            sender=sender, bases=["1 union select 1"], vuln_class="sql-injection",
            seed=1, budget=40)
        variants = list_variants(store, run_id)

    assert summary["blocked"] == 1                     # the base is blocked by the WAF
    assert summary["bypasses"] == 1                    # a preserving variant evades it
    assert summary["recorded"] == 1
    assert variants and variants[0]["base_payload"] == "1 union select 1"
    # the recorded variant really is accepted by the (fake) WAF, and is semantics-ok
    assert sender.send("http://lab/search.php", "q", variants[0]["variant"]) is not None
    assert not re.search(r"union\s+select", variants[0]["variant"], re.I)


def test_run_mutation_does_not_record_when_base_not_blocked(tmp_path):
    sender = FakeWafSender()
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("mutate", "lab")
        summary = run_mutation(
            url="http://lab/search.php", param="q", store=store, run_id=run_id,
            sender=sender, bases=["already harmless"], vuln_class="sql-injection",
            seed=1, budget=10)
        assert summary["blocked"] == 0 and summary["bypasses"] == 0
        assert list_variants(store, run_id) == []
