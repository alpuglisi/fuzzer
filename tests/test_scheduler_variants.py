"""Tests for the mutation-variant candidate source (SCHED/MUT wiring, CC-SCHED-0001 /
CC-MUT-0009): a real `payload_variant` row round-trips into a `ProbeSpec` and, from
there, into a real `run_greybox` attempt against a test-double target."""

from __future__ import annotations

import pytest

from fuzzlab.core.store import Store
from fuzzlab.greybox.run import GreyboxPoint, ProbeSpec, run_greybox
from fuzzlab.mutation.catalog import record_variant
from fuzzlab.oracle.probe import Probe
from fuzzlab.scheduler.variants import (
    load_variant_candidates,
    variant_probe_specs,
)


def _seed(store, run_id, **overrides):
    kwargs = dict(base_payload="' OR 1=1-- -", variant="'/**/OR/**/1=1-- -",
                  operators=["ws-alt"], vuln_class="sqli", sink_context="query",
                  bypassed_rule="rule-42", semantics_ok=True, coverage_gain=3.0)
    kwargs.update(overrides)
    return record_variant(store, run_id, kwargs.pop("base_payload"),
                          kwargs.pop("variant"), kwargs.pop("operators"),
                          kwargs.pop("vuln_class"), **kwargs)


# --- load_variant_candidates: reads back what the mutation engine wrote ------
def test_load_variant_candidates_round_trips_a_real_row(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("mutation", "127.0.0.1")
        vid = _seed(store, run_id)

        cands = load_variant_candidates(store)
    assert len(cands) == 1
    c = cands[0]
    assert c.id == vid
    assert c.vuln_class == "sqli"
    assert c.variant == "'/**/OR/**/1=1-- -"
    assert c.base_payload == "' OR 1=1-- -"
    assert c.operators == ["ws-alt"]
    assert c.bypassed_rule == "rule-42"
    assert c.coverage_gain == 3.0


def test_load_variant_candidates_scopes_by_vuln_class(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("mutation", "127.0.0.1")
        _seed(store, run_id, vuln_class="sqli", variant="sqli-variant")
        _seed(store, run_id, vuln_class="xss-reflected", variant="xss-variant",
              base_payload="<script>1</script>")

        sqli_only = load_variant_candidates(store, vuln_class="sqli")
        both = load_variant_candidates(store, vuln_classes=["sqli", "xss-reflected"])
        none = load_variant_candidates(store, vuln_class="ssti")
    assert [c.variant for c in sqli_only] == ["sqli-variant"]
    assert {c.variant for c in both} == {"sqli-variant", "xss-variant"}
    assert none == []


def test_load_variant_candidates_excludes_non_preserving_by_default(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("mutation", "127.0.0.1")
        _seed(store, run_id, semantics_ok=False, variant="unsafe-variant")
        _seed(store, run_id, semantics_ok=True, variant="safe-variant")

        default = load_variant_candidates(store)
        include_all = load_variant_candidates(store, semantics_ok_only=False)
    assert [c.variant for c in default] == ["safe-variant"]
    assert {c.variant for c in include_all} == {"unsafe-variant", "safe-variant"}


def test_load_variant_candidates_respects_limit_and_run_scope(tmp_path):
    with Store(tmp_path / "u.db") as store:
        r1 = store.start_run("mutation", "127.0.0.1")
        r2 = store.start_run("mutation", "127.0.0.1")
        _seed(store, r1, variant="v1")
        _seed(store, r2, variant="v2")
        _seed(store, r2, variant="v3")

        only_r2 = load_variant_candidates(store, run_id=r2)
        limited = load_variant_candidates(store, limit=1)
    assert {c.variant for c in only_r2} == {"v2", "v3"}
    assert len(limited) == 1


# --- variant_probe_specs: the ProbeSpec shape the live attempt path expects -
def test_variant_probe_specs_shape_and_family_traceability(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("mutation", "127.0.0.1")
        vid = _seed(store, run_id, vuln_class="sqli", variant="1' OR '1'='1")

        specs = variant_probe_specs(store)
    assert len(specs) == 1
    spec = specs[0]
    assert isinstance(spec, ProbeSpec)
    assert spec.value == "1' OR '1'='1"
    assert spec.kind == "sqli"                       # mapped from vuln_class
    assert spec.family == f"mut:sqli:{vid}"           # traces back to the row id
    # The family suffix really does resolve back to the exact payload_variant row.
    with Store(tmp_path / "u.db") as store2:
        row = store2.conn.execute(
            "SELECT variant FROM payload_variant WHERE id=?",
            (int(spec.family.rsplit(':', 1)[-1]),)).fetchone()
    assert row["variant"] == "1' OR '1'='1"


def test_variant_probe_specs_xss_kind_mapping(tmp_path):
    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("mutation", "127.0.0.1")
        _seed(store, run_id, vuln_class="xss-reflected", variant="<svg onload=x>",
              base_payload="<script>x</script>")
        specs = variant_probe_specs(store)
    assert specs[0].kind == "xss"


def test_variant_probe_specs_empty_store_returns_no_probes(tmp_path):
    with Store(tmp_path / "u.db") as store:
        assert variant_probe_specs(store) == []


# --- end-to-end: a real payload_variant row drives a real run_greybox attempt --
class _FakeSender:
    """A test-double target sender (not a mock of this module's own internals):
    plays back a scripted (Probe, coverage, db_fault) per send, keyed by order —
    the same fake shape `tests/test_greybox_live.py` uses for the real driver."""

    def __init__(self, script):
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
        self.sent.append((url, param, value))
        return probe, cid


class _DictCoverage:
    def __init__(self, sender):
        self._s = sender

    def lines_for(self, cid):
        return {f: set(v) for f, v in self._s.cov.get(cid, {}).items()}


class _DictFault:
    def __init__(self, sender):
        from fuzzlab.greybox.dbfault import DbFault
        self._s = sender
        self._DbFault = DbFault

    def fault_for(self, cid):
        return self._DbFault(faulted=bool(self._s.faults.get(cid)))


def test_mutation_variant_round_trips_into_a_real_attempt(tmp_path):
    """A real `payload_variant` row -> `variant_probe_specs` -> a real `run_greybox`
    call against a test-double target -> a real `attempt` row, with
    `payload_family` tracing back to the mutation-engine row (not a mock of this
    module's own code)."""
    app = "/var/www/html/search.php"
    with Store(tmp_path / "u.db") as store:
        mut_run = store.start_run("mutation", "127.0.0.1")
        vid = _seed(store, mut_run, vuln_class="sqli", variant="1' OR SLEEP(0)-- -",
                   coverage_gain=None)

        extra = variant_probe_specs(store, vuln_class="sqli")
        assert len(extra) == 1
        probes = (ProbeSpec("baseline", "1", "baseline"),) + tuple(extra)

        sender = _FakeSender([
            (Probe(200, "ok"), {app: [1, 2]}, False),                       # baseline
            (Probe(500, "You have an error in your SQL syntax"),
             {app: [1, 2, 9, 10]}, True),                                   # mutation variant
        ])
        cov, fault = _DictCoverage(sender), _DictFault(sender)
        point = GreyboxPoint(url="http://127.0.0.1:8080/search.php", param="q",
                             method="GET", location="query", vuln_class="sqli")

        fuzz_run = store.start_run("greybox", "127.0.0.1")
        summary = run_greybox(base_url="http://127.0.0.1:8080", store=store,
                              run_id=fuzz_run, points=[point], sender=sender,
                              coverage_source=cov, dbfault_source=fault, probes=probes)

        rows = store.conn.execute(
            "SELECT payload_family, reward, db_fault FROM attempt WHERE run_id=?",
            (fuzz_run,)).fetchall()

    assert summary["attempts"] == 2
    families = {r["payload_family"] for r in rows}
    assert families == {"baseline", f"mut:sqli:{vid}"}
    by_family = {r["payload_family"]: r for r in rows}
    # The variant attempt found the SQL error + new code -> outscores the baseline.
    assert by_family[f"mut:sqli:{vid}"]["db_fault"] == 1
    assert by_family[f"mut:sqli:{vid}"]["reward"] > by_family["baseline"]["reward"]
    # sanity: sent the actual mutation-engine variant string, not the base payload.
    assert sender.sent[1][2] == "1' OR SLEEP(0)-- -"


def test_mutation_variants_are_additive_not_replacing(tmp_path):
    """`--mutation-variants` semantics: extra probes are appended to the default
    set, never substituted for it (FR-SCHED-9 / FR-MUT-8's "alongside" contract)."""
    from fuzzlab.greybox.run import DEFAULT_PROBES

    with Store(tmp_path / "u.db") as store:
        run_id = store.start_run("mutation", "127.0.0.1")
        _seed(store, run_id, vuln_class="sqli", variant="extra-variant")
        extra = variant_probe_specs(store, vuln_class="sqli")

    merged = tuple(DEFAULT_PROBES) + tuple(extra)
    assert set(DEFAULT_PROBES).issubset(set(merged))
    assert any(p.value == "extra-variant" for p in merged)
    assert len(merged) == len(DEFAULT_PROBES) + len(extra)


def test_load_variant_candidates_no_filter_needs_no_extra_args(tmp_path):
    # Guard against an accidental required-kwarg regression on the plain call shape.
    with Store(tmp_path / "u.db") as store:
        assert load_variant_candidates(store) == []
