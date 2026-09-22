"""`fuzzlab greybox-run --mutation-variants` reachability (CC-SCHED-0001): the new
mutation-variant candidate source is actually wired into the CLI, additive to the
default probes, and gated the same way as every other request-sending path here
(`--authorized`) — not just a dead class sitting in `fuzzlab/scheduler/variants.py`.
"""

from __future__ import annotations

from fuzzlab.core.store import Store
from fuzzlab.greybox import greybox_cli
from fuzzlab.greybox.run import DEFAULT_PROBES, GreyboxPoint, ProbeSpec
from fuzzlab.mutation.catalog import record_variant


def test_build_parser_exposes_mutation_variant_flags():
    p = greybox_cli.build_parser()
    args = p.parse_args(["--base-url", "http://127.0.0.1:8080", "--store", "x.db",
                         "--authorized", "--mutation-variants",
                         "--mutation-limit", "7"])
    assert args.mutation_variants is True
    assert args.mutation_limit == 7
    # Default off, matching every other opt-in traffic-shaping flag in this project.
    default_args = p.parse_args(["--base-url", "http://127.0.0.1:8080",
                                 "--store", "x.db", "--authorized"])
    assert default_args.mutation_variants is False


def test_greybox_run_requires_authorized_even_with_mutation_variants(capsys):
    p = greybox_cli.build_parser()
    import pytest
    with pytest.raises(SystemExit):
        greybox_cli.main(["--base-url", "http://127.0.0.1:8080", "--store", "x.db",
                          "--mutation-variants"])   # no --authorized -> refused
    assert "authorized" in capsys.readouterr().err


def test_main_merges_mutation_variants_into_the_probe_set(tmp_path, monkeypatch):
    """Drives `main()` for real (store, run_id, points), only stubbing the two
    live-network seams (`points_from_store`, `run_greybox`'s actual send loop
    is exercised via a captured call, not the real HTTP correlating sender) —
    the mutation-variant lookup itself hits the real DB."""
    store_path = tmp_path / "u.db"
    point = GreyboxPoint(url="http://127.0.0.1:8080/search.php", param="q",
                         method="GET", location="query", vuln_class="sqli")

    # Seed a real payload_variant row the CLI run should pick up.
    with Store(store_path) as seed_store:
        mut_run = seed_store.start_run("mutation", "127.0.0.1")
        record_variant(seed_store, mut_run, "' OR 1=1-- -", "'/**/OR/**/1=1-- -",
                       ["ws-alt"], "sqli", sink_context="query")

    captured = {}

    def _fake_run_greybox(*, probes, **kwargs):
        captured["probes"] = tuple(probes)
        return {"points": 1, "attempts": 0, "db_faults": 0, "novel_lines": 0,
                "m10_would_confirm": 0, "max_reward": 0.0, "baseline_reward": 0.0,
                "newcode_reward": 0.0, "coverage_lines_seen": 0}

    monkeypatch.setattr(greybox_cli.gbrun, "points_from_store", lambda *a, **k: [point])
    monkeypatch.setattr(greybox_cli.gbrun, "run_greybox", _fake_run_greybox)

    rc = greybox_cli.main(["--base-url", "http://127.0.0.1:8080",
                           "--store", str(store_path), "--authorized",
                           "--mutation-variants", "--mutation-limit", "5"])
    assert rc == 0
    assert "probes" in captured
    got = captured["probes"]
    # Additive: every default probe is still present...
    for spec in DEFAULT_PROBES:
        assert spec in got
    # ...plus the mutation-engine variant, scoped by the point's known vuln_class.
    mutation_specs = [s for s in got if isinstance(s, ProbeSpec) and s.family.startswith("mut:")]
    assert len(mutation_specs) == 1
    assert mutation_specs[0].value == "'/**/OR/**/1=1-- -"
    assert mutation_specs[0].kind == "sqli"


def test_main_without_mutation_variants_flag_uses_only_defaults(tmp_path, monkeypatch):
    store_path = tmp_path / "u.db"
    point = GreyboxPoint(url="http://127.0.0.1:8080/search.php", param="q")

    with Store(store_path) as seed_store:
        mut_run = seed_store.start_run("mutation", "127.0.0.1")
        record_variant(seed_store, mut_run, "' OR 1=1-- -", "'/**/OR/**/1=1-- -",
                       ["ws-alt"], "sqli")

    captured = {}

    def _fake_run_greybox(*, probes, **kwargs):
        captured["probes"] = tuple(probes)
        return {"points": 1, "attempts": 0, "db_faults": 0, "novel_lines": 0,
                "m10_would_confirm": 0, "max_reward": 0.0, "baseline_reward": 0.0,
                "newcode_reward": 0.0, "coverage_lines_seen": 0}

    monkeypatch.setattr(greybox_cli.gbrun, "points_from_store", lambda *a, **k: [point])
    monkeypatch.setattr(greybox_cli.gbrun, "run_greybox", _fake_run_greybox)

    rc = greybox_cli.main(["--base-url", "http://127.0.0.1:8080",
                           "--store", str(store_path), "--authorized"])
    assert rc == 0
    # A real payload_variant row exists but is never pulled in without the flag.
    assert captured["probes"] == tuple(DEFAULT_PROBES)
