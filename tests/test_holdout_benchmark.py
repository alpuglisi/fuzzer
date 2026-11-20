"""The held-out benchmark's own tests (lab/HOLDOUT.md, FR-LAB-420..423, FR-CORE-680..).

This is the ONLY test file that may name a held-out lab (lab/HOLDOUT.md rule 4). It
holds: the guard that enforces that rule, the table parser's checks, the benchmark
script's offline checks (``scripts/holdout_score.py`` against fakes: nothing here
sends traffic), and each held-out lab fixture's unit tests (its bootstrap against a fake
client). No test here runs a held-out lab or reads its answer key for anything but
structure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fuzzlab.lab_fixtures import heldout

REPO = Path(__file__).resolve().parent.parent
TESTS = REPO / "tests"
THIS = Path(__file__).resolve()


# --- the rule's guard (lab/HOLDOUT.md rule 4) -----------------------------------------

def held_out_name_offenders(root: Path, labs, allowed: set[Path]) -> list[str]:
    """``file:line`` of every held-out name in a text file under ``root``, except
    ``allowed``."""
    pat = heldout.name_pattern(labs)
    out = []
    for f in sorted(root.rglob("*")):
        if not f.is_file() or "__pycache__" in f.parts or f.resolve() in allowed:
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue                      # binary data: no name a reader could follow
        for n, line in enumerate(text.splitlines(), 1):
            if pat.search(line):
                out.append(f"{f.relative_to(root)}:{n}")
    return out


def test_the_holdout_table_lists_the_held_out_labs():
    labs = heldout.held_out_labs()
    assert labs, "lab/HOLDOUT.md lists no held-out lab"
    for lab in labs:
        assert lab.upstream and lab.stack and lab.names


def test_no_other_test_file_names_a_held_out_lab():
    """Only this file may name a held-out lab (lab/HOLDOUT.md rule 4)."""
    labs = heldout.held_out_labs()
    assert held_out_name_offenders(TESTS, labs, {THIS}) == []


def test_the_guard_flags_a_synthetic_offender(tmp_path):
    labs = heldout.parse_holdout_table(
        "## Held-out labs\n\n| Lab | Upstream | Stack | Names |\n| --- | --- | --- | --- |\n"
        "| acme-lab | someone/acme | Go | acmelab, acme-lab |\n")
    (tmp_path / "test_tuned.py").write_text("LAB = 'ACMELAB'\n")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "key.json").write_text('{"dir": "lab/ground-truth-acme-lab"}\n')
    (tmp_path / "test_clean.py").write_text("x = 'acmelabs and xacmelab'\n")
    (tmp_path / "blob.bin").write_bytes(b"\xff\xfe acmelab")
    assert held_out_name_offenders(tmp_path, labs, set()) == [
        "data/key.json:1", "test_tuned.py:1"]
    assert held_out_name_offenders(tmp_path, labs, {(tmp_path / "test_tuned.py").resolve(),
                                                    (tmp_path / "data/key.json").resolve()}
                                   ) == []


@pytest.mark.parametrize("text", [
    "no section here",
    "## Held-out labs\n\n(none)\n",
    "## Held-out labs\n| a | b | c | d |\n| - | - | - | - |\n| Bad Name | u | s | x1x |\n",
    "## Held-out labs\n| a | b | c | d |\n| - | - | - | - |\n| ok | u | s |  |\n",
    "## Held-out labs\n| a | b | c | d |\n| - | - | - | - |\n| ok | u | s | ok1 |\n"
    "| ok | u | s | ok2 |\n",
    "## Held-out labs\n| a | b | c |\n| - | - | - |\n| ok | u | s |\n",
])
def test_a_malformed_holdout_table_fails_closed(text):
    with pytest.raises(heldout.HoldoutTableError):
        heldout.parse_holdout_table(text)


def test_every_held_out_lab_has_its_fixture_and_answer_key():
    """The benchmark can run each listed lab: a compose file, a registered LabMeta and an
    answer key at ``lab/ground-truth-<lab>/`` (where PA-0660's guard reads it)."""
    from fuzzlab.lab_fixtures import external as ext
    from fuzzlab.labels import contract
    for lab in heldout.held_out_labs():
        assert (REPO / "lab" / "external" / lab.name / "compose.yaml").is_file(), lab.name
        assert lab.name in ext.LAB_META, lab.name
        gt = contract.load(REPO / "lab" / f"ground-truth-{lab.name}")
        assert gt.positives() and gt.negatives(), lab.name


# --- scripts/holdout_score.py (offline) ------------------------------------------------

def _score_mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location("holdout_score",
                                                  REPO / "scripts" / "holdout_score.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _case(cid, url, param, vc, vuln=True, reach="crawl,gt"):
    from fuzzlab.labels import contract
    return contract.Case(case_id=cid, url=url, method="GET", param=param, location="query",
                         vuln_class=vc, sink_context="html", expected_vulnerable=vuln,
                         rendering="server", notes=f"[reach: {reach}] [prov: p] x")


def test_the_reach_tag_is_read_from_the_notes():
    m = _score_mod()
    assert m.reach_tag("[reach: crawl,gt] [prov: x] y") == "crawl,gt"
    assert m.reach_tag("[reach: none - websocket only] [prov: x] y") == "none - websocket only"
    assert m.reach_tag("no tag") == "?"


def test_candidate_progress_tells_discovery_from_detection():
    from fuzzlab.core.oracle_status import CHECKED
    m = _score_mod()
    case = _case("X-0001", "/a", "q", "sql-injection")
    from fuzzlab.core.runmode import to_category
    cat = to_category("sql-injection")
    assert m.candidate_progress([], case) == "no candidate"
    assert m.candidate_progress([("/a", "GET", "q", "xss", CHECKED)], case) == (
        "no candidate for the class")
    assert m.candidate_progress([("/a", "GET", "q", cat, "SKIPPED")], case).startswith(
        "candidate not checked")
    assert m.candidate_progress([("/a", "GET", "q", cat, CHECKED)], case) == (
        "checked, not confirmed")


def test_a_lab_row_lists_every_fn_with_its_point_class_and_reach():
    from fuzzlab.harness.scoring import Detection, score
    from fuzzlab.labels import contract
    m = _score_mod()
    cases = [_case("X-0001", "/a", "q", "sql-injection"),
             _case("X-0002", "/b", "id", "sql-injection", reach="gt"),
             _case("X-0003", "/c", "q", "sql-injection", vuln=False)]
    gt = contract.GroundTruth(target="t", cases=cases, points=[])
    report = score([Detection("/a", "GET", "q", "sql-injection"),
                    Detection("/c", "GET", "q", "sql-injection")], gt)
    row = m.lab_row("lab-x", gt, report, [], 42, 1.23)
    assert (row["tp"], row["fp"], row["fn"], row["tn"]) == (1, 1, 1, 0)
    assert row["fns"] == [{"case_id": "X-0002", "url": "/b", "method": "GET", "param": "id",
                           "location": "query", "vuln_class": "sql-injection",
                           "reach": "gt", "progress": "no candidate"}]
    assert row["requests"] == 42 and row["fps"]
    md = m.render_markdown({"fuzzlab_commit": "abc", "detection_base": "e14c925",
                            "detection_identical": True, "generated": "now", "labs": [row]})
    assert "| lab-x | ok | 1 | 1 | 1 | 0 |" in md and "X-0002" in md


def test_the_benchmark_refuses_without_authorized_and_unknown_labs(capsys):
    m = _score_mod()
    assert m.main([]) == 2
    assert "--authorized" in capsys.readouterr().err
    assert m.main(["--lab", "not-held-out", "--authorized"]) == 2


def test_a_benchmark_run_uses_crawl_points_only(tmp_path, monkeypatch):
    """The run's argv: discovery, then `auto --points crawl` with the key only for
    scoring -- never a ground-truth-point run (lab/HOLDOUT.md rule 2)."""
    import types
    m = _score_mod()
    lab = heldout.held_out_labs()[0].name
    calls = []

    def fake_run(self, argv, *, timeout=None, cwd=None):
        calls.append(argv)
        if "disco" in argv:
            out = Path(argv[argv.index("--out") + 1])
            out.mkdir()
            (out / "capture.jsonl").write_text("{}\n")
        if "auto" in argv:
            Path(argv[argv.index("--store") + 1]).write_text("")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    from fuzzlab.harness.scoring import ScoreReport
    from fuzzlab.labels import contract
    gt = contract.GroundTruth(target="t", cases=[_case("X-0001", "/a", "q", "sql-injection")],
                              points=[])
    monkeypatch.setattr(m.Runner, "_run", fake_run)
    monkeypatch.setattr(m, "score_store",
                        lambda store, gt_dir: (gt, ScoreReport(fn=1, missed=["X-0001"]), [], 7))
    row = m.Runner(lab, tmp_path, budget_total=10, timeout=10, disco_deadline=5,
                   log=lambda s: None).run()
    assert row["status"] == "ok" and row["fn"] == 1
    autos = [a for a in calls if "auto" in a]
    assert len(autos) == 1
    auto = autos[0]
    assert auto[auto.index("--points") + 1] == "crawl"
    assert "--authorized" in auto and "--score" in auto
    assert calls[0][0].endswith("labctl.sh") and calls[0][1:3] == ["reset", lab]
    assert calls[-1][-2:] == ["down", lab]


# --- held-out lab fixture: vampi --------------------------------------------------------


# --- end vampi --------------------------------------------------------------------------


# --- held-out lab fixture: dvws-node ----------------------------------------------------


# --- end dvws-node ----------------------------------------------------------------------


# --- held-out lab fixture: railsgoat ----------------------------------------------------


# --- end railsgoat ----------------------------------------------------------------------
