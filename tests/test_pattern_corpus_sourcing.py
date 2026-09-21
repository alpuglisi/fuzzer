"""Tests for the T-LAB0.8 mechanical OSV/GHSA pull + candidate-list tooling
(fuzzlab/tools/pattern_corpus_sourcing.py).

All indexing/scoping/ranking/clustering tests run entirely offline against
synthetic advisory fixtures (never real GHSA IDs or real disclosure text —
see the module docstring's note on why real advisory text is kept out of
test fixtures). The git layer is exercised against a fake, injectable
runner; the one real-network test is a cheap reachability probe only
(``git ls-remote``, no clone), auto-skipped if this environment can't reach
GitHub rather than gated behind a separate opt-in flag, matching this repo's
existing ``skipif``-on-capability-probe convention (see e.g.
``tests/test_lab_waf.py``'s ``PHP is None`` guard).
"""

from __future__ import annotations

import json
import subprocess
from datetime import date
from pathlib import Path

import pytest

from fuzzlab.tools import pattern_corpus_sourcing as sourcing

REAL_CROSSWALK_PATH = "lab/patterns/sourcing/crosswalk.yaml"


# ---------------------------------------------------------------------------
# Fake git runner
# ---------------------------------------------------------------------------


class FakeRunner:
    """Records every invocation and returns a scripted result per argv[1]
    (the git subcommand), so tests never shell out for real."""

    def __init__(self, results: dict[str, subprocess.CompletedProcess]):
        self.results = results
        self.calls: list[list[str]] = []

    _SUBCOMMANDS = frozenset({"clone", "pull", "rev-parse", "ls-remote"})

    def __call__(self, argv):
        self.calls.append(list(argv))
        key = next((tok for tok in argv[1:] if tok in self._SUBCOMMANDS), None)
        if key not in self.results:
            raise AssertionError(f"FakeRunner: no scripted result for git subcommand {key!r} (argv={argv})")
        return self.results[key]


def _ok(stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def _fail(stderr: str = "boom") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=stderr)


# ---------------------------------------------------------------------------
# Synthetic advisory fixtures (never real GHSA text)
# ---------------------------------------------------------------------------


def _write_advisory(base: Path, ghsa_id: str, year: str, month: str, **fields) -> Path:
    defaults = {
        "schema_version": "1.4.0",
        "id": ghsa_id,
        "modified": "2025-06-01T00:00:00Z",
        "published": "2025-06-01T00:00:00Z",
        "summary": "Synthetic test advisory",
        "details": "Synthetic details for offline testing only.",
        "severity": [],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "example-pkg"}}],
        "references": [],
        "database_specific": {"cwe_ids": ["CWE-89"], "severity": "MODERATE", "github_reviewed": True},
    }
    defaults.update(fields)
    d = base / "advisories" / "github-reviewed" / year / month / ghsa_id
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{ghsa_id}.json"
    path.write_text(json.dumps(defaults))
    return path


@pytest.fixture()
def synthetic_repo(tmp_path):
    base = tmp_path / "advisory-database"
    _write_advisory(
        base,
        "GHSA-test-0001",
        "2025",
        "06",
        summary="ORM query builder allows column-name injection via kwargs",
        details=(
            "A caller-supplied field name for a dynamic filter is formatted "
            "directly into the generated SQL string by the query builder, "
            "bypassing the ORM's usual value binding.\n"
            "## Impact\n"
            "Remote attackers can alter query structure."
        ),
        database_specific={"cwe_ids": ["CWE-89"], "severity": "HIGH", "github_reviewed": True},
    )
    _write_advisory(
        base,
        "GHSA-test-0002",
        "2025",
        "06",
        summary="Similar ORM identifier injection in a sibling query builder",
        details=(
            "A caller-supplied field name for a dynamic filter is formatted "
            "directly into the generated SQL string by the query builder, "
            "the same identifier-position shape as other advisories in this "
            "ecosystem."
        ),
        database_specific={"cwe_ids": ["CWE-89"], "severity": "HIGH", "github_reviewed": True},
    )
    _write_advisory(
        base,
        "GHSA-test-0003",
        "2025",
        "06",
        summary="Server-side template injection via unsandboxed Jinja rendering",
        details="User input reaches a Jinja template engine render call directly, allowing arbitrary code execution.",
        database_specific={"cwe_ids": ["CWE-94"], "severity": "CRITICAL", "github_reviewed": True},
    )
    _write_advisory(
        base,
        "GHSA-test-0004",
        "2025",
        "06",
        summary="Unrelated command injection, unrelated to rendering",
        details="A shell command is built via string concatenation of raw user input before execution.",
        database_specific={"cwe_ids": ["CWE-94"], "severity": "HIGH", "github_reviewed": True},
    )
    _write_advisory(
        base,
        "GHSA-test-0005",
        "2025",
        "06",
        summary="Community-reviewed-only advisory, not GitHub-reviewed",
        details="Should never appear in iter_advisories output.",
        database_specific={"cwe_ids": ["CWE-89"], "severity": "LOW", "github_reviewed": False},
    )
    _write_advisory(
        base,
        "GHSA-test-0006",
        "2019",
        "01",
        summary="Too old for the currency window",
        details="Published well outside the 24-month window.",
        published="2019-01-01T00:00:00Z",
        modified="2019-01-01T00:00:00Z",
        database_specific={"cwe_ids": ["CWE-89"], "severity": "HIGH", "github_reviewed": True},
    )
    _write_advisory(
        base,
        "GHSA-test-0007",
        "2025",
        "06",
        summary="Right class, wrong ecosystem",
        details="A SQL injection in an ecosystem this project doesn't target.",
        affected=[{"package": {"ecosystem": "crates.io", "name": "example-crate"}}],
        database_specific={"cwe_ids": ["CWE-89"], "severity": "HIGH", "github_reviewed": True},
    )
    return base


# ---------------------------------------------------------------------------
# parse_advisory_file / iter_advisories
# ---------------------------------------------------------------------------


def test_parse_advisory_file_extracts_expected_fields(synthetic_repo):
    path = synthetic_repo / "advisories" / "github-reviewed" / "2025" / "06" / "GHSA-test-0001" / "GHSA-test-0001.json"
    advisory = sourcing.parse_advisory_file(path)
    assert advisory.id == "GHSA-test-0001"
    assert advisory.cwe_ids == ("CWE-89",)
    assert advisory.ecosystems == ("PyPI",)
    assert "kwargs" in advisory.summary


def test_parse_advisory_file_skips_non_github_reviewed(synthetic_repo):
    path = synthetic_repo / "advisories" / "github-reviewed" / "2025" / "06" / "GHSA-test-0005" / "GHSA-test-0005.json"
    assert sourcing.parse_advisory_file(path) is None


def test_parse_advisory_file_raises_on_malformed_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(sourcing.SourcingError):
        sourcing.parse_advisory_file(bad)


def test_iter_advisories_walks_nested_dirs_and_skips_unreviewed(synthetic_repo):
    ids = {a.id for a in sourcing.iter_advisories(synthetic_repo)}
    assert "GHSA-test-0005" not in ids  # not github_reviewed
    assert {"GHSA-test-0001", "GHSA-test-0002", "GHSA-test-0003"} <= ids


def test_iter_advisories_raises_for_non_advisory_database_dir(tmp_path):
    with pytest.raises(sourcing.SourcingError):
        list(sourcing.iter_advisories(tmp_path))


# ---------------------------------------------------------------------------
# Crosswalk loading + matching
# ---------------------------------------------------------------------------


def test_load_real_crosswalk_has_all_ten_first_wave_classes():
    crosswalk = sourcing.load_crosswalk(REAL_CROSSWALK_PATH)
    ids = {c.id for c in crosswalk.classes}
    assert ids == {
        "sqli_orm", "deserialization", "proto_pollution", "authz_bypass", "ssti",
        "idor_bola", "mass_assignment", "xss_context", "race_condition", "ssrf",
    }
    assert crosswalk.ecosystems == ("npm", "PyPI", "Packagist", "Maven")
    assert crosswalk.currency_window_months == 24


def test_missing_crosswalk_file_raises():
    with pytest.raises(sourcing.SourcingError):
        sourcing.load_crosswalk("does/not/exist.yaml")


def test_crosswalk_matches_direct_cwe(synthetic_repo):
    crosswalk = sourcing.load_crosswalk(REAL_CROSSWALK_PATH)
    advisories = {a.id: a for a in sourcing.iter_advisories(synthetic_repo)}
    assert crosswalk.matches(advisories["GHSA-test-0001"]) == ["sqli_orm"]


def test_crosswalk_keyword_gated_cwe_requires_keyword(synthetic_repo):
    crosswalk = sourcing.load_crosswalk(REAL_CROSSWALK_PATH)
    advisories = {a.id: a for a in sourcing.iter_advisories(synthetic_repo)}
    # CWE-94 + "jinja" (a template-engine keyword) -> ssti
    assert "ssti" in crosswalk.matches(advisories["GHSA-test-0003"])
    # CWE-94 alone, no template-engine keyword -> not ssti
    assert "ssti" not in crosswalk.matches(advisories["GHSA-test-0004"])


# ---------------------------------------------------------------------------
# scope()
# ---------------------------------------------------------------------------


def test_scope_applies_ecosystem_currency_and_crosswalk_filters(synthetic_repo):
    crosswalk = sourcing.load_crosswalk(REAL_CROSSWALK_PATH)
    advisories = list(sourcing.iter_advisories(synthetic_repo))
    candidates = sourcing.scope(advisories, crosswalk, as_of=date(2025, 12, 1))
    ids = {c.advisory.id for c in candidates}
    assert "GHSA-test-0001" in ids
    assert "GHSA-test-0002" in ids
    assert "GHSA-test-0006" not in ids  # too old
    assert "GHSA-test-0007" not in ids  # wrong ecosystem
    assert "GHSA-test-0004" not in ids  # CWE-94 without template keyword matches no class


def test_scope_assigns_primary_class_and_other_matches():
    crosswalk = sourcing.load_crosswalk(REAL_CROSSWALK_PATH)
    advisory = sourcing.Advisory(
        id="GHSA-multi-0001",
        summary="x",
        details="y",
        published="2025-06-01T00:00:00Z",
        modified="2025-06-01T00:00:00Z",
        cwe_ids=("CWE-639", "CWE-89"),  # idor_bola AND sqli_orm
        ecosystems=("PyPI",),
        severity="HIGH",
        source_path="synthetic",
    )
    [candidate] = sourcing.scope([advisory], crosswalk, as_of=date(2025, 12, 1))
    # idor_bola is declared before sqli_orm in the crosswalk -> precedence wins
    assert candidate.class_id == "idor_bola"
    assert candidate.other_matches == ("sqli_orm",)


# ---------------------------------------------------------------------------
# rank()
# ---------------------------------------------------------------------------


def test_rank_prefers_longer_and_structured_prose():
    crosswalk = sourcing.load_crosswalk(REAL_CROSSWALK_PATH)
    short = sourcing.Advisory("GHSA-a", "short", "tiny", "2025-06-01T00:00:00Z", "", ("CWE-89",), ("PyPI",), None, "a")
    long = sourcing.Advisory(
        "GHSA-b", "long", "## Impact\nMuch longer structured prose describing the mechanism in detail." * 3,
        "2025-06-01T00:00:00Z", "", ("CWE-89",), ("PyPI",), None, "b",
    )
    candidates = sourcing.scope([short, long], crosswalk, as_of=date(2025, 12, 1))
    ranked = sourcing.rank(candidates)
    assert ranked[0].advisory.id == "GHSA-b"


def test_rank_is_deterministic_tie_break_by_id():
    a = sourcing.ScopedCandidate(
        sourcing.Advisory("GHSA-b", "s", "d", "2025-06-01T00:00:00Z", "", (), (), None, "b"), "x", ()
    )
    b = sourcing.ScopedCandidate(
        sourcing.Advisory("GHSA-a", "s", "d", "2025-06-01T00:00:00Z", "", (), (), None, "a"), "x", ()
    )
    assert [c.advisory.id for c in sourcing.rank([a, b])] == ["GHSA-a", "GHSA-b"]


# ---------------------------------------------------------------------------
# cluster_by_shape()
# ---------------------------------------------------------------------------


def test_cluster_groups_similar_shapes_and_separates_distinct_ones(synthetic_repo):
    crosswalk = sourcing.load_crosswalk(REAL_CROSSWALK_PATH)
    advisories = list(sourcing.iter_advisories(synthetic_repo))
    candidates = sourcing.scope(advisories, crosswalk, as_of=date(2025, 12, 1))
    clusters = sourcing.cluster_by_shape(candidates)

    sqli_clusters = [c for c in clusters if c.class_id == "sqli_orm"]
    # 0001 and 0002 describe the same identifier-injection shape in near-identical
    # prose -> one cluster with 0002 as an alternate.
    assert len(sqli_clusters) == 1
    ids_in_cluster = {sqli_clusters[0].representative.advisory.id} | {
        a.advisory.id for a in sqli_clusters[0].alternates
    }
    assert ids_in_cluster == {"GHSA-test-0001", "GHSA-test-0002"}


def test_cluster_max_alternates_respected():
    crosswalk = sourcing.load_crosswalk(REAL_CROSSWALK_PATH)
    same_shape_text = "Identical shape shared identifier injection column name query builder shared shape " * 5
    advisories = [
        sourcing.Advisory(f"GHSA-dup-{i:04d}", "dup", same_shape_text, "2025-06-01T00:00:00Z", "", ("CWE-89",), ("PyPI",), None, "x")
        for i in range(5)
    ]
    candidates = sourcing.scope(advisories, crosswalk, as_of=date(2025, 12, 1))
    [cluster] = sourcing.cluster_by_shape(candidates, max_alternates=2)
    assert len(cluster.alternates) == 2


def test_cluster_is_order_independent(synthetic_repo):
    crosswalk = sourcing.load_crosswalk(REAL_CROSSWALK_PATH)
    advisories = list(sourcing.iter_advisories(synthetic_repo))
    candidates = sourcing.scope(advisories, crosswalk, as_of=date(2025, 12, 1))
    forward = sourcing.cluster_by_shape(candidates)
    backward = sourcing.cluster_by_shape(list(reversed(candidates)))

    def shape(clusters):
        return sorted(
            (c.class_id, c.representative.advisory.id, tuple(sorted(a.advisory.id for a in c.alternates)))
            for c in clusters
        )

    assert shape(forward) == shape(backward)


# ---------------------------------------------------------------------------
# clusters_to_candidate_list() -- never a card, never provenance
# ---------------------------------------------------------------------------


def test_candidate_list_shape_and_no_card_authoring_fields(synthetic_repo):
    crosswalk = sourcing.load_crosswalk(REAL_CROSSWALK_PATH)
    advisories = list(sourcing.iter_advisories(synthetic_repo))
    candidates = sourcing.scope(advisories, crosswalk, as_of=date(2025, 12, 1))
    clusters = sourcing.cluster_by_shape(candidates)
    candidate_list = sourcing.clusters_to_candidate_list(clusters)

    assert "classes" in candidate_list
    for class_id, entries in candidate_list["classes"].items():
        for entry in entries:
            assert set(entry) == {"representative", "alternates"}
            for c in [entry["representative"], *entry["alternates"]]:
                # A candidate is raw advisory data, not a pattern card: it
                # must never carry root_cause/confidence/triage_hint, the
                # human-authored fields that belong only to a real card.
                assert "root_cause" not in c
                assert "confidence" not in c
                assert "triage_hint" not in c


# ---------------------------------------------------------------------------
# quarter_label()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "d,expected",
    [
        (date(2026, 1, 15), "2026-Q1"),
        (date(2026, 4, 1), "2026-Q2"),
        (date(2026, 9, 21), "2026-Q3"),
        (date(2026, 12, 31), "2026-Q4"),
    ],
)
def test_quarter_label(d, expected):
    assert sourcing.quarter_label(d) == expected


# ---------------------------------------------------------------------------
# Git sync layer (fake runner; no network)
# ---------------------------------------------------------------------------


def test_probe_reachable_true_and_false():
    ok_runner = FakeRunner({"ls-remote": _ok()})
    bad_runner = FakeRunner({"ls-remote": _fail()})
    assert sourcing.probe_reachable(runner=ok_runner) is True
    assert sourcing.probe_reachable(runner=bad_runner) is False


def test_probe_reachable_handles_runner_exception():
    def raising_runner(argv):
        raise OSError("no network")

    assert sourcing.probe_reachable(runner=raising_runner) is False


def test_sync_clones_when_no_existing_checkout(tmp_path):
    cache_dir = tmp_path / "cache"
    runner = FakeRunner({"clone": _ok(), "rev-parse": _ok("deadbeef\n")})
    sha = sourcing.sync_advisory_database(cache_dir, runner=runner)
    assert sha == "deadbeef"
    assert runner.calls[0][1] == "clone"


def test_sync_pulls_when_checkout_already_exists(tmp_path):
    cache_dir = tmp_path / "cache"
    (cache_dir / ".git").mkdir(parents=True)
    runner = FakeRunner({"pull": _ok(), "rev-parse": _ok("cafef00d\n")})
    sha = sourcing.sync_advisory_database(cache_dir, runner=runner)
    assert sha == "cafef00d"
    assert "pull" in runner.calls[0]


def test_sync_raises_on_git_failure(tmp_path):
    runner = FakeRunner({"clone": _fail("network unreachable")})
    with pytest.raises(sourcing.SourcingError):
        sourcing.sync_advisory_database(tmp_path / "cache", runner=runner)


def test_sync_raises_on_rev_parse_failure(tmp_path):
    runner = FakeRunner({"clone": _ok(), "rev-parse": _fail()})
    with pytest.raises(sourcing.SourcingError):
        sourcing.sync_advisory_database(tmp_path / "cache", runner=runner)


# ---------------------------------------------------------------------------
# run_refresh() end-to-end (offline, sync=False) + REFRESH_LOG idempotency
# ---------------------------------------------------------------------------


def test_run_refresh_end_to_end_offline(synthetic_repo, tmp_path):
    output_dir = tmp_path / "refresh-out"
    refresh_log = tmp_path / "REFRESH_LOG.md"
    result = sourcing.run_refresh(
        cache_dir=synthetic_repo,
        crosswalk_path=REAL_CROSSWALK_PATH,
        output_dir=output_dir,
        refresh_log_path=refresh_log,
        as_of=date(2025, 12, 1),
        sync=False,
    )
    assert result["sha"] == "unknown"  # no .git in the synthetic fixture
    assert Path(result["candidates_path"]).exists()
    assert Path(result["report_path"]).exists()
    assert result["refresh_log_appended"] is True
    assert refresh_log.exists()
    report_text = Path(result["report_path"]).read_text()
    assert "Mechanical output only" in report_text


def test_run_refresh_never_writes_to_cards_or_provenance(synthetic_repo, tmp_path):
    output_dir = tmp_path / "refresh-out"
    cards_dir = Path("lab/patterns/cards")
    provenance_path = Path("lab/patterns/provenance.yaml")
    before_cards = sorted(cards_dir.glob("*.yaml"))
    before_provenance = provenance_path.read_text()

    sourcing.run_refresh(
        cache_dir=synthetic_repo,
        crosswalk_path=REAL_CROSSWALK_PATH,
        output_dir=output_dir,
        refresh_log_path=tmp_path / "REFRESH_LOG.md",
        as_of=date(2025, 12, 1),
        sync=False,
    )

    assert sorted(cards_dir.glob("*.yaml")) == before_cards
    assert provenance_path.read_text() == before_provenance


def test_run_refresh_is_idempotent_for_an_unchanged_sha(synthetic_repo, tmp_path):
    output_dir = tmp_path / "refresh-out"
    refresh_log = tmp_path / "REFRESH_LOG.md"
    kwargs = dict(
        cache_dir=synthetic_repo,
        crosswalk_path=REAL_CROSSWALK_PATH,
        output_dir=output_dir,
        refresh_log_path=refresh_log,
        as_of=date(2025, 12, 1),
        sync=False,
    )
    first = sourcing.run_refresh(**kwargs)
    first_candidates = Path(first["candidates_path"]).read_text()
    first_log = refresh_log.read_text()

    second = sourcing.run_refresh(**kwargs)
    assert second["refresh_log_appended"] is False
    assert Path(second["candidates_path"]).read_text() == first_candidates  # overwritten, identical
    assert refresh_log.read_text() == first_log  # no duplicate line appended


def test_run_refresh_appends_a_new_line_for_a_different_sha(synthetic_repo, tmp_path):
    refresh_log = tmp_path / "REFRESH_LOG.md"
    (synthetic_repo / ".git").mkdir()
    runner_v1 = FakeRunner({"rev-parse": _ok("sha-one\n")})
    sourcing.run_refresh(
        cache_dir=synthetic_repo,
        crosswalk_path=REAL_CROSSWALK_PATH,
        output_dir=tmp_path / "out",
        refresh_log_path=refresh_log,
        as_of=date(2025, 12, 1),
        sync=False,
        runner=runner_v1,
    )
    runner_v2 = FakeRunner({"rev-parse": _ok("sha-two\n")})
    result2 = sourcing.run_refresh(
        cache_dir=synthetic_repo,
        crosswalk_path=REAL_CROSSWALK_PATH,
        output_dir=tmp_path / "out",
        refresh_log_path=refresh_log,
        as_of=date(2025, 12, 1),
        sync=False,
        runner=runner_v2,
    )
    assert result2["refresh_log_appended"] is True
    text = refresh_log.read_text()
    assert "sha-one" in text and "sha-two" in text


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_refresh_smoke(monkeypatch, synthetic_repo, tmp_path, capsys):
    output_dir = tmp_path / "out"
    refresh_log = tmp_path / "REFRESH_LOG.md"
    rc = sourcing.main(
        [
            "refresh",
            "--cache-dir", str(synthetic_repo),
            "--crosswalk", REAL_CROSSWALK_PATH,
            "--output-dir", str(output_dir),
            "--refresh-log", str(refresh_log),
            "--no-sync",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["sha"] == "unknown"
    assert Path(out["candidates_path"]).exists()


def test_cli_probe_reflects_reachability(monkeypatch, capsys):
    monkeypatch.setattr(sourcing, "probe_reachable", lambda remote: True)
    assert sourcing.main(["probe"]) == 0
    assert "reachable" in capsys.readouterr().out

    monkeypatch.setattr(sourcing, "probe_reachable", lambda remote: False)
    assert sourcing.main(["probe"]) == 1


# ---------------------------------------------------------------------------
# Live reachability probe (real network, cheap, auto-skipped if unreachable)
# ---------------------------------------------------------------------------

_LIVE_REACHABLE = sourcing.probe_reachable()


@pytest.mark.skipif(not _LIVE_REACHABLE, reason="github/advisory-database not reachable from this environment")
def test_probe_reachable_live():
    """A real `git ls-remote` against the actual remote -- no clone, just a
    reachability check. This is the only test in this file that touches the
    network; a real `sync_advisory_database()` clone (~3.3 GB per the
    sourcing plan) is intentionally never exercised by the test suite."""
    assert sourcing.probe_reachable() is True
