"""Tests for `fuzzlab.labgen.corpus_analysis` (plan §2.4, lane L-P1.4).

Fixtures are the repo's own example manifests under `lab/manifests/` (per the
task brief) rather than hand-written cell literals, so the three analyses are
exercised against the corpus shapes actually authored in this project --
including `phase0_real_pages_sample.yaml`'s deliberate near-duplicate pairs
(`/product.php` vs `/blog_post.php`, the same shape on two different real
pages).

PA-0001: expectations are derived from the manifests / from
`corpus_analysis`'s own definitions wherever a literal would duplicate a
source of truth; literals are reserved for the genuinely-fixed facts of a
committed fixture manifest (e.g. that it has two distinct vuln classes).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from fuzzlab.labgen import corpus_analysis as ca
from fuzzlab.labgen.schema import Manifest, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix

MANIFEST_DIR = Path("lab/manifests")
REAL_PAGES = MANIFEST_DIR / "phase0_real_pages_sample.yaml"

#: Every committed example manifest -- used for the "holds for all fixtures"
#: sweeps below, so a newly-added manifest is covered automatically rather
#: than needing this list edited (PA-0024's whole-collection instinct).
ALL_MANIFESTS = sorted(MANIFEST_DIR.glob("*.yaml"))


@pytest.fixture(scope="module")
def real_pages() -> Manifest:
    return load_manifest(REAL_PAGES)


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


def test_every_example_manifest_is_a_fixture():
    """Guard the sweep itself: if `lab/manifests/` were ever empty or moved,
    the parametrized tests below would silently pass with zero cases."""
    assert ALL_MANIFESTS, f"no example manifests found under {MANIFEST_DIR}"


# --- signatures / generating-rule grouping ----------------------------------


def test_signature_ignores_cell_id_route_stack_and_param(real_pages):
    """The near-duplicate definition is `(vuln_class, sink_context,
    transform-shape)` regardless of cell ID -- and, for this corpus, also
    regardless of route and stack profile."""
    by_id = {c.cell_id: c for c in real_pages.cells}
    # Same shape, different real page (/product.php vs /blog_post.php).
    assert ca.duplicate_signature(by_id["LABGEN-RP-0001"]) == ca.duplicate_signature(
        by_id["LABGEN-RP-0003"]
    )
    assert ca.duplicate_signature(by_id["LABGEN-RP-0002"]) == ca.duplicate_signature(
        by_id["LABGEN-RP-0004"]
    )
    # Different transform shape -> different signature (the minimal pair).
    assert ca.duplicate_signature(by_id["LABGEN-RP-0001"]) != ca.duplicate_signature(
        by_id["LABGEN-RP-0002"]
    )
    # Different sink family -> different signature.
    assert ca.duplicate_signature(by_id["LABGEN-RP-0001"]) != ca.duplicate_signature(
        by_id["LABGEN-RP-0005"]
    )


def test_signature_is_transform_order_sensitive():
    """Order matters, because `verdict()` is order-sensitive over
    `pipeline.ops` -- two cells whose pipelines differ only in order are not
    duplicates."""
    from fuzzlab.labgen.schema import Cell

    base = {
        "class": "sqli",
        "stack_profile": "php_current",
        "route": {"method": "GET", "path": "/a.php"},
        "sink_context": {"family": "sql_string_literal", "required_neutralizations": ["sql_syntax_break"]},
    }
    forward = Cell.from_dict({**base, "cell_id": "T-0001", "transform": ["url_decode", "param_bind"]})
    reverse = Cell.from_dict({**base, "cell_id": "T-0002", "transform": ["param_bind", "url_decode"]})
    assert ca.duplicate_signature(forward) != ca.duplicate_signature(reverse)


def test_required_neutralizations_order_does_not_split_a_group():
    """`required_neutralizations` is a set of concerns, not a pipeline, so
    authoring order must not create two groups out of one."""
    from fuzzlab.labgen.schema import Cell

    base = {
        "class": "xss",
        "stack_profile": "php_current",
        "route": {"method": "GET", "path": "/a.php"},
        "transform": [],
    }
    a = Cell.from_dict(
        {
            **base,
            "cell_id": "T-0003",
            "sink_context": {"family": "html_body", "required_neutralizations": ["html_tag_break", "html_attr_break"]},
        }
    )
    b = Cell.from_dict(
        {
            **base,
            "cell_id": "T-0004",
            "sink_context": {"family": "html_body", "required_neutralizations": ["html_attr_break", "html_tag_break"]},
        }
    )
    assert ca.generating_rule_id(a) == ca.generating_rule_id(b)


def test_rule_id_is_the_signature_and_grouping_agrees(real_pages):
    """One definition, two consumers: the dedup report's grouping and the
    split's grouping key can never drift apart (PA-0003)."""
    groups = ca.group_cells_by_rule(real_pages.cells)
    assert sum(len(v) for v in groups.values()) == len(real_pages.cells)
    for rule_id, members in groups.items():
        signatures = {ca.duplicate_signature(c) for c in members}
        assert len(signatures) == 1
        assert signatures.pop().rule_id == rule_id


@pytest.mark.parametrize("manifest_path", ALL_MANIFESTS, ids=lambda p: p.name)
def test_rule_id_is_free_of_cell_ids(manifest_path):
    """A rule ID must not embed any cell ID -- otherwise "regardless of cell
    ID" would be false and every cell would be its own group."""
    manifest = load_manifest(manifest_path)
    rule_ids = {ca.generating_rule_id(c) for c in manifest.cells}
    for cell in manifest.cells:
        assert not any(cell.cell_id in rid for rid in rule_ids)


# --- (2) de-duplication report ----------------------------------------------


def test_duplication_report_on_real_pages(real_pages):
    """The real-pages manifest deliberately repeats two shapes on a second
    real page; the report must find exactly those and nothing else."""
    report = ca.duplication_report(real_pages.cells)
    assert report.n_cells == len(real_pages.cells)
    assert report.n_signatures == len(ca.group_cells_by_rule(real_pages.cells))
    assert report.n_redundant_cells == report.n_cells - report.n_signatures
    assert report.duplicate_rate == pytest.approx(report.n_redundant_cells / report.n_cells)
    assert report.max_group_size == 2
    duplicated_ids = {ids for group in report.duplicate_groups for ids in group.cell_ids}
    assert duplicated_ids == {
        "LABGEN-RP-0001",
        "LABGEN-RP-0003",
        "LABGEN-RP-0002",
        "LABGEN-RP-0004",
    }


def test_duplicate_groups_are_ordered_largest_first_and_only_real_groups(real_pages):
    report = ca.duplication_report(real_pages.cells)
    sizes = [g.size for g in report.duplicate_groups]
    assert sizes == sorted(sizes, reverse=True)
    assert all(g.size > 1 for g in report.duplicate_groups)


def test_duplication_report_identifies_an_all_duplicate_corpus(real_pages):
    """Feeding the same cell set twice must double the redundancy, not the
    signature count."""
    doubled = list(real_pages.cells) * 2
    report = ca.duplication_report(doubled)
    single = ca.duplication_report(real_pages.cells)
    assert report.n_signatures == single.n_signatures
    assert report.n_cells == 2 * single.n_cells
    assert report.duplicate_rate > single.duplicate_rate


def test_duplication_report_on_empty_corpus_is_zeroed_not_an_error():
    report = ca.duplication_report([])
    assert (report.n_cells, report.n_signatures, report.duplicate_rate) == (0, 0, 0.0)
    assert report.duplicate_groups == ()


@pytest.mark.parametrize("manifest_path", ALL_MANIFESTS, ids=lambda p: p.name)
def test_duplication_report_rate_is_bounded_for_every_manifest(manifest_path):
    manifest = load_manifest(manifest_path)
    report = ca.duplication_report(manifest.cells)
    assert 0.0 <= report.duplicate_rate < 1.0
    assert report.n_signatures >= 1


# --- (3) diversity report (artifact, not a gate) -----------------------------


def test_diversity_report_counts_cross_tab_and_marginals(real_pages, matrix):
    report = ca.diversity_report(real_pages.cells, matrix)
    assert report.n_cells == len(real_pages.cells)
    assert sum(c.count for c in report.counts) == report.n_cells
    assert sum(report.class_counts.values()) == report.n_cells
    assert sum(report.transform_counts.values()) == report.n_cells
    assert sum(report.verdict_counts.values()) == report.n_cells
    assert sum(report.stack_counts.values()) == report.n_cells
    assert sum(report.sink_family_counts.values()) == report.n_cells
    # Derived from the fixture, not hardcoded (PA-0001).
    assert report.class_counts == {
        cls: sum(1 for c in real_pages.cells if c.vuln_class == cls)
        for cls in {c.vuln_class for c in real_pages.cells}
    }
    assert report.safety_matrix_version == matrix.version
    assert report.n_underivable_verdicts == 0


def test_diversity_report_labels_the_empty_pipeline_raw(real_pages, matrix):
    report = ca.diversity_report(real_pages.cells, matrix)
    n_raw = sum(1 for c in real_pages.cells if not c.transform.ops)
    assert report.transform_counts["raw"] == n_raw


def test_diversity_report_covers_both_verdicts_for_a_minimal_pair_corpus(real_pages, matrix):
    """The fixture is built as minimal pairs, so both verdict values must
    appear -- this is the informative signal the report exists to surface."""
    report = ca.diversity_report(real_pages.cells, matrix)
    assert set(report.verdict_counts) == {"VULNERABLE", "SECURE"}


def test_diversity_report_without_a_matrix_is_still_usable(real_pages):
    report = ca.diversity_report(real_pages.cells)
    assert report.safety_matrix_version is None
    assert report.n_underivable_verdicts == report.n_cells
    assert set(report.verdict_counts) == {ca.UNDERIVABLE_VERDICT}
    # The class x transform half is unaffected.
    assert sum(report.class_counts.values()) == report.n_cells


def test_diversity_report_is_never_a_gate(real_pages, matrix):
    """A one-class, one-transform, wholly-skewed corpus -- which the χ² gate
    would reject -- must still produce a report, not an exception."""
    skewed = [c for c in real_pages.cells if c.vuln_class == "xss" and not c.transform.ops]
    assert skewed, "fixture no longer contains a raw xss cell"
    report = ca.diversity_report(skewed * 5, matrix)
    assert report.n_cells == 5 * len(skewed)
    assert "informative" in report.gating


def test_underivable_verdict_is_counted_not_raised(real_pages, matrix):
    """An `(op, sink_family)` pair the matrix does not cover makes `verdict()`
    raise by design; the artifact must record it instead of failing."""
    import dataclasses

    from fuzzlab.labgen.schema import Pipeline

    bogus = dataclasses.replace(
        real_pages.cells[0],
        cell_id="LABGEN-BOGUS-0001",
        transform=Pipeline(("no_such_op_in_the_matrix",)),
    )
    report = ca.diversity_report([*real_pages.cells, bogus], matrix)
    assert report.n_underivable_verdicts == 1
    assert report.verdict_counts[ca.UNDERIVABLE_VERDICT] == 1


# --- (1) stratified, rule-grouped split -------------------------------------

#: Only the split needs scikit-learn; the de-duplication and diversity
#: reports are pure-Python, so the skip is scoped to the split tests rather
#: than applied module-wide (a module-level `importorskip` would skip those
#: too).
requires_sklearn = pytest.mark.skipif(
    importlib.util.find_spec("sklearn") is None,
    reason="the rule-grouped stratified split requires scikit-learn",
)


@requires_sklearn
def test_split_never_puts_a_generating_rule_on_both_sides(real_pages):
    split = ca.stratified_split(real_pages.cells, n_splits=3)
    assert set(split.train_rule_ids).isdisjoint(split.holdout_rule_ids)


@requires_sklearn
def test_split_partitions_every_cell_exactly_once(real_pages):
    split = ca.stratified_split(real_pages.cells, n_splits=3)
    all_ids = set(split.train_cell_ids) | set(split.holdout_cell_ids)
    assert all_ids == {c.cell_id for c in real_pages.cells}
    assert len(split.train_cell_ids) + len(split.holdout_cell_ids) == len(real_pages.cells)
    assert set(split.train_cell_ids).isdisjoint(split.holdout_cell_ids)


@requires_sklearn
def test_split_keeps_known_near_duplicate_pairs_together(real_pages):
    """The point of the whole exercise: the deliberate /product.php vs
    /blog_post.php near-duplicates must not straddle the split."""
    split = ca.stratified_split(real_pages.cells, n_splits=3)
    holdout = set(split.holdout_cell_ids)
    for pair in (("LABGEN-RP-0001", "LABGEN-RP-0003"), ("LABGEN-RP-0002", "LABGEN-RP-0004")):
        assert (pair[0] in holdout) == (pair[1] in holdout), pair


@requires_sklearn
def test_split_is_deterministic_for_a_fixed_random_state(real_pages):
    a = ca.stratified_split(real_pages.cells, n_splits=3, random_state=7)
    b = ca.stratified_split(real_pages.cells, n_splits=3, random_state=7)
    assert a == b


@requires_sklearn
def test_every_fold_is_reachable_and_the_folds_cover_the_corpus(real_pages):
    n_splits = 3
    holdouts = [
        set(ca.stratified_split(real_pages.cells, n_splits=n_splits, fold=f).holdout_cell_ids)
        for f in range(n_splits)
    ]
    assert set().union(*holdouts) == {c.cell_id for c in real_pages.cells}
    for i in range(n_splits):
        for j in range(i + 1, n_splits):
            assert holdouts[i].isdisjoint(holdouts[j])


@requires_sklearn
def test_split_class_counts_match_the_returned_sides(real_pages):
    split = ca.stratified_split(real_pages.cells, n_splits=3)
    by_id = {c.cell_id: c for c in real_pages.cells}
    for ids, counts in (
        (split.train_cell_ids, split.train_class_counts),
        (split.holdout_cell_ids, split.holdout_class_counts),
    ):
        expected: dict[str, int] = {}
        for cell_id in ids:
            expected[by_id[cell_id].vuln_class] = expected.get(by_id[cell_id].vuln_class, 0) + 1
        assert counts == expected


@requires_sklearn
def test_split_rejects_more_folds_than_generating_rule_groups(real_pages):
    n_groups = len(ca.group_cells_by_rule(real_pages.cells))
    with pytest.raises(ca.CorpusSplitError, match="generating-rule groups"):
        ca.stratified_split(real_pages.cells, n_splits=n_groups + 1)


@requires_sklearn
def test_split_rejects_a_single_class_corpus(real_pages):
    single_class = [c for c in real_pages.cells if c.vuln_class == "sqli"]
    with pytest.raises(ca.CorpusSplitError, match="two distinct vuln_class"):
        ca.stratified_split(single_class, n_splits=2)


@requires_sklearn
@pytest.mark.parametrize("n_splits,fold", [(1, 0), (0, 0), (3, 3), (3, -1)])
def test_split_rejects_out_of_range_arguments(real_pages, n_splits, fold):
    with pytest.raises(ca.CorpusSplitError):
        ca.stratified_split(real_pages.cells, n_splits=n_splits, fold=fold)


@requires_sklearn
def test_split_reuses_the_leakage_probes_grouping_construction():
    """Plan §2.4 requires reuse of `leakage_probe`'s grouping logic, not a
    second derivation of it. Asserted structurally: the probe and the split
    call the same factory, and it yields a group-aware, stratified CV."""
    from sklearn.model_selection import StratifiedGroupKFold

    from fuzzlab.labgen.leakage_probe import grouped_cv

    cv = grouped_cv(n_splits=3, random_state=0)
    assert isinstance(cv, StratifiedGroupKFold)
    assert cv.get_n_splits() == 3
    source = Path("fuzzlab/labgen/corpus_analysis.py").read_text("utf-8")
    assert "from .leakage_probe import grouped_cv" in source
    assert "StratifiedGroupKFold(" not in source, (
        "corpus_analysis must not construct its own grouped CV -- it reuses "
        "leakage_probe.grouped_cv (plan §2.4, PA-0003)"
    )


# --- the bundled artifact ----------------------------------------------------


def test_corpus_report_bundles_both_reports(real_pages, matrix):
    report = ca.corpus_report(real_pages.cells, matrix)
    assert report.duplication == ca.duplication_report(real_pages.cells)
    assert report.diversity == ca.diversity_report(real_pages.cells, matrix)
    assert report.n_generating_rules == len(ca.group_cells_by_rule(real_pages.cells))


def test_write_corpus_report_is_deterministic_json(tmp_path, real_pages, matrix):
    report = ca.corpus_report(real_pages.cells, matrix)
    first = ca.write_corpus_report(tmp_path / "sub" / "corpus.json", report)
    payload = first.read_bytes()
    second = ca.write_corpus_report(tmp_path / "sub" / "corpus.json", ca.corpus_report(real_pages.cells, matrix))
    assert second.read_bytes() == payload, "artifact must be byte-stable (NFR-LAB-reproducible)"
    loaded = json.loads(payload)
    assert loaded["duplication"]["n_cells"] == len(real_pages.cells)
    assert loaded["diversity"]["class_transform_verdict_counts"]
    assert "never a build gate" in loaded["gating"]


@pytest.mark.parametrize("manifest_path", ALL_MANIFESTS, ids=lambda p: p.name)
def test_corpus_report_round_trips_for_every_manifest(manifest_path, matrix, tmp_path):
    manifest = load_manifest(manifest_path)
    report = ca.corpus_report(manifest.cells, matrix)
    out = ca.write_corpus_report(tmp_path / f"{manifest_path.stem}.json", report)
    loaded = json.loads(out.read_text("utf-8"))
    assert loaded["diversity"]["n_cells"] == len(manifest.cells)
    assert loaded["n_generating_rules"] >= 1


def test_cli_corpus_report_flag_writes_the_artifact_and_never_gates(tmp_path):
    """The CLI wiring: `--corpus-report` writes the artifact, is independent
    of `--check`, and cannot fail the run."""
    from fuzzlab.labgen.cli import main

    out_dir = tmp_path / "out"
    artifact = tmp_path / "reports" / "corpus.json"
    rc = main(
        [
            "--manifest",
            str(REAL_PAGES),
            "--out",
            str(out_dir),
            "--corpus-report",
            str(artifact),
        ]
    )
    assert rc == 0
    loaded = json.loads(artifact.read_text("utf-8"))
    assert loaded["duplication"]["n_cells"] == len(load_manifest(REAL_PAGES).cells)
