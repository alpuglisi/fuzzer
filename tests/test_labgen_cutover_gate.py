"""L-P3.3c-CUT prep (`CC-LAB-0053`/`FR-LAB-51`): the parity/cutover coverage
gate, `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.6 point 3.

Every `PFF-` case in `lab/ground-truth/labels.json` must map to at least one
emitted `php_laravel` cell (derived from `LaravelEmitter.supports()` over
every `lab/manifests/*.yaml` cell, PA-0001/PA-0027) or to an entry in
`lab/ground-truth/migration-exemptions.yaml`. This module tests both the
gate mechanics (against synthetic fixtures, so a future regression here is
never masked by the real repo's current state) and the gate's actual result
against the real repo files (so this test itself is the "run it and report"
step -- it is expected to be green with today's manifests + exemption
register; a change that adds a `PFF-` case, a manifest cell, or an exemption
entry that breaks this invariant fails here, not silently).
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen import cutover_gate
from fuzzlab.labgen.cutover_gate import (
    CutoverGateError,
    assert_cutover_coverage,
    diff_cutover_coverage,
    load_exemptions,
)
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter
from fuzzlab.labels import contract

LABELS_DIR = "lab/ground-truth"


# ---------------------------------------------------------------------------
# Fixture-based mechanics (never depend on the real repo's current coverage)
# ---------------------------------------------------------------------------


def test_load_exemptions_reads_pff_case_and_reason(tmp_path) -> None:
    path = tmp_path / "migration-exemptions.yaml"
    path.write_text(
        "exemptions:\n"
        "  - pff_case: PFF-1002\n"
        "    reason: no sink at all\n"
        "  - pff_case: PFF-0007\n"
        "    reason: DOM XSS, decided out of scope\n"
    )
    exemptions = load_exemptions(path)
    assert exemptions == {"PFF-1002": "no sink at all", "PFF-0007": "DOM XSS, decided out of scope"}


def test_load_exemptions_missing_file_is_empty_not_an_error(tmp_path) -> None:
    assert load_exemptions(tmp_path / "does-not-exist.yaml") == {}


@pytest.mark.parametrize(
    "content",
    [
        "not_exemptions: []\n",
        "exemptions: not-a-list\n",
        "exemptions:\n  - pff_case: PFF-0001\n",  # missing reason
        "exemptions:\n  - reason: x\n",  # missing pff_case
        "exemptions:\n  - pff_case: NOT-PFF-SHAPED\n    reason: x\n",
        "exemptions:\n  - pff_case: PFF-0001\n    reason: ''\n",
        "exemptions:\n  - pff_case: PFF-0001\n    reason: a\n  - pff_case: PFF-0001\n    reason: b\n",
    ],
)
def test_load_exemptions_rejects_malformed_registers(tmp_path, content: str) -> None:
    path = tmp_path / "migration-exemptions.yaml"
    path.write_text(content)
    with pytest.raises(CutoverGateError):
        load_exemptions(path)


def _write_labels(tmp_path, cases: list[dict]) -> None:
    import json

    (tmp_path / "labels.json").write_text(
        json.dumps({"version": 1, "target": "synthetic", "cases": cases})
    )


_CASE_A = {
    # Must be PFF-0001, not a synthetic id: coverage is keyed by whatever
    # case id product.php's real page profile names via `ground_truth_case`
    # (PFF-0001), which this test relies on to exercise the real derivation.
    "case_id": "PFF-0001",
    "url": "/product.php",
    "method": "GET",
    "param": "id",
    "location": "query",
    "vuln_class": "sqli",
    "sink_context": "sql",
    "expected_vulnerable": True,
    "rendering": "server",
}
_CASE_B = {
    "case_id": "PFF-9002",
    "url": "/nowhere.php",
    "method": "GET",
    "param": "x",
    "location": "query",
    "vuln_class": "none",
    "sink_context": "none",
    "expected_vulnerable": False,
    "rendering": "server",
}


def test_diff_cutover_coverage_classifies_covered_exempted_and_uncovered(tmp_path) -> None:
    _write_labels(tmp_path, [_CASE_A, _CASE_B])
    exemptions_path = tmp_path / "migration-exemptions.yaml"
    exemptions_path.write_text("exemptions:\n  - pff_case: PFF-9002\n    reason: not reproduced\n")

    # PFF-0001 is covered because product.php's real page profile names it
    # via `ground_truth_case`/`canonical_cell_id` -- the real
    # phase3_php_laravel_real_pages_numeric.yaml manifest supplies the
    # covering cell, so this exercises the real derivation end to end while
    # only the labels/exemptions inputs are synthetic.
    diff = diff_cutover_coverage(
        labels_dir=str(tmp_path),
        manifest_paths=["lab/manifests/phase3_php_laravel_real_pages_numeric.yaml"],
        exemptions_path=exemptions_path,
    )
    assert diff.covered_case_ids == ("PFF-0001",)
    assert diff.exempted_case_ids == ("PFF-9002",)
    assert diff.uncovered_case_ids == ()
    assert diff.is_clean
    assert "LABGEN-RPL-PRODUCT" in diff.covering_cells["PFF-0001"]


def test_assert_cutover_coverage_raises_naming_the_uncovered_case(tmp_path) -> None:
    _write_labels(tmp_path, [_CASE_B])  # no covering cell, no exemption
    with pytest.raises(CutoverGateError, match="PFF-9002"):
        assert_cutover_coverage(
            labels_dir=str(tmp_path),
            manifest_paths=[],
            exemptions_path=tmp_path / "does-not-exist.yaml",
        )


def test_an_exempted_case_does_not_need_a_covering_cell(tmp_path) -> None:
    _write_labels(tmp_path, [_CASE_B])
    exemptions_path = tmp_path / "migration-exemptions.yaml"
    exemptions_path.write_text("exemptions:\n  - pff_case: PFF-9002\n    reason: deliberately not reproduced\n")
    diff = assert_cutover_coverage(  # must not raise
        labels_dir=str(tmp_path), manifest_paths=[], exemptions_path=exemptions_path
    )
    assert diff.exempted_case_ids == ("PFF-9002",)


def test_coverage_is_derived_from_supports_never_a_hand_maintained_literal() -> None:
    """PA-0001/PA-0027: an emitter that supports nothing covers nothing, even
    though the manifest cells and page profiles are unchanged -- proving the
    gate actually calls `supports()` rather than reading a case-id list off
    the page profiles directly."""

    class _NothingSupported(LaravelEmitter):
        def supports(self, vuln_class: str, sink_context) -> bool:  # noqa: ARG002
            return False

    coverage = cutover_gate.compute_php_laravel_coverage(
        ["lab/manifests/phase3_php_laravel_real_pages_numeric.yaml"],
        emitter=_NothingSupported(),
    )
    assert coverage == {}


# ---------------------------------------------------------------------------
# The real gate, against the real repo files (the "run it and report" step)
# ---------------------------------------------------------------------------


def test_every_real_pff_case_is_covered_or_exempted() -> None:
    """The actual gate result reported for L-P3.3c-CUT prep. Must not raise:
    every one of `labels.json`'s 16 cases is either reproduced by a real
    `php_laravel` cell or named in `migration-exemptions.yaml`."""
    assert_cutover_coverage()  # must not raise


def test_the_exemption_register_names_exactly_the_expected_cases() -> None:
    """Pins today's exemption register contents so a change to it (adding,
    removing, or renaming an exemption) is a visible, reviewed diff here --
    not a silent change to what the gate accepts."""
    exemptions = load_exemptions()
    # PFF-0003 (CC-LAB-0058/FR-LAB-55): search.php's real, simultaneously-true
    # reflected-XSS case, genuinely downgraded from covered to exempted once
    # PFF-0002 (the LIKE-clause SQLi at the same real URL) was made canonical
    # -- see lab/ground-truth/migration-exemptions.yaml's own entry.
    # PFF-0007/PFF-0008 (reviews.php/feedback.php's DOM XSS) were removed from
    # the register once L-P3.3c-DOM built real php_laravel coverage for them
    # (CC-LAB-0066) -- see lab/ground-truth/migration-exemptions.yaml's own
    # note.
    assert set(exemptions) == {"PFF-1002", "PFF-0003"}
    for case_id, reason in exemptions.items():
        assert reason.strip(), case_id


def test_covered_and_exempted_partition_every_labels_json_case() -> None:
    """Every case is covered XOR exempted -- no case is both (an exemption
    for a case that already has a covering cell is a stale/incorrect entry)
    and none is neither (that is exactly what `assert_cutover_coverage`
    gates on, asserted again here for the diagnostic split)."""
    all_case_ids = {c.case_id for c in contract.load_labels(LABELS_DIR)}
    diff = diff_cutover_coverage()
    assert set(diff.covered_case_ids) | set(diff.exempted_case_ids) == all_case_ids
    assert not (set(diff.covered_case_ids) & set(diff.exempted_case_ids))
    assert diff.uncovered_case_ids == ()
