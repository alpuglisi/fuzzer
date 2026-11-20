"""Crawl-run scores are the detection figure; ground-truth-point scores are an oracle
diagnostic (PA-0660, CC-FUZZ-0661, FR-FUZZ-661). Presentation only: the score math is
unchanged."""
from __future__ import annotations

from types import SimpleNamespace

from fuzzlab.harness.auto_cli import score_label
from fuzzlab.harness.multitarget import TargetOutcome, format_transfer, transfer_summary


def _report(tp, fp, fn):
    return SimpleNamespace(tp=tp, fp=fp, fn=fn, tn=0,
                           precision=tp / (tp + fp) if tp + fp else 0.0,
                           recall=tp / (tp + fn) if tp + fn else 0.0,
                           as_dict=lambda: {"tp": tp, "fp": fp, "fn": fn, "tn": 0,
                                            "precision": 1.0, "recall": tp / (tp + fn)})


def test_the_score_line_names_what_it_measures():
    assert score_label("crawl").startswith("detection score (crawl run")
    gt = score_label("ground-truth")
    assert gt.startswith("oracle diagnostic") and "not a detection figure" in gt
    assert "points from other" in score_label("other")


def test_the_transfer_summary_labels_each_target_and_the_macro_line():
    crawl = TargetOutcome("a", 1, 1, report=_report(1, 0, 1), points_source="crawl")
    gt = TargetOutcome("b", 2, 2, report=_report(2, 0, 0), points_source="ground-truth")
    text = format_transfer(transfer_summary([crawl]))
    assert "[crawl run: detection]" in text and "detection (crawl runs): macro" in text
    text = format_transfer(transfer_summary([gt]))
    assert "[ground-truth points: oracle diagnostic]" in text
    assert "oracle diagnostic (ground-truth points; not a detection figure): macro" in text
    summary = transfer_summary([crawl, gt])
    assert summary["measures"] == "mixed"
    assert "mixed points sources (not a detection figure)" in format_transfer(summary)


def test_the_macro_math_is_unchanged_by_the_labels():
    a = TargetOutcome("a", 1, 1, report=_report(1, 0, 1), points_source="crawl")
    b = TargetOutcome("b", 2, 2, report=_report(2, 0, 0), points_source="ground-truth")
    s = transfer_summary([a, b])
    assert s["macro_recall"] == round((0.5 + 1.0) / 2, 4)
    assert s["per_target"][0]["points_source"] == "crawl"
