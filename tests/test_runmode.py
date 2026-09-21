"""Tests for run-mode category selection (D14) and the fail-safe (D15)."""

import pytest

from fuzzlab.audit import known_categories
from fuzzlab.core.runmode import (
    RunModeError, categories_from_vuln_classes, resolve_run,
)
from fuzzlab.labels import contract


def test_categories_from_vuln_classes_normalizes():
    cats = categories_from_vuln_classes(
        ["sqli", "xss-reflected", "xss-dom", "none", "sqli"])
    assert cats == ["sql-injection", "xss"]        # normalized, deduped, no 'none'


# --- D14: automatic against our lab auto-derives from ground truth -----------
def test_automatic_lab_auto_derives_and_is_scored():
    gt = contract.load("lab/ground-truth")
    gt_cats = categories_from_vuln_classes(c.vuln_class for c in gt.positives())
    plan = resolve_run("automatic", ground_truth_categories=gt_cats)
    assert plan.scored is True and plan.source == "ground-truth"
    assert "sql-injection" in plan.categories and "xss" in plan.categories


# --- D14: manual selects; defaults to all when unselected --------------------
def test_manual_uses_selection_then_defaults_to_all():
    known = known_categories()
    picked = resolve_run("manual", selected_categories=["sql-injection"],
                         all_categories=known)
    assert picked.categories == ["sql-injection"] and not picked.scored and picked.source == "user"
    default = resolve_run("manual", all_categories=known)
    assert default.categories == sorted(known) and default.source == "default"


# --- D15: no-ground-truth fail-safe -----------------------------------------
def test_automatic_no_ground_truth_requires_explicit_categories():
    with pytest.raises(RunModeError):
        resolve_run("automatic")                    # fail loud: no gt, no selection


def test_automatic_no_ground_truth_with_categories_runs_unscored():
    plan = resolve_run("automatic", selected_categories=["sql-injection"],
                       all_categories=known_categories())
    assert plan.categories == ["sql-injection"]
    assert plan.scored is False and plan.source == "user"


# --- validation + errors -----------------------------------------------------
def test_unknown_category_fails_loud():
    with pytest.raises(RunModeError):
        resolve_run("manual", selected_categories=["not-a-category"],
                    all_categories=known_categories())


def test_unknown_mode_fails_loud():
    with pytest.raises(RunModeError):
        resolve_run("sideways", all_categories=known_categories())
