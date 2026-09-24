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


def test_categories_from_vuln_classes_maps_ssti():
    # CC-CORE-0020: ssti has a real, verified working rule+strategy pairing
    # (R-SSTI/SstiStrategy) -- unlike category 3's other 5 new classes,
    # which stay unmapped (see _VULN_TO_CATEGORY's own comment).
    cats = categories_from_vuln_classes(["ssti"])
    assert cats == ["server-side-template-injection"]


def test_categories_from_vuln_classes_maps_open_redirect():
    # CC-CORE-0021: open_redirect has a real, verified working rule+strategy
    # pairing (R-OPEN-REDIRECT/OpenRedirectStrategy) -- unlike category 5's
    # other 3 built classes, which stay unmapped (see _VULN_TO_CATEGORY's
    # own comment). Live-verifying this mapping found and fixed two real,
    # distinct defects (BUG-0039/BUG-0040) before it was considered done.
    cats = categories_from_vuln_classes(["open_redirect"])
    assert cats == ["open-redirect"]


def test_categories_from_vuln_classes_maps_spel_injection():
    # CC-FUZZ-0028: spel_injection needed a genuinely NEW rule+strategy pair
    # (R-SPEL-INJECTION/SpelInjectionStrategy) -- unlike ssti/open_redirect,
    # no existing confirmer applied (a bare-arithmetic canary would have
    # been a guaranteed false positive against this shape's real secure
    # twin, caught by the pre-change review gate). Live-verified against
    # both of Expedia's real twins: tp=1, fn=0, fp=0.
    cats = categories_from_vuln_classes(["spel_injection"])
    assert cats == ["spel-injection"]


def test_categories_from_vuln_classes_maps_price_integrity_bypass():
    # CC-FUZZ-0029: price_integrity_bypass needed a genuinely NEW rule+
    # strategy pair (R-PRICE-INTEGRITY/PriceIntegrityBypassStrategy) -- the
    # vulnerable twin (LABGEN-BC-0005) has an empty transform pipeline, so
    # the real differential is the secure twin's own server-side rate-table
    # recomputation, which the vulnerable twin never performs. Live-verified
    # against both of Booking.com's real twins.
    cats = categories_from_vuln_classes(["price_integrity_bypass"])
    assert cats == ["price-integrity-bypass"]


def test_categories_from_vuln_classes_maps_csv_formula_injection():
    # CC-FUZZ-0030: csv_formula_injection needed a genuinely NEW rule+
    # strategy pair (R-CSV-FORMULA-INJECTION/CsvFormulaInjectionStrategy) --
    # tries all four OWASP trigger characters (=, +, -, @), not just one,
    # per the pre-change adequacy review's own false-negative concern.
    # Live-verified against both of Booking.com's real twins -- this is
    # category 5's fourth and final real detection for this app.
    cats = categories_from_vuln_classes(["csv_formula_injection"])
    assert cats == ["csv-formula-injection"]


def test_categories_from_vuln_classes_maps_insecure_deserialization():
    # CC-FUZZ-0034: insecure_deserialization now has a real, verified
    # working rule+strategy pairing (R-INSECURE-DESERIALIZATION/
    # InsecureDeserializationTypeConfusionStrategy) -- superseded this
    # test's own prior "stays unmapped" assertion (see git history), same
    # as ssti's own precedent above.
    cats = categories_from_vuln_classes(["insecure_deserialization"])
    assert cats == ["insecure-deserialization"]


def test_categories_from_vuln_classes_leaves_unmapped_classes_unchanged():
    # xxe/webhook_signature/etc. still have no confirmer -- to_category()
    # falls through to the raw class name (no audit rule matches it, so it
    # never nominates a candidate, and stays an honest false negative rather
    # than a mis-wired one).
    cats = categories_from_vuln_classes(["xxe", "webhook_signature"])
    assert cats == ["webhook_signature", "xxe"]


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
