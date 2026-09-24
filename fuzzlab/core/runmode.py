"""Run-mode category selection and the no-ground-truth fail-safe (D14 / D15).

Decides which injection categories a run tests, and whether it is scored, from the
launcher run mode and whether the target has ground truth:

- **automatic + ground truth** (our lab): categories auto-derived from the ground
  truth; scored (a detection benchmark). (D14)
- **automatic + no ground truth** (validation lab / unknown target): requires an
  explicit selection, else **fails loudly**; unscored. (D15 fail-safe)
- **manual**: the user selects; unselected defaults to all known categories;
  unscored. (D14)

Pure and dependency-light: callers pass the ground-truth categories and the set of
known categories in (the harness/audit layer provides them), so this never inverts
the layering.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

AUTOMATIC = "automatic"
MANUAL = "manual"

# Ground-truth vuln_class values normalized to reference-style category slugs.
# A class is added here once it has a real, independently-verified working
# rule+strategy pairing -- mapping one before that would only relabel an
# honest false negative as a false negative that looks wired but never
# confirms (evaluate() would nominate a candidate with no strategy to confirm
# it, `category_to_oracle_class()` returning None), not a real improvement.
# `ssti` (CC-CORE-0020): `R-SSTI`/`SstiStrategy`, verified live against both
# of TrackerNest's real twins. `access_control` (CC-FUZZ-0033): its
# vuln_class ("access_control", underscore -- ground truth's own convention)
# and its category ("access-control", hyphen -- this project's reference-slug
# convention, matching every other multi-word category here) genuinely
# differ, unlike e.g. `ssrf` (identical either way, so it needs no entry);
# `R-ACCESS-CONTROL`/`AccessControlIdorStrategy`, verified live against
# Twitch's real IDOR twins (`test_real_boot_proves_the_access_control_idor_
# strategy_end_to_end`). `insecure_deserialization` (CC-FUZZ-0034): same
# underscore/hyphen mismatch, `R-INSECURE-DESERIALIZATION`/
# `InsecureDeserializationTypeConfusionStrategy`, verified live against
# Netflix's real Jackson-deserialization twins. `xxe` (CC-FUZZ-0035) and
# `jwt_algorithm_confusion` (CC-FUZZ-0037) followed the same pattern.
# `tests/test_oracle.py::test_every_ruled_strategy_category_is_reachable_
# from_its_vuln_class` now guards the whole dict pairing generically (for
# every *ruled* category) so a missed entry fails loudly at test time
# instead of silently shipping an unreachable strategy.
# `webhook_signature` (and `outbound_header_injection`) still have no
# confirmer built -- stay unmapped until each does. `unrestricted_file_
# upload` (CC-LAB-0186's deferred follow-on) is the seventh instance of this
# same underscore/hyphen mismatch found in this session -- checked
# proactively before landing, not found by the guard test after the fact
# this time: `R-UNRESTRICTED-FILE-UPLOAD`/`UnrestrictedFileUploadContent
# TypeTrustStrategy`, verified live against Twitch's real
# LABGEN-GO-0017/0018 twins.
_VULN_TO_CATEGORY = {
    "sqli": "sql-injection",
    "xss-reflected": "xss",
    "xss-stored": "xss",
    "xss-dom": "xss",
    "ssti": "server-side-template-injection",
    "access_control": "access-control",
    "insecure_deserialization": "insecure-deserialization",
    "jwt_algorithm_confusion": "jwt-algorithm-confusion",
    "weak_token_entropy": "weak-token-entropy",
    "mass_assignment": "mass-assignment",
    "unrestricted_file_upload": "unrestricted-file-upload",
    # `open_redirect` (category 5, Booking.com, `CC-LAB-0210`): a real rule
    # (`R-OPEN-REDIRECT`, `name_regex` matching "return_to" via its "return"
    # alternative) and confirmation strategy (`OpenRedirectStrategy` in
    # fuzzlab/oracle/strategies.py) already existed and were already
    # correctly scoped for this cell -- purely a missing mapping, not a
    # missing detector. Verified live against both of Booking.com's real
    # twins before landing (see this change's own change-control entry);
    # doing so surfaced and fixed a real, separate defect in
    # `RequestsProbeSender` (`BUG-0039`) that would otherwise have made this
    # mapping look wired but silently fail (or crash) against a real target.
    # Independently rediscovered (`BUG-0045`/`PA-0047`) as the first
    # instance the guard test (`test_every_ruled_strategy_category_is_
    # reachable_from_its_vuln_class`, `CC-FUZZ-0034`) failed to catch --
    # that guard iterates `fuzzlab.oracle.strategies._CATEGORY_TO_CLASS`'s
    # own keys, where `_CATEGORY_TO_CLASS["open-redirect"] ==
    # "open-redirect"` (identical, since `OpenRedirectStrategy.vuln_class`
    # happens to already be hyphenated) trivially skipped its own
    # `vuln_class == category` early-continue, never checking against what
    # ground-truth `labels.json` files actually spell the class as
    # (`"open_redirect"`, underscored, this project's labels-schema
    # convention). `R-OPEN-REDIRECT`/`OpenRedirectStrategy` (verified live
    # for category 5's Booking.com pilot and this stack's own Twitch page,
    # `CC-LAB-0199`) were both genuinely reachable all along -- only this
    # mapping entry was missing.
    "open_redirect": "open-redirect",
    # `spel_injection` (category 5, Expedia, `CC-LAB-0214`): a new rule
    # (`R-SPEL-INJECTION`) and confirmation strategy (`SpelInjectionStrategy`
    # in fuzzlab/oracle/strategies.py) built specifically for this class --
    # unlike `ssti`/`open_redirect` above, no existing rule+strategy pair
    # applied here (SstiStrategy's own bare-arithmetic-product canary would
    # be a guaranteed false positive against this shape's real secure twin,
    # a `SimpleEvaluationContext` that restricts type/method access but not
    # literal arithmetic -- caught by this component's own pre-change review
    # gate before implementation). `SpelInjectionStrategy` uses a
    # `T(java.lang.Math).abs(-n)` type-reference canary instead, the exact
    # differential this project already proved live. Verified live against
    # both of Expedia's real twins before landing.
    "spel_injection": "spel-injection",
    # `price_integrity_bypass` (category 5, Booking.com, `CC-LAB-0212`): a
    # new rule (`R-PRICE-INTEGRITY`) and confirmation strategy
    # (`PriceIntegrityBypassStrategy` in fuzzlab/oracle/strategies.py) built
    # specifically for this class -- the vulnerable twin (`LABGEN-BC-0005`)
    # has an empty transform pipeline (no named op to detect); the real
    # differential is the secure twin's own server-side rate-table
    # recomputation, which the vulnerable twin never performs, proven live
    # in `tests/test_labgen_price_integrity.py`'s own live-boot test before
    # this mapping landed. Verified live against both of Booking.com's real
    # twins before landing. (Category 4's own Netflix/Twitch instances of
    # this same class, `CC-LAB-0188`/`CC-LAB-0189`, reuse this identical
    # mapping entry -- see `PriceTrustDifferentialStrategy` in
    # `fuzzlab/oracle/strategies.py` for their own, differently-shaped
    # confirmation strategy.)
    "price_integrity_bypass": "price-integrity-bypass",
    # `csv_formula_injection` (category 5, Booking.com, `CC-LAB-0211`): a new
    # rule (`R-CSV-FORMULA-INJECTION`) and confirmation strategy
    # (`CsvFormulaInjectionStrategy` in fuzzlab/oracle/strategies.py) built
    # specifically for this class -- tries all four OWASP trigger characters
    # (=, +, -, @), not just one, per this component's own pre-change
    # adequacy review (a single-character canary risked a false negative
    # against a neutralizer that only escapes a subset). Verified live
    # against both of Booking.com's real twins before landing.
    "csv_formula_injection": "csv-formula-injection",
    # `http_header_injection` (CC-FUZZ-0045): the same underscore/hyphen
    # mismatch class again, added proactively alongside `HttpHeaderInjection
    # CrlfStrategy`/`R-HEADER-INJECTION` rather than being found empirically
    # after the fact -- checked both this dict and `_CATEGORY_TO_CLASS`
    # (`fuzzlab/oracle/strategies.py`) before assuming either already had
    # an entry, per this change's own task instructions.
    "http_header_injection": "http-header-injection",
    # `path_traversal` (CC-FUZZ-0046): the same underscore/hyphen mismatch
    # class again (`PathTraversalFsPathReadStrategy.vuln_class ==
    # "path_traversal"`, category `"path-traversal"`), added proactively
    # alongside `R-PATH-TRAVERSAL` rather than found empirically after the
    # fact -- checked both this dict and `_CATEGORY_TO_CLASS`
    # (`fuzzlab/oracle/strategies.py`) before assuming either already had
    # an entry, per `BUG-0045`'s own lesson.
    "path_traversal": "path-traversal",
}


class RunModeError(RuntimeError):
    """Fail-loud: an invalid or unsafe run-mode/category selection."""


@dataclass
class RunPlan:
    mode: str
    categories: list[str]
    scored: bool
    source: str            # 'ground-truth' | 'user' | 'default'


def to_category(vuln_class: str) -> str:
    return _VULN_TO_CATEGORY.get(vuln_class, vuln_class)


def categories_from_vuln_classes(vuln_classes: Iterable[str]) -> list[str]:
    """Normalize ground-truth vuln classes to a sorted category set (excl. 'none')."""
    return sorted({to_category(v) for v in vuln_classes if v and v != "none"})


def resolve_run(mode: str, *, ground_truth_categories: list[str] | None = None,
                selected_categories: Iterable[str] | None = None,
                all_categories: Iterable[str] | None = None) -> RunPlan:
    """Resolve the active categories + scoring for a run, enforcing D14/D15."""
    selected = list(selected_categories) if selected_categories else []
    known = set(all_categories) if all_categories is not None else None
    if known is not None and selected:
        unknown = [c for c in selected if c not in known]
        if unknown:
            raise RunModeError(f"unknown categor(y/ies): {unknown}; known: {sorted(known)}")

    if mode == AUTOMATIC:
        if ground_truth_categories is not None:
            # D14: auto-derive from the lab's ground truth; scored benchmark.
            return RunPlan(AUTOMATIC, list(ground_truth_categories), True, "ground-truth")
        # D15 fail-safe: no ground truth -> must be explicit, else fail loud; unscored.
        if not selected:
            raise RunModeError(
                "automatic run against a target with no ground truth requires an "
                "explicit category selection (fail-safe); pass --categories")
        return RunPlan(AUTOMATIC, selected, False, "user")

    if mode == MANUAL:
        if selected:
            return RunPlan(MANUAL, selected, False, "user")
        return RunPlan(MANUAL, sorted(known) if known else [], False, "default")

    raise RunModeError(f"unknown run mode {mode!r}")
