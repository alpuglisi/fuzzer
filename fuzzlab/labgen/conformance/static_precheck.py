"""Static-precheck flag mechanism (T-LAB0.7).

Per ``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.7 and ``CR-LAB-0001`` Addendum C
point 4: each ``(vuln_class, sink_context.family)`` shape the safety matrix
covers also carries a ``static_precheck: informative | uninformative`` flag.
A taint analyzer (Psalm+``psalm/plugin-laravel`` for PHP, Semgrep for
Python/Node) is used only as a bespoke *shape*-conformance rule ("does the
module contain the intended sink/transform"), never as a vulnerability
detector -- it is structurally blind to the identifier/alias/connector-
position injection shapes this program actually cares about, so a clean
scan for those shapes is not evidence of anything and must be **skipped**,
never trusted as confirmation.

This module builds only the flag mechanism and the skip rule -- not a real
Psalm/Semgrep integration (out of scope for this task; the plan treats the
checker as a later, pluggable concern). ``STATIC_PRECHECK_BY_SHAPE`` is this
task's own registry, kept here rather than in ``lab/safety_matrix.yaml``:
that file and its schema are owned by a concurrently-developed sibling
lane, and ``CR-LAB-0001``'s ``static_precheck`` field is a documented
*forward* addition to that schema that has not landed there yet. Once it
does, this registry's lookup can be swapped for a real matrix-entry read
without changing :func:`run_static_precheck`'s contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class StaticPrecheckStatus(str, Enum):
    INFORMATIVE = "informative"
    UNINFORMATIVE = "uninformative"


#: (vuln_class, sink_context_family) -> whether a taint-style static
#: checker's result means anything for this shape.
#:
#: Per Addendum C point 4: identifier/alias/connector-position SQL
#: injection looks identical to safe code to a taint engine, so every SQL
#: shape this Phase-0 sample renders is UNINFORMATIVE. An HTML-escaping
#: omission (``html_body``) is the one shape here a taint/lint-style
#: checker could plausibly flag for real (missing ``htmlspecialchars()``
#: around an echoed value is a textbook static-analysis finding), so it is
#: marked INFORMATIVE -- this exercises :func:`run_static_precheck`'s
#: "run for real" branch in tests, not only its skip branch, even though no
#: real Psalm/Semgrep checker is wired in yet (see the module docstring).
STATIC_PRECHECK_BY_SHAPE: dict[tuple[str, str], StaticPrecheckStatus] = {
    ("sqli", "sql_numeric_literal"): StaticPrecheckStatus.UNINFORMATIVE,
    ("sqli", "sql_string_literal"): StaticPrecheckStatus.UNINFORMATIVE,
    ("xss", "html_body"): StaticPrecheckStatus.INFORMATIVE,
    # --- L-P1.2b harder shapes (docs/LAB_IMPLEMENTATION_PLAN.md §2.2) ------
    # Identifier/alias/connector-position SQLi: UNINFORMATIVE for the same
    # (now empirically confirmed) reason as every other SQL shape here -- and
    # more sharply. A real sqlmap 1.8.4 spot-check could not detect the
    # allowlist-respecting identifier-swap case at all (see
    # fuzzlab/labgen/identifier_sqli_oracle.py's docstring, finding #3); a
    # taint engine has strictly less to go on than that, since the code
    # contains a visible input filter and no unescaped-string-concatenation
    # tell it keys on.
    ("sqli", "sql_identifier"): StaticPrecheckStatus.UNINFORMATIVE,
    ("sqli", "sql_join_alias"): StaticPrecheckStatus.UNINFORMATIVE,
    # Escaping-context-mismatch XSS: UNINFORMATIVE, and this is the
    # interesting case -- ("xss", "html_body") above is INFORMATIVE precisely
    # because a *missing* htmlspecialchars() is a textbook static finding. In
    # these two shapes the escaping is *present* and correct-looking; what is
    # wrong is the context it was chosen for. A taint engine that treats
    # htmlspecialchars() as a sanitizer (they all do) reports clean, so its
    # clean scan is evidence of nothing here and must be skipped, never
    # recorded as confirmation.
    ("xss", "url_javascript_scheme"): StaticPrecheckStatus.UNINFORMATIVE,
    ("xss", "html_attribute_unquoted"): StaticPrecheckStatus.UNINFORMATIVE,
    # --- L-P3.3c-G6: search.php's quoted-attribute reflection -------------
    # INFORMATIVE, unlike its unquoted sibling above, and for the same reason
    # the safety matrix scores the two families' `html_entity_escape` rows
    # differently: at a *quoted* attribute the vulnerable cell simply has no
    # escaping at all, which is the textbook missing-`htmlspecialchars()`
    # finding a taint engine is expected to report -- exactly `(xss,
    # html_body)`'s situation. The unquoted family is uninformative because
    # there the escaping is *present* and only the context is wrong.
    ("xss", "html_attribute_quoted"): StaticPrecheckStatus.INFORMATIVE,
    # --- CC-LAB-0064: mass-assignment (orm_entity_bulk_assign) ------------
    # UNINFORMATIVE, same underlying reason as every SQL shape above: a
    # dynamic UPDATE built from a runtime-computed field list looks
    # syntactically unremarkable to a static tool with no business-logic
    # awareness of which fields *should* be assignable -- there is no
    # missing-sanitizer-shaped tell to key on (unlike the plain
    # ("xss", "html_body") case, where an absent htmlspecialchars() is a
    # textbook finding).
    ("mass_assignment", "orm_entity_bulk_assign"): StaticPrecheckStatus.UNINFORMATIVE,
    # --- CC-LAB-0072/0074 (ruby_rails Phase B): webhook-signature and
    # insecure-deserialization, the two genuinely new (vuln_class,
    # sink_family) shapes this lane adds. Both UNINFORMATIVE for the same
    # underlying reason as the mass-assignment row directly above: a static
    # PHP/Ruby taint tool has no business-logic awareness of "is this the
    # provider's own shared secret" (webhook-signature) or "which loader
    # call the surrounding code chose" as a security-relevant fact distinct
    # from an ordinary method call (insecure-deserialization) -- there is no
    # missing-sanitizer-shaped tell to key on, unlike the plain
    # ("xss", "html_body") case.
    ("webhook_signature", "webhook_signature_verification"): StaticPrecheckStatus.UNINFORMATIVE,
    ("insecure_deserialization", "object_deserialization"): StaticPrecheckStatus.UNINFORMATIVE,
    # --- L-P3.3c-DOM: DOM-based XSS (reviews.php/feedback.php) --------------
    # UNINFORMATIVE, and more sharply than every SQL shape above: a Psalm-style
    # PHP taint checker analyzes PHP data flow, and this shape's taint never
    # touches a single PHP variable -- the value is read and written entirely
    # by client-side JavaScript embedded in the response. There is no PHP
    # source, no PHP sink and no PHP-observable flow for the checker to find
    # clean *or* vulnerable; a clean PHP scan is evidence of nothing here
    # (the same reasoning as the escaping-context-mismatch rows above, one
    # step further: those shapes at least have a PHP-observable call for the
    # checker to mis-trust as a sanitizer).
    ("xss-dom", "dom_html_sink"): StaticPrecheckStatus.UNINFORMATIVE,
    # --- CC-LAB-0070: prototype pollution (object_property_bulk_set) -------
    # UNINFORMATIVE. Not by the same "PHP has no observable flow" reasoning
    # as the DOM-XSS row above -- a Node/Express static analyzer (e.g. a
    # CodeQL/eslint-plugin-security prototype-pollution query) genuinely
    # *could* flag an unguarded `for...in` + bracket-assignment recursive
    # merge, unlike this component's SQL/mass-assignment rows above, whose
    # "no informative static tell" claim rests on real spot-checks recorded
    # elsewhere in this file's own history. This row has had no such
    # spot-check run against it yet (no Node-oriented static tool has been
    # exercised against this shape in this project) -- marked UNINFORMATIVE
    # as the conservative default until one actually is, not as a claim that
    # no tool could ever find it.
    ("prototype_pollution", "object_property_bulk_set"): StaticPrecheckStatus.UNINFORMATIVE,
    # --- CC-LAB-0076: ReDoS (regex_highlight_match) -------------------------
    # UNINFORMATIVE, same conservative-default reasoning as the prototype-
    # pollution row above: a static ReDoS checker (e.g. `eslint-plugin-
    # redos`/`safe-regex`) genuinely *could* flag `new RegExp(userInput)` as
    # a pattern built from unescaped user input, but no such tool has been
    # exercised against this shape in this project yet -- marked
    # UNINFORMATIVE until one actually is, not as a claim that no tool could
    # ever find it. This shape's real confirmation mechanism is the new
    # timing-differential (M1) oracle strategy, not a static checker at all
    # (see docs/architecture/oracle-confirmation.md).
    ("redos", "regex_highlight_match"): StaticPrecheckStatus.UNINFORMATIVE,
    # --- CC-LAB-0210: open redirect (category 5, Booking.com pilot) --------
    # INFORMATIVE: a vulnerable cell's `redirect($value)` sink is fed a
    # request-parameter value with no check applied at all -- the same
    # textbook "value reaches a sensitive sink with nothing between source
    # and sink" shape as ("xss", "html_body") above, which a taint-style
    # static checker (most of which model `header()`/redirect-style sinks
    # explicitly) is reasonably expected to flag. Unlike the escaping-
    # context-mismatch XSS shapes, the secure twin's `redirect_target_
    # allowlist` transform is a real, present validation call immediately
    # before the sink, not an escaping function misapplied to the wrong
    # context -- so a clean scan of the secure twin is not evidence of
    # nothing the way it is for those shapes.
    ("open_redirect", "http_redirect_location"): StaticPrecheckStatus.INFORMATIVE,
    # --- CC-LAB-0211: CSV/report export formula injection (category 5) ----
    # UNINFORMATIVE: a PHP taint checker analyzes PHP data flow and string
    # sinks (echo/file writes/HTTP responses), not spreadsheet-application
    # semantics -- it has no notion that a value's *first character* being
    # `=`/`+`/`-`/`@`/tab/CR makes a downstream Excel/Sheets import execute
    # it as a formula. Even a checker that flags "unescaped value reaches an
    # HTTP response body" would flag this identically whether or not
    # `csv_formula_neutralize` ran, since a single-quote prefix looks like
    # ordinary string concatenation to a taint engine, not a recognized
    # sanitizer -- the same reasoning as the escaping-context-mismatch XSS
    # shapes above, one step further removed (there is no PHP-level function
    # call this shape's fix hangs off of at all, just a `preg_match`-guarded
    # string prefix a generic checker has no CSV-specific model for).
    ("csv_formula_injection", "csv_cell_value"): StaticPrecheckStatus.UNINFORMATIVE,
    # --- CC-LAB-0212: price integrity / business-logic amount trust -------
    # UNINFORMATIVE, same underlying reason as ("mass_assignment",
    # "orm_entity_bulk_assign") above: a numeric business-value field
    # (a payment amount) reaching a DB write looks syntactically
    # unremarkable to a static tool with no business-logic awareness that
    # *this specific* numeric value should never come from client input --
    # there is no missing-sanitizer-shaped tell to key on, unlike the
    # plain ("xss", "html_body") case.
    ("price_integrity_bypass", "payment_charge_amount"): StaticPrecheckStatus.UNINFORMATIVE,
    # --- CC-LAB-0214: SpEL injection (spring_boot, Expedia) ----------------
    # UNINFORMATIVE: both the vulnerable and secure twins call the
    # *identical* `SpelExpressionParser().parseExpression(tainted).
    # getValue(context)` sequence -- the only difference is which
    # `EvaluationContext` object was constructed beforehand
    # (`new StandardEvaluationContext()` vs.
    # `SimpleEvaluationContext.forReadOnlyDataBinding().build()`). A
    # generic taint/pattern checker has no differing call-shape or
    # missing-sanitizer-call to key on -- it would flag (or not flag) both
    # twins identically, the same reasoning already used for the
    # escaping-context-mismatch XSS rows above, not the SSTI shape's
    # differing-API case (`Ognl.getValue()` vs. a fixed `Map` lookup),
    # which a checker genuinely could distinguish.
    ("spel_injection", "spel_expression_evaluate"): StaticPrecheckStatus.UNINFORMATIVE,
}


class NoStaticCheckerConfiguredError(RuntimeError):
    """Raised when an INFORMATIVE shape is precheck'd with no checker
    callable supplied -- an authoring gap (real Psalm/Semgrep wiring is
    still separate, later work), not something to silently pass."""


@dataclass(frozen=True)
class PrecheckResult:
    status: StaticPrecheckStatus
    ran: bool
    passed: bool | None  # None when not run (skipped)
    detail: str


def static_precheck_status(vuln_class: str, sink_family: str) -> StaticPrecheckStatus:
    """Look up this shape's ``static_precheck`` flag.

    Fails loud on an unregistered shape, matching this project's "an
    authoring gap fails loud, never defaults silently" convention (see
    ``fuzzlab.labgen.verdict.SafetyMatrix.lookup``).
    """
    try:
        return STATIC_PRECHECK_BY_SHAPE[(vuln_class, sink_family)]
    except KeyError as exc:
        raise KeyError(
            f"no static_precheck entry for (vuln_class={vuln_class!r}, sink_family={sink_family!r}) "
            "-- add one to STATIC_PRECHECK_BY_SHAPE rather than defaulting silently"
        ) from exc


def run_static_precheck(
    vuln_class: str,
    sink_family: str,
    checker: Callable[[], bool] | None = None,
) -> PrecheckResult:
    """Run (or skip) a static-shape-conformance check for one
    ``(vuln_class, sink_family)`` shape.

    An **uninformative** shape is always skipped -- ``checker``, even if
    supplied, is never called: a clean-but-meaningless scan must never be
    recorded as evidence (Addendum C point 4). An **informative** shape
    calls ``checker`` and *requires* one to be supplied -- there is no
    silent default here either.
    """
    status = static_precheck_status(vuln_class, sink_family)
    if status is StaticPrecheckStatus.UNINFORMATIVE:
        return PrecheckResult(
            status=status,
            ran=False,
            passed=None,
            detail=(
                f"skipped: ({vuln_class}, {sink_family}) is static_precheck=uninformative -- "
                "a taint-style checker is structurally blind to this shape (CR-LAB-0001 Addendum C point 4)"
            ),
        )
    if checker is None:
        raise NoStaticCheckerConfiguredError(
            f"({vuln_class}, {sink_family}) is static_precheck=informative but no checker was supplied "
            "-- wiring a real Psalm/Semgrep checker is separate, later work; this shape must not be "
            "silently treated as passing or skipped in the meantime"
        )
    passed = checker()
    return PrecheckResult(
        status=status,
        ran=True,
        passed=passed,
        detail=f"ran: ({vuln_class}, {sink_family}) is static_precheck=informative",
    )
