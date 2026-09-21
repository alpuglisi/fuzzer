"""Minimal-pair invariant checker (pulled forward from Phase 1).

Per `docs/change-requests/CR-LAB-0001-manifest-generator-realism-and-variation.md`
§3 and `docs/LAB_SEED_AUTHORING_PLAYBOOK.md` step 5/6: a cell's vulnerable and
secure twins must differ **only** in the declared transform/sink region --
everything else (identifiers, unrelated code structure) must be identical, so
a detector's false positive/negative is attributable to the actual
security-relevant difference, not incidental noise. The playbook cites
Juliet's own documented failure mode as the cautionary example: a generic
helper name made false positives unattributable to the right variant.

This module is a **standalone, offline checker** over two already-rendered
:class:`~fuzzlab.labgen.emitter.EmittedFiles` results -- it does not render
anything itself and does not know which emitter produced its input. It reads
(never modifies) two things from ``fuzzlab.labgen``:

- :mod:`fuzzlab.labgen.emitter` -- the ``EmittedFile``/``EmittedFiles`` types.
- :mod:`fuzzlab.labgen.modules` -- the module registries (``SOURCES``,
  ``TRANSFORMS``, ``SINKS``, ``COMPLEXITIES``), used only to look up each
  named module's own declared ``category`` (``"source" | "transform" |
  "sink" | "complexity"``, forward-compatible with ``CR-LAB-0001`` Addendum
  D's ``"view"``/``"route"`` categories) -- never to re-render a module.

How the "declared region" is determined, without over-fitting to one
emitter's internals
--------------------------------------------------------------------------
Per this project's own module-composition emitter convention (see
``fuzzlab/labgen/emitters/php_current/__init__.py``), an emitter that
assembles a cell from composable fragments records the exact ordered
sequence of module names it used in a single comment line:

    // Module composition: get_param -> param_bind -> sql_numeric_lookup -> single_statement

This checker parses that line from both variants and classifies each
position by its module's registered ``category``. Any position whose
category is in ``variable_categories`` (default ``{"transform", "sink"}`` --
a sink's own rendering is allowed to change too, since ``verdict()`` derives
a cell's label from ``(transform, sink_context)`` *jointly*, and this
project's real sink module for the Phase-0 pair branches on a flag a
transform module sets, per ``fuzzlab/labgen/modules/__init__.py``'s
``SqlNumericLookupSink`` docstring) may legitimately differ between the two
variants. Any other position must name the *same* module in both variants,
or this is not a minimal pair -- it is a structural change (e.g. a different
source module silently swapped in) this checker refuses to wave through.

Within the actual file content, the exact differing line span is found
independently via a longest-common-prefix / longest-common-suffix trim over
each file's lines (excluding the composition comment line itself, which is
build provenance, not code, and is expected to differ whenever the
composition differs) -- the middle band left over after trimming is the
*empirically* differing region. Because a module-composition emitter
concatenates its fragments in declared order before wrapping them, the
transform+sink fragments are always contiguous in the assembled body, so
this middle band and the composition-derived "declared" positions describe
the same region from two independent angles; when the composition sequences
are identical name-for-name, the middle band is required to be empty --
catching exactly the "someone tweaked something unrelated and the diff still
looks small" failure mode this checker exists to prevent.

**Explicitly out of scope for this Phase-0-pulled-forward delivery** (kept
simple per this project's own "minimal, correct, not fully general"
convention): the two variants' composition sequences must have equal
length. A future emitter whose secure twin uses a longer transform pipeline
than its vulnerable twin (e.g. two chained transforms vs. zero) is not yet
supported -- this raises :class:`MinimalPairError`, not a silent false pass.
Identifier-pattern extraction (:func:`check_identifier_stability`) is
currently PHP-oriented (``function NAME(`` declarations, ``$var`` tokens); a
future non-PHP emitter is a documented extension point, not attempted here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .emitter import EmittedFile, EmittedFiles
from .modules import COMPLEXITIES, SINKS, SOURCES, TRANSFORMS

#: Every module name this project's module registries know, mapped to its
#: own declared category. Read-only lookup -- never re-renders a module.
_MODULE_CATEGORY: dict[str, str] = {
    name: module.category
    for registry in (SOURCES, TRANSFORMS, SINKS, COMPLEXITIES)
    for name, module in registry.items()
}

#: Categories allowed to differ between a minimal pair's twins by default.
DEFAULT_VARIABLE_CATEGORIES: frozenset[str] = frozenset({"transform", "sink"})

_COMPOSITION_RE = re.compile(r"^\s*//\s*Module composition:\s*(.+?)\s*$", re.MULTILINE)
_FUNCTION_NAME_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
_PHP_VARIABLE_RE = re.compile(r"\$[A-Za-z_]\w*")


class MinimalPairError(ValueError):
    """Raised when the minimal-pair invariant cannot even be evaluated for a
    given input (e.g. no composition comment found, or a module name the
    registry doesn't recognize) -- a setup problem, not itself proof of a
    violation. Never raised silently as a substitute for a real check."""


class MinimalPairViolation(MinimalPairError):
    """Raised when the minimal-pair invariant is actually violated: the two
    variants differ outside the declared transform/sink region, their
    composition sequences disagree somewhere they shouldn't, or a stable
    identifier (a function/handler name) differs between them. The message
    always names exactly what differed and where."""


@dataclass(frozen=True)
class _CompositionEntry:
    position: int
    name: str
    category: str


def _parse_composition(text: str, *, label: str) -> tuple[_CompositionEntry, ...]:
    match = _COMPOSITION_RE.search(text)
    if match is None:
        raise MinimalPairError(
            f"{label}: no '// Module composition: ...' line found -- cannot determine the "
            "declared transform/sink region without it (this checker refuses to guess)"
        )
    names = [n.strip() for n in match.group(1).split("->") if n.strip()]
    entries = []
    for i, name in enumerate(names):
        category = _MODULE_CATEGORY.get(name)
        if category is None:
            raise MinimalPairError(
                f"{label}: composition names module {name!r} at position {i}, which is not "
                f"registered in any of fuzzlab.labgen.modules' SOURCES/TRANSFORMS/SINKS/"
                f"COMPLEXITIES -- cannot classify it, refusing to guess its category"
            )
        entries.append(_CompositionEntry(position=i, name=name, category=category))
    return tuple(entries)


def _strip_composition_line(text: str) -> list[str]:
    return [line for line in text.splitlines() if not _COMPOSITION_RE.match(line)]


def _common_prefix_len(a: list[str], b: list[str]) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def _common_suffix_len(a: list[str], b: list[str], *, after: int) -> int:
    n = 0
    while n < len(a) - after and n < len(b) - after and a[len(a) - 1 - n] == b[len(b) - 1 - n]:
        n += 1
    return n


def check_identifier_stability(vulnerable_text: str, secure_text: str, *, label: str = "") -> None:
    """Assert every declared function/handler identifier is byte-identical
    between the two variants.

    This is the direct mechanical check for the playbook's rule 6 ("per-cell
    identifiers derive from the cell ID; the vulnerable and secure twins
    must emit identical identifiers") and its cited Juliet failure mode (a
    generic helper name made a false positive unattributable to the right
    variant). Currently PHP-oriented (``function NAME(`` declarations); see
    the module docstring's note on extending this to other languages.
    """
    prefix = f"{label}: " if label else ""
    v_names = _FUNCTION_NAME_RE.findall(vulnerable_text)
    s_names = _FUNCTION_NAME_RE.findall(secure_text)
    if v_names != s_names:
        raise MinimalPairViolation(
            f"{prefix}declared function/handler identifier(s) differ between the vulnerable and "
            f"secure variant: {v_names} vs {s_names} -- per-cell identifiers must derive from the "
            "cell ID and be identical across twins (Juliet's documented helper-naming defect)"
        )


def _check_file_pair(vulnerable: EmittedFile, secure: EmittedFile, *, variable_categories: frozenset[str]) -> None:
    label = vulnerable.path
    v_text = vulnerable.content.decode("utf-8")
    s_text = secure.content.decode("utf-8")

    v_comp = _parse_composition(v_text, label=f"{label} (vulnerable)")
    s_comp = _parse_composition(s_text, label=f"{label} (secure)")

    if len(v_comp) != len(s_comp):
        raise MinimalPairError(
            f"{label}: composition sequences have different lengths "
            f"({[e.name for e in v_comp]} vs {[e.name for e in s_comp]}) -- variable-length "
            "transform pipelines between twins are not supported by this Phase-0 checker"
        )

    # `any_declared_difference` must be *evidence-based* (an actual module
    # NAME differed at a position the composition says is allowed to
    # differ) -- never merely "this category is eligible to differ." A
    # position whose category happens to be in `variable_categories` but
    # whose name is identical in both variants is not itself evidence of a
    # real difference (e.g. every cell has *some* transform module named in
    # its composition; that alone must never be treated as "a difference
    # exists here"). Getting this wrong effectively disables the whole
    # content-confinement check below for nearly every real cell -- caught
    # by tests/test_labgen_minimal_pair.py's identifier-rename fixture.
    any_declared_difference = False
    for v_entry, s_entry in zip(v_comp, s_comp):
        names_differ = v_entry.name != s_entry.name
        if not names_differ:
            continue
        either_category_variable = v_entry.category in variable_categories or s_entry.category in variable_categories
        if not either_category_variable:
            raise MinimalPairViolation(
                f"{label}: composition position {v_entry.position} differs "
                f"({v_entry.name!r} vs {s_entry.name!r}, category={v_entry.category!r}) but that "
                f"category is not in the declared-variable set {sorted(variable_categories)} -- "
                "a minimal pair may only differ in its transform/sink region"
            )
        any_declared_difference = True

    v_lines = _strip_composition_line(v_text)
    s_lines = _strip_composition_line(s_text)
    prefix_len = _common_prefix_len(v_lines, s_lines)
    suffix_len = _common_suffix_len(v_lines, s_lines, after=prefix_len)
    v_middle = v_lines[prefix_len : len(v_lines) - suffix_len]
    s_middle = s_lines[prefix_len : len(s_lines) - suffix_len]

    if not any_declared_difference and (v_middle or s_middle):
        raise MinimalPairViolation(
            f"{label}: files differ outside any declared transform/sink change -- composition "
            f"sequences are identical ({[e.name for e in v_comp]}) yet content differs starting at "
            f"line {prefix_len + 1}:\n  vulnerable: {v_middle!r}\n  secure:     {s_middle!r}"
        )

    check_identifier_stability(v_text, s_text, label=label)


def check_minimal_pair(
    vulnerable: EmittedFiles,
    secure: EmittedFiles,
    *,
    variable_categories: frozenset[str] = DEFAULT_VARIABLE_CATEGORIES,
) -> None:
    """Assert ``vulnerable`` and ``secure`` -- two :class:`EmittedFiles`
    results for the same cell, one rendered with its transform pipeline
    weakened/emptied and one with it intact -- form a valid minimal pair.

    Raises :class:`MinimalPairViolation` naming exactly what differs
    unexpectedly, or :class:`MinimalPairError` if the invariant cannot be
    evaluated at all (e.g. no composition comment to parse). Returns
    ``None`` (no exception) when the pair is valid. Never a silent pass on
    an actual violation.
    """
    v_by_path = {f.path: f for f in vulnerable}
    s_by_path = {f.path: f for f in secure}
    if set(v_by_path) != set(s_by_path):
        raise MinimalPairViolation(
            f"file sets differ between variants: vulnerable={sorted(v_by_path)} "
            f"secure={sorted(s_by_path)}"
        )
    for path in sorted(v_by_path):
        v_file, s_file = v_by_path[path], s_by_path[path]
        if v_file.role != s_file.role:
            raise MinimalPairViolation(f"{path}: role differs (vulnerable={v_file.role!r}, secure={s_file.role!r})")
        _check_file_pair(v_file, s_file, variable_categories=variable_categories)
