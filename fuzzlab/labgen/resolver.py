"""Covering-array resolver (T-LAB0.3): a real, tested expansion engine, not
yet wired into the Phase 0 manifest's cell count.

Per ``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.3, this uses **`covertable` 3.2.0**
(Apache-2.0) rather than shelling out to NIST ACTS or hand-rolling IPOG — the
plan cites it as measured to match or beat ACTS's published reference array
sizes. Phase 0's manifest itself still lists cells explicitly (one axis
level each, per ``fuzzlab.labgen.schema``); this module proves the machinery
without touching today's cells or labels, ready for Phase 1 to wire in.

Two things this module exists specifically to guard against, both named in
``docs/PREVENTIVE_ACTIONS.md`` PA-0010 and the plan itself:

1. **A silently-swallowed bad kwarg.** ``covertable.make()`` accepts
   arbitrary extra keyword arguments via ``**params`` and does nothing with
   an unrecognized one — verified directly against the installed 3.2.0
   package (``covertable/main.py``'s ``make``/``make_async``/``Controller``
   signatures): a typo'd or renamed option is silently ignored rather than
   raising, which is exactly the "wrong-granularity/silently-empty-or-wrong"
   failure mode PA-0010 warns about. ``expand()`` therefore never forwards a
   caller-supplied kwargs mapping to ``covertable.make()`` directly; it goes
   through :func:`validate_covering_array_config`, which rejects anything
   outside a small, explicit allowlist.
2. **An unpinned sorter.** ``covertable.make()`` defaults ``sorter`` to
   ``covertable.sorters.hash`` today, but the plan is explicit that
   array-stability across the library's own releases is not documented — a
   future covertable release could change that default. :func:`expand`
   always passes ``sorter=covertable.sorters.hash`` explicitly and never
   relies on the library's default.

**Versioning convention (documented here, not mechanically enforced by this
module):** per the plan, bumping the installed ``covertable`` version is
treated as a manifest version bump (``manifest_version``), since neither
this library nor this module promises array stability across a
``covertable`` upgrade — changing the arrays would change every downstream
cell ID. See ``_COVERTABLE_VERSION`` below.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from covertable import make as _covertable_make
from covertable import sorters as _covertable_sorters

# The covertable version this module was written and pinned against
# (pyproject.toml pins the installed package to this exact release). A
# version bump here is a manifest_version bump, per this module's docstring
# and docs/LAB_PHASE_0_PLAN.md T-LAB0.3.
_COVERTABLE_VERSION = "3.2.0"

# The only covertable.make() kwargs this project constructs from
# caller-supplied (eventually manifest-supplied) data. `sorter` is
# deliberately absent: this module always pins it itself (see module
# docstring point 2) and never lets a caller override it.
_ALLOWED_KWARGS = frozenset({"factors", "strength", "sub_models", "constraints"})


class CoveringArrayError(ValueError):
    """Raised for an invalid covering-array request or a covertable build
    failure: an unrecognized config key, a non-JSON-serializable value, an
    empty/invalid factor set, or an exception from ``covertable.make()``
    itself."""


def _assert_json_serializable(value: Any, *, what: str) -> None:
    try:
        json.dumps(value)
    except TypeError as exc:
        raise CoveringArrayError(f"{what} is not JSON-serializable: {exc}") from exc


def validate_covering_array_config(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a raw covering-array config (as it would eventually come
    from a manifest's covering-array section) against the allowlist and
    basic shape rules, returning a normalized dict with defaults filled in.

    Raises :class:`CoveringArrayError` for any key outside
    :data:`_ALLOWED_KWARGS`, rather than silently ignoring it the way
    ``covertable.make()`` itself would (PA-0010).
    """
    unknown = set(raw) - _ALLOWED_KWARGS
    if unknown:
        raise CoveringArrayError(
            f"unrecognized covering-array config key(s) {sorted(unknown)} — "
            f"covertable.make() would silently accept and ignore these via **params "
            f"rather than erroring (PA-0010); allowed keys: {sorted(_ALLOWED_KWARGS)}"
        )
    if "factors" not in raw:
        raise CoveringArrayError("covering-array config requires 'factors'")

    _assert_json_serializable(dict(raw), what="covering-array config")

    factors: Mapping[str, Sequence[Any]] = raw["factors"]
    if not factors:
        raise CoveringArrayError("'factors' must be a non-empty mapping of axis name -> level list")
    for name, levels in factors.items():
        if not levels:
            raise CoveringArrayError(f"factor {name!r} has no levels")

    strength = raw.get("strength", 2)
    if not isinstance(strength, int) or isinstance(strength, bool) or strength < 1:
        raise CoveringArrayError(f"'strength' must be a positive integer, got {strength!r}")

    sub_models = list(raw.get("sub_models", ()))
    for sm in sub_models:
        if "fields" not in sm:
            raise CoveringArrayError(f"sub_model {sm!r} is missing required 'fields'")
        unknown_fields = set(sm["fields"]) - set(factors)
        if unknown_fields:
            raise CoveringArrayError(f"sub_model references unknown factor(s) {sorted(unknown_fields)}")

    constraints = list(raw.get("constraints", ()))

    return {
        "factors": dict(factors),
        "strength": strength,
        "sub_models": sub_models,
        "constraints": constraints,
    }


def expand(raw: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Expand a validated covering-array config into the covering array: a
    list of ``{axis_name: level_value}`` rows covering every ``strength``-way
    combination of factor levels (plus any ``sub_models``' own strength),
    honoring any declarative ``constraints``.

    Pure and deterministic for a fixed ``covertable`` version: the pinned
    ``sorters.hash`` sorter is FNV-1a32-based, not Python's randomized string
    hashing, so two calls — including across separate processes — return the
    identical array (verified in
    ``tests/test_labgen_resolver.py::test_expand_is_deterministic_across_processes``).
    """
    validated = validate_covering_array_config(raw)
    kwargs: dict[str, Any] = {
        "factors": validated["factors"],
        "strength": validated["strength"],
        "sorter": _covertable_sorters.hash,  # pinned explicitly — never the library default
    }
    if validated["sub_models"]:
        kwargs["sub_models"] = validated["sub_models"]
    if validated["constraints"]:
        kwargs["constraints"] = validated["constraints"]
    try:
        return _covertable_make(**kwargs)
    except Exception as exc:  # pragma: no cover - covertable's own error surface
        raise CoveringArrayError(f"covertable.make() failed: {exc}") from exc
