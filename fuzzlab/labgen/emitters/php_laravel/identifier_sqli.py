"""Wiring lane L-P1.2a's identifier-SQLi differential prober to a
**Laravel-rendered** identifier/alias cell (L-P3.3b, §4.3 step 2).

This lane's brief asked whether :mod:`fuzzlab.labgen.identifier_sqli_assertion`
(L-P1.2b's oracle wiring) can be reused as-is for a Laravel-rendered cell, or
needs a small adapter. **Verified, not assumed -- it needs exactly one small
adapter, and no change to that module.**

What is already stack-agnostic there, and is reused unchanged:

* the whole derive-then-confirm contract
  (:func:`~fuzzlab.labgen.identifier_sqli_assertion.assert_identifier_sqli_cell`
  derives the verdict from the pinned safety matrix and compares it with the
  oracle's outcome -- never a hand-asserted expectation);
* every fail-closed refusal
  (:func:`~fuzzlab.labgen.identifier_sqli_assertion.build_identifier_sqli_request`
  rejects a non-identifier sink family, a non-query parameter location and a
  non-raw encoding, and an ``inconclusive`` probe raises);
* the probe mechanics themselves (it talks HTTP to a running target, so *which*
  framework rendered the page is genuinely irrelevant to it).

The one thing that is **not** framework-independent is where the cell is
served. That module derives the probed URL from the cell's own
``route``/``sink_endpoint`` path, which is correct for ``php_current``
(filesystem-routed: ``cell.route.path`` *is* the served URL). ``php_laravel``
is router-dispatched and deliberately serves each cell at its own
cell-ID-derived URL -- ``/cell/labgen-pl-0007``, not ``/catalog`` -- precisely
so a vulnerable cell and its twins can coexist in one build (see
``route_accumulator``'s module docstring). Probing ``cell.route.path``
against a Laravel build would therefore hit a route that does not exist and
report a meaningless result.

The adapter is consequently a **route rewrite, not a second assertion**:
:func:`probe_cell_for` returns the same cell with ``route`` rewritten to the
URL this emitter actually serves it at, and :func:`assert_laravel_identifier_sqli_cell`
hands that to the shared assertion. No verdict derivation, oracle call,
comparison or fail-closed branch is re-implemented here (PA-0003/PA-0021: one
shared function, called at the one site that needs adapting), and the
rewrite cannot change the derived verdict, since ``verdict()`` reads
``(transform, sink_context)`` only.

The probe metadata (parameter name and the two value-differing columns) is
read from this emitter's own page profile rather than duplicated here
(PA-0001), the same split ``php_current``'s ``_PAGE_PARAMS`` already uses.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Mapping

from fuzzlab.labgen.emitters.php_laravel import _PAGE_PROFILES, _url_path_for
from fuzzlab.labgen.identifier_sqli_assertion import (
    IdentifierSqliAssertionError,
    IdentifierSqliAssertionResult,
    assert_identifier_sqli_cell,
    build_identifier_sqli_request,
    is_identifier_sqli_cell,
)
from fuzzlab.labgen.identifier_sqli_oracle import IdentifierSqliOracleRequest
from fuzzlab.labgen.schema import Cell
from fuzzlab.labgen.verdict import SafetyMatrix

__all__ = [
    "probe_cell_for",
    "probe_params_for",
    "build_laravel_identifier_sqli_request",
    "assert_laravel_identifier_sqli_cell",
]


def probe_cell_for(cell: Cell) -> Cell:
    """``cell`` with its ``route`` rewritten to the URL ``php_laravel``
    actually serves it at (``/cell/<cell-slug>``).

    This is the entire Laravel-specific adaptation (see the module
    docstring). ``sink_endpoint`` is asserted absent rather than rewritten:
    this emitter renders ``context_depth == "direct"`` cells only, so a cell
    carrying a second endpoint could not have been rendered in the first
    place, and silently rewriting one would invent a URL no generated route
    serves.
    """
    if cell.sink_endpoint is not None:
        raise IdentifierSqliAssertionError(
            f"{cell.cell_id}: carries a sink_endpoint ({cell.sink_endpoint.path!r}), which "
            "php_laravel does not render yet (it renders context_depth 'direct' only) -- there "
            "is no generated Laravel route for that endpoint to probe"
        )
    return dataclasses.replace(
        cell, route=dataclasses.replace(cell.route, path=_url_path_for(cell.cell_id))
    )


def probe_params_for(cell: Cell) -> dict[str, str]:
    """The ``param_name``/``column_a``/``column_b`` probe metadata for
    ``cell``, read from this emitter's own page profile.

    Raises :class:`IdentifierSqliAssertionError` for a cell whose page
    profile does not carry the two value-differing probe columns -- a page
    the oracle cannot honestly probe, which is a fail-closed refusal rather
    than a guessed column pair.
    """
    if not is_identifier_sqli_cell(cell):
        raise IdentifierSqliAssertionError(
            f"{cell.cell_id}: sink_context.family={cell.sink_context.family!r} is not an "
            "identifier/alias position -- this oracle means nothing elsewhere (the shared "
            "assertion refuses it for the same reason)"
        )
    profile: Mapping[str, Any] = _PAGE_PROFILES.get(cell.route.path, {})
    missing = [key for key in ("param_name", "column_a", "column_b") if key not in profile]
    if missing:
        raise IdentifierSqliAssertionError(
            f"{cell.cell_id}: php_laravel's page profile for {cell.route.path!r} is missing "
            f"identifier-SQLi probe metadata {missing} -- the oracle needs the parameter name "
            "and two real, value-differing columns; it must never be handed a guessed pair"
        )
    return {
        "param_name": str(profile["param_name"]),
        "column_a": str(profile["column_a"]),
        "column_b": str(profile["column_b"]),
    }


def build_laravel_identifier_sqli_request(
    cell: Cell, *, target_base_url: str, **request_kwargs
) -> IdentifierSqliOracleRequest:
    """The oracle request for a Laravel-rendered ``cell``.

    Delegates to
    :func:`~fuzzlab.labgen.identifier_sqli_assertion.build_identifier_sqli_request`
    (so every one of its fail-closed refusals still applies, unchanged) after
    the route rewrite, and fills ``param_name``/``column_a``/``column_b`` from
    the page profile unless the caller overrides them.
    """
    kwargs = {**probe_params_for(cell), **request_kwargs}
    return build_identifier_sqli_request(
        probe_cell_for(cell), target_base_url=target_base_url, **kwargs
    )


def assert_laravel_identifier_sqli_cell(
    cell: Cell, matrix: SafetyMatrix, *, target_base_url: str, **assertion_kwargs
) -> IdentifierSqliAssertionResult:
    """Derive ``cell``'s verdict from ``matrix`` and confirm it against the
    **Laravel** build's served URL for that cell.

    A thin adapter over
    :func:`~fuzzlab.labgen.identifier_sqli_assertion.assert_identifier_sqli_cell`
    -- same result type, same
    :class:`~fuzzlab.labgen.identifier_sqli_assertion.IdentifierSqliAssertionError`
    on disagreement *or* on an inconclusive probe (fail-closed, PA-0025).
    """
    kwargs = {**probe_params_for(cell), **assertion_kwargs}
    return assert_identifier_sqli_cell(
        probe_cell_for(cell), matrix, target_base_url=target_base_url, **kwargs
    )
