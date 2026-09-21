"""Emitter interface (T-LAB0.4).

Per ``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.4 and ``CR-LAB-0001`` Addendum C, an
:class:`Emitter` turns a resolved :class:`~fuzzlab.labgen.schema.Cell` into
real, per-stack source files. This module defines only the *interface* and
the *output shape*; an emitter's internal rendering is expected to be
**module composition** (small, independently-authored source/transform/sink/
complexity fragments assembled per cell -- see
``fuzzlab.labgen.modules``), never one monolithic template per
``(vuln_class, sink_context)``.

Unsupported pairs are declared, not raised: a caller asks
``emitter.supports(cell.vuln_class, cell.sink_context)`` and skips the cell
if it is ``False`` -- "declare unsupported and skip," per the plan's own
rule -- rather than calling :meth:`Emitter.render` and handling an exception
as normal control flow.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from .schema import Cell, SinkContext


@dataclass(frozen=True)
class EmittedFile:
    """One file an emitter produces for a cell.

    ``role`` is forward-compatible with ``CR-LAB-0001`` Addendum D's
    per-module ``file_role``/cardinality concept (e.g. ``"controller"``,
    ``"view"``, ``"route"`` for a routed, multi-file emitter). Phase 0's
    ``php_current`` emitter only ever produces ``"page"`` files, since
    today's PHP app is filesystem-routed with no central routes file and
    needs none of the accumulator/view/route machinery Addendum D reserves
    for Phase 3's Laravel/Express emitters.
    """

    path: str
    content: bytes
    role: str = "page"


EmittedFiles = tuple[EmittedFile, ...]
"""One-or-more files an :meth:`Emitter.render` call produces for a single
:class:`~fuzzlab.labgen.schema.Cell`.

Deliberately a tuple of :class:`EmittedFile`, not a single ``(path, bytes)``
pair, so the interface does not structurally assume single-file output.
Phase 3's Laravel/Express emitters will need to return, for one cell, a
controller fragment, a view fragment, and a fragment merged into a shared
routes accumulator file (``CR-LAB-0001`` Addendum D) -- nothing about this
type needs to change for that; ``php_current`` simply always returns a
one-tuple today.
"""


class Emitter(ABC):
    """A per-stack renderer that turns a resolved
    :class:`~fuzzlab.labgen.schema.Cell` into real source files.

    Implementations are expected to render internally via composition of
    small, reusable modules (:mod:`fuzzlab.labgen.modules`) rather than one
    template per ``(vuln_class, sink_context)`` -- see this module's
    docstring and ``CR-LAB-0001`` Addendum C.
    """

    @abstractmethod
    def supports(self, vuln_class: str, sink_context: SinkContext) -> bool:
        """Whether this emitter can render a cell of this
        ``(vuln_class, sink_context)`` shape.

        A caller must check this before calling :meth:`render` and skip a
        cell this emitter does not support -- "declare unsupported and
        skip," never an error, per ``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.4.
        """
        raise NotImplementedError

    @abstractmethod
    def render(self, cell: Cell) -> EmittedFiles:
        """Render ``cell`` to one or more output files.

        Two calls with an equal ``cell`` (and, transitively, an equal
        ``root_seed`` wherever an emitter's caller threads one through) must
        return byte-identical ``content`` for every path
        (NFR-LAB-reproducible) -- an emitter must never depend on
        wall-clock time, randomness, or unordered ``dict``/``set``
        iteration. Implementations should treat a call on an unsupported
        cell (one :meth:`supports` would reject) as a caller bug and may
        raise, but that is a defensive guard, not the intended control flow
        -- see the class docstring.
        """
        raise NotImplementedError
