"""Lab-generator foundation (component LAB, Phase 0 — CR-LAB-0001/D20).

Kept minimal deliberately: this package is also home to a sibling,
independently-developed module (``fuzzlab.labgen.oracle_wrapper``, the
sqlmap/commix oracle wrapper) built concurrently in a separate lane. This
``__init__`` re-exports only the modules delivered here so the two lanes'
work merges cleanly; it does not import ``oracle_wrapper``.
"""

from . import denylist, gates, schema, subseed, verdict

__all__ = ["denylist", "gates", "schema", "subseed", "verdict"]
