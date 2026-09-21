"""Reproducible evaluation report (component #12/docs, Phase 10 T10.4).

A deterministic report over a stored run — its inputs, versions, seeds, metrics, findings,
active plugins, and models — so a run can be reproduced and two runs compared. Reading is
pure and offline (no traffic); the same store + run always renders identical output.
"""

from __future__ import annotations

from fuzzlab.report.report import build_report, format_json, format_text

__all__ = ["build_report", "format_text", "format_json"]
