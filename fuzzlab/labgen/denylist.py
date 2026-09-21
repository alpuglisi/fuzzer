"""Vulnerability-class name denylist for the name-leak build gate
(NFR-LAB-no-leak, T-LAB0.6).

Deliberately hand-maintained for this Phase 0 scaffold rather than
auto-derived from a live manifest/class-vocabulary file — the corpus is tiny
right now and a hand-reviewed list is easy to keep in sync. Pulling the full
``labels.json`` class vocabulary in automatically (per
``docs/LAB_PHASE_0_PLAN.md`` T-LAB0.6) is left for when that vocabulary
actually grows in Phase 1+.
"""

from __future__ import annotations

VULN_CLASS_DENYLIST: tuple[str, ...] = (
    "sqli",
    "sql_injection",
    "sql-injection",
    "xss",
    "cross_site_scripting",
    "cross-site-scripting",
    "ssrf",
    "ssti",
    "xxe",
    "idor",
    "bola",
    "csrf",
    "rce",
    "command_injection",
    "command-injection",
    "lfi",
    "rfi",
    "path_traversal",
    "path-traversal",
    "directory_traversal",
    "open_redirect",
    "open-redirect",
    "deserialization",
    "prototype_pollution",
    "prototype-pollution",
    "race_condition",
    "race-condition",
    "business_logic",
    "vuln",
    "exploit",
    "payload",
)
