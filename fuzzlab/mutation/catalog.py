"""Variant write-back + destructive gate (Phase 8 T8.5, FR-MUT-6 / NFR-MUT-safe).

Accepted mutations are recorded with their provenance in the `payload_variant` table
(migration 8) — which operator chain produced the variant, which WAF rule it bypassed,
the semantics verdict, any coverage gain — for reuse and analysis. Live runs also send
the variant through the fuzzer's `attempt` path; that is the harness's job.

The **destructive gate** applies to generated payloads too (NFR-MUT-safe): a payload
that looks destructive (raw or normalised, `refuse_destructive`) is refused unless
`allow_destructive` is explicitly set. It is never **sent** — the live filter and the
greybox loop check it at send time (BUG-0082) — and never persisted
(`record_variant`). The default is off, matching `core/config.py`.
"""

from __future__ import annotations

import json
import re

from fuzzlab.mutation.search import SearchResult

# Conservative destructive-intent signatures (SQL + shell). Lab-only, default-refused.
_DESTRUCTIVE = re.compile(
    r"\b(drop|truncate|delete|alter|create|shutdown|xp_cmdshell)\b"
    r"|\binsert\s+into\b|\bupdate\b[^;]*\bset\b"
    r"|rm\s+-rf|mkfs|:\(\)\s*\{|\bshutdown\b|\breboot\b|>\s*/dev/",
    re.IGNORECASE,
)


def is_destructive(payload: str) -> bool:
    """True if the payload matches a destructive-intent signature."""
    return bool(_DESTRUCTIVE.search(payload or ""))


def normalize_for_gate(payload: str, strip_line_comments: bool = True) -> str:
    """``payload`` with the obfuscations mutation operators produce undone, for the
    destructive gate only: up to 3 rounds of URL decoding, HTML entities, NULs removed,
    ``/*…*/`` comments removed, ``--`` / ``#`` comments removed **to the end of the line
    only**, ``+`` read as a space, whitespace collapsed, lower-cased."""
    import html
    from urllib.parse import unquote
    s = payload or ""
    for _ in range(3):
        decoded = unquote(s)
        if decoded == s:
            break
        s = decoded
    s = html.unescape(s).replace("\x00", "").replace("+", " ")
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    if strip_line_comments:
        s = re.sub(r"(--|#)[^\n]*", " ", s)
    return re.sub(r"\s+", " ", s).strip().lower()


def refuse_destructive(payload: str, allow_destructive: bool = False) -> bool:
    """True when ``payload`` must not be sent: it looks destructive, raw **or** once
    normalised (normalising can only add refusals), and ``allow_destructive`` is off.
    The send-time gate (BUG-0082, FR-MUT-9): every live mutation and greybox send checks
    it before the payload leaves the process."""
    if allow_destructive:
        return False
    # every form is checked, so normalising only ever adds refusals: a line-comment
    # strip alone could hide a destructive tail ("1-- -; DR/**/OP TABLE x")
    return (is_destructive(payload) or is_destructive(normalize_for_gate(payload))
            or is_destructive(normalize_for_gate(payload, strip_line_comments=False)))


def record_variant(store, run_id, base_payload: str, variant: str,
                   operators: list[str], vuln_class: str, *, sink_context: str | None = None,
                   bypassed_rule: str | None = None, semantics_ok: bool = True,
                   coverage_gain: float | None = None,
                   allow_destructive: bool = False) -> int | None:
    """Persist one variant's provenance. Returns the row id, or ``None`` if the
    destructive gate refused it (nothing is written or sent)."""
    if is_destructive(variant) and not allow_destructive:
        return None
    cur = store.conn.execute(
        "INSERT INTO payload_variant (run_id, vuln_class, base_payload, variant, "
        "operators, sink_context, bypassed_rule, semantics_ok, coverage_gain) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (run_id, vuln_class, base_payload, variant, json.dumps(operators), sink_context,
         bypassed_rule, int(bool(semantics_ok)),
         float(coverage_gain) if coverage_gain is not None else None))
    store.conn.commit()
    return int(cur.lastrowid)


def record_search_result(store, run_id, base_payload: str, result: SearchResult,
                         vuln_class: str, *, sink_context: str | None = None,
                         bypassed_rule: str | None = None,
                         allow_destructive: bool = False) -> int | None:
    """Record a `MutationSearch` result (convenience over `record_variant`)."""
    return record_variant(
        store, run_id, base_payload, result.variant, list(result.operators), vuln_class,
        sink_context=sink_context, bypassed_rule=bypassed_rule,
        semantics_ok=result.semantics_ok, coverage_gain=float(result.novel_lines),
        allow_destructive=allow_destructive)


def list_variants(store, run_id: int | None = None) -> list[dict]:
    where = "WHERE run_id=?" if run_id is not None else ""
    args: tuple = (run_id,) if run_id is not None else ()
    rows = store.conn.execute(
        f"SELECT * FROM payload_variant {where} ORDER BY id", args).fetchall()
    return [dict(r) for r in rows]
