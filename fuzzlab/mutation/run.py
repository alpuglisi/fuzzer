"""Live WAF-evasion run: learn a semantics-preserving bypass and record it (Phase 8).

Backs the mutation engine's `Filter` seam with the live lab WAF (:class:`HttpFilter`),
runs `MutationSearch` per base payload, and — when a base is blocked and a
semantics-preserving variant evades — writes the variant to `payload_variant` via the
destructive-gated `record_search_result`. Optionally measures real coverage gain through
the Part E grey-box side channel so the "reach new code" half of the exit is live too.
Lab-only; the caller supplies an authorized sender.
"""

from __future__ import annotations

import time

from fuzzlab.mutation.catalog import record_search_result
from fuzzlab.mutation.livefilter import HttpFilter
from fuzzlab.mutation.search import MutationSearch

DEFAULT_BASES: dict[str, list[str]] = {
    "sql-injection": ["1 union select 1"],
    "xss": ["<script>alert(1)</script>"],
}


def make_coverage_fn(url: str, param: str, *, cov_dir: str,
                     app_root: str = "/var/www/html", method: str = "GET",
                     location: str = "query", cookie: str | None = None,
                     settle: float = 0.1):
    """A `coverage_fn` for MutationSearch backed by the Part E pcov side channel.

    Sends the payload with a fresh ``X-Fzl-Cov`` id and reads the covered app lines back,
    so a variant that reaches new application code scores coverage novelty.
    """
    from fuzzlab.greybox.coverage import FileCoverageSource, app_lines
    from fuzzlab.greybox.run import RequestsCorrelatingSender

    sender = RequestsCorrelatingSender(cookie=cookie)
    src = FileCoverageSource(cov_dir)
    include = (app_root.rstrip("/") + "/",)

    def cov(payload: str):
        _probe, cid = sender.send_correlated(url, param, payload,
                                             method=method, location=location)
        if settle:
            time.sleep(settle)
        return app_lines(src.lines_for(cid), include_prefixes=include)

    return cov


def run_mutation(*, url: str, param: str, store, run_id: int, sender,
                 bases: list[str], vuln_class: str = "sql-injection",
                 method: str = "GET", location: str = "query", coverage_fn=None,
                 seed: int = 0, budget: int = 40,
                 allow_destructive: bool = False) -> dict:
    """Search for a bypass per base; record the preserving evaders. Returns a summary."""
    flt = HttpFilter(sender, url, param, method=method, location=location)
    summary = {"bases": 0, "blocked": 0, "bypasses": 0, "recorded": 0, "results": []}
    for base in bases:
        base_blocked = flt.caught(base)
        search = MutationSearch(flt, coverage_fn=coverage_fn, seed=seed, budget=budget)
        res = search.search(base, vuln_class)
        bypass = bool(res.evaded and res.semantics_ok and base_blocked)
        recorded = None
        if bypass:
            base_hits = flt.evaluate(base).hits
            recorded = record_search_result(
                store, run_id, base, res, vuln_class,
                bypassed_rule=(",".join(base_hits) or None),
                allow_destructive=allow_destructive)
        summary["bases"] += 1
        summary["blocked"] += 1 if base_blocked else 0
        summary["bypasses"] += 1 if bypass else 0
        summary["recorded"] += 1 if recorded is not None else 0
        summary["results"].append({
            "base": base,
            "base_blocked": base_blocked,
            "variant": res.variant,
            "operators": list(res.operators),
            "evaded": res.evaded,
            "semantics_ok": res.semantics_ok,
            "novel_lines": res.novel_lines,
            "recorded_id": recorded,
        })
    return summary
