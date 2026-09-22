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
                 allow_destructive: bool = False, oracle=None) -> dict:
    """Search for a bypass per base; record the preserving evaders. Returns a summary.

    ``oracle`` (optional, CC-MUT-0006 nice-to-have): when given, a recorded bypass is
    also checked with ``Oracle.confirm()`` at the same (url, param, method, location),
    scoped to ``vuln_class`` as the confirmation category. This is an **independent**
    re-check via the oracle's own strategies, not a literal replay of the accepted
    variant string — a `ConfirmationStrategy` crafts its own probe payload per class, it
    does not take an arbitrary caller-supplied payload — so it answers "does the oracle
    also confirm this class of vulnerability at this endpoint," a related but distinct
    question from "did this exact variant trigger it." The oracle remains the sole
    finding-writer (`finding` rows only ever come from `Oracle.confirm`, never written
    here) — mutation stays advisory, matching M10's existing advisory/oracle split
    (CC-FUZZ-0016). Never runs when `oracle` is omitted (default): behavior unchanged.
    """
    flt = HttpFilter(sender, url, param, method=method, location=location)
    summary = {"bases": 0, "blocked": 0, "bypasses": 0, "recorded": 0,
              "oracle_confirmed": 0, "results": []}
    for base in bases:
        base_blocked = flt.caught(base)
        search = MutationSearch(flt, coverage_fn=coverage_fn, seed=seed, budget=budget,
                                store=store, run_id=run_id)
        res = search.search(base, vuln_class)
        bypass = bool(res.evaded and res.semantics_ok and base_blocked)
        recorded = None
        oracle_confirmed = None
        if bypass:
            base_hits = flt.evaluate(base).hits
            recorded = record_search_result(
                store, run_id, base, res, vuln_class,
                bypassed_rule=(",".join(base_hits) or None),
                allow_destructive=allow_destructive)
            if oracle is not None:
                from fuzzlab.oracle.probe import Candidate
                candidate = Candidate(url=url, param=param, method=method,
                                      location=location, category=vuln_class)
                verdict = oracle.confirm(candidate, sender)
                oracle_confirmed = bool(verdict is not None and verdict.confirmed)
        summary["bases"] += 1
        summary["blocked"] += 1 if base_blocked else 0
        summary["bypasses"] += 1 if bypass else 0
        summary["recorded"] += 1 if recorded is not None else 0
        summary["oracle_confirmed"] += 1 if oracle_confirmed else 0
        summary["results"].append({
            "base": base,
            "base_blocked": base_blocked,
            "variant": res.variant,
            "operators": list(res.operators),
            "evaded": res.evaded,
            "semantics_ok": res.semantics_ok,
            "novel_lines": res.novel_lines,
            "recorded_id": recorded,
            "oracle_confirmed": oracle_confirmed,
        })
    return summary
