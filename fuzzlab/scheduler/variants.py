"""Mutation-variant candidate source (SCHED/MUT bridge, Phase 8 wiring gap close).

The mutation engine (MUT, `fuzzlab/mutation/{run.py,catalog.py}`) writes accepted
variants' provenance to the `payload_variant` table (migration 8) — but until this
module existed, nothing downstream read those rows back in as candidates for the
live attempt path. `attempt` rows only ever came from the grey-box driver's fixed
`DEFAULT_PROBES` (`fuzzlab/greybox/run.py`); `payload_variant` was write-only.

This mirrors the existing catalog candidate-source seam in `scheduler/context.py`
(`catalog_families`/`catalog_priors`, which read the static `references/<cat>/
payloads/*.txt` catalogs) — but reads the mutation engine's **DB-backed** catalog
instead of files, with the same "family list, optionally scoped" shape. Callers
(the grey-box/fuzzer attempt path) add these candidates **alongside**, never in
place of, the existing catalog/default probes (FR-SCHED-9 / FR-MUT-8).

Nothing here sends a request by itself — it only reads rows and builds
`greybox.run.ProbeSpec` values for a caller to pass into `run_greybox`, which (via
`fuzlab greybox-run`) is already gated on `--authorized` like every other
request-sending path in this project (D11). See `--mutation-variants` in
`fuzzlab/greybox/greybox_cli.py`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

# Kind used by `greybox.run._screening` to score the black-box hit signal; a variant
# whose vuln_class doesn't map to a known kind still runs (and still earns coverage/
# db-fault reward), it just scores 0 on the coarse screening tier.
_KIND_BY_VULN_PREFIX = (
    ("sqli", "sqli"),
    ("xss", "xss"),
)


def _kind_for(vuln_class: str | None) -> str:
    vc = (vuln_class or "").lower()
    for prefix, kind in _KIND_BY_VULN_PREFIX:
        if vc.startswith(prefix):
            return kind
    return "other"


@dataclass(frozen=True)
class VariantCandidate:
    """One `payload_variant` row, as a candidate (mirrors `mutation.catalog.list_variants`
    but filterable/scoped like a candidate source, not a raw dump)."""
    id: int
    run_id: int | None
    vuln_class: str
    base_payload: str
    variant: str
    operators: list[str] = field(default_factory=list)
    sink_context: str | None = None
    bypassed_rule: str | None = None
    coverage_gain: float | None = None


def load_variant_candidates(store, *, vuln_class: str | None = None,
                            vuln_classes: "list[str] | None" = None,
                            sink_context: str | None = None,
                            semantics_ok_only: bool = True,
                            run_id: int | None = None,
                            limit: int | None = None) -> list[VariantCandidate]:
    """Read `payload_variant` rows as candidates, optionally scoped.

    Scoping mirrors how the existing candidate source scopes by category/reference
    (`catalog_families(reference, ...)`): here the equivalent scope keys are
    ``vuln_class``/``vuln_classes`` (target class) and ``sink_context`` (injection
    point). ``run_id`` narrows to one mutation run; omit it to pool variants across
    every run recorded so far (the default — a fresh fuzz run has produced none of
    its own yet). ``semantics_ok_only`` (default True) excludes any row whose stored
    `semantics_ok` verdict is false — belt-and-braces alongside FR-MUT-7's fail-closed
    validator, for a consumer that only sees the stored verdict, not the validator
    itself. ``limit`` bounds how many variants are pulled in (newest first), since a
    long-running lab session can accumulate many.
    """
    classes = list(vuln_classes) if vuln_classes else ([vuln_class] if vuln_class else None)
    where: list[str] = []
    args: list = []
    if run_id is not None:
        where.append("run_id = ?")
        args.append(run_id)
    if classes:
        where.append(f"vuln_class IN ({','.join('?' * len(classes))})")
        args.extend(classes)
    if sink_context is not None:
        where.append("sink_context = ?")
        args.append(sink_context)
    if semantics_ok_only:
        where.append("semantics_ok = 1")
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    sql = f"SELECT * FROM payload_variant {clause} ORDER BY id DESC"
    if limit is not None:
        sql += " LIMIT ?"
        args.append(int(limit))
    rows = store.conn.execute(sql, args).fetchall()
    out: list[VariantCandidate] = []
    for r in rows:
        d = dict(r)
        out.append(VariantCandidate(
            id=d["id"], run_id=d.get("run_id"), vuln_class=d.get("vuln_class") or "",
            base_payload=d["base_payload"], variant=d["variant"],
            operators=json.loads(d.get("operators") or "[]"),
            sink_context=d.get("sink_context"), bypassed_rule=d.get("bypassed_rule"),
            coverage_gain=d.get("coverage_gain")))
    return out


def variant_probe_specs(store, *, family_prefix: str = "mut", **kwargs):
    """`payload_variant` rows as `greybox.run.ProbeSpec`s for the live attempt path.

    Each variant is its own arm, ``"<family_prefix>:<vuln_class>:<row id>"`` — distinct
    per row so a resulting `attempt.payload_family` traces back to the exact
    `payload_variant` row (``SELECT * FROM payload_variant WHERE id = <the trailing
    id>``). Additive by design: the caller appends these to (never replaces) the
    existing default/catalog probes passed to `run_greybox`. Accepts every keyword
    `load_variant_candidates` does (scoping/limit).
    """
    from fuzzlab.greybox.run import ProbeSpec   # local import: avoid a hard MUT/SCHED->greybox cycle

    candidates = load_variant_candidates(store, **kwargs)
    return [ProbeSpec(family=f"{family_prefix}:{c.vuln_class or 'unknown'}:{c.id}",
                      value=c.variant, kind=_kind_for(c.vuln_class))
            for c in candidates]
