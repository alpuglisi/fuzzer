#!/usr/bin/env bash
#
# Part H — Phase 7: ranker + active learning, end to end (T7.4).
#
# Runs the runbook Part H activities against the lab you own on loopback:
#   1. Crawl + `fuzzlab auto --rank` to train the pointwise ranker (zero extra
#      requests) and score ordering vs a random baseline.
#   2. Print rank_ndcg/rank_precision vs their random-baseline counterparts (the
#      exit criterion) and the top ranked candidates.
#   3. Propose the most informative next candidates to confirm (active learning,
#      library-only — no CLI flag), by uncertainty sampling and by committee.
#
# LAB-ONLY, loopback, on infrastructure you own. Sends real traffic; requires
# --authorized.
#
# Env knobs (optional):
#   PFF_WEB_PORT   lab web port (default 8080)
#   GT_DIR         ground-truth contract dir (default lab/ground-truth)
#   RANK_STORE     store for the ranked run (default auto.db)
#   AL_BUDGET      active-learning query budget (default 5)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${PFF_WEB_PORT:-8080}"
LAB="http://127.0.0.1:${PORT}"
GT_DIR="${GT_DIR:-lab/ground-truth}"
STORE="${RANK_STORE:-auto.db}"
AL_BUDGET="${AL_BUDGET:-5}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
command -v fuzzlab >/dev/null 2>&1 && FUZZLAB=(fuzzlab) || FUZZLAB=(python -m fuzzlab.cli)

curl -fs -o /dev/null "${LAB}/" \
  || die "lab not reachable at ${LAB}/ (bring it up first: cd lab && ./labctl.sh up)"
[ -d "${GT_DIR}" ] || die "ground-truth dir not found: ${GT_DIR}"

# --- 1. crawl + rank ------------------------------------------------------------
say "1/3  crawl + auto --rank into ${STORE}"
[ -d lab ] && ( cd lab && ./labctl.sh reset ) || true
rm -f spider_results.db
"${FUZZLAB[@]}" crawl --start "${LAB}" --db spider_results.db
"${FUZZLAB[@]}" auto --base-url "${LAB}" --spider-db spider_results.db \
  --store "${STORE}" --ground-truth "${GT_DIR}" --rank --authorized

# --- 2. rank metrics + top candidates --------------------------------------------
say "2/3  rank_ndcg/rank_precision vs the random baseline; top ranked candidates"
sqlite3 -header -column "${STORE}" \
  "SELECT key, value FROM run_metrics WHERE key LIKE 'rank_%' ORDER BY key;"
python - "$STORE" <<'PY'
import sys
from fuzzlab.core.store import Store
with Store(sys.argv[1]) as s:
    m = dict(s.conn.execute(
        "SELECT key, value FROM run_metrics WHERE key LIKE 'rank_%'").fetchall())
    ndcg, ndcg_r = m.get("rank_ndcg"), m.get("rank_ndcg_random")
    prec, prec_r = m.get("rank_precision"), m.get("rank_precision_random")
    if ndcg is not None and ndcg_r is not None:
        print(f"  rank_ndcg={ndcg} vs random={ndcg_r} "
              f"-> {'PASS' if ndcg > ndcg_r else 'BELOW BASELINE'}")
    if prec is not None and prec_r is not None:
        print(f"  rank_precision={prec} vs random={prec_r} "
              f"-> {'PASS' if prec >= prec_r else 'BELOW BASELINE'}")
PY
sqlite3 -header -column "${STORE}" \
  "SELECT id, round(rank_score,3), round(rank_uncertainty,3) FROM candidate \
   WHERE run_id=(SELECT MAX(id) FROM run) AND rank_score IS NOT NULL \
   ORDER BY rank_score DESC LIMIT 10;"

# --- 3. active learning: what to confirm next ------------------------------------
say "3/3  Active learning: most informative candidates to confirm next (budget ${AL_BUDGET})"
python - "$STORE" "$AL_BUDGET" <<'PY'
import sys
from fuzzlab.core.store import Store
from fuzzlab.ml.active import propose_queries
with Store(sys.argv[1]) as s:
    rid = s.conn.execute("SELECT MAX(id) FROM run").fetchone()[0]
    budget = int(sys.argv[2])
    print("  uncertainty:", propose_queries(s, rid, budget=budget, method="uncertainty"))
    print("  committee:  ", propose_queries(s, rid, budget=budget, method="committee"))
PY
echo
echo "  Exit (T7.4): rank_ndcg > rank_ndcg_random (and rank_precision >= rank_precision_random)."
