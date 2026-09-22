#!/usr/bin/env bash
#
# Part F — Phase 4: bandit orders the oracle's mechanisms, end to end (T4.6).
#
# Runs the runbook Part F activities against the lab you own on loopback:
#   1. Control run (fixed mechanism order, no --bandit).
#   2. Bandit runs (--bandit), repeated into ONE store so posteriors accumulate.
#   3. Print what the bandit learned (posterior means per context/arm) — per the
#      BUG-0016 metric caveat, verify the bandit by what it LEARNS, not by
#      pipeline_requests_per_finding, which is dominated by discovery on this
#      small lab and won't move much even when the bandit is working correctly.
#
# LAB-ONLY, loopback, on infrastructure you own. Sends real traffic; every
# `fuzzlab auto` call requires --authorized. POST probing is state-changing, so
# the lab DB is reset before each bandit repetition.
#
# Env knobs (optional):
#   PFF_WEB_PORT     lab web port (default 8080)
#   GT_DIR           ground-truth contract dir (default lab/ground-truth)
#   CONTROL_STORE    control-run store (default base.db)
#   BANDIT_STORE     bandit-runs store, accumulated across repeats (default bandit.db)
#   BANDIT_REPEATS   how many times to repeat the bandit run (default 5)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${PFF_WEB_PORT:-8080}"
LAB="http://127.0.0.1:${PORT}"
GT_DIR="${GT_DIR:-lab/ground-truth}"
CONTROL_STORE="${CONTROL_STORE:-base.db}"
BANDIT_STORE="${BANDIT_STORE:-bandit.db}"
REPEATS="${BANDIT_REPEATS:-5}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
command -v fuzzlab >/dev/null 2>&1 && FUZZLAB=(fuzzlab) || FUZZLAB=(python -m fuzzlab.cli)

curl -fs -o /dev/null "${LAB}/" \
  || die "lab not reachable at ${LAB}/ (bring it up first: cd lab && ./labctl.sh up)"
[ -d "${GT_DIR}" ] || die "ground-truth dir not found: ${GT_DIR}"
[ -d lab ] || die "expected a ./lab directory with labctl.sh (run from the repo root)"

# --- 1. control run (fixed order) ---------------------------------------------
say "1/3  Control run (fixed mechanism order, no --bandit) into ${CONTROL_STORE}"
( cd lab && ./labctl.sh reset )
rm -f "${CONTROL_STORE}" spider_results.db
"${FUZZLAB[@]}" crawl --start "${LAB}" --db spider_results.db
"${FUZZLAB[@]}" auto --base-url "${LAB}" --spider-db spider_results.db \
  --store "${CONTROL_STORE}" --ground-truth "${GT_DIR}" --authorized
sqlite3 "${CONTROL_STORE}" \
  "SELECT value FROM run_metrics WHERE key='pipeline_requests_per_finding';"

# --- 2. bandit runs, repeated into one store ----------------------------------
say "2/3  Bandit runs (--bandit), repeated ${REPEATS}x into ${BANDIT_STORE}"
rm -f "${BANDIT_STORE}"
for i in $(seq 1 "${REPEATS}"); do
  echo "  -- repeat ${i}/${REPEATS} --"
  ( cd lab && ./labctl.sh reset )        # POST probes are state-changing
  "${FUZZLAB[@]}" auto --base-url "${LAB}" --spider-db spider_results.db \
    --store "${BANDIT_STORE}" --ground-truth "${GT_DIR}" --bandit --authorized
done
sqlite3 "${BANDIT_STORE}" "SELECT id,value FROM run_metrics \
  WHERE key='pipeline_requests_per_finding' ORDER BY id;"

# --- 3. what the bandit learned -----------------------------------------------
say "3/3  Posteriors: the arm with the highest mean per context is what confirms there"
sqlite3 -header -column "${BANDIT_STORE}" \
  "SELECT context, arm, round(alpha/(alpha+beta),3) AS mean, cost_n \
   FROM bandit_posteriors ORDER BY mean DESC LIMIT 10;"
echo
echo "  Exit (T4.6): the top arm for sql-injection:query should be sqli:error-signature,"
echo "  well above the timing arms. pipeline_requests_per_finding staying flat vs the"
echo "  control is EXPECTED here (BUG-0016 metric caveat) — the bandit optimizes oracle"
echo "  probes, which this small lab's discovery-dominated request count doesn't surface."
