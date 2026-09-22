#!/usr/bin/env bash
#
# Part G — Phase 5: detection classifier beats baselines, end to end (T5.5).
#
# Runs the runbook Part G activities against the lab you own on loopback:
#   1. Crawl + `fuzzlab auto --score` to train the detection classifier over the
#      store and write advisory candidate scores (never labels).
#   2. Print ml_pr_auc vs its prevalence/sigma baselines (the exit criterion).
#   3. Print the top advisory-scored candidates.
#
# LAB-ONLY, loopback, on infrastructure you own. Sends real traffic; requires
# --authorized. Thin-data note: one run may not have enough confirmed positives to
# train (the model then reports 'prevalence-fallback' and skips PR-AUC) — set
# SCORE_STORE to an existing store from prior runs (or CLASSIFIER_REPEATS > 1) to
# accumulate candidates/findings first.
#
# Env knobs (optional):
#   PFF_WEB_PORT        lab web port (default 8080)
#   GT_DIR              ground-truth contract dir (default lab/ground-truth)
#   SCORE_STORE          store to accumulate into (default auto.db)
#   CLASSIFIER_REPEATS   how many crawl+auto passes to accumulate first (default 1)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${PFF_WEB_PORT:-8080}"
LAB="http://127.0.0.1:${PORT}"
GT_DIR="${GT_DIR:-lab/ground-truth}"
STORE="${SCORE_STORE:-auto.db}"
REPEATS="${CLASSIFIER_REPEATS:-1}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
command -v fuzzlab >/dev/null 2>&1 && FUZZLAB=(fuzzlab) || FUZZLAB=(python -m fuzzlab.cli)

curl -fs -o /dev/null "${LAB}/" \
  || die "lab not reachable at ${LAB}/ (bring it up first: cd lab && ./labctl.sh up)"
[ -d "${GT_DIR}" ] || die "ground-truth dir not found: ${GT_DIR}"

# --- 1. crawl + score, accumulated over REPEATS passes ------------------------
say "1/3  crawl + auto --score, ${REPEATS} pass(es), accumulating into ${STORE}"
for i in $(seq 1 "${REPEATS}"); do
  echo "  -- pass ${i}/${REPEATS} --"
  [ -d lab ] && ( cd lab && ./labctl.sh reset ) || true
  rm -f spider_results.db
  "${FUZZLAB[@]}" crawl --start "${LAB}" --db spider_results.db
  "${FUZZLAB[@]}" auto --base-url "${LAB}" --spider-db spider_results.db \
    --store "${STORE}" --ground-truth "${GT_DIR}" --score --authorized
done

# --- 2. PR-AUC vs baselines ----------------------------------------------------
say "2/3  ml_pr_auc vs its prevalence/sigma baselines"
sqlite3 -header -column "${STORE}" \
  "SELECT key, value FROM run_metrics WHERE key LIKE 'ml_pr_auc%' ORDER BY key;"
python - "$STORE" <<'PY'
import sys
from fuzzlab.core.store import Store
with Store(sys.argv[1]) as s:
    row_ids = dict(s.conn.execute(
        "SELECT key, value FROM run_metrics WHERE key LIKE 'ml_pr_auc%'").fetchall())
    if not row_ids:
        print("  no ml_pr_auc metrics recorded — thin-data fallback (see the header note)")
    else:
        auc = row_ids.get("ml_pr_auc")
        prevalence = row_ids.get("ml_pr_auc_prevalence")
        sigma = row_ids.get("ml_pr_auc_sigma")
        if auc is not None and prevalence is not None and sigma is not None:
            ok = auc > prevalence and auc > sigma
            print(f"  ml_pr_auc={auc} prevalence={prevalence} sigma={sigma} "
                  f"-> {'PASS' if ok else 'BELOW BASELINE'}")
PY

# --- 3. top advisory-scored candidates -----------------------------------------
say "3/3  Top advisory-scored candidates for the latest run"
sqlite3 -header -column "${STORE}" \
  "SELECT id, round(score,3) FROM candidate \
   WHERE run_id=(SELECT MAX(id) FROM run) AND score IS NOT NULL \
   ORDER BY score DESC LIMIT 10;"
echo
echo "  Exit (T5.5): ml_pr_auc > both ml_pr_auc_prevalence and ml_pr_auc_sigma."
echo "  If it reports model='prevalence-fallback', re-run with CLASSIFIER_REPEATS>1"
echo "  (or point SCORE_STORE at an existing store) to accumulate more confirmed"
echo "  positives before training."
