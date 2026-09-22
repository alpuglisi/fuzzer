#!/usr/bin/env bash
#
# Part L — Phase 10: plugins, anomaly, report, transfer, end to end.
#
# Runs the runbook Part L activities against the lab you own on loopback:
#   1. Plugins — crawl + `fuzzlab auto --plugins`; print the active plugin set
#      recorded per run (empty is fine with no plugin package installed; the
#      point is that it's recorded and a failing plugin would be contained, not
#      fatal).
#   2. Anomaly tripwire (ECOD, advisory) over the run's candidates.
#   3. Reproducible report for the run (human + canonical JSON).
#   4. Transfer to a second target (T10.6) — OPTIONAL, skipped unless
#      TRANSFER_BASE_URL and TRANSFER_GT_DIR are both set, since it needs a
#      second, already-running external validation lab (OWASP Juice Shop /
#      WAVSEP, per D10) with its own ground-truth contract.
#
# LAB-ONLY, loopback, on infrastructure you own. Sends real traffic; requires
# --authorized. `fuzzlab report` is read-only and sends nothing.
#
# Env knobs (optional):
#   PFF_WEB_PORT       lab web port (default 8080)
#   GT_DIR             ground-truth contract dir (default lab/ground-truth)
#   PLUGIN_STORE       store for the plugins/anomaly/report steps (default auto.db)
#   TRANSFER_BASE_URL  second target's base URL — set together with TRANSFER_GT_DIR
#                      to run step 4 (e.g. http://127.0.0.1:3000 for Juice Shop)
#   TRANSFER_GT_DIR    second target's ground-truth contract dir
#   TRANSFER_STORE     store for the transfer run (default transfer.db)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${PFF_WEB_PORT:-8080}"
LAB="http://127.0.0.1:${PORT}"
GT_DIR="${GT_DIR:-lab/ground-truth}"
STORE="${PLUGIN_STORE:-auto.db}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
command -v fuzzlab >/dev/null 2>&1 && FUZZLAB=(fuzzlab) || FUZZLAB=(python -m fuzzlab.cli)

curl -fs -o /dev/null "${LAB}/" \
  || die "lab not reachable at ${LAB}/ (bring it up first: cd lab && ./labctl.sh up)"
[ -d "${GT_DIR}" ] || die "ground-truth dir not found: ${GT_DIR}"

# --- 1. plugins ------------------------------------------------------------
say "1/4  crawl + auto --plugins into ${STORE}; active plugin set"
[ -d lab ] && ( cd lab && ./labctl.sh reset ) || true
rm -f spider_results.db
"${FUZZLAB[@]}" crawl --start "${LAB}" --db spider_results.db
"${FUZZLAB[@]}" auto --base-url "${LAB}" --spider-db spider_results.db \
  --store "${STORE}" --ground-truth "${GT_DIR}" --plugins --authorized
sqlite3 -header -column "${STORE}" \
  "SELECT name, version, priority FROM run_plugin \
   WHERE run_id=(SELECT MAX(id) FROM run);"
echo "  (empty is expected with no fuzzlab.plugins entry point installed)"

# --- 2. anomaly tripwire -----------------------------------------------------
say "2/4  Anomaly tripwire (ECOD, advisory) over the run's candidates"
python - "$STORE" <<'PY'
import sys
from fuzzlab.core.store import Store
from fuzzlab.ml.anomaly import detect_anomalies
with Store(sys.argv[1]) as s:
    rid = s.conn.execute("SELECT MAX(id) FROM run").fetchone()[0]
    print(" ", detect_anomalies(s, rid, contamination=0.1))
PY

# --- 3. reproducible report --------------------------------------------------
say "3/4  Reproducible report (read-only; sends nothing)"
"${FUZZLAB[@]}" report --store "${STORE}"
"${FUZZLAB[@]}" report --store "${STORE}" --json > "${STORE%.db}_report.json"
echo "  canonical JSON saved to ${STORE%.db}_report.json"

# --- 4. transfer to a second target (optional) --------------------------------
if [ -n "${TRANSFER_BASE_URL:-}" ] && [ -n "${TRANSFER_GT_DIR:-}" ]; then
  say "4/4  Transfer (T10.6): ${LAB} vs ${TRANSFER_BASE_URL}"
  [ -d "${TRANSFER_GT_DIR}" ] || die "TRANSFER_GT_DIR not found: ${TRANSFER_GT_DIR}"
  curl -fs -o /dev/null "${TRANSFER_BASE_URL}/" \
    || die "second target not reachable at ${TRANSFER_BASE_URL}/"
  TRANSFER_STORE="${TRANSFER_STORE:-transfer.db}" \
  python - "$LAB" "$GT_DIR" "$TRANSFER_BASE_URL" "$TRANSFER_GT_DIR" <<'PY'
import os, sys
from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary, format_transfer
from fuzzlab.labels import contract
from fuzzlab.tools.probesender import make_probe_sender

pff_url, pff_gt, other_url, other_gt = sys.argv[1:5]
specs = [
    TargetSpec("pff", pff_url, ground_truth=contract.load(pff_gt), points_source="ground-truth"),
    TargetSpec("other", other_url, ground_truth=contract.load(other_gt), points_source="ground-truth"),
]
store_path = os.environ.get("TRANSFER_STORE", "transfer.db")
with Store(store_path) as s:
    outs = run_targets(specs, s, sender_for=lambda spec: make_probe_sender(spec.base_url, None))
    print(format_transfer(transfer_summary(outs)))
PY
  echo "  Exit: non-trivial recall on the second target (generalizes=True)."
else
  say "4/4  Skipping transfer (T10.6) — set TRANSFER_BASE_URL and TRANSFER_GT_DIR"
  echo "  to a second, already-running validation lab (e.g. OWASP Juice Shop) to run it."
fi
