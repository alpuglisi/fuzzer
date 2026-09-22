#!/usr/bin/env bash
#
# Part D — Phase 2: automatic run + request-reduction measurement, end to end.
#
# Runs the runbook Part D activities against the lab you own on loopback:
#   1. Crawl, then run the detection benchmark (`fuzzlab auto --ground-truth`),
#      scored against the enumerated ground-truth points.
#   2. Optionally re-run with --browser to also confirm the DOM/stored-XSS points
#      (M6; set WITH_BROWSER=1).
#   3. D15 fail-safe check: a target with no --ground-truth and no --categories must
#      refuse loudly; with --categories it must run unscored.
#   4. Print the request-efficiency metrics, negatives, and target fingerprint.
#
# LAB-ONLY, loopback, on infrastructure you own. Sends real traffic; requires
# --authorized on every fuzzlab auto call. POST probing is state-changing on some
# endpoints (register/checkout/add_to_cart) — this script resets the lab DB between
# the scored and fail-safe runs for clean, comparable results.
#
# Env knobs (optional):
#   PFF_WEB_PORT     lab web port (default 8080)
#   GT_DIR           ground-truth contract dir (default lab/ground-truth)
#   AUTO_STORE       store for the scored benchmark run (default auto.db)
#   WITH_BROWSER=1   also run the --browser pass (needs Playwright on-host)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${PFF_WEB_PORT:-8080}"
LAB="http://127.0.0.1:${PORT}"
GT_DIR="${GT_DIR:-lab/ground-truth}"
STORE="${AUTO_STORE:-auto.db}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
command -v fuzzlab >/dev/null 2>&1 && FUZZLAB=(fuzzlab) || FUZZLAB=(python -m fuzzlab.cli)

curl -fs -o /dev/null "${LAB}/" \
  || die "lab not reachable at ${LAB}/ (bring it up first: cd lab && ./labctl.sh up)"
[ -d "${GT_DIR}" ] || die "ground-truth dir not found: ${GT_DIR}"

# --- 1. detection benchmark ---------------------------------------------------
say "1/4  Crawl + detection benchmark (fuzzlab auto --ground-truth) into ${STORE}"
rm -f "${STORE}" spider_results.db
"${FUZZLAB[@]}" crawl --start "${LAB}" --db spider_results.db
"${FUZZLAB[@]}" auto --base-url "${LAB}" --spider-db spider_results.db \
  --store "${STORE}" --ground-truth "${GT_DIR}" --authorized

# --- 2. optional browser pass (M6) --------------------------------------------
if [ "${WITH_BROWSER:-0}" = "1" ]; then
  say "2/4  Re-running with --browser (DOM/stored XSS, M6)"
  ( cd lab && ./labctl.sh reset )        # POST probing is state-changing
  "${FUZZLAB[@]}" auto --base-url "${LAB}" --spider-db spider_results.db \
    --store "${STORE}" --ground-truth "${GT_DIR}" --browser --authorized
  echo "  expect reviews.php#author and feedback.php?ref (xss-dom) now confirmed;"
  echo "  the 'not audited' list in the summary above should be empty."
else
  say "2/4  Skipping --browser pass (set WITH_BROWSER=1 to also confirm DOM/stored XSS)"
fi

# --- 3. D15 fail-safe check ----------------------------------------------------
say "3/4  D15 no-ground-truth fail-safe check"
( cd lab && ./labctl.sh reset )          # POST probing is state-changing
if "${FUZZLAB[@]}" auto --base-url "${LAB}" --spider-db spider_results.db \
     --store fail_safe_check.db --authorized 2>/tmp/auto_failsafe_out.txt; then
  die "expected 'auto' with no --ground-truth and no --categories to refuse loudly, but it exited 0"
fi
grep -qi "categories" /tmp/auto_failsafe_out.txt \
  || die "refusal message did not mention --categories: $(cat /tmp/auto_failsafe_out.txt)"
echo "  OK: refused loudly without --ground-truth/--categories, as D15 requires."
echo "  Running the same target with --categories (must succeed, unscored):"
"${FUZZLAB[@]}" auto --base-url "${LAB}" --spider-db spider_results.db \
  --store fail_safe_check.db --categories sql-injection --authorized
rm -f fail_safe_check.db /tmp/auto_failsafe_out.txt

# --- 4. request-efficiency + negatives + fingerprint --------------------------
say "4/4  Request-efficiency metrics, negatives, target fingerprint"
python - "$STORE" <<'PY'
import sys
from fuzzlab.core.store import Store
with Store(sys.argv[1]) as s:
    print("  pipeline_* metrics:")
    for r in s.conn.execute(
            "SELECT key, value FROM run_metrics WHERE key LIKE 'pipeline_%' ORDER BY key"):
        print(f"    {r['key']} = {r['value']}")
    fired = dict(s.conn.execute(
        "SELECT fired, COUNT(*) c FROM evaluation GROUP BY fired").fetchall())
    print(f"  evaluations: {fired.get(1, 0)} fired, {fired.get(0, 0)} negatives")
    tgt = s.conn.execute(
        "SELECT base_url, dbms, framework, waf FROM target ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if tgt:
        print(f"  fingerprint: {tgt['base_url']} dbms={tgt['dbms']} "
              f"framework={tgt['framework']} waf={tgt['waf']}")
PY
echo
echo "  Compare pipeline_requests_per_finding above against a Phase-1 baseline"
echo "  (a standalone 'fuzzlab fuzz' run's request count for the same findings) —"
echo "  the Phase 2 exit is measurably fewer requests. Expect fp=0 on every secure"
echo "  control and tp~4-5 on the known-vulnerable points."
