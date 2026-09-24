#!/usr/bin/env bash
# on_host_full_run.sh — run every deferred on-host task from
# docs/ON_HOST_TASKS.md / docs/ON_HOST_RUNBOOK.md, in order, and append each
# task's output (commands run + their stdout/stderr + the runbook's own
# follow-up sqlite3/python read-back queries) to one evaluation log.
#
# This CANNOT be run in the sandbox that built this repo (no container
# daemon, no live target — see docs/ON_HOST_TASKS.md's own "why deferred").
# Run it on the Fedora host that has the containerized lab, per
# docs/ON_HOST_RUNBOOK.md Parts A/B (bring up the lab, install the toolkit)
# BEFORE running this script — it assumes both are already done, exactly
# like every runbook Part below Part B does.
#
# Every command below is copied from docs/ON_HOST_RUNBOOK.md verbatim (same
# flags, same store names) so this script's own commands and that document
# never drift apart — if you change one, change the other.
#
# Design: never aborts on a failing task (a real eval run wants to see every
# part's result, not stop at the first one that needs attention). Each task's
# section in the log starts with a timestamp and ends with PASS/FAIL/SKIP so
# the log is greppable (`grep '^=== ' on_host_results.txt`).
#
# Usage:
#   scripts/on_host_full_run.sh                # run everything
#   scripts/on_host_full_run.sh --only E,J      # run just Part(s) E and J
#   scripts/on_host_full_run.sh --skip K,L      # run everything except K, L
#   OUT_FILE=my_run.txt scripts/on_host_full_run.sh
#
# Env knobs (all optional, same names/defaults as the runbook):
#   OUT_FILE        default: on_host_results.txt (repo root, appended to)
#   LAB_DIR         default: lab
#   PFF_WEB_PORT    default: 8080
#   BASE_URL        default: http://127.0.0.1:${PFF_WEB_PORT}
#   IDENTITY        default: admin      (test accounts: admin/admin123,
#                                        alice/password1, bob/letmein)
#   IDENTITY_USER   default: admin
#   IDENTITY_PASS   default: admin123   (lab-only throwaway credential)
#   PROXY_PORT      default: 8888
#   CA_DIR          default: ~/.fuzzlab/ca
#   FZL_COV_DIR     default: /tmp/fzl-cov
#   WAF_MODE        default: block
#   JUICE_BASE_URL  unset by default -> Part L's transfer step is SKIPPED
#                   (needs a second, external validation lab per D10; set
#                   this plus JUICE_GROUND_TRUTH to run it)
#   JUICE_GROUND_TRUTH  path to that lab's ground-truth contract dir

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT_FILE="${OUT_FILE:-on_host_results.txt}"
LAB_DIR="${LAB_DIR:-lab}"
PFF_WEB_PORT="${PFF_WEB_PORT:-8080}"
BASE_URL="${BASE_URL:-http://127.0.0.1:${PFF_WEB_PORT}}"
IDENTITY="${IDENTITY:-admin}"
IDENTITY_USER="${IDENTITY_USER:-admin}"
IDENTITY_PASS="${IDENTITY_PASS:-admin123}"
PROXY_PORT="${PROXY_PORT:-8888}"
CA_DIR="${CA_DIR:-$HOME/.fuzzlab/ca}"
FZL_COV_DIR="${FZL_COV_DIR:-/tmp/fzl-cov}"
WAF_MODE="${WAF_MODE:-block}"
GT_DIR="lab/ground-truth"

# --- --only / --skip filtering -------------------------------------------
ONLY=""
SKIP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    --skip) SKIP="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

should_run() {
  local part="$1"
  if [ -n "$ONLY" ]; then
    [[ ",$ONLY," == *",$part,"* ]] && return 0 || return 1
  fi
  if [ -n "$SKIP" ]; then
    [[ ",$SKIP," == *",$part,"* ]] && return 1 || return 0
  fi
  return 0
}

# --- logging ----------------------------------------------------------------
log_header() {
  {
    echo ""
    echo "===================================================================="
    echo "=== $(date -u +'%Y-%m-%dT%H:%M:%SZ') RUN START — on_host_full_run.sh"
    echo "=== repo: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "=== base_url=$BASE_URL identity=$IDENTITY"
    echo "===================================================================="
  } >>"$OUT_FILE"
}

# run_task NAME PART -- runs the rest of argv as a command, appends a
# section to $OUT_FILE with the command, its combined output, exit code and
# a PASS/FAIL verdict, then returns 0 regardless (so the sequence continues).
run_task() {
  local name="$1" part="$2"; shift 2
  if ! should_run "$part"; then
    {
      echo ""
      echo "--- [$(date -u +'%Y-%m-%dT%H:%M:%SZ')] Part $part: $name -- SKIPPED (filtered by --only/--skip)"
    } >>"$OUT_FILE"
    echo "[skip] Part $part: $name"
    return 0
  fi
  echo "[run ] Part $part: $name"
  {
    echo ""
    echo "--- [$(date -u +'%Y-%m-%dT%H:%M:%SZ')] Part $part: $name"
    echo "--- command: $*"
    echo "--- output:"
  } >>"$OUT_FILE"
  local start end rc
  start=$(date +%s)
  # A subshell, not a `{ }` group: a task command that itself calls `exit`
  # (a stray `exit` in an eval'd string, or a sourced snippet) must only end
  # that one task, never this whole driver script.
  # shellcheck disable=SC2068
  ( eval "$@" ) >>"$OUT_FILE" 2>&1
  rc=$?
  end=$(date +%s)
  {
    echo "--- exit_code=$rc duration_s=$((end - start))"
    if [ "$rc" -eq 0 ]; then
      echo "=== Part $part: $name -- PASS"
    else
      echo "=== Part $part: $name -- FAIL (exit $rc)"
    fi
  } >>"$OUT_FILE"
  if [ "$rc" -eq 0 ]; then echo "[ ok ] Part $part: $name"; else echo "[FAIL] Part $part: $name (exit $rc)"; fi
  return 0
}

# run_sql STORE QUERY LABEL -- read-back helper, logged the same way, never
# fatal if the store/table doesn't exist yet (a skipped/failed prior task).
run_sql() {
  local store="$1" query="$2" label="$3"
  {
    echo ""
    echo "--- read-back: $label ($store)"
    echo "--- query: $query"
  } >>"$OUT_FILE"
  sqlite3 "$store" "$query" >>"$OUT_FILE" 2>&1 || echo "(no data -- store/table missing, likely because the producing task above did not complete)" >>"$OUT_FILE"
}

log_header

# ============================================================================
# Part A — bring up the lab, verify the DB fix
# ============================================================================
run_task "bring up the containerized lab" A \
  "(cd '$LAB_DIR' && ./labctl.sh up && ./labctl.sh status)"

run_task "verify DB connection (BUG-0004: pff user, not root)" A \
  "curl -sS '$BASE_URL/product.php?id=1' | head -20"

# ============================================================================
# Part C — Phase 1: authenticated per-identity run
# ============================================================================
run_task "save credential for $IDENTITY@127.0.0.1" C \
  "printf '%s\n' '$IDENTITY_PASS' | fuzzlab session set-credential --host 127.0.0.1 --identity '$IDENTITY' --username '$IDENTITY_USER'"

run_task "confirm login detection prints a session header" C \
  "fuzzlab session print --host 127.0.0.1 --identity '$IDENTITY' --base-url '$BASE_URL/'"

run_task "crawl (identity=$IDENTITY)" C \
  "fuzzlab crawl --start '$BASE_URL' --store run.db --identity '$IDENTITY'"

run_task "audit (identity=$IDENTITY)" C \
  "fuzzlab audit --spider-db spider_results.db --store run.db --identity '$IDENTITY' --base-url '$BASE_URL/'"

run_task "fuzz product.php?id (identity=$IDENTITY)" C \
  "fuzzlab fuzz --url '$BASE_URL/product.php' --param id --store run.db --identity '$IDENTITY' --authorized"

{
  echo ""
  echo "--- NOTE: the runbook's Part C.4 (two-lab validation across cookie vs"
  echo "    JWT auth) needs a SECOND lab/host and is not attempted by this"
  echo "    script -- run it by hand against that second host if you have one."
} >>"$OUT_FILE"

# ============================================================================
# Part D — Phase 2: automatic run + request-reduction measurement
# ============================================================================
run_task "crawl for auto's spider-db" D \
  "fuzzlab crawl --start '$BASE_URL' --db spider_results.db"

run_task "auto: detection benchmark (ground-truth, unauthenticated)" D \
  "fuzzlab auto --base-url '$BASE_URL' --spider-db spider_results.db --store auto.db --ground-truth '$GT_DIR' --authorized"

run_task "reset lab before the stateful browser run" D \
  "(cd '$LAB_DIR' && ./labctl.sh reset)"

run_task "auto: detection benchmark + browser (M6 DOM/stored XSS)" D \
  "fuzzlab auto --base-url '$BASE_URL' --spider-db spider_results.db --store auto.db --ground-truth '$GT_DIR' --browser --authorized"

run_task "fail-safe check (D15): no ground-truth, no categories -> must refuse" D \
  "fuzzlab auto --base-url '$BASE_URL' --spider-db spider_results.db --store t.db --authorized; echo '(a non-zero/error exit above is the EXPECTED pass condition for this fail-safe check)'"

run_task "fail-safe check (D15): --categories given -> unscored run proceeds" D \
  "fuzzlab auto --base-url '$BASE_URL' --spider-db spider_results.db --store t.db --categories sql-injection --authorized"

run_sql auto.db "SELECT key,value FROM run_metrics WHERE key LIKE 'pipeline_%';" "Part D: pipeline request metrics"
run_sql auto.db "SELECT fired, COUNT(*) FROM evaluation GROUP BY fired;" "Part D: fired vs negatives (0=negative)"
run_sql auto.db "SELECT dbms, framework FROM target;" "Part D: target fingerprint"

# ============================================================================
# Part E — Phase 3: grey-box instrumentation (single script)
# ============================================================================
run_task "greybox e2e (T3.1-T3.7)" E "scripts/greybox_e2e.sh"

run_sql greybox.db "SELECT id, payload_family, round(reward,3) AS reward, db_fault FROM attempt WHERE run_id=(SELECT MAX(id) FROM run WHERE tool='greybox') ORDER BY reward DESC LIMIT 10;" "Part E: attempt rewards (T3.7 exit check)"

# ============================================================================
# Part F — Phase 4: bandit scheduler (control vs bandit)
# ============================================================================
run_task "bandit control run (fixed order, no --bandit)" F \
  "fuzzlab auto --base-url '$BASE_URL' --spider-db spider_results.db --store base.db --ground-truth '$GT_DIR' --authorized"

run_sql base.db "SELECT value FROM run_metrics WHERE key='pipeline_requests_per_finding';" "Part F: control pipeline_requests_per_finding"

run_task "bandit accumulation runs (x5, one shared store)" F \
  "for i in 1 2 3 4 5; do ( cd '$LAB_DIR' && ./labctl.sh reset ); fuzzlab auto --base-url '$BASE_URL' --spider-db spider_results.db --store bandit.db --ground-truth '$GT_DIR' --bandit --authorized; done"

run_sql bandit.db "SELECT id,value FROM run_metrics WHERE key='pipeline_requests_per_finding' ORDER BY id;" "Part F: bandit pipeline_requests_per_finding over runs"
run_sql bandit.db "SELECT context, arm, round(alpha/(alpha+beta),3) AS mean, cost_n FROM bandit_posteriors ORDER BY mean DESC LIMIT 10;" "Part F: bandit posteriors (T4.6 exit check)"

# ============================================================================
# Part G — Phase 5: detection classifier beats baselines
# ============================================================================
run_task "auto --score (train + score classifier)" G \
  "fuzzlab auto --base-url '$BASE_URL' --spider-db spider_results.db --store auto.db --ground-truth '$GT_DIR' --score --authorized"

run_sql auto.db "SELECT key, value FROM run_metrics WHERE key LIKE 'ml_pr_auc%';" "Part G: PR-AUC vs baselines (T5.5 exit check)"
run_sql auto.db "SELECT id, round(score,3) FROM candidate WHERE run_id=(SELECT MAX(id) FROM run) AND score IS NOT NULL ORDER BY score DESC LIMIT 10;" "Part G: top advisory candidate scores"

# ============================================================================
# Part H — Phase 7: ranker + active learning
# ============================================================================
run_task "auto --rank (train + score ranker)" H \
  "fuzzlab auto --base-url '$BASE_URL' --spider-db spider_results.db --store auto.db --ground-truth '$GT_DIR' --rank --authorized"

run_sql auto.db "SELECT key, value FROM run_metrics WHERE key LIKE 'rank_%';" "Part H: NDCG/precision vs random (T7.4 exit check)"
run_sql auto.db "SELECT id, round(rank_score,3), round(rank_uncertainty,3) FROM candidate WHERE run_id=(SELECT MAX(id) FROM run) AND rank_score IS NOT NULL ORDER BY rank_score DESC LIMIT 10;" "Part H: top ranked candidates"

run_task "active learning: propose_queries (uncertainty + committee)" H \
"python3 - <<'PY'
from fuzzlab.core.store import Store
from fuzzlab.ml.active import propose_queries
with Store('auto.db') as s:
    rid = s.conn.execute('SELECT MAX(id) FROM run').fetchone()[0]
    print('uncertainty:', propose_queries(s, rid, budget=5, method='uncertainty'))
    print('committee:  ', propose_queries(s, rid, budget=5, method='committee'))
PY"

# ============================================================================
# Part I — Phase 6: intercepting proxy, live TLS (single script)
# ============================================================================
run_task "proxy e2e (real upstream, CONNECT/TLS, byte-exact malformed forward)" I \
  "PROXY_PORT='$PROXY_PORT' CA_DIR='$CA_DIR' scripts/proxy_e2e.sh"

run_task "real CA leaf-minting + CONNECT/TLS tunnel tests" I \
  "pytest tests/test_proxy_server.py::test_real_ca_mints_signed_leaf tests/test_proxy_live.py::test_connect_tls_tunnel_forwards_byte_exact -v"

# ============================================================================
# Part J — Phase 8: mutation engine vs the live lab WAF (single script)
# ============================================================================
run_task "waf evasion e2e (T8.7: bypass + coverage gain, restores WAF off)" J \
  "WAF_MODE='$WAF_MODE' FZL_COV_DIR='$FZL_COV_DIR' scripts/waf_evasion_e2e.sh"

run_sql waf_variants.db "SELECT base_payload, variant, operators, bypassed_rule, coverage_gain FROM payload_variant WHERE run_id=(SELECT MAX(id) FROM run WHERE tool='mutate');" "Part J: recorded WAF-bypass variants"

# ============================================================================
# Part K — Phase 9: protocol depth, h2->h1 desync (single script)
# ============================================================================
run_task "h2 desync e2e (T9.6: live h2c request + desync primitives)" K \
  "scripts/h2_desync_e2e.sh"

run_task "optional parsed h2/wsproto path tests" K \
  "pytest tests/test_proxy_h2.py tests/test_proxy_h2_transport.py -v"

# ============================================================================
# Part L — Phase 10: plugins, anomaly tripwire, report, transfer
# ============================================================================
run_task "auto --plugins (sample entry-point plugin attaches)" L \
  "fuzzlab auto --base-url '$BASE_URL' --spider-db spider_results.db --store auto.db --ground-truth '$GT_DIR' --plugins --authorized"

run_sql auto.db "SELECT name, version, priority FROM run_plugin WHERE run_id=(SELECT MAX(id) FROM run);" "Part L: active plugin set"

run_task "anomaly tripwire (ECOD, advisory) over the latest run" L \
"python3 - <<'PY'
from fuzzlab.core.store import Store
from fuzzlab.ml.anomaly import detect_anomalies
with Store('auto.db') as s:
    rid = s.conn.execute('SELECT MAX(id) FROM run').fetchone()[0]
    print(detect_anomalies(s, rid, contamination=0.1))
PY"

run_task "reproducible report (human summary)" L "fuzzlab report --store auto.db"
run_task "reproducible report (canonical JSON)" L "fuzzlab report --store auto.db --json"

if [ -n "${JUICE_BASE_URL:-}" ] && [ -n "${JUICE_GROUND_TRUTH:-}" ]; then
  run_task "T10.6 transfer exit: pff + external lab" L \
"python3 - <<PY
from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary, format_transfer
from fuzzlab.labels import contract
from fuzzlab.tools.probesender import make_probe_sender
specs = [
    TargetSpec('pff', '$BASE_URL',
               ground_truth=contract.load('$GT_DIR'), points_source='ground-truth'),
    TargetSpec('juice', '$JUICE_BASE_URL',
               ground_truth=contract.load('$JUICE_GROUND_TRUTH'), points_source='ground-truth'),
]
with Store('transfer.db') as s:
    outs = run_targets(specs, s, sender_for=lambda spec: make_probe_sender(spec.base_url, None))
    print(format_transfer(transfer_summary(outs)))
PY"
else
  {
    echo ""
    echo "--- [$(date -u +'%Y-%m-%dT%H:%M:%SZ')] Part L: T10.6 transfer exit -- SKIPPED"
    echo "    (set JUICE_BASE_URL + JUICE_GROUND_TRUTH to a second, external"
    echo "    validation lab's URL + ground-truth contract dir to run this;"
    echo "    per D10, e.g. OWASP Juice Shop or WAVSEP)"
  } >>"$OUT_FILE"
  echo "[skip] Part L: T10.6 transfer exit (no second lab configured)"
fi

{
  echo ""
  echo "===================================================================="
  echo "=== $(date -u +'%Y-%m-%dT%H:%M:%SZ') RUN END"
  echo "=== summary (PASS/FAIL/SKIP per task):"
  grep -E '^(=== Part|--- \[.*SKIPPED)' "$OUT_FILE" | tail -n 60
  echo "===================================================================="
} >>"$OUT_FILE"

echo ""
echo "Full log: $OUT_FILE"
echo "Quick summary:"
grep -E '^(=== Part|--- \[.*SKIPPED)' "$OUT_FILE" | tail -n 60
