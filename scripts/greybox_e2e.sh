#!/usr/bin/env bash
#
# Part E — Phase 3: grey-box instrumentation, end to end (T3.1–T3.7).
#
# Runs every activity in ON_HOST_RUNBOOK.md Part E, in order, against the lab you own
# on loopback:
#   1. (Re)build the instrumented lab image (pcov + the FzlCoverage coverage/db-fault middleware).
#   2. Wait for the web tier to be healthy.
#   3. Self-test the side channel with curl (proves coverage + db_fault are captured).
#   4. Snapshot the DB baseline (deterministic resets, T3.5).
#   5. Run the live grey-box pass (`fuzzlab greybox-run`) — shaped reward + db_fault.
#   6. Print the exit check (T3.7): new-code requests score higher; error-based SQLi
#      sets db_fault=1.
#
# LAB-ONLY. This drives a deliberately vulnerable app; it stays on 127.0.0.1 and must
# never be pointed at anything you are not authorized to test. Idempotent: safe to
# re-run (step 1 reuses `reset`, which re-seeds a clean DB).
#
# Usage:
#   scripts/greybox_e2e.sh                 # ground-truth points (a detection benchmark)
#   PFF_WEB_PORT=8080 scripts/greybox_e2e.sh
#   GB_POINTS=crawl GB_SPIDER_DB=spider_results.db scripts/greybox_e2e.sh
#
# Env knobs (all optional):
#   PFF_WEB_PORT   lab web port (default 8080)
#   FZL_COV_DIR    host side-channel dir (default /tmp/fzl-cov)
#   GB_STORE       output store (default greybox.db)
#   GB_POINTS      auto | ground-truth | crawl (default ground-truth)
#   GB_SPIDER_DB   crawl DB for GB_POINTS=crawl/auto (default spider_results.db)
#   GB_GROUND_TRUTH ground-truth dir (default lab/ground-truth)
#   GB_SETTLE      seconds to wait after each probe for the shim to flush (default 0.1)
set -euo pipefail

# --- locate the repo root (this script lives in scripts/) --------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${PFF_WEB_PORT:-8080}"
BASE_URL="http://127.0.0.1:${PORT}"
COV_DIR="${FZL_COV_DIR:-/tmp/fzl-cov}"
STORE="${GB_STORE:-greybox.db}"
POINTS="${GB_POINTS:-ground-truth}"
SPIDER_DB="${GB_SPIDER_DB:-spider_results.db}"
GROUND_TRUTH="${GB_GROUND_TRUTH:-lab/ground-truth}"
SETTLE="${GB_SETTLE:-0.1}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

command -v fuzzlab >/dev/null 2>&1 || command -v python >/dev/null 2>&1 \
  || die "neither 'fuzzlab' nor 'python' on PATH — install the toolkit (pip install -e .)"
FUZZLAB=(fuzzlab)
command -v fuzzlab >/dev/null 2>&1 || FUZZLAB=(python -m fuzzlab.cli)

# --- 1. build + start the instrumented lab -----------------------------------
say "1/6  Building the instrumented lab (pcov + FzlCoverage middleware) and re-seeding the DB"
export FZL_COV_DIR="${COV_DIR}"
mkdir -p "${COV_DIR}"
chmod 777 "${COV_DIR}" 2>/dev/null || true      # the container (www-data) must write here
( cd lab && ./labctl.sh reset )

# --- 2. wait for health ------------------------------------------------------
# Probe a real served endpoint, not "/": the generated Laravel target has no
# homepage route and returns 404 on "/", so `curl -f "${BASE_URL}/"` (fail-on-4xx)
# would never succeed even with the app fully up. /product.php?id=1 returns 200
# and also proves DB connectivity — the same endpoint step 3's self-test uses.
READY_URL="${BASE_URL}/product.php?id=1"
say "2/6  Waiting for ${READY_URL} to come up"
ok=0
for _ in $(seq 1 60); do
  if curl -fs -o /dev/null "${READY_URL}"; then ok=1; break; fi   # -s (no -S): quiet retries
  sleep 2
done
[ "${ok}" = 1 ] || die "lab did not become reachable at ${READY_URL} (see: cd lab && ./labctl.sh logs)"
echo "lab is up."

# --- 3. side-channel self-test ----------------------------------------------
say "3/6  Self-testing the coverage / db_fault side channel with curl"
# First, a definitive check that pcov is actually loaded in the running container —
# an empty coverage file otherwise looks like a wiring bug but is really a missing ext.
if ( cd lab && ./labctl.sh exec web php -m 2>/dev/null ) | grep -qi '^pcov$'; then
  echo "  pcov: loaded in the web container."
else
  die "pcov is NOT loaded in the web container. Force a clean rebuild:
       (cd lab && ./labctl.sh down && podman-compose build --no-cache web && ./labctl.sh up)
     then re-run this script. (web.Dockerfile installs pcov + \$PHPIZE_DEPS.)"
fi
rm -f "${COV_DIR}/selftest_cov" "${COV_DIR}/selftest_fault" 2>/dev/null || true
# benign request -> should record covered app lines
curl -fsS -o /dev/null -H "X-Fzl-Cov: selftest_cov" "${BASE_URL}/product.php?id=1" || true
# error-based SQLi on the login username -> should set db_fault=1
curl -fsS -o /dev/null -H "X-Fzl-Cov: selftest_fault" \
  --data-urlencode "username='" --data-urlencode "password=x" \
  "${BASE_URL}/login.php" || true
sleep 0.5                         # let the shim's shutdown handler flush both files

python - "$COV_DIR" <<'PY' || die "side-channel self-test failed (see hints above the traceback)"
import json, sys, pathlib
d = pathlib.Path(sys.argv[1])
def load(name):
    p = d / name
    if not p.exists():
        raise SystemExit(f"  FAIL: {p} was not written — is the FzlCoverage middleware installed "
                         f"and is {d} bind-mounted into the container? "
                         f"(check lab/web.Dockerfile + lab/compose.yaml)")
    return json.loads(p.read_text())
cov = load("selftest_cov")
files = cov.get("files") or {}
if not files:
    raise SystemExit("  FAIL: benign request recorded no covered lines. pcov is loaded "
                     "(checked above), so this points at the shim's collection logic in "
                     "the FzlCoverage middleware (e.g. \\pcov\\collect() filter "
                     "or the app path prefix), not the image.")
fault = load("selftest_fault")
if not fault.get("db_fault"):
    raise SystemExit("  FAIL: error-based SQLi did not set db_fault — check that the "
                     "app throws on SQL errors (an uncaught Illuminate\\Database\\"
                     "QueryException) and the FzlCoverage middleware's handler.")
print(f"  OK: coverage captured ({sum(len(v) for v in files.values())} app lines) "
      f"and db_fault=1 on the error-based SQLi probe.")
PY

# --- 4. snapshot the DB baseline (T3.5) --------------------------------------
say "4/6  Snapshotting the DB baseline for deterministic resets"
( cd lab && ./labctl.sh snapshot baseline )

# --- 5. live grey-box run ----------------------------------------------------
say "5/6  Running the live grey-box pass (fuzzlab greybox-run)"
GB_ARGS=(greybox-run --base-url "${BASE_URL}" --store "${STORE}"
         --cov-dir "${COV_DIR}" --labctl "lab/labctl.sh" --reset
         --settle "${SETTLE}" --points "${POINTS}" --authorized)
if [ "${POINTS}" = "ground-truth" ] || [ "${POINTS}" = "auto" ]; then
  [ -d "${GROUND_TRUTH}" ] && GB_ARGS+=(--ground-truth "${GROUND_TRUTH}")
fi
if [ "${POINTS}" = "crawl" ] || [ "${POINTS}" = "auto" ]; then
  GB_ARGS+=(--spider-db "${SPIDER_DB}")
fi
"${FUZZLAB[@]}" "${GB_ARGS[@]}"

# --- 6. exit check (T3.7) ----------------------------------------------------
say "6/6  Exit check (T3.7): reward ordering + db_fault"
python - "$STORE" <<'PY'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1]); con.row_factory = sqlite3.Row
run = con.execute("SELECT MAX(id) AS r FROM run WHERE tool='greybox'").fetchone()["r"]
print(f"  run_id={run}")
rows = con.execute(
    "SELECT id, payload_family, ROUND(reward,3) AS reward, db_fault "
    "FROM attempt WHERE run_id=? ORDER BY reward DESC LIMIT 10", (run,)).fetchall()
print("  top attempts by reward:")
for r in rows:
    print(f"    #{r['id']:>4}  {r['payload_family']:<14} reward={r['reward']:<6} "
          f"db_fault={r['db_fault']}")
base = con.execute("SELECT MAX(reward) m FROM attempt WHERE run_id=? AND payload_family='baseline'",
                   (run,)).fetchone()["m"] or 0.0
new = con.execute("SELECT MAX(reward) m FROM attempt WHERE run_id=? AND payload_family!='baseline'",
                  (run,)).fetchone()["m"] or 0.0
faults = con.execute("SELECT COUNT(*) c FROM attempt WHERE run_id=? AND db_fault=1",
                     (run,)).fetchone()["c"]
print(f"\n  baseline max reward = {base:.3f}   payload max reward = {new:.3f}")
print(f"  db_fault attempts   = {faults}")
ok = new > base and faults > 0
print("\n  " + ("PASS: new-code/payload requests score higher AND error-based SQLi faulted."
                if ok else
                "REVIEW: expected payload reward > baseline and >=1 db_fault. See notes above."))
PY

say "Done. Store: ${STORE}  (re-run this script any time; it re-seeds a clean DB.)"
