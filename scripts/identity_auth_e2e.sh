#!/usr/bin/env bash
#
# Part C — Phase 1: authenticated per-identity run, end to end.
#
# Runs the runbook Part C activities against the lab you own on loopback:
#   1. Save credentials for one identity into the OS keyring (D12) — prompts for the
#      password; never writes it to the repo or the project store.
#   2. Confirm login detection prints a usable session header.
#   3. Run crawl -> audit -> fuzz for that identity into one shared store.
#   4. Print a quick summary (findings recorded, identity used).
#
# LAB-ONLY, loopback, on infrastructure you own. `fuzzlab fuzz` sends real traffic
# and requires --authorized; this script passes it, so only run it against your own
# lab. Re-run with a different IDENTITY/USERNAME to cover other test accounts
# (admin/admin123, alice/password1, bob/letmein per puppy-fort-factory's seed data).
#
# Env knobs (optional):
#   PFF_WEB_PORT   lab web port (default 8080)
#   PFF_HOST       lab hostname, no port (default 127.0.0.1) — credentials are
#                  looked up by hostname (D12), so this must match --host below
#   IDENTITY       identity name to save/use (default admin)
#   USERNAME       username for that identity (default admin)
#   AUTH_STORE     shared store for crawl/audit/fuzz (default identity_run.db)
#   SKIP_SET_CREDENTIAL=1   skip step 1 (use already-saved keyring credentials)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${PFF_WEB_PORT:-8080}"
HOST="${PFF_HOST:-127.0.0.1}"
LAB="http://${HOST}:${PORT}"
IDENTITY="${IDENTITY:-admin}"
USERNAME="${USERNAME:-admin}"
STORE="${AUTH_STORE:-identity_run.db}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
command -v fuzzlab >/dev/null 2>&1 && FUZZLAB=(fuzzlab) || FUZZLAB=(python -m fuzzlab.cli)

curl -fs -o /dev/null "${LAB}/" \
  || die "lab not reachable at ${LAB}/ (bring it up first: cd lab && ./labctl.sh up)"

# --- 1. save credentials -----------------------------------------------------
if [ "${SKIP_SET_CREDENTIAL:-0}" = "1" ]; then
  say "1/4  Skipping set-credential (SKIP_SET_CREDENTIAL=1); using saved keyring entry"
else
  say "1/4  Saving credentials for ${IDENTITY} (host ${HOST}, username ${USERNAME})"
  echo "  you will be prompted for the password interactively (never stored in the repo)"
  "${FUZZLAB[@]}" session set-credential --host "${HOST}" --identity "${IDENTITY}" \
    --username "${USERNAME}"
fi

# --- 2. confirm login detection ----------------------------------------------
say "2/4  Confirming login detection for ${IDENTITY}"
"${FUZZLAB[@]}" session print --host "${HOST}" --identity "${IDENTITY}" \
  --base-url "${LAB}/"

# --- 3. crawl -> audit -> fuzz for this identity ------------------------------
say "3/4  crawl -> audit -> fuzz as ${IDENTITY}, into ${STORE}"
rm -f "${STORE}" spider_results.db
"${FUZZLAB[@]}" crawl --start "${LAB}" --store "${STORE}" --identity "${IDENTITY}"
"${FUZZLAB[@]}" audit --spider-db spider_results.db --store "${STORE}" \
  --identity "${IDENTITY}" --base-url "${LAB}/"
"${FUZZLAB[@]}" fuzz --url "${LAB}/product.php" --param id \
  --store "${STORE}" --identity "${IDENTITY}" --authorized

# --- 4. summary ---------------------------------------------------------------
say "4/4  Summary"
python - "$STORE" "$IDENTITY" <<'PY'
import sys
from fuzzlab.core.store import Store
with Store(sys.argv[1]) as s:
    rows = s.conn.execute(
        "SELECT vuln_class, url, param, confidence FROM finding "
        "ORDER BY id DESC LIMIT 10").fetchall()
    print(f"  identity: {sys.argv[2]}")
    if not rows:
        print("  no findings recorded yet in this store")
    for r in rows:
        print(f"    {r['vuln_class']} {r['url']} [{r['param']}] ({r['confidence']})")
PY
echo "  Expect: product.php?id and search.php?q confirmed; secure pages stay clean"
echo "  (puppy-fort-factory/VULNERABILITIES.md is the map). Re-run with a different"
echo "  IDENTITY/USERNAME env pair to cover the other test accounts."
