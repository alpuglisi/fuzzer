#!/usr/bin/env bash
#
# Part I — Phase 6: intercepting proxy, live TLS / real upstream, end to end.
#
# Runs the runbook Part I activities against the lab you own on loopback:
#   1. Ensure the lab is up.
#   2. Export the local CA (to import into your browser for HTTPS interception).
#   3. Start `fuzzlab proxy` (real upstream SocketSender + flow recording + CONNECT/TLS).
#   4. Prove the real upstream: curl the lab THROUGH the proxy -> 200.
#   5. Prove byte-exact forwarding of a MALFORMED request (duplicate Content-Length):
#      send it through the proxy, then read it back from the recorded store and confirm
#      both Content-Length headers went on the wire while the parsed path rejects them.
#   6. Print how to trust the CA and browse the lab through the proxy.
#
# LAB-ONLY. Everything stays on 127.0.0.1. Idempotent; safe to re-run.
#
# Env knobs (optional):
#   PFF_WEB_PORT   lab web port (default 8080)
#   PROXY_PORT     proxy listen port (default 8888)
#   PROXY_STORE    flow store (default proxy_flows.db)
#   CA_DIR         local CA dir (default ~/.fuzzlab/ca)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PORT="${PFF_WEB_PORT:-8080}"
LAB_URL="http://127.0.0.1:${PORT}"
PROXY_PORT="${PROXY_PORT:-8888}"
STORE="${PROXY_STORE:-proxy_flows.db}"
CA_DIR="${CA_DIR:-$HOME/.fuzzlab/ca}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

command -v fuzzlab >/dev/null 2>&1 && FUZZLAB=(fuzzlab) || FUZZLAB=(python -m fuzzlab.cli)

PROXY_PID=""
cleanup() { [ -n "${PROXY_PID}" ] && kill "${PROXY_PID}" 2>/dev/null || true; }
trap cleanup EXIT

# --- 1. lab up --------------------------------------------------------------
# Probe a real served endpoint, not "/": the generated Laravel target 404s on
# "/" (no homepage route), so `curl -f "${LAB_URL}/"` would never pass. Use
# /product.php?id=1 (returns 200, also confirms DB).
READY_URL="${LAB_URL}/product.php?id=1"
say "1/6  Ensuring the lab is up at ${READY_URL}"
if ! curl -fs -o /dev/null "${READY_URL}"; then
  ( cd lab && ./labctl.sh up )
  for _ in $(seq 1 60); do curl -fs -o /dev/null "${READY_URL}" && break; sleep 2; done
fi
curl -fs -o /dev/null "${READY_URL}" || die "lab not reachable at ${READY_URL}"
echo "lab is up."

# --- 2. export the CA -------------------------------------------------------
say "2/6  Exporting the local CA (for HTTPS interception)"
if "${FUZZLAB[@]}" proxy --export-ca --ca-dir "${CA_DIR}"; then
  :
else
  echo "  (CA export needs a working 'cryptography'; the plain-HTTP proxy still works.)"
fi

# --- 3. start the proxy -----------------------------------------------------
say "3/6  Starting the proxy on 127.0.0.1:${PROXY_PORT} (recording to ${STORE})"
rm -f "${STORE}"
"${FUZZLAB[@]}" proxy --host 127.0.0.1 --port "${PROXY_PORT}" --scope 127.0.0.1 \
  --ca-dir "${CA_DIR}" --store "${STORE}" --authorized >/tmp/fzl-proxy.log 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 40); do
  (exec 3<>"/dev/tcp/127.0.0.1/${PROXY_PORT}") 2>/dev/null && { exec 3>&- 3<&-; break; }
  sleep 0.25
done
kill -0 "${PROXY_PID}" 2>/dev/null || { cat /tmp/fzl-proxy.log; die "proxy did not start"; }
echo "proxy up (pid ${PROXY_PID})."

# --- 4. real upstream through the proxy -------------------------------------
say "4/6  Fetching the lab THROUGH the proxy (real upstream SocketSender)"
code=$(curl -sS -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:${PROXY_PORT}" \
       "${LAB_URL}/product.php?id=1" || true)
echo "  GET /product.php?id=1 via proxy -> HTTP ${code}"
[ "${code}" = "200" ] || die "expected 200 through the proxy, got ${code} (see /tmp/fzl-proxy.log)"

# --- 5. byte-exact malformed forwarding (the Part I exit) -------------------
say "5/6  Forwarding a duplicate-Content-Length request byte-exact through the proxy"
python - "$PROXY_PORT" "$PORT" <<'PY'
import socket, sys
proxy_port, lab_port = int(sys.argv[1]), int(sys.argv[2])
# Two CONFLICTING Content-Length values: duplicate *identical* CL is valid per RFC 7230
# (a parser may accept it), so only conflicting values are guaranteed to be rejected by
# the parsed path. The proxy reads the first (0 -> no body) and forwards byte-exact.
req = (f"POST http://127.0.0.1:{lab_port}/product.php?id=1 HTTP/1.1\r\n"
       f"Host: 127.0.0.1:{lab_port}\r\n"
       f"Content-Length: 0\r\n"
       f"Content-Length: 5\r\n\r\n").encode()
s = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
s.sendall(req); s.recv(65536); s.close()
print("  sent a request carrying two conflicting Content-Length headers through the proxy")
PY

# stop the proxy, then read the recorded bytes back. Flows are persisted per-record
# (batch_size=1), so shutdown timing never loses them; the wait is bounded so a stubborn
# process can't hang the script.
kill -INT "${PROXY_PID}" 2>/dev/null || true
for _ in $(seq 1 20); do kill -0 "${PROXY_PID}" 2>/dev/null || break; sleep 0.5; done
kill -0 "${PROXY_PID}" 2>/dev/null && kill -KILL "${PROXY_PID}" 2>/dev/null || true
wait "${PROXY_PID}" 2>/dev/null || true
PROXY_PID=""

python - "$STORE" <<'PY'
import sys
from fuzzlab.core.store import Store
from fuzzlab.proxy import parser
with Store(sys.argv[1]) as s:
    rows = s.conn.execute(
        "SELECT b.data AS raw FROM flow f JOIN body b ON f.req_raw_sha=b.sha256 "
        "WHERE f.run_id=(SELECT MAX(id) FROM run WHERE tool='proxy')").fetchall()
raws = [bytes(r["raw"]) for r in rows]
dup = [r for r in raws if r.count(b"Content-Length:") >= 2]
if not dup:
    raise SystemExit("  FAIL: no recorded flow carried a duplicate Content-Length "
                     "(is the proxy recording to the store?)")
r = dup[0]
if parser.is_valid_request(r) is not False:
    raise SystemExit("  FAIL: the parsed path did not reject the duplicate Content-Length")
print(f"  OK: recorded {len(raws)} flow(s); a duplicate Content-Length was forwarded "
      f"byte-exact, and the parsed path rejects it (raw path preserved the malformed bytes).")
PY

# --- 6. how to browse through it --------------------------------------------
say "6/6  Done"
cat <<EOF
  Flow store: ${STORE}   (proxy log: /tmp/fzl-proxy.log)
  To browse interactively through the proxy:
    1. Trust the CA:  import ${CA_DIR}/fuzzlab-ca.crt into your browser/OS store.
    2. Point the browser's HTTP/HTTPS proxy at 127.0.0.1:${PROXY_PORT}.
    3. Run:  ${FUZZLAB[*]} proxy --scope 127.0.0.1 --ca-dir ${CA_DIR} --store ${STORE} --authorized
    4. Browse ${LAB_URL}/ ; intercept + hand-edit requests; flows record to the store.
  The CA private key stays on this host (0600) and is never distributed.
EOF
