# BUG-0048 — the on-host e2e scripts' lab-readiness probes used `curl -f "${BASE}/"`, but the generated Laravel target 404s on `/`, so they declared a healthy lab "not reachable"

## Description

`scripts/greybox_e2e.sh`, `scripts/proxy_e2e.sh`, and `scripts/waf_evasion_e2e.sh`
each wait for the lab to come up with a `curl -fs -o /dev/null "${BASE_URL}/"`
loop (the `-f` flag makes curl exit non-zero on any HTTP ≥ 400). Against the
current generated lab, `GET /` returns **404** (the app is a set of `.php`-path
routes plus JSON endpoints; it has no `/` homepage route), so the probe never
succeeds and the scripts abort with e.g.:

```
== 2/6  Waiting for http://127.0.0.1:8080/ to come up
ERROR: lab did not become reachable at http://127.0.0.1:8080/ (see: cd lab && ./labctl.sh logs)
```

even though the lab was fully up and serving (`/product.php?id=1` → 200
throughout).

## Where encountered

On-host run of `ON_HOST_RUNBOOK.md` Part E (`greybox_e2e.sh`), 2026-09-24. The
same latent defect was present in Part I (`proxy_e2e.sh`) and Part J
(`waf_evasion_e2e.sh`) readiness gates.

## What it caused to fail

Part E aborted at its readiness gate (step 2/6) before running any grey-box
work. Parts I and J would have aborted identically had their readiness probe
been reached first (they were fixed in the same change before re-run, and both
then passed).

## What the bug was identified to be

A readiness/health check that couples "the web tier is up" to "`GET /` returns a
2xx/3xx status." That coupling held for the retired hand-built app (whose `/`
served a 200 homepage) but is false for the generated Laravel app, which has no
`/` route and correctly returns a 404 for it. `curl -f` treats that 404 as
failure, so a fully-serving lab reads as unreachable.

## Root cause analysis (Five Whys)

1. Why did the scripts abort? Their readiness probe `curl -f "${BASE}/"` failed.
2. Why did it fail against a running lab? `GET /` returns 404 and `-f` fails on
   4xx.
3. Why does `/` return 404? The generated app serves only its modelled routes
   (`/product.php`, `/search.php`, …); it has no homepage route, and none is in
   the ground-truth surface.
4. Why did the probe assume `/` is 200? It was written against the hand-built
   predecessor app, which served a homepage at `/`; the `L-P3.3c-CUT` cutover to
   the generator changed the served surface, but the e2e readiness probes were
   not revisited for it.
5. **Root cause:** a liveness check conflated "server is up" with "a specific,
   incidental route returns success," and the specific route it chose
   (`/`) is one whose behaviour the target-app cutover changed — so the check
   became a false-negative liveness signal with no code change to the scripts
   themselves.

## Corrective action

- Changed all three scripts' readiness probes from `"${BASE}/"` to
  `"${BASE}/product.php?id=1"` — a real modelled endpoint that returns 200 and
  additionally confirms DB connectivity, and the same endpoint each script
  already uses for its own downstream self-test. Added an explanatory comment at
  each site.
- Swept `scripts/` for other bare-`/`-with-`-f` readiness probes: none remained
  (`h2_desync_e2e.sh` waits on a raw TCP connect to the h2c port, not an HTTP
  status, so it was already correct).
- Re-ran Parts E, I, J: all pass. See CC-LAB-0235.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`.

**Related prior finding: `BUG-0023` / `PA-0025`** — "a tool-oracle wrapper must
not infer a target's security state from an *unreachable* target (fail closed,
surface connectivity diagnostics, never suppress them)." That PA is about the
*audit oracle* inferring `secure` from a dead target; it lives in the tool's
oracle layer, not in the on-host shell harnesses, and its concern is the
opposite direction (treating unreachable as *secure*). BUG-0048 is the mirror
failure in a different layer: a *readiness* probe treating a *reachable* lab as
*dead* because it keyed liveness on an incidental route's status code. Same
underlying doctrine (never infer host state from a single incidental signal),
different layer and direction, so PA-0025 did not — and by its scope could not —
prevent it.

## Prior-preventive-action failure analysis

`PA-0025` was scoped narrowly to the audit/nuclei *oracle wrapper* ("a
tool-oracle wrapper …"), so it never reached the on-host e2e shell scripts, and
it addressed inferring *secure-from-unreachable*, not *dead-from-a-404*. The new
PA generalises the doctrine to any liveness/readiness check (in any layer,
shell included): probe a known-good modelled endpoint and treat "server
answered at all" as up — do not equate liveness with an incidental route's
success status.

## Preventive action

**PA-0050** (see `docs/PREVENTIVE_ACTIONS.md`) — a liveness/readiness probe must
target a known-served endpoint and must not equate "up" with a 2xx/3xx on an
incidental path such as `/`; strengthens/generalises `PA-0025` from the oracle
layer to every reachability check, on-host scripts included.
