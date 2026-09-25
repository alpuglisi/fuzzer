# BUG-0056 — `python_fastapi` and `node_express` routes had no declared absent-input behavior: a bare request crashed, killed the process, or answered twin-asymmetrically

- Date: 2026-09-25
- Status: fixed for the absent-input class in both emitters. The different-class
  Node async-rejection exit (F2) is pinned by a strict xfail, not fixed.
- Severity: medium

## Description

Neither the `python_fastapi` emitter nor the `node_express` emitter could
declare what a route does when its request input is absent. The source modules
read the parameter with no default and no guard, so the language's absent value
flowed into sinks that are only correct for a present value.

| # | Where | Bare request | Result before the fix |
|---|---|---|---|
| D1 | `python_fastapi` `/products`, `LABGEN-PY-0001` (vulnerable) | `GET /products` | **500**: `str(None)` gives `WHERE id = None`, and SQLite raises `no such column: None`. The secure twin binds `None`, so it matched no row and was not reachable anyway (F3). |
| D2 | `node_express` `/api/products`, served at `/generated/labgen-ne-0001` | `GET` | **The Node process exits (rc=1).** The handler is `async` and its rejected `pool.query` is unhandled. Express 4 does not catch async rejections, and Node 22's default `--unhandled-rejections=throw` kills the process. The exact failure mode varies by environment, as described below the table. |
| D3 | `node_express` `/api/search` (MeadowMart, `LABGEN-RD-0001/0002`) | `GET /api/search` | Both twins answered 200, but with different bodies. The vulnerable twin gave `<mark></mark>` between every character, because `new RegExp(undefined)` is the empty pattern. The secure twin gave plain content, because `escapeRegExp(undefined)` is `"undefined"` and matches nothing. It is not a crash, but the behavior was undeclared and differed between the twins. |
| D4 | `node_express` `/api/login` secure twin (`LABGEN-NE-0006`) | `POST` with no `username` | Here the process exits via the same path as D2 (`ECONNREFUSED`). With a live DB it does not crash: `mysql2` formats an `undefined` bind as `NULL`, which was checked with `mysql2.format`, so the query simply matches no user. It is undeclared either way. |

**How D2 and D4 fail depends on the environment** (this was a round-1
accuracy footnote). In this DB-less sandbox, the rejection is
`ECONNREFUSED` to 127.0.0.1:3306. With a MySQL server running, D2's
undeclared `id` would instead produce the malformed SQL
`… WHERE id = undefined`. That is also rejected, and just as unhandled.

## Where encountered

- **Planning:** found during Browsable Labs Lane 6 planning, by direct
  probing (`docs/LAB_LANE6_NODE_FASTAPI_PLAN.md` §1d).
  - `python_fastapi` was probed through `TestClient` with
    `raise_server_exceptions=False`.
  - All 12 `node_express` cells were probed by booting them with
    `npm install` + `node app.js` on loopback.
- **Review:** the round-1 accuracy reviewer independently reproduced D1–D4.
- **Implementation:** the checks built in `CC-LAB-0246` confirm the fix:
  - `tests/test_labgen_python_fastapi_browsable.py::test_pa_0054_bare_request_sweep`;
  - `tests/test_labgen_node_meadowmart_navigability_live_boot.py::test_pa_0054_bare_request_sweep_of_every_served_route`;
  - the offline declaration checks in both emitters' `*_browsable.py`
    modules.

## What it caused to fail

- **FastAPI homepage:** the sample's new homepage (`CC-LAB-0246`) links
  `/products`, so a click would have hit a 500. That fails the Browsable
  Labs PA-0053 requirement.
- **MeadowMart's bare search:** before the fix it returned 200, not a crash,
  so no "< 500" sweep would have flagged it. Yet it gives a different body
  on each twin for the same request. A bare URL is exactly where a crawler
  or detection oracle takes its baseline, so this silently tells the twins
  apart.
- **Node sample:** the whole process dies, which takes every other route
  down with it.

## What the bug was identified to be

The same absent-input defect as BUG-0051 (`php_laravel`) and BUG-0052
(`django`), now in two more emitters:
- "Parameter absent" was never modelled at the **source** module.
- The route profile had no key in which to declare it.
- So `None`/`undefined` reached the sink.

## Root cause analysis

Five Whys (D1, then generalized):

1. *Why did a bare `GET /products` 500?* The SQL text was `… WHERE id = None`.
2. *Why `None`?* `get_param.py.j2` rendered `request.query_params.get("id")`
   with no default.
3. *Why no default?* `python_fastapi`'s `_PAGE_PARAMS`, like
   `node_express`'s `_ROUTE_PARAMS`, had no declaration key at all. The
   per-profile defaults added by BUG-0051/0052 exist only in `php_laravel`
   and `django`.
4. *Why was this still present after PA-0054?* PA-0054 (1) required
   **every** emitter's route profile to declare absent input, checked
   offline. But the only offline check ever built was
   `tests/test_labgen_django_browsable.py`, which covers `django` alone. No
   check enumerated the other emitters. BUG-0052's PA-0002 sweep listed them
   as belonging to "Browsable Labs Lanes 3-6" without pinning each known
   instance.
5. *Why did D3 escape even the strengthened rules?* Every mechanical check
   so far asserts a bare request answers **< 500**: PA-0053's crawl,
   PA-0054's sweep, and Lanes 3/4's own-method sweeps (PA-0055/PA-0056 as
   planned). A route whose absent-input path does not crash, but differs
   between the twins, passes all of them.

**Root cause:**
- Absent input is declared per emitter in ad-hoc vocabularies. Lane 2 used
  two keys; Lanes 3 and 4 each use one key but spell the values differently.
- It is enforced per emitter, by whichever lane reaches that emitter.
- The enforcement checks "did not crash" instead of "answered the declared
  behavior, identically on both twins".

## Corrective action

`CC-LAB-0246` (FR-LAB-168/169):
- **Declaration key:** every route profile in both emitters now carries one
  required `absent_input` key, using the shared vocabulary from Lane 4's S15
  (`default_value` with `default_literal`, `required_param`,
  `empty_body_400`, `no_input`).
- **Allowed values:** the values each source kind may carry are listed per
  emitter in `ABSENT_INPUT_BY_SOURCE`.
- **Rendering:** the source templates render the declaration in the source
  region, identically on both twins.

Per route:
- `python_fastapi`: `/products` → `default_value` `"1"` (fixes D1);
  `/login` → `required_param` (a handled 400); `/profile` → `no_input`.
- `node_express`:
  - `/api/products` and `/api/posts` → `default_value` `'1'` (the
    absent-input half of D2);
  - `/api/login` → `required_param` (D4);
  - `/api/search` → `required_param`, a 400 before the RegExp is built on
    both twins (D3);
  - `/api/preferences` → `empty_body_400`;
  - `/api/profile` → `no_input`.

Verified:
- the offline declaration and twin-identity checks;
- the live MeadowMart bare sweep (GET and POST);
- the `python_fastapi` bare sweep, with twins included.

The declared statuses are asserted exactly, on both twins.

**Not fixed here (different class, plan §7):** F2, the unhandled rejection
in `node_express` async handlers. It is why D2 exits the process rather than
returning an error. It is pinned by
`tests/test_labgen_node_express_browsable.py::test_f2_async_handlers_handle_rejections`
(`xfail(strict=True)`), with its follow-up number to be assigned by the
orchestrator.

## Recurrence review

Checked every `docs/bugs/BUG-*.md` and `docs/PREVENTIVE_ACTIONS.md`, plus the
concurrent lanes' planned PAs, which are not merged yet. The planned PAs
were read in their plans:
- Lane 3: `docs/LAB_LANE3_GO_NET_HTTP_TWITCH_PLAN.md`, PA-0055.
- Lane 4: `docs/LAB_LANE4_SPRING_BOOT_PLAN.md`, PA-0056.

Results:
- **Match: `BUG-0052` / `PA-0054`.** The identical bug in `django`. PA-0054
  was supposed to prevent exactly this.
- **Match: `BUG-0051` / `PA-0053`.** The identical bug in `php_laravel`.
- **Match: `BUG-0037` / `PA-0039`.** `python_fastapi`'s sinks carry the same
  `str(...)` cast, which again turned a `TypeError` into a SQL error.
- **Concurrent: planned PA-0055 (Lane 3)**: sweep each route with its own
  method, not only GET.
- **Concurrent: planned PA-0056 (Lane 4)**: input channels, request method,
  and pinning other emitters now, through the cross-emitter S15 test.

## Prior-preventive-action failure analysis

`PA-0054` (from `BUG-0052`) did not prevent this recurrence.

1. **Not enforced for these emitters (wrong layer).** Its offline rule was
   stated for "every emitter", but the only check that implements it was
   written inside the `django` lane's own test module. No check enumerated
   the emitters, so `python_fastapi` and `node_express` were never
   evaluated.
2. **Its third clause was not applied to its own sweep.** BUG-0052's own
   PA-0002 sweep named these emitters as "Lanes 3-6" in prose instead of
   pinning them. Lane 4's S15 (planned) now closes this, and PA-0056 (as
   planned) covers it.
3. **The check itself cannot see D3.** Both PA-0053's crawl and PA-0054's
   sweep assert only "< 500", and a declared, non-crashing absent-input path
   was never the property checked. Neither planned PA-0055 (own-method
   sweep) nor planned PA-0056 (channels, method, pin-now) changes that
   assertion. This is the failure mode left for PA-0058.
4. **The vocabulary is fragmented.** Lane 2 used two keys
   (`default_value`/`required_param`). Lanes 3 and 4 each use one
   `absent_input` key, but with different value spellings (`default:<v>` vs
   `default_value`). A cross-emitter check that tests for "a declaration is
   present" cannot tell a valid value from a misspelled one, and each
   emitter's declaration is unreadable to another emitter's check.

## Preventive action

**PA-0058** (see `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0054, and adds
to the planned PA-0055/PA-0056 only what they do not cover (failure modes 3
and 4 above):
1. A bare request's check must assert the route's **declared** absent-input
   status **exactly, and identically on both twins**. "< 500" is not
   enough, because an undeclared but non-crashing path (D3) passes it while
   telling the twins apart.
2. An `absent_input` declaration is valid only if it comes from **one
   closed, shared value set**, and only if the value is allowed for the
   route's source kind. The check validates membership, not mere presence.

Enforced here:
- `ABSENT_INPUT_BY_SOURCE` in both emitters, with offline tests that
  validate each value against its source kind;
- the MeadowMart live sweep and the `python_fastapi` in-process sweep, which
  assert the declared statuses exactly on both twins.

Two things are flagged to Lane 7 (reserved `CC-LAB-0247`), because no single
lane owns them:
- unifying the Lane 3 and Lane 4 spellings into one closed set;
- making Lane 4's S15 cross-emitter check validate membership against that
  set.

**PA-0002 sweep (this change):**
- **`node_express`:** all 12 cells across all 3 manifests.
  - Offline: declaration, rendering and twin identity.
  - Live, for MeadowMart's build: every served route, bare GET and POST.
    None answers ≥ 500, and every declared status matches.
  - The Tier-A `LABGEN-NE-*` cells cannot be served live without a MySQL
    server. Their declarations are verified offline, and their live
    process-exit behavior is pinned by F2's strict xfail.
- **`python_fastapi`:** all 6 cells, through TestClient, twins included now
  that F3 is fixed. None answers ≥ 500, and every declared status matches.
- **`php_current`:** no Browsable Labs lane owns it. Lane 4's
  `tests/test_absent_input_declarations_cross_emitter.py` (S15) pins it with
  a strict xfail. This lane adds no second pin (plan §6). If Lane 4's S15
  does not merge, this pin is missing, and the orchestrator must add it at
  merge.
