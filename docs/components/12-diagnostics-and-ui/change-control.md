# Diagnostics and UI — Change Control Log

Component code: **UI**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-UI-0450 — Project files: start screen, new / open / temporary / save as / snapshot / close, recent list, run history, jobs pinned to the project (2026-10-15)
- Change:
  - New `web/projects.py`: `ProjectManager` (one open project; startup binds an
    explicitly configured `store_path` — or an existing `./fuzzlab.db` — only if its
    schema is this build's; with only the built-in default and no such file nothing is
    open and the start screen offers it (FR-UI-458) — an older file waits for
    the migration offer, a newer/invalid one is refused; lifecycle under one
    `asyncio.Lock` with a busy check; temporary projects with an owner `flock` and an
    exact-file discard; the recent list under `secretfile.locked` + `replace_secret`;
    names only from the browser, files confined to the projects directory),
    `ProjectBoundConfig` (every existing `cfg.get("store_path")` follows the open
    project, `None` when none is open), `open_reader` (never creates), `OPTION_CLASS` /
    `pin_values` / `is_pinned` (every `str` option of every spec classified; `--store`
    and intermediates pinned), `record_argv`.
  - New `web/projectroutes.py`: `/projects`, `/project`, `/api/projects`,
    `/api/project/history`, and PRG POSTs (`new`, `temporary`, `use-default`, `open`,
    `save-as`, `snapshot`, `forget`, `close`, `migrate`, `dismiss`, `discard-temporary`,
    `make-private`, `/project/meta`); refusals become a server-held message, never
    reflected text; `/` redirects to the start screen when nothing is open.
  - `web/app.py`: one registration call; `create_app` wraps the config, pops
    `FUZZLAB_LAUNCH_TOKEN` from its own environment, readers use `open_reader`, writers
    (saved views, Repeater, in-process proxy) call `require_writable()` first; pinned
    launches go through `ProjectManager.launch` (409 with no project); the dry run shows
    the pin; the automatic run holds a frozen path and counts as busy; `--with-proxy`
    keeps the project busy and refuses a waiting/refused start-up project with the remedy;
    nav gains "Project"; the shell context carries the project.
  - `web/runner.py`: `launch(project=, command=, on_done=, umask=)`; `_Run.project` set
    only after a successful spawn; `on_done` runs off the loop before `done` (always sent;
    a named error list reported on the stream); `recorded`; `pinned_jobs`, `unrecorded`;
    `shutdown` marks jobs stopping.
  - `web/proxycontrol.py`: Repeater stores and run ids keyed by project path (a switch
    gives the new project its own `repeater` run); opens never create; the proxy's history
    store opens with `create=False`.
  - Templates: `base.html` project chip + banner; new `sections/projects.html` (the start
    screen and project manager, laid out from the UI research), `sections/project.html`
    (metadata, lineage, run history), `static/css/projects.css`; `run.html` findings
    anchor.
- Impact (other components / project): **`fuzzlab web` with the built-in default config
  no longer opens `./fuzzlab.db` unless that file exists** — it starts on the start screen,
  which offers it (FR-UI-458; `--with-proxy` still creates it at start-up, PA-0452(3)); an
  explicit `store_path` (env, config file, override) is bound as before. Tests that built a
  default-config app now seed a private store or follow the redirect
  (`test_web_frontend.py`, `test_web_runner.py`, `test_web_launcher.py`). Launched
  store-writing commands now always write the open project; a typed `--store`, `--db`, `--spider-db`, `--out` (audit) or
  `--output` (fuzz) is overridden, and the default intermediates move from the working
  directory into `<project>.d/`. Site-tree session: its route reading
  `cfg.get("store_path")` follows the project automatically, but must open the store with
  `projects.open_reader` (or `Store(path, create=False)`) — the AST guard
  `tests/test_web_projects.py::test_no_web_module_opens_a_store_that_can_create` fails on a
  creating open in `fuzzlab/web/`. CLI-restructure session: no dependency (no CLI flag
  added; a `fuzzlab web --project` flag is a follow-up for that session). Core:
  CC-CORE-0450; fuzzer: CC-FUZZ-0450.
- Risk (level; mitigation or accepted-risk justification): medium. Mitigations: path
  confinement and name grammar, 0600/0700 + child umask, one lock + busy-until-recorded,
  typed refusals, cross-site gate on every new POST (tested), browser page walk.
  Residuals (stated in the NFRs): a path swap between validation and SQLite's open by a
  process of the same user; a CLI process writing the same file is invisible to the UI;
  the Repeater stores typed requests as typed; with `--with-proxy` the project cannot be
  switched. The default-store change is mitigated by binding an existing `./fuzzlab.db`
  exactly as before (an existing setup sees no change) and by the start screen's one-click
  "Use it".
- Deliverables:
  - [x] `web/projects.py`, `web/projectroutes.py`, app/runner/proxycontrol wiring — done
  - [x] pages + topbar chip/banner — done
  - [x] tests: `tests/test_web_projects.py` (new); `test_web_launcher_browser.py` (pinned preview), `test_web_repeater.py` (controller never creates) updated — done
  - [x] FR-UI-450..457, NFR-UI-project-{private,paths-confined,provenance-redacted,switch-safe}, NFR-UI-read-only amended, §5; traceability classification; runbook section — done
  - [x] page layout from the UI research — done (layout pass, below): start screen + `/` redirect, use-default, Snapshot, Remove from list, leftover Discard confirmation, lineage, truthful last-written/size, labels
  - [x] real-browser tests: `tests/test_web_projects_browser.py` — done
- Review: design gate 3/3 (reviewers A and B, three rounds). Code review round 1 (on
  9f1536e): A — 1 blocking, 10 non-blocking; B — 4 blocking, 9 non-blocking. Fixed in the
  follow-up commit:
  - (A1, blocking) opening an older/newer file while a project is open was a silent
    no-op → the offer/refusal card shows whenever one is pending, with a message; the
    migrate form carries the discard confirmation.
  - (B1, blocking — CORE) a trigger named like a table hid from the trigger/view refusal
    (one name → type map) → see CC-CORE-0450's review note.
  - (B2/A3, blocking) New / Save as adopted, or on failure deleted, a stale
    `<name>.fuzzlab.d` → both refuse when any file the project would own exists.
  - (B3, blocking) a planted symlink (or hard link) at a pinned intermediate let a tool's
    `open()` write outside the project → each is checked (absent, or a plain singly
    linked file of ours, side files included) before the job starts.
  - (B4, blocking — CORE) `redact_for_record` kept part of a password containing `@`, and
    fragment / matrix / scheme-relative secrets → see CC-CORE-0450.
  - Non-blocking, all fixed: discard leftovers reported on every transition (`_switch`
    flashes; `current` set even if leaving raises); owner lock held until deletion ends;
    exception lists narrowed (`_ACTION_ERRORS`, `_RECORD_ERRORS` = `OperationalError`;
    OS errors converted to `ProjectError` at their sites; `ProjectError` → 409 on the API);
    `recent.json` opened `O_NOFOLLOW | O_NONBLOCK`, regular files only, read capped;
    missing parents of the projects directory created 0700; `.temporary` checked like the
    projects directory; recent entries must match `FILE_RE`; `_temporary` releases and
    removes on failure; a failure before the spawn marks the launch failed; `shutdown`
    waits (≤ `RECORD_WAIT_S`) so stopped jobs record `stopped`; the whole `_pump` tail is
    in its `finally`; thread-read dicts are snapshotted; Repeater state keyed by the
    file's identity (path + inode); `_ensure_created` tolerates a CLI creating the file
    meanwhile; AST guards track import aliases, `getattr`, openers passed as arguments,
    `core_project.create`/`copy_to` outside their functions, and every SQL write form.
  - Recorded deviation from design F18: refusals are a server-held, autoescaped message
    queue (`manager.flash`), not `?notice=<code>`; the text may quote the name the
    operator typed. One local operator; the next projects page consumes it.
- Code review round 2 (on 1e81639; reviewers A and B, fresh agents after a container
  restart): A — 1 blocking (narrowing the exception lists made stale pages and corrupt
  files 500s → each project operation's worker converts OS/SQLite errors into a named
  refusal via `projects._refusal`; recent ids must be ASCII digits), plus Repeater run ids
  re-checked on a cache hit (inodes are reused), a long target refused before any launch
  row, the pump tail always recording (`ProcUtilError` reported, `_RECORD_ERRORS` =
  `DatabaseError`, `SchemaTooNew`), and test fixes; B — 1 blocking (BUG-0451, CORE), plus a
  linear userinfo pattern and a 4096-character value cap, deep `recent.json` handled,
  AST guards that resolve aliases, flag any non-call use of an opener and join split SQL,
  `_copy_sidecars` single-link, `_temporary` cleanup by inode, `projects_dir` absolute, and
  two stated residuals (pinned-file TOCTOU, odd-character passwords).
- **Layout pass** (owner decisions: the research branch `claude/new-session-jqk4ku`;
  startup = the configured store, else the start screen; Save As **and** Snapshot;
  `recent.json` kept, the D21 global config DB a follow-up). Design gate: reviewers C and
  D, two rounds, 3/3 (with D's redirect rule and C's "no queued warning" condition).
  Built: the start screen (FR-UI-458) and `/` redirect; "Use ./fuzzlab.db" (BUG-0452's
  fix); the chip (FR-UI-454); Snapshot; Remove from list; leftover Discard confirmation;
  Open/Remove matched by index and path; listing summaries; interrupted labels; lineage on
  `/project`; real-browser lifecycle tests (`tests/test_web_projects_browser.py`).
  BUG-0452 (tests created `./fuzzlab.db`) recorded with PA-0452 and a session guard.
- Code review round 3 (on 8569187; a correctness and a security reviewer, fresh agents):
  - (blocking, CORE) BUG-0453 — see CC-CORE-0450.
  - (blocking, docs) living docs behind the code → FR-UI-450 (startup) and FR-UI-457
    (allowlist) brought current, ARCHITECTURE's build status, this entry's
    Change/Impact/Risk/Deliverables, CC-CORE-0450's migration 23 + allowlist impact, the
    CHANGELOG line and the module docstring.
  - BUG-0454 (CORE) — crafted values crashed `/project`; BUG-0455 (CORE) — see CC-CORE-0450.
  - Non-blocking, fixed: a migrated leftover temporary stays temporary (owner lock taken
    before the migration, inode recorded, never in Recent; `Pending.project_kind`);
    Not now takes the lock and a vanished offer is a refusal; `_refusal` no longer
    converts SQLite's defect classes (`ProgrammingError`, `InterfaceError`,
    `InternalError`, `IntegrityError`, `NotSupportedError`) and wraps the launch workers
    (a database error while recording a job is a 409); a failure leaving the previous
    project after a successful New/Open/Save as/migrate is a warning and the success's
    bookkeeping (recent, pending) still runs; Open from Recent requires the path; the
    already-open project from Recent is a no-op even while busy; the Open list's size and
    time count a non-empty `-wal`; the default offer says whether the file exists; a
    missing "last written" or metadata value reads "unknown"; `identity_malformed` is
    shown; the BUG-0452 guard compares the default store's state (store, side files, `.d`)
    so it stays armed when one pre-exists; `--with-proxy`'s start-up creation written
    into PA-0452(3)/FR-UI-458. Tests named in each fix's commit.
  - Follow-up (BUG-0454's sweep): the results pages that predate project files
    (`/runs/{id}`, findings, flows) also read the open project and may 500 on an odd
    value in a crafted file that passed the schema allowlist — a page error, not code
    execution or a write; for the results-pages owner.
  - Residual (stated): a migrated temporary's pre-migration backup (`<tmp>.d/backups/`)
    is kept, and reported, when the temporary is discarded. *(Superseded in round 4: it
    is now removed with the temporary.)*
- Code review round 4 (on bffa9c1; the same two reviewers): correctness — APPROVE with
  non-blocking items, all fixed: one `_refusal` on `_ensure_created` ("creating the
  project file"); a failure leaving the previous project gets its own warning, not "was
  discarded, but"; the dismiss test proves Not now waits for the lock; an unreadable
  recent list in the already-open check is a refusal, not a 500; a discarded temporary's
  own pre-migration backups (`backups/<stem>.pre-v<N>-<UTC>-<hex>.fuzzlab` and side files,
  regular files of this user) are removed with it, anything else in `backups/` left and
  reported (`_remove_own_backups`; also the security reviewer's item 2). Security — 1
  blocking (BUG-0456, CORE; see CC-CORE-0450).
- Effectiveness (assessed pending): pending.

### CC-UI-0054 — The run page names why a check was inconclusive (forms phase 3, lane J) (2026-10-14)
- Change: `web/results.inconclusive_by` and `templates/run.html` list inconclusive
  candidates by mechanism (a cost-capped check, or `unplaceable`: no mechanism could
  place the point), from the production-written metrics. Built in lane J (recorded
  there under CC-FUZZ-0068); this entry gives the UI component its own record at merge.
- Impact: FR-UI-19 (updated in place by lane J).
- Risk: low.
- Deliverables:
  - [x] code and template — done (lane J, 45a74b4)
  - [x] tests: `tests/test_web_ml_context.py`, `tests/test_web_pages_browser.py` — done
- Review: reviewers A and B (lane J re-reviews).
- Effectiveness: verified offline.

### CC-UI-0053 — Launcher jobs are tied to the UI and stopped as a whole tree (BUG-0125) (2026-10-14)
- Change: `web/runner.py`: `Runner.launch` starts each job with
  `procutil.astart_server(..., allow_thread=True)` (the event-loop thread lives as long
  as the UI); `stop()` requests a stop (non-blocking) and a watchdog falls back to an
  identity-checked group kill; the pump collects the supervisor and reports an
  unrequested stop on the job's stream; new `Runner.shutdown()` stops every live job,
  called from the app's lifespan shutdown (`web/app.py`). `web/labcontrol.py`:
  `fetch_states` runs `labctl.sh ps` through `procutil.arun_bounded`, so a timeout
  stops the container-engine child too, not only `bash`. FR-UI-6 gains the job-lifetime
  sentence.
- Decision (BUG-0125 D18, the coordinator's rule "keep the most operator
  flexibility"): **tied to the UI's life**, not "outlive it with a stop path". A job's
  output streams to the UI over a pipe, so a job that outlived its UI would run blind
  and die on its next write; tying it gives a deterministic whole-tree stop, and the
  operator keeps the other option by running the previewed command from the CLI.
- Impact: Stop now ends a crawl's browser and a `labctl.sh` compose call too; closing
  the UI ends its jobs.
- Risk: low. A `labctl.sh` action stopped mid-way by a UI shutdown leaves what the
  compose provider leaves; `labctl.sh`'s own self-heal (PA-0018/PA-0059) handles the
  next call.
- Deliverables:
  - [x] runner, app lifespan, labcontrol — done
  - [x] tests: `tests/test_web_runner.py::test_runner_stop_takes_the_jobs_whole_tree`,
    `::test_runner_shutdown_stops_every_live_job`,
    `tests/test_web_lab.py::test_fetch_states_timeout_stops_labctls_whole_tree` — done
- Effectiveness (assessed 2026-10-14): `test_web_runner.py` 14 passed, `test_web_lab.py`
  42 passed (offline; a stand-in `labctl.sh`, no engine, no traffic).
- BUG-0130 note (2026-10-14, with CC-CORE-0051): `Runner.stop` reports on the job's
  stream any socket of its tree listening beyond loopback (checked while it still runs;
  the tools gate their own listeners), and the stop watchdog and `shutdown` report a
  `NonLoopbackListener` / `ServerLost` on the stream instead of dropping it. Test:
  `tests/test_web_runner.py::test_runner_stop_reports_a_job_listening_beyond_loopback`
  (19 passed in that file). No template or JS change.
- BUG-0125 review rounds 2-3 (2026-10-14, with CC-CORE-0050): `Runner._pump` reads output
  in a task, waits for the supervisor's exit, then drains for at most `Runner.DRAIN_S`
  (a descendant that outlives the job cannot hold the stream open); a run's end is its
  own `finished` flag; an unknown exit status (the supervisor reaped outside fuzzlab,
  `procutil.CODE_UNKNOWN`) goes out as `returncode: null` plus a `[fuzzlab] exit status
  unknown` line, and `launcher.js` / `lab.js` print `[exit unknown]` for null (never
  `[exit -256]`); `labcontrol.fetch_states` says "exit status unknown". Tests:
  `tests/test_web_runner.py::test_runner_stops_reading_output_a_survivor_holds_open`,
  `::test_runner_done_event_carries_null_for_an_unknown_exit_status`,
  `::test_lab_states_report_an_unknown_exit_status_plainly`, and the real-browser
  `tests/test_web_pages_browser.py::test_an_unknown_exit_status_renders_as_unknown`
  (routed run and stream: no job, no container). Effectiveness (PA-0065(2)): with
  `FUZZLAB_REQUIRE_BROWSER=1`, `test_web_pages_browser.py` + `test_web_launcher_browser.py`
  **10 passed** and `test_web_templates_csp.py` 20 passed, 0 skipped; reverting either JS
  handler fails the browser test.

### CC-UI-0052 — Run page: `inconclusive` oracle coverage; `pending` reworded (2026-10-14)
- Change:
  - **`web/results._ml_context`:** counts `inconclusive` (CC-CORE-0043) as its own
    status. Before, an unknown value fell into "unrecorded".
  - **`run.html`'s oracle-coverage card:**
    - shows "inconclusive N (a cost cap stopped a check that had started)";
    - includes it in the card's show condition and in the unlabelled note;
    - rewords `pending` to "not reached: run interrupted, or stopped by a safety
      breaker". This covers lane A's header-breaker rows, which stay `pending`.
- Impact: display only. FR-UI-19 is amended.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_web_ml_context.py`): the counts dict, and the browser page
        showing the new line with "unrecorded" still separate — done
  - [x] FR-UI-19 — done
- Review: reviewer A (web change list for the new status); pre-assigned with lane A's
  `pending` wording (PA-0031).

### CC-UI-0051 — Safety-NFR traceability lines (PA-0112, BUG-0111/0112 sweep; documentation only) (2026-10-13)
- Change: `requirements.md` gains `Enforced by:` / `Not yet enforced:` lines under
  NFR-UI-localhost, -read-only, -redacted, -no-auto-run, -control-plane-hardened, naming the enforcing code and the test functions that fail without it
  (checked by `tests/test_requirements_traceability.py`). Open: Repeater/plugin-config redaction, "served separately", read-only by convention, several untested control-plane cases. No code change.
- Impact: none at run time. The guard now fails if these lines go stale (a renamed or
  deleted test) or if a new NFR is left unclassified.
- Risk: none (documentation, plus a test that reads it).
- Deliverables:
  - [x] traceability lines — done
  - [x] open clauses recorded and reported to the operator — done
- Review: reviewers A and B (BUG-0111/0112 draft v2, AGREED) asked for one doc-only entry
  per touched component.
- Effectiveness: verified by the guard (3 passed, incl. synthetic offenders).

### CC-UI-0050 — The ML tab never shows a number computed from sealed labels (BUG-0091) (2026-10-13)
- Change:
  - `mlview._scored_pairs` (classifier panel: PR, reliability, ECE) and `ranker_panel`
    compute `holdout.held_ids(store, ds)` once and pass `held=` to
    `train.metric_input`, so every sealed row is left out, whatever model scored it.
  - `disagreement_panel` never fits its committee on a sealed row, and is unavailable
    on an unknown holdout membership.
  - `_ml()` exposes `fuzzlab.ml.holdout`.
- Impact (other components / project):
  - **ML** (CC-ML-0024): the predicate.
  - On a sealed target, the panels show fewer rows (the public ones).
  - The conformal panel (decisions, no labels) and the anomaly panel (label-free) are
    unchanged, by design.
- Risk: low. The panels are covered by the flip-sealed-labels test and the existing
  ML-tab and browser suites.
- Deliverables:
  - [x] readers sealed — done
  - [x] tests: `test_ml_holdout_seal` (panels flipped, unknown membership) — done
  - [x] the UI requirements note amended — done
- Implementation divergence: none.
- Review: the review-8 draft (all seven findings reproduced first) went v1 → v4 through both reviewers. v1→v2: B, 4 should-fix + 4 nits. v2→v3: A, 1 must-fix + 4 should-fix + 3 nits. v3→v4: A and B, the same must-fix (an implied holdout for every trainer). v4 was AGREED 3/3, and the final optional nits (A: store-wide trains skip, not refuse, an unknown target; B: the prioritizer raises, never returns None) were adopted.
- Effectiveness (assessed 2026-10-13): effective offline. Every finding's reproduction is now a test that fails on `5eb4be9` (counts in each bug doc). Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 38 mutants across the seven fixes, 35 killed on the first pass. The 3 survivors each showed a test gap (the plural fold of `pass`, the loader boundary's `OverflowError` catch, the discovery-hop https floor), and each gap was closed with a new test, after which 3/3 were killed (38/38). Full non-labgen suite (145 files, `FUZZLAB_REQUIRE_BROWSER=1`): 1869 passed, 13 skipped, 2 xfailed, 0 failed. The review-8 test files, re-run after the gap tests: 327 passed, and `test_secretfile` 13/13 with the reviewers' self-healing test. The labgen half was not re-run, since no labgen code changed.

### CC-UI-0049 — Proxy API rule validation; one loopback gate; IPv6 repeater seeding; pooled bandit rows (BUG-0080, BUG-0085, BUG-0086, BUG-0088) (2026-10-13)
- Change:
  - **Rule validation (BUG-0085).** `POST /api/proxy/scope` answers **400** on an
    invalid rule, as match/replace already did.
  - **Loopback (BUG-0080).** `app.serve` and `ProxyController.build` use
    `core.net.require_loopback`.
  - **IPv6 seeding (BUG-0086).** `proxycontrol.create_from_flow` splits the flow's
    host with `split_authority`.
  - **Pooled bandit rows (BUG-0088).** `mlview.bandit_panel` and
    `diagnostics.bandit_arms` flag `pooled` contexts. `ml.js` and `diagnostics.js`
    label them "(pooled)" / "(all contexts, pooled)", and a pooled mean cost shows
    "n/a (pooled)".
- Impact (other components / project): reads CORE, PROXY and SCHED changes. JSON fields
  are added (`pooled`); none are removed.
- Risk: low.
- Deliverables:
  - [x] API 400s; gate; IPv6 seeding; pooled labels — done
  - [x] tests in `test_proxy_rules_and_scope`, `test_loopback_listeners` and
        `test_scheduler_backoff`; the web suites with the real browser required — done
  - [x] FR-UI-11 amended — done
- Review: the review-7 draft v1 got AGREE-with-changes from both reviewers (A: 2 must-fix, 7 should-fix, 3 nits; B: 6 should-fix, 4 nits), all adopted; v2 was agreed 3/3, with the final nits adopted.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Mutation check** (a copy of the worktree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **40 of 40** review-7 mutants killed. Six first survivors were killed after adding tests for: the leaf cache refusing directly; 0600 with `chmod` disabled; the path backstop alone; a same-origin 307; a line-comment-split `INSERT … INTO`; a JS string open at a newline.
  - **Suites:** **non-labgen suite** (143 files, real browser and lint required; ): **1730 passed, 13 skipped, 2 xfailed, 0 failed**. The live multitarget category-3 / category-4 runs pass with no concurrent load. Packaging / no-ML / contract writers / lint: 22 passed, 1 skipped (the wheel, the known Debian setuptools issue). The labgen suites are untouched by this batch; the last full run (review 6) failed only the 33 known environmental tests (no scipy, scikit-learn or gitleaks).

### CC-UI-0048 — Ranker panel baseline from the trainer's function (BUG-0073); bandit pulls from `cost_n` (BUG-0077); pending oracle status on the run page (BUG-0071) (2026-10-13)
- Change:
  - **Ranker panel (BUG-0073).** `mlview.ranker_panel` computes nDCG@k / precision@k and
    their random baselines with `rank_train.evaluate_vs_random`, over the same rows and
    groups, with the model's recorded seed. It adds `random_baseline_ndcg_at_k`. The JS
    meta line shows both baselines, and the bars chart plots the real nDCG baseline (it
    was 0).
  - **Bandit panel (BUG-0077).** `pulls` is the stored `cost_n`, not `α + β − 2`. A NULL
    shows "n/a (legacy)" in the forest table.
  - **Run page (BUG-0071).** `_ml_context` counts `pending`. The Oracle-coverage card
    shows "pending N (run interrupted before the oracle reached them)" and appears when
    only pending rows exist.
- Impact (other components / project): reads CC-ML-0023 (`evaluate_vs_random`) and
  CC-CORE-0033 (`PENDING`). No route or JSON field was removed; `oracle_status` and the
  ranker panel gain fields.
- Risk: low. Display only.
- Deliverables:
  - [x] ranker baselines; bandit pulls; pending count — done
  - [x] tests:
    - a constant ranker shows no lift over its baseline (0.5 = 0.5, nDCG = the
      permutation expectation);
    - a production-writer bandit pull count;
    - the panel pull test asserts `cost_n` (was the pinned `α + β − 2 = 14`);
    - `pending: 0` in the ML context test — done
  - [x] FR-UI-11 updated in place — done
- Review: the review-phase draft agreed 3/3.
- Effectiveness (assessed 2026-10-13): effective offline. Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **26 of 26** review-batch mutants killed (one survivor, the ranker reader passing the classifier's score column, was killed after adding `test_each_family_reader_backs_a_legacy_row_with_its_own_score_column`). Every new regression test fails on the pre-fix code. Suite results: see the related suites (83 files: auto, pipeline, plugins, ML, web incl. real-browser, report, oracle, scheduler, CLI, contract writers, lint, no-ML, packaging, harness, store, migrations, diagnostics; `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 1054 passed, 1 skipped, before the last three tests were added, which pass with their files; greybox / multitarget / auto / store / CLI: 143 passed. The non-labgen and full-suite runs were still in progress at commit time and are recorded in a follow-up entry.

### CC-UI-0047 — Report `feature_versions` per counter, from what the run actually read (BUG-0069); dead `overview_summary` removed; web lint (2026-10-13)
- Change:
  - **`report/report.py` `_feature_versions`.**
    `reproducibility.feature_versions` becomes `{"candidate": [...], "flow": [...]}`.
    **This is a JSON contract change from a list.**
    - **candidate:** stored `candidate.feature_version`, the run's pinned models'
      `feature_version`, and the `anomaly_feature_version` /
      `pipeline_budget_feature_version` metrics;
    - **flow:** `flow_anomaly_feature_version`.

    The text report gains a `feature versions:` line.
  - **`web/results.py`.** The first, dead `overview_summary` (R1: category / 7-day
    breakdown) is removed. It was entirely shadowed by the second (U1: severity), which
    every consumer, the template and the tests use, so behaviour is unchanged.
  - **`web/proxycontrol.py`.** An unused import is removed.
- Impact:
  - Consumers of the report JSON reading `feature_versions` as a list must read the
    dict. The only in-repo consumer is `tests/test_report.py`, which is updated.
  - Nothing else changes in behaviour.
- Risk: low.
- Deliverables:
  - [x] report — done
  - [x] dead definition removed — done
  - [x] FR-UI-17 note — done
  - [x] tests:
    - a production-writers-only report test: no stage → `[]`, trained → `[1]`, anomaly
      only → `[1]`, a read-only refit records nothing;
    - flow (once across reruns) and the prioritizer;
    - `test_report`'s updated expectation;
    - `tests/test_lint.py` (pyflakes clean, honouring `# noqa`; `FUZZLAB_REQUIRE_LINT=1`
      makes a missing pyflakes fail).

    — done
  - [x] BUG-0069 report, ERROR_LOG, PA-0071, `tests/test_contract_writers.py` — done
- Review: covered by the batch-5 3/3 pre-change review (A4, A5, B5, B10, B3 v2).
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Related suites** (95 files: ML, auto, web incl. real-browser, plugins, report,
    no-ML incl. the real no-ML build, harness, multitarget, pipeline, diagnostics, core,
    CLI, store, migrations, packaging, lint, contract writers, on-host script, greybox,
    store adapter, session, labgen CLI, mutation, oracle;
    `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 1249 passed, 3 skipped,
    11 failed.
    - 10 failures are `test_labgen_cli.py` tests, among the 33 known environmental
      failures (no scipy, sklearn or gitleaks).
    - The 11th, the multitarget live-boot test, failed with a connection reset from its
      locally booted server while two other suites held the CPU. It passes alone
      (2 passed).
  - **Mutation check** (a staged git copy, bytecode caches cleared): all 21 batch-5
    mutants are killed. Three were first mis-anchored by shell expansion in the
    mutation script and were re-run correctly. Killed:
    - old per-directory globs; no dotfiles;
    - deny-list missing pem / env; an over-broad deny pattern; a one-line no-ML switch;
    - report union missing models / stage metrics / flow;
    - the anomaly version on the read-only path, or missing;
    - flow-version duplicates; prioritizer / pipeline version missing;
    - CSV / greybox schema missing;
    - `_check_sql` never failing; the reveal not opt-in; a literal 5 in the budget check;
    - a lint regression; the dropped `Probe` import.

### CC-UI-0046 — Ranker panel shows pairwise honestly; anomaly panel reads stored flags; anomaly method on the run page; `flow-anomaly` in the launcher (2026-10-13)
- Change:
  - **`mlview.ranker_panel`:**
    - `uncertainty_available` (false for pairwise: no uncertainty histogram or scatter)
      and `objective` (per pooled run's ranker; "mixed" when they differ);
    - `global`: the selected ranker's stored per-fold run-wide NDCG / P@k, for a per-run
      view or a store-wide train.
  - **`mlview.anomaly_panel`:**
    - per run, the **stored** scores and flags with `_anomaly_stage` (method and
      contamination from the run's `ml-anomaly` config, or "unknown (assumed ECOD)");
    - `flag_budget` from `run_metrics`, `reason` from `core.anomaly_flags.flag_note`,
      and a per-method `axis`;
    - otherwise ECOD is recomputed, labelled `source: "recomputed (ECOD, c)"`.
  - **`ml.js`.** The ranker meta adds "objective …", "run-wide nDCG@k … (per-fold
    scales — not pooled)" and "uncertainty n/a (pairwise)". The anomaly meta leads with
    the source, method and contamination. The histogram axis is per method. All of it
    is text.
  - **Run page.** `_ml_context` adds `anomaly.method`, and the card shows "method X".
  - **`commandspec._REGISTRY`** gains `flow-anomaly` (`sends_traffic=False`, loader
    `_load_flow_anomaly`).
- Impact:
  - A run's anomaly panel now agrees with its run page and CLI: it shows the stored
    flags, not a fresh ECOD refit.
  - The batch-2 browser assertion on the anomaly meta was updated deliberately: it now
    checks the stored path and the all-runs recomputed path.
  - The launcher lists one more command.
- Risk: low.
- Deliverables:
  - [x] ranker panel — done
  - [x] anomaly panel — done
  - [x] run page method — done
  - [x] launcher entry — done
  - [x] FR-UI-11 / FR-UI-19 notes — done
  - [x] tests:
    - data-level panel and run page tests (`tests/test_ml_batch4.py`);
    - a real-browser test of the pairwise and iforest text;
    - `tests/test_web_ml_context.py`'s updated stored / recomputed anomaly assertions;
    - `flow-anomaly` in `command_names()`.

    — done
- Review: covered by CC-ML-0021's 3/3 pre-change review (A2, A3, B4-3, B4v2-1/2).
  Renumbered from CC-UI-0045 (PA-0031).
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (61 files incl. real-browser, no-ML, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 953 passed. Batch-4 files (`test_ml_batch4.py`, `test_candidate_features_core.py`, `test_no_ml.py`, `test_web_ml_context.py`): 57 passed after the mutation-driven additions. Its mutants are among CC-ML-0021's 28, all killed.

### CC-UI-0045 — ML tab: held-out rows left out of out-of-fold metrics; calibration evidence; sealed tables hidden (2026-10-13)
- Change:
  - **`mlview._scored_pairs`** joins each row with its own run's scoring model and
    keeps a row only per `train.metric_input`: out-of-fold where stored, never a sealed
    held-out row. It returns `(scores, labels, groups)`.
  - **`ranker_panel`** does the same for `rank_score_oof`, with `_rank_calibration`.
  - **`mlview._reliability`** delegates to `metrics.reliability`; its output is
    unchanged.
  - **`classifier_panel` gains `calibration`** (`_calibration_evidence`): the
    calibrator and its out-of-fold ECE / Brier, raw against cross-fitted, rounded to
    4 dp. It is shown for a per-run model, or a store-wide train in the all-runs view.
  - **`ml.js` `calibrationNote`** adds "Platt-calibrated: out-of-fold ECE a raw → b
    cross-fitted", or "calibration: none (degenerate fit)". It is text only.
  - **`diagnostics.list_tables` / `_resolve_table`** exclude
    `core.sealed.SEALED_TABLES`: they are not listed, and browsing one answers like a
    missing table.
- Impact:
  - The ML tab's out-of-fold numbers for a holdout-trained run exclude its held-out rows,
    which is correct and intended. Every other run's numbers are unchanged.
  - The store browser lists two fewer tables once migration 17 is applied.
  - No route changes.
- Risk: low.
- Deliverables:
  - [x] metric exclusion (classifier and ranker) — done
  - [x] calibration evidence and note — done
  - [x] sealed tables hidden — done
  - [x] FR-UI-2 and FR-UI-11 notes — done
  - [x] tests:
    - the classifier panel `n` excludes held rows;
    - the shared ECE;
    - the sealed surfaces, with every route returning 200 and the sealed tables
      answering 404 like a missing table;
    - a real-browser calibration note (`FUZZLAB_REQUIRE_BROWSER=1`).

    — done
- Review: covered by CC-ML-0020's 3/3 pre-change review (A2/B3v2-2, B3-12).
  Renumbered from CC-UI-0044 after BUG-0070 took that number (PA-0031).
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (58 files: ML, auto, web incl. real-browser, plugins, report, no-ML, harness, multitarget, pipeline, diagnostics, core, CLI, store, migrations; `FUZZLAB_REQUIRE_BROWSER=1`): 901 passed. `tests/test_ml_holdout_calibration.py`: 42 passed. Its mutants are among CC-ML-0020's 27, all killed.

### CC-UI-0044 — Gate and anomaly-flag notes on the run page and ML tab; "never" thresholds (BUG-0070) (2026-10-13)
- Change (readers of CC-ML-0019's corrected gate and tripwire):
  - **Run page** (`results.py`, `templates/run.html`):
    - The "Model scores" card lists `model.gate_notes` (`train.gate_notes`) as
      `[data-field="gate-note"]` lines, e.g. "Conformal gate: never drops: needs ≥ 9
      positives at α=0.1 (has 6)", or the pre-BUG-0070 label for an old row.
    - The anomaly card gains `budget` and `note` (`core.anomaly_flags.flag_note`): an
      old-rule label, or why fewer than k were flagged. The card now also shows when
      nothing was flagged but there is a note, so a run flagged 0 because of ties says
      so.
  - **ML tab conformal panel** (`mlview.conformal_panel`, `ml.js`):
    - `t_lo` / `t_hi` are shown via `_threshold`: 4 dp, `null` for a "never" sentinel
      (rendered "never"), never `-0.0`.
    - New `notes` field: the selected gate's `gate_notes`, plus the old-rule note when
      **any** pooled run's gate lacks `gate_rule`.
  - **ML tab anomaly panel** (`mlview.anomaly_panel`, `ml.js`):
    - k comes from `anomaly.flag_budget` instead of being recomputed here (PA-0003).
    - `threshold` is the lowest flagged score, or `null` when nothing was flagged.
    - New fields `flag_budget` and `reason`. The meta line reads "flagged F/N (P%, at
      most k) · threshold … · <reason>".
  - All new text is inserted as text (`textContent` / Jinja autoescape).
- Impact: read-only views. No API removed; `conformal_panel` and `anomaly_panel` gain
  fields, and `t_lo`/`t_hi`/`threshold` may now be `null`. `ml.js` handles that. The
  run page works without ML: the anomaly note is a core store read, and gate notes come
  through `import_ml` only when a classifier exists.
- Risk: low. Nullable thresholds are covered by the browser test.
- Deliverables:
  - [x] run page gate notes + anomaly note — done
  - [x] conformal panel "never" display, notes, pooled old-rule note — done
  - [x] anomaly panel `flag_budget` / `reason` — done
  - [x] `tests/test_web_ml_context.py::test_gate_and_anomaly_notes_show_as_text` in real
    Chromium (`FUZZLAB_REQUIRE_BROWSER=1`) — done. It covers the run-page gate note
    text, the run-page anomaly note for a tie-limited run, the ML tab "t_lo=never" plus
    the never-drops note and anomaly reason, and no `-0`.
- Review: covered by CC-ML-0019's 3/3 pre-change review (the reader items came from A1,
  A6, B3 and B v2-1).
- Effectiveness (assessed 2026-10-13): effective offline.
  - The browser test passes in real Chromium, and `test_web_ml_context.py` passes
    (15).
  - These mutants are killed: the panel's `-0.0` / never display, the pooled old-rule
    note, and the run-page gate note (CC-ML-0019's mutation check).

### CC-UI-0043 — ML tab run picker; run page shows oracle coverage, anomaly flags and the plugin record (2026-10-13)
- Change:
  - **ML tab** (`sections/ml.html`, `static/js/ml.js`):
    - **Picker.** `<select id="ml-run">` offers "All runs" plus each run from
      `GET /api/runs` (newest first, labelled "#id tool started_at").
      - Options are built with `new Option(text, value)`, so text only.
      - Runs with no candidates are suffixed "(no candidates)" and disabled.
    - **Choosing a run** fetches `/api/ml/data?run_id=N` and re-renders every panel.
      - Before each render, `resetPanel` hides the empty message, clears the meta lines,
        destroys the panel's charts and empties its tables.
      - Only the latest choice renders: a sequence token drops late responses, and an
        `AbortController` cancels the in-flight one.
    - **URL.** The choice is kept as `/ml?run=N` (`history.replaceState`). A value that is
      not a positive integer, an unknown id, or a disabled run falls back to all runs,
      with no request for it.
    - **Bandit panel** is titled "(all runs)", since it is store-wide in every view.
  - **Run page** (`results.run_detail` + `run.html`): three new cards, all plain per-run
    store reads, so they work without the ML package.
    - **Oracle coverage:** checked / skipped (budget) / no confirmer / unrecorded
      counts, bound to `core.oracle_status`. The note that skipped rows count as misses
      appears only on a scored run.
    - **Anomaly tripwire:**
      - the top 10 flagged candidates by stored score, read through the new ML-free
        `core/anomaly_flags.top_flagged`;
      - the run's own `anomaly_flagged`, and the `ml-anomaly` stage config, as
        provenance;
      - a note that these are the last fit's values.
    - **Plugins and ML stages:** name, version, config, and the status as text: NULL →
      "unknown", `attached` → "attached — run did not finish", `failed` → "FAILED:
      <error>" (truncated to 300 characters, full text in `title`), `ok`.
  - **One reader.** `core/anomaly_flags.top_flagged(store, run_id, limit)` replaces the ML
    stage's copy (PA-0003). It orders by score, then id, descending, the order the CLI
    always printed, so the golden summaries are unchanged.
  - **`list_runs`** gains each run's candidate count, one more COUNT per run (accepted:
    the runs list is small).
- Impact: read-only UI. FR-UI-19 is added and FR-UI-11 gets a note.
  - **PA-0063(2) / PA-0067(1) reader audit:** the new `run_plugin`, `oracle_status`,
    anomaly and `run_metrics` reads on the run page are per run, filtered by `run_id`,
    which matches their reader (one run's page).
- Risk: low.
- Deliverables:
  - [x] Picker, reset, stale-response guard, URL state; run-page cards; shared
    `top_flagged` — done
  - [x] `tests/test_web_ml_context.py` (14, real Chromium, `FUZZLAB_REQUIRE_BROWSER=1`) — done:
    - **Run data:** the coverage counts; anomaly order, limit and provenance; every
      plugin status text, including truncation; candidate counts in `list_runs`; the
      per-run payload.
    - **Picker:** lists runs as text, with a hostile run label rendered literally, no
      injected element, no CSP violation, empty runs disabled.
    - **Choosing a run:** the request carries `run_id=N`, and that run's own OOF line
      appears.
    - **Switching:** available → unavailable → available leaves no stale panel; a late
      response for an older choice is dropped.
    - **`?run=`:** `0`, `-1`, `abc`, an unknown id and a disabled run all fall back;
      a valid choice is restored.
    - **Run page:** the coverage, anomaly and plugin cards render hostile values as
      literal text.
- Review: pre-change review gate cleared 3/3 over drafts v1 to v3 (every raised issue
  adopted).
- Effectiveness (assessed 2026-10-13): effective in a real browser.
  - **Tests:** `test_web_ml_context.py` 14 passed under `FUZZLAB_REQUIRE_BROWSER=1`.
    The browser smoke (`test_web_pages_browser.py`) and the no-ML child
    (`test_no_ml.py`) still pass, as do `test_web_templates_csp.py` and the golden
    summaries.
  - **Mutation check** on a copy: every behavioural mutant is killed:
    - the per-panel reset;
    - stale-response handling (the sequence check and the abort removed together);
    - the picker ignored; `innerHTML` options; empty runs enabled; a disabled or unknown
      run accepted from the URL;
    - NULL status shown as ok; error truncation; `|safe` in the template;
    - the anomaly order; the flagged count.
  - **Equivalent mutants**, stated and not counted:
    - removing *only* the sequence check, or *only* the abort, is masked by the other
      guard;
    - removing the URL's integer regex is masked by the known-option check.
### CC-UI-0042 — Gates judge the score they were calibrated for (BUG-0067 fix site); evaluation labels; saved models in the report (2026-10-13)
- Change:
  - **Run page** (`results._scored_candidates` + `run.html`):
    - Each decision uses `train.gate_input`.
    - A new **decision score** column shows the score the decision judged: the
      out-of-fold score for a labelled run-mode row, else the deploy score.
    - A legacy in-sample row reads "n/a (in-sample score)".
    - The list stays ordered by the deploy `score`. A note explains the decision score.
  - **ML tab (`mlview`):**
    - `conformal_panel` gates every row with its own run's classifier and
      `gate_input`, counts `n/a` rows separately, and reports `judged` and
      `per_run_gates`.
    - The classifier and ranker metrics are recomputed from `score_oof` /
      `rank_score_oof` when stored.
    - **Evaluation labels:**
      - `out-of-fold (labelled rows)` for `score_source == "oof-labelled"`;
      - `not trained on this run's labels (saved model #ID)` for saved;
      - earlier as before; legacy `in-sample (deploy fit)`;
      - `mixed` across disagreeing pools.
    - `_earlier_trained` accepts `saved`, so forward metrics and `seen_fraction` show.
  - **`ml.js`:** the conformal line shows "(each run gated by its own model)" and
    "n/a K (in-sample score)".
  - **Report:**
    - `_training` gives `{trained_on: "saved", train_run_ids, source_model_id}`;
    - the text note reads "(saved model #ID, trained on runs …)".
- Impact:
  - Read-only. FR-UI-11's evaluation text is updated in place, and FR-UI-17 gets a
    note.
  - **Tests updated deliberately:**
    - `test_ml_oof.py` and `test_ml_train_on_earlier.py`: new run-mode models read
      "out-of-fold";
    - `test_web_ml.py`: a legacy seeded model is now all `n/a`, and a new test gates
      out-of-fold scores;
    - `test_web_pages_browser.py`: the label.
- Risk: low.
- Deliverables:
  - [x] Run page, `mlview`, `ml.js`, report — done
  - [x] Tests — done:
    - the out-of-fold decision and decision score on the run page;
    - the legacy n/a case;
    - re-scored runs gated on `score`;
    - the conformal panel's out-of-fold gating against contradicting deploy scores;
    - the labels;
    - the saved report block and text;
    - the browser smoke (8 passed under `FUZZLAB_REQUIRE_BROWSER=1`).
- Review: pre-change review gate cleared 3/3 over drafts v1 to v4 (the proposing agent plus 2 independent reviewer agents; every raised issue adopted).
  - **Process note:** `core/oracle_status.py`, `core/urls.canonical_origin`, the dataset changes and `--hybrid` were drafted in the working tree **before** agreement. They were kept uncommitted and reconciled with the agreed v4.
  - **Reverted:** my early in-column version of D-c was reverted; reviewer B's separate-column design replaced it.
- Effectiveness (assessed 2026-10-13): effective offline. Related suites (ML, auto, web incl. browser smoke, plugins, report, no-ML, harness, multitarget; `FUZZLAB_REQUIRE_BROWSER=1`): 705 passed, including `test_ml_saved_and_decisions.py` 39 and `test_auto_train_on.py` 13. Mutation-checked on a copy with bytecode caches cleared: all 20 mutants are killed. The first run left two survivors, and each got a new test (noisy data where in-sample and out-of-fold PR-AUC differ; an earlier-trained saved source). Killed:
  - **gates:** the legacy gate on in-sample scores, `score_oof` ignored, the run page or conformal panel judging `score`;
  - **out-of-fold columns:** not written, not cleared by earlier mode, ranker out-of-fold dropped;
  - **saved selector:** any scope run, a bool scope, copies chosen, the wrong `train_run_ids`;
  - **targets and labels:** the localhost alias dropped, an empty host matching, no_confirmer labelled, exact-text target matching;
  - **UI and report:** the tab's metrics on deploy scores, the out-of-fold label missing, the report's saved block missing;
  - **CLI:** `--hybrid` allowed with saved.
  Full-suite result (on commit c16477e, `FUZZLAB_REQUIRE_BROWSER=1`): 3113 passed, 65
  skipped, 9 xfailed, 33 failed. The 33 failures are exactly the known environmental
  labgen failures (no scipy, sklearn or gitleaks), identical to the step-3 baseline.

### CC-UI-0041 — Web app and report work without `fuzzlab.ml`; report shows plugin config and status (2026-10-13)
- Change:
  - **`mlview`:**
    - No module-level ML import. `_ml()` loads the modules through `import_ml`
      (cached).
    - The ML-backed panels (`@_ml_panel`: classifier, weights, ranker, conformal,
      anomaly, disagreement) return `{"available": false, "reason": "ML components are
      not installed"}`. The bandit and mutation panels are unaffected.
  - **`results`:**
    - `_scored_candidates` still lists the stored scores, with no model and decision
      `n/a`.
    - The run detail gains `ml_unavailable`, which the run page's "Model:" line shows
      (`run.html`, text only).
  - **`report`:**
    - **ML absent:** `models: []` plus `models_unavailable` (also in `reproducibility`);
      the text report reads `models: unavailable (…)`. It never claims "no models" and
      never falls back to an inline `model` query.
    - **`plugins` items** gain `config`, `status` and `error`. `reproducibility` gains
      `plugin_config` and `plugin_status`, and `plugins` stays name→version.
    - **Text report:** a failed plugin is marked `(FAILED)`.
- Impact: read-only. FR-UI-18 is added and FR-UI-17 extended. `test_report.py` was
  updated explicitly for the new plugin item keys.
- Risk: low.
- Deliverables:
  - [x] `mlview`, `results`, `run.html` and `report` — done
  - [x] `tests/test_no_ml.py` (8) — done.
    - **Setup:** a store is seeded with ML (`--score --rank --anomaly`). A child process
      (`tests/_no_ml_child.py`) installs a meta-path finder that **raises**
      `ModuleNotFoundError(name="fuzzlab.ml")`; the child proves ML is genuinely blocked.
    - **Scan:** a scan works; `--score` exits 2 with the message, no run row and no
      traceback.
    - **Report:** models unavailable, the ML stages still listed with their config.
    - **Web:** every HTML route returns 200. The ML panels are unavailable with the
      reason, and bandit/mutation are not. The run page lists the stored scores with
      `n/a`.
    - **Real Chromium** against a server child running without ML: `/ml` shows the
      reason in the calibration and ranker panels, the run page shows it, and there are
      zero page errors, console errors and CSP violations.
- Review: pre-change review gate cleared 3/3. The proposing agent and 2 independent reviewer agents went through DRAFT v1 to v4.
  - Reviewer A focused on architecture and spec fit; reviewer B on adversarial correctness, safety and tests, with SQLite experiments.
  - Every raised issue was adopted.
  - v1's guard was bypassable (a rename round-trip, a later-firing trigger, a temp shadow table, label state outside `finding`, an unguarded prioritizer). v1's failed-stage writes could also be committed by the next stage. Both were redesigned before any code.
- Effectiveness (assessed 2026-10-13): effective, including in a real browser. `tests/test_no_ml.py` 8 passed under `FUZZLAB_REQUIRE_BROWSER=1`. The child genuinely cannot import `fuzzlab.ml`, and real Chromium renders `/ml` and the run page without ML, with zero errors and zero CSP violations. With ML present, `test_web_*.py` and the browser smoke pass, and `test_report.py` passes as updated. The `mlview`, report and run-page mutants are killed. Full suite (2026-10-13, whole `tests/` with this change, `FUZZLAB_REQUIRE_BROWSER=1`): 3062 passed, 33 failed, 68 skipped, 9 xfailed. The 33 failures are the identical environmental labgen set as at `a3b782d` and `882cda8` (diffed: no scipy, scikit-learn or `gitleaks` binary here). Every skip is in lab/labgen/corpus tests guarded on toolchains or services, none in a file this change touches; the +3 against `882cda8`'s run is in that environment-dependent set.

### CC-UI-0040 — ML tab and report say how the scoring model was trained (2026-10-13)
- Change:
  - **`mlview.classifier_panel` / `ranker_panel`:**
    - **`evaluation`, per run:**
      - `"in-sample (deploy fit)"` for a `run`-trained, store-wide or legacy model
        (unchanged);
      - `NOT_TRAINED_ON_RUN` = `"not trained on this run's labels (trained on earlier
        runs)"` for an earlier-trained one.
    - **`evaluation`, all-runs view:** from every pooled run's scoring model (the runs
      with stored scores). One label when they all agree, else `"mixed"` (PA-0064(2)).
    - **`oof`** gains `scope` (`"this run"` / `"earlier runs"`). An earlier-trained
      model adds:
      - `forward` (the forward numbers, or `null`) and `forward_skipped_reason`;
      - `seen_fraction` and `train_run_ids`.
  - **`ml.js`** shows the label, "out-of-fold … on <scope>", the forward numbers (or
    "no forward evaluation (<reason>)") and "N% of this run's candidates seen in
    training".
  - **`report.py`:**
    - The reproducibility block gains `model_training: {name: {trained_on,
      train_run_ids}}` next to `model_params_sha256`.
    - A legacy or `run`-mode row reports `{"trained_on": "run", "train_run_ids": null}`.
    - The text report appends "(trained on earlier runs …)" to an earlier-trained model.
- Impact: read-only. FR-UI-11 gets a note; FR-UI-17 is extended.
- Risk: low.
- Deliverables:
  - [x] Panels, `ml.js`, report — done
  - [x] Tests — done:
    - The per-run label for each mode, and the exact `oof` payload with forward and
      seen fraction.
    - The forward-skip reason is shown.
    - The all-runs view is `mixed` for in-sample plus earlier-trained runs, and
      `NOT_TRAINED_ON_RUN` once only earlier-trained runs are pooled.
    - The report training block, for both modes and for a legacy row.
    - Real-browser test (g): the label, forward numbers, skip reason and seen
      percentage render with zero console errors or CSP violations.
    - The existing in-sample test is updated for `scope`.
- Implementation divergence (written back per the review gate):
  1. The all-runs view keeps `"in-sample (deploy fit)"` when every pooled run was
     run-trained. It is `"mixed"` only when pooled runs disagree. The draft's literal
     "mixed unless every pooled run is earlier-trained" would have relabelled every
     existing store-wide view, contradicting "the default `run` path is unchanged".
  2. `oof` also carries `train_run_ids` and `forward_skipped_reason`.
  3. The text report shows the training note.
- Preventive-action compliance:
  - **PA-0064(2):** in-sample, earlier-trained and mixed pools are each labelled for
    what they are.
  - **PA-0065:** verified under `FUZZLAB_REQUIRE_BROWSER=1` with a new real-browser
    test. No template change, so the CSP template guard is unaffected.
  - **PA-0067(1):** every pooled run's model is read per run through `latest_*`
    (reader scope: one run each).
- Review: pre-change review gate cleared 3/3 (with CC-ML-0016).
- Effectiveness (assessed 2026-10-13): effective, including in a real browser. `tests/test_web_pages_browser.py` 8 passed under `FUZZLAB_REQUIRE_BROWSER=1`, including the new (g): the label, `out-of-fold … on earlier runs`, the forward numbers, the skip reason and the seen percentage render with zero console errors or CSP violations. The payload and report tests pass. The UI-never-earlier, UI-no-mixed and report-always-run mutants are killed. Full suite (2026-10-13, whole `tests/` with this change, `FUZZLAB_REQUIRE_BROWSER=1`): 2973 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are exactly the same labgen `--check`/fingerprint-gate tests as at `a3b782d` and `369e887`, which fail identically in this environment because it has no scipy, scikit-learn or `gitleaks` binary. None is caused by this change.

### CC-UI-0039 — Per-run report pins the run's own models, not the store's newest (BUG-0066) (2026-10-13)
- Change: in `report/report.py::build_report`, `models` and `reproducibility.model_versions`
  come from `latest_classifier(store, run_id)` and `latest_ranker(store, run_id)`: the
  models whose scope covers *this* run (FR-ML-10). They no longer come from
  `SELECT name, MAX(version) … GROUP BY name` over the whole store.
  - Each entry is `{name, version, feature_version}`, as before.
  - A run with no trained model lists none.
  - Legacy rows without a `run_id` scope still cover every run, which is the old
    behaviour.
- Impact: on multi-run stores, reports of earlier runs stop citing later runs' models.
  `test_report.py:50,53` (single run) is unchanged. FR-UI-17.
- Risk: low.
- Deliverables:
  - [ ] Report reads through the scoped readers — done
  - [ ] Regression: two runs each train; run 1's report pins run 1's model versions, and
    fails on the old query — done
  - [ ] Full bug protocol: ERROR_LOG, BUG-0066, PA-0067, with a recurrence review naming
    BUG-0061's wrong sweep verdict — done
- Implementation divergence (reflected back per the review gate): per PA-0067 the model-table guard (`tests/test_ml_model_selection.py`) now also flags `MAX(version)` reads of `model` without a name filter; the old report query moved from its must-not-match fixtures to its must-match fixtures.
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3; both reviewers independently found BUG-0066; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — `test_report_pins_the_runs_own_models_not_the_newest` and the extended model-table guard both fail on the old `MAX(version) … GROUP BY name` query and pass on the fix; `tests/test_report.py` passes unchanged. Full suite at `a3b782d` (2026-10-13, whole `tests/`, `FUZZLAB_REQUIRE_BROWSER=1`): 2915 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are the same environmental labgen tests as at `369e887` (diffed, identical set); none is caused by this change.

### CC-UI-0038 — ML tab shows the saved logistic coefficients; report pins model params (2026-10-13)
- Change:
  - **`web/mlview.py::weights_panel(store, run_id)`**, added to `ml_overview` as
    `weights`:
    - For a `logistic` classifier it returns `{available, model: {name, version,
      params_sha256}, weights: [{feature, weight}] (sorted by |weight|), bias, note}`.
      An `anomaly_ecod` weight is labelled "anomaly score (ECOD)".
    - Otherwise it gives a reason: no classifier yet; trained before model saving;
      `gbt` ("tree model — no linear coefficients"); `prevalence` ("fallback has no
      features"); or the stored features no longer match (`check_compatible` failed).
  - **`ml.html`:** the panel gets the standard hidden `empty` / `summary` fields. The
    heading becomes "Logistic coefficients", with the caption "standardised log-odds
    coefficients — per standard deviation of each feature, other features held fixed;
    not feature importance (correlated features share weight; 0/1 features read
    oddly per SD)". The per-instance sentence is removed.
  - **`ml.js`:** `renderWeights` draws a signed bars chart, with meta "logistic vN ·
    sha <12> · bias b (standardised space)", through `renderSafely("weights", …)`.
  - **`report.py`:** the reproducibility block gains `model_params_sha256: {name:
    sha | null}` for the run's own models (CC-UI-0039).
- Impact: read-only. FR-UI-11 updated (weights panel real, per-instance sentence
  removed). The browser smoke covers the panel automatically.
- Risk: low.
- Deliverables:
  - [ ] `weights_panel` + overview; template; `ml.js`; report sha — done
  - [ ] Tests:
    - payload weights equal the stored `w`, mapped to names;
    - reasons for gbt, prevalence, legacy, none and incompatible;
    - the browser renders the weights chart with zero errors;
    - the report sha equals the row's sha, and is null for legacy — done
  - [ ] FR-UI-11 — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3; both reviewers independently found BUG-0066; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — weights payload equals the saved model's `w` mapped to names (the hybrid's ECOD weight labelled), sorted by |weight|; reasons for none / gbt / fallback / legacy; the report's sha block equals the row's sha and is null for a legacy row; the browser smoke renders the coefficients chart (its panel is available in the seeded store) with zero page/console errors and zero CSP violations (`test_web*.py` 270 passed under `FUZZLAB_REQUIRE_BROWSER=1`). Full suite at `a3b782d` (2026-10-13, whole `tests/`, `FUZZLAB_REQUIRE_BROWSER=1`): 2915 passed, 33 failed, 65 skipped, 9 xfailed. The 33 failures are the same environmental labgen tests as at `369e887` (diffed, identical set); none is caused by this change.

### CC-UI-0037 — Templates comply with the app's own CSP: no inline script/style (BUG-0064) (2026-10-13)
- Change:
  - `templates/base.html`: inline no-FOUC `<script>` moved verbatim to new
    `static/js/prefs.js`, loaded by a classic blocking `<script src="/static/js/prefs.js">`
    at the same place in `<head>` (still before first paint; allowed by `script-src
    'self'`; CC-UI-0026's CSP unchanged — a hash would break on any whitespace edit, a
    nonce needs per-response plumbing through the raw ASGI middleware).
  - `templates/sections/overview.html`: severity bar → one inline `<svg class="sev-bar-svg"
    viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label="…">` with a
    `<rect class="sev-seg sev-{sev}" x="…" width="…" height="10"><title>{sev}:
    {n}</title></rect>` per non-zero severity (x accumulated with a Jinja `namespace`).
    Presentation attributes are not inline styles (reviewer-verified: zero violations under
    the real `_CSP`, proportional widths, no JS). `overview.css`: `fill:` per `.sev-seg.sev-*`;
    svg sized to the existing `.sev-bar` box.
  - `templates/sections/launcher.html:129` and `launch.html:126`: `style="margin-top:.7rem"`
    → class `ft2--spaced` in the existing section stylesheet. `launch.html` is rendered by
    no route (grep) — fixed so the guard holds; recorded as dead in the bug doc, not
    deleted here.
  - Tests: `tests/test_web_frontend.py:110` asserts `/static/js/prefs.js` is referenced in
    `<head>` before the stylesheets (it previously asserted the inline script — the test
    enshrined the bug); `tests/test_web_overview.py:168-169` asserts the `<rect
    class="sev-seg sev-…"` markup; new static guard `tests/test_web_templates_csp.py`:
    every template under `fuzzlab/web/templates/` has no `<script>` without `src`, no
    `<style>` block, no `style=` attribute, no `\son[a-z]+\s*=` handler, no `javascript:`
    URL — each pattern proven first on must-match and must-not-match fixtures
    (`data-section=`, `content=`, `aria-controls=`, `<script src=…>`; PA-0022/PA-0034(2)).
- Impact (other components / project): UI only. Persisted theme/density/collapsed preferences
  apply on load for the first time since CC-UI-0026; the Overview severity bar shows. CSP
  unchanged.
- Risk (level; mitigation or accepted-risk justification): low; one cacheable same-origin
  static fetch in `<head>`. Covered by CC-UI-0036's browser test (zero violations on every
  page; (e), (f)) and the static guard.
- Deliverables:
  - [ ] `static/js/prefs.js` + `base.html` — done
  - [ ] SVG severity bar + `overview.css` — done
  - [ ] margin class (launcher.html, launch.html) — done
  - [ ] `test_web_frontend.py`, `test_web_overview.py` updated; `test_web_templates_csp.py` — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3, both reviewers verifying the fixes in real Chromium; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective — zero CSP violations on every page in real Chromium (CC-UI-0036's smoke); a persisted `fl-theme=dark` is applied after reload; severity `<rect>` widths are proportional to the seeded counts (critical:high = 6:1 within 5%); `tests/test_web_templates_csp.py` 20 passed and, with the fix reverted, flags exactly `base.html:7`, `launch.html:126`, `launcher.html:129`, `overview.html:120`; `test_web_frontend.py` + `test_web_overview.py` 42 passed.

### CC-UI-0036 — Charts actually render: uPlot option misuse fixed, ML panels fail-isolated, every page browser-smoked (BUG-0063) (2026-10-13)
- Change:
  - `static/js/chart.js::createChart.build()`: uPlot `class: "fl-chart"` (one token —
    uPlot 1.6.32 `addClass` is `classList.add(c)`, `uPlot.esm.js:85-90,2940`), then
    `u.root.classList.add(\`fl-chart--${type}\`)` right after `new uPlot(...)` inside
    `build()`, so `rebuild()` (theme/density change) keeps it. Mount gets
    `role="figure"` instead of `role="img"` (children of `img` are presentational, which
    hid the visually-hidden a11y data table from assistive tech). The mount's
    `aria-label` from `opts.caption` is refreshed on every `build()` when chart.js set it
    (marked `data-fl-aria="1"`); a template-authored `aria-label` is never overwritten
    (`chart.js:209` previously set it only once, so a reused mount kept a stale label); a
    rebuild without a caption removes a label chart.js set (reviewer edge case).
  - `static/js/diagnostics.js`: `renderTrendChart` / `renderSeriesChart` stop passing an
    x-series of their own (`[{}, …]`, `[{}]`) — `createChart` already prepends it, so they
    produced one series more than data columns (uPlot throws `reading 'length'`) and
    mislabeled the y series; the x label is passed as `opts.xLabel` ("run" / "step"). The
    series chart gets `scales.x.time = false` (step indices were drawn as timestamps).
    Both pass `caption` (the documented option, `chart.js:128`) instead of the ignored
    `ariaLabel`.
  - `static/js/ml.js::initMl`: each `renderX(...)` runs through `renderSafely(panelKey,
    fn)` — catch, `console.error`, and show that panel's existing empty state "could not
    render this panel (see console)" — so one panel's throw no longer blanks every later
    panel. `diagnostics.js` needs no equivalent: each chart is built in its own handler and
    the loaders are independent promises.
  - New `tests/_browser.py`: `launch_browser_or_skip(pw)` — imports Playwright, launches
    real Chromium (pre-installed `/opt/pw-browsers/chromium-*` fallback, as the existing
    tests do); on failure it skips, **or fails when `FUZZLAB_REQUIRE_BROWSER=1`** — which
    also fails (instead of skipping) when the `web` extra (`fastapi`) is missing. The two
    existing browser tests switch from module-level `importorskip("playwright")` to it
    (`fastapi` import-skip kept: without the web extra there is no page to test).
  - New `tests/test_web_pages_browser.py` (real Chromium + uvicorn, existing `_Server`
    pattern): store seeded with real `train_and_score` + `train_and_rank`, findings of two
    severities, metric series; `labcontrol.fetch_states` stubbed. It
    (a) walks every `GET` route in `create_app(cfg).routes` whose response is HTML (path
        params filled from seeded ids: `/runs/{id}`, `/findings/{id}`), plus one unknown
        path (404 page) — failing if any non-`/api` GET route is not an HTML route or has a
        path param it cannot fill, so a new page cannot be silently left out — and asserts zero `pageerror`s, zero console errors and zero
        `securitypolicyviolation` events (init-script collector);
    (b) `/ml`: every chart mount the `/api/ml/data` payload makes available renders a
        `.uplot.fl-chart` with an `fl-chart--<type>` class (count derived from the
        payload's `available` panels, not a literal); the ranker meta line shows
        "in-sample" (CC-UI-0035, previously hidden by the cascade);
    (c) `/diagnostics`: check a run, click a metric → trend + series charts render, legend
        shows the metric / `run #N` labels, no errors; clicking a second metric updates the
        mount's `aria-label`;
    (d) isolation: `page.route` serves `/api/ml/data` with a malformed `classifier`
        payload → its panel shows the could-not-render reason and the later panels still
        render;
    (e) a persisted `fl-theme=dark` in localStorage is applied on reload (`html[data-theme
        =dark]`) — CC-UI-0037;
    (f) `/`: severity `<rect>`s render with widths proportional to the seeded counts —
        CC-UI-0037.
- Impact (other components / project): UI only. Every chart on the ML and Diagnostics tabs
  renders for the first time; FR-UI-11/12/14 hold in a browser, not only in payload tests.
  No route/payload/Python change. Test infra: one shared browser helper.
- Risk (level; mitigation or accepted-risk justification): low. Small JS edits verified in
  Chromium by both reviewers (patched via `page.route`: 10 ML charts render, classes survive
  resize). Newly rendering charts may expose further latent bugs — the smoke test is what
  surfaces them. Browser tests add ~10–20 s where Chromium exists.
- Deliverables:
  - [ ] `chart.js` class token + modifier in `build()` + `role="figure"` — done
  - [ ] `diagnostics.js` series spec / `xLabel` / `time:false` / `caption` — done
  - [ ] `ml.js` `renderSafely` — done
  - [ ] `tests/_browser.py` + the two existing browser tests migrated — done
  - [ ] `tests/test_web_pages_browser.py` (a)–(f) — done
  - [ ] UI requirements: new NFR-UI-browser-verified — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, three rounds v1→v3, both reviewers verifying the fixes in real Chromium; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective — in real Chromium 141 (pre-installed build), `tests/test_web_pages_browser.py` 7 passed: every HTML GET route (10, walked from `app.routes`) plus the not-found page load with zero page errors, console errors and CSP violations; every chart mount in each available ML panel renders a `.uplot.fl-chart` with its `fl-chart--<type>` class; the Diagnostics trend + series charts render, labelled, and the accessible name follows the selected metric; a throwing ML panel no longer blanks the rest. With the `fuzzlab/` changes reverted, all 6 behavior tests fail (and with only `diagnostics.js` reverted, the Diagnostics test fails). Web + ML suites under `FUZZLAB_REQUIRE_BROWSER=1`: 354 passed, 0 skipped. This entry also corrects the record of `CC-UI-0031`/`CC-UI-0032`: their "every panel renders" effectiveness was established by payload/markup tests only; no chart had rendered in a browser until this change (BUG-0063).

### CC-UI-0035 — ML tab labels in-sample metrics and shows the scoring model's own out-of-fold metrics (BUG-0062 sweep) (2026-10-13)
- Change: `fuzzlab/web/mlview.py::classifier_panel` / `ranker_panel` compute PR-AUC /
  ECE / nDCG@k / precision@k from stored `candidate.score` / `rank_score`, i.e. the
  deploy fit's scores on its own training rows (`train.py:95-97`, `rank_train.py:75-76`)
  — in-sample — and `static/js/ml.js:68,91` show them unlabelled beside a baseline as if
  held-out. Both panels gain `"evaluation": "in-sample (deploy fit)"` and an `oof`
  object read from the calibration of the model that wrote those scores
  (`latest_classifier(store, run_id)` / `latest_ranker(store, run_id)`): classifier
  `{pr_auc, pr_auc_prevalence, pr_auc_sigma}` <- `oof_pr_auc`, `oof_pr_auc_prevalence`,
  `oof_pr_auc_sigma`; ranker `{at_k, ndcg, precision, ndcg_random, precision_random}` <-
  `at_k`, `oof_ndcg`, `oof_precision`, `oof_ndcg_random`, `oof_precision_random`. `oof`
  is `null` when there is no such model, it is a fallback, it is a legacy row without the
  keys, or (all-runs view, `run_id=None`) the selected row is not a store-wide train
  (`run_id` null) — so OOF numbers are only ever shown next to the scores of the model
  that produced them. `run_metrics` is not read. `ml.js` meta lines read "in-sample
  PR-AUC … · out-of-fold PR-AUC … (prevalence …)" and "in-sample nDCG@k … ·
  out-of-fold nDCG@{oof.at_k} …", omitting the OOF part when `oof` is null. Charts
  unchanged.
- Impact (other components / project): read-only, additive payload keys; no write. ML —
  consumes `CC-ML-0011`'s readers and calibration keys. FR-UI-11 wording updated.
- Risk (level; mitigation or accepted-risk justification): low; display-only.
- Deliverables:
  - [ ] panels add `evaluation` + `oof` — done
  - [ ] `ml.js` labels — done
  - [ ] tests: after real `train_and_score`/`train_and_rank` the panels carry `evaluation` and `oof` equal to the trainer's returned OOF numbers; `oof` null after a fallback train, with no model, and in the all-runs view over per-run rows — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, four rounds v1→v4; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — panel payload tests in `tests/test_ml_oof.py` pass; rendered in Chromium against a seeded store, the ML tab's classifier line now reads `in-sample (deploy fit) PR-AUC …` (on `main`: unlabelled `PR-AUC …`). `oof` is null in that view, as specified, because `ml.js` always requests the all-runs view and the rows are per-run. The ranker line could not be browser-checked: a pre-existing `chart.js` error (`classList.add` given `"fl-chart fl-chart--line"`), present on `main` too, aborts rendering after the classifier panel — flagged, not in scope. Full suite (2026-10-13, whole `tests/`): 2801 passed, 33 failed, 67 skipped, 9 xfailed. All 33 failures are labgen `--check`/fingerprint-gate tests that fail identically on an `origin/main` @ `0800e42` worktree (re-run: the same 33 fail) because this environment lacks `scipy`/`scikit-learn` (the declared `labgen`/`labgen-stats` extras) and the `gitleaks` binary — environmental, not caused by this change. Browser tests were among the skips (Playwright not yet installed when that run started); see CC-UI-0036 for the browser-verified run.

### CC-UI-0034 — Run page + ML tab conformal split read the run's own classifier (BUG-0061) (2026-10-13)
- Change: `fuzzlab/web/results.py::_scored_candidates` (run page "Model scores
  (advisory)" card) and `fuzzlab/web/mlview.py::conformal_panel` drop their inline
  `SELECT name, version, calibration FROM model ORDER BY id DESC LIMIT 1` + JSON parse +
  `ConformalGate(...)` and call `fuzzlab.ml.train.latest_classifier(store, run_id)`
  (`results.py` imports it inside the function, as it already does `ConformalGate`, to
  stay dependency-light). Before: after `fuzzlab auto --score --rank`
  (`auto_cli.py:153-162`) every decision shows `n/a` under model "ranker" and the ML tab
  says "latest model has no conformal calibration"; after a later run trains, an earlier
  run's page gates its scores with the later run's thresholds. After: the newest
  classifier whose scope covers the run. Unavailable reasons become "no trained
  classifier yet" / "latest classifier has no conformal calibration".
- Impact (other components / project): ML — consumes `CC-ML-0011`. Read-only contract
  unchanged; `/runs/{id}` and `/api/ml/data` shapes unchanged except the two reason
  strings (no test or JS asserts them). **Known limitation, kept:** the ML tab's
  all-runs view (`conformal_panel(store, None)`, the `/api/ml/data` default) gates every
  run's scores with the newest classifier's thresholds — one set of thresholds is all
  that panel can display; per-run views are exact. Recorded in FR-UI-11. New FR-UI-16
  states the run-page panel's contract (it had none).
- Risk (level; mitigation or accepted-risk justification): low. Lazy import; no import
  cycle. Existing tests seed `logistic` rows without `run_id` (legacy -> still selected).
- Deliverables:
  - [ ] `_scored_candidates`, `conformal_panel` use `latest_classifier` — done
  - [ ] regression tests: score -> rank -> run page decision is a gate decision under the classifier's name; `conformal_panel` available; two runs each trained -> each run page shows its own model version — done
  - [ ] FR-UI-16 added; FR-UI-11 conformal wording + all-runs limitation — done
- Review: pre-change review gate cleared 3/3 (proposing agent + 2 independent reviewer agents, four rounds v1→v4; every raised issue adopted).
- Effectiveness (assessed 2026-10-13): effective offline — `tests/test_ml_model_selection.py` run-page and conformal-panel regressions pass (score → rank keeps real gate decisions; each run uses its own classifier); fail with the old query restored. Full suite (2026-10-13, whole `tests/`): 2801 passed, 33 failed, 67 skipped, 9 xfailed. All 33 failures are labgen `--check`/fingerprint-gate tests that fail identically on an `origin/main` @ `0800e42` worktree (re-run: the same 33 fail) because this environment lacks `scipy`/`scikit-learn` (the declared `labgen`/`labgen-stats` extras) and the `gitleaks` binary — environmental, not caused by this change. Browser tests were among the skips (Playwright not yet installed when that run started); see CC-UI-0036 for the browser-verified run.

### CC-UI-0033 — Lab page: an on/off switch per lab container (2026-10-13, FR-UI-15; pairs with CC-LAB-0250)
- Change: a new **Lab** section (`GET /lab`, sidebar entry "Lab" in the Workbench
  group) that lists every compose service of the target lab with its live state and a
  Start/Stop switch, replacing the manual `labctl.sh up`/`down` round-trip to a
  terminal for day-to-day lab use. Built from the control plane's existing pieces
  rather than new machinery: the table is rendered server-side (no-JS shows the
  services; the switches need JS, stated on the page) from a new pure module
  `fuzzlab/web/labcontrol.py`, which **parses `lab/compose.yaml`** for the service
  list, each service's first compose profile, and its published loopback port
  (resolving `${VAR:-default}` host ports through the environment so the row links
  where the lab is actually published); only the human-facing app labels are a
  hand-kept map (an unlabelled service still renders under its compose name).
  `GET /api/lab/services` merges that list with the engine's real container state
  (`labctl.sh ps`, parsed back to services independently of the provider's naming
  scheme -- `pff-lab_web_1` vs `pff-lab-web-1`); `POST /api/lab/{service}/{action}`
  (`start`|`stop`) resolves the name against the compose-derived list first (unknown
  → 404, never an argument), then launches `bash lab/labctl.sh <action> <service>`
  through the launcher's `Runner` with the service's profile as `PFF_PROFILE` in the
  child's environment (`Runner.launch` gained an optional `env=`), and the page
  streams the run's output over the existing `/api/launch/{token}/stream` SSE route,
  re-reading state when it finishes. Files: `fuzzlab/web/labcontrol.py` (new),
  `fuzzlab/web/app.py` (NAV entry + 3 routes + import), `fuzzlab/web/runner.py`
  (`env=`), `templates/sections/lab.html`, `static/js/lab.js`, `static/css/lab.css`
  (new), `tests/test_web_lab.py` (new).
- Impact (other components / project): LAB -- `lab/labctl.sh` gained the `start`,
  `stop` and `ps` subcommands this page drives (`CC-LAB-0250`, `FR-LAB-172`); no other
  component touched. Additive to the UI: no existing route, template, or contract
  changed; `Runner.launch(argv)` callers are unaffected (`env` is keyword-only and
  defaults to inherit). D11's no-auto-run holds (rendering `/lab` runs nothing; a
  switch is an explicit POST). This is the first control-plane action that runs a
  host command other than `python -m fuzzlab.cli`, so its argv is fixed-shape
  (`bash <labctl> <start|stop> <service>`) with the only variable token validated on
  both sides (compose-derived allowlist here; a strict identifier regex in
  `labctl.sh`).
- Risk (level; mitigation or accepted-risk justification): low-medium.
  - *A hostile page flipping lab containers:* the POSTs sit behind the existing
    `SecurityGateMiddleware` (Host allow-list + same-origin Fetch Metadata + the
    `X-Fuzzlab-Client` header), tested cross-origin in `test_web_lab.py`. Accepted:
    anyone who can already POST to the loopback panel same-origin could already run
    `labctl.sh` themselves.
  - *Argument injection through the service name:* mitigated twice (above) and tested
    with shell-metacharacter, path-shaped and uppercase names on both layers.
  - *Provider drift (docker compose vs podman-compose):* `ps`/`stop` key on the
    compose project label both providers set and on real engine state, not on either
    provider's container names or exit codes (`PA-0059`(1)). Not live-verified here
    (no engine in this sandbox) -- see Effectiveness.
  - *Stale `PFF_PROFILE` in the panel's own environment:* `control_env` strips it for a
    default-profile service so a switch never enables profiles the user did not pick
    (tested).
- Deliverables:
  - [x] `fuzzlab/web/labcontrol.py` + routes + NAV entry -- done
  - [x] `sections/lab.html`, `js/lab.js`, `css/lab.css` -- done
  - [x] `tests/test_web_lab.py` (compose parsing, port/env resolution, both naming
        schemes, routes, gate, name validation on both layers) -- done, passing
  - [x] `requirements.md` FR-UI-15; `ARCHITECTURE.md` #12 -- done
  - [ ] First live use on the lab host (switch a default-profile and an `apps`-profile
        service on and off from the page under the real provider) -- caller follow-up
- Effectiveness (assessed 2026-10-13, offline): `PYTHONPATH=<worktree> pytest tests/test_web_lab.py
  tests/test_web_runner.py tests/test_web_launcher.py tests/test_web_security.py
  tests/test_web_frontend.py tests/test_lab_labctl_profile_parsing.py` -- 107 passed;
  the whole non-slow suite is green apart from the 14 pre-existing `--check` tests that
  need `gitleaks` on PATH (environment, unchanged by this entry). Live check-back pending
  the deliverable above.

### CC-UI-0032 — Lane U5: Diagnostics tab + store explorer (2026-09-22)
- Change: per `docs/UI_IMPLEMENTATION_PLAN.md` §3 (U5) and its resolved
  R-02/R-05/R-12, built out the Diagnostics section (previously a stub since
  U0/CC-UI-0025's MPA split): cross-run scalar trend lines over `run_metrics`
  (`fuzzlab.web.diagnostics.run_metrics_trend`); intra-run/cross-run overlay
  step series over `metric_series` (`metric_series_data`), read-side
  downsampled server-side via a ~40-line pure-Python **LTTB** implementation
  (`diagnostics.lttb`, R-05: "≈1000 pts/series, preserves loss spikes/regret
  jumps a naive stride/average erases") — then **EMA smoothing applied
  client-side, after downsampling** (`chart.js::ema`), matching R-05's
  specified render order; snapshot panels for candidate-score distribution
  (pre-binned server-side, never raw per-candidate rows), bandit arm
  posteriors (`bandit_posteriors`, posterior mean derived client-visible),
  and the model-registry timeline (`model`). Controls per R-05: a run
  multi-select with per-run color (stable palette index by run id), a metric
  picker grouped by `source` (collapsible `<details>`) with a substring
  filter, an EMA slider (0–0.99), an x-axis toggle (step/relative-time/
  wall-clock — the latter two currently fall back to step order pending a
  timestamp array in the series payload, noted as a known gap below), and a
  y-axis log toggle. Also built the **store explorer** (FR-UI-14, previously
  unimplemented), used to satisfy `FR-UI-2`'s realized annotation: read-only,
  Datasette-style browsing of any table in the store via
  `GET /api/store/tables` + `GET /api/store/tables/{name}`, with the table
  name re-validated against `sqlite_master` server-side before every use
  (never taken from the request unchecked) — the actual injection-safety
  mechanism, with a strict-identifier regex as defense-in-depth on top. New
  files: `fuzzlab/web/diagnostics.py` (pure query/LTTB/store-explorer module,
  mirrors `results.py`/`proxyview.py`), `fuzzlab/web/static/js/diagnostics.js`,
  `fuzzlab/web/static/css/diagnostics.css`, `tests/test_web_diagnostics.py`.
  Extended `fuzzlab/web/templates/sections/diagnostics.html` (was a stub) and
  added nine `GET /api/diagnostics/*` + `GET /api/store/*` read routes plus a
  `_with_store` helper to `fuzzlab/web/app.py` — no writes, no new backend
  beyond these read routes (matches the U5 acceptance criteria verbatim).
- Impact (other components / project): additive-only — no schema change (uses
  `run_metrics`/`metric_series`/`candidate`/`bandit_posteriors`/`model`,
  `metric_series` already landed via lane B0-table before this lane started),
  no change to any existing route or template. **Shared-infra reconciliation
  (PA-0031 merge protocol):** this lane was dispatched from a pre-Wave-2 base
  where `js/chart.js`/`js/datatable.js`/vendored uPlot did not yet exist, and
  independently built its own complete copies of all three, duplicating work
  U4 (`CC-UI-0031`, `js/chart.js` + vendored uPlot 1.6.32) and U2
  (`CC-UI-0029`, `js/datatable.js`) had already landed by the time this lane
  merged. Rather than a raw merge (which would have silently clobbered the
  already-landed, already-consumed versions), the integrator reconciled by
  hand: `chart.js` — U5's `createChart(el, {id, type, data, series, opts})`
  contract and handle shape were compatible with U4's landed version, so only
  U5's unique `ema(values, alpha)` client-side smoothing helper (used by the
  EMA slider above) was appended to U4's file; U5's own `chart.js` and
  vendored uPlot copies were discarded in favor of U4's. `datatable.js` — U5's
  `mount(el, {columns, data, onRowClick, rowActions, textFilterKeys}) →
  {setData, setFilter, destroy}` contract was incompatible with U2's landed
  `createDataTable(root, {caption, columns, data, ...}) → {setData,
  setTextFilter, setFilter, setSort, getSort, getVisible, element}` (row-based
  `render(row)` vs. value-based `render(value)`, no self-mount/`destroy()` on
  U2's side since it mounts via `root.replaceChildren()`), so `diagnostics.js`
  was adapted to call U2's actual API rather than landing a second, divergent
  DataTable implementation; U5's own `datatable.js` was discarded entirely. No
  other component's contract changed.
- Risk (level; mitigation): low-medium.
  - **Store explorer injection risk** (the highest-consequence risk this lane
    touches): mitigated by construction — `diagnostics._resolve_table` always
    re-reads the caller's table name against a live `sqlite_master` query and
    only ever interpolates the name *that query itself returned*, never the
    raw request value, so no string an attacker controls can reach raw SQL
    beyond selecting among tables that already exist; `limit`/`offset` are
    separately `int()`-cast, clamped, and bound as parameters regardless.
    Covered by `test_web_diagnostics.py`'s injection-attempt parametrized
    tests (both the pure-function and the HTTP-route layer) asserting the
    store is provably untouched afterward, plus a BLOB-column test (never
    emits raw bytes into JSON).
  - **Client-side rendering risk**: the store explorer renders arbitrary,
    fuzzer-written row content (URLs, payloads, bodies) — `datatable.js`
    writes every cell via `textContent` only; a static test greps
    `datatable.js`/`diagnostics.js`/`chart.js` for any live (non-comment)
    `innerHTML` use.
  - **Vendoring provenance**: uPlot's provenance is documented under
    `CC-UI-0031` (U4 vendored it first; this lane reuses that copy as-is).
  - **x-axis wall-clock/relative-time toggle is not fully wired**: the
    `metric_series` read path (`diagnostics.metric_series_data`) does not yet
    return per-point timestamps in the JSON payload (only `step`), so
    `diagnostics.js` currently falls back to step-order for both
    "relative-time" and "wall-clock" x-axis modes rather than real
    wall-clock ticks. `metric_series.ts` already exists in the store
    (per B0's schema) and is queried in the SQL but simply not yet returned
    on the wire — a small, low-risk follow-up (a later change-control entry),
    not a functional regression since step order is still monotonic and
    correctly labeled in the axis-toggle UI's semantics for now.
  - **Not independently browser-tested**: `playwright` is not installed in
    this environment (`tests/test_web_repeater_browser.py`'s own
    `importorskip("playwright")` pattern confirms other browser tests already
    skip here too), so the R-09 "dark-mode/density correct" acceptance point
    and the `window.__charts` a11y-table contract are exercised only by
    static/manual code review against the R-12 spec, not an automated
    browser assertion, in this environment. Flagged for the integrator to
    re-run with a browser-capable runner before considering R-09/R-11
    coverage complete for this tab.
- Deliverables:
  - [x] `fuzzlab/web/diagnostics.py` — pure LTTB/trend/series/snapshot/store-
    explorer query functions — done.
  - [x] `GET /api/diagnostics/{runs,metrics,trend,series,candidates/{id},
    bandit,models}` + `GET /api/store/{tables,tables/{name}}` read routes in
    `fuzzlab/web/app.py` — done.
  - [x] Reused U4's vendored uPlot 1.6.32 (`/static/vendor/uplot/`) — done.
  - [x] `js/chart.js` shared `createChart()` wrapper (R-12: tokens, density,
    ResizeObserver, retheme, teardown, `window.__charts`, a11y table) — done;
    U5's unique `ema()` helper merged into U4's landed file (see the
    reconciliation note above).
  - [x] `js/diagnostics.js` adapted to call U2's landed `js/datatable.js`
    (`createDataTable`) rather than duplicating a second `DataTable` (see the
    reconciliation note above).
  - [x] `js/diagnostics.js` page orchestration + `sections/diagnostics.html`
    extended with the controls/panels/store-explorer markup — done.
  - [x] `css/diagnostics.css` — done.
  - [x] `tests/test_web_diagnostics.py` (28 tests: LTTB correctness, pure
    query functions, API routes, read-only-no-store-file guarantee,
    injection-attempt rejection, BLOB summarization, static innerHTML guard)
    — done, all passing against the reconciled tree.
  - [ ] Wire real timestamps into `metric_series_data`'s response for the
    wall-clock/relative-time x-axis modes — todo (follow-up).
  - [ ] Browser-driven (Playwright) dark-mode/density/`window.__charts`
    verification — todo, blocked on a browser-capable test environment.
- Effectiveness (assessed 2026-09-22): effective for the acceptance criteria
  that are testable in this environment — charts/panels/store-explorer render
  from `run_metrics`/`metric_series`/`candidate`/`bandit_posteriors`/`model`
  with no new backend beyond the listed read routes; the store explorer is
  provably read-only and injection-safe (parametrized SQL-injection tests
  against both the pure functions and the live HTTP routes all pass and leave
  the store unmodified). Dark-mode/density correctness and the R-09
  `window.__charts` browser contract are implemented per spec but not
  machine-verified here (no Playwright) — re-assess once a browser-capable
  run confirms them.

### CC-UI-0031 — Lane U4: ML tab — read-only, advisory model-internals panels (2026-09-22)
- Change: per `docs/UI_IMPLEMENTATION_PLAN.md` §3 (U4) and its resolved R-06/R-02/R-12,
  filled in the `/ml` section (previously a placeholder card, U0) with read-only,
  advisory panels over model internals already in the store: classifier PR curve +
  operating point, a reliability diagram + ECE (the advisory anchor), a logistic
  weights panel (documented not-available — see below), ranker nDCG@k/precision@k vs. a
  random baseline + rank score/uncertainty histograms + a score-vs-uncertainty scatter,
  the conformal flag/abstain/drop stacked split (leads the tab, per R-06) + a
  nonconformity histogram with the calibrated thresholds, the ECOD anomaly score
  histogram + flagged-rate, active-learning committee disagreement histogram + a top-N
  query queue, Thompson-bandit Beta posteriors (an overlaid density per arm via a
  15-line `lgamma`-based pdf on a 200-point grid, pure stdlib `math` — no numpy/scipy —
  plus a mean/90%-CI/pulls/mean-cost forest table), and a mutation-engine
  killed/survived variants table. A persistent, **non-dismissible** advisory banner
  ("Model output is advisory; confirmed findings come from the oracle") leads every
  render; every score carries an uncertainty companion, its N, and (where meaningful) a
  baseline; verb hygiene throughout is "scored/ranked/flagged", never
  "detected/vulnerable/confirmed"; the palette is neutral blue (`--accent`) / amber
  (`--warn`) only — never `--crit`/`--ok` (the oracle's red/green, reserved for
  Results/Findings).
  - New `fuzzlab/web/mlview.py`: one function per panel plus `ml_overview()`, all
    **read-only** — every function only `SELECT`s from the store; two panels
    (anomaly, active-learning disagreement) recompute a lightweight, deterministic
    derivation of already-stored candidate feature vectors on the fly (ECOD fit +
    score; a capped bootstrap committee fit + disagreement) without persisting
    anything back — unlike the training-time equivalents
    (`fuzzlab.ml.anomaly.detect_anomalies`, which records `run_metrics`), this module
    writes nothing, ever. Reuses existing pure-Python ML helpers
    (`fuzzlab.ml.metrics.pr_auc`, `fuzzlab.ml.ranking.mean_ndcg_at_k`/
    `mean_precision_at_k`, `fuzzlab.ml.conformal.ConformalGate`,
    `fuzzlab.ml.anomaly.ECOD`/`flag_top`, `fuzzlab.ml.active.Committee`/
    `disagreement`) rather than re-deriving them.
  - New route `GET /api/ml/data` (optional `?run_id=`) in `fuzzlab/web/app.py`,
    backed by `_read_ml()` (mirrors `_read_runs`/`_read_detail`'s
    store-existence-checked read pattern); degrades to `{"available_any": false}` on a
    missing/empty store rather than erroring, and each panel degrades independently to
    `{"available": false, "reason": ...}` on partially-populated data (e.g. candidates
    exist but nothing has been scored yet).
  - **Vendored uPlot 1.6.32** (MIT; R-02's resolved decision) verbatim as two static
    files — `fuzzlab/web/static/vendor/uplot/uPlot.esm.js` (145 KB) +
    `uPlot.min.css` — pulled via `npm pack uplot@1.6.32` and copied from the
    package's own `dist/`, unmodified; no bundler, no CDN.
  - New shared wrapper `fuzzlab/web/static/js/chart.js::createChart(el, {id, type,
    data, series, opts})` (R-12's exact spec), a standalone ES module built to be
    shared with U5's Diagnostics tab (not ML-specific): resolves CSS color tokens
    through a hidden-probe element's computed style (`getPropertyValue` alone can
    return an unresolved `var()`/`color-mix()` chain the canvas can't parse); maps
    `data-density` to discrete font/gutter/tick/gap/point sizing buckets; a debounced
    `ResizeObserver` on the chart's **parent cell** (not uPlot's own root, which would
    self-trigger an RO feedback loop) coalesced with `requestAnimationFrame`; a
    `MutationObserver` on `<html>` (`data-theme`/`data-density`) plus a `matchMedia`
    listener for an unforced system-preference flip, both driving one idempotent
    `destroy()` + recreate (never a partial restyle — uPlot bakes colors into the
    canvas at draw and measures axis geometry at construction); `window.__charts` is a
    `Map<id, handle>` for tests/debugging; every chart renders a visually-hidden
    `<table>` a11y fallback (canvas `aria-hidden`, wrapper `role="img"`, ~200-row cap,
    refreshed on `setData()`) since a canvas chart is opaque to screen readers.
    `handle.destroy()` disconnects both observers, removes the `matchMedia` listener,
    cancels any pending `requestAnimationFrame`, and calls `uPlot.destroy()` — the
    observers otherwise hold references and leak across the app's MPA navigations.
  - `fuzzlab/web/static/tokens.css`: added `--chart-h` (density-varying chart height
    token both `chart.js` and any section CSS can read).
  - New `fuzzlab/web/static/css/ml.css`, rewritten `templates/sections/ml.html`
    (still extends `base.html`; no shell change) and `static/js/ml.js`.
- Impact (other components / project): UI-only; no write path added anywhere. ML
  component (component #10): a **consumer** of its already-stored outputs, not a
  producer — no change to any ML training/scoring code. Documents one real gap
  against ML component #10's own requirement spec: the logistic classifier's
  coefficients are never persisted to the store (`train_and_score` only ever writes
  the conformal calibration thresholds to `model.calibration`), so the "logistic
  weights diverging bar" panel R-06 calls for renders a documented not-available
  state instead of fabricating or inventing a value — recorded as `FR-ML-9`'s known
  gap in `10-ml-components/requirements.md`, not silently dropped. `static/js/chart.js`
  and `static/vendor/uplot/` are new shared infrastructure U5 (Diagnostics, same wave)
  also depends on; at dispatch time neither existed yet, so this lane created them
  (U5 should reuse, not re-vendor — flagged to the integrator per the multi-agent
  orchestration merge protocol).
- Risk (level; mitigation): low — strictly additive and read-only; no existing route,
  table, or write path is touched. The one thing worth naming: `mlview.py`'s active-
  learning panel trains a small bootstrap committee (`fuzzlab.ml.active.Committee`,
  5 rankers by default) synchronously inside a `GET` handler — capped to 300 sampled
  candidates (deterministic stride sample) to bound the cost on a large store, and
  wrapped so a fit failure degrades to `{"available": false}` rather than a 500.
  Mitigated by 17 new tests (`tests/test_web_ml.py`): every panel function against a
  seeded store, an empty-store degrade-gracefully case for the whole overview, the
  `/api/ml/data` route (seeded and missing-store), the advisory banner (present,
  non-dismissible, normalized-whitespace matched) and verb-hygiene checks against the
  actual template/JS source, the vendored uPlot files and new static assets serving,
  and an explicit read-only assertion (`run_metrics` row count unchanged around the
  anomaly panel call, the one case with a training-time write-carrying sibling).
- Deliverables:
  - [x] `fuzzlab/web/mlview.py` — one read-only function per panel + `ml_overview()` — done.
  - [x] `GET /api/ml/data` (+ `_read_ml` in `app.py`) — done.
  - [x] Vendored uPlot 1.6.32 (`static/vendor/uplot/`) — done.
  - [x] Shared `createChart()` wrapper (`static/js/chart.js`) per R-12 — done.
  - [x] `sections/ml.html` + `js/ml.js` + `css/ml.css`, advisory banner + categorical
    bands + verb hygiene + blue/amber palette (R-06) — done.
  - [x] `--chart-h` token added to `tokens.css` — done.
  - [x] Tests (`tests/test_web_ml.py`, 17 new) — done.
  - [ ] On-host visual QA (light/dark/compact, real trained models) — on-host.
- Effectiveness (assessed 2026-09-22): effective in tests — every panel renders from a
  seeded store or degrades to a named reason, the read-only assertion holds, and the
  advisory framing (banner, verb hygiene, palette) is present in the served markup/JS.
  Full-suite pass/skip counts recorded in this same date's CHANGELOG entry.
### CC-UI-0030 — Proxy workbench rebuild: shared message editor + resizable panes + sub-nav (lane U3) (2026-09-22)
- Change: re-laid the Proxy section's History / Intercept / Repeater byte editors
  on one new shared custom element, `<message-editor>`
  (`fuzzlab/web/static/js/msgeditor.js`), per the resolved R-04 marker in
  `docs/UI_IMPLEMENTATION_PLAN.md` §3 (U3):
  - API: `{editable, bytes, meta}` in as properties, `getBytes()` out. The
    editable pane is a plain `<textarea>` (`.value` is the single byte-exact
    source of truth); Raw is the only editable mode and the default. Pretty
    (hand-rolled HTTP tokenizer, JSON body pretty-print when the content-type
    says so) and read-only Hex (response only) render into a separate
    read-only `<pre>` mirror, built entirely with `createElement`/`textContent`
    — never `innerHTML`, matching the existing untrusted-flow-content
    discipline already in `proxy.js`.
  - A status/timing strip (status+reason, elapsed ms, byte length,
    content-type).
  - A CRLF/non-printing-byte display toggle (Unicode control-picture glyphs;
    display only, never touches the underlying bytes).
  - Ctrl-F in-message search painted via `CSS.highlights`/the Custom Highlight
    API over the read-only mirror's text nodes — never by span-injecting the
    buffer. For an editable Raw pane (which can't host highlight ranges), the
    search briefly shows a synced read-only overlay of the same bytes; the
    textarea underneath is never touched and `getBytes()` still reads only it.
  - No vendored highlighting/editor library — hand-rolled tokenizer + DOM,
    per R-04's explicit "hand-roll, do not vendor" verdict.
  - `attachSplitter()`: a vanilla CSS-grid resizable splitter (one rewritable
    `--a` grid-track custom property + pointer-capture drag + arrow-key a11y +
    localStorage persistence, try/catch-guarded) — no library — used for the
    request/response pane pairs in History's flow detail and in Repeater, each
    with a "stack vertically" layout toggle.
  - A sticky in-page sub-nav (`.proxy-subnav`) linking the four Proxy cards
    (History / Intercept / Repeater / Scope · Match-Replace).
  - `sections/proxy.html`, `js/proxy.js`, and `css/proxy.css` were extended
    (not replaced) to wire the new editors into the existing History/Intercept/
    Repeater flows; the editable editors keep the exact element ids the
    pre-existing tests target (`#pending-raw`, `#rep-raw`) and the read-only
    response mirror keeps `#rep-resp`, so `toWire()`'s CRLF-restore
    (`fuzzlab/web/static/js/common.js`) remains the one documented
    `\n`→`\r\n` normalization point applied right before a byte-exact send —
    `msgeditor.js` does not duplicate it.
- Impact (other components / project): UI-only markup/JS change plus an
  incidental PROXY-facing note (this lane's dual bookkeeping — see
  `CC-PROXY-0018` for the PROXY-component entry; no PROXY backend code
  changed). No new routes, no schema change, no change to
  `NFR-UI-control-plane-hardened`'s request-gating. Does not touch
  `RepeaterController`'s per-thread fix (BUG-0021/`CC-PROXY-0016`). Does not
  flip proxy/desync tooling's default-off, lab-only posture (CLAUDE.md Safety)
  — the `--authorized` gate on Repeater sends and the "not running in-process"
  fallbacks are unchanged.
- Risk (level; mitigation): low-medium — a real-DOM-structure change to a
  route already covered by a Playwright browser test
  (`tests/test_web_repeater_browser.py`). Mitigated by: keeping the exact ids
  that test drives (`#rep-new-host`/`#rep-new-port`/`#rep-new-raw`/`#rep-create`/
  `#rep-editor`/`#rep-raw`/`#rep-send`/`#rep-resp`) live in the light DOM (no
  shadow root, by design, specifically so automation and section CSS keep
  working); `getBytes()` reading only the plain textarea's `.value` so
  byte-exact editing is unchanged; running the full suite unmodified after the
  change (see Deliverables/Effectiveness for the pass/skip counts). The CSS
  Custom Highlight API is feature-detected (`'highlights' in CSS && typeof
  Highlight === 'function'`) and search degrades to "no paint" rather than
  throwing where unsupported.
- Deliverables:
  - [x] `fuzzlab/web/static/js/msgeditor.js` — new shared `<message-editor>`
    custom element + `attachSplitter()` — done.
  - [x] `sections/proxy.html` extended: sub-nav, `message-editor` markup for
    History detail / Intercept / Repeater, resizable-split containers + layout
    toggles — done.
  - [x] `js/proxy.js` extended: wires flow detail / intercept / repeater to the
    new editors' `{bytes, meta, getBytes()}` API instead of raw
    textarea/`<pre>` access; `toWire()` usage unchanged — done.
  - [x] `css/proxy.css` extended: sub-nav, `message-editor` layout/toolbar/
    search-highlight, `.me-split` splitter styles, all via existing design
    tokens (no raw hex) — done.
  - [x] Full test suite run unmodified; existing Repeater browser test and
    intercept/history/scope suites green — see Effectiveness for counts.
- Effectiveness (assessed 2026-09-22): pending full independent verification
  by an integrator per `docs/MULTI_AGENT_ORCHESTRATION.md`; self-assessed
  effective from this lane's own full-suite run — see the lane's handback
  report for the pass/skip counts.
### CC-UI-0029 — Lane U2: Findings workbench (faceted filters + saved views + shared DataTable) (2026-09-22)
- Change: per `docs/UI_IMPLEMENTATION_PLAN.md` §3 (U2) and its resolved R-03/R-07/R-11,
  added the Findings workbench: `GET /findings` (list) and `GET /findings/{id}` (detail),
  reading `finding`/`attempt` via the new `fuzzlab.web.findingsview` module (mirrors
  `web/results.py`/`web/proxyview.py`: pure, read-only functions over the shared store,
  never creates the store file). **Facet sidebar** (severity, vuln class, method,
  mechanism/`confidence`, endpoint — 5 groups per R-03) implemented as the APG Disclosure
  pattern (`<button aria-expanded aria-controls>` per group, native checkboxes with the
  live count inside each `<label>`, `fieldset`/`role=group`) with **live counts**
  recomputed against every *other* active group's filter (OR within a group, AND across
  groups) — all client-side over one bounded (`limit=5000`) fetched snapshot
  (`GET /api/findings`), matching D4's "hand-roll tables/filters, no virtualization" and
  R-03's "a few thousand rows is fine" ceiling. Top **quick-filter** (debounced substring
  over url/param/vuln_class/mechanism) + **applied-filter chips**
  (`role=group` "Applied filters", each a `<button aria-label="Remove filter: …">`, focus
  moved to the quick-filter input on removal — never to `<body>`, per R-11) + "Clear all".
  **Severity** has no store column (the schema has none — see `NFR-UI-read-only`'s "the UI
  reads" posture and `docs/ARCHITECTURE.md`'s store-as-contract); `findingsview.
  derive_severity(vuln_class)` computes a UI-only, advisory band via substring rules,
  documented as never written back and never treated as a stored/scored fact. Rendered as
  a text+color `.badge` (never color alone, R-11).
  **Saved views** persist server-side (`saved_views` table, migration 12 —
  `CC-CORE-0019`; see that entry for the store-contract change and its bookkeeping-number
  note) via `fuzzlab.web.savedviews` + `GET/POST/PUT/DELETE /api/views?table=`; a spec is
  `{version, name, filter:{text, facets}, sort}` (R-03's shape, `predicates` deferred —
  no caller needs Tenable-style predicates yet). `localStorage` (try/catch-wrapped) holds
  only throwaway per-viewer state (collapsed facet groups, the last-applied view id, a
  draft quick-filter string) per R-07's state-decision rule.
  **"Send to Repeater / open request" pivot** follows U0's PRG+303 pattern exactly:
  `POST /findings/repeater/from-finding` (a real `<form>`, both on the list's per-row
  action and the detail page) → `RepeaterController.create_from_finding` →
  `RedirectResponse(..., 303)` to `/proxy?repeater_tab=ID` — opaque tab id only, never
  bytes on the wire. `finding`/`attempt` carry no raw request bytes (only proxy flow
  history does, via the existing `create_from_flow`), so `create_from_finding`
  reconstructs a minimal, best-effort request line from the finding's own
  `url`/`method`/`param` against the configured target host; the tab name says
  "(reconstructed)" so it is never mistaken for a byte-exact replay.
  **Ground truth**: the detail view renders `primary_endpoint`/`primary_role`/
  `related_endpoints`/`flow_variant` (CR-LAB-0001 Addendum B /
  `fuzzlab.labels.contract.Case`) when a finding's `evidence` JSON happens to carry them
  — additive/optional, matched by key, never required or invented. Note the honest
  current state: the oracle (`fuzzlab/oracle/oracle.py`, the sole finding-writer) never
  reads ground truth (D9/D10 fail-closed: it must not know the answer) and no existing
  writer currently attaches these keys to `verdict.evidence`, so this renders today only
  if/when a future harness-integration or plugin chooses to carry them through — the
  detail template and `findingsview._ground_truth_fields` are the reading side of that
  contract, built ahead of a writer per the lane's own scope (`app.py` read routes only).
  **Shared `js/datatable.js`** (new standalone ES module, D3): native `<table>` (not
  `role="grid"` — read-only sort + row-link, not a composite widget, per R-11), every
  cell via `textContent` (never innerHTML — url/param/payload are target-derived,
  untrusted), a real `<a href>` in the primary cell wrapped around JS-rendered content
  (row-click is an enhancement on top), named row-action buttons, a fixed severity rank
  map for non-lexicographic sort, and `safeHref()` (http/https/relative-only, blocks
  `javascript:`/`data:`) applied to every rendered pivot href. API: `createDataTable(root,
  {caption, columns:[{key,label,render,sortValue,sortable}], data, getRowId, rowHref,
  onRowClick, rowActions, textFilterKeys, emptyMessage, liveRegion}) ->
  {setData, setTextFilter, setFilter, setSort, getSort, getVisible, element}`. Files:
  `sections/findings.html`, `templates/finding.html` (detail; alongside `templates/
  run.html`, not under `sections/` — a record detail page, not a section route), `js/
  findings.js`, `js/datatable.js`, `css/findings.css`; `app.py` gained the `findings` NAV
  entry (Workbench group, after Proxy) and `_read_findings`/`_read_finding`/
  `_saved_views` read helpers.
- Impact (other components / project): read-only over `finding`/`attempt` (no schema
  change to either); the one write surface (`saved_views`) is view *definitions* a person
  authored in the panel, not tool output — `CC-CORE-0019` covers that table's own impact.
  `fuzzlab/web/app.py` and `fuzzlab/web/proxycontrol.py` (new `RepeaterController.
  create_from_finding`) are shared with U0/U3/U6's prior changes to those files but this
  lane only adds routes/methods, touching no existing route/method body. `js/datatable.js`
  is new and currently has exactly one consumer (this lane); U1 (recent-runs table) and
  U5 (store explorer) are documented in `docs/UI_IMPLEMENTATION_PLAN.md` §3 to reuse it
  *minus* the facet sidebar — **flagging for the integrator**: those are concurrent
  Wave-1 lanes and neither imports/depends on `datatable.js` as written here, so there is
  no code collision today, but their own dispatch prompts should point at this file's
  actual API (above) rather than assume a different shape, since none of the three lanes
  coordinated the exact signature ahead of time.
- Risk (level; mitigation): low — additive routes/files, no result-table writes, no
  change to `NFR-UI-localhost`/`NFR-UI-control-plane-hardened` (the existing
  `SecurityGateMiddleware` covers the new POST route the same as every other `/proxy/
  repeater/from-*` route). The reconstructed-request pivot could mislead someone into
  treating it as a byte-exact replay; mitigated by the explicit "(reconstructed)" tab
  name and this entry's documentation, plus `test_create_from_finding_reconstructs_a_
  request_not_byte_exact`. XSS-shaped `url`/`param`/`evidence` values are covered by
  `test_finding_detail_page_renders_untrusted_fields_dom_safe` (Jinja autoescape) and
  `datatable.js`'s `textContent`-only rendering (exercised transitively by the list page;
  no headless-browser test in this lane — see Deliverables).
- Deliverables:
  - [x] `fuzzlab.web.findingsview` (list/detail, derived severity, ground-truth pass-through) — done.
  - [x] `fuzzlab.web.savedviews` (CRUD over `saved_views`) — done.
  - [x] Migration 12 (`saved_views`) — done (`CC-CORE-0019`).
  - [x] `RepeaterController.create_from_finding` — done.
  - [x] Routes: `/findings`, `/findings/{id}`, `/api/findings`, `/findings/repeater/
    from-finding` (PRG+303), `/api/views` (GET/POST/PUT/DELETE) — done.
  - [x] `sections/findings.html`, `templates/finding.html`, `js/datatable.js`, `js/
    findings.js`, `css/findings.css` — done.
  - [x] Tests: filter/facet derivation, saved-view round-trip (store + HTTP), DOM-safe
    rendering of untrusted fields, PRG+303 pivot, reads-only — done
    (`tests/test_web_findings.py`, 16 tests).
  - [ ] Real-browser/headless a11y smoke of the facet Disclosure + DataTable keyboard
    model (focus-visible ring, `aria-sort` toggling, chip-removal focus target) — not
    done in this lane; existing precedent (`test_web_launcher_browser.py`, `test_web_
    repeater_browser.py`) shows the pattern other lanes used for this, left as a
    follow-up rather than expanding this lane's scope past its `app.py`-read-routes
    + shared-file remit.
- Effectiveness (assessed 2026-09-22): effective for the stated scope — filter+saved-view
  round-trip, DOM-safe untrusted-field rendering, and the "send to Repeater" PRG pivot are
  all covered by passing tests; the workbench renders against both an empty store and a
  seeded one without creating the store file on a bare read.

### CC-UI-0028 — Overview dashboard: new landing route "/", Launcher moved to "/launcher" (lane U1) (2026-09-22)
- Change: built the Overview dashboard (`FR-UI-10`, resolved marker R-10 in
  `docs/UI_IMPLEMENTATION_PLAN.md`) as the panel's new landing route:
  - `fuzzlab/web/results.py`: added `severity_of()` (a fixed, read-only
    `vuln_class` → severity bucket map — critical/high/medium/low/info — since
    `finding` has no `severity` column, only `confidence`, which the oracle
    actually uses for the detection *mechanism*, e.g. "error-signature", not a
    severity level) and `overview_summary(store, recent_limit=10)`: one
    aggregate read (total findings, severity breakdown, total runs, runs in the
    last 7 days, the ~10 newest runs, the latest scored run's detection quality,
    the latest budgeted run's efficiency).
  - `fuzzlab/web/app.py`: `GET /` now renders `sections/overview.html` via a new
    `_overview_context`/`_read_overview` (empty-store-safe, never creates the
    store); the **Launcher** moved from `/` to a new `GET /launcher` route with
    otherwise unchanged behavior/context (`_launcher_context` unchanged). `NAV`
    gained an "Overview" entry (`href="/"`, first in the Workbench group) and the
    existing "Launcher" entry's `href` changed to `/launcher`.
  - New files: `fuzzlab/web/templates/sections/overview.html`,
    `fuzzlab/web/static/css/overview.css`, `fuzzlab/web/static/js/overview.js`
    (a small hand-rolled click-to-sort for the recent-runs table — progressive
    enhancement only, the table fully renders server-side without it).
  - Findings-by-severity is a plain CSS horizontal segmented bar over the
    existing `--crit/--high/--med/--low/--info` design tokens (`tokens.css`,
    already present for exactly this purpose); no chart library added (R-10
    explicitly calls uPlot poor for this shape).
- Impact (other components / project): the panel's landing URL now serves
  different content — a person/bookmark/script that opened `/` expecting the
  Launcher must now use `/launcher` (also true of the Playwright browser-smoke
  test, updated in this change — see Deliverables). No backend/store schema
  change (severity is derived, not stored) and no other component's contract
  changed. `docs/UI_IMPLEMENTATION_PLAN.md`'s R-03-resolved shared `DataTable`
  (reserved for U2's Findings workbench, reused by U1's recent-runs table and
  U5's store explorer) **did not exist in this lane's worktree** (`js/
  datatable.js` absent) — flagged, not guessed at: this lane built its own
  minimal recent-runs table instead of the shared component, so U2 (which is
  expected to land `js/datatable.js`) and U5 should reconcile Overview's table
  onto the shared component once it exists, per the parallel-lane merge
  protocol in `docs/MULTI_AGENT_ORCHESTRATION.md`.
- Risk (level; mitigation): low — strictly read-only (never creates the store,
  never writes a result-table row; verified by a dedicated test asserting row
  counts are unchanged after repeated `GET /`) and additive (one new route +
  one relocated route, both GET, both already covered by the existing
  loopback/control-plane hardening middleware, which wraps every route by
  construction). The route move is a real behavior change for anyone who had
  `/` open expecting the Launcher; mitigated by moving it to a clearly-related,
  discoverable URL (`/launcher`, linked from the sidebar and from Overview's own
  quick actions) rather than removing it, and by updating every test that
  depended on `/` == Launcher (see Deliverables) so the suite still pins the
  Launcher's exact behavior, just at its new address.
- Deliverables:
  - [x] `fuzzlab/web/results.py::severity_of`/`overview_summary` — done.
  - [x] `app.py` routes (`/` → Overview, `/launcher` → Launcher) + NAV update — done.
  - [x] `sections/overview.html`, `css/overview.css`, `js/overview.js` — done.
  - [x] New `tests/test_web_overview.py` (14 tests: severity mapping, the
    aggregate on an empty/seeded/unscored store, recent-runs capping/order, the
    empty state never creating the store, KPI tiles, partial-empty em-dashes,
    the severity bar, quick actions, nav active-state, and a no-writes
    assertion) — done, all passing.
  - [x] Updated existing suites that assumed `/` == Launcher:
    `tests/test_web_launcher.py`, `tests/test_web_frontend.py` (SECTIONS table +
    the Launcher-content block), `tests/test_web_launcher_browser.py` (Playwright
    smoke's base URL) — done; `tests/test_web_security.py` needed no change (its
    `/` assertions are status/header-only, not content).
  - [x] Full repo test suite run, confirmed green (see Effectiveness) — done.
  - [x] `docs/components/12-diagnostics-and-ui/requirements.md` — `FR-UI-7`
    updated in place (route map) + new `FR-UI-10` added — done.
  - [x] `CHANGELOG.md` line — done.
  - [ ] Reconcile Overview's recent-runs table onto the shared `DataTable` once
    U2 lands `js/datatable.js` — todo, owned by whichever of U2/U5 lands second
    (flagged above, not this lane's to build).
- Effectiveness (assessed 2026-09-22): intent achieved — `/` renders the Overview
  spec from R-10 (5 tiles, recent-runs table, severity bar, quick actions, both
  empty states), `/launcher` preserves the pre-existing Launcher behavior
  unchanged, and the full local test suite passes with no regressions (see the
  commit's reported pass count). The one open item (shared `DataTable`
  reconciliation) is explicitly deferred to U2/U5 above, not silently dropped.

### CC-UI-0027 — Incidental: CLI `--dry-run` flag surfaces in the launcher form (lane D0a) (2026-09-22)
- Change: lane D0a added a `--dry-run` flag to the `build_parser()` of `crawl`,
  `audit`, `fuzz`, `auto`, `mutate-run`, and `proxy` (see CC-CRAWL-0007,
  CC-AUD-0015, CC-FUZZ-0020, CC-MUT-0010, CC-PROXY-0017 for the per-component
  detail). `fuzzlab/web/commandspec.py::introspect()` reads each tool's flags
  straight from its own `build_parser()` by design (see that module's docstring:
  "a new flag shows up in the UI automatically with no change here"), so this new
  flag now appears as an ordinary `bool` option (a checkbox) in each affected
  activity's form in the web launcher, with **no code change to
  `fuzzlab/web/app.py` or `fuzzlab/web/commandspec.py`**. This entry exists to
  record that UI-visible effect, per PA-0031 (D0a's reserved bookkeeping numbers
  include this conditional UI number precisely for this case).
- Impact (other components / project): UI-visible only — one more checkbox per
  affected activity's launcher form. No behavior change to the web launcher's own
  `POST /api/launch/dry-run` route (CC-UI-0013/0015), which already previews any
  command without executing it and does not depend on this new flag. If a person
  checks the new `--dry-run` box and clicks the real "launch" action, the child
  process now started via `POST /api/launch` would itself just print its plan and
  exit 0 (the same behavior the CLI gets directly) — harmless, and arguably useful,
  but not a scenario this lane added UI copy/handling for. `fuzzlab/greybox/
  greybox_cli.py` (`greybox-run`'s form) is unaffected — that tool's `--dry-run` is
  a separate, later change (lane D0b, `CC-FUZZ-0022`).
- Risk (level; mitigation): low — the new option is inert unless a person explicitly
  checks it, and even then only causes the corresponding CLI process (launched
  in-process by the web launcher, same as any other flag) to print its plan and
  exit instead of running for real; it cannot be more permissive than running
  without it. Mitigated by the unchanged `tests/test_web_commandspec.py` and
  `tests/test_web_launcher.py` suites (no assertion pinned the pre-existing flag
  count per tool, so introspecting one more flag did not break anything) plus the
  new `tests/test_cli_dry_run.py`.
- Deliverables:
  - [x] Confirmed via `commandspec.spec(name).to_dict()` that `--dry-run` appears
    as a `bool` option for each of the six affected activities, with no code change
    needed in `commandspec.py`/`app.py` — done.
  - [x] Confirmed the web dry-run suites still pass unchanged — done.
- Effectiveness (assessed 2026-09-22): effective as a record — the launcher form now
  offers `--dry-run` for the six affected activities purely through the existing
  introspection contract; no drift between the CLI's flags and the UI's form
  (PA-0001/PA-0003 preserved).
### CC-UI-0026 — Lane U6: control-plane hardening (Host/Origin/Fetch-Metadata gate) (2026-09-22)
- Change: per `docs/UI_IMPLEMENTATION_PLAN.md` §3 (U6) and its resolved R-13, added
  `fuzzlab.web.app.SecurityGateMiddleware` — a raw ASGI middleware (not
  `BaseHTTPMiddleware`, to avoid interfering with the SSE launch-output stream) guarding
  the whole control plane against being driven by a hostile web page the operator's
  browser happens to visit, given NFR-UI-localhost's "loopback-only" alone does not stop
  that. Two independent gates, both required (each defeats an attack the other misses):
  (a) an exact Host (`host:port`) allow-list on **every** request, rolled ourselves since
  Starlette's `TrustedHostMiddleware` strips the port and can't pin against DNS
  rebinding; (b) on POST/PUT/DELETE, Origin == the allow-list **and**
  `Sec-Fetch-Site == same-origin` (same-site rejected too — the deliberately-vulnerable
  lab this panel drives is same-site with it on a sibling port, the R-13 "landmine"),
  plus a custom `X-Fuzzlab-Client: 1` header on `/api/*` JSON bodies (forces a CORS
  preflight a cross-origin page can't satisfy). The custom-header check cannot apply to
  the panel's existing no-JS `<form method="post" action="/api/run/automatic">` (a
  native form can never set a custom header at all, JS or not), so form-encoded
  (`application/x-www-form-urlencoded` / `multipart/form-data`) `/api/*` bodies are
  exempted from that one check and rely on Origin + Sec-Fetch-Site alone — still real: a
  cross-site auto-submitted forged form fails the same-origin check. Clients sending no
  Fetch Metadata (older browsers, non-browser/API clients) fall back to Origin, then
  Referer. Stays cookieless — no ambient credential means no CSRF token/session store is
  needed, and SameSite wouldn't help given the same-site landmine. Fails closed on any
  ambiguity. Every response (success or denial) also gets a tight offline CSP
  (`default-src 'none'` etc.), `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, COOP/CORP `same-origin`, and
  `Cache-Control: no-store` off `/static/`. Pinned `starlette>=1.0.1,<2` explicitly in
  the `web` extra (`pyproject.toml`) — the R-13 prerequisite (CVE-2026-48710 "BadHost":
  a pre-1.0.1 Host-header validation bypass that would undercut gate (a)); the installed
  version (1.6.0) already satisfied it, this just makes it a declared, enforced floor
  rather than an accident of fastapi's own transitive range. Wired the browser's own JS
  (originally `static/app.js`'s, now `static/js/common.js`'s `postJSON`/`delJSON` after
  lane U0's asset split — the only two call sites that ever issue a state-changing
  `fetch()`) to send `X-Fuzzlab-Client: 1`, so the existing launcher/proxy/repeater UI
  keeps working unmodified from the operator's own browser.
- Impact (other components / project): UI only; no result-table/store contract change.
  **Shares `fuzzlab/web/app.py` with lane U0** (MPA route split, `CC-UI-0025`, merged
  first) — kept additive and localized (one new module-level block + a 4-line
  `add_middleware` call in `create_app`) so it slotted in cleanly alongside U0's route
  registrations without touching them; manually reapplied onto the post-U0 tree by the
  integrating session rather than a raw `git merge` (U0 renamed `static/app.js` →
  `static/js/*.js`, which would otherwise have conflicted). Every existing web test's
  `TestClient` now needs a `base_url`/headers matching this gate (httpx's default
  `http://testserver` base URL and lack of Origin/Sec-Fetch-Site headers would otherwise
  421/403 on everything); centralized in a new `tests/_webclient.py` helper and applied
  across all existing web-test files rather than duplicated per file. The two
  real-browser Playwright tests (`test_web_launcher_browser.py`,
  `test_web_repeater_browser.py`) bind uvicorn to an OS-assigned ephemeral port directly
  but previously left `cfg`'s `web_host`/`web_port` at their defaults (unused before
  this change); now pass `"web_port": port` explicitly so this gate's Host allow-list
  matches the port the browser actually navigates to.
- Risk (level; mitigation): medium (a fail-closed gate on a widely-shared file, wrong in
  either direction is bad — too loose reopens R-13, too strict breaks the panel/lab
  workflow). Mitigated: new `tests/test_web_security.py` (16 cases) covers both gates
  independently — wrong Host (421) including the DNS-rebinding case (correct
  Origin/Sec-Fetch-Site, wrong Host, still 421); classic cross-site CSRF (403); the
  same-site-sibling-port landmine specifically (403); same-origin missing the custom
  header on `/api/*` (403) vs. present (reaches the handler, proven by a distinct 400
  from unknown-command business logic, not a 403); the no-Fetch-Metadata → Origin →
  Referer fallback chain (pass and reject cases); the form-POST custom-header exemption
  (reaches the handler) vs. a forged cross-site form (still 403); security headers
  present on both success and denial responses; `Cache-Control: no-store` present on API
  responses and absent on `/static/`. Full web test suite (post-U0-merge, one adjusted
  asset path — `/static/app.css` → `/static/css/shell.css` — since U0's asset split
  landed first): 135 passed, 2 skipped (Playwright-gated browser tests skip when
  Chromium isn't installed).
- Deliverables:
  - [x] `SecurityGateMiddleware` + `_security_allowlist`/`_origin_of`/`_deny`/
    `_inject_response_headers` + the CSP/security-header constants, added to
    `fuzzlab/web/app.py` as one self-contained block right after `_STATIC_DIR` (before
    the sidebar-nav source of truth U0 added) — done.
  - [x] Wired into `create_app` via a single `app.add_middleware(SecurityGateMiddleware,
    ...)` call, added immediately after `app = FastAPI(...)` and before
    `app.mount("/static", ...)` — the *only* other touch to `create_app`'s existing body;
    no route handler in `fuzzlab/web/app.py` was modified — done.
  - [x] `static/js/common.js`: `postJSON`/`delJSON` now send `X-Fuzzlab-Client: 1` —
    done (applied to U0's post-split module, not the pre-split `static/app.js`).
  - [x] `pyproject.toml`: explicit `starlette>=1.0.1,<2` pin in the `web` extra — done.
  - [x] `tests/_webclient.py` shared TestClient helper (extended to accept passthrough
    `**kwargs` for U0's `follow_redirects=False` PRG test) + all existing web-test files
    updated to use it — done.
  - [x] `tests/test_web_launcher_browser.py` / `tests/test_web_repeater_browser.py`:
    pass `web_port` matching the real bind port — done.
  - [x] `tests/test_web_security.py` — new, 16 cases, both gates — done.
  - [x] `docs/components/12-diagnostics-and-ui/requirements.md`: new
    **NFR-UI-control-plane-hardened**, NFR-UI-localhost cross-referenced to it, new
    acceptance-criteria bullet — done.
  - [x] `CHANGELOG.md` line — done.
  - [x] full test suite run — done (counts recorded above).
- Effectiveness (assessed 2026-09-22): effective for the stated scope — both R-13 gates
  verified independently by `tests/test_web_security.py`, and the existing launcher/
  proxy/repeater surfaces (sync `TestClient` suites + the two real-Chromium Playwright
  suites) keep passing through the gate rather than around it. Re-assess once U1–U5 add
  their own POST routes, to confirm every new state-changing route is still `/api/*`-
  shaped (or is deliberately reviewed as the form-POST exemption's next instance) and so
  stays covered by this gate without a per-route opt-in being needed.

### CC-UI-0025 — Lane U0: MPA routes + asset split (the serialization-breaker) (2026-09-22)
- Change: per `docs/UI_IMPLEMENTATION_PLAN.md` §3 (U0) and resolved markers R-01/R-07,
  replaced the hash-switched single page (`GET /` rendering all five `.panel` sections,
  `app.js`'s `initTabs()` toggling `.hidden` on `hashchange`) with **real, independently
  deep-linkable per-section routes**: `GET /` (Launcher), `/proxy`, `/results`, `/ml`,
  `/diagnostics`, plus the pre-existing `/runs/{id}`. `fuzzlab/web/app.py` gained a single
  `NAV` source of truth (grouped Workbench/Analysis links, each `{id, label, href, icon}`)
  and `_shell_context(cfg, active=...)`/`_launcher_context`/`_results_context` builders that
  compute the active section server-side per request; every `TemplateResponse` already used
  the modern `(request, name, ctx)` signature (R-01), unchanged. Split
  `templates/index.html` into `templates/sections/{launcher,proxy,results,ml,diagnostics}.html`
  (each `{% extends "base.html" %}`), `static/app.js` into `static/js/{shell,common,
  launcher,proxy}.js` (`shell.js` = theme/density/sidebar/proxy-chip, loaded on every page;
  `common.js` = shared `postJSON`/`delJSON`/`toWire`/`subscribe`; `launcher.js`/`proxy.js` =
  per-section behavior), and `static/app.css` into `static/css/{shell,launcher,proxy,
  results}.css` (`shell.css` = the app-shell grid + shared primitives, loaded on every page;
  each section links its own partial). `base.html`'s sidebar now renders real `<a href="...">`
  links from `NAV` with server-rendered `aria-current="page"` on the active one (never color
  alone — a left accent bar too, R-11); the no-FOUC inline `<head>` script is unchanged and
  now runs on every full-page MPA navigation, as required. `initTabs()`/the hash router is
  fully retired, not just unused. Converted the Proxy "send to Repeater" pivot to **POST /
  Redirect / GET with a 303** (R-07): a real `<form method="post" action="/proxy/repeater/
  from-flow">` posts the opaque `flow_id`; the new `POST /proxy/repeater/from-flow` route
  (parses the small `application/x-www-form-urlencoded` body by hand via `urllib.parse.
  parse_qsl` rather than pulling in `python-multipart` for one field, per PA-0005's spirit)
  creates the tab server-side and 303-redirects to `/proxy?repeater_tab=<id>` — an opaque
  hint the Repeater JS treats as a fallback-safe seed (never bytes on the wire; an unknown
  flow id degrades to the default view, never a 404). The pre-existing JSON API
  (`POST /api/proxy/repeater/from-flow/{flow_id}`, used by `test_web_repeater.py` and the
  controller layer) is untouched. `run.html`/`not_found.html` now link back to `/results`
  (the run listing's real route) instead of `/`, and carry `active="results"` so the sidebar
  reflects that a run detail is a Results sub-page.
- Impact (other components / project): UI only; no schema/contract change. Establishes the
  file-disjoint surface (`templates/sections/*.html`, `static/{js,css}/<section>.*`) every
  Wave-1 UI lane (U1–U5) depends on to build in parallel without touching each other's files,
  per `docs/UI_IMPLEMENTATION_PLAN.md` §4's dependency map. `FR-UI-7`/`FR-UI-8` in
  `requirements.md` updated in place to describe the MPA shell (superseding the
  hash-switched-`.panel` description from CC-UI-0021/0022). No change to `core/`, the store
  contract, or any tool's CLI. U6 (control-plane hardening, `CC-UI-0026`) is a same-`app.py`
  Wave-0 lane that lands with/right after this one per that plan's own note; this change adds
  no CSRF/Origin/Host validation itself (out of U0's scope) and does not weaken the existing
  no-auto-run/loopback-only/authorized-gate invariants (unchanged gate checks on
  `/api/run/automatic`, `/api/launch`, `/api/proxy/repeater/tabs/{id}/send`).
- Risk (level; mitigation): low-medium — the change is a structural refactor of every route
  and every static asset path, so a missed reference could 404 a whole section. Mitigated by:
  a full route inventory (`/`, `/proxy`, `/results`, `/ml`, `/diagnostics`, `/runs/{id}`,
  `not_found.html`) each asserted directly via `TestClient`; a parametrized route/no-JS test
  over every section (`test_section_route_renders_the_app_shell`,
  `test_section_route_is_deep_linkable_and_marks_active_nav`) asserting the shell, the
  section's own content, `aria-current="page"`, and the `data-section` hook exist together;
  explicit assertions that no `href="/#..."` hash link remains and that `initTabs` is gone;
  a 303-redirect test for the new PRG pivot (both the found and not-found flow-id cases); a
  grep across `fuzzlab/`/`tests/` confirming no remaining reference to the retired
  `templates/index.html`/`static/app.css`/`static/app.js` paths. The PRG route's hand-rolled
  form parse is scoped to one trusted-shape field (`flow_id`, cast through `int()`) so a
  malformed body degrades to the safe default redirect rather than raising.
- Deliverables:
  - [x] `NAV` + per-route `_shell_context`/`_launcher_context`/`_results_context` in
    `app.py`, with `/`, `/proxy`, `/results`, `/ml`, `/diagnostics` routes — done.
  - [x] `templates/sections/*.html` split (extends `base.html`; per-section `{% block
    styles %}`/`{% block scripts %}`) — done.
  - [x] `static/css/{shell,launcher,proxy,results}.css` + `static/js/{shell,common,
    launcher,proxy}.js` split; `app.css`/`app.js` removed — done.
  - [x] Server-rendered sidebar `aria-current="page"` + `data-section` hooks on `<nav>`
    links and `<main>` — done.
  - [x] PRG + 303 "send to Repeater" pivot (`POST /proxy/repeater/from-flow`) — done.
  - [x] `run.html`/`not_found.html` updated to link `/results` and carry `active="results"`
    — done.
  - [x] Tests updated for routes (`test_web_frontend.py` rewritten; `test_web_results.py`,
    `test_web_proxy_history.py` moved their shell assertions off `/` to `/results`/`/proxy`;
    browser-smoke selectors updated to `data-section`) — done, focused run green (see below).
  - [x] `docs/components/12-diagnostics-and-ui/requirements.md` (`FR-UI-7`, `FR-UI-8`)
    updated in place — done.
- Effectiveness (assessed 2026-09-22): effective for its own scope — every section is
  independently reachable and deep-linkable, no-JS (`TestClient`, which runs no JS) renders
  each section's full content, the active-nav state is server-rendered, and the focused web
  suite (`test_web_frontend.py` plus every other `test_web_*.py` file) passed locally (128
  passed; see the report for exact counts). Re-assess once U1–U5 land on top of this split
  and once U6's control-plane hardening lands alongside it in `app.py`.

### CC-UI-0024 — Lane X0: register `lab-generate` in the launcher (own group) (2026-09-22)
- Change: surfaced `fuzzlab lab-generate` as a launchable activity in the web launcher (Wave-0
  lane X0 of `docs/UI_IMPLEMENTATION_PLAN.md`). `fuzzlab/labgen/cli.py` already exposed
  `build_parser()`, so this added a `_load_labgen` loader + a `_REGISTRY` entry in
  `fuzzlab/web/commandspec.py` (`sends_traffic=False` — it renders files locally and `--check`
  runs offline build gates, so **no `authorized`/destructive gate**). Introduced an optional
  `group` field on `_Entry`/`CommandSpec` (+ `to_dict()`), set to `"Lab / authoring"` for
  lab-generate; made `app.py`'s `_group_activities` bucket leftover activities by that spec
  `group` (falling back to the existing name-map / "Other"), so the activity picker shows
  lab-generate under its own group while every other tool's grouping is unchanged.
- Impact (other components / project): UI only; no schema/contract change. The command-spec form
  contract is unchanged (fields still argparse-derived — PA-0001). The new `group` field is
  additive and defaults to `None`. Establishes the U0↔X0 grouping contract (X0 sets `group`; U0
  reads `a.get("group")`), so U0's app.py refactor composes without conflict. `lab-generate`'s
  parser pulls in `fuzzlab.labgen`, which needs the declared `covertable` dep; `all_specs()`
  already skips any activity whose parser import fails, so a missing optional dep degrades the
  launcher rather than breaking it.
- Risk (level; mitigation): low. Registering an activity runs nothing (introspection is pure).
  Mitigation: new `test_web_commandspec.py` cases assert lab-generate is registered, grouped
  ("Lab / authoring"), non-traffic/ungated, and argparse-derived, and that `group` defaults to
  `None` elsewhere; `python -m fuzzlab.cli lab-generate --help` verified; web + command-spec
  suites green (44 passed in the focused run). No `authorized` gate on a file-rendering tool
  keeps no-auto-run intact (it sends no traffic).
- Deliverables:
  - [x] `_load_labgen` + `_REGISTRY` entry + `group` field in `commandspec.py` — done.
  - [x] group-aware `_group_activities` in `app.py` — done.
  - [x] command-spec tests for lab-generate + the `group` default — done.
  - [x] full-suite check (X0 introduced no new failures; 1281 passed — the only failures are
    pre-existing LAB `--check` tests needing the `gitleaks` binary, absent in this sandbox) — done.
- Effectiveness (assessed 2026-09-22): effective — lab-generate now appears as a grouped,
  non-traffic launcher activity with argparse-derived fields, and the `group` contract is in place
  for U0. Re-assess once U0's MPA refactor renders the grouped picker end-to-end.

### CC-UI-0023 — UI implementation plan + build policy + round-1 research (2026-09-22)
- Change: added `docs/UI_IMPLEMENTATION_PLAN.md`, the single tracked plan for the remaining web UI
  work (companion to `UI_REVAMP_PLAN.md`, `UI_LAYOUT_REDESIGN.md`, and the LAB plan). It records
  the **settled build policy** ("no build step, ever; offline + loopback; hand-roll where vanilla
  is cheap; vendor exactly one zero-dependency static file only where hand-rolling is expensive")
  and the **five locked decisions** (D1 MPA routes; D2 vendor one zero-dep chart lib; D3 split
  assets, no bundler; D4 hand-roll tables; D5 include `lab-generate` in the launcher). It breaks
  the outstanding work into clear, executable, lane-organized deliverables — **U0** (MPA routes +
  asset split, the enabling refactor), **U1** Overview, **U2** Findings, **U3** Proxy rebuild,
  **U4** ML, **U5** Diagnostics + store explorer, **B0** `metric_series` + emitters, **X0**
  `lab-generate` in the launcher — with per-deliverable scope/files/deps/sub-lanes/acceptance and a
  wave/dependency map for concurrent-agent dispatch. It runs a research-refinement loop (mark gaps
  → dispatch one web agent per gap → fold findings back, ×3). **Round 1** (six agents, R-01…R-06)
  is folded in: full-page MPA, no HTMX; **uPlot 1.6.32** as the vendored chart lib (canvas;
  re-theme on `[data-theme]`; columnar data; offscreen-table a11y fallback); findings facet
  sidebar + **SQLite-backed saved views** + a hand-rolled DataTable (no virtualization,
  `textContent`-only, scheme-checked pivots); one shared `<message-editor>` (byte-exact textarea,
  vanilla grid splitter, hand-rolled highlighting); TensorBoard-style diagnostics controls +
  validated `metric_series(run_id, source, key, step, ts, value)` schema + a buffered
  `MetricLogger` emitter + **LTTB** server-side downsampling → client-side EMA; advisory-framed
  read-only ML panels (PR/reliability/weights/nDCG/conformal/anomaly/Beta-posteriors). Realizes
  more of FR-UI-8.
- Impact (other components / project): documentation/planning only — no code, schema, or contract
  change yet. Flags forthcoming work in CORE (the `metric_series` migration + WAL/concurrency in
  B0) and a `saved_views` table (U2); those land under their own change-control when built. Does
  not alter any invariant.
- Risk (level; mitigation): none (planning). The plan itself carries the invariants forward
  (no-auto-run / loopback / authorized / read-only / redaction / no-build-offline) into every lane
  and its acceptance criteria.
- Deliverables:
  - [x] `docs/UI_IMPLEMENTATION_PLAN.md` (policy + deliverables + lane map) — done.
  - [x] Round 1 research (R-01…R-06) dispatched + folded in — done.
  - [x] Round 2 (R-07 MPA pivot/state, R-08 SQLite WAL concurrency, R-09 test strategy, R-10
    Overview content) — folded in.
  - [x] Round 3 (R-11 accessibility, R-12 uPlot theming/responsive, R-13 loopback security) —
    folded in; added lane **U6 — control-plane hardening** and two §2 invariants (accessible;
    not-itself-an-attack-surface).
- Effectiveness (assessed 2026-09-22): effective — the 3-round research loop (13 markers) converted
  every open UI design fork into concrete, cited, executable spec and surfaced one net-new lane
  (U6) that a security tool needs to keep its own control plane off the attack surface. Deliverables
  are lane/wave-organized for distributed builds. Re-assess once the first lanes (U0/B0/X0/U6)
  build against it.

### CC-UI-0022 — Launch view rebuilt as the approved master-detail (2026-09-21)
- Change: rebuilt the Launcher section inside the R0 shell to match the **approved mockup**
  (`docs/UI_LAYOUT_REDESIGN.md`), replacing the old stacked cards (Target/Scope/Mode,
  Automatic, Manual, one card per activity). Brought forward from R1 at the user's request so
  the Launch view they reviewed is what ships now.
  - **Master-detail layout** (`.launch` grid): a left **activity picker** (`.actlist`) listing
    every activity grouped (Discovery / Attack / Analysis / Other), each row carrying compact
    **gate tags** (`traffic` / `auth` / `destr`) and an accent bar when selected; a right
    **detail** (`.lform`) that shows the selected activity's configurable form. All activity
    forms render server-side; `initLaunchNav()` shows one at a time (no-JS shows all — same
    progressive-enhancement rule as the tabs). Default selection is `auto`.
  - Detail form: a `.lform-head` (name + `sends traffic` / `--authorized` /
    `--allow-destructive` tags + Dry-run / Run / Stop), the tool's fields as `.frow` rows,
    bool flags folded into one inline `.optck` row, the D14 category picker as checkbox pills,
    and the plugins panel (`.plugpanel`) on `auto`. The dry-run **preview** and live SSE
    **console** are retokenized.
  - `auto` keeps a one-click **Run full pipeline** action (`POST /api/run/automatic`) above
    its flag form; the Manual/CLI prewired-command reference moved into a collapsed
    `<details>` below the grid.
  - Server: `_group_activities()` buckets activities into the ordered launcher groups
    (unknown tools fall into "Other"); `activity_groups` added to the index context.
- Impact (other components / project): UI only; no schema, contract, route, or CLI change.
  The command-spec-driven form contract is unchanged — every control still carries the same
  `data-dest` / `data-type` / `data-catgroup` hooks, so the runner, dry-run, gating, and SSE
  are untouched. Realizes the Launch portion of FR-UI-8 (the rest of R1 — per-section routes +
  Overview — still pending).
- Risk (level; mitigation): low. The forms and their JS are the same; only their container
  markup and CSS changed. Mitigation: full suite green (499 passed / 6 skipped), the
  whitespace-fragile gate assertion rewritten to match the stable gate title, the real-browser
  launcher test updated to select the activity first (dry-run + gated Run + SSE still verified
  end-to-end), and screenshots of the rebuilt view in light and dark.
- Deliverables:
  - [x] Master-detail Launch markup (activity picker + detail) — done.
  - [x] `initLaunchNav()` selection + retokenized launch CSS — done.
  - [x] `_group_activities()` + `activity_groups` context — done.
  - [x] Tests updated (gate title, browser select-first) + full suite green — done.
  - [x] Real-browser screenshot verification (light + dark) — done.
- Effectiveness (assessed 2026-09-21): effective. The Launch view now matches the reviewed
  mockup (verified by screenshots), the launcher behavior is unchanged, and the suite is green.

### CC-UI-0021 — App shell + design tokens (layout redesign R0) (2026-09-21)
- Change: implemented **R0** of the layout redesign (`docs/UI_LAYOUT_REDESIGN.md`,
  CC-UI-0020): replaced the top hash-tab masthead with a persistent **app shell** and a
  **design-token** system, with **no behavior change** to the launcher / proxy / results.
  Realizes new requirement **FR-UI-8**.
  - New `fuzzlab/web/static/tokens.css` — the single source of truth for color, elevation,
    and density: light default, dark under `@media (prefers-color-scheme: dark)` guarded by
    `:root:not([data-theme="light"])`, an explicit `:root[data-theme="dark"]` override, and
    `:root[data-density="compact"]`.
  - `base.html` rewritten into the shell: a left **sidebar** (`<nav class="tabs">`, grouped
    Workbench / Analysis) + a **top context bar** with target / scope / authorized / proxy
    chips and theme / density / collapse controls, over a scrolling `<main class="content">`
    (`{% block content %}`). A no-FOUC `<head>` script applies persisted theme / density /
    collapse to `<html>` before first paint (wrapped in try/catch — blocked storage never
    breaks rendering). `tokens.css` is linked before `app.css`.
  - `index.html` / `run.html` / `not_found.html` moved from `{% block body %}` to
    `{% block content %}` (the masthead + top-tabs were dropped from index; the five
    `.panel` sections and every launcher form are byte-for-byte unchanged). Each adds a
    `{% block crumb %}`.
  - `app.css` rewritten as a CSS-grid shell (`grid-template-areas: "side top" "side main"`)
    with **retokenized** components — every existing class preserved (`.card`, `nav.tabs`,
    `.panel`/`.hidden`, `.field`, `.launch-form`/`.catgroup`/`.cat`/`.actions`/
    `.launch-preview`/`.launch-output`, `#flow-table`/`.flow-raw`, `#pending-table`/
    `.pending-raw`, `.pill`/`.result`, tables) now consuming tokens instead of raw hex.
  - `app.js`: added `initShell()` (theme cycle system→light→dark, density toggle, sidebar
    collapse — all persisted in `localStorage` behind try/catch — plus the topbar proxy
    chip from `/api/proxy/status`); `initTabs()` now no-ops on pages without `.panel`
    sections (run detail / not-found) so no tab is falsely highlighted. Selectors,
    `subscribe`, and all proxy/launcher init unchanged.
  - `app.py`: added `_shell_context(cfg)` (target / scope / authorized) and merged it into
    the index, run-detail, and not-found `TemplateResponse`s so every page carries identical
    shell chrome; `_index_context` now spreads it.
- Impact (other components / project): UI only; no schema, contract, or CLI change. No route
  added or changed. Supersedes the Phase-0.2 top-tab shell (CC-UI-0012) as the layout, while
  keeping its hash-based section switching. New static asset `/static/tokens.css`. Adds
  decision **D-UI-shell** (left-nav app shell + design tokens) to the roadmap.
- Risk (level; mitigation): low. Chrome-only rewrite; the invariant-bearing markup (launcher
  forms, gate pills, proxy cards, result tables) is unchanged, so the no-auto-run / loopback /
  authorized / read-only / redaction invariants are untouched. Mitigation: full suite green
  (499 passed / 6 skipped) — existing shell tests pass unchanged because `nav.tabs` / `.card`
  / `initTabs` / `subscribe` were preserved — plus new asset/shell tests, and a real-browser
  (Playwright) screenshot check of launcher + proxy in light and dark.
- Deliverables:
  - [x] `tokens.css` (light / dark / system + density) — done.
  - [x] `base.html` app shell (sidebar + top context bar + no-FOUC) — done.
  - [x] `index.html` / `run.html` / `not_found.html` → `{% block content %}` + crumb — done.
  - [x] `app.css` grid shell + retokenized components (all classes preserved) — done.
  - [x] `app.js` `initShell()` + `initTabs()` guard — done.
  - [x] `app.py` `_shell_context()` merged into every page — done.
  - [x] Tests: tokens served, shell renders, shell context on run/not-found — done.
  - [x] Full suite + real-browser visual verification — done.
  - [ ] R1 (routes + Overview), R2 (Findings), R3 (Proxy rebuild) — pending.
- Effectiveness (assessed 2026-09-21): effective. The shell renders professionally in both
  themes (verified by screenshots), section switching and all launcher/proxy controls behave
  exactly as before, and the full suite is green with the design system now centralized in
  `tokens.css` for R1–R3 to build on.

### CC-UI-0020 — Web UI layout redesign (design record) (2026-09-21)
- Change: added `docs/UI_LAYOUT_REDESIGN.md` — a design record for reworking the panel's
  **layout / information architecture** (distinct from the feature revamp in
  `UI_REVAMP_PLAN.md`). Grounded in researched UI/UX patterns from Rapid7 InsightVM, Tenable
  (Nessus / VM / .sc), Qualys VMDR, Greenbone/OpenVAS (GSA), NodeWare, Burp Suite, and OWASP
  ZAP. Proposes replacing the single-page top hash-tab layout with an **app shell** (persistent
  left sidebar + top context bar) over a **deep-linkable multi-page app** (jinja `shell.html` +
  per-section routes, still dependency-light — no SPA/build), a shared design system (tokens
  with light/dark + density, one DataTable with faceted filters + saved views, one reusable
  proxy message editor, list→detail with breadcrumbs, command palette + "send to" chaining),
  an Overview dashboard, a Findings workbench, and a rebuilt Proxy workbench; plus an
  incremental migration path (R0 shell/tokens → R1 routes+Overview → R2 Findings → R3 Proxy
  rebuild) that preserves the no-auto-run / loopback / authorized / read-only / redaction
  invariants and folds Phases 3–4 in as sections.
- Impact (other components / project): design only — no code, no schema change. Supersedes the
  Phase-0.2 top-tab shell (CC-UI-0012) once adopted; will add a decision (UI shell = left-nav
  MPA) and FR-UI entries at that point.
- Risk (level; mitigation): none (documentation). The doc scopes each migration step as
  independently testable with invariants preserved.
- Deliverables:
  - [x] `docs/UI_LAYOUT_REDESIGN.md` (research synthesis + IA + design system + migration) — done.
  - [ ] Visual mockup of the shell for review — in progress.
  - [ ] R0–R3 implementation — pending user direction.
- Effectiveness (assessed 2026-09-21): effective as a design record — grounded in a
  cross-tool UX review; awaiting direction before implementation.

### CC-UI-0019 — Proxy tab: Scope + Match-Replace (Phase 2.4; completes the workbench) (2026-09-21)
- Change: `ProxyController` gained live `scope_view` / `scope_add(host, path_regex?, exclude)`
  / `scope_remove(index)` over the engine's default-deny `Scope`, and `matchreplace_view` /
  `matchreplace_add(target, match, replace, header_name?, is_regex)` / `matchreplace_remove` /
  `matchreplace_toggle` over the ordered `MatchReplaceEngine`. Routes: `GET|POST
  /api/proxy/scope`, `DELETE /api/proxy/scope/{index}`, `GET|POST /api/proxy/matchreplace`,
  `DELETE /api/proxy/matchreplace/{index}`, `POST /api/proxy/matchreplace/{index}/toggle`
  (all 409 without the in-process proxy; a bad match-replace target / missing header_name →
  400). The Proxy tab's **Scope · Match-Replace** card lists/add/removes scope rules
  (host + optional path-regex, include/exclude) and match-replace rules (target, header,
  match→replace, regex, enable toggle); rows are DOM-built. Changes apply to subsequent
  proxied requests on the same event loop.
- Impact (other components / project): **completes the Proxy workbench** (History,
  Intercept, Repeater, Scope/Match-Replace) — realizing ask #2 of the revamp. Consumes the
  proxy `Scope`/`MatchReplaceEngine` unchanged; no schema change. Available only under
  `fuzzlab web --with-proxy` (else the card shows a start hint).
- Risk (level; mitigation): low — edits an opt-in, loopback, authorized proxy's config.
  Mitigated by tests: `tests/test_web_scope.py` (controller scope add/remove + in_scope
  effect; match-replace add/view/toggle/remove + a real rewrite via `engine.matchreplace.apply`;
  add-validation raises; routes 409 without proxy, scope add/remove + host-required 400,
  match-replace add/toggle/remove + bad-target 400). Suite 496 passed / 6 skipped.
- Deliverables:
  - [x] Controller scope + match-replace methods; routes — done.
  - [x] Scope / Match-Replace UI (list/add/remove/toggle) — done.
  - [x] Tests (controller effects + routes) — done; verified in a real browser (screenshot).
- Effectiveness (assessed 2026-09-21): effective — scope include/exclude and ordered byte
  rewrites are manageable live and take effect on the engine; the Proxy workbench is complete.

### CC-UI-0018 — Proxy tab: Repeater (replay tabs) (Phase 2.3) (2026-09-21)
- Change: added a `RepeaterController` (web) over the existing `Repeater` backend — its own
  `SocketSender` + lazily-opened store (created only on first write), `list_tabs` (all tabs,
  newest first, read-only), `create_tab`, `create_from_flow`, and `send` (byte-exact replay,
  `authorized`-gated by the route). Routes: `GET /api/proxy/repeater/tabs`, `POST
  /api/proxy/repeater/tabs`, `POST /api/proxy/repeater/from-flow/{flow_id}` (seed a tab from
  a History flow), `POST /api/proxy/repeater/tabs/{id}/send` (403 unless authorized; 404 for
  an unknown tab). These handlers are async so the controller's persistent SQLite connection
  is only touched from the event-loop thread. The Proxy tab's **Repeater** card renders a
  tabs dropdown, a new-tab form, an editable raw request, Send, and a response viewer; a
  History flow gains a "→ Repeater" button. **Bug fixed:** a `<textarea>` normalizes
  newlines to LF, which breaks HTTP framing — the client now restores CRLF (`toWire`) before
  sending an edited request (repeater **and** intercept-forward); the API stays byte-exact.
- Impact (other components / project): replay is available whenever authorized, independent
  of the in-process proxy; tabs persist in `repeater_tab` across sessions. Consumes the proxy
  `Repeater`/`SocketSender` unchanged; no schema change. Sending is the only traffic path and
  is gated.
- Risk (level; mitigation): low–medium — replay sends traffic. Mitigated by the authorized
  gate, and tests: `tests/test_web_repeater.py` (controller create/list/send-with-injected-
  sender/from-flow; routes list/create, send 403 gate + a real over-socket send to a threaded
  upstream + 404, from-flow 404) and a real-browser regression `tests/test_web_repeater_browser.py`
  (create + edit in a textarea + Send → the upstream echoes the edited target, proving the
  CRLF fix). Suite 490 passed / 6 skipped.
- Deliverables:
  - [x] `RepeaterController` + routes (tabs/create/from-flow/send) — done.
  - [x] Repeater UI (tabs, new-tab, editor, Send, response) + History "→ Repeater" — done.
  - [x] CRLF (`toWire`) fix for textarea-edited raw (repeater + intercept) — done.
  - [x] Controller/route tests + real-browser regression — done.
  - [ ] Scope / match-replace (Phase 2.4) — next.
- Effectiveness (assessed 2026-09-21): effective — verified in a real browser: create a tab,
  edit the raw request, Send, and see the upstream's response; and a flow seeds a tab via
  "→ Repeater". Screenshot captured.

### CC-UI-0017 — Proxy tab: live Intercept (pause/edit/drop/forward) (Phase 2.2) (2026-09-21)
- Change: added the intercept control surface. `ProxyController` gained `pending_view()`
  (JSON-safe held flows: id/direction/host/method/target + raw text), `forward(id, raw?)`
  (edit via `RawMessage.from_bytes(raw.encode('latin-1'))`), `drop(id)`, and
  `set_intercept_responses(on)` (status now carries `intercept_responses`). Routes:
  `POST /api/proxy/intercept` extended to toggle `on`/`responses`, `GET
  /api/proxy/intercept/pending`, `POST /api/proxy/intercept/{id}/forward` (optional
  `{"raw"}`), `POST /api/proxy/intercept/{id}/drop` — all 409 without an in-process proxy.
  The Proxy tab's **Intercept** card renders the request/response toggles, a polled pending
  table, and an editable raw-bytes textarea with Forward / Drop. Pending rows come from
  traffic (untrusted) so they're DOM-built with `textContent`.
- Impact (other components / project): realizes live pause/edit/drop/forward in the browser,
  backed by the in-process proxy (Phase 0.4) and the CC-PROXY-0015 response hook. Available
  only under `fuzzlab web --with-proxy` (else the card shows a start hint). No schema change;
  the UI writes no results.
- Risk (level; mitigation): low–medium — the panel can now alter live traffic. Mitigated by
  the proxy being opt-in + `--authorized`-gated, DOM-safe rendering, and tests:
  `tests/test_web_intercept.py` (controller pending_view/forward round-trip against a real
  paused flow, unknown-id benign, responses toggle; routes 409 without proxy and
  pending/forward/drop with a pre-built proxy) plus the engine + over-socket integration
  tests under CC-PROXY-0015. Suite 484 passed / 6 skipped.
- Deliverables:
  - [x] Controller pending_view/forward/drop/set_intercept_responses — done.
  - [x] Intercept routes; Intercept UI (toggles, polled pending, edit + Forward/Drop) — done.
  - [x] Tests (controller + routes); live over-socket + engine tests — done.
  - [ ] Repeater (Phase 2.3); scope / match-replace (Phase 2.4) — next.
- Effectiveness (assessed 2026-09-21): effective — verified in a real browser holding a real
  in-flight request ("intercept ON · 1 pending"), with the raw bytes editable and
  Forward/Drop; and over real sockets an edited request reaches the upstream. Screenshot
  captured.

### CC-UI-0016 — Proxy tab: read-only flow History (Phase 2.1) (2026-09-21)
- Change: added `fuzzlab/web/proxyview.py` (pure, store-backed `list_flows` + `flow_detail`
  over `flow`/`body`/`flow_fts`; newest-first, FTS search, and raw request/response decoded
  for display) and read routes `GET /api/proxy/flows[?q=]` and `GET /api/proxy/flows/{id}`
  (404 for a missing flow). The Proxy tab now renders a **History** sub-panel — a search
  box, a flows table (method/url/host/status/ms/protocol), and a req/resp viewer — plus a
  live proxy-status line. Flow url/host/head come from recorded traffic (untrusted), so the
  rows are built with DOM APIs + `textContent`, never interpolated HTML.
- Impact (other components / project): surfaces the proxy component's flow history in the
  panel; works cross-process (reads the store a running `fuzzlab proxy` / `web --with-proxy`
  writes). Read-only — never creates the store, sends no traffic, writes no results. No
  schema change; the proxy component is consumed unchanged.
- Risk (level; mitigation): low — read-only store reads and DOM-safe rendering (redacted
  bytes on write; `textContent` blocks stored-XSS from flow fields). Mitigated by
  `tests/test_web_proxy_history.py` (7: list newest-first, FTS query hit/miss, detail decode
  + 404, API list/search, API detail/404, missing-store empty + no-create, tab renders) and
  the real-browser smoke extended to switch to the Proxy tab, see a seeded flow, and open
  its detail. Suite 474 passed / 6 skipped.
- Deliverables:
  - [x] `web/proxyview.py` (list_flows / flow_detail) — done.
  - [x] `/api/proxy/flows[/{id}]` routes; Proxy-tab History UI + status line — done.
  - [x] Tests (view + routes + read-only invariant) + browser smoke — done.
  - [ ] Live intercept (edit/drop/forward), repeater, scope/match-replace (Phase 2.2+) — next.
- Effectiveness (assessed 2026-09-21): effective — recorded flows list and are searchable,
  and a flow's redacted raw request/response render; verified in a real browser.

### CC-UI-0015 — Activity Launcher UI: forms + dry-run + live output (Phase 1) (2026-09-21)
- Change: turned the read-only activity preview into an interactive **launcher**. The
  Launcher tab now renders a form per non-subcommand activity, server-side from each
  command spec — a widget per flag by type (text / number / `<select>` for choices /
  checkbox for bools / textarea for repeatables), keyed by argparse `dest`. `app.js` gained
  `collectValues` + `initLaunchForms`: **Dry-run** (`POST /api/launch/dry-run`) shows the
  exact command and sends nothing; **Run** (`POST /api/launch`) streams the child's output
  live via a named-event `EventSource` (`output`/`done`), with **Stop**. Traffic tools' Run
  is disabled unless `authorized`, and `--authorized` is pre-checked when the panel is
  authorized. Added a **D14 category picker** — the `--categories` flag renders as
  checkboxes from `known_categories()`, joined to a comma value. Added a **Plugins** panel +
  `GET /api/plugins` (the active entry-point set that `--plugins` would attach). Session
  (subparsers) renders as a CLI note, not a form.
- Impact (other components / project): realizes FR-UI-6 (launcher) and FR-UI-5 (dry-run) in
  the browser, and the D14 manual category selection. Consumes the Phase-0 endpoints and the
  command spec; no backend behavior/schema change beyond the read-only `/api/plugins`. The
  no-auto-run / loopback / authorized / read-only invariants hold (launch is explicit and
  gated; the UI writes no results).
- Risk (level; mitigation): low–medium — new client JS driving real launches. Mitigated by
  the gate (traffic Run disabled/refused without `authorized`), the declared-flags-only +
  no-shell runner (CC-UI-0013), and tests: `tests/test_web_frontend.py` extended (form per
  activity, dest-keyed fields, Run-button gating by authorization, category picker, plugins
  panel/endpoint, session-as-note) and a real-browser end-to-end smoke
  `tests/test_web_launcher_browser.py` (Chromium + uvicorn: fills the report form, asserts
  the dry-run preview `fuzzlab report --store x.db`, then Runs and sees output stream to
  `[exit …]` over SSE — skip-guarded when no browser). Suite 467 passed / 6 skipped.
- Deliverables:
  - [x] Per-activity forms (server-rendered from specs) + dry-run/run/stop wiring — done.
  - [x] Live SSE output in the browser; Run gated by authorization — done.
  - [x] D14 category picker; Plugins panel + `/api/plugins` — done.
  - [x] Frontend tests + real-browser end-to-end smoke — done.
  - [ ] Phase 2 proxy workbench; Phase 3 ML tab; Phase 4 diagnostics — next.
- Effectiveness (assessed 2026-09-21): effective — verified in real Chromium: the launcher
  builds each command from its parser, previews it on dry-run without traffic, and streams a
  gated run's output to completion. Screenshot captured for review.

### CC-UI-0014 — Unified serve mode: in-process proxy controller (Phase 0.4; D19) (2026-09-21)
- Change: added `fuzzlab/web/proxycontrol.py` (`ProxyConfig` + `ProxyController`) — it
  builds the proxy engine (Scope + `MatchReplaceEngine` + `Interceptor` + `SocketSender` +
  optional `HistoryWriter` + `LocalCA`) and owns its lifecycle. `create_app(..., proxy=)`
  gained a FastAPI **lifespan** that starts the controller on startup and stops it on
  shutdown, so the live interceptor shares the panel's event loop (its `asyncio.Future`s
  are not cross-process). New endpoints `GET /api/proxy/status` (dormant `{configured:
  false}` when no proxy) and `POST /api/proxy/intercept` (toggle; 409 when none). `serve()`
  takes an optional `proxy` and refuses a non-loopback proxy host; a new `web_main()` parses
  `fuzzlab web [--with-proxy …]` and, because the proxy forwards to upstreams, requires
  `--authorized` before wiring one (mirrors `fuzzlab proxy`). `fuzzlab web` now routes
  through `web_main` (`cli.py`).
- Impact (other components / project): the seam the **Phase-2 Proxy workbench** will use —
  its routes reach the live `Interceptor` via the controller (pause/edit/drop/forward),
  while flow history stays store-readable cross-process. Consumes the existing proxy
  component unchanged (no proxy code edited; the response-intercept hook is Phase 2). No
  schema change. The proxy is opt-in, `--authorized`-gated, loopback-only, on a separate
  port; without `--with-proxy` the panel is unchanged. Records D18 (subprocess launch, from
  0.3) and D19 (in-process proxy).
- Risk (level; mitigation): medium — the panel can now host a listener that forwards
  traffic. Mitigated by the authorization gate on `--with-proxy`, loopback-only binding for
  both the panel and the proxy (asserted; `serve` refuses non-loopback), the opt-in default
  (dormant unless asked), and tests: `tests/test_web_proxy_serve.py` (7) — controller
  start/status/stop on an ephemeral port, intercept toggle, dormant status + 409 without a
  proxy, lifespan start/stop via the TestClient context manager, `serve` refusing a
  non-loopback proxy host, and `web_main` refusing `--with-proxy` without `--authorized`.
  Suite 462 passed / 6 skipped.
- Deliverables:
  - [x] `web/proxycontrol.py` (build/start/stop/status/set_intercept) — done.
  - [x] Lifespan wiring + `/api/proxy/status` + `/api/proxy/intercept` — done.
  - [x] `serve(proxy=)` loopback guard + `web_main` (`--with-proxy`, authorized-gated) — done.
  - [x] D18/D19 recorded; tests — done.
  - [ ] Proxy workbench UI: history, intercept edit/drop/forward, repeater (Phase 2) — next.
- Effectiveness (assessed 2026-09-21): effective — the controller binds/stops cleanly in the
  app's loop, status/intercept reflect the live engine, and the gates hold. This completes
  the Phase-0 foundations; Phases 1–4 build the tabs on them.

### CC-UI-0013 — Launcher runner: dry-run + gated execution + SSE output (Phase 0.3) (2026-09-21)
- Change: added `fuzzlab/web/runner.py` and four launcher endpoints. `build_flags`/
  `build_argv`/`display_command` turn a `CommandSpec` + submitted flag values into an argv
  (`python -m fuzzlab.cli <name> <flags>`, mirroring the real CLI); `Runner` launches it
  with `asyncio.create_subprocess_exec` and streams stdout/stderr as SSE (`output` events
  then a `done` event with the return code), with `stop()` to terminate. Endpoints:
  `POST /api/launch/dry-run` (plans + returns the exact argv/display, sends nothing —
  FR-UI-5), `POST /api/launch` (no-auto-run gate: a `sends_traffic` activity is refused
  with 403 unless `authorized:true`), `GET /api/launch/{token}/stream` (SSE), and
  `POST /api/launch/{token}/stop`. Two safety properties by construction: **only flags the
  spec declares reach argv** (unknown `values` keys are ignored — no arbitrary-arg
  injection), and **no shell** is used (`create_subprocess_exec` with an argv list, so
  values can't be shell-interpreted).
- Impact (other components / project): the execution backbone for the Phase-1 launcher UI
  (forms → dry-run → gated run → live output). Runs each tool as its own subprocess, so the
  tools keep writing their own results (the UI writes none). No schema change. The UI does
  not send traffic on its own — only an explicit, authorized `POST /api/launch` of a
  traffic tool does.
- Risk (level; mitigation): medium — the panel can now spawn tools. Mitigated by the
  authorized gate (mirrors automatic mode), the declared-flags-only + no-shell properties,
  dry-run-first, and tests: `tests/test_web_runner.py` (12) — argv type mapping,
  unknown-key rejection, CLI-targeted argv, a real child-process stream asserting output +
  exit code, unknown-token stream, dry-run without executing, 400 unknown command, the 403
  traffic gate, launch returns a token, and stop of an unknown token. Suite 455 passed /
  6 skipped.
- Deliverables:
  - [x] `runner.py` (build_argv + async `Runner` + SSE stream + stop) — done.
  - [x] `/api/launch/dry-run`, `/api/launch`, `/api/launch/{token}/stream|stop` — done.
  - [x] Tests (pure argv, real-subprocess stream, endpoint gate) — done.
  - [ ] Launcher UI forms wired to these endpoints — Phase 1.
- Effectiveness (assessed 2026-09-21): effective — dry-run previews the exact command
  without traffic, the gate blocks unauthorized traffic tools, and a real child's output +
  exit code stream over SSE. HTTP-level SSE draining is validated live/in Phase 1 (reading
  an event-stream synchronously through TestClient is avoided; the Runner stream is tested
  directly).

### CC-UI-0012 — Frontend foundation: jinja2 + static assets + tab shell + SSE (Phase 0.2) (2026-09-21)
- Change: reworked `fuzzlab/web/app.py` from hand-rendered HTML f-strings to **jinja2
  templates** (`fuzzlab/web/templates/`: `base.html`, `index.html`, `run.html`,
  `not_found.html`; autoescaped) served alongside a **static asset pipeline**
  (`fuzzlab/web/static/app.css`, `app.js`) mounted at `/static`. The index is now a
  **tabbed shell** — Launcher / Proxy / Results / ML / Diagnostics — with all panels
  rendered server-side and a small vanilla-JS module toggling them (progressive
  enhancement: no-JS shows every panel). The Launcher tab previews every activity from the
  command-spec registry (CC-UI-0011) with gate pills; Results holds the existing runs
  dashboard; Proxy/ML/Diagnostics are stubs for Phases 2–4. Added `fuzzlab/web/sse.py`
  (`format_event`, `sse_response`) as the SSE plumbing for later live streams (first
  consumer: the Phase 0.3 runner). `jinja2` (already a declared `web` extra) is now used;
  FastAPI is imported at module scope so route `Request` annotations resolve. Templates and
  static files added to `[tool.setuptools.package-data]`.
- Impact (other components / project): UI-internal. No route/behavior change to the JSON
  API, no schema change, no traffic, and the read-only + loopback + no-auto-run invariants
  are unchanged (the only interactive form is still gated automatic mode). Sets up the
  Phase-1 launcher UI and the Phase-2/3/4 tabs.
- Risk (level; mitigation): low–medium — a rendering refactor of every panel. Mitigated by
  the unchanged launcher/results suites (13 tests: mode selection, 403-without-auth,
  injected-pipeline-not-run-on-load, loopback refusal, run-detail strings, empty-store
  no-create) plus new `tests/test_web_frontend.py` (10: static assets served, tab shell,
  activities preview, single-form invariant) and `tests/test_web_sse.py` (SSE formatting).
  Suite 443 passed / 6 skipped.
- Deliverables:
  - [x] jinja2 templates + `/static` pipeline; tab shell (5 tabs) — done.
  - [x] `fuzzlab/web/sse.py` + client `subscribe()` helper — done.
  - [x] Package-data for templates/static — done.
  - [x] Tests (frontend shell + SSE); existing web suites green — done.
  - [ ] Vendored charting lib (uPlot) — deferred to first use (Phase 4 diagnostics).
  - [ ] Launcher run controls (forms/dry-run/live output) — Phase 1 (needs the runner).
- Effectiveness (assessed 2026-09-21): effective — the panel renders as a tabbed shell with
  external CSS/JS, previews all activities from their parsers, and keeps every prior
  invariant; SSE plumbing is in place for the runner.

### CC-UI-0011 — Command-spec registry + `build_parser()` convention (Phase 0.1) (2026-09-21)
- Change: added `fuzzlab/web/commandspec.py` — a registry that introspects each launchable
  activity's own `argparse` parser into a machine-readable form schema
  (`OptionSpec`/`CommandSpec`: name, dest, type ∈ {bool,int,float,str,choice}, required,
  default, choices, multiple; plus per-command `sends_traffic`, `needs_authorized`,
  `destructive_gate`). The authorized/destructive gates are *derived* from the parser
  (presence of the flags), not restated. To supply the parsers without parsing, every tool
  now exposes a **`build_parser()`** returning its `ArgumentParser`; each `main()` delegates
  to it — a behavior-preserving refactor (see the per-component CC entries). This is the
  single-source-of-truth backbone for the Phase-1 launcher: a new tool flag appears in the
  UI automatically, with nothing hand-mirrored (PA-0001/PA-0003). Parsers are imported
  lazily and the registry survives a single tool's optional-dep import failure.
- Impact (other components / project): the launcher (Phase 1) renders controls from these
  specs. Touches the tool modules across CRAWL/AUD/FUZZ/MUT/PROXY/SESS + UI(report) to add
  `build_parser()` (CC-CRAWL-0006, CC-AUD-0014, CC-FUZZ-0018, CC-MUT-0007, CC-PROXY-0014,
  CC-SESS-0009). No CLI behavior, flags, or defaults change; no schema change; no traffic.
- Risk (level; mitigation): low — a refactor + a pure read-only introspection module.
  Mitigated by `tests/test_web_commandspec.py` (17 tests: type mapping in isolation,
  subparser recursion, long-flag naming, every activity builds + is JSON-serializable, the
  gate/traffic matrix, gates-derived-from-parser, defaults-read-from-parser-not-a-constant)
  and the unchanged full suite. Suite 433 passed / 6 skipped.
- Deliverables:
  - [x] `fuzzlab/web/commandspec.py` (introspection + registry) — done.
  - [x] `build_parser()` on all launchable tools; `main()` delegates — done.
  - [x] `tests/test_web_commandspec.py` — done.
  - [ ] Consume the spec in the launcher UI (Phase 1) — next.
- Effectiveness (assessed 2026-09-21): effective — the registry yields correct form schemas
  for all 10 activities from their real parsers, and the tests pin the mapping + the
  no-hand-mirror invariant.

### CC-UI-0010 — Web UI revamp implementation plan (design record) (2026-09-21)
- Change: added `docs/UI_REVAMP_PLAN.md` — the tracked design plan to take the read-only
  control panel to a full local control plane: (1) an activity launcher with per-tool
  flag forms, dry-run preview, and live output; (2) a proxy workbench (history, intercept
  edit/drop/forward, repeater, scope/match-replace); (3) a dedicated ML tab; (4) a
  TensorBoard-like diagnostics tab. Records the target tab architecture, the Phase-0
  foundations (jinja2 + vendored static assets + SSE; an argparse-introspecting command
  spec; a subprocess runner; a unified serve mode that hosts an in-process proxy for live
  interception), the honest exists-vs-needs-building split (most proxy/ML backends exist;
  time-series charts need a new `metric_series` table + per-step emitters), and how every
  new capability preserves the no-auto-run / loopback / authorized / read-only / redaction
  invariants.
- Impact (other components / project): design only — no code, no schema change. Scopes
  upcoming work across UI (#12), the intercepting proxy (#11 — a response-intercept hook),
  and core (#2 — a `metric_series` migration). New FR-UI entries and the two Phase-0
  decisions (UI-launches-tools-as-gated-subprocesses; unified-serve-in-process-proxy) will
  be recorded when Phase 0 lands.
- Risk (level; mitigation): none (documentation). The plan itself calls out the invariants
  each phase must preserve and the tests each ships with.
- Deliverables:
  - [x] `docs/UI_REVAMP_PLAN.md` recorded — done.
  - [ ] Phase 0 foundations (command spec, runner, frontend stack, unified serve) — next.
  - [ ] Phases 1–4 (launcher, proxy workbench, ML tab, diagnostics) — planned.
- Effectiveness (assessed 2026-09-21): effective as a design record — the plan is grounded
  in a full survey of the web/proxy/ML/instrumentation code and preserves the component's
  requirements (D11/D14/D15, NFR-UI-*).

### CC-UI-0009 — Reproducible evaluation report + `fuzzlab report` (T10.4) (2026-09-21)
- Change: added `fuzzlab/report/` — `build_report(store, run_id)` assembles a
  **deterministic** report from a stored run (run/config identity, target fingerprint,
  pipeline counts, confirmed findings, `run_metrics`, deployed models, and the active
  plugin set from migration 10), with every list stably sorted; `format_json` renders
  canonical (sorted-key) JSON for diffing, `format_text` a human summary. Wired as a
  read-only `fuzzlab report [--run latest|<id>] [--json]` command (dispatched from
  `fuzzlab/cli.py`).
- Impact (other components / project): the reproducibility artifact for Phase 10 — a run
  can be captured, diffed, and re-verified, and it records exactly what produced a result
  (config hash, feature/model versions, plugin set, schema version). Pure reads, no
  traffic; no schema change.
- Risk (level; mitigation): low — read-only, offline, deterministic. Mitigated by 6 tests
  (`tests/test_report.py`): captures run/target/counts/findings/metrics/models/plugins/
  reproducibility; canonical JSON is byte-identical across builds and valid; defaults to
  the latest run; empty store; text summary; and the `fuzzlab report` CLI (text + `--json`).
  Suite 381 passed / 4 skipped.
- Deliverables:
  - [x] `build_report` + `format_json`/`format_text` (T10.4) — done.
  - [x] `fuzzlab report` CLI dispatch — done.
  - [ ] Surface the report in the web panel — optional follow-up.
- Effectiveness (assessed 2026-09-21): effective in tests — the report renders
  deterministically over a run and names the versions/plugins that produced it; a live
  reproduce-a-run demonstration is part of the T10.6 exit.

### CC-UI-0008 — Panel surfaces advisory model scores (Phase 5) (2026-09-21)
- Change: `web/results.py::run_detail` now includes the latest `model` and the run's
  top advisory-scored candidates with their conformal flag/abstain/drop decision; the
  run-detail page renders a "Model scores (advisory)" card. Read-only.
- Impact (other components / project): the scores/triage the classifier writes
  (CC-ML-0003) are visible in the panel, clearly marked advisory (never findings).
- Risk (level; mitigation): low — read-only rendering. Mitigated by
  `tests/test_web_results.py::test_run_page_surfaces_model_scores`. Suite 192 passed / 2 skipped.
- Deliverables:
  - [x] `run_detail` model + scored candidates + decision; run-page card — done.
- Effectiveness (assessed 2026-09-21): effective — the run page shows scored candidates
  and their decision after a `--score` run.

### CC-UI-0007 — Web control panel: results review + full dashboard (D11) (2026-09-21)
- Change: built out the local web control panel beyond the Phase-0 launcher. Added
  `fuzzlab/web/results.py` (pure, store-backed `list_runs` / `run_detail` / `store_exists`)
  and expanded `fuzzlab/web/app.py` with a **runs dashboard** (index lists every run
  with its finding count), **run-detail** views (`GET /runs/{id}` HTML and
  `GET /api/runs/{id}` JSON) showing the score (TP/FP/FN/TN, precision/recall), the
  target fingerprint, dataset counts (candidates, negatives, evaluations, attempts,
  pages), the oracle findings table, and all run metrics, plus `GET /api/runs`. Manual
  mode now surfaces the selectable categories (D14) and the pre-wired commands use the
  `fuzzlab` CLI (crawl/audit/fuzz/auto). The panel is **read-only** over the store — it
  never creates the store file and never sends traffic (no-auto-run preserved).
- Impact (other components / project): turns the store into a reviewable dashboard —
  the results of any crawl/audit/fuzz/auto run (findings, negatives, fingerprint,
  score, request metrics) are browsable locally. Reads the store written by every
  other component; no schema change.
- Risk (level; mitigation): low — read-only and loopback-only (serve() refuses
  non-loopback). Store opened only when the file already exists (no accidental
  creation / no cwd pollution). Mitigated by tests: the existing launcher tests
  (no-auto-run, mode selection, 403 without authorization, injected pipeline) plus
  `tests/test_web_results.py` (results functions; `/api/runs`; run detail + 404; the
  run HTML renders findings + score; index runs table; missing-store shows no runs and
  creates no file). Suite 160 passed / 2 skipped.
- Deliverables:
  - [x] `web/results.py` (list_runs / run_detail) — done.
  - [x] Dashboard + run-detail HTML + `/api/runs[/{id}]` — done.
  - [x] Manual category surfacing; CLI-based pre-wired commands — done.
  - [x] Tests (results review; read-only/no-create invariant) — done.
  - [ ] Live use on the host (`fuzzlab web`, review real runs) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests and a rendered preview — runs
  list, run detail shows the score/fingerprint/findings/negatives/metrics, and the
  panel stays read-only and loopback-only.

### CC-UI-0006 — No-ground-truth fail-safe for automatic runs (spec) (2026-09-21)
- Change: added FR-UI-nogt (D15). An automatic run against a target with no
  ground-truth contract must not auto-select or test everything; it requires an
  explicit category selection, fails loudly if none is given, runs unscored
  (findings shown, no TP/FP/FN), and keeps all safety gates on. Complements D14
  (which covers the known-lab and manual cases). Spec only — no code.
- Impact (other components / project): governs automatic runs on external
  validation labs / unknown targets; the integration harness must skip scoring
  without ground truth (and never fabricate a score); ties to D10 external
  validation. Recorded as D15 + a cross-cutting safety principle in
  `DECISIONS_AND_ROADMAP.md` and `ARCHITECTURE.md`; `oracle-confirmation.md` and
  `PHASE_2_PLAN.md` (T2.10) updated.
- Risk (level; mitigation): this change reduces risk — it prevents a surprise
  "test everything" or a silent no-op against an unknown target. Residual risk is a
  missing/instructive error message; mitigated by fail-loud with clear guidance.
- Deliverables:
  - [x] FR-UI-nogt + D15 + cross-cutting principle recorded — done.
  - [ ] Implement: detect no ground truth; require categories; unscored run; gates — todo (Phase 2, T2.10).
- Effectiveness (assessed or pending): pending — spec. Judged when an automatic run
  on a no-ground-truth target fails loudly without `--categories` and runs unscored
  with them, gates on.

### CC-UI-0005 — Injection-category selection by run mode (spec) (2026-09-21)
- Change: added FR-UI-categories (D14) — automatic mode auto-selects injection
  categories from the lab's ground truth; manual mode presents a category selector
  and passes a `--categories` flag to the tools. The selection scopes the auditor's
  rules, payload sources, and which oracle `ConfirmationStrategy` classes run.
  Spec only — no code.
- Impact (other components / project): threads category scope from the launcher
  through the auditor (#5), payload catalogs (#6), and the oracle (#7,
  `architecture/oracle-confirmation.md`). Recorded as D14; no store-schema change.
- Risk (level; mitigation): low — a selection/scoping control; the default is
  conservative (automatic = exactly the ground-truth set; manual = only what the
  user picks). No-auto-run (D11) unchanged.
- Deliverables:
  - [x] FR-UI-categories + D14 recorded; oracle doc updated — done.
  - [ ] Implement the selector + `--categories` flag + ground-truth derivation — todo (Phase 2).
- Effectiveness (assessed or pending): pending — spec. Judged when the selector and
  flag land and a manual run tests only the chosen categories while an automatic lab
  run tests exactly the ground-truth set.

### CC-UI-0004 — Minimal web launcher + integration harness (2026-09-21)
- Change: built the Phase 0 minimal local web launcher (`fuzzlab/web/app.py`,
  FastAPI): a control panel that shows target/scope/mode and offers **automatic**
  vs **manual**, sending nothing to the target until the user acts; `serve()`
  binds to loopback only and refuses a non-loopback host. Automatic mode is gated
  on `authorized` and runs an injected pipeline callable. Added a `fuzzlab` CLI
  entry point (`web`, `crawl`, `audit`, `fuzz`, `build-db`, `version`) that also
  sends nothing on its own. Built the integration harness that automatic mode
  drives (T0.7): `fuzzlab/harness/scoring.py` (TP/FP/TN/FN + precision/recall/F1/
  MCC, matching by case key) and `integration.py` (`assert_known_vulns` reads the
  oracle's findings, scores against the ground-truth contract, records
  `run_metrics`). Realizes Phase 0 T0.9 and T0.7.
- Impact (other components / project): gives the project its no-auto-run entry
  point (D11) and its assert-known-vulns evaluation. The harness reads LAB's
  ground-truth contract (CC-LAB-0002) and the oracle's `finding` rows (self-
  describing via CC-CORE-0003). The pipeline runner is injected, so the crawler →
  auditor → fuzzer wiring drops in once the tools write to the store (T0.8).
- Risk (level; mitigation): low–medium. A local web server is a surface; mitigated
  by loopback-only binding (asserted, with a non-loopback refusal), the
  authorization gate on automatic mode, and the invariant that loading the panel
  runs nothing (a test asserts the injected pipeline is not called on GET). Harness
  correctness is covered by scoring tests (perfect run, misses, false alarms,
  wrong-class-on-right-param, and a store round-trip).
- Deliverables:
  - [x] Minimal web control panel with automatic/manual selection (T0.9) — done.
  - [x] Loopback-only serve with non-loopback refusal (T0.9) — done.
  - [x] `fuzzlab` CLI entry point + headless tool passthrough — done.
  - [x] Integration harness: scoring + assert-known-vulns + run_metrics (T0.7) — done.
  - [x] Web (6) + harness (5) tests passing — done.
  - [ ] Wire the real crawler→auditor→fuzzer pipeline into automatic mode — todo (needs T0.8).
  - [ ] Full dashboard (live runs, results tables) — todo (later UI phase).
- Effectiveness (assessed 2026-09-21): effective — panel offers both modes and
  stays idle on load; automatic mode is blocked without authorization and runs the
  injected pipeline only on explicit POST; harness scores a seeded store run as a
  pass with correct metrics. Real-pipeline wiring pending T0.8.

### CC-UI-0003 — Primary UI is a local web app, not a `textual` TUI (2026-09-21)
- Change: adopt decision D11 — the primary interface becomes a **local web
  application** (control panel + dashboard on localhost) instead of a `textual`
  TUI. The no-auto-run launcher (CC-UI-0002) now lives on the web page; the
  `textual` TUI is dropped as the primary UI. A plain CLI entry point per tool is
  kept for headless/automation use (FR-UI-cli). Datasette stays for deep store
  exploration. Adds NFR-UI-localhost (loopback-only, never exposed, separate from
  the target). Supersedes FR-UI-1 (was a `textual` TUI) and the TUI parts of
  CC-UI-0001/CC-UI-0002.
- Impact (other components / project): confined to this component and the docs —
  `DECISIONS_AND_ROADMAP.md` (new D11; Phase 6 UI line; deferred-list wording),
  `ARCHITECTURE.md` (component map, component #12, no change to the store
  contract), and `PHASE_0_PLAN.md` (T0.9 becomes a minimal local web panel). No
  other component's interface changes; the web app remains a `core/` store reader
  that orchestrates the tools in automatic mode. Reason: results and output are far
  easier to review in a browser, and it composes with the already-planned Datasette.
- Risk (level; mitigation): low–medium. A local web server is a new surface;
  mitigated by binding to loopback only, never exposing it, and serving it
  separately from the vulnerable target (different origin/port; never in the
  target's web root) so the control plane is never confused with, or an attack
  path into, the system under test. The no-auto-run guarantee is unchanged.
- Risk justification (accepted): a web app is more implementation work than a TUI;
  accepted for far better result review and reuse of the Datasette web view. Exact
  stack is deferred to build time.
- Deliverables:
  - [ ] Minimal local web control panel hosting the automatic/manual launcher — todo (Phase 0 T0.9).
  - [ ] Loopback-only binding, separate origin/port from the target — todo (Phase 0 T0.9).
  - [ ] Plain CLI entry point per tool (headless) — todo (Phase 0).
  - [ ] Full web dashboard (live runs/interception/results) — todo (later UI phase).
  - [ ] Confirm web stack (FastAPI/Flask + frontend; Datasette embed vs link) — todo.
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  results being reviewable in the browser and the panel being reachable only on
  localhost, with the no-auto-run guarantee intact.

### CC-UI-0002 — Launcher with run-mode selection; no auto-run (2026-09-21)
- Change: add a launcher as a UI subcomponent (FR-UI-launcher, NFR-UI-no-auto-run).
  Bringing up the lab no longer starts tool traffic; instead a UI offers two run
  modes — automatic (run the pipeline + integration harness against the lab) or
  manual (leave the lab up and expose the tools for hand-driven use) — and nothing
  is sent to the target until the user chooses. A minimal launcher lands in
  Phase 0 (T0.9); the full `textual` TUI elaborates it later.
- Impact (other components / project): establishes a project-wide "no auto-run"
  principle (recorded in `DECISIONS_AND_ROADMAP.md` cross-cutting principles,
  `ARCHITECTURE.md` integration model + Security-and-safety, and `PHASE_0_PLAN.md`
  Goal/T0.7/T0.9/exit criterion). Gives this component an orchestration role in
  automatic mode (it invokes crawler → auditor → fuzzer → harness), beyond
  read-only diagnostics; those tools still write their own results. No change to
  the store contract or to other components' interfaces.
- Risk (level; mitigation): low, and safety-reducing on balance — the change
  removes an implicit auto-run and puts the user in control of when tools touch
  the target. Residual risk is a mode selector that mis-wires the target/store in
  manual mode; mitigated by pre-wiring from the same `core/` config the automatic
  path uses, and by `--dry-run`.
- Deliverables:
  - [ ] Minimal launcher with automatic/manual selection — todo (Phase 0 T0.9).
  - [ ] Manual mode: print pre-wired ready-to-run commands / interactive shell — todo (Phase 0 T0.9).
  - [ ] Automatic mode: invoke the pipeline + integration harness — todo (Phase 0 T0.7/T0.9).
  - [ ] Full launcher/mode UI folded into the `textual` TUI — todo (later).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  bring-up stopping at the launcher with zero requests to the target until a mode
  is chosen, and by both modes behaving as specified.

### CC-UI-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented;
  today's observability is per-tool stdout plus the root `CHANGELOG.md`/
  `ERROR_LOG.md`.
- Impact (other components / project): read-only over the store, so it adds no
  hard dependency for any tool; it relies on `core/`'s store and structured
  logging existing. Adds a `run_metrics` table to the store contract. Realizes the
  research-platform diagnostics posture (D2) used to verify functionality and find
  bugs.
- Risk (level; mitigation): low — read-only and off the data path. Main risk is
  rendering secrets; mitigated by redaction-on-write in `core/` and a
  render-redacted-only rule here.
- Deliverables:
  - [ ] `textual` TUI for live runs/interception — todo.
  - [ ] Datasette-over-the-store exploration — todo.
  - [ ] `run_metrics` table — todo.
  - [ ] Structured audit/debug logs (`run_id`/`tool`/`identity`/`flow_id`) — todo.
  - [ ] `--dry-run` mode — todo.
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  whether a live run is legible in the TUI and bugs are locatable from the store
  and logs without instrumenting each tool by hand.
