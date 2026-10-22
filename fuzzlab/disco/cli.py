"""``fuzzlab disco <capture|synth|generate|run>`` -- the behavioural discovery and
contract-fuzzing pipeline (D70; see `fuzzlab.disco`).

* ``capture`` (sends traffic: ``--authorized``) -- the capture proxy plus the guarded
  browser explore the target; writes ``<out>/capture.jsonl`` (and ``actions.jsonl``,
  ``explore.json``). A directory that already holds a capture is refused (PA-0450).
* ``synth`` (no traffic) -- one or more captures -> an OpenAPI-shaped inventory.
* ``generate`` (no target traffic) -- inventory -> contract. Only with ``--llm`` (the
  explicit opt-in NFR-MUT-offline requires) does it send the inventory's *schemas* to
  the LLM API for test cases; without it the contract holds the endpoints only.
* ``run`` (sends traffic: ``--authorized``) -- execute a contract; writes the results
  ledger (one JSON line per case, as it completes) and prints the verdict counts.

Every usage check runs before any side effect (PA-0079): a missing ``--authorized``, an
existing output, an invalid contract all exit 2 having written nothing. ``--dry-run``
prints what would run and sends nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

AUTH_PROFILE_HELP = ("ID:KIND[:REF], repeatable; KIND is none|bearer|basic|cookie|header|"
                     "storage_state; REF is keyring:<identity>, env:<NAME> or a storage-"
                     "state file -- never the secret itself (D12). Default: anon:none")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fuzzlab disco",
                                description="behavioural discovery and contract fuzzing")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("capture", help="explore the target through the capture proxy")
    c.add_argument("--start", required=True, help="the start URL (in scope)")
    c.add_argument("--scope", action="append", default=[], metavar="URL",
                   help="another in-scope origin (repeatable); the start URL's is always in")
    c.add_argument("--out", required=True, help="the run directory (a new capture)")
    c.add_argument("--profile", default="anon", help="auth profile name stamped on records")
    c.add_argument("--storage-state", help="a Playwright storage-state file to start "
                   "authenticated (kept to in-scope origins)")
    c.add_argument("--max-states", type=int, default=60)
    c.add_argument("--max-harvest", type=int, default=500,
                   help="loads of linked, never-requested in-scope URLs after exploring")
    c.add_argument("--workers", type=int, default=1,
                   help="browsers exploring at once (1-8; each is a Chromium)")
    c.add_argument("--max-actions", type=int, default=400)
    c.add_argument("--deadline", type=float, default=900.0, help="seconds")
    c.add_argument("--deny", action="append", default=[], metavar="WORD",
                   help="never act on an element whose label/name holds WORD (repeatable)")
    c.add_argument("--keep-tag", action="store_true",
                   help="forward x-disco-action to the target (default: stripped)")
    c.add_argument("--upstream-insecure", action="store_true",
                   help="accept the target's self-signed TLS certificate (lab)")
    c.add_argument("--authorized", action="store_true",
                   help="confirm the target is yours to test (required: sends traffic)")
    c.add_argument("--dry-run", action="store_true", help="print the plan; send nothing")
    from fuzzlab.core.storepath import store_help
    c.add_argument("--store", default=None,
                   help=store_help("record the capture's trace live into this store, as "
                                   "a new run (FR-CRAWL-30); off unless given"))
    c.add_argument("--record", action="store_true",
                   help="record the trace live into the default store (see --store)")

    s = sub.add_parser("synth", help="captures -> an OpenAPI-shaped inventory")
    s.add_argument("--capture", action="append", required=True, metavar="FILE")
    s.add_argument("--out", required=True, help="inventory JSON path (must not exist)")

    g = sub.add_parser("generate", help="inventory -> contract with LLM test cases")
    g.add_argument("--inventory", required=True)
    g.add_argument("--out", required=True, help="contract path (.yaml/.json; must not exist)")
    g.add_argument("--run-id")
    g.add_argument("--base-url")
    g.add_argument("--scope", action="append", default=[], metavar="URL_OR_HOSTPORT")
    g.add_argument("--auth-profile", action="append", default=[], metavar="SPEC",
                   help=AUTH_PROFILE_HELP)
    g.add_argument("--max-cases", type=int, default=12)
    g.add_argument("--endpoint", action="append", default=[], metavar="ID",
                   help="only these endpoint ids (repeatable)")
    g.add_argument("--model", default=None, help="the LLM model id")
    g.add_argument("--api-key-identity", metavar="NAME",
                   help="read the API key from the keyring (host api.anthropic.com, this "
                        "identity) instead of the SDK's own resolution")
    g.add_argument("--llm", action="store_true",
                   help="opt in: send the inventory's schemas to the LLM API for test cases "
                        "(default: endpoints only, nothing leaves the machine)")

    e = sub.add_parser("ede", help="excessive data exposure: replay a run's JSON answers "
                       "with one field removed and compare the page")
    e.add_argument("--run", required=True, help="a disco run directory (its capture.jsonl)")
    e.add_argument("--scope", action="append", required=True, metavar="URL",
                   help="an in-scope origin (repeatable): only its pages are tested")
    e.add_argument("--max-pages", type=int, default=20)
    e.add_argument("--deadline", type=float, default=900.0, help="seconds")
    e.add_argument("--authorized", action="store_true",
                   help="confirm the target is yours to test (required: pages and assets "
                        "load from it; the replayed API answers do not)")
    e.add_argument("--dry-run", action="store_true", help="print the plan; send nothing")

    r = sub.add_parser("run", help="execute a contract")
    r.add_argument("--contract", required=True)
    r.add_argument("--results", required=True, help="results ledger (JSONL; must not exist)")
    r.add_argument("--evidence", help="directory for redacted request/response evidence")
    r.add_argument("--allow-destructive", action="store_true",
                   help="run cases the contract marks destructive")
    r.add_argument("--allow-reset-hook", action="store_true",
                   help="let the contract's reset_hook command run around destructive cases")
    r.add_argument("--authorized", action="store_true",
                   help="confirm the target is yours to test (required: sends traffic)")
    r.add_argument("--dry-run", action="store_true", help="print the plan; send nothing")
    return p


def _fail(msg: str) -> int:
    print(f"fuzzlab disco: {msg}", file=sys.stderr)
    return 2


def parse_auth_profile(spec: str) -> dict:
    """``ID:KIND[:REF]`` -> an auth profile (ValueError when malformed)."""
    from fuzzlab.disco.contract import AUTH_KINDS
    parts = spec.split(":", 2)
    if len(parts) < 2 or not parts[0] or parts[1] not in AUTH_KINDS:
        raise ValueError(f"auth profile {spec!r}: expected ID:KIND[:REF]")
    prof = {"id": parts[0], "kind": parts[1]}
    if len(parts) == 3 and parts[2]:
        prof["ref"] = parts[2]
    return prof


#: What a capture run writes into ``--out`` that its consumers read back as this run's:
#: the import (`store_adapter.import_disco`, `observe.observe_disco`) and the live trace
#: (`disco.livetrace`). A directory holding any of them is refused before anything runs
#: (PA-0450, BUG-0525): the explorer appends to its log, so an earlier run's lines would
#: be attributed to this one. ``capture.jsonl`` is first: its own message.
RUN_FILES = ("capture.jsonl", "actions.jsonl", "capture.jsonl.stats.json", "explore.json",
             "script_segments.json")


def _capture(ns) -> int:
    from fuzzlab.core import storepath
    from fuzzlab.core.urls import canonical_origin
    out = Path(ns.out)
    scope = [ns.start, *ns.scope]
    if any(canonical_origin(u) is None for u in scope):
        return _fail("--start and --scope take absolute http(s) URLs")
    if (out / "capture.jsonl").exists():
        return _fail(f"{out} already holds a capture: use a new directory (PA-0450)")
    stale = [name for name in RUN_FILES[1:] if (out / name).exists()]
    if stale:
        return _fail(f"{out} already holds {', '.join(stale)} from an earlier run: use a "
                     f"new directory (PA-0450, BUG-0525)")
    state = None
    if ns.storage_state:
        try:
            state = json.loads(Path(ns.storage_state).read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError) as exc:
            return _fail(f"--storage-state: {type(exc).__name__}")
        if not isinstance(state, dict):
            return _fail("--storage-state is not a storage-state object")
    recording = None
    if ns.store is not None or ns.record:
        try:
            recording = storepath.resolve(ns.store)
            storepath.check_writable(recording)
        except storepath.StorePathError as exc:
            return _fail(f"--store: {exc}")
    if ns.dry_run:
        print("DRY RUN -- disco capture: plans the action, sends nothing.")
        print(f"  start: {ns.start}\n  scope: {sorted({canonical_origin(u) for u in scope})}")
        print(f"  out: {out / 'capture.jsonl'}\n  sends_traffic: True\n"
              f"  needs_authorized: True\n  would_execute: {bool(ns.authorized)}")
        print(f"  trace: {recording.path} (live, a new run)" if recording is not None
              else "  trace: off (--store / --record to record it live)")
        return 0
    if not ns.authorized:
        return _fail("capture sends traffic: pass --authorized (lab-only, D11)")
    from fuzzlab.disco.explore import MAX_WORKERS, Explorer, ExploreOptions
    from fuzzlab.disco.proxyproc import CaptureProxy
    if not 1 <= ns.workers <= MAX_WORKERS:
        return _fail(f"--workers must be 1..{MAX_WORKERS}")
    opts = ExploreOptions(max_states=ns.max_states, max_actions=ns.max_actions,
                          workers=ns.workers, max_harvest=ns.max_harvest,
                          deadline_s=ns.deadline, deny=tuple(ns.deny))
    store = run_id = live = None
    if recording is not None:
        from urllib.parse import urlsplit

        from fuzzlab.core.store import Store
        store = Store(recording.path)
        run_id = store.start_run("disco", urlsplit(ns.start).netloc or ns.start)
    proxy = CaptureProxy(scope, out=out / "capture.jsonl", keep_tag=ns.keep_tag,
                         upstream_insecure=ns.upstream_insecure, profile=ns.profile)
    status, problem = "aborted", None
    try:
        try:
            proxy.start()
            try:
                if store is not None:
                    from fuzzlab.disco.livetrace import LiveTrace
                    live = LiveTrace(out, recording.path, run_id).start()
                report = Explorer(ns.start, scope_urls=scope, proxy=proxy.endpoint,
                                  options=opts, storage_state=state,
                                  actions_log=out / "actions.jsonl").run()
            finally:
                proxy.stop()
            doc = {"explore": report.__dict__, "proxy": proxy.stats()}
            (out / "explore.json").write_text(json.dumps(doc, indent=1, sort_keys=True))
            status = "complete"
        except BaseException as exc:
            status = f"aborted: {type(exc).__name__}"
            if store is not None:
                store.mark_aborted(run_id, exc)
            raise
        finally:
            # after the proxy stopped (its last records and stats are written) and after
            # explore.json; never raises (FR-CRAWL-30)
            if live is not None:
                problem = live.stop(status)
                if problem:
                    print(f"fuzzlab disco: live trace: {problem}", file=sys.stderr)
    finally:
        if store is not None:
            store.close()
    print(f"disco capture: {report.states} states, {report.actions} actions "
          f"({report.submissions} submissions, {report.submissions_sent} of them sent "
          f"the form's values; {report.perturbations} perturbations), "
          f"{doc['proxy'].get('recorded', 0)} exchanges recorded -> {out / 'capture.jsonl'}")
    blocked = {**report.out_of_scope}
    for host, n in (doc["proxy"].get("blocked") or {}).items():
        blocked[host] = blocked.get(host, 0) + n
    if blocked:
        print(f"  refused out of scope: {dict(sorted(blocked.items()))}")
    if report.session_host_unreached:
        # SP-74 (BUG-0559): never sent, so never explored as the identity's
        print(f"  refused, the session's cookies do not reach the host (start on that "
              f"host if it is this app's): "
              f"{dict(sorted(report.session_host_unreached.items()))}")
    if report.harvest_found:
        print(f"  harvest: {report.harvest_found} linked URL(s) never requested found, "
              f"{report.harvest_loads} loaded, {report.harvest_states} state(s) from them")
    if report.script_routes or report.script_route_seeds:
        print(f"  routes from the app's scripts: {report.script_routes} route(s), "
              f"{report.script_route_seeds} route-query seed(s), queued for the harvest")
    if report.scripts_too_large:
        print(f"  scripts too large to scan for routes: {report.scripts_too_large}")
    if report.harvest_aliases:
        print(f"  harvest loads answered with a document already known under another "
              f"path (not explored again): {report.harvest_aliases}")
    if report.captcha_submissions:
        print(f"  CAPTCHA forms sent with a filler answer (D71): "
              f"{report.captcha_submissions}")
    if report.refused:
        print(f"  never acted on: {dict(sorted(report.refused.items()))}")
    if report.budget_hit:
        print(f"  stopped by budget: {report.budget_hit}")
    if live is not None:
        st = live.stats
        print(f"  trace: run {run_id} in {recording.path}: {int(st.get('written', 0))} "
              f"events written, {int(st.get('dropped', 0))} dropped"
              + (f" -- {problem}" if problem else ""))
        if problem and problem.startswith("timeout"):
            return 1
    return 0


def _synth(ns) -> int:
    from fuzzlab.disco.capture import read_capture
    from fuzzlab.disco.synth import synthesize
    out = Path(ns.out)
    if out.exists():
        return _fail(f"{out} exists (PA-0450)")
    records, quarantined = [], 0
    for path in ns.capture:
        try:
            read = read_capture(path)
        except FileNotFoundError:
            return _fail(f"no capture at {path}")
        records += read.records
        quarantined += read.quarantined
    inv = synthesize(records, captures=list(ns.capture), quarantined=quarantined)
    out.write_text(json.dumps(inv, indent=1, sort_keys=True), encoding="utf-8")
    x = inv["x-disco"]
    print(f"disco synth: {x['endpoints']} endpoints from {x['endpoint_records']} exchanges "
          f"({quarantined} malformed lines quarantined, {len(x['candidates'])} JS "
          f"candidates) -> {out}")
    return 0


def _generate(ns) -> int:
    import yaml

    from fuzzlab.disco.generate import (DEFAULT_MODEL, AnthropicProvider, build_contract,
                                        default_run_id)
    out = Path(ns.out)
    if out.exists():
        return _fail(f"{out} exists (PA-0450)")
    try:
        inventory = json.loads(Path(ns.inventory).read_text(encoding="utf-8"))
        profiles = [parse_auth_profile(s) for s in ns.auth_profile] or None
    except (OSError, ValueError, RecursionError) as exc:
        return _fail(f"{type(exc).__name__}: {str(exc)[:200]}")
    if not isinstance(inventory, dict) or "paths" not in inventory:
        return _fail("--inventory is not a disco inventory")
    provider = None
    if ns.llm:
        api_key = None
        if ns.api_key_identity:
            from fuzzlab.core.credentials import CredentialStore
            cred = CredentialStore().get("api.anthropic.com", ns.api_key_identity)
            if cred is None:
                return _fail("no API key stored for that identity")
            api_key = cred.password
        provider = AnthropicProvider(ns.model or DEFAULT_MODEL, api_key=api_key)
        print("disco generate: sending the inventory's schemas (no captured header values) "
              "to the LLM API, one request per endpoint", file=sys.stderr)
    try:
        contract, report = build_contract(inventory, provider, run_id=ns.run_id or default_run_id(),
                                          base_url=ns.base_url, scope=ns.scope or None,
                                          auth_profiles=profiles, max_cases=ns.max_cases,
                                          only=set(ns.endpoint) or None)
    except ValueError as exc:
        return _fail(str(exc))
    from fuzzlab.disco.contract import validate
    probs = validate(contract)
    if probs:
        return _fail("the assembled contract is invalid:\n  " + "\n  ".join(probs))
    text = json.dumps(contract, indent=1) if out.suffix.lower() == ".json" else \
        yaml.safe_dump(contract, sort_keys=False, allow_unicode=True)
    out.write_text(text, encoding="utf-8")
    print(f"disco generate: {len(contract['endpoints'])} endpoints, {report.kept} test cases "
          f"from {report.asked} requests -> {out}")
    if report.dropped:
        print(f"  dropped: {dict(sorted(report.dropped.items()))}")
    if report.refused:
        print(f"  declined by the model: {dict(sorted(report.refused.items()))}")
    return 0


def _run(ns) -> int:
    from fuzzlab.disco.contract import ContractError, load_contract
    results = Path(ns.results)
    if results.exists():
        return _fail(f"{results} exists (PA-0450)")
    try:
        contract = load_contract(ns.contract)
    except ContractError as exc:
        return _fail(str(exc))
    if ns.dry_run:
        cases = contract.doc["test_cases"]
        destructive = sum(1 for c in cases if c["safety"].get("destructive"))
        print("DRY RUN -- disco run: plans the action, sends nothing.")
        print(f"  contract: {ns.contract} (run {contract.run_id})\n"
              f"  target: {contract.base_url}\n  scope: {sorted(contract.allowed_origins)}\n"
              f"  cases: {len(cases)} ({destructive} destructive"
              f"{'' if ns.allow_destructive else ', skipped'})\n"
              f"  sends_traffic: True\n  needs_authorized: True\n"
              f"  would_execute: {bool(ns.authorized)}")
        return 0
    if not ns.authorized:
        return _fail("run sends traffic: pass --authorized (lab-only, D11)")
    from fuzzlab.disco.runner import Runner, TargetUnreachable, summary
    runner = Runner(contract, authorized=True, allow_destructive=ns.allow_destructive,
                    allow_reset_hook=ns.allow_reset_hook,
                    evidence_dir=Path(ns.evidence) if ns.evidence else None)
    results.parent.mkdir(parents=True, exist_ok=True)
    with open(results, "x", encoding="utf-8") as fh:
        def write(result: dict) -> None:
            fh.write(json.dumps(result, sort_keys=True) + "\n")
            fh.flush()
        try:
            runner.run(on_result=write)
        except TargetUnreachable as exc:
            print(f"disco run: stopped, the target cannot be reached ({exc}); "
                  f"{len(runner.results)} results written", file=sys.stderr)
            return 1
    counts = summary(runner.results)
    print(f"disco run: {len(runner.results)} cases: {counts} -> {results}")
    return 0


def _ede(ns) -> int:
    from fuzzlab.core.urls import canonical_origin
    from fuzzlab.disco.capture import lost_action_ids, read_capture
    from fuzzlab.disco.ede import EdeRunner, write_report
    run = Path(ns.run)
    if any(canonical_origin(u) is None for u in ns.scope):
        return _fail("--scope takes absolute http(s) URLs")
    if ns.max_pages < 1:
        return _fail("--max-pages must be at least 1")
    out = run / "ede.json"
    if out.exists():
        return _fail(f"{out} exists (PA-0450)")
    try:
        records = read_capture(run / "capture.jsonl").records
    except FileNotFoundError:
        return _fail(f"{run} holds no capture.jsonl")
    # FR-CRAWL-41 (D'): no answer of a known-lost window is replayed or tested
    runner = EdeRunner(records, scope_urls=ns.scope, max_pages=ns.max_pages,
                       deadline_s=ns.deadline, lost_actions=lost_action_ids(run))
    if ns.dry_run:
        print("DRY RUN -- disco ede: plans the test, sends nothing.")
        print(f"  pages: {len(runner.pages)}  replayable answers: {len(runner.replay)}\n"
              f"  scope: {sorted({canonical_origin(u) for u in ns.scope})}\n"
              f"  sends_traffic: True (pages and assets; never the replayed answers)\n"
              f"  needs_authorized: True\n  would_execute: {bool(ns.authorized)}")
        return 0
    if not ns.authorized:
        return _fail("ede loads the target's pages: pass --authorized (lab-only, D11)")
    report = runner.run()
    write_report(report, out)
    print(f"disco ede: {report.pages} pages ({report.pages_skipped_nondeterministic} "
          f"non-deterministic, {report.pages_failed} failed), {report.answers} answers, "
          f"{report.fields_tested} fields tested, {report.fields_unused} unused at load "
          f"({sum(f['sensitive_name'] for f in report.findings)} with a sensitive name) "
          f"-> {out}")
    if report.budget_hit:
        print(f"  stopped by budget: {report.budget_hit}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ns = build_parser().parse_args(argv)
    return {"capture": _capture, "synth": _synth, "generate": _generate, "run": _run,
            "ede": _ede}[ns.cmd](ns)


if __name__ == "__main__":
    sys.exit(main())
