# BUG-0310 — The external labs' exposure checks failed open (a network-mode denylist, engine errors read as "clean")

- Date: 2026-10-15
- Status: fixed (CC-LAB-0300, commit e74fba8; CC-CORE-0300)
- ERROR_LOG: the 2026-10-15 entry "the loopback exposure checks failed open". Rule:
  PA-0310.
- Severity: high for safety. A compose file or engine state that put a deliberately
  vulnerable app in the host's network namespace would have been reported "loopback
  only" by the pre-flight, the post-boot check and `status`. No run was affected: both
  fixtures use bridge networking, and the defect was found in review before merge.

## Description
The external lab fixtures (FR-LAB-300/301) guard their loopback-only property in three
places: a pre-flight of the resolved compose config (`config_problems`), a post-boot
inspection of the running project (`exposure_problems`/`check_exposure`), and the shell
lifecycle (`extctl.sh`). As first committed (575962e), each guard enumerated the bad
cases it knew instead of allowing only the good ones, and treated "the engine could not
answer" as "nothing wrong":

- `config_problems` refused only `network_mode: host`, `container:` and an unknown
  `service:`; podman's `ns:/proc/1/ns/net`, `slirp4netns:allow_host_loopback=true`,
  `pasta`, and a top-level network declared `{name: host, external: true}` all passed.
- `exposure_problems` refused only `NetworkMode == "host"`; under `ns:` nothing is
  published, so the published-port set was empty and the host LISTEN table was never
  consulted.
- It merged the two inspect port sources with `setdefault`, so a non-loopback binding
  present only in `NetworkSettings.Ports` for a key also in `HostConfig.PortBindings`
  was never judged.
- `check_exposure` failed closed only for `ExternalLabError`/`ValueError`; a missing
  engine, a timeout or a procutil error escaped as a traceback (the shell still failed,
  the API did not).
- `extctl.sh`'s `_leftovers` read an engine error as "no containers left" (`down` exit
  0), `status` read it as "not running", and the exposed-stack teardown never checked
  that it worked.

## Where encountered
Code review round 1 of CC-LAB-0300 (reviewer A, findings A1-A5), each reproduced
in-process by calling the functions on synthetic configs and inspect shapes (no engine).

## What it caused to fail
Nothing at run time (both shipped compose files are bridge-networked, so every check
passed for the right reason). The guards' claim in NFR-LAB-safety ("bound to localhost,
checked at boot") was false for a host-namespace container under podman, for an
external host network, and whenever the engine errored.

## What the bug was identified to be
Safety checks over an external system's state (a container engine) that (1) used a
denylist of known-bad modes, and (2) mapped "could not determine" to "safe".

## Root cause analysis
Five whys:
1. Why did `ns:/proc/1/ns/net` pass? The check listed `host` as the only bad mode.
2. Why only `host`? It was modelled on docker's vocabulary, the engine in front of the
   author; podman's modes and compose's external networks were not enumerated.
3. Why did an enumeration miss them? Any enumeration of an external system's bad states
   is open-ended: engines add modes, and a mode string is not the property that matters
   (whether the container shares the host's network namespace).
4. Why did engine errors read as clean? The helpers returned the engine's empty output
   on failure (`$(cmd 2>/dev/null)` is empty either way), and the Python side caught a
   narrow exception list, so "no answer" and "no problem" were indistinguishable.
5. Why was neither caught by the tests? The synthetic offenders were drawn from the same
   enumeration as the check (docker's `host`, wildcard IPs), and no stub engine ever
   failed.

**Root cause:** the loopback guards for an external engine were written as
enumerations of known-bad states, with "no answer" defaulting to "safe", and their
offenders were drawn from the same enumeration, so nothing tested the cases the
enumeration missed.

## Corrective action
Commit e74fba8 (CC-LAB-0300 "Code review round 1"; CC-CORE-0300):
- an allowlist of network modes in the pre-flight (`none`/`bridge`/`default`/
  `service:<own service>`; external or host-driver networks refused) and in the
  post-check (bridge/default/none, a `<project>_` network, a project container's
  namespace);
- an engine-agnostic comparison of each container's network namespace (`State.Pid` →
  `procutil.netns_of`) with the host's (`procutil.host_netns`), whatever the engine calls
  its mode;
- both inspect port sources combined; every engine/OS/timeout/procutil error and a
  non-list inspect result are problems;
- `_leftovers` counts an engine error as leftovers (`down` exit 1), `status` exits 2 on
  an engine error, and an exposed stack that survives its teardown is reported loudly.
- Synthetic offenders for each missed mode and shape, a raising engine runner, failing
  stub engines; the mutation check kills each of these mechanisms (CC-LAB-0300).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for the same bug or root cause:
- **BUG-0130 / PA-0130** (a launched server bound 0.0.0.0; "the runtime check is
  authoritative, the source rules are lints"). Same safety property, same layer
  (runtime exposure check). PA-0130 covers servers launched through `procutil`, whose
  sockets are read from `/proc`; it does not speak to a container engine's network modes.
- **BUG-0057 / PA-0059(1)** ("never trust a wrapped compose command's own exit code;
  check real post-state"). Same family: PA-0059(1) was followed (post-state is checked)
  but its check itself read an engine error as "no containers", the inverse of the
  exit-code trust it forbids.
- **BUG-0023 / PA-0025** (fail-closed: never infer "secure" from the absence of a
  positive signal), generalised by PA-0035/PA-0050. Same root cause in a new layer: "no
  answer from the engine" was inferred as "no exposure".
Result: a recurrence of PA-0025's root cause and of PA-0059(1)'s class, in a layer
(container-engine state) neither rule names.

## Prior-preventive-action failure analysis
- **PA-0025** (BUG-0023) states the fail-closed doctrine for a tool oracle's output;
  PA-0035/PA-0050 extended it to capability probes and liveness. None names a *safety*
  check over an external system's state, and none asks for an allowlist: the doctrine
  was known but scoped too narrowly to be applied mechanically here (too narrow).
- **PA-0059(1)** (BUG-0057) asks to check real post-state but not what the post-state
  check does when the engine cannot answer (too narrow: it guards the exit code, not
  the empty output of a failed query).
- **PA-0130** (BUG-0130) makes the runtime check authoritative for procutil servers;
  container engines were outside its scope and its enforcement (the AST guards do not
  see compose files) (wrong layer for this case).

## Preventive action
**PA-0310** (strengthens PA-0025, PA-0059(1) and PA-0130 for container engines): a
safety check over an external system's state is an **allowlist** of the states known to
be safe, backed where possible by an engine-agnostic fact (here: the network namespace),
and **every inability to determine the state is a failure**, in the shell and in the
API. Its tests include offenders that are not drawn from the check's own list (another
engine's vocabulary; a failing engine), and each fail-closed branch is mutation-checked.
The PA-0002 sweep for this class covers every safety check in `lab/external/extctl.sh`
and `fuzzlab/lab_fixtures/external.py` (done: pre-flight, post-check, `published_port`,
`_leftovers`, `status`, the exposed-stack teardown) and `lab/labctl.sh`'s existing
`_force_clean`/`down` path, which still trusts `podman ps` output on error: recorded as a
follow-up (outside this change's files; labctl.sh's main path is unchanged here).
